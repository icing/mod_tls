import json
import os
import subprocess
import sys
import time
from configparser import ConfigParser
from datetime import timedelta
from http.client import HTTPConnection
from typing import List, Optional, Dict
from urllib.parse import urlparse

from test_cert import TlsTestCert


class ExecResult:

    def __init__(self, exit_code: int, stdout: str, stderr: str = None):
        self._exit_code = exit_code
        self._stdout = stdout if stdout is not None else ""
        self._stderr = stderr if stderr is not None else ""
        # noinspection PyBroadException
        try:
            self._json_out = json.loads(self._stdout)
        except:
            self.json_out = None

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def stdout(self) -> str:
        return self._stdout

    @property
    def json(self) -> Optional[Dict]:
        """Output as JSON dictionary or None if not parseable."""
        return self._json_out

    @property
    def stderr(self) -> str:
        return self._stderr


class TlsTestEnv:

    DOMAIN_A = "a.mod-tls.test"
    DOMAIN_B = "b.mod-tls.test"

    _initialized = False

    @classmethod
    def init_class(cls, base_dir: str):
        if not cls._initialized:
            certs = TlsTestCert()
            for domain in [cls.DOMAIN_A, cls.DOMAIN_B]:
                certs.create_self_signed(base_dir, domain, sans=[domain])
            cls._initialized = True

    def __init__(self):
        config = ConfigParser()
        config.read('test.ini')

        self._prefix = config.get('global', 'prefix')
        self._gen_dir = config.get('global', 'gen_dir')
        self._server_dir = config.get('global', 'server_dir')
        self._server_conf_dir = os.path.join(self._server_dir, "conf")

        self._apachectl = os.path.join(self._prefix, 'bin', 'apachectl')
        self._http_port = int(config.get('global', 'http_port'))
        self._https_port = int(config.get('global', 'https_port'))

        self._httpd_url = "http://localhost:{port}".format(port=self._http_port)
        self._httpd_check_url = self._httpd_url

        self._curl = config.get('global', 'curl_bin')
        if self._curl is None or len(self._curl) == 0:
            self._curl = "curl"
        self._openssl = config.get('global', 'openssl_bin')
        TlsTestEnv.init_class(self._server_dir)

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def https_port(self) -> int:
        return self._https_port

    @property
    def http_base_url(self) -> str:
        return self._httpd_url

    @property
    def server_dir(self) -> str:
        return self._server_dir

    @property
    def server_conf_dir(self) -> str:
        return self._server_conf_dir

    @property
    def domain_a(self) -> str:
        return self.DOMAIN_A

    @property
    def domain_b(self) -> str:
        return self.DOMAIN_B

    @staticmethod
    def run(args: List[str]) -> ExecResult:
        print("run: {0}".format(args))
        p = subprocess.run(args, capture_output=True, text=True)
        # noinspection PyBroadException
        return ExecResult(exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr)

    # --------- HTTP ---------

    def is_live(self, url: str = None, timeout: timedelta = None):
        url = url if url else self._httpd_check_url
        server = urlparse(url)
        timeout = timeout if timeout is not None else timedelta(seconds=20)
        try_until = time.time() + timeout.total_seconds()
        print("checking is reachable: {url}".format(url=url))
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout.total_seconds())
                c.request('HEAD', server.path)
                _resp = c.getresponse()
                c.close()
                return True
            except ConnectionRefusedError:
                print("connection refused")
                time.sleep(.1)
            except:
                print("Unexpected error:", sys.exc_info()[0])
                time.sleep(.1)
        print("Unable to contact server after {timeout} sec".format(timeout=timeout))
        return False

    def is_dead(self, url: str = None, timeout: timedelta = None):
        url = url if url else self._httpd_check_url
        server = urlparse(url)
        timeout = timeout if timeout is not None else timedelta(seconds=20)
        try_until = time.time() + timeout.total_seconds()
        print("checking is unreachable: {url}".format(url=url))
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout.total_seconds())
                c.request('HEAD', server.path)
                _resp = c.getresponse()
                c.close()
                time.sleep(.1)
            except IOError:
                return True
            except:
                return True
        print(f"Server still responding after {timeout} sec".format(timeout=timeout))
        return False

    # --------- control apache ---------

    def apachectl(self, cmd, check_live=True):
        args = [self._apachectl, "-d", self._server_dir, "-k", cmd]
        p = subprocess.run(args, capture_output=True, text=True)
        rv = p.returncode
        if rv == 0:
            timeout = timedelta(seconds=10)
            if check_live:
                rv = 0 if self.is_live(timeout=timeout) else -1
            else:
                rv = 0 if self.is_dead(timeout=timeout) else -1
                print("waited for a apache.is_dead, rv=%d" % rv)
        else:
            print("exit %d, stderr: %s" % (rv, p.stderr))
        return rv

    def apache_restart(self):
        return self.apachectl("graceful")

    def apache_start(self):
        return self.apachectl("start")

    def apache_stop(self):
        return self.apachectl("stop", check_live=False)

    def apache_fail(self):
        rv = self.apachectl("graceful", check_live=False)
        if rv != 0:
            print("graceful restart returned: {0}".format(rv))
            return 0 if self.is_dead(timeout=timedelta(seconds=5)) else -1
        return rv

    def curl(self, args: List[str]) -> ExecResult:
        return self.run([self._curl] + args)

    def https_get_json(self, domain, path):
        r = self.curl(["--insecure", "-vvvvvv", "--resolve", "{domain}:{port}:127.0.0.1".format(
            domain=domain, port=self.https_port
        ), "https://{domain}:{port}{path}".format(
            domain=domain, port=self.https_port, path=path
        )])
        assert r.exit_code == 0, r.stderr
        return r.json
