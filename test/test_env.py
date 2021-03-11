import inspect
import json
import logging
import os
import subprocess
import sys
import time

from configparser import ConfigParser
from datetime import timedelta, datetime
from http.client import HTTPConnection
from typing import List, Optional, Dict, Tuple, Union
from urllib.parse import urlparse

from test_cert import TlsTestCA, CertificateSpec

log = logging.getLogger(__name__)

class ExecResult:

    def __init__(self, exit_code: int, stdout: str, stderr: str = None, duration: timedelta = None):
        self._exit_code = exit_code
        self._stdout = stdout if stdout is not None else ""
        self._stderr = stderr if stderr is not None else ""
        self._duration = duration if duration is not None else timedelta()
        # noinspection PyBroadException
        try:
            self._json_out = json.loads(self._stdout)
        except:
            self._json_out = None

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

    @property
    def duration(self) -> timedelta:
        return self._duration


class TlsTestEnv:

    DOMAIN_A = "a.mod-tls.test"
    DOMAIN_B = "b.mod-tls.test"

    CERT_SPECS = [
        CertificateSpec([DOMAIN_A]),
        CertificateSpec([DOMAIN_B], key_type='secp256r1', single_file=True),
        CertificateSpec([DOMAIN_B], key_type='rsa4096'),
    ]
    CERT_FILES = {}
    CA = None

    SNI_CERT_BROKEN = True  # cerrtificate selection based on SNI not implemented

    CRUSTLY_SUPPORTS_TLS_VERSION = False
    CRUSTLY_SUPPORTS_TLS_CIPHER = False

    @classmethod
    def init_class(cls, base_dir: str):
        if cls.CA is None:
            cls.CA = TlsTestCA(ca_dir=os.path.join(base_dir, 'ca'), key_type="rsa4096")
            cls.CERT_FILES['ca'] = cls.CA.ca_cert_file, None
            for spec in cls.CERT_SPECS:
                cert_file, key_file = cls.CA.create_cert(spec)
                for name in spec.domains:
                    if name not in cls.CERT_FILES:
                        cls.CERT_FILES[name] = []
                    cls.CERT_FILES[name].append((cert_file, key_file))
            cls._initialized = True

    def __init__(self):
        our_dir = os.path.dirname(inspect.getfile(TlsTestEnv))
        config = ConfigParser()
        config.read(os.path.join(our_dir, 'test.ini'))
        self._prefix = config.get('global', 'prefix')
        self._gen_dir = os.path.join(our_dir, 'gen')
        self._server_dir = os.path.join(self._gen_dir, 'apache')
        self._server_conf_dir = os.path.join(self._server_dir, "conf")
        self._server_docs_dir = os.path.join(self._server_dir, "htdocs")
        self._mpm_type = os.environ['MPM'] if 'MPM' in os.environ else 'event'

        self._apachectl = os.path.join(self._prefix, 'bin', 'apachectl')
        self._httpd = os.path.join(self._prefix, 'bin', 'httpd')
        self._http_port = int(config.get('global', 'http_port'))
        self._https_port = int(config.get('global', 'https_port'))

        self._http_base = "http://localhost:{port}".format(port=self._http_port)
        self._httpd_check_url = self._http_base
        self._https_base = "https://localhost:{port}".format(port=self._https_port)

        self._curl = config.get('global', 'curl_bin')
        if self._curl is None or len(self._curl) == 0:
            self._curl = "curl"
        self._openssl = config.get('global', 'openssl_bin')
        TlsTestEnv.init_class(self._server_dir)

    @property
    def prefix(self) -> str:
        return self._prefix

    @property
    def mpm_type(self) -> str:
        return self._mpm_type

    @property
    def http_port(self) -> int:
        return self._http_port

    @property
    def https_port(self) -> int:
        return self._https_port

    @property
    def http_base_url(self) -> str:
        return self._http_base

    @property
    def https_base_url(self) -> str:
        return self._https_base

    @property
    def gen_dir(self) -> str:
        return self._gen_dir

    @property
    def server_dir(self) -> str:
        return self._server_dir

    @property
    def server_conf_dir(self) -> str:
        return self._server_conf_dir

    @property
    def server_docs_dir(self) -> str:
        return self._server_docs_dir

    @property
    def domain_a(self) -> str:
        return self.DOMAIN_A

    @property
    def domain_b(self) -> str:
        return self.DOMAIN_B

    @property
    def ca_cert(self) -> str:
        return self.CERT_FILES['ca'][0]

    def cert_files_for(self, domain: str) -> List[Tuple[str, str]]:
        return self.CERT_FILES[domain]

    @staticmethod
    def run(args: List[str]) -> ExecResult:
        print("run: {0}".format(" ".join(args)))
        start = datetime.now()
        p = subprocess.run(args, capture_output=True, text=True)
        # noinspection PyBroadException
        return ExecResult(exit_code=p.returncode, stdout=p.stdout, stderr=p.stderr,
                          duration=datetime.now() - start)

    # --------- HTTP ---------

    def is_live(self, url: str = None, timeout: timedelta = None):
        url = url if url else self._httpd_check_url
        server = urlparse(url)
        timeout = timeout if timeout is not None else timedelta(seconds=20)
        try_until = time.time() + timeout.total_seconds()
        log.debug("checking is reachable: {url}".format(url=url))
        while time.time() < try_until:
            # noinspection PyBroadException
            try:
                c = HTTPConnection(server.hostname, server.port, timeout=timeout.total_seconds())
                c.request('HEAD', server.path)
                _resp = c.getresponse()
                c.close()
                return True
            except ConnectionRefusedError:
                log.debug("connection refused")
                time.sleep(.1)
            except:
                log.warning("Unexpected error:", sys.exc_info()[0])
                time.sleep(.1)
        log.warning("Unable to contact server after {timeout} sec".format(timeout=timeout))
        return False

    def is_dead(self, url: str = None, timeout: timedelta = None):
        url = url if url else self._httpd_check_url
        server = urlparse(url)
        timeout = timeout if timeout is not None else timedelta(seconds=20)
        try_until = time.time() + timeout.total_seconds()
        log.debug("checking is unreachable: {url}".format(url=url))
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
        log.warning(f"Server still responding after {timeout} sec".format(timeout=timeout))
        return False

    # --------- control apache ---------

    def httpd(self):
        args = [self._httpd, "-X", "-d", self._server_dir]
        p = subprocess.run(args, capture_output=True, text=True)
        rv = p.returncode
        return rv

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
                log.debug("waited for a apache.is_dead, rv=%d" % rv)
        else:
            log.warning("exit %d, stderr: %s" % (rv, p.stderr))
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
            log.warning("graceful restart returned: {0}".format(rv))
            return 0 if self.is_dead(timeout=timedelta(seconds=5)) else -1
        return rv

    def curl(self, args: List[str]) -> ExecResult:
        return self.run([self._curl] + args)

    def https_get(self, domain, paths: Union[str, List[str]], extra_args: List[str] = None) -> ExecResult:
        args = []
        if extra_args:
            args.extend(extra_args)
        args.extend(["--cacert", self.ca_cert, "--resolve", "{domain}:{port}:127.0.0.1".format(
            domain=domain, port=self.https_port
        )])
        if isinstance(paths, str):
            paths = [paths]
        for path in paths:
            args.append("https://{domain}:{port}{path}".format(
                domain=domain, port=self.https_port, path=path))
        return self.curl(args)

    def https_get_json(self, domain, path, extra_args: List[str] = None):
        r = self.https_get(domain=domain, paths=path, extra_args=extra_args)
        assert r.exit_code == 0, r.stderr
        return r.json

    def run_diff(self, fleft: str, fright: str) -> ExecResult:
        return self.run(['diff', '-u', fleft, fright])

    def openssl(self, args: List[str]) -> ExecResult:
        return self.run([self._openssl] + args)

    def openssl_client(self, domain, extra_args: List[str] = None) -> ExecResult:
        args = ["s_client", "-CAfile", self.ca_cert, "-servername", domain,
                "-connect", "localhost:{port}".format(
                    port=self.https_port
                )]
        if extra_args:
            args.extend(extra_args)
        args.extend([])
        return self.openssl(args)

