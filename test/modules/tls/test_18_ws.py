import ssl
from datetime import datetime, timedelta
import inspect
import os
import shutil
import subprocess
import time

import pytest
import websockets
from websockets.sync.client import connect

from .conf import TlsTestConf


def mk_text_file(fpath: str, lines: int):
    t110 = 11 * "0123456789"
    with open(fpath, "w") as fd:
        for i in range(lines):
            fd.write("{0:015d}: ".format(i))  # total 128 bytes per line
            fd.write(t110)
            fd.write("\n")


class TestWebSockets:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # Apache config that CONNECT proxies a WebSocket server for paths starting
        # with '/ws/'
        # The WebSocket server is started in pytest fixture 'ws_server' below.
        conf = TlsTestConf(env, extras={
            'base': [
                'Timeout 1',
            ],
            'localhost': [
                f'ProxyPass /ws/ http://127.0.0.1:{env.ws_port}/ upgrade=websocket \\',
                f'timeout=2 flushpackets=on',
            ],
            f'cgi.{env.http_tld}': [
              f'  ProxyPass /ws/ http://127.0.0.1:{env.ws_port}/ \\',
              f'           upgrade=websocket timeout=2 flushpackets=on',
              f'  ReadBufferSize 65535'
            ]
        })
        conf.add_vhost('localhost', port=env.http_port)
        conf.add_tls_vhosts(['localhost'], port=env.https_port)
        conf.install()
        mk_text_file(os.path.join(env.gen_dir, "1k.txt"), 8)
        mk_text_file(os.path.join(env.gen_dir, "10k.txt"), 80)
        mk_text_file(os.path.join(env.gen_dir, "100k.txt"), 800)
        mk_text_file(os.path.join(env.gen_dir, "1m.txt"), 8000)
        mk_text_file(os.path.join(env.gen_dir, "10m.txt"), 80000)
        assert env.apache_restart() == 0

    def ws_check_alive(self, env, timeout=5):
        url = f'http://localhost:{env.ws_port}/'
        end = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end:
            r = env.curl_get(url, 5)
            if r.exit_code == 0:
                return True
            time.sleep(.1)
        return False

    def _mkpath(self, path):
        if not os.path.exists(path):
            return os.makedirs(path)

    def _rmrf(self, path):
        if os.path.exists(path):
            return shutil.rmtree(path)

    def ws_recv_text(self, ws):
        msg = ""
        while True:
            try:
                msg += ws.recv()
            except websockets.exceptions.ConnectionClosedOK:
                return msg

    def ws_recv_bytes(self, ws):
        msg = b''
        while True:
            try:
                msg += ws.recv()
            except websockets.exceptions.ConnectionClosedOK:
                return msg

    @pytest.fixture(autouse=True, scope='class')
    def ws_server(self, env):
        # Run our python websockets server that has some special behaviour
        # for the different path to CONNECT to.
        run_dir = os.path.join(env.gen_dir, 'ws-server')
        err_file = os.path.join(run_dir, 'stderr')
        self._rmrf(run_dir)
        self._mkpath(run_dir)
        with open(err_file, 'w') as cerr:
            cmd = os.path.join(os.path.dirname(inspect.getfile(TestWebSockets)),
                               'ws_server.py')
            args = ['python3', cmd, '--port', str(env.ws_port)]
            p = subprocess.Popen(args=args, cwd=run_dir, stderr=cerr,
                                 stdout=cerr)
            if not self.ws_check_alive(env):
                p.kill()
                p.wait()
                pytest.fail(f'ws_server did not start. stderr={open(err_file).readlines()}')
            yield
            p.terminate()

    def test_tls_18_01_direct(self, env):
        with connect(f"ws://127.0.0.1:{env.ws_port}/echo") as ws:
            message = "Hello world!"
            ws.send(message)
            response = self.ws_recv_text(ws)
            assert response == message

    def test_tls_18_02_httpd_plain(self, env):
        with connect(f"ws://localhost:{env.http_port}/ws/echo/") as ws:
            message = "Hello world!"
            ws.send(message)
            response = self.ws_recv_text(ws)
            assert response == message

    @pytest.mark.parametrize("fname", ["1k.txt", "10k.txt", "100k.txt", "1m.txt", "10m.txt"])
    def test_tls_18_03_file(self, env, fname):
        expected = open(os.path.join(env.gen_dir, fname), 'rb').read()
        with connect(f"ws://localhost:{env.http_port}/ws/file/{fname}") as ws:
            response = self.ws_recv_bytes(ws)
            assert response == expected

    @pytest.mark.parametrize("fname", ["1k.txt", "10k.txt", "100k.txt", "1m.txt", "10m.txt"])
    def test_tls_18_04_tls_file(self, env, fname):
        expected = open(os.path.join(env.gen_dir, fname), 'rb').read()
        ssl_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.VerifyMode.CERT_NONE
        with connect(f"wss://localhost:{env.https_port}/ws/file/{fname}",
                     ssl_context=ssl_ctx) as ws:
            response = self.ws_recv_bytes(ws)
            assert response == expected
