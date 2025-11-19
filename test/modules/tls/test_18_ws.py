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


class WsServer:

    def __init__(self, name, env, port, creds=None):
        self.name = name
        self.env = env
        self.process = None
        self.cerr = None
        self.port = port
        self.creds = creds
        self.run_dir = os.path.join(env.gen_dir, self.name)
        self.err_file = os.path.join(self.run_dir, 'stderr')
        self._rmrf(self.run_dir)
        self._mkpath(self.run_dir)

    def start(self):
        if not self.process:
            self.cerr = open(self.err_file, 'w')
            cmd = os.path.join(os.path.dirname(inspect.getfile(TestWebSockets)),
                               'ws_server.py')
            args = ['python3', cmd, '--port', str(self.port)]
            if self.creds:
                args.extend([
                    '--cert', self.creds[0].cert_file,
                    '--key', self.creds[0].pkey_file,
                ])
            self.process = subprocess.Popen(args=args, cwd=self.run_dir,
                                            stderr=self.cerr, stdout=self.cerr)
            if not self.check_alive():
                self.stop()
                pytest.fail(f'ws_server did not start. stderr={open(self.err_file).readlines()}')

    def stop(self):
        if self.process:
            self.process.kill()
            self.process.wait()
            self.process = None
        if self.cerr:
            self.cerr.close()
            self.cerr = None

    def check_alive(self, timeout=5):
        if self.creds:
            url = f'https://localhost:{self.port}/'
        else:
            url = f'http://localhost:{self.port}/'
        end = datetime.now() + timedelta(seconds=timeout)
        while datetime.now() < end:
            r = self.env.curl_get(url, 5)
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



class TestWebSockets:

    @staticmethod
    def mk_text_file(fpath: str, lines: int):
        t110 = 11 * "0123456789"
        with open(fpath, "w") as fd:
            for i in range(lines):
                fd.write("{0:015d}: ".format(i))  # total 128 bytes per line
                fd.write(t110)
                fd.write("\n")


    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        # Apache config that CONNECT proxies a WebSocket server for paths starting
        # with '/ws/'
        # The WebSocket server is started in pytest fixture 'ws_server' below.
        conf = TlsTestConf(env, extras={
            'base': [
                'Timeout 1',
                f'<Proxy https://localhost:{env.wss_port}/>',
                '    TLSProxyEngine on',
                f'    TLSProxyCA {env.ca.cert_file}',
                '    ProxyPreserveHost on',
                '</Proxy>',
            ],
            'localhost': [
                f'ProxyPass /ws/ http://127.0.0.1:{env.ws_port}/ upgrade=websocket \\',
                f'timeout=2 flushpackets=on',
                f'ProxyPass /wss/ https://localhost:{env.wss_port}/ upgrade=websocket \\',
                f'timeout=2 flushpackets=on',
            ],
        })
        conf.add_vhost('localhost', port=env.http_port)
        conf.add_tls_vhosts(['localhost'], port=env.https_port)
        conf.install()
        TestWebSockets.mk_text_file(os.path.join(env.gen_dir, "1k.txt"), 8)
        TestWebSockets.mk_text_file(os.path.join(env.gen_dir, "10k.txt"), 80)
        TestWebSockets.mk_text_file(os.path.join(env.gen_dir, "100k.txt"), 800)
        TestWebSockets.mk_text_file(os.path.join(env.gen_dir, "1m.txt"), 8000)
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='class')
    def ws_server(self, env):
        # Run our python websockets server that has some special behaviour
        # for the different path to CONNECT to.
        ws_server = WsServer('ws-server', env, port=env.ws_port)
        ws_server.start()
        yield ws_server
        ws_server.stop()

    @pytest.fixture(autouse=True, scope='class')
    def wss_server(self, env):
        # Run our python websockets server that has some special behaviour
        # for the different path to CONNECT to.
        creds = env.get_credentials_for_name('localhost')
        assert creds
        ws_server = WsServer('wss-server', env, port=env.wss_port, creds=creds)
        ws_server.start()
        yield ws_server
        ws_server.stop()

    def ssl_ctx(self, env):
        ssl_ctx = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.load_verify_locations(cafile=env.ca.cert_file)
        return ssl_ctx

    def ws_recv_text(self, ws):
        msg = ""
        while True:
            try:
                msg += ws.recv()
            except websockets.exceptions.ConnectionClosedOK:
                return msg
            except websockets.exceptions.ConnectionClosedError:
                return msg

    def ws_recv_bytes(self, ws):
        msg = b''
        while True:
            try:
                msg += ws.recv()
            except websockets.exceptions.ConnectionClosedOK:
                return msg
            except websockets.exceptions.ConnectionClosedError:
                return msg

    # verify the our plain websocket server works
    def test_tls_18_01_ws_direct(self, env, ws_server):
        with connect(f"ws://127.0.0.1:{env.ws_port}/echo") as ws:
            message = "Hello world!"
            ws.send(message)
            response = self.ws_recv_text(ws)
            assert response == message

    # verify that our secure websocket server works
    def test_tls_18_02_wss_direct(self, env, wss_server):
        pytest.skip(reason='For unknown reasons, this is flaky in CI')
        with connect(f"wss://localhost:{env.wss_port}/echo",
                     ssl_context=self.ssl_ctx(env)) as ws:
            message = "Hello world!"
            ws.send(message)
            response = self.ws_recv_text(ws)
            assert response == message

    # verify to send plain websocket message pingpong through apache
    def test_tls_18_03_http_ws(self, env, ws_server):
        with connect(f"ws://localhost:{env.http_port}/ws/echo/") as ws:
            message = "Hello world!"
            ws.send(message)
            response = self.ws_recv_text(ws)
            assert response == message

    # verify to send secure websocket message pingpong through apache
    def test_tls_18_04_http_wss(self, env, wss_server):
        # pytest.skip(reason='This fails, needing a fix like PR #9')
        with connect(f"ws://localhost:{env.http_port}/wss/echo/") as ws:
            message = "Hello world!"
            ws.send(message)
            response = self.ws_recv_text(ws)
            assert response == message

    # verify that getting a large file works without any TLS involved
    @pytest.mark.parametrize("fname", ["1m.txt"])
    def test_tls_18_05_http_ws_file(self, env, fname, ws_server):
        expected = open(os.path.join(env.gen_dir, fname), 'rb').read()
        with connect(f"ws://localhost:{env.http_port}/ws/file/{fname}") as ws:
            response = self.ws_recv_bytes(ws)
            assert response == expected

    # verify getting secure websocket from the http: server
    # this is "backend" mod_tls work
    @pytest.mark.parametrize("fname", ["1k.txt", "10k.txt", "100k.txt", "1m.txt"])
    def test_tls_18_06_http_wss_file(self, env, fname, ws_server):
        expected = open(os.path.join(env.gen_dir, fname), 'rb').read()
        with connect(f"ws://localhost:{env.http_port}/wss/file/{fname}") as ws:
            response = self.ws_recv_bytes(ws)
            assert response == expected
