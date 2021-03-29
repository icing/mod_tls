import json
import socket
import sys
import time
from datetime import timedelta

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestTimeout:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': """
            RequestReadTimeout handshake=1
            """,
        })
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def test_09_timeout_handshake(self):
        # in domain_b root, the StdEnvVars is switch on
        s = socket.create_connection(('localhost', self.env.https_port))
        s.settimeout(0.0)
        try:
            s.recv(1024)
            assert False, "able to recv() on a TLS connection before we sent a hello"
        except BlockingIOError:
            pass
        s.settimeout(2.0)
        try:
            while True:
                buf = s.recv(1024)
                if not buf:
                    break
                print("recv() -> {0}".format(buf))
        except BlockingIOError:
            assert False, "socket not closed as handshake timeout should trigger"
        s.close()
