import time
from datetime import timedelta
import socket
from threading import Thread

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestProto:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    CURL_SUPPORTS_TLS_1_3 = None

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': "LogLevel tls:debug",
            cls.env.domain_a: "TLSProtocols TLSv1.3+",
            cls.env.domain_b: """
            # the commonly used name
            TLSProtocols TLSv1.2+
            # the numeric one (yes, this is 1.2)
            TLSProtocols TLSv0x0303+
            """,
        })
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        pass

    def test_05_proto_1_2(self):
        r = self.env.https_get(self.env.domain_b, "/index.json",
                               extra_args=["--tlsv1.2"])
        assert r.exit_code == 0, r.stderr
        if self.env.curl_supports_tls_1_3():
            r = self.env.https_get(self.env.domain_b, "/index.json",
                                   extra_args=["--tlsv1.3"])
            assert r.exit_code != 0, r.stderr

    def test_05_proto_1_3(self):
        r = self.env.https_get(self.env.domain_a, "/index.json",
                               extra_args=["--tlsv1.3"])
        if self.env.curl_supports_tls_1_3():
            assert r.exit_code == 0, r.stderr
        else:
            assert r.exit_code == 4, r.stderr

    def test_05_proto_close(self):
        s = socket.create_connection(('localhost', self.env.https_port))
        time.sleep(0.1)
        s.close()

    def test_05_proto_ssl_close(self):
        conf = TlsTestConf(env=self.env)
        conf.add_ssl_vhosts(domains=[self.env.domain_a, self.env.domain_b], extras={
            'base': "LogLevel ssl:debug",
            self.env.domain_a: "SSLProtocol TLSv1.3",
            self.env.domain_b: "SSLProtocol TLSv1.2",
        })
        conf.write()
        assert self.env.apache_restart() == 0
        s = socket.create_connection(('localhost', self.env.https_port))
        time.sleep(0.1)
        s.close()


