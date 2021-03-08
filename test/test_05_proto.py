import time
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestProto:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    CURL_SUPPORTS_TLS_1_3 = None

    @classmethod
    def curl_supports_tls_1_3(cls) -> bool:
        if cls.CURL_SUPPORTS_TLS_1_3 is None:
            r = cls.env.https_get(cls.env.domain_a, "/index.json",
                                  extra_args=["--tlsv1.3"])
            cls.CURL_SUPPORTS_TLS_1_3 = r.exit_code == 0
        return cls.CURL_SUPPORTS_TLS_1_3

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            cls.env.domain_a: "TLSProtocols v1.3",
            cls.env.domain_b: "TLSProtocols v1.2",
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
        if self.curl_supports_tls_1_3():
            r = self.env.https_get(self.env.domain_b, "/index.json",
                               extra_args=["--tlsv1.3"])
            assert r.exit_code != 0, r.stderr

    def test_05_proto_1_3(self):
        r = self.env.https_get(self.env.domain_a, "/index.json",
                               extra_args=["--tlsv1.3"])
        if self.curl_supports_tls_1_3():
            assert r.exit_code == 0, r.stderr
        else:
            assert r.exit_code == 4, r.stderr

