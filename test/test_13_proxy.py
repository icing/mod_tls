import os
import re
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestProxy:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': f"""
            LogLevel proxy:trace1 proxy_http:trace1
            """,
            cls.env.domain_b: f"""
            ProxyPreserveHost on
            ProxyPass "/proxy/" "http://127.0.0.1:{cls.env.http_port}/"
            ProxyPassReverse "/proxy/" "http://{cls.env.domain_b}:{cls.env.http_port}" 
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

    def test_13_proxy_http_get(self):
        data = self.env.https_get_json(self.env.domain_b, "/proxy/index.json")
        assert data == {'domain': self.env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", ""),
        ("SSL_SECURE_RENEG", ""),
        ("SSL_COMPRESS_METHOD", ""),
        ("SSL_CIPHER_EXPORT", ""),
        ("SSL_CLIENT_VERIFY", ""),
    ])
    def test_13_proxy_http_vars(self, name: str, value: str):
        r = self.env.https_get(self.env.domain_b, f"/proxy/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == { name: value }, r.stdout