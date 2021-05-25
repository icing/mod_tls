import os
import re
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestProxySSL:

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
            SSLProxyEngine on
            SSLProxyVerify none
            ProxyPreserveHost on
            ProxyPass "/proxy-ssl/" "https://127.0.0.1:{cls.env.https_port}/"
            ProxyPassReverse "/proxy-ssl/" "https://{cls.env.domain_b}:{cls.env.https_port}" 
            TLSOptions +StdEnvVars
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

    def test_13_proxy_ssl_get(self):
        data = self.env.https_get_json(self.env.domain_b, "/proxy-ssl/index.json")
        assert data == {'domain': self.env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_13_proxy_ssl_vars_const(self, name: str, value: str):
        r = self.env.https_get(self.env.domain_b, f"/proxy-ssl/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == { name: value }, r.stdout

    @pytest.mark.parametrize("name, pattern", [
        ("SSL_VERSION_INTERFACE", r'mod_tls/\d+\.\d+\.\d+'),
        ("SSL_VERSION_LIBRARY", r'crustls/\d+\.\d+\.\d+/rustls/\d+\.\d+\.\d+'),
    ])
    def test_13_proxy_ssl_vars_match(self, name: str, pattern: str):
        r = self.env.https_get(self.env.domain_b, f"/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert name in r.json
        assert re.match(pattern, r.json[name]), r.json


