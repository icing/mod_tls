import re
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestVars:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': """
            LogLevel tls:trace4
            TLSHonorClientOrder off
            TLSOptions +StdEnvVars
            """,
        })
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def test_08_vars_root(self):
        # in domain_b root, the StdEnvVars is switch on
        if self.env.curl_supports_tls_1_3():
            exp_proto = "TLSv1.3"
            exp_cipher = "TLS_CHACHA20_POLY1305_SHA256"
        else:
            exp_proto = "TLSv1.2"
            exp_cipher = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        r = self.env.https_get(self.env.domain_b, "/vars.py")
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'https': 'on',
            'host': 'b.mod-tls.test',
            'protocol': 'HTTP/1.1',
            'ssl_protocol': exp_proto,
            # this will vary by client potentially
            'ssl_cipher': exp_cipher,
        }, r.stdout

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_08_vars_const(self, name: str, value: str):
        r = self.env.https_get(self.env.domain_b, f"/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == { name: value }, r.stdout

    @pytest.mark.parametrize("name, pattern", [
        ("SSL_VERSION_INTERFACE", r'mod_tls/\d+\.\d+\.\d+'),
        ("SSL_VERSION_LIBRARY", r'crustls/\d+\.\d+\.\d+/rustls/\d+\.\d+\.\d+'),
    ])
    def test_08_vars_match(self, name: str, pattern: str):
        r = self.env.https_get(self.env.domain_b, f"/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert name in r.json
        assert re.match(pattern, r.json[name]), r.json
