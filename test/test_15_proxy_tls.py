import os
import re
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestProxyTLS:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': f"""
            LogLevel proxy:trace1 proxy_http:trace1
            TLSProxyProtocol TLSv1.3+
            <Proxy https://127.0.0.1:{cls.env.https_port}/>
                TLSProxyEngine on
                TLSProxyCA {cls.env.CA.cert_file}
                TLSProxyProtocol TLSv1.2+
                TLSProxyCiphersPrefer TLS13_AES_256_GCM_SHA384
                TLSProxyCiphersSuppress TLS13_AES_128_GCM_SHA256
                ProxyPreserveHost on
            </Proxy>
            <Proxy https://localhost:{cls.env.https_port}/>
                ProxyPreserveHost on
            </Proxy>
            <Proxy h2://127.0.0.1:{cls.env.https_port}/>
                TLSProxyEngine on
                TLSProxyCA {cls.env.CA.cert_file}
                TLSProxyCiphersSuppress TLS_AES_256_GCM_SHA384
                ProxyPreserveHost on
            </Proxy>
            """,
            cls.env.domain_b: f"""
            Protocols h2 http/1.1
            ProxyPass /proxy-tls/ https://127.0.0.1:{cls.env.https_port}/
            ProxyPass /proxy-local/ https://localhost:{cls.env.https_port}/
            ProxyPass /proxy-h2-tls/ h2://127.0.0.1:{cls.env.https_port}/
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

    def test_15_proxy_tls_get(self):
        data = self.env.https_get_json(self.env.domain_b, "/proxy-tls/index.json")
        assert data == {'domain': self.env.domain_b}

    def test_15_proxy_tls_get_local(self):
        # does not work, since SSLProxy* not configured
        data = self.env.https_get_json(self.env.domain_b, "/proxy-local/index.json")
        assert data == None

    def test_15_proxy_tls_h2_get(self):
        r = self.env.https_get(self.env.domain_b, "/proxy-h2-tls/index.json")
        assert r.exit_code == 0
        assert r.json == {'domain': self.env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_PROTOCOL", "TLSv1.3"),
        ("SSL_CIPHER", "TLS_AES_256_GCM_SHA384"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_15_proxy_tls_h1_vars(self, name: str, value: str):
        r = self.env.https_get(self.env.domain_b, f"/proxy-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == { name: value }, r.stdout

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_PROTOCOL", "TLSv1.3"),
        ("SSL_CIPHER", "TLS_CHACHA20_POLY1305_SHA256"),
        ("SSL_SESSION_RESUMED", "Initial"),
    ])
    def test_15_proxy_tls_h2_vars(self, name: str, value: str):
        r = self.env.https_get(self.env.domain_b, f"/proxy-h2-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == { name: value }, r.stdout

    @pytest.mark.parametrize("name, pattern", [
        ("SSL_VERSION_INTERFACE", r'mod_tls/\d+\.\d+\.\d+'),
        ("SSL_VERSION_LIBRARY", r'crustls/\d+\.\d+\.\d+/rustls/\d+\.\d+\.\d+'),
    ])
    def test_15_proxy_tls_vars_match(self, name: str, pattern: str):
        r = self.env.https_get(self.env.domain_b, f"/proxy-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert name in r.json
        assert re.match(pattern, r.json[name]), r.json


