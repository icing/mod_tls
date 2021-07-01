import re
from datetime import timedelta

import pytest

from test_conf import TlsTestConf


class TestProxySSL:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_vhosts(domains=[env.domain_a, env.domain_b], extras={
            'base': f"""
            LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1 proxy_http2:trace1
            <Proxy https://127.0.0.1:{env.https_port}/>
                SSLProxyEngine on
                SSLProxyVerify require
                SSLProxyCACertificateFile {env.ca.cert_file}
                ProxyPreserveHost on
            </Proxy>
            <Proxy https://localhost:{env.https_port}/>
                ProxyPreserveHost on
            </Proxy>
            <Proxy h2://127.0.0.1:{env.https_port}/>
                SSLProxyEngine on
                SSLProxyVerify require
                SSLProxyCACertificateFile {env.ca.cert_file}
                ProxyPreserveHost on
            </Proxy>
            """,
            env.domain_b: f"""
            Protocols h2 http/1.1
            ProxyPass /proxy-ssl/ https://127.0.0.1:{env.https_port}/
            ProxyPass /proxy-local/ https://localhost:{env.https_port}/
            ProxyPass /proxy-h2-ssl/ h2://127.0.0.1:{env.https_port}/
            TLSOptions +StdEnvVars
            """,
        })
        conf.write()
        assert env.apache_restart() == 0

    def test_14_proxy_ssl_get(self, env):
        data = env.https_get_json(env.domain_b, "/proxy-ssl/index.json")
        assert data == {'domain': env.domain_b}

    def test_14_proxy_ssl_get_local(self, env):
        # does not work, since SSLProxy* not configured
        data = env.https_get_json(env.domain_b, "/proxy-local/index.json")
        assert data is None

    def test_14_proxy_ssl_h2_get(self, env):
        r = env.https_get(env.domain_b, "/proxy-h2-ssl/index.json")
        assert r.exit_code == 0
        assert r.json == {'domain': env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", "Initial"),
        ("SSL_SECURE_RENEG", "false"),
        ("SSL_COMPRESS_METHOD", "NULL"),
        ("SSL_CIPHER_EXPORT", "false"),
        ("SSL_CLIENT_VERIFY", "NONE"),
    ])
    def test_14_proxy_ssl_vars_const(self, env, name: str, value: str):
        r = env.https_get(env.domain_b, f"/proxy-ssl/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout

    @pytest.mark.parametrize("name, pattern", [
        ("SSL_VERSION_INTERFACE", r'mod_tls/\d+\.\d+\.\d+'),
        ("SSL_VERSION_LIBRARY", r'crustls/\d+\.\d+\.\d+/rustls/\d+\.\d+\.\d+'),
    ])
    def test_14_proxy_ssl_vars_match(self, env, name: str, pattern: str):
        r = env.https_get(env.domain_b, f"/proxy-ssl/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert name in r.json
        assert re.match(pattern, r.json[name]), r.json
