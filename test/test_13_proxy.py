from datetime import timedelta

import pytest

from test_conf import TlsTestConf


class TestProxy:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_vhosts(domains=[env.domain_a, env.domain_b], extras={
            'base': f"""
            LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1
            """,
            env.domain_b: f"""
            ProxyPreserveHost on
            ProxyPass "/proxy/" "http://127.0.0.1:{env.http_port}/"
            ProxyPassReverse "/proxy/" "http://{env.domain_b}:{env.http_port}" 
            """,
        })
        conf.write()
        assert env.apache_restart() == 0
        yield
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    def test_13_proxy_http_get(self, env):
        data = env.https_get_json(env.domain_b, "/proxy/index.json")
        assert data == {'domain': env.domain_b}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "b.mod-tls.test"),
        ("SSL_SESSION_RESUMED", ""),
        ("SSL_SECURE_RENEG", ""),
        ("SSL_COMPRESS_METHOD", ""),
        ("SSL_CIPHER_EXPORT", ""),
        ("SSL_CLIENT_VERIFY", ""),
    ])
    def test_13_proxy_http_vars(self, env, name: str, value: str):
        r = env.https_get(env.domain_b, f"/proxy/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout
