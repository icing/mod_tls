import re
from datetime import timedelta

import pytest

from test_conf import TlsTestConf


class TestProxyMixed:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        # add vhosts a+b and a ssl proxy from a to b
        conf.add_vhosts(domains=[env.domain_a, env.domain_b], extras={
            'base': f"""
            LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1 proxy_http2:trace1
            ProxyPreserveHost on
            <Proxy https://127.0.0.1:{env.https_port}/>
                SSLProxyEngine on
                SSLProxyVerify require
                SSLProxyCACertificateFile {env.ca.cert_file}
            </Proxy>
            <Proxy h2://127.0.0.1:{env.https_port}/>
                TLSProxyEngine on
                TLSProxyCA {env.ca.cert_file}
            </Proxy>
            """,
            env.domain_b: f"""
            Protocols h2 http/1.1
            ProxyPass /proxy-ssl/ https://127.0.0.1:{env.https_port}/
            ProxyPass /proxy-tls/ h2://127.0.0.1:{env.https_port}/
            TLSOptions +StdEnvVars
            """,
        })
        conf.write()
        assert env.apache_restart() == 0
        yield
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    def test_16_proxy_mixed_ssl_get(self, env):
        data = env.https_get_json(env.domain_b, "/proxy-ssl/index.json")
        assert data == {'domain': env.domain_b}

    def test_16_proxy_mixed_tls_get(self, env):
        data = env.https_get_json(env.domain_b, "/proxy-tls/index.json")
        assert data == {'domain': env.domain_b}

