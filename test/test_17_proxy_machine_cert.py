import os

import pytest

from test_conf import TlsTestConf


class TestProxyMachineCert:

    @pytest.fixture(autouse=True, scope='class')
    def clients_x(cls, env):
        return env.ca.get_first("clientsX")

    @pytest.fixture(autouse=True, scope='class')
    def clients_y(cls, env):
        return env.ca.get_first("clientsY")

    @pytest.fixture(autouse=True, scope='class')
    def cax_file(cls, clients_x):
        return os.path.join(os.path.dirname(clients_x.cert_file), "clientsX-ca.pem")

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(cls, env, cax_file, clients_x):
        conf = TlsTestConf(env=env)
        # add vhosts a(tls)+b(ssl, port2) and a ssl proxy from a to b with a machine cert
        # host b requires a client certificate
        conf.add_vhosts(domains=[env.domain_a], extras={
            'base': f"""
            LogLevel proxy:trace1 proxy_http:trace1 ssl:trace1 proxy_http2:trace1
            ProxyPreserveHost on
            """,
            env.domain_a: f"""
            Protocols h2 http/1.1
            TLSProxyEngine on
            TLSProxyCA {env.ca.cert_file}
            TLSProxyMachineCertificate {clients_x.get_first("user1").cert_file}

            <Location /proxy-tls/>
                ProxyPass https://127.0.0.1:{env.https_port2}/
            </Location>
            """,
        })
        conf.add_ssl_vhosts(domains=[env.domain_a], port=env.https_port2, extras={
            'base': f"""
            Listen {env.https_port2}
            """,
            env.domain_a: f"""
            SSLVerifyClient require
            SSLVerifyDepth 2
            SSLOptions +StdEnvVars +ExportCertData
            SSLCACertificateFile {cax_file}
            SSLUserName SSL_CLIENT_S_DN_CN
            """,
        })
        conf.write()
        assert env.apache_restart() == 0

    def test_17_proxy_machine_cert_get_a(self, env):
        data = env.https_get_json(env.domain_a, "/proxy-tls/index.json")
        assert data == {'domain': env.domain_a}

    @pytest.mark.parametrize("name, value", [
        ("SERVER_NAME", "a.mod-tls.test"),
        ("SSL_CLIENT_VERIFY", "SUCCESS"),
        ("REMOTE_USER", "user1"),
    ])
    def test_17_proxy_machine_cert_vars(self, env, name: str, value: str):
        r = env.https_get(env.domain_a, f"/proxy-tls/vars.py?name={name}")
        assert r.exit_code == 0, r.stderr
        assert r.json == {name: value}, r.stdout

