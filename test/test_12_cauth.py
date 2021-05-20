import os
import time
from datetime import timedelta

from test_env import TlsTestEnv, ExecResult
from test_conf import TlsTestConf


class TestMD:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0
        cls.clientsX = cls.env.CA.get_first("clientsX")
        cls.clientsY = cls.env.CA.get_first("clientsY")
        cls.ca_file = os.path.join(os.path.dirname(cls.clientsX.cert_file), "clientX-ca.pem")
        with open(cls.ca_file, 'w') as fd:
            fd.write("".join(open(cls.clientsX.cert_file).readlines()))
            fd.write("".join(open(cls.env.CA.cert_file).readlines()))

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        if self.env.is_live(timeout=timedelta(milliseconds=100)):
            assert self.env.apache_stop() == 0

    def test_12_set_ca_non_existing(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_a, self.env.domain_b], extras={
            self.env.domain_a: """
            TLSClientCA xxx 
            """
        })
        conf.write()
        assert self.env.apache_restart() == 1

    def test_12_set_ca_existing(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_a, self.env.domain_b], extras={
            self.env.domain_a: f"""
            TLSClientCA {self.ca_file}
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0

    def test_12_set_auth_no_ca(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_a, self.env.domain_b], extras={
            self.env.domain_a: """
            TLSClientCertificate required
            """
        })
        conf.write()
        # will fail bc lacking clien CA
        assert self.env.apache_restart() == 1

    def test_12_auth_required(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_b], extras={
            self.env.domain_b: f"""
            TLSClientCertificate required
            TLSClientCA {self.ca_file}
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        # should be denied
        r = self.env.https_get(domain=self.env.domain_b, paths="/index.json")
        assert r.exit_code != 0, r.stdout
        # should work
        data = self.env.https_get_json(self.env.domain_b, "/index.json", extra_args=[
            "--cert", self.clientsX.get_first("user1").cert_file
        ])
        assert data == {'domain': self.env.domain_b}
        r = self.env.https_get(self.env.domain_b, "/vars.py?name=REMOTE_USER")
        assert r.exit_code != 0, "should have been prevented"
        r = self.env.https_get(self.env.domain_b, "/vars.py?name=SSL_CLIENT_S_DN_CN", extra_args=[
            "--cert", self.clientsX.get_first("user1").cert_file
        ])
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': 'Not Implemented',
        }, r.stdout


    def test_12_auth_ssl_optional(self):
        conf = TlsTestConf(env=self.env)
        domain = self.env.domain_b
        conf.add_ssl_vhosts(domains=[domain], extras={
            domain: f"""
            SSLVerifyClient optional
            SSLVerifyDepth 2
            SSLOptions +StdEnvVars
            SSLCACertificateFile {self.ca_file}
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        # should work either way
        data = self.env.https_get_json(domain, "/index.json")
        assert data == {'domain': domain}
        # no client cert given, we expect the server variable to be empty
        r = self.env.https_get(domain, "/vars.py?name=SSL_CLIENT_S_DN_CN")
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': '',
        }, r.stdout
        client_cert = self.clientsX.get_first("user1")
        data = self.env.https_get_json(domain, "/index.json", extra_args=[
            "--cert", client_cert.cert_file
        ])
        assert data == {'domain': domain}
        r = self.env.https_get(domain, "/vars.py?name=SSL_CLIENT_S_DN_CN", extra_args=[
            "--cert", client_cert.cert_file
        ])
        # with client cert, we expect the server variable to show? Do we?
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': 'user1',
        }, r.stdout

    def test_12_auth_optional(self):
        conf = TlsTestConf(env=self.env)
        domain = self.env.domain_b
        conf.add_md_vhosts(domains=[domain], extras={
            domain: f"""
            TLSClientCertificate optional
            TLSClientCA {self.ca_file}
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        # should work either way
        data = self.env.https_get_json(domain, "/index.json")
        assert data == {'domain': domain}
        # no client cert given, we expect the server variable to be empty
        r = self.env.https_get(domain, "/vars.py?name=SSL_CLIENT_S_DN_CN")
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': '',
        }, r.stdout
        data = self.env.https_get_json(domain, "/index.json", extra_args=[
            "--cert", self.clientsX.get_first("user1").cert_file
        ])
        assert data == {'domain': domain}
        r = self.env.https_get(domain, "/vars.py?name=SSL_CLIENT_S_DN_CN", extra_args=[
            "--cert", self.clientsX.get_first("user1").cert_file
        ])
        # with client cert, we expect the server variable to show? Do we?
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'SSL_CLIENT_S_DN_CN': 'Not Implemented',
        }, r.stdout

    def test_12_auth_expired(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_b], extras={
            self.env.domain_b: f"""
            TLSClientCertificate required
            TLSClientCA {self.ca_file}
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        # should not work
        r = self.env.https_get(domain=self.env.domain_b, paths="/index.json", extra_args=[
            "--cert", self.clientsX.get_first("user_expired").cert_file
        ])
        assert r.exit_code != 0

    def test_12_auth_other_ca(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_b], extras={
            self.env.domain_b: f"""
            TLSClientCertificate required
            TLSClientCA {self.ca_file}
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        # should not work
        r = self.env.https_get(domain=self.env.domain_b, paths="/index.json", extra_args=[
            "--cert", self.clientsY.get_first("user1").cert_file
        ])
        assert r.exit_code != 0
        # This will work, as the CA root is present in the CA file
        r = self.env.https_get(domain=self.env.domain_b, paths="/index.json", extra_args=[
            "--cert", self.env.CA.get_first("user1").cert_file
        ])
        assert r.exit_code == 0
