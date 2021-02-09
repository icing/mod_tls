import os
import time
from datetime import timedelta

from test_cert import TlsTestCert
from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestGet:

    env = TlsTestEnv()
    domain_a = None

    @classmethod
    def setup_class(cls):
        cls.domain_a = cls.env.domain_a
        cls.domain_b = cls.env.domain_b
        conf = TlsTestConf(env=cls.env)
        conf.add("""
        LogLevel tls:trace8
        TLSListen {https}
        <VirtualHost *:{https}>
          ServerName {domain_a}
          DocumentRoot htdocs/{domain_a}
          TLSCertificate {domain_a}.cert.pem {domain_a}.pkey.pem
        </VirtualHost>
        <VirtualHost *:{https}>
          ServerName {domain_b}
          DocumentRoot htdocs/{domain_b}
          TLSCertificate {domain_b}.cert.pem {domain_b}.pkey.pem
        </VirtualHost>""".format(
            https=cls.env.https_port,
            domain_a=cls.domain_a,
            domain_b=cls.domain_b,
        ))
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        pass

    def test_03_get_a(self):
        # do we see the correct json for the domain_a?
        data = self.env.https_get_json(self.domain_a, "/index.json")
        assert data == {'domain': self.domain_a}

    def test_03_get_b(self):
        # do we see the correct json for the domain_a?
        data = self.env.https_get_json(self.domain_b, "/index.json")
        assert data == {'domain': self.domain_b}

    def test_03_sni_unknown(self):
        # do we see the first vhost respone for an unknown domain?
        domain_unknown = "unknown.test"
        data = self.env.https_get_json(domain_unknown, "/index.json")
        assert data == {'domain': self.domain_a}

    def test_03_sni_host_differ(self):
        # do we see the first vhost respone for an unknown domain?
        r = self.env.https_get(self.domain_b, "/index.json", extra_args=[
            "-vvvv", "--header", "Host: {0}".format(self.domain_a)
        ])
        # for now, this works as we do not have checks that fail between a and b
        assert r.exit_code == 0
        assert r.json == {'domain': self.domain_a}
