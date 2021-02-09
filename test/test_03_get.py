import os
import time
from datetime import timedelta

from test_cert import TlsTestCert
from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestGet:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        pass

    def test_03_get(self):
        domain = self.env.domain_a
        conf = TlsTestConf(env=self.env)
        conf.add("""
        LogLevel tls:trace8
        TLSListen {https}
        <VirtualHost *:{https}>
          ServerName {domain}
          TLSCertificate {domain}.cert.pem {domain}.pkey.pem
        </VirtualHost>""".format(
            https=self.env.https_port,
            domain=domain
        ))
        conf.write()
        assert self.env.apache_restart() == 0
        data = self.env.https_get_json(domain, "/index.json")
        # TODO: this is how it should be when we support SNI
        # assert data == {'domain': self.env.domain_a}
        assert data == {'domain': 'localhost'}
