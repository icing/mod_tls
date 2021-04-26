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
            self.env.domain_a: """
            TLSClientCA ca/ca.rsa4096.cert.pem
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0

    def test_12_set_auth_no_ca(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_a, self.env.domain_b], extras={
            self.env.domain_a: """
            TLSClientAuthentication required
            """
        })
        conf.write()
        assert self.env.apache_restart() == 1

    def test_12_set_auth_and_ca(self):
        conf = TlsTestConf(env=self.env)
        conf.add_md_vhosts(domains=[self.env.domain_a, self.env.domain_b], extras={
            self.env.domain_a: """
            TLSClientAuthentication required
            TLSClientCA ca/ca.rsa4096.cert.pem
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
