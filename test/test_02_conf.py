import os
from datetime import timedelta

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestApache:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    @classmethod
    def setup_method(self, _method):
        if self.env.is_live(timeout=timedelta(milliseconds=100)):
            assert self.env.apache_stop() == 0

    def test_02_cert_args_missing(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_cert_single_arg(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate cert.pem")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_cert_file_missing(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate cert.pem key.pem")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_cert_file_exist(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate test-02-cert.pem test-02-key.pem")
        conf.write()
        for name in ["test-02-cert.pem", "test-02-key.pem"]:
            with open(os.path.join(self.env.server_dir, name), "w") as fd:
                fd.write("")
        assert self.env.apache_restart() == 0

    def test_02_cert_listen_missing(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_cert_listen_wrong(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen invalid")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_cert_listen_port(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen 443")
        conf.write()
        assert self.env.apache_restart() == 0

    def test_02_cert_listen_ipv4port(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen 129.168.178.188:443")
        conf.write()
        assert self.env.apache_restart() == 0

    def test_02_cert_listen_ipv6port(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen [::]:443")
        conf.write()
        assert self.env.apache_restart() == 0

