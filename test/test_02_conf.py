import os
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestConf:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        if self.env.is_live(timeout=timedelta(milliseconds=100)):
            assert self.env.apache_stop() == 0

    def test_02_conf_cert_args_missing(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_conf_cert_single_arg(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate cert.pem")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_conf_cert_file_missing(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate cert.pem key.pem")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_conf_cert_file_exist(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCertificate test-02-cert.pem test-02-key.pem")
        conf.write()
        for name in ["test-02-cert.pem", "test-02-key.pem"]:
            with open(os.path.join(self.env.server_dir, name), "w") as fd:
                fd.write("")
        assert self.env.apache_fail() == 0

    def test_02_conf_cert_listen_missing(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen")
        conf.write()
        assert self.env.apache_fail() == 0

    def test_02_conf_cert_listen_wrong(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen ^^^^^")
        conf.write()
        assert self.env.apache_fail() == 0

    @pytest.mark.parametrize("listen", [
        "443",
        "129.168.178.188:443",
        "[::]:443",
    ])
    def test_02_conf_cert_listen_valid(self, listen: str):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSListen {listen}".format(listen=listen))
        conf.write()
        assert self.env.apache_restart() == 0

    def test_02_conf_cert_listen_cert(self):
        domain = self.env.domain_a
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[domain])
        conf.write()
        assert self.env.apache_restart() == 0

    def test_02_conf_proto_wrong(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSProtocols wrong")
        conf.write()
        assert self.env.apache_fail() == 0

    @pytest.mark.parametrize("proto", [
        "default",
        "TLSv1.2+",
        "TLSv1.3+",
        "TLSv0x0303+",
    ])
    def test_02_conf_proto_valid(self, proto):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSProtocols {proto}".format(proto=proto))
        conf.write()
        assert self.env.apache_restart() == 0

    def test_02_conf_honor_wrong(self):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSHonorClientOrder wrong")
        conf.write()
        assert self.env.apache_fail() == 0

    @pytest.mark.parametrize("honor", [
        "on",
        "OfF",
    ])
    def test_02_conf_honor_valid(self, honor: str):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSHonorClientOrder {honor}".format(honor=honor))
        conf.write()
        assert self.env.apache_restart() == 0

    @pytest.mark.parametrize("cipher", [
        "default",
        "TLS13_AES_128_GCM_SHA256:TLS13_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        """TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 \\
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\\
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"""
    ])
    def test_02_conf_cipher_valid(self, cipher):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCiphersPrefer {cipher}".format(cipher=cipher))
        conf.write()
        assert self.env.apache_restart() == 0

    @pytest.mark.parametrize("cipher", [
        "wrong",
        "YOLO",
        "TLS_NULL_WITH_NULL_NULLX",       # not supported
        "TLS_DHE_RSA_WITH_AES128_GCM_SHA256",     # not supported
    ])
    def test_02_conf_cipher_wrong(self, cipher):
        conf = TlsTestConf(env=self.env)
        conf.add("TLSCiphersPrefer {cipher}".format(cipher=cipher))
        conf.write()
        assert self.env.apache_fail() == 0

