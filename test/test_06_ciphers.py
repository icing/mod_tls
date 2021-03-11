import re
import time
from datetime import timedelta

import pytest

from test_env import TlsTestEnv, ExecResult
from test_conf import TlsTestConf


class TestCiphers:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @classmethod
    def setup_class(cls):
        cls.domain_a = cls.env.domain_a
        cls.domain_b = cls.env.domain_b
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.domain_a, cls.domain_b])
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        pass

    def _get_protocol_cipher(self, output: str):
        protocol = None
        cipher = None
        for line in output.splitlines():
            m = re.match(r'^\s+Protocol\s*:\s*(\S+)$', line)
            if m:
                protocol = m.group(1)
                continue
            m = re.match(r'^\s+Cipher\s*:\s*(\S+)$', line)
            if m:
                cipher = m.group(1)
        return protocol, cipher

    def test_06_ciphers_ecdsa(self):
        r = self.env.openssl_client(self.domain_b, extra_args=[
            "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384", "-tls1_2"
        ])
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == "ECDHE-ECDSA-AES256-GCM-SHA384", r.stdout

    def test_06_ciphers_rsa(self):
        r = self.env.openssl_client(self.domain_b, extra_args=[
            "-cipher", "ECDHE-RSA-AES256-GCM-SHA384", "-tls1_2"
        ])
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == "ECDHE-RSA-AES256-GCM-SHA384", r.stdout

    @pytest.mark.skipif(not TlsTestEnv.CRUSTLY_SUPPORTS_TLS_CIPHER,
                        reason="crustls-not-implemented")
    def test_06_ciphers_server_ecdsa(self):
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSCiphers ECDHE-ECDSA-AES256-GCM-SHA384
            """,
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.openssl_client(self.domain_b)
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == "ECDHE-ECDSA-AES256-GCM-SHA384", r.stdout

    @pytest.mark.skipif(not TlsTestEnv.CRUSTLY_SUPPORTS_TLS_CIPHER,
                        reason="crustls-not-implemented")
    def test_06_ciphers_server_rsa(self):
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSCiphers ECDHE-RSA-AES256-GCM-SHA384
            """,
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.openssl_client(self.domain_b)
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == "ECDHE-RSA-AES256-GCM-SHA384", r.stdout

