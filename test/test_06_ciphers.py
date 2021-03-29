import re
import time
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
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
        conf.add_vhosts(domains=[cls.domain_a, cls.domain_b], extras={
            'base': """
            TLSHonorClientOrder off
            """
        })
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
        ecdsa_1_2 = [c for c in self.env.RUSTLS_CIPHERS
                     if c.max_version == 1.2 and c.flavour == 'ECDSA'][0]
        # client speaks only this cipher, see that it gets it
        r = self.env.openssl_client(self.domain_b, extra_args=[
            "-cipher", ecdsa_1_2.openssl_name, "-tls1_2"
        ])
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == ecdsa_1_2.openssl_name, r.stdout

    def test_06_ciphers_rsa(self):
        rsa_1_2 = [c for c in self.env.RUSTLS_CIPHERS
                   if c.max_version == 1.2 and c.flavour == 'RSA'][0]
        # client speaks only this cipher, see that it gets it
        r = self.env.openssl_client(self.domain_b, extra_args=[
            "-cipher", rsa_1_2.openssl_name, "-tls1_2"
        ])
        protocol, cipher = self._get_protocol_cipher(r.stdout)
        assert protocol == "TLSv1.2", r.stdout
        assert cipher == rsa_1_2.openssl_name, r.stdout

    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'ECDSA'
    ], ids=[
        c.name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'ECDSA'
    ])
    def test_06_ciphers_server_prefer_ecdsa(self, cipher):
        # Select a ECSDA ciphers as preference and suppress all RSA ciphers.
        # The last is not strictly necessary since rustls prefers ECSDA anyway
        suppress_names = [c.name for c in self.env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'RSA']
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSHonorClientOrder off
            TLSCiphersPrefer {0}
            TLSCiphersSuppress {1}
            """.format(cipher.name, ":".join(suppress_names)),
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.openssl_client(self.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ], ids=[
        c.name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ])
    def test_06_ciphers_server_prefer_rsa(self, cipher):
        # Select a RSA ciphers as preference and suppress all ECDSA ciphers.
        # The last is necessary since rustls prefers ECSDA and openssl leaks that it can.
        suppress_names = [c.name for c in self.env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'ECDSA']
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSHonorClientOrder off
            TLSCiphersPrefer {0}
            TLSCiphersSuppress {1}
            """.format(cipher.name, ":".join(suppress_names)),
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.openssl_client(self.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ], ids=[
        c.openssl_name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ])
    def test_06_ciphers_server_prefer_rsa_alias(self, cipher):
        # same as above, but using openssl names for ciphers
        suppress_names = [c.openssl_name for c in self.env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'ECDSA']
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSHonorClientOrder off
            TLSCiphersPrefer {0}
            TLSCiphersSuppress {1}
            """.format(cipher.openssl_name, ":".join(suppress_names)),
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.openssl_client(self.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    @pytest.mark.parametrize("cipher", [
        c for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ], ids=[
        c.id_name for c in TlsTestEnv.RUSTLS_CIPHERS if c.max_version == 1.2 and c.flavour == 'RSA'
    ])
    def test_06_ciphers_server_prefer_rsa_id(self, cipher):
        # same as above, but using openssl names for ciphers
        suppress_names = [c.id_name for c in self.env.RUSTLS_CIPHERS
                          if c.max_version == 1.2 and c.flavour == 'ECDSA']
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSHonorClientOrder off
            TLSCiphersPrefer {0}
            TLSCiphersSuppress {1}
            """.format(cipher.id_name, ":".join(suppress_names)),
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.openssl_client(self.domain_b, extra_args=["-tls1_2"])
        client_proto, client_cipher = self._get_protocol_cipher(r.stdout)
        assert client_proto == "TLSv1.2", r.stdout
        assert client_cipher == cipher.openssl_name, r.stdout

    def test_06_ciphers_pref_unknown(self):
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSCiphersPrefer TLS_MY_SUPER_CIPHER:SSL_WHAT_NOT
            """
        })
        conf.write()
        assert self.env.apache_restart() != 0
        # get a working config again, so that subsequent test cases do not stumble
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b])
        conf.write()
        self.env.apache_restart()

    def test_06_ciphers_pref_unsupported(self):
        # a warning on prefering a known, but not supported cipher
        self.env.apache_error_log_clear()
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSCiphersPrefer TLS_NULL_WITH_NULL_NULL
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        (errors, warnings) = self.env.apache_error_log_count()
        assert errors == 0
        assert warnings == 1

    def test_06_ciphers_supp_unknown(self):
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSCiphersSuppress TLS_MY_SUPER_CIPHER:SSL_WHAT_NOT
            """
        })
        conf.write()
        assert self.env.apache_restart() != 0

    def test_06_ciphers_supp_unsupported(self):
        # no warnings on suppressing known, but not supported ciphers
        self.env.apache_error_log_clear()
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_b: """
            TLSCiphersSuppress TLS_NULL_WITH_NULL_NULL
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        (errors, warnings) = self.env.apache_error_log_count()
        assert errors == 0
        assert warnings == 0

