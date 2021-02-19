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

    def _get_cipher(self, output: str):
        for line in output.splitlines():
            m = re.match(r'^\*\s+Cipher selection:\s+(.*)$', line)
            if m:
                return m.group(1)
        for line in output.splitlines():
            m = re.match(r'^\*\s+SSL connection using\s+(.*)\s+/\s+(.*)$', line)
            if m:
                return m.group(2)
        return None

    def test_06_ciphers_ecdsa(self):
        # do we see the correct json for the domain_a?
        r = self.env.https_get(self.domain_b, "/index.json", extra_args=[
            "-vvvvvv", "--cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"
        ])
        assert r.exit_code == 0, r.stderr
        cipher = self._get_cipher(r.stderr)
        assert cipher == "ECDHE-ECDSA-AES256-GCM-SHA384"

    def test_06_ciphers_rsa(self):
        # do we see the correct json for the domain_a?
        r = self.env.https_get(self.domain_b, "/index.json", extra_args=[
            "-vvvvvv", "--cipher", "ECDHE-RSA-AES256-GCM-SHA384"
        ])
        assert r.exit_code == 0, r.stderr
        cipher = self._get_cipher(r.stderr)
        assert cipher == "ECDHE-RSA-AES256-GCM-SHA384"


