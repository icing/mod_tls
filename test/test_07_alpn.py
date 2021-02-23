import re
from datetime import timedelta

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestAlpn:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @classmethod
    def setup_class(cls):
        cls.domain_a = cls.env.domain_a
        cls.domain_b = cls.env.domain_b
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.domain_a, cls.domain_b], extras={
            cls.domain_b: """
    Protocols h2 http/1.1"""
        })
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        pass

    def _get_protocol(self, output: str):
        for line in output.splitlines():
            m = re.match(r'^\*\s+ALPN, server accepted to use\s+(.*)$', line)
            if m:
                return m.group(1)
        return None

    def test_07_alpn_get_a(self):
        # do we see the correct json for the domain_a?
        r = self.env.https_get(self.domain_a, "/index.json", extra_args=["-vvvvvv"])
        assert r.exit_code == 0, r.stderr
        protocol = self._get_protocol(r.stderr)
        assert protocol == "http/1.1", r.stderr

    def test_07_alpn_get_b(self):
        # do we see the correct json for the domain_a?
        r = self.env.https_get(self.domain_b, "/index.json", extra_args=["-vvvvvv"])
        assert r.exit_code == 0, r.stderr
        protocol = self._get_protocol(r.stderr)
        assert protocol == "h2"
