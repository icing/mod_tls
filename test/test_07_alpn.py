import re
from datetime import timedelta

import pytest

from test_conf import TlsTestConf


class TestAlpn:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_vhosts(domains=[env.domain_a, env.domain_b], extras={
            env.domain_b: """
        Protocols h2 http/1.1"""
        })
        conf.write()
        assert env.apache_restart() == 0
        yield
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def _get_protocol(self, output: str):
        for line in output.splitlines():
            m = re.match(r'^\*\s+ALPN, server accepted to use\s+(.*)$', line)
            if m:
                return m.group(1)
        return None

    def test_07_alpn_get_a(self, env):
        # do we see the correct json for the domain_a?
        r = env.https_get(env.domain_a, "/index.json", extra_args=["-vvvvvv"])
        assert r.exit_code == 0, r.stderr
        protocol = self._get_protocol(r.stderr)
        assert protocol == "http/1.1", r.stderr

    def test_07_alpn_get_b(self, env):
        # do we see the correct json for the domain_a?
        r = env.https_get(env.domain_b, "/index.json", extra_args=["-vvvvvv"])
        assert r.exit_code == 0, r.stderr
        protocol = self._get_protocol(r.stderr)
        assert protocol == "h2"
