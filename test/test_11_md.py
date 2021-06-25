import time
from datetime import timedelta

import pytest

from test_conf import TlsTestConf


class TestMD:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_md_vhosts(domains=[env.domain_a, env.domain_b], extras={
            'base': """
            LogLevel tls:trace4 md:trace4
            """
        })
        conf.write()
        assert env.apache_restart() == 0
        yield
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    def test_11_get_a(self, env):
        # do we see the correct json for the domain_a?
        data = env.https_get_json(env.domain_a, "/index.json")
        assert data == {'domain': env.domain_a}

    def test_11_get_b(self, env):
        # do we see the correct json for the domain_a?
        data = env.https_get_json(env.domain_b, "/index.json")
        assert data == {'domain': env.domain_b}

    def test_11_get_base(self, env):
        # give the base server domain_a and lookup its index.json
        conf = TlsTestConf(env=env)
        conf.add_md_base(domain=env.domain_a)
        conf.write()
        assert env.apache_restart() == 0
        data = env.https_get_json(env.domain_a, "/index.json")
        assert data == {'domain': 'localhost'}
