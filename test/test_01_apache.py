import pytest

from test_conf import TlsTestConf

class TestApache:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TlsTestConf(env=env).write()
        assert env.apache_restart() == 0
        yield
        assert env.apache_stop() == 0

    def test_01_apache_http(self, env):
        assert env.is_live(env.http_base_url)