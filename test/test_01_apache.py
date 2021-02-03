from test_env import TlsTestEnv


class TestApache:

    env = TlsTestEnv()

    @classmethod
    def setup_class(cls):
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        print("teardown_class:%s" % cls.__name__)
        assert cls.env.apache_stop() == 0

    def test_01_apache_http(self):
        assert self.env.is_live(self.env.http_base_url)