from datetime import timedelta

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestSni:

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

    def test_03_sni_get_a(self):
        # do we see the correct json for the domain_a?
        data = self.env.https_get_json(self.domain_a, "/index.json")
        assert data == {'domain': self.domain_a}

    def test_03_sni_get_b(self):
        # do we see the correct json for the domain_a?
        data = self.env.https_get_json(self.domain_b, "/index.json")
        assert data == {'domain': self.domain_b}

    def test_03_sni_unknown(self):
        # do we see the first vhost respone for an unknown domain?
        domain_unknown = "unknown.test"
        data = self.env.https_get_json(domain_unknown, "/index.json")
        assert data == {'domain': self.domain_a}

    def test_03_sni_request_other_same_config(self):
        # do we see the first vhost respone for an unknown domain?
        r = self.env.https_get(self.domain_a, "/index.json", extra_args=[
            "-vvvv", "--header", "Host: {0}".format(self.domain_b)
        ])
        # request goes through, we see the correct JSON
        assert r.exit_code == 0
        assert r.json == {'domain': self.domain_b}

    def test_03_sni_request_other_other_honor(self):
        # do we see the first vhost respone for an unknown domain?
        conf = TlsTestConf(env=self.env)
        conf.add_vhosts(domains=[self.domain_a, self.domain_b], extras={
            self.domain_a: """
    TLSHonorClientOrder on
            """
        })
        conf.write()
        assert self.env.apache_restart() == 0
        r = self.env.https_get(self.domain_a, "/index.json", extra_args=[
            "-vvvv", "--header", "Host: {0}".format(self.domain_b)
        ])
        # request denied
        assert r.exit_code == 0
        assert r.json is None
