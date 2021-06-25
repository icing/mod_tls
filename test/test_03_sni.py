from datetime import timedelta

import pytest

from test_conf import TlsTestConf


class TestSni:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_vhosts(domains=[env.domain_a, env.domain_b])
        conf.write()
        assert env.apache_restart() == 0
        env.curl_supports_tls_1_3()  # init
        yield
        if env.is_live(timeout=timedelta(milliseconds=100)):
            assert env.apache_stop() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    def test_03_sni_get_a(self, env):
        # do we see the correct json for the domain_a?
        data = env.https_get_json(env.domain_a, "/index.json")
        assert data == {'domain': env.domain_a}

    def test_03_sni_get_b(self, env):
        # do we see the correct json for the domain_a?
        data = env.https_get_json(env.domain_b, "/index.json")
        assert data == {'domain': env.domain_b}

    def test_03_sni_unknown(self, env):
        # connection will be denied as cert does not cover this domain
        domain_unknown = "unknown.test"
        r = env.https_get(domain_unknown, "/index.json")
        assert r.exit_code != 0

    def test_03_sni_request_other_same_config(self, env):
        # do we see the first vhost respone for an unknown domain?
        r = env.https_get(env.domain_a, "/index.json", extra_args=[
            "-vvvv", "--header", "Host: {0}".format(env.domain_b)
        ])
        # request goes through, we see the correct JSON
        assert r.exit_code == 0
        assert r.json == {'domain': env.domain_b}

    def test_03_sni_request_other_other_honor(self, env):
        if env.curl_supports_tls_1_3():
            # can't do this test then
            return
        # do we see the first vhost respone for an unknown domain?
        conf = TlsTestConf(env=env)
        conf.add_vhosts(domains=[env.domain_a, env.domain_b], extras={
            env.domain_a: """
    TLSProtocol TLSv1.2+
            """,
            env.domain_b: """
        TLSProtocol TLSv1.3+
                """
        })
        conf.write()
        assert env.apache_restart() == 0
        r = env.https_get(env.domain_a, "/index.json", extra_args=[
            "-vvvv", "--header", "Host: {0}".format(env.domain_b)
        ])
        # request denied
        assert r.exit_code == 0
        assert r.json is None

    def test_03_sni_bad_hostname(self, env):
        # curl checks hostnames we give it, but the openssl client
        # does not. Good for us, since we need to test it.
        r = env.openssl(["s_client", "-connect",
                          "localhost:{0}".format(env.https_port),
                          "-servername", b'x\x2f.y'.decode()])
        assert r.exit_code == 1, r.stderr
