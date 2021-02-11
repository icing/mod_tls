from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestProto:

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

    @pytest.mark.parametrize("proto", [
        "",
        "--tlsv1.2",
        # "--tlsv1.3",  # not supported by native macos curl
    ])
    def test_05_proto_default(self, proto: str):
        # do we see the correct json for the domain_a?
        r = self.env.https_get(self.domain_a, "/index.json",
                               extra_args=[proto])
        assert r.exit_code == 0, r.stderr

