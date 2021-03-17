import json
import sys
import time
from datetime import timedelta

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestVars:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': "LogLevel trace4",
            cls.env.domain_b: """
            TLSOptions StdEnvVars
            <Location /dir1>
                TLSOptions -StdEnvVars
            </Location>
            """
        })
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def test_08_vars(self):
        # in domain_b root, the StdEnvVars is switch on
        r = self.env.https_get(self.env.domain_b, "/vars.py")
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'https': 'on',
            'host': 'b.mod-tls.test',
            'protocol': 'HTTP/1.1',
            'ssl_protocol': 'TLSv1.2',
            'ssl_cipher': 'ECDHE-RSA-AES128-GCM-SHA256',
        }, r.stdout

    def test_08_vars_dir1(self):
        # in dir1, the StdEnvVars is switch off
        r = self.env.https_get(self.env.domain_b, "/dir1/vars.py")
        assert r.exit_code == 0, r.stderr
        assert r.json == {
            'https': 'on',
            'host': 'b.mod-tls.test',
            'protocol': 'HTTP/1.1',
            'ssl_protocol': '',
            'ssl_cipher': '',
        }, r.stdout
