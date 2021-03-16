import re
import time
from datetime import timedelta
from typing import List

from test_env import TlsTestEnv, ExecResult
from test_conf import TlsTestConf


class TestSessionID:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @classmethod
    def setup_class(cls):
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.env.domain_a, cls.env.domain_b], extras={
            'base': """
            LogLevel socache_shmcb:trace8
            """,
        })
        conf.write()
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def find_openssl_session_ids(self, r: ExecResult) -> List[str]:
        ids = []
        for line in r.stdout.splitlines():
            m = re.match(r'^\s*Session-ID: (\S+)$', line)
            if m:
                ids.append(m.group(1))
        return ids

    def test_10_session_id_default(self):
        r = self.env.openssl_client(self.env.domain_b, extra_args=[
            "-reconnect"
        ])
        session_ids = self.find_openssl_session_ids(r)
        assert 1 < len(session_ids), "expected several session-ids: {0}".format(session_ids)
        assert 1 == len(set(session_ids)), "sesion-ids should all be the same: {0}".format(session_ids)
