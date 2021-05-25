import os
import time
from datetime import timedelta

import pytest

from test_env import TlsTestEnv
from test_conf import TlsTestConf


class TestGet:

    env = TlsTestEnv()
    domain_a = None
    domain_b = None

    @staticmethod
    def mk_text_file(fpath:str, lines: int):
        t110 = 11 * "0123456789"
        with open(fpath, "w") as fd:
            for i in range(lines):
                fd.write("{0:015d}: ".format(i)) # total 128 bytes per line
                fd.write(t110)
                fd.write("\n")


    @classmethod
    def setup_class(cls):
        cls.domain_a = cls.env.domain_a
        cls.domain_b = cls.env.domain_b
        conf = TlsTestConf(env=cls.env)
        conf.add_vhosts(domains=[cls.domain_a, cls.domain_b], extras={
            'base': """
            LogLevel tls:trace8
            """,
        })
        conf.write()
        docs_a = os.path.join(cls.env.server_docs_dir, cls.domain_a)
        cls.mk_text_file(os.path.join(docs_a, "1k.txt"), 8)
        cls.mk_text_file(os.path.join(docs_a, "10k.txt"), 80)
        cls.mk_text_file(os.path.join(docs_a, "100k.txt"), 800)
        cls.mk_text_file(os.path.join(docs_a, "1m.txt"), 8000)
        cls.mk_text_file(os.path.join(docs_a, "10m.txt"), 80000)
        assert cls.env.apache_restart() == 0

    @classmethod
    def teardown_class(cls):
        if cls.env.is_live(timeout=timedelta(milliseconds=100)):
            assert cls.env.apache_stop() == 0

    def setup_method(self, _method):
        pass

    @pytest.mark.parametrize("fname, flen", [
        ("1k.txt", 1024),
        ("10k.txt", 10*1024),
        ("100k.txt", 100 * 1024),
        ("1m.txt", 1000 * 1024),
        ("10m.txt", 10000 * 1024),
    ])
    def test_04_get(self, fname, flen):
        # do we see the correct json for the domain_a?
        docs_a = os.path.join(self.env.server_docs_dir, self.domain_a)
        r = self.env.https_get(self.domain_a, "/{0}".format(fname))
        assert r.exit_code == 0
        assert len(r.stdout) == flen
        pref = os.path.join(docs_a, fname)
        pout = os.path.join(docs_a, "{0}.out".format(fname))
        with open(pout, 'w') as fd:
            fd.write(r.stdout)
        dr = self.env.run_diff(pref, pout)
        assert dr.exit_code == 0, "differences found:\n{0}".format(dr.stdout)

    @pytest.mark.parametrize("fname, flen", [
        ("1k.txt", 1024),
    ])
    def test_04_double_get(self, fname, flen):
        # we'd like to check that we can do >1 requests on the same connection
        # however curl hides that from us, unless we analyze its verbose output
        docs_a = os.path.join(self.env.server_docs_dir, self.domain_a)
        r = self.env.https_get(self.domain_a, paths=[
            "/{0}".format(fname),
            "/{0}".format(fname)
        ])
        assert r.exit_code == 0
        assert len(r.stdout) == 2*flen
