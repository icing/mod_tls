import argparse
import os
import sys
from datetime import timedelta

from test_conf import TlsTestConf
from test_env import TlsTestEnv, ExecResult


class LoadTest:

    def __init__(self, env: TlsTestEnv):
        self.env = env
        self.domain_a = self.env.domain_a

    @staticmethod
    def mk_text_file(fpath: str, lines: int):
        t110 = ""
        for _ in range(11):
            t110 += "0123456789"
        with open(fpath, "w") as fd:
            for i in range(lines):
                fd.write("{0:015d}: ".format(i))  # total 128 bytes per line
                fd.write(t110)
                fd.write("\n")

    def _setup(self, module: str, resource_kb: int) -> str:
        conf = TlsTestConf(env=self.env)
        extras = {
            'base': """
        LogLevel tls:info
        Protocols h2 http/1.1
        """
        }
        if 'mod_tls' == module:
            conf.add_vhosts(domains=[self.domain_a], extras=extras)
        elif 'mod_ssl' == module:
            conf.add_ssl_vhosts(domains=[self.domain_a], extras=extras)
        else:
            raise NotImplementedError("tests for module: {0}".format(module))
        conf.write()
        docs_a = os.path.join(self.env.server_docs_dir, self.domain_a)
        fname = "{0}k.txt".format(resource_kb)
        self.mk_text_file(os.path.join(docs_a, fname), 8*resource_kb)
        assert self.env.apache_restart() == 0
        return "/{0}".format(fname)

    def _teardown(self):
        if self.env.is_live(timeout=timedelta(milliseconds=100)):
            assert self.env.apache_stop() == 0

    def run(self, clients: int, requests: int, resource_kb: int,
            module: str = 'mod_tls', http_version: int = 2,
            threads: int = None) -> ExecResult:
        resource_path = self._setup(module=module, resource_kb=resource_kb)
        threads = threads if threads is not None else min(16, clients)
        try:
            args = [
                'h2load',
                '--clients={0}'.format(clients),
                '--threads={0}'.format(threads),
                '--requests={0}'.format(requests),
                '--log-file=h2load.log',
                '--connect-to=localhost:{0}'.format(self.env.https_port)
            ]
            if http_version == 1:
                args.append('--h1')
            r = self.env.run(args + [
                'https://{0}:{1}{2}'.format(self.domain_a, self.env.https_port, resource_path)
            ])
            return r
        finally:
            self._teardown()

    @classmethod
    def main(cls):
        parser = argparse.ArgumentParser(prog='load_h1', description="""
            Run a range of load tests against the test Apache setup.
            """)
        parser.add_argument("-c", "--case", type=str, default=None,
                            help="which load case to run, defaults to all")
        load = LoadTest(env=TlsTestEnv())
        r = load.run(clients=1, requests=1000, resource_kb=10*1024, module="mod_tls", http_version=2)
        print(r.stdout)
        print(r.stderr)

        sys.exit(r.exit_code)


if __name__ == "__main__":
    LoadTest.main()
