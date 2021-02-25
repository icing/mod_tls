import argparse
import logging
import os
import re
import sys
import time
from datetime import timedelta
from threading import Thread
from tqdm import tqdm  # type: ignore
from typing import Dict, Iterable, List

from test_conf import TlsTestConf
from test_env import TlsTestEnv


log = logging.getLogger(__name__)

class LoadTestException(Exception):
    pass

class H2LoadLogSummary:

    @staticmethod
    def from_file(fpath: str, title: str, duration: timedelta) -> 'H2LoadLogSummary':
        with open(fpath) as fd:
            return H2LoadLogSummary.from_lines(fd.readlines(), title=title, duration=duration)

    @staticmethod
    def from_lines(lines: Iterable[str], title: str, duration: timedelta) -> 'H2LoadLogSummary':
        stati = {}
        count = 0
        all_durations = timedelta(milliseconds=0)
        for line in lines:
            parts = re.split(r'\s+', line)  # start(us), status(int), duration(ms), tbd.
            if len(parts) >= 3 and parts[0] and parts[1] and parts[2]:
                count += 1
                status = int(parts[1])
                if status in stati:
                    stati[status] += 1
                else:
                    stati[status] = 1
                all_durations += timedelta(microseconds=int(parts[2]))
            else:
                sys.stderr.write("unrecognize log line: {0}".format(line))
        return H2LoadLogSummary(title=title, total=count, stati=stati,
                                duration=duration, all_durations=all_durations)

    def __init__(self, title: str, total: int, stati: Dict[int, int],
                 duration: timedelta, all_durations: timedelta):
        self._title = title
        self._total = total
        self._stati = stati
        self._duration = duration
        self._all_durations = all_durations
        self._transfered_mb = 0.0

    @property
    def title(self) -> int:
        return self._title

    @property
    def response_count(self) -> int:
        return self._total

    @property
    def duration(self) -> timedelta:
        return self._duration

    @property
    def response_durations(self) -> timedelta:
        return self._all_durations

    @property
    def response_stati(self) -> Dict[int, int]:
        return self._stati

    def all_200(self) -> bool:
        non_200s = [n for n in self._stati.keys() if n != 200]
        return len(non_200s) == 0

    @property
    def throughput_mb(self) -> float:
        if self._transfered_mb > 0.0:
            return self._transfered_mb / self.duration.total_seconds()
        return 0.0

    def set_transfered_mb(self, mb: float) -> None:
        self._transfered_mb = mb


class H2LoadMonitor:

    def __init__(self, fpath: str, expected: int, title: str):
        self._fpath = fpath
        self._expected = expected
        self._title = title
        self._tqdm = tqdm(desc=title, total=expected, unit="request", leave=False)
        self._running = False
        self._lines = ()

    def start(self):
        self._tail = Thread(target=self._collect, kwargs={'self': self})
        self._running = True
        self._tail.start()

    def get_summary(self, duration: timedelta) -> H2LoadLogSummary:
        self._running = False
        self._tail.join()
        return H2LoadLogSummary.from_file(self._fpath, title=self._title, duration=duration)

    def stop(self):
        self._running = False

    @staticmethod
    def _collect(self) -> None:
        first_call = True
        line_count = 0
        while self._running:
            try:
                with open(self._fpath) as fd:
                    if first_call:
                        fd.seek(0, 2)
                        first_call = False
                    latest_data = fd.read()
                    while self._running:
                        if '\n' not in latest_data:
                            latest_data += fd.read()
                            if '\n' not in latest_data:
                                if not os.path.isfile(self._fpath):
                                    break
                                time.sleep(0.1)
                                continue
                        lines = latest_data.split('\n')
                        if lines[-1] != '\n':
                            latest_data = lines[-1]
                            lines = lines[:-1]
                        else:
                            latest_data = None
                        self._tqdm.update(n=len(lines))
                        if latest_data is None:
                            latest_data = fd.read()
            except IOError:
                time.sleep(0.1)
        self._tqdm.close()


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

    def _setup(self, module: str, resource_kb: int, log_level: str = "info") -> str:
        conf = TlsTestConf(env=self.env)
        extras = {
            'base': """
        LogLevel tls:{log_level}
        Protocols h2 http/1.1
        """.format(
                log_level=log_level,
            )
        }
        if 'mod_tls' == module:
            conf.add_vhosts(domains=[self.domain_a], extras=extras)
        elif 'mod_ssl' == module:
            conf.add_ssl_vhosts(domains=[self.domain_a], extras=extras)
        else:
            raise LoadTestException("tests for module: {0}".format(module))
        conf.write()
        docs_a = os.path.join(self.env.server_docs_dir, self.domain_a)
        fname = "{0}k.txt".format(resource_kb)
        self.mk_text_file(os.path.join(docs_a, fname), 8 * resource_kb)
        assert self.env.apache_restart() == 0
        return "/{0}".format(fname)

    def _teardown(self):
        if self.env.is_live(timeout=timedelta(milliseconds=100)):
            assert self.env.apache_stop() == 0

    def run(self, clients: int, requests: int, resource_kb: int,
            module: str = 'mod_tls', http_version: int = 2,
            threads: int = None, log_level: str = "info"
            ) -> H2LoadLogSummary:
        resource_path = self._setup(module=module, resource_kb=resource_kb,
                                    log_level=log_level)
        threads = threads if threads is not None else min(16, clients)
        monitor = None
        try:
            log_file = "{gen_dir}/h2load.log".format(gen_dir=self.env.gen_dir)
            if os.path.isfile(log_file):
                os.remove(log_file)
            monitor = H2LoadMonitor(log_file, expected=requests,
                                    title="{module}/h{http_version}/{conn}c/{kb}MB".format(
                                        conn=clients,
                                        module=module,
                                        kb=(resource_kb/1024),
                                        http_version=http_version
                                    ))
            monitor.start()
            args = [
                'h2load',
                '--clients={0}'.format(clients),
                '--threads={0}'.format(threads),
                '--requests={0}'.format(requests),
                '--log-file={0}'.format(log_file),
                '--connect-to=localhost:{0}'.format(self.env.https_port)
            ]
            if http_version == 1:
                args.append('--h1')
            r = self.env.run(args + [
                'https://{0}:{1}{2}'.format(self.domain_a, self.env.https_port, resource_path)
            ])
            if r.exit_code != 0:
                raise LoadTestException("h2load returned {0}: {1}".format(r.exit_code, r.stderr))
            summary = monitor.get_summary(duration=r.duration)
            summary.set_transfered_mb(requests * resource_kb / 1024)
            return summary
        finally:
            if monitor is not None:
                monitor.stop()
            self._teardown()

    @staticmethod
    def print_table(table: List[List[str]]):
        col_widths = []
        col_sep = "   "
        for row in table[1:]:
            for idx, cell in enumerate(row):
                if idx >= len(col_widths):
                    col_widths.append(len(cell))
                else:
                    col_widths[idx] = max(len(cell), col_widths[idx])
        row_len = sum(col_widths) + (len(col_widths) * len(col_sep))
        print(f"{' '.join(table[0]):^{row_len}}")
        for row in table[1:]:
            line = ""
            for idx, cell in enumerate(row):
                line += f"{col_sep if idx > 0 else ''}{cell:>{col_widths[idx]}}"
            print(line)

    @classmethod
    def main(cls):
        parser = argparse.ArgumentParser(prog='load_h1', description="""
            Run a range of load tests against the test Apache setup.
            """)
        parser.add_argument("-c", "--case", type=str, default=None,
                            help="which load case to run, defaults to all")
        parser.add_argument("-v", "--verbose", action='count', default=0,
                            help="log more output on stderr")
        args = parser.parse_args()

        if args.verbose > 0:
            console = logging.StreamHandler()
            console.setLevel(logging.DEBUG)
            console.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
            logging.getLogger('').addHandler(console)

        try:
            log.debug("starting tests")
            load = LoadTest(env=TlsTestEnv())

            for scenario in [
                {
                    "title": "1 conn, 1k-10k requests, sizes and throughput (MB/s)",
                    "base": {"clients": 1},
                    "row0_title": "module protocol",
                    "row_title": "{module} h{http}",
                    "rows": [
                        {"module": "mod_ssl", "http": 1},
                        {"module": "mod_tls", "http": 1},
                        {"module": "mod_ssl", "http": 2},
                        {"module": "mod_tls", "http": 2},
                    ],
                    "col_title": "{rsize}KB",
                    "columns": [
                        {"requests": 1000, "rsize": 10 * 1024},
                        {"requests": 1000, "rsize": 1024},
                        {"requests": 5000, "rsize": 100},
                        {"requests": 10000, "rsize": 10},
                    ],
                }
            ]:
                table = [
                    [scenario['title']],
                ]
                headers = [scenario['row0_title']]
                for col in scenario['columns']:
                    headers.append(scenario['col_title'].format(**col))
                table.append(headers)
                cls.print_table(table)
                for row in scenario['rows']:
                    row_line = [scenario['row_title'].format(**row)]
                    table.append(row_line)
                    for col in scenario['columns']:
                        t = scenario['base'].copy()
                        t.update(row)
                        t.update(col)
                        summary = load.run(clients=t['clients'], requests=t['requests'],
                                           resource_kb=t['rsize'],
                                           module=t['module'], http_version=t['http'])
                        if summary.response_count != t['requests']:
                            sys.stderr.write("responses missing: {0}, expected {1}\n".format(
                                summary.response_count, t['requests']))
                            sys.exit(1)
                        if not summary.all_200():
                            sys.stderr.write("errors in responses:")
                            for status in [n for n in summary.response_stati.keys() if n != 200]:
                                sys.stderr.write(" {0}={1}".format(status, summary.response_stati[status]))
                            sys.stderr.write("\n")
                            sys.exit(1)
                        row_line.append("{1:.1f}".format(summary.title, summary.throughput_mb))
                        cls.print_table(table)
        except KeyboardInterrupt:
            sys.exit(1)
        except LoadTestException as ex:
            sys.stderr.write(str(ex))
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    LoadTest.main()
