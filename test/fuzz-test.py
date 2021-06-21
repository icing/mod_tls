import argparse
import logging
import multiprocessing
import os
import re
import sys
import time
from datetime import timedelta, datetime
from threading import Thread
from tqdm import tqdm  # type: ignore
from typing import Dict, Iterable, List, Tuple, Optional

from test_conf import TlsTestConf
from test_env import TlsTestEnv, ExecResult

log = logging.getLogger(__name__)


class FuzzTestException(Exception):
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
        self._exec_result = None
        self._expected_responses = 0

    @property
    def title(self) -> str:
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

    @property
    def expected_responses(self) -> int:
        return self._expected_responses

    @property
    def execution(self) -> ExecResult:
        return self._exec_result

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

    def set_exec_result(self, result: ExecResult):
        self._exec_result = result

    def set_expected_responses(self, n: int):
        self._expected_responses = n

    def get_footnote(self) -> Optional[str]:
        notes = []
        note = ""
        if self.expected_responses > 0 and \
                self.response_count != self.expected_responses:
            note += "{0}/{1} missing".format(
                self.expected_responses - self.response_count,
                self.expected_responses
            )
        if not self.all_200():
            note += ", non 200s:"
            for status in [n for n in self.response_stati.keys() if n != 200]:
                note += " {0}={1}".format(status, self.response_stati[status])
        return note if len(note) else None


class H2LoadMonitor:

    def __init__(self, fpath: str, expected: int, title: str):
        self._fpath = fpath
        self._expected = expected
        self._title = title
        self._tqdm = tqdm(desc=title, total=expected, unit="request", leave=False)
        self._running = False
        self._lines = ()
        self._tail = None

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


class FuzzTestCase:

    @staticmethod
    def from_scenario(scenario: Dict, env: TlsTestEnv) -> 'FuzzTest':
        raise NotImplemented

    def run(self) -> H2LoadLogSummary:
        raise NotImplemented

    def format_result(self, summary: H2LoadLogSummary) -> str:
        raise NotImplemented

    def setup_base_conf(self, env: TlsTestEnv, worker_count: int = 5000) -> TlsTestConf:
        conf = TlsTestConf(env=env)
        # ylavic's formula
        process_count = int(max(10, min(100, int(worker_count / 100))))
        thread_count = int(max(25, worker_count / process_count))
        conf.add(f"""
        StartServers             1
        ServerLimit              {int(process_count * 2.5)}
        ThreadLimit              {thread_count}
        ThreadsPerChild          {thread_count}
        MinSpareThreads          {thread_count}
        MaxSpareThreads          {int(worker_count / 2)}
        MaxRequestWorkers        {worker_count}
        MaxConnectionsPerChild   0
        KeepAliveTimeout         60
        MaxKeepAliveRequests     0
        """)
        return conf

    def start_server(self, cd: timedelta = None):
        if self.env.apache_stop() == 0 and cd:
            with tqdm(desc="connection cooldown", total=int(cd.total_seconds()), unit="s", leave=False) as t:
                end = datetime.now() + cd
                while datetime.now() < end:
                    time.sleep(1)
                    t.update()
        assert self.env.apache_start() == 0


class SingleUrlFuzzTest(FuzzTestCase):

    def __init__(self, env: TlsTestEnv, server: str, clients: int,
                 protocol: str = 'h2', duration: timedelta = None):
        self.env = env
        self.domain = self.env.domain_b
        self._server = server
        self._clients = clients
        self._protocol = protocol
        self._duration = duration
        self._requests = 2
        self._threads = min(multiprocessing.cpu_count()/2, self._clients)
        self._url_file = "{gen_dir}/h2load-urls.txt".format(gen_dir=self.env.gen_dir)
        self._url_paths = ["/resp-jitter.py"]

    @staticmethod
    def from_scenario(scenario: Dict, env: TlsTestEnv) -> 'SingleUrlFuzzTest':
        def get_val(d, key, defval):
            return d[key] if key in d else defval

        return SingleUrlFuzzTest(
            env=env,
            server=scenario['server'],
            clients=scenario['clients'],
            protocol=get_val(scenario, 'protocol', 'h2'),
            duration=get_val(scenario, 'duration', timedelta(seconds=30))
        )

    def _setup(self) -> str:
        conf = self.setup_base_conf(env=self.env)
        extras = {
            'base': self._server
        }
        conf.add_vhosts(domains=[self.domain], extras=extras)
        conf.write()
        self.start_server()
        with open(self._url_file, 'w') as fd:
            fd.write("\n".join(self._url_paths))
            fd.write("\n")
        return "/resp-jitter.py"

    def _teardown(self):
        if self.env.is_live(timeout=timedelta(milliseconds=100)):
            assert self.env.apache_stop() == 0

    def run_test(self, mode: str, path: str) -> H2LoadLogSummary:
        monitor = None
        try:
            log_file = "{gen_dir}/h2load.log".format(gen_dir=self.env.gen_dir)
            if os.path.isfile(log_file):
                os.remove(log_file)
            monitor = H2LoadMonitor(log_file, expected=0,
                                    title=f"{self._protocol}/"\
                                          f"{self._clients}c/{self._duration.total_seconds()}s")
            monitor.start()
            args = [
                'h2load',
                '--clients={0}'.format(self._clients),
                '--requests={0}'.format(self._requests * self._clients),
                '--input-file={0}'.format(self._url_file),
                '--log-file={0}'.format(log_file),
                '--connect-to=localhost:{0}'.format(self.env.https_port)
            ]
            if self._protocol == 'h1' or self._protocol == 'http/1.1':
                args.append('--h1')
            elif self._protocol == 'h2':
                args.extend(['-m', "6"])
            else:
                raise Exception(f"unknown protocol: {self._protocol}")
            args += [
                '--base-uri=https://{0}:{1}/'.format(
                    self.domain, self.env.https_port)
            ]
            end = datetime.now() + self._duration
            while datetime.now() < end:
                r = self.env.run(args)
                if r.exit_code != 0:
                    raise FuzzTestException("h2load returned {0}: {1}".format(r.exit_code, r.stderr))
            summary = monitor.get_summary(duration=self._duration)
            summary.set_exec_result(r)
            return summary
        finally:
            if monitor is not None:
                monitor.stop()

    def run(self) -> H2LoadLogSummary:
        path = self._setup()
        try:
            return self.run_test(mode="fuzz", path=path)
        finally:
            self._teardown()

    def format_result(self, summary: H2LoadLogSummary) -> Tuple[str, List[str]]:
        return 'ok' if summary.all_200() else 'x', summary.get_footnote()


class FuzzTest:

    @staticmethod
    def print_table(table: List[List[str]], foot_notes: List[str] = None):
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
        if foot_notes is not None:
            for idx, note in enumerate(foot_notes):
                print("{0:3d}) {1}".format(idx+1, note))

    @staticmethod
    def scenario_with(base: Dict, updates: Dict) -> Dict:
        scenario = base.copy()
        scenario.update(updates)
        return scenario

    @classmethod
    def main(cls):
        parser = argparse.ArgumentParser(prog='load_h1', description="""
            Run a range of fuzz tests against the test Apache setup.
            """)
        parser.add_argument("-d", "--duration", type=float, default=120,
                            help="how long it shall run (seconds)")
        parser.add_argument("-p", "--protocol", type=str, default=None,
                            help="which protocols to test, defaults to all")
        parser.add_argument("-v", "--verbose", action='count', default=0,
                            help="log more output on stderr")
        parser.add_argument("names", nargs='*', help="Name(s) of scenarios to run")
        args = parser.parse_args()

        if args.verbose > 0:
            console = logging.StreamHandler()
            console.setLevel(logging.INFO)
            console.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
            logging.getLogger('').addHandler(console)

        try:
            log.debug("starting tests")

            server_config = """
        LogLevel tls:warn
        LogLevel ssl:warn
        Protocols h2 http/1.1
                """

            scenario_s = {
                "title": "sizes and throughput (MB/s)",
                "class": SingleUrlFuzzTest,
                "server": server_config,
                "clients": 1,
                "requests": 1,
                "duration": timedelta(seconds=120),
                "row0_title": "protocol",
                "row_title": "{protocol}",
                "rows": [
                    {"protocol": 'h1'},
                    {"protocol": 'h2'},
                ],
                "col_title": "",
                "columns": [],
            }

            scenarios = {
                "resp-jitter": cls.scenario_with(scenario_s, {
                    "title": "",
                    "clients": 1,
                    "col_title": "{clients}c",
                    "columns": [
                        {"clients": 128},
                    ],
                }),
            }
            for name in args.names:
                if name not in scenarios:
                    raise FuzzTestException(f"scenario unknown: '{name}'")
            names = args.names if len(args.names) else sorted(scenarios.keys())

            env = TlsTestEnv()
            for name in names:
                scenario = scenarios[name]
                table = [
                    [scenario['title']],
                ]
                foot_notes = []
                headers = [scenario['row0_title']]
                for col in scenario['columns']:
                    headers.append(scenario['col_title'].format(**col))
                table.append(headers)
                cls.print_table(table)
                for row in scenario['rows']:
                    if args.protocol is not None and row['protocol'] != args.protocol:
                        continue
                    row_line = [scenario['row_title'].format(**row)]
                    table.append(row_line)
                    for col in scenario['columns']:
                        t = scenario.copy()
                        t.update(row)
                        t.update(col)
                        t['duration'] = timedelta(seconds=args.duration)
                        test = scenario['class'].from_scenario(t, env=env)
                        env.apache_error_log_clear()
                        summary = test.run()
                        result, fnote = test.format_result(summary)
                        if fnote:
                            foot_notes.append(fnote)
                        row_line.append("{0}{1}".format(result,
                            f"[{len(foot_notes)}]" if fnote else ""
                        ))
                        cls.print_table(table, foot_notes)
        except KeyboardInterrupt:
            sys.exit(1)
        except FuzzTestException as ex:
            sys.stderr.write(f"ERROR: {str(ex)}\n")
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    FuzzTest.main()
