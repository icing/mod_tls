import os
from typing import List, Union

from test_env import TlsTestEnv


class TlsTestConf:

    def __init__(self, env: TlsTestEnv, name: str = "test.conf"):
        self.env = env
        self.name = name
        self._content = []

    def add(self, text: Union[List[str], str]) -> None:
        if isinstance(text, List):
            self._content.extend(text)
        else:
            self._content.append(text)

    def write(self) -> None:
        with open(os.path.join(self.env.server_conf_dir, self.name), "w") as fd:
            fd.write("\n".join(self._content))