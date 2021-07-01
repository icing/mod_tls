import logging
import os
from datetime import timedelta

import pytest

from test_cert import TlsTestCA, CertificateSpec
from test_env import TlsTestEnv


def pytest_report_header(config, startdir):
    env = TlsTestEnv()
    return "mod_tls [apache: {aversion}({prefix})]".format(
        prefix=env.prefix,
        aversion=env.get_httpd_version()
    )


@pytest.fixture(scope="session")
def env() -> TlsTestEnv:
    level = logging.INFO
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logging.getLogger('').addHandler(console)
    logging.getLogger('').setLevel(level=level)
    env = TlsTestEnv()
    cert_specs = [
        CertificateSpec(domains=[env.domain_a]),
        CertificateSpec(domains=[env.domain_b], key_type='secp256r1', single_file=True),
        CertificateSpec(domains=[env.domain_b], key_type='rsa4096'),
        CertificateSpec(name="clientsX", sub_specs=[
            CertificateSpec(name="user1", client=True, single_file=True),
            CertificateSpec(name="user2", client=True, single_file=True),
            CertificateSpec(name="user_expired", client=True,
                            single_file=True, valid_from=timedelta(days=-91),
                            valid_to=timedelta(days=-1)),
        ]),
        CertificateSpec(name="clientsY", sub_specs=[
            CertificateSpec(name="user1", client=True, single_file=True),
        ]),
        CertificateSpec(name="user1", client=True, single_file=True),
    ]
    ca = TlsTestCA.create_root(name="abetterinternet-mod_tls",
                               store_dir=os.path.join(env.server_dir, 'ca'), key_type="rsa4096")
    ca.issue_certs(cert_specs)
    env.set_ca(ca)
    return env

@pytest.fixture(autouse=True, scope="session")
def _session_scope(env):
    yield
    assert env.apache_stop() == 0
