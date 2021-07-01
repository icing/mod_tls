import time
from datetime import timedelta
import socket
from threading import Thread

import pytest

from test_conf import TlsTestConf


class TestProto:

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        conf = TlsTestConf(env=env)
        conf.add_vhosts(domains=[env.domain_a, env.domain_b], extras={
            'base': "LogLevel tls:debug",
            env.domain_a: "TLSProtocol TLSv1.3+",
            env.domain_b: """
            # the commonly used name
            TLSProtocol TLSv1.2+
            # the numeric one (yes, this is 1.2)
            TLSProtocol TLSv0x0303+
            """,
        })
        conf.write()
        assert env.apache_restart() == 0

    @pytest.fixture(autouse=True, scope='function')
    def _function_scope(self, env):
        pass

    CURL_SUPPORTS_TLS_1_3 = None

    def test_05_proto_1_2(self, env):
        r = env.https_get(env.domain_b, "/index.json",
                               extra_args=["--tlsv1.2"])
        assert r.exit_code == 0, r.stderr
        if env.curl_supports_tls_1_3():
            r = env.https_get(env.domain_b, "/index.json",
                                   extra_args=["--tlsv1.3"])
            assert r.exit_code == 0, r.stderr

    def test_05_proto_1_3(self, env):
        r = env.https_get(env.domain_a, "/index.json",
                               extra_args=["--tlsv1.3"])
        if env.curl_supports_tls_1_3():
            assert r.exit_code == 0, r.stderr
        else:
            assert r.exit_code == 4, r.stderr

    def test_05_proto_close(self, env):
        s = socket.create_connection(('localhost', env.https_port))
        time.sleep(0.1)
        s.close()

    def test_05_proto_ssl_close(self, env):
        conf = TlsTestConf(env=env)
        conf.add_ssl_vhosts(domains=[env.domain_a, env.domain_b], extras={
            'base': "LogLevel ssl:debug",
            env.domain_a: "SSLProtocol TLSv1.3",
            env.domain_b: "SSLProtocol TLSv1.2",
        })
        conf.write()
        assert env.apache_restart() == 0
        s = socket.create_connection(('localhost', env.https_port))
        time.sleep(0.1)
        s.close()


