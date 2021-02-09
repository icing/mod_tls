import os
from datetime import timedelta
from typing import List

import OpenSSL


class TlsTestCert:

    def __init__(self):
        pass

    def create_self_signed(self, path, fname : str, sans: List[str],
                           duration: timedelta = None, serial: int = 1000):
        if not os.path.exists(path):
            os.makedirs(path)

        cert_file = os.path.join(path, '{name}.cert.pem'.format(name=fname))
        pkey_file = os.path.join(path, '{name}.pkey.pem'.format(name=fname))
        # create a key pair
        if os.path.exists(pkey_file):
            key_buffer = open(pkey_file, 'rt').read()
            k = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_buffer)
        else:
            k = OpenSSL.crypto.PKey()
            k.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        # create a self-signed cert
        cert = OpenSSL.crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "CA"
        cert.get_subject().L = "San Francisco"
        cert.get_subject().O = "Internet Security Research Group"
        cert.get_subject().CN = fname
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(-int(timedelta(days=1).total_seconds()))
        cert.gmtime_adj_notAfter(int(duration.total_seconds() if duration
                                     else timedelta(days=90).total_seconds()))
        cert.set_issuer(cert.get_subject())

        cert.add_extensions([OpenSSL.crypto.X509Extension(
            b"subjectAltName", False, b", ".join(map(lambda n: b"DNS:" + n.encode(), sans))
        )])
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        open(cert_file, "wt").write(
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode('utf-8'))
        open(pkey_file, "wt").write(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k).decode('utf-8'))
