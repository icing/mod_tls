import os
from datetime import timedelta, datetime
from typing import List, Tuple

import OpenSSL
import trustme


class TlsTestCA:

    def __init__(self, ca_dir: str = ".", key_type: str = None):
        self._ca_dir = ca_dir
        self._ca = trustme.CA(
            organization_name="abetterinternet-mod_tls",
        )
        if not os.path.exists(self._ca_dir):
            os.makedirs(self._ca_dir)
        self._ca_cert_file, ca_pkey_file = self._fpaths_for('ca')
        self._ca.cert_pem.write_to_path(self._ca_cert_file)
        self._ca.private_key_pem.write_to_path(ca_pkey_file)

    @property
    def ca_cert_file(self):
        return self._ca_cert_file

    def _fpaths_for(self, domain: str):
        return os.path.join(self._ca_dir, '{dname}.cert.pem'.format(dname=domain)),\
               os.path.join(self._ca_dir, '{dname}.pkey.pem'.format(dname=domain))

    def create_cert(self, domains: List[str]) -> Tuple[str, str]:
        """Create a certificate signed by this CA for the given domains.
        :returns: the certificate and private key PEM file paths
        """
        dname = domains[0]
        cert_file, pkey_file = self._fpaths_for(dname)

        cert = self._ca.issue_cert(" ".join(domains))
        for idx, blob in enumerate(cert.cert_chain_pems):
            blob.write_to_path(cert_file, append=(idx > 0))
        cert.private_key_pem.write_to_path(pkey_file)
        return cert_file, pkey_file

    def create_self_signed_cert(self, domains: List[str]) -> Tuple[str, str]:
        """Create a self signed certificate signed by this CA for the given domains.
        :returns: the certificate and private key PEM file paths
        """
        dname = domains[0]
        cert_file, pkey_file = self._fpaths_for(dname)
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
        cert.get_subject().CN = dname
        cert.set_serial_number(int(datetime.now().timestamp()*100))
        cert.gmtime_adj_notBefore(int(timedelta(days=-1).total_seconds()))
        cert.gmtime_adj_notAfter(int(timedelta(days=89).total_seconds()))
        cert.set_issuer(cert.get_subject())

        cert.add_extensions([OpenSSL.crypto.X509Extension(
            b"subjectAltName", False, b", ".join(map(
                lambda n: b"DNS:" + n.encode(), domains)
            )
        )])
        cert.set_pubkey(k)
        # noinspection PyTypeChecker
        cert.sign(k, 'sha1')

        open(cert_file, "wt").write(
            OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode('utf-8'))
        open(pkey_file, "wt").write(
            OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k).decode('utf-8'))
        return cert_file, pkey_file
