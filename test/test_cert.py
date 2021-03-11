import os
import re
from datetime import timedelta, datetime
from typing import List, Tuple, Any, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509 import ExtendedKeyUsageOID, NameOID


EC_SUPPORTED = {}
EC_SUPPORTED.update([(curve.name.upper(), curve) for curve in [
    ec.BrainpoolP256R1,
    ec.BrainpoolP384R1,
    ec.BrainpoolP512R1,
    ec.SECP192R1,
    ec.SECP224R1,
    ec.SECP256R1,
    ec.SECP384R1,
]])


def _private_key(key_type):
    if isinstance(key_type, str):
        key_type = key_type.upper()
        m = re.match(r'^(RSA)?(\d+)$', key_type)
        if m:
            key_type = int(m.group(2))

    if isinstance(key_type, int):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_type,
            backend=default_backend()
        )
    if not isinstance(key_type, ec.EllipticCurve) and key_type in EC_SUPPORTED:
        key_type = EC_SUPPORTED[key_type]
    return ec.generate_private_key(
        curve=key_type,
        backend=default_backend()
    )

class CertificateSpec:

    def __init__(self, domains: List[str], key_type: str = None, single_file: bool = False):
        self.domains = domains
        self.key_type = key_type
        self.single_file = single_file


class Credentials:

    def __init__(self, name: str, cert: Any, pkey: Any, key_type: str,
                 issuer: 'Credentials' = None):
        self._name = name
        self._cert = cert
        self._pkey = pkey
        self._key_type = key_type
        self._issuer = issuer

    @property
    def name(self) -> str:
        return self._name

    @property
    def key_type(self):
        return self._key_type

    @property
    def private_key(self) -> Any:
        return self._pkey

    @property
    def certificate(self) -> Any:
        return self._cert

    @property
    def cert_pem(self) -> bytes:
        return self._cert.public_bytes(Encoding.PEM)

    @property
    def pkey_pem(self) -> bytes:
        return self._pkey.private_bytes(
            Encoding.PEM,
            PrivateFormat.TraditionalOpenSSL if self._key_type.startswith('rsa') else PrivateFormat.PKCS8,
            NoEncryption())


class CertStore:

    def __init__(self, fpath: str):
        self._store_dir = fpath
        if not os.path.exists(self._store_dir):
            os.makedirs(self._store_dir)

    def save(self, creds: Credentials, name: str = None,
             single_file: bool = False) -> Tuple[str, str]:
        name = name if name is not None else creds.name
        cert_file, pkey_file = self._fpaths_for(name, creds)
        if single_file:
            pkey_file = None
        with open(cert_file, "wb") as fd:
            fd.write(creds.cert_pem)
            if pkey_file is None:
                fd.write(creds.pkey_pem)
        if pkey_file is not None:
            with open(pkey_file, "wb") as fd:
                fd.write(creds.pkey_pem)
        return cert_file, pkey_file

    def _fpaths_for(self, name: str, creds: Credentials):
        key_infix = ".{0}".format(creds.key_type) if creds.key_type is not None else ""
        return os.path.join(self._store_dir, '{dname}{key_infix}.cert.pem'.format(
            dname=name, key_infix=key_infix)),\
               os.path.join(self._store_dir, '{dname}{key_infix}.pkey.pem'.format(
                   dname=name, key_infix=key_infix))


class TlsTestCA:

    def __init__(self, ca_dir: str = ".", key_type: str = None):
        self._certs = {}
        self._def_key_type = key_type if key_type is not None else "rsa2048"
        self._store = CertStore(fpath=ca_dir)
        self._name = "abetterinternet-mod_tls"
        self._root = None
        self._root = self._make_ca_credentials(name=self._name, key_type=self._def_key_type)
        self._certs[self._name] = self._root
        self._ca_cert_file, _ = self._store.save(self._root, name="ca")

    @property
    def ca_cert_file(self):
        return self._ca_cert_file

    def create_cert(self, spec: CertificateSpec) -> Tuple[str, str]:
        """Create a certificate signed by this CA for the given domains.
        :returns: the certificate and private key PEM file paths
        """
        creds = self._make_leaf_credentials(domains=spec.domains,
                                            issuer=self._root,
                                            key_type=spec.key_type)
        return self._store.save(creds, single_file=spec.single_file)

    @staticmethod
    def _make_x509_name(name: str, org_name: str, common_name: str = None) -> x509.Name:
        name_pieces = [
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, org_name
            ),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name),
        ]
        if common_name is not None:
            name_pieces.append(
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)
            )
        return x509.Name(name_pieces)

    def _make_csr(
            self,
            name: str,
            pkey: Any,
            issuer_subject: Optional[Credentials],
            valid_from_delta: timedelta = None,
            valid_until_delta: timedelta = None
    ):
        subject = self._make_x509_name(name=name, org_name="test", common_name=name)
        pubkey = pkey.public_key()
        issuer_subject = issuer_subject if issuer_subject is not None else subject

        valid_from = datetime.now()
        if valid_until_delta is not None:
            valid_from += valid_from_delta
        valid_until = datetime.now()
        if valid_until_delta is not None:
            valid_until += valid_until_delta

        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_subject)
            .public_key(pubkey)
            .not_valid_before(valid_from)
            .not_valid_after(valid_until)
            .serial_number(x509.random_serial_number())
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(pubkey),
                critical=False,
            )
        )

    def _add_ca_usages(self, csr: Any) -> Any:
        return csr.add_extension(
            x509.BasicConstraints(ca=True, path_length=9),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]),
            critical=True
        )

    def _add_leaf_usages(self, csr: Any, domains: List[str], issuer: Credentials) -> Any:
        return csr.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer.certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value),
            critical=False
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True
        )

    def _make_ca_credentials(self, name, key_type: Any = None,
                             issuer: Credentials = None) -> Credentials:
        key_type = key_type if key_type is not None else self._def_key_type
        pkey = _private_key(key_type=key_type)
        if issuer is not None:
            issuer_subject = issuer.certificate.subject
            issuer_key = issuer.private_key
        else:
            issuer_subject = None
            issuer_key = pkey
        csr = self._make_csr(name=name,
                             issuer_subject=issuer_subject,
                             pkey=pkey,
                             valid_from_delta=timedelta(days=-1),
                             valid_until_delta=timedelta(days=89))
        csr = self._add_ca_usages(csr)
        cert = csr.sign(private_key=issuer_key,
                        algorithm=hashes.SHA256(),
                        backend=default_backend())
        return Credentials(name=name, cert=cert, pkey=pkey, key_type=key_type)

    def _make_leaf_credentials(self, domains: List[str],
                               issuer: Credentials,
                               key_type: Any = None) -> Credentials:
        name = domains[0]
        key_type = key_type if key_type is not None else self._def_key_type
        pkey = _private_key(key_type=key_type)
        csr = self._make_csr(name,
                             issuer_subject=issuer.certificate.subject,
                             pkey=pkey,
                             valid_from_delta=timedelta(days=-1),
                             valid_until_delta=timedelta(days=89))
        csr = self._add_leaf_usages(csr, domains=domains, issuer=issuer)
        cert = csr.sign(private_key=issuer.private_key,
                        algorithm=hashes.SHA256(),
                        backend=default_backend())
        return Credentials(name=name, cert=cert, pkey=pkey, key_type=key_type)
