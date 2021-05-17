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

    def __init__(self, name: str = None, domains: List[str] = None,
                 dn: List[Tuple[str, str]] = None, email: str = None,
                 key_type: str = None, single_file: bool = False,
                 valid_from: timedelta = timedelta(days=-1),
                 valid_to: timedelta = timedelta(days=89),
                 sub_specs: List['CertificateSpec'] = None):
        self.name = name
        self.dn = dn
        self.domains = domains
        self.email = email
        self.key_type = key_type
        self.single_file = single_file
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.sub_specs = sub_specs


class Credentials:

    def __init__(self, name: str, cert: Any, pkey: Any, key_type: str,
                 issuer: 'Credentials' = None):
        self._name = name
        self._cert = cert
        self._pkey = pkey
        self._key_type = key_type
        self._issuer = issuer
        self._cert_file = None
        self._pkey_file = None
        self._store = None

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

    def set_store(self, store: 'CertStore'):
        self._store = store

    def set_files(self, cert_file: str, pkey_file: str = None):
        self._cert_file = cert_file
        self._pkey_file = pkey_file

    @property
    def cert_file(self) -> str:
        return self._cert_file

    @property
    def pkey_file(self) -> Optional[str]:
        return self._pkey_file

    def get_first(self, name) -> Optional['Credentials']:
        creds = self._store.get_credentials_for_name(name) if self._store else []
        return creds[0] if len(creds) else None

    def get_credentials_for_name(self, name) -> List['Credentials']:
        return self._store.get_credentials_for_name(name) if self._store else []

    def issue_certs(self, specs: List[CertificateSpec]) -> List['Credentials']:
        return [self.issue_cert(spec=spec) for spec in specs]

    def issue_cert(self, spec: CertificateSpec) -> 'Credentials':
        cert = TlsTestCA.create_credentials(spec=spec, issuer=self,
                                            key_type=spec.key_type if spec.key_type else self.key_type,
                                            valid_from=spec.valid_from, valid_to=spec.valid_to
                                            )
        if self._store:
            self._store.save(cert, single_file=spec.single_file)
        if spec.sub_specs:
            if self._store:
                sub_store = CertStore(fpath=os.path.join(self._store.path, cert.name))
                cert.set_store(sub_store)
            cert.issue_certs(spec.sub_specs)
        return cert


class CertStore:

    def __init__(self, fpath: str):
        self._store_dir = fpath
        if not os.path.exists(self._store_dir):
            os.makedirs(self._store_dir)
        self._creds_by_name = {}

    @property
    def path(self) -> str:
        return self._store_dir

    def save(self, creds: Credentials, name: str = None,
             single_file: bool = False) -> None:
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
        creds.set_files(cert_file, pkey_file)
        if name not in self._creds_by_name:
            self._creds_by_name[name] = []
        self._creds_by_name[name].append(creds)

    def get_credentials_for_name(self, name) -> List[Credentials]:
        return self._creds_by_name[name] if name in self._creds_by_name else []

    def _fpaths_for(self, name: str, creds: Credentials):
        key_infix = ".{0}".format(creds.key_type) if creds.key_type is not None else ""
        return os.path.join(self._store_dir, '{dname}{key_infix}.cert.pem'.format(
            dname=name, key_infix=key_infix)),\
            os.path.join(self._store_dir, '{dname}{key_infix}.pkey.pem'.format(
                   dname=name, key_infix=key_infix))


class TlsTestCA:

    @classmethod
    def create(cls, name: str, store_dir: str, key_type: str = "rsa2048") -> Credentials:
        store = CertStore(fpath=store_dir)
        cert = TlsTestCA._make_ca_credentials(name=name, key_type=key_type)
        store.save(cert, name="ca")
        cert.set_store(store)
        return cert

    @staticmethod
    def create_credentials(spec: CertificateSpec, issuer: Credentials, key_type: Any,
                           valid_from: timedelta = timedelta(days=-1),
                           valid_to: timedelta = timedelta(days=89),
                           ) -> Credentials:
        """Create a certificate signed by this CA for the given domains.
        :returns: the certificate and private key PEM file paths
        """
        if spec.domains and len(spec.domains):
            creds = TlsTestCA._make_server_credentials(domains=spec.domains,
                                                       issuer=issuer,
                                                       valid_from=valid_from,
                                                       valid_to=valid_to,
                                                       key_type=key_type)
        elif spec.dn and len(spec.dn):
            creds = TlsTestCA._make_client_credentials(dn=spec.dn,
                                                       issuer=issuer,
                                                       email=spec.email,
                                                       valid_from=valid_from,
                                                       valid_to=valid_to,
                                                       key_type=key_type)
        elif spec.name:
            creds = TlsTestCA._make_ca_credentials(name=spec.name,
                                                   issuer=issuer,
                                                   valid_from=valid_from,
                                                   valid_to=valid_to,
                                                   key_type=key_type)
        else:
            raise Exception(f"unrecognized certificate specification: {spec}")
        return creds

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

    @staticmethod
    def _make_csr(
            name: str,
            pkey: Any,
            issuer_subject: Optional[Credentials],
            valid_from_delta: timedelta = None,
            valid_until_delta: timedelta = None
    ):
        subject = TlsTestCA._make_x509_name(name=name, org_name="test", common_name=name)
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

    @staticmethod
    def _add_ca_usages(csr: Any) -> Any:
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

    @staticmethod
    def _add_leaf_usages(csr: Any, domains: List[str], issuer: Credentials) -> Any:
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

    @staticmethod
    def _add_client_usages(csr: Any, issuer: Credentials, rfc82name: str = None) -> Any:
        cert = csr.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer.certificate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier).value),
            critical=False
        )
        if rfc82name:
            cert.add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(rfc82name)]),
                critical=True,
            )
        cert.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True
        )
        return cert

    @staticmethod
    def _make_ca_credentials(name, key_type: Any,
                             issuer: Credentials = None,
                             valid_from: timedelta = timedelta(days=-1),
                             valid_to: timedelta = timedelta(days=89),
                             ) -> Credentials:
        pkey = _private_key(key_type=key_type)
        if issuer is not None:
            issuer_subject = issuer.certificate.subject
            issuer_key = issuer.private_key
        else:
            issuer_subject = None
            issuer_key = pkey
        csr = TlsTestCA._make_csr(name=name,
                                  issuer_subject=issuer_subject, pkey=pkey,
                                  valid_from_delta=valid_from, valid_until_delta=valid_to)
        csr = TlsTestCA._add_ca_usages(csr)
        cert = csr.sign(private_key=issuer_key,
                        algorithm=hashes.SHA256(),
                        backend=default_backend())
        return Credentials(name=name, cert=cert, pkey=pkey, key_type=key_type, issuer=issuer)

    @staticmethod
    def _make_server_credentials(domains: List[str], issuer: Credentials,
                                 key_type: Any,
                                 valid_from: timedelta = timedelta(days=-1),
                                 valid_to: timedelta = timedelta(days=89),
                                 ) -> Credentials:
        name = domains[0]
        pkey = _private_key(key_type=key_type)
        csr = TlsTestCA._make_csr(name,
                                  issuer_subject=issuer.certificate.subject, pkey=pkey,
                                  valid_from_delta=valid_from, valid_until_delta=valid_to)
        csr = TlsTestCA._add_leaf_usages(csr, domains=domains, issuer=issuer)
        cert = csr.sign(private_key=issuer.private_key,
                        algorithm=hashes.SHA256(),
                        backend=default_backend())
        return Credentials(name=name, cert=cert, pkey=pkey, key_type=key_type, issuer=issuer)

    @staticmethod
    def _make_client_credentials(dn: List[Tuple[str, str]],
                                 issuer: Credentials, email: Optional[str],
                                 key_type: Any,
                                 valid_from: timedelta = timedelta(days=-1),
                                 valid_to: timedelta = timedelta(days=89),
                                 ) -> Credentials:
        pkey = _private_key(key_type=key_type)
        name = dn[-1][1].replace(' ', '_')
        csr = TlsTestCA._make_csr(", ".join([f"{n[0]}={n[1]}" for n in dn]),
                                  issuer_subject=issuer.certificate.subject, pkey=pkey,
                                  valid_from_delta=valid_from, valid_until_delta=valid_to)
        csr = TlsTestCA._add_client_usages(csr, issuer=issuer, rfc82name=email)
        cert = csr.sign(private_key=issuer.private_key,
                        algorithm=hashes.SHA256(),
                        backend=default_backend())
        return Credentials(name=name, cert=cert, pkey=pkey, key_type=key_type, issuer=issuer)
