import os
from typing import List, Union, Dict

from test_env import TlsTestEnv


class TlsTestConf:

    def __init__(self, env: TlsTestEnv, name: str = "test.conf", mpm_type: str = None):
        self.env = env
        self.name = name
        self._mpm_type = mpm_type if mpm_type is not None else env.mpm_type
        self._content = [
            "LoadModule mpm_{mpm_type}_module  \"{prefix}/modules/mod_mpm_{mpm_type}.so\"".format(
                prefix=self.env.prefix,
                mpm_type=self._mpm_type
            ),
        ]

    def add(self, text: Union[List[str], str]) -> None:
        if isinstance(text, List):
            self._content.extend(text)
        else:
            self._content.append(text)

    def write(self) -> None:
        with open(os.path.join(self.env.server_conf_dir, self.name), "w") as fd:
            fd.write("\n".join(self._content))

    def add_vhosts(self, domains: List[str], extras: Dict[str, str] = None):
        extras = extras if extras is not None else {}
        self.add("""
TLSEngine {https}
LogLevel tls:trace4
{extras}
        """.format(
            https=self.env.https_port,
            extras=extras['base'] if 'base' in extras else "",
        ))
        for domain in domains:
            self.add("""
    <VirtualHost *:{https}>
      ServerName {domain}
      DocumentRoot htdocs/{domain}
                 """.format(
                    https=self.env.https_port,
                    domain=domain))
            for cred in self.env.get_certs_for(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else ""
                self.add("  TLSCertificate {cert_file} {pkey_file}".format(
                    cert_file = cert_file,
                    pkey_file = pkey_file,
                ))
            self.add("""
      {extras}
    </VirtualHost>
                """.format(
                    extras=extras[domain] if domain in extras else ""
                ))

    def add_ssl_vhosts(self, domains: List[str], extras: Dict[str, str] = None):
        extras = extras if extras is not None else {}
        self.add("""
LogLevel ssl:trace4
{extras}
        """.format(
            https=self.env.https_port,
            extras=extras['base'] if 'base' in extras else "",
        ))
        for domain in domains:
            self.add("""
    <VirtualHost *:{https}>
      ServerName {domain}
      DocumentRoot htdocs/{domain}
      SSLEngine on
                 """.format(
                    https=self.env.https_port,
                    domain=domain))
            for cred in self.env.get_certs_for(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
                self.add("  SSLCertificateFile {cert_file}".format(
                    cert_file = cert_file,
                ))
                self.add("  SSLCertificateKeyFile {pkey_file}".format(
                    pkey_file=pkey_file,
                ))
            self.add("""
      {extras}
    </VirtualHost>
                """.format(
                    https=self.env.https_port,
                    domain=domain,
                    cert_file=cert_file,
                    pkey_file=pkey_file,
                    extras=extras[domain] if domain in extras else ""
                ))

    def add_md_vhosts(self, domains: List[str], extras: Dict[str, str] = None):
        extras = extras if extras is not None else {}
        self.add(f"""
LoadModule md_module       {self.env.prefix}/modules/mod_md.so

TLSEngine {self.env.https_port}
LogLevel md:debug
LogLevel tls:trace8
{extras['base'] if 'base' in extras else ""}
        """)
        for domain in domains:
            self.add(f"""
    <MDomain {domain}>
                """)
            for cred in self.env.get_certs_for(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
                self.add(f"""
      MDCertificateFile {cert_file}
      MDCertificateKeyFile {pkey_file}
      """)
            self.add(f"""
    </MDomain>

    <VirtualHost *:{self.env.https_port}>
      ServerName {domain}
      DocumentRoot htdocs/{domain}
      {extras[domain] if domain in extras else ""}
    </VirtualHost>
                """)

    def add_md_base(self, domain: str):
        self.add(f"""
    LoadModule md_module       {self.env.prefix}/modules/mod_md.so

    TLSEngine {self.env.https_port}
    LogLevel md:debug
    LogLevel tls:trace8
    
    ServerName {domain}
    MDBaseServer on
    <MDomain {domain}>
                """)
        for cred in self.env.get_certs_for(domain):
            cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
            pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
            self.add(f"""
      MDCertificateFile {cert_file}
      MDCertificateKeyFile {pkey_file}
          """)
        self.add(f"""
    </MDomain>
        """)
