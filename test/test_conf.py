import os
from typing import List, Union, Dict

from test_env import TlsTestEnv


class TlsTestConf:

    def __init__(self, env: TlsTestEnv, name: str = "test.conf", mpm_type: str = None):
        self.env = env
        self.name = name
        self._mpm_type = mpm_type if mpm_type is not None else env.mpm_type
        self._content = [
            "LoadModule mpm_{mpm_type}_module  \"{libexecdir}/mod_mpm_{mpm_type}.so\"".format(
                libexecdir=self.env.libexec_dir,
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

    def add_vhosts(self, domains: List[str], extras: Dict[str, str] = None, port: str = None):
        extras = extras if extras is not None else {}
        port = port if port else self.env.https_port
        self.add(f"""
TLSEngine {port}
LogLevel tls:trace4
{extras['base'] if 'base' in extras else ""}
        """)
        for domain in domains:
            self.add(f"""
    <VirtualHost *:{port}>
      ServerName {domain}
      DocumentRoot htdocs/{domain}
                 """)
            for cred in self.env.ca.get_credentials_for_name(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else ""
                self.add(f"  TLSCertificate {cert_file} {pkey_file}")
            self.add("""
      {extras}
    </VirtualHost>
                """.format(
                    extras=extras[domain] if domain in extras else ""
                ))

    def add_ssl_vhosts(self, domains: List[str], extras: Dict[str, str] = None, port: str = None):
        extras = extras if extras is not None else {}
        port = port if port else self.env.https_port
        self.add(f"""
LogLevel ssl:trace4
{extras['base'] if 'base' in extras else ""}
        """)
        for domain in domains:
            self.add(f"""
    <VirtualHost *:{port}>
      ServerName {domain}
      DocumentRoot htdocs/{domain}
      SSLEngine on
                 """)
            for cred in self.env.ca.get_credentials_for_name(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
                self.add(f"  SSLCertificateFile {cert_file}")
                self.add(f"  SSLCertificateKeyFile {pkey_file}")
            self.add(f"""
      {extras[domain] if domain in extras else ""}
    </VirtualHost>
                """)

    def add_md_vhosts(self, domains: List[str], extras: Dict[str, str] = None, port: str = None):
        extras = extras if extras is not None else {}
        port = port if port else self.env.https_port
        self.add(f"""
LoadModule md_module       {self.env.libexec_dir}/mod_md.so

TLSEngine {port}
LogLevel md:debug
LogLevel tls:trace8
{extras['base'] if 'base' in extras else ""}
        """)
        for domain in domains:
            self.add(f"""
    <MDomain {domain}>
                """)
            for cred in self.env.ca.get_credentials_for_name(domain):
                cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
                pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
                self.add(f"""
      MDCertificateFile {cert_file}
      MDCertificateKeyFile {pkey_file}
      """)
            self.add(f"""
    </MDomain>

    <VirtualHost *:{port}>
      ServerName {domain}
      DocumentRoot htdocs/{domain}
      {extras[domain] if domain in extras else ""}
    </VirtualHost>
                """)

    def add_md_base(self, domain: str):
        self.add(f"""
    LoadModule md_module       {self.env.libexec_dir}/mod_md.so

    TLSEngine {self.env.https_port}
    LogLevel md:debug
    LogLevel tls:trace8
    
    ServerName {domain}
    MDBaseServer on
    <MDomain {domain}>
                """)
        for cred in self.env.ca.get_credentials_for_name(domain):
            cert_file = os.path.relpath(cred.cert_file, self.env.server_dir)
            pkey_file = os.path.relpath(cred.pkey_file, self.env.server_dir) if cred.pkey_file else cert_file
            self.add(f"""
      MDCertificateFile {cert_file}
      MDCertificateKeyFile {pkey_file}
          """)
        self.add(f"""
    </MDomain>
        """)
