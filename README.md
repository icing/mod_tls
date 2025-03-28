# `mod_tls` - rust based TLS for Apache httpd

This repository contains `mod_tls`, a module for Apache httpd that uses
[rustls](https://github.com/ctz/rustls) to provide a memory safe TLS
implementation in Rust.

## Status

The current state is compatible with **rustls-ffi v0.14.0 or newer** 
and needs at least Apache 2.4.48 for the necessary infrastructure.

`mod_tls` gives you:
 
 * a memory safe TLS via [rustls](https://docs.rs/rustls/0.19.1/rustls/).
 * TLS v1.2 and TLS v1.3
 * Configuration similar to Apache's own `mod_ssl`.
 * Similar performance as `mod_ssl`, better in some areas.
 * Frontend TLS for your clients
 * Backend TLS for `mod_proxy`
 * Frontend OCSP Stapling via `mod_md`
 
`mod_tls` currently does **not** support:
 
  * client certificates

There is a [comparison table with mod_ssl functionality](#comparison-with-mod_ssl).

## Platforms

 * rustls-ffi v0.14.0 or newer
 * Apache 2.4.48 or later
 * build system: autoconf/automake

### Installation from source

Run the usual autoconf/automake magic incantations. You need a built Apache trunk and specify the `--with-apxe=<path>/bin/apxs` on configuration if that is not in your `$PATH`. Also, you need [rustls-ffi](https://github.com/rustls/rustls-ffi) installed.

Run the usual autoconf/automake magic incantations.

```
> autoreconf -i
> automake
> autoconf
> ./configure --with-apxs=<path to apxs>
> make
```

#### OCSP Stapling with mod_tls

`mod_tls` adds OCSP responses to TLS handshakes (this is what "Stapling" is), **when** someone provides these responses. It has no own implementation to retrieve these responses, like `mod_ssl` does.

In Apache 2.4.48 there is a new internal API where modules can ask around for someone willing to provide this. `mod_md` is currently the only choice here and you need to enable this via:

```
MDStapling on       # provide OCSP responses (for certificates by mod_md)
MDStapleOthers on   # provide OCSP for all other server certs as well
```

You'd want to enable this when you use `mod_tls`. To check that this works, you can enable Apache's `server-status`
handler by [`mod_status`](https://httpd.apache.org/docs/2.4/mod/mod_status.html). On that page, you'll then also see certificate and OCSP information from `mod_md`.


## Tests

If you want to run the test suite, you need:

 * `curl` and `openssl` in your path
 * Some Python packages: `pytest`, `cryptography`

```
> make test
```

## History

This project has been sponsored in 2020 by the [ISRG](https://www.abetterinternet.org)
([Read what they said about it.](https://www.abetterinternet.org/post/memory-safe-tls-apache/)). It had been added as an *experimental* module into the Apache httpd project. However, the `rustls-ffi`API proved to be unstable, mostly due to `rustls` own ongoing development. This requires rework of `mod_tls` on new releases and the schedule of that does not fit into the release schedule of the httpd project.

In September 2024, I chose to give the module a standalone github location with its own releases and removed it from the Apache httpd project again. This will make maintenance and participation easier.

Should rustls one day become stable, we can consider merging it to the httpd project again.

## Comparison with `mod_ssl`

 Feature          | mod_ssl  | mod_tls | Comment
 -----------------|:--------:|:-------:|---------
 Frontend TLS     |  yes     | yes  |
 Backend TLS (proxy) |  yes  |  yes |
 TLSv1.3           | yes*    |  yes | *)with recent OpenSSL
 TLSv1.2          |  yes    |  yes  |
 TLSv1.1/1.0      | yes*    |  no    | *)if enabled in OpenSSL
 Individual VirtualHost TLS Settings |  yes  | yes  |
 Frontend client certificates |  yes  | no |
 Backend machine certificate |  yes  | yes* | *)since v0.8.1
 Frontend OCSP stapling | yes  | yes*  | *)via mod_md
 Backend OCSP check |  yes  | no*  |  *)stapling will be verified
 TLS version used | min-max  |  min |
 TLS ciphers     | exclusive list | preferred/suppressed |
 TLS ciphers preference | client/server | client/server | whose ordering shall be honored
 TLS sessions    |  yes   |  yes  |
 SNI strictness  | default no |  default yes | 
 Option EnvVars   | exhaustive | limited | See [variables](#variables)
 Option ExportCertData  | client+server | server | See [variables](#variables)
 Backend CA     | file/dir  | file  |
 Revocation CRLs |  yes  |  no  |
 FIPS           | yes*   |  no  | *)depends on OpenSSL
 TLS Renegotiation |  yes  |  no  | e.g. varying TLS settings per location
 Encrypted Certificate Keys |  yes  | no  |
 TLS SRP         |  yes  |  no  |
 TLS SCT         |  no    |  no  |
 
 
## Configuration

`mod_tls` has, like all other Apache httpd modules, a number of configuration directives that
you need to use for the module to become active in your server. The whole list is described
below in the [directives section](#directives).

### Loading

For the module to become available in your server, it needs to be loaded. The directive for that
looks like:

```
LoadModule tls_module           "<modules-path>/mod_tls.so"
```

On several linux distributions there are mechanisms to do that from the command line, e.g. debian has
the nice `a2enmod` command.

When you restart the server afterwards, the module will log in `INFO` entry. This lists versions of `rustls-ffi` binding and the `rustls` library are logged by `mod_tls`, like this:

```
[date time] [tls:info] [pid] mod_tls/0.6.0 (crustls=crustls/0.6.0/rustls/0.19.0), initializing...
```

If you do not see this, make sure that the log level does not suppress this message. You may add `LogLevel tls:info` to your configuration for this.

#### Peace and Harmony

You can load `mod_tls` and other SSL modules like `mod_ssl` at the same time. If you have a running `mod_ssl` setup, you can load `mod_tls` in addition and it will by itself not change anything. You need to add configuration directives to tell the module where it should handle connections.

### Handling connections

Clients connect to your server using an IP address and a port number. You apache may listen for new connections
on several of those. Most setups use 2 ports, 80 and 443, on all addresses that the server has. This is easy, because
should the address of your server change, the apache config will continue to work. For this, somewhere in your server, there are directives like this:

```
Listen 80
Listen 443

<VirtualHost *:80>
  ServerName a.net
  ...
</VirtualHost>
<VirtalHost *:443>
  ServerName b.net
  ...
</VirtualHost>

```
This means clients can reach `a.net` on port 80 and `b.net` on port 443. Both of these do `http:` so far.

#### `https:` with `mod_ssl`

To have `b.net` use encrypted `https:` traffic, you need to add SSL directives:

```
...
<VirtalHost *:443>
  ServerName b.net
  SSLEngine on
  SSLCertificateFile file_with_certificate.pem
  SSLCertificateKeyFile file_with_key.pem
  ...
</VirtualHost>
```

If you have several `VirtualHost *:443`, you need to add the `SSLEngine on` in each of them, especially the first one.

#### `https:` with `mod_tls`

With `mod_tls`, the configuration is slightly different:

```
...
TLSEngine 443

<VirtalHost *:443>
  ServerName b.net
  TLSCertificate file_with_certificate.pem file_with_key.pem
  ...
</VirtualHost>
```

You instruct `mod_tls` to encrypt all incoming connections on port 443. You add the certificate+key to the `VirtualHost`s like with `mod_ssl`. If you have certificate and key in the same file (no real reason not to), you can just add the file once.

The certificate and key file formats are the same.

#### `https:` with `mod_ssl` *and* `mod_tls`?

First: you can **not** mix both modules on the same address and port! 

But you can use `mod_ssl` on one port and `mod_tls` on another. You can also use `mod_tls` for incoming connections and `mod_ssl` for connections to proxied servers (backends).

Theoretically, if your server has two interfaces (IP addresses `addr1` and `addr2`), you could use one module on `addr1:443` and another on `addr2:443`. But you would need to define separate `VirtualHost`s for particular addresses. That seems quite an edge configuration, but it is doable.

### Handling certificates

Certificates and keys are commonly stored in `PEM` file, which is a standardized format. This means you can use the same files for `mod_ssl` and `mod_tls`. The only exception is that `mod_tls` does not support encrypted keys.

A certificate file needs to contain the certificate, followed by the certificates that make up the "trust chain" up to, but excluding, the `root` certificate. All these are sent to the client on a new connection, as the client is the one who needs to verify trust. The server never verifies itself.

Like in `mod_ssl`, you may configure more than one certificate for a `VirtualHost`. As in:

```
<VirtalHost *:443>
  ServerName b.net
  TLSCertificate cert_A.pem key_A.pem
  TLSCertificate cert_B.pem key_B.pem
  ...
</VirtualHost>
```
Both certificates need to be valid for host `b.net`. But why would one do that?

The latest in SSL security are algorithms that use mathemagical named "Elliptic Curves" (EC). The seem to be pretty strong and are a lot smaller than the `RSA` ones used so far. Not all clients might support them, though.

If `cert_A` is an EC certificate and `cert_B` is RSA, all capable clients will get the first and all legacy clients the second. `mod_tls` will use the first one that is compatible.

#### ACME (Let's Encrypt) certificates

Certificates obtained by ACME clients, such as `certbot` can be used with `mod_tls` as well. However their automatic rewriting of Apache httpd configurations does commonly assume a `mod_ssl`. So, you have to check their documentation on how to best integrate them.

The ACME support in Apache itself, the module `mod_md`, does work with `mod_tls` just like with `mod_ssl`. For example:

```
Listen 443
TLSEngine 443
MDomain b.net

<VirtalHost *:443>
  ServerName b.net
  ...
</VirtualHost>
```

would be the minimal configuration to get a Let's Encrypt certificate for `b.net` and serve that via `mod_tls`.


### What else to configure for?

#### security

The `rustls` library supports only TLS versions and ciphers that are nowadays (2021) considered secure for the internet. That means, unless a new weakness is discovered, the default configuration is safe to use. Most people will not have to configure anything besides the port(s) to listen on. And certificates if they do not use `mod_md` for that.

For people with special needs, there are ways to tweak protocol versions and ciphers and client orders. And those are described in more detail below.

The general gist of these configuration options is to give admins control, but allow for future enhancements. A server where a new TLS version can be run, should be able to. If some new cipher is added to TLSv1.3 in an attempt to overcome a newly found weakness, it should not require all servers to be reconfigured for its use. If an LTS installation gets new security features, maybe there is a reason for that.

If a cipher is deemed unsuitable by you, use `TLSCiphersSuppress` to disable it.

#### performance

There are performance differences between ciphers, depending on the hardware used/available. In most web server scenarios, the limitations seem to be mostly on the client side (battery life!). Since the set of supported ciphers in `rustls` is carefully selected, the module will honor preferences as announced by a client by default.

Since clients always specify their ciphers ordered, the servers preferences normally have no effect. For scenarios where servers should override this (`TLSHonorClientOrder off`), use `TLSCiphersPrefer` to signal your preferences.

### Protocol Versions

There are two way to name a TLS protocol version in `mod_tls`:

1. The defined names `TLSv1.2` and `TLSv1.3`.
2. the numeric names `TLSv0xnnnn` with `nnnn` being the hexadecimal version value as defined in the RFC standards for TLS.

In `mod_tls` one configures the minimum TLS version to use by mentioning that version with an added `+`. Having a host only support v1.3 (and higher) would be achieved through:

```
TLSProtocol TLSv1.3+
```

### Cipher Names

There are three ways to name a TLS cipher in `mod_tls`:

1. The [IANA assigned name](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
   which uses `_` to separate parts. Example: `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`.
2. The OpenSSL name, using `-` as separator (for 1.2). Example: `ECDHE-ECDSA-AES256-SHA384`. Such names often appear in documentation. `mod_tls` defines them for all TLS v1.2 ciphers. For TLS v1.3 ciphers, names starting with `TLS13_` are also supported.
3. The [IANA assigned identifier](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4), which is a 16-bit numeric value. This is what is used on the wire. Example: `0xc024`. You can use this in `mod_tls` configurations as `TLS_CIPHER_0xc024`.

The list of TLS ciphers supported in the `rustls` library, can be found [here](https://docs.rs/rustls/).

It is considered a configuration **failure** to specify a cipher name that is *unknown*, e.g. not in the IANA registry at the time `mod_tls` was last updated. If there is no name in `mod_tls` for a cipher you need, use the identifier name, such as `TLS_CIPHER_0xnnnn`. Those will always be accepted.

A **warning** will be written to the log if you configure preference for a *known* cipher that is not *supported* by rustls. For example:

```
TLSCiphersPrefer SSL_RSA_FIPS_WITH_DES_CBC_SHA
```

will log a `WARNING`, because you seem to want something that `rustls` is unable to deliver. It is not considered an error, because a preference is no guarantee that a certain cipher is used. Also, should `rustls` for security reasons decide to drop a cipher, your `mod_tls` configuration will not break. 

You may suppress any known cipher without any warning or error. Either `rustls` does not support it anyway, or `mod_tls` will disable it, the outcome is the same.

If you suppress all ciphers supported for a TLS protocol version, that version is de-facto disabled. The only way this currently *could* make sense is if you wanted a server that *only* speaks TLSv1.2. This is not really recommended, but the world is a large place. So now, you know what happens if you do it. (Btw: if you want a server no longer supporting v1.2, you should configure `TLSProtocol TLSv1.3+` and not mess with 1.2 ciphers at all). 

### Variables

Like `mod_ssl` the module supports variables in the request environment (e.g. forwarded to CGI processing). There is a small set of variables that will always be set and a larger one that is only added when `TLSOptions StdEnvVars` is configured.

Variable       | TLSOption | Description
-----------------|:---------:|:-----------------
`SSL_TLS_SNI`    |  *     |  the server name indicator (SNI) send by the client
`SSL_PROTOCOL`     |  *    |  the TLS protocol negotiated (TLSv1.2, TLSv1.3)
`SSL_CIPHER`       |  *    |  the name of the TLS cipher negotiated
`SSL_VERSION_INTERFACE` |StdEnvVars| the module version as `mod_tls/n.n.n`
`SSL_VERSION_LIBRARY` |StdEnvVars  | the rustls-ffi version as `crustls/n.n.n/rustls/n.n.n` 
`SSL_SECURE_RENEG` | StdEnvVars    | always `false` since rustls does not support that feature
`SSL_COMPRESS_METHOD`| StdEnvVars  | always `NULL` since rustls does not support that feature
`SSL_CIPHER_EXPORT` |  StdEnvVars  | always `false` as rustls does not support such ciphers
`SSL_CLIENT_VERIFY` |  StdEnvVars  | always `NONE` as client certificates are not supported
`SSL_SESSION_RESUMED` | StdEnvVars | either `Resumed` if a known TLS session id was presented by the client or `Initial` otherwise
`SSL_SERVER_CERT` | ExportCertData| the selected server certificate in PEM format.

*) NI: Not Implemented

The variable `SSL_SESSION_ID` is intentionally not supported as it contains sensitive information.

### Client Certificates

Client certificates are currently not supported my `mod_tls`. The basic infrastructure is there, but
suitable Rust implementations for revocations checks on such certificates (CRL, OCSP) have so far 
not been identified.

Offering client certificate authentication without a revocation mechanism is not an option, we feel.

## Directives

The following configuration directives are available once `mod_tls` is loaded into Apache:

### `TLSEngine`
 
`TLSEngine [address:]port` defines on which address+port the module shall handle incoming connections. 

This is set on a global level, not in individual `VirtualHost`s. It will affect all `VirtualHost` that match
the specified address/port. You can use `TLSEngine` several times to use more than one address/port.
 
It is similar but different to the [SSLEngine](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslengine) directive of mod_ssl. If you have `VirtualHost`s, some on port 443, you need to set `SSLEngine on` in every `VirtualHost` that is defined for `*:443`.
 
### `TLSCertificate`

`TLSCertificate cert_file [key_file]` adds a certificate file (PEM encoded) to a server/virtual host. 

If you do not specify a separate key file, the key is assumed to also be found in the first file. You may add more than one certificate to a server/virtual host. The first certificate suitable for a client is then chosen.

The path can be specified relative to the server root.

### `TLSProtocol`

`TLSProtocol version+` specifies the minimum version of the TLS protocol to use. 

The default is `v1.2+`. Settings this to `v1.3+` would disable TLSv1.2.

### `TLSCipherPrefer`

`TLSCipherPrefer cipher(-list)` defines ciphers that are preferred. 

This will not disable any ciphers supported by `rustls`. If you specify a cipher that is completely unknown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

### `TLSCipherSuppress`

`TLSCipherSuppress cipher(-list)` defines ciphers that are not used. 

This will not disable any unmentioned ciphers supported by `rustls`. If you specify a cipher that is completely unknown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

### `TLSHonorClientOrder`

`TLSHonorClientOrder on|off` determines if the order of ciphers supported by the client is honored. This is `on` by default.

### `TLSOptions`

`TLSOptions [+|-]option` is analog to `SSLOptions` in `mod_ssl`.

This can be set per directory/location and `option` can be:

* `StdEnvVars`: adds more variables to the requests environment, as forwarded for example to CGI processing and other applications.
* `ExportCertData`: adds certificate related variables to the request environment.
* `Defaults`: resets all options to their default values.

See [Variables](#variables) to see exactly which values are set on an option.

Adding variables to a request environment adds overhead, especially when certificates need to be inspected and
fields extracted. Therefore most variables are not set by default.

You can configure `TLSOptions` per location or generally on a server/virtual host. Prefixing an option with `-` disables this option while leaving others unchanged. A `+` prefix is the same as writing the option without one.

The `Defaults` value can be used to reset any options that are inherited from other locations or the virtual host/server. Example:

```
<Location /myplace/app>
  TLSOptions Defaults StdEnvVars
  ...
</Location>
```

### `TLSProxyEngine`

`TLSProxyEngine on|off` is analog to `SSLProxyEngine`.

This can be used in a server/virtual host or `<Proxy>` section to enable the module for
outgoing connections using `mod_proxy`.

### `TLSProxyCA`

`TLSProxyCA file.pem` sets the root certificates to validate the backend server with.


### `TLSProxyProtocol`

`TLSProxyProtocol version+` specifies the minimum version of the TLS protocol to use in proxy connections. 

The default is `v1.2+`. Settings this to `v1.3+` would disable TLSv1.2.


### `TLSProxyCipherPrefer`

`TLSProxyCipherPrefer cipher(-list)` defines ciphers that are preferred for a proxy connection. 

This will not disable any ciphers supported by `rustls`. If you specify a cipher that is completely unknown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

### `TLSProxyCipherSuppress`

`TLSProxyCipherSuppress cipher(-list)` defines ciphers that are not used for a proxy connection. 

This will not disable any unmentioned ciphers supported by `rustls`. If you specify a cipher that is completely unknown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

### `TLSProxyMachineCertificate`

`TLSProxyMachineCertificate cert_file [key_file]` adds a certificate file (PEM encoded) to a proxy setup. The
certificate is used to authenticate against a proxied backend server.

If you do not specify a separate key file, the key is assumed to also be found in the first file. You may add more than one certificate to a proxy setup. The first certificate suitable for a proxy connection to a backend is then chosen.

The path can be specified relative to the server root.


<!---
### `TLSStrictSNI`

`TLSStrictSNI on|off` enforces exact matches of client server indicators (SNI) against host names. 

Client connections will be unsuccessful if no match is found. This is `on` by default.

### `TLSSessionCache`

`TLSSessionCache cache-spec` specifies the cache for TLS session resumption. This uses a cache on the server side to allow clients to resume connections. 

You can set this to `none` or define a cache as in the [`SSLSessionCache`](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslsessioncache) directive. If not configured, `mod_tls` will try to create a shared memory cache on its own, using `shmcb:tls/session-cache` as specification. Should that fail, a warning is logged, but the server continues.

### `TLSClientCertificate`

`TLSClientCertificate required|optional|none` controls the handling of client certificates in a server/virtual host.

With `required` a client must present a valid certificate or the connection is rejected. `optional` allows the client to present one (which then must also validate) or continue without it. `none` is the default and no client certificate will be requested.

NOTE: the current implementation is incomplete. Certificates are checked and validated, however the necessary field names are not extracted and hosted applications do not see a user name.

### `TLSClientCA`

`TLSClientCA file.pem` sets the root certificates to validate client certificates against.

This must be defined if client certificates are configured. The file needs to contain the certificates that form a verifiable chain of trust together with the ones that clients present. If you have client certification with `mod_ssl` via [SSLCACertificateFile](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslcacertificatefile), the same file will work here.

The path can be specified relative to the server root.

-->
