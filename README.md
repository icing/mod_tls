# `mod_tls` - memory safety for TLS in Apache

This repository contains `mod_tls`, a module for Apache httpd that uses
[rustls](https://github.com/ctz/rustls) to provide a memory safe TLS
implementation in Rust.

This project is sponsored by the [ISRG](https://www.abetterinternet.org). 
[Read what they said about it.](https://www.abetterinternet.org/post/memory-safe-tls-apache/).


## Status

In development. The module's `master` branch follows the `main` branch of [crustls](https://github.com/abetterinternet/crustls),
the `C` binding for the `rustls` crate and the `trunk` version of the Apache httpd server.

Apache `trunk` has received patches that allow two (or more) SSL providing modules
to be loaded and active on the same server. This required an extension of the core
API which has become part of the 2.4.48 release..

`mod_tls` supports:
 
 * TLS for incoming connections on a address+port. You can use `mod_ssl` on another port at the same time.
 * certificates for the server and/or a virtual host. You may specify more than one certificate for a host and the first one matching client capabilities will be chosen.
 * protocol versions. You may specify the minimum version to use.
 * cipher preferences. You may specified the ciphers that should be considered first during negotiation. This does not disable any other ciphers.
 * cipher suppression. You may specify ciphers that are never used. All unmentioned ciphers remain active.
 * cipher client order disregard. By default, the order of client supplied ciphers is honored.
 * option to forward certain variables, such as `SSL_CIPHER` and `SSL_PROTOCOL` to request processing.
 * interworking with Apache's module `mod_md` for Let's Encrypt (ACME) certificates and OCSP stapling.

`mod_tls` currently does **not** support:
 
  * client certificates
  * backend connections (via `mod_proxy`)

## Platforms

 * Apache 2.4.48 or later
 * OS: wherever apache and (c)rustls are available
 * build system: autoconf/automake

### Installation from source

Run the usual autoconf/automake magic incantations. You need a built Apache trunk and specify the `--with-apxe=<path>/bin/apxs` on configuration if that is not in your `$PATH`. Also, you need [crustls](https://github.com/abtterinternet/crustls/) installed.

Run the usual autoconf/automake magic incantations.

```
> autoreconf -i
> automake
> autoconf
> ./configure --with-apxs=<path to apxs>
> make
```

### Docker Test Image

There is now support for building a Docker image based on `debian sid` to run the test suite in.

```
> docker-compose build debian-test
> docker-compose run debian-test
```

This clone the git repository from `apache` and `crustls`, switched to the necessary branches and builds a copy of the local `mod_tls` sources. If you want to setup your own build, you'll find the instructions in `docker/debian-test/bin/update.sh`.

## Tests

### Functional Tests

If you want to run the test suite, you need:

 * `curl` and `openssl` in your path
 * Some Python packages: `pytest`, `pyopenssl`

```
> make test
```

### Load Tests

There are load tests for putting the module under a bit of pressure and getting some numbers.
All benchmarks are limited in how they can be applied to reality. It is terribly easy in 
these limited tests to hit a sweet spot on your system where CPU+Disc caches align and 
you see wonderful numbers. But they will not apply to a production server.

To run these, you nee:

 * `h2load` from the exceptional [nghttp2](https://nghttp2.org).
 * Python package: `tqdm`

```
> make loadtest
```

This runs one test. There are several defined in `test/load_test.py` which you can invoke via arguments.

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

When you restart the server afterwards, the module will log in `INFO` entry. This lists versions of `crustls` binding and the `rustls` library are logged by `mod_tls`, like this:

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
TLSListen 443

<VirtalHost *:443>
  ServerName b.net
  TLSCertificate file_with_certificate.pem file_with_key.pem
  ...
</VirtualHost>
```

You instruct `mod_tls` to encrypt all incoming connections on port 443. You add the certificate+key to the `VirtualHost`s like with `mod_ssl`. If you have certificate and key in the same file (no real reason not to), you can just add the file once.

The certificate and key file formats are the same.

#### `https:` with both?

First: you cannot mix both modules on the same address and port. You may use the modules on different ports and, with some care, on the same port for different addresses. Maybe you do that for evaluation, if `mod_tls` fits your setup well. But for production setups, this is most likely not a good idea. Every module offers an attack surface and having two for the same task does only make you more vulnerable.

That being said, it makes sense to use one module for connection from outside and the other for proxy connections to backend servers. Especially when legacy backend with older SSL protocols need to be proxied.


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
TLSListen 443
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
TLSProtocols TLSv1.3+
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

If you suppress all ciphers supported for a TLS protocol version, that version is de-facto disabled. The only way this currently *could* make sense is if you wanted a server that *only* speaks TLSv1.2. This is not really recommended, but the world is a large place. So now, you know what happens if you do it. (Btw: if you want a server no longer supporting v1.2, you should configure `TLSProtocols TLSv1.3+` and not mess with 1.2 ciphers at all). 

### Variables

Like `mod_ssl` the module supports variables in the request environment (e.g. forwarded to CGI processing). There is a small set of variables that will always be set and a larger one that is only added when `TLSOptions StdEnvVars` is configured.

Variable       | TLSOption | Description
-----------------|:---------:|:-----------------
`SSL_TLS_SNI`    |  *     |  the server name indicator (SNI) send by the client
`SSL_PROTOCOL`     |  *    |  the TLS protocol negotiated (TLSv1.2, TLSv1.3)
`SSL_CIPHER`       |  *    |  the name of the TLS cipher negotiated
`SSL_VERSION_INTERFACE` |StdEnvVars| the module version as `mod_tls/n.n.n`
`SSL_VERSION_LIBRARY` |StdEnvVars  | the rustls version as `crustls/n.n.n/rustls/n.n.n` 
`SSL_SECURE_RENEG` | StdEnvVars    | always `false` since rustls does not support that feature
`SSL_COMPRESS_METHOD`| StdEnvVars  | always `NULL` since rustls does not support that feature
`SSL_CIPHER_EXPORT` |  StdEnvVars  | always `false` as rustls does not support such ciphers
`SSL_CLIENT_VERIFY` |  StdEnvVars  | either `SUCCESS` when a valid client certificate was presented or `NONE`
`SSL_SESSION_RESUMED` | StdEnvVars | either `Resumed` if a known TLS session id was presented by the client or `Initial` otherwise
`SSL_CLIENT_S_DN_CN` | NI*       | the common name (CN) of the distinguished name (DN) in the client certificate subject.
`SSL_CLIENT_CERT` | ExportCertData| the client certificate in PEM format.
`SSL_CLIENT_CHAIN_0` | ExportCertData| the 1st client chain certificate in PEM format.
`SSL_CLIENT_CHAIN_[1-9]` | ExportCertData| the 2nd to 10th client chain certificate in PEM format.
`SSL_SERVER_CERT` | ExportCertData| the selected server certificate in PEM format.

*) NI: Not Implemented

The variables exposing several fields in the client and server certificate, such as `SSL_CLIENT_S_DN_CN` are not
supported at the moment, as crustls is missing code to parse x.509 certificates.

The variable `SSL_SESSION_ID` is intentionally not supported as it contains sensitive information.

### Client Certificates

NOTE: the current implementation is incomplete. Certificates are checked and validated, however the necessary field names are not extracted and hosted applications do not see a user name.

You may use client certificates in a server/virtual host. They might be optional or required. Validation is performed against a set of root certificates which you need to provide in a PEM file. An example would be:

```
<VirtalHost *:443>
  ServerName b.net
  TLSClientCertificate required
  TLSClientCA my_client_roots.pem
  ...
</VirtualHost>
```

Contrary to `mod_ssl` this can not be specified at directory level, only on a host or the complete server. 
The reason behind this is that `rustls` does not allow renegotiation in an ongoing TLS connection.

## Directives

The following configuration directives are available once `mod_tls` is loaded into Apache:

### `TLSListen`
 
`TLSListen [address:]port` defines on which address+port the module shall handle incoming connections. 

This is similar to the [Listen](https://httpd.apache.org/docs/2.4/en/bind.html) binding directive of Apache. You can use `TLSListen` several times to use more than one binding address.
 
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

* `StdEnvVars`: adds more variables to the requests environemnt, as forwarded for example to CGI processing and other applications.
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

