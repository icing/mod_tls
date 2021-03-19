# mod_tls - memory safety for TLS in Apache

This repository contains `mod_tls`, a module for Apache httpd that uses
[rustls](https://github.com/ctz/rustls) to provide a memory safe TLS
implementation in Rust.

This project is sponsored by the [ISRG](https://www.abetterinternet.org). 
[Read what they said about it.](https://www.abetterinternet.org/post/memory-safe-tls-apache/).


## Status

In development. The module currently only works with an patched [crustls](https://github.com/abetterinternet/crustls),
the `C` binding for the `rustls` crate and the `trunk` version of the Apache httpd server.

Apache `trunk` has received patches that allow two (or more) SSL providing modules
to be loaded and active on the same server. This required an extension of the core
API which is currently in trunk after review by the team. The goal is to propose
these changes for backport into a 2.4.x version when this becomes stabilized.

`mod_tls` supports:
 
 * TLS for incoming connections on a address+port. You can use `mod_ssl` on another port at the same time.
 * certificates for the server and/or a virtual host. You may specify more than one certificate for a host and the first one matching client capabilities will be chosen.
 * protocol versions. You may specify the minimum version to use.
 * cipher preferences. You may specified the ciphers that should be considered first during negotiation. This does not disable any other ciphers.
 * cipher supression. You may specify ciphers that are never used. All unmentioned ciphers remain active.
 * cipher client order disregard. By default, the order of client supplied ciphers is honored.
 * option to forward certain variables, such as `SSL_CIPHER` and `SSL_PROTOCOL` to request processing.

`mod_tls` currently does **not** support:
 
  * client certificates
  * backend connections (via `mod_proxy`)
  * OCSP Stapling 

## Platforms

 * Apache trunk (2.4.x is the intended target later)
 * OS: whereever apache and (c)rustls are available
 * build system: autoconf/automake

### Installation from source

Run the usual autoconf/automake magic incantations. You need a built Apache trunk and specify the `--with-apxe=<path>/bin/apxs` on configuration if that is not in your `$PATH`. Also, you need a modified [crustls](https://github.com/icing/crustls/tree/icing/main) (that is my fork branch with the changes) installed.

Run the usual autoconf/automake magic incantations.

```
> autoreconf -i
> automake
> autoconf
> ./configure --with-apxs=<path to apxs>
> make
```

## Tests

### Functional Tests

If you want to run the test suite, you need:

 * `curl` and `openssl` in your path
 * Some Python packages: `pytest`, `pyopenssl`

```
> make test
```

### Load Tests

There are load tests for putting the module und a bit of pressure and getting some numbers.
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

The following configuration directives are available once `mod_tls` is loaded into Apache:

 * `TLSListen [address:]port` to define on which port the module shall handle incoming connections. This is similar to the [Listen](https://httpd.apache.org/docs/2.4/en/bind.html) binding directive of Apache. You can use `TLSListen` several times to use more than one binding address.
 
 * `TLSCertificate cert_file [key_file]` to add a certificate file (PEM encoded) to the server/virtual host. If you do not specify a separate key file, the key is assumed to also be found in the first file. You may add more than one certificate to a server/virtual host. The first certificate suitable for a client is then chosen.

 * `TLSProtocol version+` to specify the minimum version of the TLS protocol to use. The default is `v1.2+`. Settings this to `v1.3+` would disable TLSv1.2.

 * `TLSCipherPrefer cipher(-list)` to define ciphers that are preferred. This will not disable any ciphers supported by `rustls`. If you specify a cipher that is completely unkown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

 * `TLSCipherSuppress cipher(-list)` to define ciphers that are not used. This will not disable any unmentioned ciphers supported by `rustls`. If you specify a cipher that is completely unkown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

 * `TLSHonorClientOrder on|off` to pay attention to the order of ciphers supported by the client. This is `on` by default.

 * `TLSOptions [+|-]StdEnvVars` this is analog to `SSLOptions` in `mod_ssl` and only relevant if you want to have certain TLS connection properties visible to request processing. This can be set per directory/location.

 * `TLSSessionCache cache-spec` to specify the cache for TLS session resumption. This uses a cache on the server side to allow clients to resume connections. You can set this to `none` or define a cache as in the [`SSLSessionCache`](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslsessioncache) directive. If not configured, `mod_tls` will try to create a shared memory cache on its own, using `shmcb:tls/session-cache` as specification. Should that fail, a warning is logged, but the server continues.

The gist of all this to give the server administrator enough control to ensure the safety of the system without it necessarily becoming *ossified*. Many installations have copy+paste TLS specifications from years ago and those can hinder deployment of improved implementations. On the other hand, should a specific setting turn out to be non-secure, an admin needs to be able to disable it right away (until the proper fix comes down the release lines). That is why one may suppress ciphers (and if one supresses all ciphers in a protocol version, that version is effectively disabled as well).

It is impossible to foresee future surprises - that is the nature of them.


### Cipher Names

These are still under discussion. People seem to have an opinion. The names are defined in [`tls_proto.c`](src/tls_proto.c) and examples currently are: `TLS13_CHACHA20_POLY1305_SHA256` and `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.

When specifying several ciphers, these can be separated by whitespace or `:`. For example:

```
TLSCiphersPrefer TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS13_CHACHA20_POLY1305_SHA256
TLSCiphersPrefer TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  TLS13_CHACHA20_POLY1305_SHA256
TLSCiphersPrefer TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 \
                 TLS13_CHACHA20_POLY1305_SHA256
```

would all work. You can also mix those.