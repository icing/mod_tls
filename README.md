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
 * cipher suppression. You may specify ciphers that are never used. All unmentioned ciphers remain active.
 * cipher client order disregard. By default, the order of client supplied ciphers is honored.
 * option to forward certain variables, such as `SSL_CIPHER` and `SSL_PROTOCOL` to request processing.

`mod_tls` currently does **not** support:
 
  * client certificates
  * backend connections (via `mod_proxy`)
  * OCSP Stapling 

## Platforms

 * Apache trunk (2.4.x is the intended target later)
 * OS: wherever apache and (c)rustls are available
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

The following configuration directives are available once `mod_tls` is loaded into Apache:

 * `TLSListen [address:]port` to define on which port the module shall handle incoming connections. This is similar to the [Listen](https://httpd.apache.org/docs/2.4/en/bind.html) binding directive of Apache. You can use `TLSListen` several times to use more than one binding address.
 
 * `TLSCertificate cert_file [key_file]` to add a certificate file (PEM encoded) to the server/virtual host. If you do not specify a separate key file, the key is assumed to also be found in the first file. You may add more than one certificate to a server/virtual host. The first certificate suitable for a client is then chosen.

 * `TLSProtocol version+` to specify the minimum version of the TLS protocol to use. The default is `v1.2+`. Settings this to `v1.3+` would disable TLSv1.2.

 * `TLSCipherPrefer cipher(-list)` to define ciphers that are preferred. This will not disable any ciphers supported by `rustls`. If you specify a cipher that is completely unknown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

 * `TLSCipherSuppress cipher(-list)` to define ciphers that are not used. This will not disable any unmentioned ciphers supported by `rustls`. If you specify a cipher that is completely unknown, the configuration will fail. If you specify a cipher that is known but not supported by `rustls`, a warning will be logged but the server will continue.

 * `TLSHonorClientOrder on|off` to pay attention to the order of ciphers supported by the client. This is `on` by default.

 * `TLSOptions [+|-]StdEnvVars` this is analog to `SSLOptions` in `mod_ssl` and only relevant if you want to have certain TLS connection properties visible to request processing. This can be set per directory/location.

 * `TLSStrictSNI on|off` to enforce exact matches of client server indicators (SNI) against host names. Client connections will be unsuccessful if no match is found. This is `on` by default.

 * `TLSSessionCache cache-spec` to specify the cache for TLS session resumption. This uses a cache on the server side to allow clients to resume connections. You can set this to `none` or define a cache as in the [`SSLSessionCache`](https://httpd.apache.org/docs/current/mod/mod_ssl.html#sslsessioncache) directive. If not configured, `mod_tls` will try to create a shared memory cache on its own, using `shmcb:tls/session-cache` as specification. Should that fail, a warning is logged, but the server continues.

The gist of all this to give the server administrator enough control to ensure the safety of the system without it necessarily becoming *ossified*. Many installations have copy+paste TLS specifications from years ago and those can hinder deployment of improved implementations. On the other hand, should a specific setting turn out to be non-secure, an admin needs to be able to disable it right away (until the proper fix comes down the release lines). That is why one may suppress ciphers (and if one suppresses all ciphers in a protocol version, that version is effectively disabled as well).

### What to configure?

#### for security

The `rustls` library supports only TLS versions and ciphers that are nowadays (2021) considered secure for the internet. That means, unless a new weakness is discovered, the default configuration is safe to use. Most people will not have to configure anything besides the port(s) to listen on. And certificates if they do not use `mod_md` for that.

For people with special needs, there are ways to tweak protocol versions and ciphers and client orders. And those are described in more detail below.

The general gist of these configuration options is to give admins control, but allow for future enhancements. A server where a new TLS version can be run, should be able to. If some new cipher is added to TLSv1.3 in an attempt to overcome a newly found weakness, it should not require all servers to be reconfigured for its use. If an LTS installation gets new security features, maybe there is a reason for that.

If a cipher is deemed unsuitable by you, use `TLSCiphersSuppress` to disable it.

#### for performance

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

### Module/Library Versions

The versions of `crustls` binding and the `rustls` library are logged by `mod_tls` at level `INFO` at server startup. Configure `LogLevel tls:info` and you will see something like:

```
[date time] [tls:info] [pid] mod_tls (v0.1.0, crustls=crustls/0.3.0/rustls/0.19.0), initializing...
```

in your server log.

