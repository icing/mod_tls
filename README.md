# mod_tls - memory safety for TLS in Apache

This repository contains `mod_tls`, a module for Apache httpd that uses
[rustls](https://github.com/ctz/rustls) to provide a memory safe TLS
implementation.

This project is sponsored by the [ISRG](https://www.abetterinternet.org). 
[Read what they said about it.](https://www.abetterinternet.org/post/memory-safe-tls-apache/).


## Goals

Vital:

 * ```https:``` connectivity for Apache virtual hosts, supporting SNI and ALPN.
 * Own configuration directives with secure defaults. The module will not be a drop-in
   replacement for ```mod_ssl```.
 * A test suite with a good coverage of the support TLS features.
 * A load test giving some performance indicators.
 * User manual on how to deploy/configure.

Aimed for:

 * Coexistence with ```mod_ssl```. There are setups where it is desirable to use
   ```mod_tls``` for frontend connections and ```mod_ssl``` for conections to backends.
   It is not intended to have a mixed configuration on frontends.
 * Provide OCSP Stapling via the [```mod_md```](https://github.com/icing/mod_md) module.
 * Provide use of ```mod_tls``` for back backend https: connections.

## Platforms

 * Apache 2.4.x (some patches or a newer release will most likely be necessary.)
 * OS: anything you can run apache and build rustls on
 * build system: autoconf/automake (for now)
