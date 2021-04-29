/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_ocsp_h
#define tls_ocsp_h

/**
 * Prime the collected certified keys for OCSP response provisioning (aka. Stapling).
 *
 * To be called in the post-config phase of the server before connections are handled.
 * @param gc the global module configuration with the certified_key registry
 * @param p the pool to use for allocations
 * @param s the base server record
 */
apr_status_t tls_ocsp_prime_certs(tls_conf_global_t *gc, apr_pool_t *p, server_rec *s);

/**
 * Provide the OCSP response data for the certified_key into the offered buffer,
 * so available.
 * If not data is available `out_n` is set to 0. Same, if the offered buffer
 * is not large enough to hold the complete response.
 * If OCSP response DER data is copied, the number of copied bytes is given in `out_n`.
 *
 * Note that only keys that have been primed initially will have OCSP data available.
 * @param c the current connection
 * @param certified_key the key to get the OCSP response data for
 * @param buf a buffer which can hold up to `buf_len` bytes
 * @param buf_len the length of `buf`
 * @param out_n the number of OCSP response DER bytes copied or 0.
 */
apr_status_t tls_ocsp_update_key(
    conn_rec *c, const rustls_certified_key *certified_key,
    const rustls_certified_key **key_out);

#endif /* tls_ocsp_h */
