/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_ocsp_h
#define tls_ocsp_h

apr_status_t tls_ocsp_prime_certs(tls_conf_global_t *gc, apr_pool_t *p, server_rec *s);

void tls_ocsp_provide_resp(
    void *userdata, const rustls_certified_key *certified_key,
    unsigned char *buf, size_t buf_len, size_t *out_n);

#endif /* tls_ocsp_h */
