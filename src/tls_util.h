/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_util_h
#define tls_util_h

/* Return != 0 if fpath is a 'real' file */
int tls_util_is_file(apr_pool_t *p, const char *fpath);

apr_status_t tls_util_rustls_error(apr_pool_t *p, rustls_result rr, const char **perr_descr);


typedef struct {
    unsigned char *cert_pem_bytes;
    size_t cert_pem_len;
    unsigned char *key_pem_bytes;
    size_t key_pem_len;
} tls_util_cert_pem_t;

apr_status_t tls_util_load_pem(apr_pool_t *p, tls_certificate_t *cert,
    tls_util_cert_pem_t **ppem);

#endif /* tls_util_h */