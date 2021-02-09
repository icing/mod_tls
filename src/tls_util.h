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


apr_status_t tls_util_file_load(
    apr_pool_t *p, const char *fpath, size_t min_len, size_t max_len,
    unsigned char **pbuffer, apr_size_t *plen);


typedef struct {
    unsigned char *cert_pem_bytes;
    size_t cert_pem_len;
    unsigned char *pkey_pem_bytes;
    size_t pkey_pem_len;
} tls_util_cert_pem_t;

apr_status_t tls_util_load_pem(apr_pool_t *p, tls_certificate_t *cert,
    tls_util_cert_pem_t **ppem);


/**
 * Transfer up to <length> bytes from <src> to <dest>, including all
 * encountered meta data buckets. The transfered buckets/data are
 * removed from <src>.
 * Return the actual byte count transfered in <pnout>.
 */
apr_status_t tls_util_brigade_transfer(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout);

/**
 * Copy up to <length> bytes from <src> to <dest>, including all
 * encountered meta data buckets. <src> remains semantically unchaanged,
 * meaning there might have been buckets split or changed while reading
 * their content.
 * Return the actual byte count copied in <pnout>.
 */
apr_status_t tls_util_brigade_copy(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout);

#endif /* tls_util_h */