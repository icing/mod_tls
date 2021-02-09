/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */

#include <assert.h>
#include <apr_lib.h>
#include <apr_file_info.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "tls_defs.h"
#include "tls_util.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


apr_status_t tls_util_rustls_error(
    apr_pool_t *p, rustls_result rr, const char **perr_descr)
{
    char buffer[HUGE_STRING_LEN];
    apr_size_t len = 0;

    rustls_error(rr, buffer, sizeof(buffer), &len);
    *perr_descr = apr_pstrndup(p, buffer, len);
    return APR_EGENERAL;
}

int tls_util_is_file(
    apr_pool_t *p, const char *fpath)
{
    apr_finfo_t finfo;

    return (fpath != NULL
        && apr_stat(&finfo, fpath, APR_FINFO_TYPE|APR_FINFO_SIZE, p) == 0
        && finfo.filetype == APR_REG);
}

apr_status_t tls_util_file_load(
    apr_pool_t *p, const char *fpath, apr_size_t min_len, apr_size_t max_len,
    unsigned char **pbuffer, apr_size_t *plen)
{
    apr_finfo_t finfo;
    apr_status_t rv;
    apr_file_t *f = NULL;
    unsigned char *buffer;
    apr_size_t len;
    const char *err = NULL;

    rv = apr_stat(&finfo, fpath, APR_FINFO_TYPE|APR_FINFO_SIZE, p);
    if (APR_SUCCESS != rv) {
        err = "cannot stat"; goto cleanup;
    }
    if (finfo.filetype != APR_REG) {
        err = "not a plain file";
        rv = APR_EINVAL; goto cleanup;
    }
    if (finfo.size > LONG_MAX) {
        err = "file is too large";
        rv = APR_EINVAL; goto cleanup;
    }
    len = (apr_size_t)finfo.size;
    if (len < min_len || len > max_len) {
        err = "file size not in allowed range";
        rv = APR_EINVAL; goto cleanup;
    }
    buffer = apr_pcalloc(p, len);
    rv = apr_file_open(&f, fpath, APR_FOPEN_READ, 0, p);
    if (APR_SUCCESS != rv) {
        err = "error opening"; goto cleanup;
    }
    rv = apr_file_read(f, buffer, &len);
    if (APR_SUCCESS != rv) {
        err = "error reading"; goto cleanup;
    }
cleanup:
    if (f) apr_file_close(f);
    if (APR_SUCCESS == rv) {
        *pbuffer = buffer;
        *plen = len;
    }
    else {
        *pbuffer = NULL;
        *plen = 0;
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, p, APLOGNO()
                      "Failed to load file %s: %s", fpath, err? err: "-");
    }
    return rv;
}

apr_status_t tls_util_load_pem(
    apr_pool_t *p, tls_certificate_t *cert, tls_util_cert_pem_t **ppem)
{
    apr_status_t rv;
    tls_util_cert_pem_t *cpem;

    cpem = apr_pcalloc(p, sizeof(*cpem));
    rv = tls_util_file_load(p, cert->cert_file, 0, 100*1024,
        &cpem->cert_pem_bytes, &cpem->cert_pem_len);
    if (APR_SUCCESS != rv) goto cleanup;
    rv = tls_util_file_load(p, cert->pkey_file, 0, 100*1024,
        &cpem->pkey_pem_bytes, &cpem->pkey_pem_len);
    if (APR_SUCCESS != rv) goto cleanup;

cleanup:
    *ppem = (APR_SUCCESS == rv)? cpem : NULL;
    return rv;
}

apr_status_t tls_util_brigade_transfer(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout)
{
    apr_bucket *b;
    apr_off_t remain = length;
    apr_status_t rv = APR_SUCCESS;
    const char *ign;
    apr_size_t ilen;

    *pnout = 0;
    while (!APR_BRIGADE_EMPTY(src)) {
        b = APR_BRIGADE_FIRST(src);

        if (APR_BUCKET_IS_METADATA(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(dest, b);
        }
        else {
            if (remain == (apr_off_t)b->length) {
                /* fall through */
            }
            else if (remain <= 0) {
                goto cleanup;
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    rv= apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (APR_SUCCESS != rv) goto cleanup;
                }
                if (remain < (apr_off_t)b->length) {
                    apr_bucket_split(b, (apr_size_t)remain);
                }
            }
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(dest, b);
            remain -= b->length;
            *pnout += b->length;
        }
    }
cleanup:
    return rv;
}

apr_status_t tls_util_brigade_copy(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout)
{
    apr_bucket *b, *next;
    apr_off_t remain = length;
    apr_status_t rv = APR_SUCCESS;
    const char *ign;
    apr_size_t ilen;

    *pnout = 0;
    for (b = APR_BRIGADE_FIRST(src);
         b != APR_BRIGADE_SENTINEL(src);
         b = next) {
        next = APR_BUCKET_NEXT(b);

        if (APR_BUCKET_IS_METADATA(b)) {
            /* fall through */
        }
        else {
            if (remain == (apr_off_t)b->length) {
                /* fall through */
            }
            else if (remain <= 0) {
                goto cleanup;
            }
            else {
                if (b->length == ((apr_size_t)-1)) {
                    rv = apr_bucket_read(b, &ign, &ilen, APR_BLOCK_READ);
                    if (APR_SUCCESS != rv) goto cleanup;
                }
                if (remain < (apr_off_t)b->length) {
                    apr_bucket_split(b, (apr_size_t)remain);
                }
            }
        }
        rv = apr_bucket_copy(b, &b);
        if (APR_SUCCESS != rv) goto cleanup;
        APR_BRIGADE_INSERT_TAIL(dest, b);
        remain -= b->length;
        *pnout += b->length;
    }
cleanup:
    return rv;
}
