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

#include "tls_defs.h"
#include "tls_util.h"


int tls_util_is_file(apr_pool_t *p, const char *fpath)
{
    apr_finfo_t finfo;

    return (fpath != NULL
        && apr_stat(&finfo, fpath, APR_FINFO_TYPE|APR_FINFO_SIZE, p) == 0
        && finfo.filetype == APR_REG);
}

apr_status_t tls_util_rustls_error(apr_pool_t *p, rustls_result rr, const char **perr_descr)
{
    char buffer[HUGE_STRING_LEN];
    apr_size_t len = 0;

    rustls_error(rr, buffer, sizeof(buffer), &len);
    *perr_descr = apr_pstrndup(p, buffer, len);
    return APR_SUCCESS;
}


apr_status_t tls_util_load_pem(
    apr_pool_t *p, tls_certificate_t *cert, tls_util_cert_pem_t **ppem)
{
    (void)p;
    (void)cert;
    *ppem = NULL;
    return APR_ENOTIMPL;
}

