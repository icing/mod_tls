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

#include "tls_util.h"

int tls_util_is_file(apr_pool_t *p, const char *fpath)
{
    apr_finfo_t finfo;

    return (fpath != NULL
        && apr_stat(&finfo, fpath, APR_FINFO_TYPE|APR_FINFO_SIZE, p) == 0
        && finfo.filetype == APR_REG);
}

#include "tls_util.h"

