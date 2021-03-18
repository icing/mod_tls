/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_defs_h
#define tls_defs_h

#include <mpm_common.h>
#include <httpd.h>
#include <http_core.h>

#include <crustls.h>

#define TLS_DIM(a)      (sizeof(a)/sizeof(a[0]))

/* An iteration context that hold userdata and a pool for allocations. */
typedef struct {
    apr_pool_t *pool;
    server_rec *s;
    conn_rec *c;
    request_rec *r;
    void *userdata;
} tls_iter_ctx_t;

#endif /* tls_def_h */

