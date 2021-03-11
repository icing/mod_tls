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

typedef struct {
    const char *cert_file;
    const char *pkey_file;
    const char *cert_pem;
    const char *pkey_pem;
} tls_certificate_t;

typedef struct {
    const char *name;
    apr_uint16_t id;
} tls_cipher_t;

/* Configuration flags */
#define TLS_FLAG_UNSET  (-1)
#define TLS_FLAG_FALSE  (0)
#define TLS_FLAG_TRUE   (1)

#define TLS_VERSION_1_2   0x0303
#define TLS_VERSION_1_3   0x0304

/* The TLS protocol version to use */
#define TLS_PROTOCOL_AUTO  0x00
#define TLS_PROTOCOL_1_2   0x01
#define TLS_PROTOCOL_1_3   0x02

/* An iteration context that hold userdata and a pool for allocations. */
typedef struct {
    apr_pool_t *pool;
    server_rec *s;
    conn_rec *c;
    request_rec *r;
    void *userdata;
} tls_iter_ctx_t;

#define TLS_VERSION_CONFIGURATION    0
#define TLS_CIPHER_CONFIGURATION    0

#endif /* tls_def_h */

