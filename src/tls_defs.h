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

typedef struct {
    const char *cert_file;
    const char *pkey_file;
    const char *cert_pem;
    const char *pkey_pem;
} tls_certificate_t;

/* Configuration flags */
#define TLS_FLAG_UNSET  (-1)
#define TLS_FLAG_FALSE  (0)
#define TLS_FLAG_TRUE   (1)

/* The minimal TLS protocol version to use */
#define TLS_PROTO_AUTO  0
#define TLS_PROTO_1_2   2
#define TLS_PROTO_1_3   3

/* The global module configuration, created after post-config
 * and then readonly.
 */
typedef struct {
    server_addr_rec *tls_addresses;   /* the addresses/port we are active on */
} tls_conf_global_t;

/* The module configuration for a server (vhost).
 * Populated during config parsing, merged and completed
 * in the post config phase. Readonly after that.
 */
typedef struct {
    server_rec *server;         /* server this config belongs to */
    const char *name;
    tls_conf_global_t *global;        /* global module config, singleton */

    int enabled;
    apr_array_header_t *certificates; /* array of (tls_certificate_t*) available for server_rec */
    int tls_proto;                    /* the minimum TLS protocol version */
    int honor_client_order;           /* honor client cipher ordering */
    int service_unavailable;          /* TLS not trustworthy configured, return 503s */
    const rustls_server_config *rustls_config; /* config to use for TLS against this very server */
} tls_conf_server_t;


#endif /* tls_def_h */

