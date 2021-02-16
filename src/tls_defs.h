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
} tls_certificate_t;

#define TLS_FLAG_UNSET  (-1)
#define TLS_FLAG_FALSE  (0)
#define TLS_FLAG_TRUE   (1)

#define TLS_PROTO_AUTO  0
#define TLS_PROTO_1_2   2
#define TLS_PROTO_1_3   3

typedef struct {
    server_addr_rec *tls_addresses;   /* the addresses/port we are active on */
} tls_conf_global_t;

typedef struct {
    const server_rec *server;         /* server this config belongs to */
    const char *name;
    tls_conf_global_t *global;        /* global module config, singleton */

    int enabled;
    apr_array_header_t *certificates; /* array of (tls_certificate_t*) available for server_rec */
    int tls_proto;                    /* the minimum TLS protocol version */
    int honor_client_order;           /* honor client cipher ordering */
    const rustls_server_config *pre_config; /* config to create the connection's pre_session */
    const rustls_server_config *rustls_config; /* config to use for TLS against this very server */
} tls_conf_server_t;


typedef enum {
    TLS_CONN_ST_IGNORED,
    TLS_CONN_ST_PRE_HANDSHAKE,
    TLS_CONN_ST_HANDSHAKE,
    TLS_CONN_ST_TRAFFIC,
    TLS_CONN_ST_NOTIFIED,
    TLS_CONN_ST_DONE,
} tls_conn_state_t;

typedef struct {
    server_rec *server;               /* the server_rec selected for this connection,
                                       * initially c->base_server, to be negotiated. */
    tls_conn_state_t state;
    rustls_server_session *rustls_session;
    const char *sni_hostname;         /* the SNI value from the client */
    int flag_vhost_found;             /* the virtual host selected by SNI has been found. */
} tls_conf_conn_t;

#endif /* tls_def_h */

