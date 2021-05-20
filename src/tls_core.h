/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_core_h
#define tls_core_h

/* The module's state handling of a connection in normal chronological order,
 */
typedef enum {
    TLS_CONN_ST_IGNORED,
    TLS_CONN_ST_PRE_HANDSHAKE,
    TLS_CONN_ST_HANDSHAKE,
    TLS_CONN_ST_TRAFFIC,
    TLS_CONN_ST_NOTIFIED,
    TLS_CONN_ST_DONE,
} tls_conn_state_t;

struct tls_filter_ctx_t;

/* The modules configuration for a connection. Created at connection
 * start and mutable during the lifetime of the connection.
 * (A conn_rec is only ever processed by one thread at a time.)
 */
typedef struct {
    server_rec *server;               /* the server_rec selected for this connection,
                                       * initially c->base_server, to be negotiated via SNI. */
    tls_conn_state_t state;
    int service_unavailable;          /* we 503 all requests on this connection */
    int client_hello_seen;            /* the client hello has been inspected */

    const rustls_server_config *rustls_config; /* the config specially made for this connection or NULL */
    rustls_server_session *rustls_session; /* the session used on this connection or NULL */

    apr_array_header_t *local_keys;   /* rustls_certified_key* array of connection specific keys */
    const rustls_certified_key *key;  /* the key selected for the session */
    int key_cloned;                   /* != 0 iff the key is a unique clone, to be freed */
    struct tls_filter_ctx_t *filter_ctx; /* the context used by this connection's tls filters */

    const char *sni_hostname;         /* the SNI value from the client hello, or NULL */
    const apr_array_header_t *alpn;   /* the protocols proposed via ALPN by the client */
    const char *protocol_selected;    /* the ALPN selected protocol or NULL */
    apr_uint16_t tls_protocol_id;      /* the TLS version negotiated */
    const char *tls_protocol_name;     /* the name of the TLS version negotiated */
    apr_uint16_t tls_cipher_id;       /* the TLS cipher suite negotiated */
    const char *tls_cipher_name;      /* the name of TLS cipher suite negotiated */
    const rustls_certificate *client_cert; /* handshaked client ceritificate or NULL */
    int session_id_cache_hit;         /* if a submitted session id was found in our cache */

    apr_table_t *subprocess_env;      /* common TLS variables for this connection */

    rustls_result last_error;
    const char *last_error_descr;

} tls_conf_conn_t;

/* Get the connection specific module configuration. */
tls_conf_conn_t *tls_conf_conn_get(conn_rec *c);

/* Set the module configuration for a connection. */
void tls_conf_conn_set(conn_rec *c, tls_conf_conn_t *cc);

/* Return OK iff this connection is a TSL connection (or a secondary on a TLS connection). */
int tls_conn_check_ssl(conn_rec *c);

/**
 * Initialize the module's global and server specific settings. This runs
 * in Apache's "post-config" phase, meaning the configuration has been read
 * and checked for syntactic and other easily verifiable errors and now
 * it is time to load everything in and make it ready for traffic.
 * <p>      a memory pool staying with us the whole time until the server stops/reloads.
 * <ptemp>  a temporary pool as a scratch buffer that will be destroyed shortly after.
 * <base_server> the server for the global configuration which links -> next to
 *          all contained virtual hosts configured.
 */
apr_status_t tls_core_init(apr_pool_t *p, apr_pool_t *ptemp, server_rec *base_server);

/**
 * Initialize the module for the new connection based on 'c->base_server'.
 * The connection might not be for TLS which is then rememberd at the config.
 */
int tls_core_conn_base_init(conn_rec *c);

/**
 * Called when the ClientHello has been received and values from it
 * have been extracted into the `tls_conf_conn_t` of the connection.
 *
 * Decides:
 * - which `server_rec` this connection is for (SNI)
 * - which application protocol to use (ALPN)
 * This may be unsuccessful for several reasons. The SNI
 * from the client may not be known or the selected server
 * has not certificates available. etc.
 * On success, a proper `rustls_server_session` will have been
 * created and set in the `tls_conf_conn_t` of the connection.
 */
apr_status_t tls_core_conn_init_server(conn_rec *c);

/**
 * The TLS handshake for the connection has been successfully performed.
 * This means that TLS related properties, such as TLS version and cipher,
 * are known and the props in `tls_conf_conn_t` of the connection
 * can be set.
 */
apr_status_t tls_core_conn_post_handshake(conn_rec *c);

/**
 * After a request has been read, but before processing is started, we
 * check if everything looks good to us:
 * - was an SNI hostname provided by the client when we have vhosts to choose from?
 *   if not, we deny it.
 * - if the SNI hostname and request host are not the same, are they - from TLS
 *   point of view - 'compatible' enough? For example, if one server requires
 *   client certificates and the other not (or with different settings), such
 *   a request will also be denied.
 * returns DECLINED if everything is ok, otherwise an HTTP response code to
 *   generate an error page for.
 */
int tls_core_request_check(request_rec *r);

/**
 * A Rustls error happened while processing the connection. Look up an
 * error description, determine the apr_status_t to use for it and remember
 * this as the last error at tls_conf_conn_t.
 */
apr_status_t tls_core_error(conn_rec *c, rustls_result rr, const char **perrstr);

#endif /* tls_core_h */