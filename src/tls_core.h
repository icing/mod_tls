/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_core_h
#define tls_core_h

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
 * Decide upon the real server_rec (vhost) to use on this connection,
 * initialize the module's connection settings, instantiated the real
 * rustls session, etc.
 */
apr_status_t tls_core_conn_server_init(conn_rec *c);

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

#endif /* tls_core_h */