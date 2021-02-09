/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_filter_h
#define tls_filter_h

#define TLS_FILTER_RAW    "TLS raw"

void tls_filter_register(apr_pool_t *pool);

int tls_filter_conn_init(conn_rec *c);

int tls_filter_pre_connection(conn_rec *c, void *csd);

#endif /* tls_filter_h */