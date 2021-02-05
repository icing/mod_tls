/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_conf_h
#define tls_conf_h

#include "tls_defs.h"

extern const command_rec tls_conf_cmds[];

void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s);
void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv);

tls_conf_server_t *tls_conf_server_get(server_rec *s);

tls_conf_conn_t *tls_conf_conn_get(conn_rec *c);
void tls_conf_conn_set(conn_rec *c, tls_conf_conn_t *cc);

#endif /* tls_conf_h */