/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_conf_h
#define tls_conf_h

extern const command_rec tls_conf_cmds[];

typedef struct {
    int dummy;
} tls_conf_global_t;

typedef struct {
    const server_rec *s;               /* server this config belongs to */
    const char *name;
    tls_conf_global_t *global;

    apr_array_header_t *certificates;
} tls_conf_server_t;

void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s);
void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv);

tls_conf_global_t *tls_conf_global_get(server_rec *s);
tls_conf_server_t *tls_conf_server_get(server_rec *s);

#endif /* tls_conf_h */