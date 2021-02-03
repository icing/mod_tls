/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef mod_tls_config_h
#define mod_tls_config_h

extern const command_rec tls_config_cmds[];

typedef struct {
    const server_rec *s;               /* server this config belongs to */
} tls_config_srv_t;

void *tls_config_create_svr(apr_pool_t *pool, server_rec *s);
void *tls_config_merge_svr(apr_pool_t *pool, void *basev, void *addv);

#endif /* mod_tls_config_h */