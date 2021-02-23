/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_conf_h
#define tls_conf_h

#include "tls_defs.h"

/* our static registry of configuration directives. */
extern const command_rec tls_conf_cmds[];

/* registered at apache when it needs to create the modules configuration for a server_rec. */
void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s);

/* registered at apache when it needs to merge (inherit) server configurations for
 * the module. The settings in 'add' overwrite the ones in 'base' and unspecified
 * settings shine through. */
void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv);

/* Get the server specific module configuration. */
tls_conf_server_t *tls_conf_server_get(server_rec *s);

#endif /* tls_conf_h */