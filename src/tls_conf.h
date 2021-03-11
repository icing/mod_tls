/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_conf_h
#define tls_conf_h

/* The global module configuration, created after post-config
 * and then readonly.
 */
typedef struct {
    server_addr_rec *tls_addresses;   /* the addresses/port we are active on */
    apr_hash_t *supported_ciphers;    /* hash by name of tls_cipher_t* */
    apr_hash_t *var_lookups;          /* variable lookup functions by var name */
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
    int tls_protocols;                /* the minimum TLS protocol version */
    apr_array_header_t *tls_ciphers;  /* List of tls_cipher_t*, if not default */
    int honor_client_order;           /* honor client cipher ordering */

    int service_unavailable;          /* TLS not trustworthy configured, return 503s */
    const rustls_server_config *rustls_config; /* config to use for TLS against this very server */
} tls_conf_server_t;

typedef struct {
    int std_env_vars;
} tls_conf_dir_t;

/* our static registry of configuration directives. */
extern const command_rec tls_conf_cmds[];

/* create the modules configuration for a server_rec. */
void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s);

/* merge (inherit) server configurations for the module.
 * Settings in 'add' overwrite the ones in 'base' and unspecified
 * settings shine through. */
void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv);

/* create the modules configuration for a directory. */
void *tls_conf_create_dir(apr_pool_t *pool, char *dir);

/* merge (inherit) directory configurations for the module.
 * Settings in 'add' overwrite the ones in 'base' and unspecified
 * settings shine through. */
void *tls_conf_merge_dir(apr_pool_t *pool, void *basev, void *addv);


/* Get the server specific module configuration. */
tls_conf_server_t *tls_conf_server_get(server_rec *s);

/* Get the directory specific module configuration for the request. */
tls_conf_dir_t *tls_conf_dir_get(request_rec *r);

/* If any configuration values are unset, supply the global defaults. */
apr_status_t tls_conf_server_apply_defaults(tls_conf_server_t *sc, apr_pool_t *p);

#endif /* tls_conf_h */