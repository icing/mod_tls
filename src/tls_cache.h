/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_cache_h
#define tls_cache_h

/* name of the global session cache mutex, should we need it */
#define TLS_SESSION_CACHE_MUTEX_TYPE    "tls-session-cache"


/**
 * Set the specification of the session cache to use. The syntax is
 *   "default|none|<provider_name>(:<arguments>)?"
 *
 * @param spec the cache specification
 * @param gconf the modules global configuration
 * @param p pool for permanent allocations
 * @param ptemp  pool for temporary allocations
 * @return NULL on success or an error message
 */
const char *tls_cache_set_specification(
    const char *spec, tls_conf_global_t *gconf, apr_pool_t *p, apr_pool_t *ptemp);

/**
 * Setup before configuration runs, announces our potential global mutex.
 */
void tls_cache_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp);

/**
 * Verify the cache settings at the end of the configuration and
 * create the default session cache, if not already done.
 */
apr_status_t tls_cache_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s);

/**
 * Started a new child, make sure that global mutex we might use is set up.
 */
void tls_cache_init_child(apr_pool_t *p, server_rec *s);

/**
 * Free all cache related resources.
 */
void tls_cache_free(server_rec *s);

/**
 * Initialize the session store for the connections's config builder.

 * This needs to be done on the connection, and not globally or for a server,
 * since Apache's cache providers may make use of a pool which cannot be
 * global (leakage) nor would it be safe (pools are not thread safe).
 */
apr_status_t tls_cache_init_conn(
    rustls_server_config_builder *builder, conn_rec *c);

#endif /* tls_cache_h */