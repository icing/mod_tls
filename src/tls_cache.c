/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */

#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_connection.h>
#include <http_log.h>
#include <ap_socache.h>
#include <util_mutex.h>

#include "tls_defs.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_cache.h"

extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

#define TLS_CACHE_DEF_PROVIDER      "shmcb"
#define TLS_CACHE_DEF_DIR           "tls"
#define TLS_CACHE_DEF_FILE          "session_cache"
#define TLS_CACHE_DEF_SIZE          512000

static const char *cache_provider_unknown(const char *name, apr_pool_t *p)
{
    apr_array_header_t *known;
    const char *known_names;

    known = ap_list_provider_names(p, AP_SOCACHE_PROVIDER_GROUP,
                                   AP_SOCACHE_PROVIDER_VERSION);
    known_names = apr_array_pstrcat(p, known, ',');
    return apr_psprintf(p, "cache type '%s' not supported "
                        "(known names: %s). Maybe you need to load the "
                        "appropriate socache module (mod_socache_%s?).",
                        name, known_names, name);
}

void tls_cache_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    (void)plog;
    (void)ptemp;
    /* we make this visible, in case someone wants to configure it.
     * this does not mean that we will really use it, which is determined
     * by configuration and cache provider capabilities. */
    ap_mutex_register(pconf, TLS_SESSION_CACHE_MUTEX_TYPE, NULL, APR_LOCK_DEFAULT, 0);
}

static const char *cache_init(tls_conf_global_t *gconf, apr_pool_t *p, apr_pool_t *ptemp)
{
    const char *err = NULL;
    const char *name, *args = NULL;
    apr_status_t rv;

    if (gconf->session_cache) {
        goto cleanup;
    }
    else if (!apr_strnatcasecmp("none", gconf->session_cache_spec)) {
        gconf->session_cache_provider = NULL;
        gconf->session_cache = NULL;
        goto cleanup;
    }
    else if (!apr_strnatcasecmp("default", gconf->session_cache_spec)) {
        const char *path = TLS_CACHE_DEF_DIR;

#if AP_MODULE_MAGIC_AT_LEAST(20180906, 2)
        path = ap_state_dir_relative(p, path);
#endif
        gconf->session_cache_spec = apr_psprintf(p, "%s:%s/%s(%ld)",
            TLS_CACHE_DEF_PROVIDER, path, TLS_CACHE_DEF_FILE, (long)TLS_CACHE_DEF_SIZE);
    }

    name = gconf->session_cache_spec;
    args = ap_strchr(name, ':');
    if (args) {
        name = apr_pstrmemdup(p, name, (apr_size_t)(args - name));
        ++args;
    }
    gconf->session_cache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP,
                                                       name, AP_SOCACHE_PROVIDER_VERSION);
    if (!gconf->session_cache_provider) {
        err = cache_provider_unknown(name, p);
        goto cleanup;
    }
    err = gconf->session_cache_provider->create(&gconf->session_cache, args, ptemp, p);
    if (err != NULL) goto cleanup;

    if (gconf->session_cache_provider->flags & AP_SOCACHE_FLAG_NOTMPSAFE
        && !gconf->session_cache_mutex) {
        /* we need a global lock to access the cache */
        rv = ap_global_mutex_create(&gconf->session_cache_mutex, NULL,
            TLS_SESSION_CACHE_MUTEX_TYPE, NULL, gconf->ap_server, p, 0);
        if (APR_SUCCESS != rv) {
            err = apr_psprintf(p, "error setting up global %s mutex: %d",
                TLS_SESSION_CACHE_MUTEX_TYPE, rv);
            gconf->session_cache_mutex = NULL;
            goto cleanup;
        }
    }

cleanup:
    if (NULL != err) {
        gconf->session_cache_provider = NULL;
        gconf->session_cache = NULL;
    }
    return err;
}

const char *tls_cache_set_specification(
    const char *spec, tls_conf_global_t *gconf, apr_pool_t *p, apr_pool_t *ptemp)
{
    gconf->session_cache_spec = spec;
    return cache_init(gconf, p, ptemp);
}

apr_status_t tls_cache_post_config(apr_pool_t *p, apr_pool_t *ptemp, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    const char *err;
    apr_status_t rv = APR_SUCCESS;

    err = cache_init(sc->global, p, ptemp);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO()
                     "default session cache could not be initialized from '%s': %s",
                     sc->global->session_cache_spec, err);
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO()
                     "will continue without session cache. Consider specifying an "
                     "explicit one using 'TLSSessionCache' or make sure that the "
                     "necessary cache module is loaded.");
    }
    else if (sc->global->session_cache) {
        struct ap_socache_hints hints;

        memset(&hints, 0, sizeof(hints));
        hints.avg_obj_size = 150;
        hints.avg_id_len = 30;
        hints.expiry_interval = 30;

        rv = sc->global->session_cache_provider->init(
            sc->global->session_cache, "mod_tls-sess", &hints, s, p);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, APLOGNO()
                         "error initializing session cache.");
        }
    }
    return rv;
}

void tls_cache_init_child(apr_pool_t *p, server_rec *s)
{
    tls_conf_server_t *sc = tls_conf_server_get(s);
    const char *lockfile;
    apr_status_t rv;

    if (sc->global->session_cache_mutex) {
        lockfile = apr_global_mutex_lockfile(sc->global->session_cache_mutex);
        rv = apr_global_mutex_child_init(&sc->global->session_cache_mutex, lockfile, p);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                         "Cannot reinit %s mutex (file `%s`)",
                         TLS_SESSION_CACHE_MUTEX_TYPE, lockfile? lockfile : "-");
        }
    }
}

static void tls_cache_lock(tls_conf_global_t *gconf)
{
    if (gconf->session_cache_mutex) {
        apr_status_t rv = apr_global_mutex_lock(gconf->session_cache_mutex);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, gconf->ap_server, APLOGNO()
                         "Failed to acquire TLS session cache lock");
        }
    }
}

static void tls_cache_unlock(tls_conf_global_t *gconf)
{
    if (gconf->session_cache_mutex) {
        apr_status_t rv = apr_global_mutex_unlock(gconf->session_cache_mutex);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, gconf->ap_server, APLOGNO()
                         "Failed to release TLS session cache lock");
        }
    }
}

static int tls_cache_get(
    void *userdata,
    const rustls_slice_bytes *key,
    unsigned char *buf,
    size_t count,
    int remove_after,
    size_t *out_n)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc = tls_conf_server_get(cc->server);
    apr_status_t rv = APR_ENOENT;
    unsigned int val_len;

    if (!sc->global->session_cache) goto not_found;
    tls_cache_lock(sc->global);

    val_len = (unsigned int)count;
    rv = sc->global->session_cache_provider->retrieve(
        sc->global->session_cache, cc->server,
        key->data, (unsigned int)key->len, buf, &val_len, c->pool);

    if (remove_after || APR_SUCCESS != rv) {
        sc->global->session_cache_provider->remove(
            sc->global->session_cache, cc->server,
            key->data, (unsigned int)key->len, c->pool);
    }

    tls_cache_unlock(sc->global);
    if (APR_SUCCESS != rv) goto not_found;
    *out_n = count;
    return 1;

not_found:
    *out_n = 0;
    return 0;
}

static int tls_cache_put(
    void *userdata,
    const rustls_slice_bytes *key,
    const rustls_slice_bytes *val)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc = tls_conf_server_get(cc->server);
    apr_status_t rv = APR_ENOENT;
    apr_time_t expiry;
    unsigned char *data;

    if (!sc->global->session_cache) goto not_stored;
    tls_cache_lock(sc->global);

    expiry = apr_time_now() + apr_time_from_sec(300);
    data = (unsigned char *)apr_pstrmemdup(c->pool, (const char*)val->data, val->len);
    rv = sc->global->session_cache_provider->store(sc->global->session_cache, cc->server,
        (unsigned char*)key->data, (unsigned int)key->len, expiry,
        (unsigned char*)val->data, (unsigned int)val->len, c->pool);
    tls_cache_unlock(sc->global);
    if (APR_SUCCESS != rv) goto not_stored;
    return 1;

not_stored:
    return 0;
}

apr_status_t tls_cache_init_conn(
    rustls_server_config_builder *builder, conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc = cc? tls_conf_server_get(cc->server) : NULL;

    if (sc && sc->global->session_cache && /* DISABLES CODE */(1)) {
        rustls_server_config_builder_set_persistence(
            builder, c, tls_cache_get, tls_cache_put);
    }
    return APR_SUCCESS;
}
