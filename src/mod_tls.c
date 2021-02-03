/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#include <assert.h>
#include <apr_optional.h>
#include <apr_strings.h>

#include <mpm_common.h>
#include <httpd.h>
#include <http_core.h>
#include <http_log.h>

#include "mod_tls.h"
#include "mod_tls_config.h"
#include "mod_tls_version.h"

static void tls_hooks(apr_pool_t *pool);

AP_DECLARE_MODULE(md) = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per dir config */
    NULL,                  /* merge per dir config */
    tls_config_create_svr, /* create per server config */
    tls_config_merge_svr,  /* merge per server config (inheritance) */
    tls_config_cmds,       /* command handlers */
    tls_hooks,
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};

static apr_status_t tls_post_config(apr_pool_t *p, apr_pool_t *plog,
                                    apr_pool_t *ptemp, server_rec *s)
{
    const char *tls_init_key = "mod_tls_init_counter";
    int dry_run = 0;
    void *data = NULL;

    (void)p;
    (void)ptemp;
    (void)plog;

    apr_pool_userdata_get(&data, tls_init_key, s->process->pool);
    if (data == NULL) {
        /* At the first start, httpd makes a config check dry run
        * to see if the config is ok in principle.
         */
        dry_run = 1;
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s,
                     APLOGNO() "post config dry run");
        apr_pool_userdata_set((const void *)1, tls_init_key,
                              apr_pool_cleanup_null, s->process->pool);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO()
                     "mod_tls (v%s), initializing...", MOD_TLS_VERSION);
    }

    return APR_SUCCESS;
}

static void tls_hooks(apr_pool_t *pool)
{
    static const char *const mod_ssl[] = { "mod_ssl.c", NULL};

    ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");
    /* TODO: the order that config hooks run determines the order in which
     * vital filters are installed. There are challenges:
     * - some modules need to run before and/or after mod_ssl. they probably
     *   need to run before/after mod_tls as well.
     * - coexistence: if mod_ssl is loaded as well, does in matter where
     *   mod_tls runs in relation to it?
     */
    ap_hook_post_config(tls_post_config, mod_ssl, NULL, APR_HOOK_MIDDLE);
}
