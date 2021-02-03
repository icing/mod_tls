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
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>

#include "mod_tls_config.h"

extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

void *tls_config_create_svr(apr_pool_t *pool, server_rec *s)
{
    tls_config_srv_t *conf;

    conf = apr_pcalloc(pool, sizeof(*conf));
    conf->name = apr_pstrcat(pool, "srv[", CONF_S_NAME(s), "]", NULL);
    conf->s = s;

    return conf;
}

void *tls_config_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    tls_config_srv_t *base = (tls_config_srv_t *)basev;
    tls_config_srv_t *add = (tls_config_srv_t *)addv;
    tls_config_srv_t *nconfig;

    nconfig = apr_pcalloc(pool, sizeof(*nconfig));
    nconfig->name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);

    return nconfig;
}

static tls_config_srv_t *config_get_int(server_rec *s, apr_pool_t *p)
{
    tls_config_srv_t *sc = ap_get_module_config(s->module_config, &tls_module);
    ap_assert(sc);
    (void)p;
    return sc;
}

tls_config_srv_t *tls_config_get(server_rec *s)
{
    return config_get_int(s, NULL);
}

static const char *tls_config_bla(cmd_parms *cmd, void *dc, const char *value)
{
    tls_config_srv_t *sc = tls_config_get(cmd->server);

    (void)dc;
    (void)sc;
    (void)value;
    return NULL;
}

const command_rec tls_config_cmds[] = {
    /* none yet */
    AP_INIT_TAKE1("TLSBla", tls_config_bla, NULL, RSRC_CONF, ""),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
