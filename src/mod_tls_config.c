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

##include "mod_tls_config.h"

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
    md_srv_conf_t *base = (md_srv_conf_t *)basev;
    md_srv_conf_t *add = (md_srv_conf_t *)addv;
    md_srv_conf_t *nconfig;

    nconfig = apr_pcalloc(pool, sizeof(*nconfig));
    nconfig->name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);

    return nconfig;
}

const command_rec tls_config_cmds[] = {
    /* none yet */
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
