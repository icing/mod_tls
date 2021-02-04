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
#include <http_main.h>

#include "tls_defs.h"
#include "tls_conf.h"
#include "tls_util.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

static tls_conf_global_t *conf_global_get_or_make(apr_pool_t *p, server_rec *s)
{
    tls_conf_global_t *gconf;

    /* we create this only once for apache's one ap_server_conf.
     * If this gets called for another server, we should already have
     * done it for ap_server_conf. */
    if (ap_server_conf && s != ap_server_conf) {
        tls_conf_server_t *sconf = tls_conf_server_get(ap_server_conf);
        ap_assert(sconf);
        ap_assert(sconf->global);
        return sconf->global;
    }

    gconf = apr_pcalloc(p, sizeof(*gconf));
    return gconf;
}

tls_conf_server_t *tls_conf_server_get(server_rec *s)
{
    tls_conf_server_t *sc = ap_get_module_config(s->module_config, &tls_module);
    ap_assert(sc);
    return sc;
}


#define CONF_S_NAME(s)  (s && s->server_hostname? s->server_hostname : "default")

void *tls_conf_create_svr(apr_pool_t *pool, server_rec *s)
{
    tls_conf_server_t *conf;

    conf = apr_pcalloc(pool, sizeof(*conf));
    conf->name = apr_pstrcat(pool, "srv[", CONF_S_NAME(s), "]", NULL);
    conf->global = conf_global_get_or_make(pool, s);
    conf->s = s;

    conf->certificates = apr_array_make(pool, 3, sizeof(tls_certificate_t*));
    return conf;
}

void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    tls_conf_server_t *base = (tls_conf_server_t *)basev;
    tls_conf_server_t *add = (tls_conf_server_t *)addv;
    tls_conf_server_t *nconf;

    nconf = apr_pcalloc(pool, sizeof(*nconf));
    nconf->name = apr_pstrcat(pool, "[", CONF_S_NAME(add->s), ", ", CONF_S_NAME(base->s), "]", NULL);
    nconf->s = add->s;
    nconf->global = add->global? add->global : base->global;

    nconf->certificates = apr_array_append(pool, base->certificates, add->certificates);

    return nconf;
}

static const char *cmd_resolve_file(cmd_parms *cmd, const char **pfpath)
{
    char *real_path;

    /* just a dump of the configuration, dont resolve/check */
    if (ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_DUMP) {
        return NULL;
    }
    real_path = ap_server_root_relative(cmd->pool, *pfpath);
    if (!real_path) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": Invalid file path ", *pfpath, NULL);
    }
    *pfpath = real_path;

    if (!tls_util_is_file(cmd->pool, *pfpath)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": file '", *pfpath,
                           "' does not exist or is empty", NULL);
    }
    return NULL;
}

static const char *tls_conf_add_certificate(
    cmd_parms *cmd, void *dc, const char *cert_file, const char *key_file)
{
    tls_certificate_t *cert;
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    (void)dc;
    if (NULL != (err = cmd_resolve_file(cmd, &cert_file))
        || NULL != (err = cmd_resolve_file(cmd, &cert_file))) {
        goto cleanup;
    }
    cert = apr_pcalloc(cmd->pool, sizeof(*cert));
    cert->cert_file = cert_file;
    cert->key_file = key_file;
    *(const tls_certificate_t **)apr_array_push(sc->certificates) = cert;

cleanup:
    return err;
}

const command_rec tls_conf_cmds[] = {
    /* none yet */
    AP_INIT_TAKE2("TLSCertificate", tls_conf_add_certificate, NULL, RSRC_CONF, ""),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
