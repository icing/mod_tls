/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */

#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_version.h>

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

static tls_conf_global_t *conf_global_get_or_make(apr_pool_t *pool, server_rec *s)
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

    gconf = apr_pcalloc(pool, sizeof(*gconf));

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
    conf->server = s;

    conf->enabled = TLS_FLAG_UNSET;
    conf->certificates = apr_array_make(pool, 3, sizeof(tls_certificate_t*));
    conf->honor_client_order = TLS_FLAG_UNSET;
    conf->tls_proto = TLS_FLAG_UNSET;
    return conf;
}

#define MERGE_INT(base, add, field) \
    (add->field == TLS_FLAG_UNSET)? base->field : add->field;

void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    tls_conf_server_t *base = (tls_conf_server_t *)basev;
    tls_conf_server_t *add = (tls_conf_server_t *)addv;
    tls_conf_server_t *nconf;

    nconf = apr_pcalloc(pool, sizeof(*nconf));
    nconf->name = apr_pstrcat(pool, "[", CONF_S_NAME(add->server),
        ", ", CONF_S_NAME(base->server), "]", NULL);
    nconf->server = add->server;
    nconf->global = add->global? add->global : base->global;

    nconf->enabled = MERGE_INT(base, add, enabled);
    nconf->tls_proto = MERGE_INT(base, add, tls_proto);
    nconf->honor_client_order = MERGE_INT(base, add, honor_client_order);
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

static const char *tls_conf_add_listener(cmd_parms *cmd, void *dc, const char*v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    tls_conf_global_t *gc = sc->global;
    const char *err = NULL;
    char *host, *scope_id;
    apr_port_t port;
    apr_sockaddr_t *sa;
    server_addr_rec *sar;
    apr_status_t rv;

    (void)dc;
    /* Example of use:
     * TLSListen 443
     * TLSListen hostname:443
     * TLSListen 91.0.0.1:443
     * TLSListen [::0]:443
     */
    rv = apr_parse_addr_port(&host, &scope_id, &port, v, cmd->pool);
    if (APR_SUCCESS != rv) {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                          ": invalid address/port in '", v, "'", NULL);
        goto cleanup;
    }

    /* translate host/port to a sockaddr that we can match with incoming connections */
    rv = apr_sockaddr_info_get(&sa, host, APR_UNSPEC, port, 0, cmd->pool);
    if (APR_SUCCESS != rv) {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                          ": unable to get sockaddr for '", host, "'", NULL);
        goto cleanup;
    }

    if (scope_id) {
#if APR_VERSION_AT_LEAST(1,7,0)
        rv = apr_sockaddr_zone_set(sa, scope_id);
        if (APR_SUCCESS != rv) {
            err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                              ": error setting ipv6 scope id: '", scope_id, "'", NULL);
            goto cleanup;
        }
#else
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                          ": IPv6 scopes not supported by your APR: '", scope_id, "'", NULL);
        goto cleanup;
#endif
    }

    sar = apr_pcalloc(cmd->pool, sizeof(*sar));
    sar->host_addr = sa;
    sar->virthost = host;
    sar->host_port = port;

    sar->next = gc->tls_addresses;
    gc->tls_addresses = sar;
cleanup:
    return err;
}

static int flag_value(
    const char *arg)
{
    if (!strcasecmp(arg, "On")) {
        return TLS_FLAG_TRUE;
    }
    else if (!strcasecmp(arg, "Off")) {
        return TLS_FLAG_FALSE;
    }
    return TLS_FLAG_UNSET;
}

static const char *flag_err(
    cmd_parms *cmd, const char *v)
{
    return apr_pstrcat(cmd->pool, cmd->cmd->name,
        ": value must be 'On' or 'Off': '", v, "'", NULL);
}

static const char *tls_conf_add_certificate(
    cmd_parms *cmd, void *dc, const char *cert_file, const char *pkey_file)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;
    tls_certificate_t *cert;

    (void)dc;
    if (NULL != (err = cmd_resolve_file(cmd, &cert_file))) goto cleanup;
    if (NULL != (err = cmd_resolve_file(cmd, &pkey_file))) goto cleanup;

    cert = apr_pcalloc(cmd->pool, sizeof(*cert));
    cert->cert_file = cert_file;
    cert->pkey_file = pkey_file;
    *(const tls_certificate_t **)apr_array_push(sc->certificates) = cert;

cleanup:
    return err;
}

static const char *tls_conf_set_honor_client_order(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    int flag = flag_value(v);

    (void)dc;
    if (TLS_FLAG_UNSET == flag) return flag_err(cmd, v);
    sc->honor_client_order = flag;
    return NULL;
}

static const char *tls_conf_set_protocol(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);

    (void)dc;
    if (!strcasecmp(v, "auto")) {
        sc->tls_proto = TLS_PROTO_AUTO;
    } else if (!strcasecmp(v, "v1.2+")) {
        sc->tls_proto = TLS_VERSION_1_2;
    } else if (!strcasecmp(v, "v1.3+")) {
        sc->tls_proto = TLS_VERSION_1_3;
    } else {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": value must be 'auto', 'v1.2+' or 'v1.3+': '", v, "'", NULL);
    }
    return NULL;
}

const command_rec tls_conf_cmds[] = {
    /* none yet */
    AP_INIT_TAKE2("TLSCertificate", tls_conf_add_certificate, NULL, RSRC_CONF,
        "Add a certificate to the server by specifying a certificate file and"
        "a private key file (PEM format)."),
    AP_INIT_TAKE1("TLSHonorClientOrder", tls_conf_set_honor_client_order, NULL, RSRC_CONF,
        "Set 'on' to have the server honor client preferences in cipher suites, default off."),
    AP_INIT_TAKE1("TLSListen", tls_conf_add_listener, NULL, RSRC_CONF,
        "Specify an adress+port where the module shall handle incoming TLS connections."),
    AP_INIT_TAKE1("TLSProtocol", tls_conf_set_protocol, NULL, RSRC_CONF,
        "Set the minimum TLS protocol version to support."),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
