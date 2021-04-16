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
#include <ap_socache.h>

#include "tls_defs.h"
#include "tls_proto.h"
#include "tls_conf.h"
#include "tls_util.h"
#include "tls_var.h"
#include "tls_cache.h"


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
    gconf->ap_server = ap_server_conf;
    gconf->proto = tls_proto_init(pool, s);

    gconf->var_lookups = apr_hash_make(pool);
    tls_var_init_lookup_hash(pool, gconf->var_lookups);
    gconf->session_cache_spec = "default";

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
    conf->cert_specs = apr_array_make(pool, 3, sizeof(tls_cert_spec_t*));
    conf->honor_client_order = TLS_FLAG_UNSET;
    conf->strict_sni = TLS_FLAG_UNSET;
    conf->tls_protocol_min = TLS_FLAG_UNSET;
    conf->tls_pref_ciphers = apr_array_make(pool, 3, sizeof(apr_uint16_t));;
    conf->tls_supp_ciphers = apr_array_make(pool, 3, sizeof(apr_uint16_t));;
    return conf;
}

#define MERGE_INT(base, add, field) \
    (add->field == TLS_FLAG_UNSET)? base->field : add->field;

void *tls_conf_merge_svr(apr_pool_t *pool, void *basev, void *addv)
{
    tls_conf_server_t *base = basev;
    tls_conf_server_t *add = addv;
    tls_conf_server_t *nconf;

    nconf = apr_pcalloc(pool, sizeof(*nconf));
    nconf->name = apr_pstrcat(pool, "[", CONF_S_NAME(add->server),
        ", ", CONF_S_NAME(base->server), "]", NULL);
    nconf->server = add->server;
    nconf->global = add->global? add->global : base->global;

    nconf->enabled = MERGE_INT(base, add, enabled);
    nconf->cert_specs = apr_array_append(pool, base->cert_specs, add->cert_specs);
    nconf->tls_protocol_min = MERGE_INT(base, add, tls_protocol_min);
    nconf->tls_pref_ciphers = add->tls_pref_ciphers->nelts?
        add->tls_pref_ciphers : base->tls_pref_ciphers;
    nconf->tls_supp_ciphers = add->tls_supp_ciphers->nelts?
        add->tls_supp_ciphers : base->tls_supp_ciphers;
    nconf->honor_client_order = MERGE_INT(base, add, honor_client_order);
    return nconf;
}

tls_conf_dir_t *tls_conf_dir_get(request_rec *r)
{
    tls_conf_dir_t *dc = ap_get_module_config(r->per_dir_config, &tls_module);
    ap_assert(dc);
    return dc;
}

void *tls_conf_create_dir(apr_pool_t *pool, char *dir)
{
    tls_conf_dir_t *conf;

    (void)dir;
    conf = apr_pcalloc(pool, sizeof(*conf));
    conf->std_env_vars = TLS_FLAG_UNSET;
    return conf;
}

void *tls_conf_merge_dir(apr_pool_t *pool, void *basev, void *addv)
{
    tls_conf_dir_t *base = basev;
    tls_conf_dir_t *add = addv;
    tls_conf_dir_t *nconf;

    nconf = apr_pcalloc(pool, sizeof(*nconf));
    nconf->std_env_vars = MERGE_INT(base, add, std_env_vars);
    return nconf;
}

static void tls_conf_dir_set_options_defaults(apr_pool_t *pool, tls_conf_dir_t *dc)
{
    (void)pool;
    dc->std_env_vars = TLS_FLAG_FALSE;
}

apr_status_t tls_conf_server_apply_defaults(tls_conf_server_t *sc, apr_pool_t *p)
{
    (void)p;
    if (sc->enabled == TLS_FLAG_UNSET) sc->enabled = TLS_FLAG_FALSE;
    if (sc->tls_protocol_min == TLS_FLAG_UNSET) sc->tls_protocol_min = 0;
    if (sc->honor_client_order == TLS_FLAG_UNSET) sc->honor_client_order = TLS_FLAG_TRUE;
    if (sc->strict_sni == TLS_FLAG_UNSET) sc->strict_sni = TLS_FLAG_TRUE;

    return APR_SUCCESS;
}

static const char *cmd_check_file(cmd_parms *cmd, const char *fpath)
{
    char *real_path;

    /* just a dump of the configuration, dont resolve/check */
    if (ap_state_query(AP_SQ_RUN_MODE) == AP_SQ_RM_CONFIG_DUMP) {
        return NULL;
    }
    real_path = ap_server_root_relative(cmd->pool, fpath);
    if (!real_path) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": Invalid file path ", fpath, NULL);
    }
    if (!tls_util_is_file(cmd->pool, real_path)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           ": file '", real_path,
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
    const char *err = NULL, *fpath;
    tls_cert_spec_t *cert;

    (void)dc;
    if (NULL != (err = cmd_check_file(cmd, cert_file))) goto cleanup;
    /* key file may be NULL, in which case cert_file must contain the key PEM */
    if (pkey_file && NULL != (err = cmd_check_file(cmd, pkey_file))) goto cleanup;

    cert = apr_pcalloc(cmd->pool, sizeof(*cert));
    fpath = ap_server_root_relative(cmd->pool, cert_file);
    if (!tls_util_is_file(cmd->pool, fpath)) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": unable to find certificate file: '", fpath, "'", NULL);
    }
    cert->cert_file = cert_file;
    if (pkey_file) {
        fpath = ap_server_root_relative(cmd->pool, pkey_file);
        if (!tls_util_is_file(cmd->pool, fpath)) {
            return apr_pstrcat(cmd->pool, cmd->cmd->name,
                ": unable to find certificate key file: '", fpath, "'", NULL);
        }
    }
    cert->pkey_file = pkey_file;
    *(const tls_cert_spec_t **)apr_array_push(sc->cert_specs) = cert;

cleanup:
    return err;
}

static const char *tls_conf_set_preferred_ciphers(
    cmd_parms *cmd, void *dc, int argc, char *const argv[])
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;
    apr_uint16_t cipher;

    (void)dc;
    if (cmd->path) {
        err = "ciphers cannot be configured inside a directory context";
        goto cleanup;
    }
    if (!argc) {
        err = "specify the TLS ciphers to prefer or 'default' for the rustls default ordering.";
        goto cleanup;
    }
    apr_array_clear(sc->tls_pref_ciphers);
    if (argc > 1 || apr_strnatcasecmp("default", argv[0])) {
        int i;

        for (i = 0; i < argc; ++i) {
            char *name, *last = NULL;
            const char *value = argv[i];

            name = apr_strtok(apr_pstrdup(cmd->pool, value), ":", &last);
            while (name) {
                if (tls_proto_get_cipher_by_name(sc->global->proto,
                    name, &cipher) != APR_SUCCESS) {
                    err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                            ": cipher not recognized '", name, "'", NULL);
                    goto cleanup;
                }
                APR_ARRAY_PUSH(sc->tls_pref_ciphers, apr_uint16_t) = cipher;
                name = apr_strtok(NULL, ":", &last);
            }
        }
    }
cleanup:
    return err;
}

static const char *tls_conf_set_suppressed_ciphers(
    cmd_parms *cmd, void *dc, int argc, char *const argv[])
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;
    apr_uint16_t cipher;

    (void)dc;
    if (cmd->path) {
        err = "ciphers cannot be configured inside a directory context";
        goto cleanup;
    }
    if (!argc) {
        err = "specify the TLS ciphers to never use or 'none'.";
        goto cleanup;
    }
    apr_array_clear(sc->tls_supp_ciphers);
    if (argc > 1 || apr_strnatcasecmp("default", argv[0])) {
        int i;

        for (i = 0; i < argc; ++i) {
            char *name, *last = NULL;
            const char *value = argv[i];

            name = apr_strtok(apr_pstrdup(cmd->pool, value), ":", &last);
            while (name) {
                if (tls_proto_get_cipher_by_name(sc->global->proto,
                    name, &cipher) != APR_SUCCESS) {
                    err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                            ": cipher not recognized '", name, "'", NULL);
                    goto cleanup;
                }
                *(apr_uint16_t*)apr_array_push(sc->tls_supp_ciphers) = cipher;
                name = apr_strtok(NULL, ":", &last);
            }
        }
    }
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

static const char *tls_conf_set_strict_sni(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    int flag = flag_value(v);

    (void)dc;
    if (TLS_FLAG_UNSET == flag) return flag_err(cmd, v);
    sc->strict_sni = flag;
    return NULL;
}

static const char *tls_conf_set_protocol(
    cmd_parms *cmd, void *dc, const char *v)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    (void)dc;
    if (cmd->path) {
        err = "TLS protocol versions cannot be set inside a directory context";
        goto cleanup;
    }
    if (!apr_strnatcasecmp("default", v)) {
        sc->tls_protocol_min = 0;
    }
    else if (*v && v[strlen(v)-1] == '+') {
        char *name = apr_pstrdup(cmd->pool, v);
        name[strlen(name)-1] = '\0';
        sc->tls_protocol_min = tls_proto_get_version_by_name(sc->global->proto, name);
        if (!sc->tls_protocol_min) {
            err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                ": unrecognized protocol version specifier (try TLSv1.2+ or TLSv1.3+): '", v, "'", NULL);
            goto cleanup;
        }
    }
    else {
        err = apr_pstrcat(cmd->pool, cmd->cmd->name,
            ": value must be 'default', 'TLSv1.2+' or 'TLSv1.3+': '", v, "'", NULL);
        goto cleanup;
    }
cleanup:
    return err;
}

static const char *tls_conf_set_options(
    cmd_parms *cmd, void *dcv, int argc, char *const argv[])
{
    tls_conf_dir_t *dc = dcv;
    const char *err = NULL, *option;
    int i, val;

    /* Are we only having deltas (+/-) or do we reset the options? */
    for (i = 0; i < argc; ++i) {
        if (argv[i][0] != '+' && argv[i][0] != '-') {
            tls_conf_dir_set_options_defaults(cmd->pool, dc);
            break;
        }
    }

    for (i = 0; i < argc; ++i) {
        option = argv[i];
        val = TLS_FLAG_TRUE;
        if (*option == '+' || *option == '-') {
            val = (*option == '+')? TLS_FLAG_TRUE : TLS_FLAG_FALSE;
            ++option;
        }

        if (!apr_strnatcasecmp("StdEnvVars", option)) {
            dc->std_env_vars = val;
        }
        else {
            err = apr_pstrcat(cmd->pool, cmd->cmd->name,
                               ": unknown option '", option, "'", NULL);
            goto cleanup;
        }
    }
cleanup:
    return err;
}

static const char *tls_conf_set_session_cache(
    cmd_parms *cmd, void *dc, const char *value)
{
    tls_conf_server_t *sc = tls_conf_server_get(cmd->server);
    const char *err = NULL;

    (void)dc;
    if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) goto cleanup;

    err = tls_cache_set_specification(value, sc->global, cmd->pool, cmd->temp_pool);
cleanup:
    return err;
}

const command_rec tls_conf_cmds[] = {
    AP_INIT_TAKE12("TLSCertificate", tls_conf_add_certificate, NULL, RSRC_CONF,
        "Add a certificate to the server by specifying a file containing the "
        "certificate PEM, followed by its chain PEMs. The PEM of the key must "
        "either also be there or can be given as a separate file."),
    AP_INIT_TAKE_ARGV("TLSCiphersPrefer", tls_conf_set_preferred_ciphers, NULL, RSRC_CONF,
        "Set the TLS ciphers to prefer when negotiating with a client."),
    AP_INIT_TAKE_ARGV("TLSCiphersSuppress", tls_conf_set_suppressed_ciphers, NULL, RSRC_CONF,
        "Set the TLS ciphers to never use when negotiating with a client."),
    AP_INIT_TAKE1("TLSHonorClientOrder", tls_conf_set_honor_client_order, NULL, RSRC_CONF,
        "Set 'on' to have the server honor client preferences in cipher suites, default off."),
    AP_INIT_TAKE1("TLSListen", tls_conf_add_listener, NULL, RSRC_CONF,
        "Specify an adress+port where the module shall handle incoming TLS connections."),
    AP_INIT_TAKE_ARGV("TLSOptions", tls_conf_set_options, NULL, OR_OPTIONS,
        "En-/disables optional features in the module."),
    AP_INIT_TAKE1("TLSProtocols", tls_conf_set_protocol, NULL, RSRC_CONF,
        "Set the minimum TLS protocol version to use."),
    AP_INIT_TAKE1("TLSStrictSNI", tls_conf_set_strict_sni, NULL, RSRC_CONF,
        "Set strictness of client server name (SNI) check against hosts, default on."),
    AP_INIT_TAKE1("TLSSessionCache", tls_conf_set_session_cache, NULL, RSRC_CONF,
        "Set which cache to use for TLS sessions."),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};
