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
#include <http_core.h>
#include <http_main.h>
#include <http_log.h>
#include <ap_socache.h>

#include <crustls.h>

#include "tls_conf.h"
#include "tls_core.h"
#include "tls_util.h"
#include "tls_var.h"
#include "tls_version.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

typedef struct {
    apr_pool_t *p;
    server_rec *s;
    conn_rec *c;
    request_rec *r;
    tls_conf_conn_t *cc;
    const char *name;
} tls_var_lookup_ctx_t;

typedef const char *var_lookup(const tls_var_lookup_ctx_t *ctx);

static const char *var_get_ssl_protocol(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->tls_protocol_name;
}

static const char *var_get_ssl_cipher(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->tls_cipher_name;
}

static const char *var_get_sni_hostname(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->sni_hostname;
}

static const char *var_get_version_interface(const tls_var_lookup_ctx_t *ctx)
{
    tls_conf_server_t *sc = tls_conf_server_get(ctx->s);
    return sc->global->module_version;
}

static const char *var_get_version_library(const tls_var_lookup_ctx_t *ctx)
{
    tls_conf_server_t *sc = tls_conf_server_get(ctx->s);
    return sc->global->crustls_version;
}

static const char *var_get_false(const tls_var_lookup_ctx_t *ctx)
{
    (void)ctx;
    return "false";
}

static const char *var_get_null(const tls_var_lookup_ctx_t *ctx)
{
    (void)ctx;
    return "NULL";
}

static const char *var_get_client_s_dn_cn(const tls_var_lookup_ctx_t *ctx)
{
    /* TODO: we need rust code to disect a certificate DER data */
    return ctx->cc->client_cert? "Not Implemented" : NULL;
}

static const char *var_get_client_verify(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->client_cert? "SUCCESS" : "NONE";
}

static const char *var_get_session_resumed(const tls_var_lookup_ctx_t *ctx)
{
    return ctx->cc->session_id_cache_hit? "Resumed" : "Initial";
}

typedef struct {
    const char *name;
    var_lookup* fn;
} var_def_t;

static const var_def_t VAR_DEFS[] = {
    { "SSL_PROTOCOL", var_get_ssl_protocol },
    { "SSL_CIPHER", var_get_ssl_cipher },
    { "SSL_TLS_SNI", var_get_sni_hostname },
    { "SSL_CLIENT_S_DN_CN", var_get_client_s_dn_cn },
    { "SSL_VERSION_INTERFACE", var_get_version_interface },
    { "SSL_VERSION_LIBRARY", var_get_version_library },
    { "SSL_SECURE_RENEG", var_get_false },
    { "SSL_COMPRESS_METHOD", var_get_null },
    { "SSL_CIPHER_EXPORT", var_get_false },
    { "SSL_CLIENT_VERIFY", var_get_client_verify },
    { "SSL_SESSION_RESUMED", var_get_session_resumed },
};

static const char *const TlsAlwaysVars[] = {
    "SSL_TLS_SNI",
    "SSL_PROTOCOL",
    "SSL_CIPHER",
    "SSL_CLIENT_S_DN_CN",
};

/* what mod_ssl defines, plus server cert and client cert DN and SAN entries */
static const char *const StdEnvVars[] = {
    "SSL_VERSION_INTERFACE", /* implemented: module version string */
    "SSL_VERSION_LIBRARY",   /* implemented: crustls/rustls version string */
    "SSL_SECURE_RENEG",      /* implemented: always "false" */
    "SSL_COMPRESS_METHOD",   /* implemented: always "NULL" */
    "SSL_CIPHER_EXPORT",     /* implemented: always "false" */
    "SSL_CIPHER_USEKEYSIZE",
    "SSL_CIPHER_ALGKEYSIZE",
    "SSL_CLIENT_VERIFY",     /* implemented: always "SUCCESS" or "NONE" */
    "SSL_CLIENT_M_VERSION",
    "SSL_CLIENT_M_SERIAL",
    "SSL_CLIENT_V_START",
    "SSL_CLIENT_V_END",
    "SSL_CLIENT_V_REMAIN",
    "SSL_CLIENT_S_DN",
    "SSL_CLIENT_I_DN",
    "SSL_CLIENT_A_KEY",
    "SSL_CLIENT_A_SIG",
    "SSL_CLIENT_CERT_RFC4523_CEA",
    "SSL_SERVER_M_VERSION",
    "SSL_SERVER_M_SERIAL",
    "SSL_SERVER_V_START",
    "SSL_SERVER_V_END",
    "SSL_SERVER_S_DN",
    "SSL_SERVER_I_DN",
    "SSL_SERVER_A_KEY",
    "SSL_SERVER_A_SIG",
    "SSL_SESSION_ID",        /* not implemented: highly sensitive data we do not expose */
    "SSL_SESSION_RESUMED",   /* implemented: if our cache was hit successfully */
};

void tls_var_init_lookup_hash(apr_pool_t *pool, apr_hash_t *map)
{
    const var_def_t *def;
    apr_size_t i;

    (void)pool;
    for (i = 0; i < TLS_DIM(VAR_DEFS); ++i) {
        def = &VAR_DEFS[i];
        apr_hash_set(map, def->name, APR_HASH_KEY_STRING, def);
    }
}

static const char *invoke(var_def_t* def, const tls_var_lookup_ctx_t *ctx)
{
    if (ctx->cc && (ctx->cc->state != TLS_CONN_ST_IGNORED)) {
        const char *val = ctx->cc->subprocess_env?
            apr_table_get(ctx->cc->subprocess_env, def->name) : NULL;
        return (val && *val)? val : def->fn(ctx);
    }
    return NULL;
}

static void set_var(
    const tls_var_lookup_ctx_t *ctx, apr_hash_t *lookups, apr_table_t *table)
{
    var_def_t* def = apr_hash_get(lookups, ctx->name, APR_HASH_KEY_STRING);
    if (def) {
        const char *val = invoke(def, ctx);
        if (val && *val) {
            apr_table_setn(table, ctx->name, val);
        }
    }
}

const char *tls_var_lookup(
    apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *name)
{
    const char *val = NULL;
    tls_conf_server_t *sc;
    var_def_t* def;

    ap_assert(p);
    ap_assert(name);
    s = s? s : (r? r->server : (c? c->base_server : NULL));
    c = c? c : (r? r->connection : NULL);

    sc = tls_conf_server_get(s? s : ap_server_conf);
    def = apr_hash_get(sc->global->var_lookups, name, APR_HASH_KEY_STRING);
    if (def) {
        tls_var_lookup_ctx_t ctx;
        ctx.p = p;
        ctx.s = s;
        ctx.c = c;
        ctx.r = r;
        ctx.cc = c? tls_conf_conn_get(c->master? c->master : c) : NULL;
                ctx.cc = c? tls_conf_conn_get(c->master? c->master : c) : NULL;
        ctx.name = name;
        val = invoke(def, &ctx);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c, "tls lookup of var '%s' -> '%s'", name, val);
    }
    return val;
}

apr_status_t tls_var_handshake_done(conn_rec *c)
{
    tls_conf_conn_t *cc;
    apr_status_t rv = APR_SUCCESS;
    apr_table_t *env = NULL;
    tls_conf_server_t *sc;
    tls_var_lookup_ctx_t ctx;
    apr_size_t i;

    cc = tls_conf_conn_get(c);
    if (!cc || (TLS_CONN_ST_IGNORED == cc->state)) goto cleanup;

    sc = tls_conf_server_get(cc->server);
    env = apr_table_make(c->pool, 5);
    ctx.p = c->pool;
    ctx.s = cc->server;
    ctx.c = c;
    ctx.r = NULL;
    ctx.cc = cc;

    apr_table_setn(env, "HTTPS", "on");
    for (i = 0; i < TLS_DIM(TlsAlwaysVars); ++i) {
        ctx.name = TlsAlwaysVars[i];
        set_var(&ctx, sc->global->var_lookups, env);
    }

cleanup:
    cc->subprocess_env = (APR_SUCCESS == rv)? env : NULL;
    return rv;
}

int tls_var_request_fixup(request_rec *r)
{
    conn_rec *c = r->connection;
    tls_conf_server_t *sc;
    tls_conf_dir_t *dc = tls_conf_dir_get(r);
    tls_conf_conn_t *cc;
    tls_var_lookup_ctx_t ctx;
    apr_size_t i;

    cc = tls_conf_conn_get(c->master? c->master : c);
    if (!cc || (TLS_CONN_ST_IGNORED == cc->state)) goto cleanup;

    if (cc->subprocess_env) {
        apr_table_overlap(r->subprocess_env, cc->subprocess_env, APR_OVERLAP_TABLES_SET);
    }

    if (dc->std_env_vars == TLS_FLAG_TRUE) {
        sc = tls_conf_server_get(cc->server);
        ctx.p = r->pool;
        ctx.s = cc->server;
        ctx.c = c;
        ctx.r = r;
        ctx.cc = cc;

        for (i = 0; i < TLS_DIM(StdEnvVars); ++i) {
            ctx.name = StdEnvVars[i];
            set_var(&ctx, sc->global->var_lookups, r->subprocess_env);
        }
    }
cleanup:
    return DECLINED;
}
