/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */

#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_network_io.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_vhost.h>
#include <http_main.h>
#include <ap_socache.h>

#include "tls_defs.h"
#include "tls_proto.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_util.h"
#include "tls_cache.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

tls_conf_conn_t *tls_conf_conn_get(conn_rec *c)
{
    return ap_get_module_config(c->conn_config, &tls_module);
}

void tls_conf_conn_set(conn_rec *c, tls_conf_conn_t *cc)
{
    ap_set_module_config(c->conn_config, &tls_module, cc);
}

int tls_conn_check_ssl(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c->master? c->master : c);
    if (cc && (TLS_CONN_ST_IGNORED != cc->state)) {
        return OK;
    }
    return DECLINED;
}

static int we_listen_on(tls_conf_global_t *gc, server_rec *s)
{
    server_addr_rec *sa, *la;

    for (la = gc->tls_addresses; la; la = la->next) {
        for (sa = s->addrs; sa; sa = sa->next) {
            if (la->host_port == sa->host_port
                && la->host_addr->ipaddr_len == sa->host_addr->ipaddr_len
                && !memcmp(la->host_addr->ipaddr_ptr,
                    la->host_addr->ipaddr_ptr, (size_t)la->host_addr->ipaddr_len)) {
                /* exact match */
                return 1;
            }
        }
    }
    return 0;
}

static apr_status_t tls_core_free(void *data)
{
    server_rec *base_server = (server_rec *)data;
    server_rec *s;
    tls_conf_server_t *sc;

    /* free all rustls things we are owning. */
    for (s = base_server; s; s = s->next) {
        sc = tls_conf_server_get(s);
        if (sc) {
            if (sc->rustls_config) {
                rustls_server_config_free(sc->rustls_config);
                sc->rustls_config = NULL;
            }
        }
    }
    tls_cache_free(base_server);

    return APR_SUCCESS;
}

static apr_status_t use_certificates(
    rustls_server_config_builder *builder,
    apr_pool_t *p, server_rec *s,
    apr_array_header_t *cert_specs)
{
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_array_header_t *certified_keys = NULL;
    const rustls_certified_key *ckey;
    apr_status_t rv = APR_SUCCESS;
    int i;

    if (cert_specs && cert_specs->nelts > 0) {
        certified_keys = apr_array_make(p, cert_specs->nelts, sizeof(rustls_certified_key *));

        for (i = 0; i < cert_specs->nelts; ++i) {
            tls_certificate_t *spec = APR_ARRAY_IDX(cert_specs, i, tls_certificate_t*);
            rv = tls_proto_load_certified_key(p, s, spec, &ckey);
            if (APR_SUCCESS != rv) {
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                             "Failed to load certified key[cert=%s(%d), key=%s(%d)]: %s",
                             spec->cert_file, (int)(spec->cert_pem? strlen(spec->cert_pem) : 0),
                             spec->pkey_file, (int)(spec->pkey_pem? strlen(spec->pkey_pem) : 0),
                             s->server_hostname);
                goto cleanup;
            }
            APR_ARRAY_PUSH(certified_keys, const rustls_certified_key*) = ckey;
        }

        rr = rustls_server_config_builder_set_certified_keys(
            builder, (const rustls_certified_key**)certified_keys->elts,
            (size_t)certified_keys->nelts);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
    }

cleanup:
    if (certified_keys != NULL) {
        for (i = 0; i < certified_keys->nelts; ++i) {
            ckey = APR_ARRAY_IDX(certified_keys, i, rustls_certified_key*);
            rustls_certified_key_free(ckey);
        }
        apr_array_clear(certified_keys);
    }
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr;
        rv = tls_util_rustls_error(p, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                     "Failed to configure server %s: [%d] %s",
                     s->server_hostname, (int)rr, err_descr);
        goto cleanup;
    }
    return rv;
}

static void add_file_specs(
    apr_array_header_t *certificates,
    apr_pool_t *p,
    apr_array_header_t *cert_files,
    apr_array_header_t *key_files)
{
    tls_certificate_t *spec;
    int i;

    for (i = 0; i < cert_files->nelts; ++i) {
        spec = apr_pcalloc(p, sizeof(*spec));
        spec->cert_file = APR_ARRAY_IDX(cert_files, i, const char*);
        spec->pkey_file = (i < key_files->nelts)? APR_ARRAY_IDX(key_files, i, const char*) : NULL;
        *(const tls_certificate_t**)apr_array_push(certificates) = spec;
    }
}

static apr_status_t set_ciphers(
    apr_pool_t *pool, tls_conf_server_t *sc,
    rustls_server_config_builder *builder)
{
    apr_array_header_t *ordered_ciphers;
    const apr_array_header_t *ciphers;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;
    apr_uint16_t id;
    int i;

    /* remove all suppressed ciphers from the ones supported by rustls */
    ciphers = tls_util_array_uint16_remove(pool,
        sc->global->proto->rustls_ciphers, sc->tls_supp_ciphers);
    ordered_ciphers = NULL;
    /* if preferred ciphers are actually still present in allowed_ciphers, put
     * them into `ciphers` in this order */
    for (i = 0; i < sc->tls_pref_ciphers->nelts; ++i) {
        id = APR_ARRAY_IDX(sc->tls_pref_ciphers, i, apr_uint16_t);
        if (tls_util_array_uint16_contains(ciphers, id)) {
            if (ordered_ciphers == NULL) {
                ordered_ciphers = apr_array_make(pool, ciphers->nelts, sizeof(apr_uint16_t));
            }
            APR_ARRAY_PUSH(ordered_ciphers, apr_uint16_t) = id;
        }
    }
    /* if we found ciphers with preference among allowed_ciphers,
     * append all other allowed ciphers. */
    if (ordered_ciphers) {
        for (i = 0; i < ciphers->nelts; ++i) {
            id = APR_ARRAY_IDX(ciphers, i, apr_uint16_t);
            if (!tls_util_array_uint16_contains(ordered_ciphers, id)) {
                APR_ARRAY_PUSH(ordered_ciphers, apr_uint16_t) = id;
            }
        }
        ciphers = ordered_ciphers;
    }

    if (ciphers != sc->global->proto->rustls_ciphers) {
        /* this changed the default rustls ciphers, configure it. */
        if (APLOGtrace2(sc->server)) {
            tls_proto_conf_t *conf = sc->global->proto;
            ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, sc->server,
                         "tls ciphers configured[%s]: %s",
                         sc->server->server_hostname,
                         tls_proto_get_cipher_names(conf, ciphers, pool));
        }
        rr = rustls_server_config_builder_set_ciphers(builder,
            (apr_uint16_t*)ciphers->elts, (apr_size_t)ciphers->nelts);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
    }

cleanup:
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr;
        rv = tls_util_rustls_error(pool, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to configure ciphers %s: [%d] %s",
                     sc->server->server_hostname, (int)rr, err_descr);
    }
    return rv;
}

static apr_status_t server_conf_setup(
    apr_pool_t *p, apr_pool_t *ptemp, tls_conf_server_t *sc)
{
    rustls_server_config_builder *builder = NULL;
    apr_array_header_t *cert_adds, *key_adds, *certificates;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    (void)p;
    if (!sc || sc->enabled != TLS_FLAG_TRUE) goto cleanup;

    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, sc->server,
                 "init server: %s", sc->server->server_hostname);
    rv = tls_conf_server_apply_defaults(sc, p);
    if (APR_SUCCESS != rv) goto cleanup;

    builder = rustls_server_config_builder_new();
    if (!builder) {
        rv = APR_ENOMEM; goto cleanup;
    }

    certificates = apr_array_copy(ptemp, sc->certificates);
    cert_adds = apr_array_make(ptemp, 2, sizeof(const char*));
    key_adds = apr_array_make(ptemp, 2, sizeof(const char*));

    ap_ssl_add_cert_files(sc->server, ptemp, cert_adds, key_adds);
    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, sc->server,
                 "init server: ap_ssl_add_cert_files added %d certs", cert_adds->nelts);
    add_file_specs(certificates, ptemp, cert_adds, key_adds);

    if (apr_is_empty_array(certificates)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, sc->server,
                     "init server: ap_ssl_add_fallback");
        ap_ssl_add_fallback_cert_files(sc->server, ptemp, cert_adds, key_adds);
        if (cert_adds->nelts > 0) {
            add_file_specs(certificates, ptemp, cert_adds, key_adds);
            sc->service_unavailable = 1;
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sc->server, APLOGNO()
                         "Init: %s will respond with '503 Service Unavailable' for now. There "
                         "are no SSL certificates configured and no other module contributed any.",
                         sc->server->server_hostname);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, sc->server, APLOGNO()
                         "Init: %s has no certificates configured. Use 'TLSCertificate' to "
                         "configure a certificate and key file.",
                         sc->server->server_hostname);
        }
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, sc->server,
                 "init server: use certificates");
    rv = use_certificates(builder, ptemp, sc->server, certificates);
    if (APR_SUCCESS != rv) goto cleanup;

    if (sc->tls_protocol_min > 0) {
        apr_array_header_t *tls_versions;

        ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, sc->server,
                     "init server: set protocol min version %04x", sc->tls_protocol_min);
        tls_versions = tls_proto_create_versions_plus(
            sc->global->proto, (apr_uint16_t)sc->tls_protocol_min, ptemp);
        if (tls_versions->nelts > 0) {
            rr = rustls_server_config_builder_set_versions(builder,
                (const apr_uint16_t*)tls_versions->elts, (apr_size_t)tls_versions->nelts);
            if (RUSTLS_RESULT_OK != rr) goto cleanup;
            if (sc->tls_protocol_min != APR_ARRAY_IDX(tls_versions, 0, apr_uint16_t)) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, sc->server, APLOGNO()
                             "Init: the minimum protocol version configured for %s (%04x) "
                             "is not supported and version %04x was selected instead.",
                             sc->server->server_hostname, sc->tls_protocol_min,
                             APR_ARRAY_IDX(tls_versions, 0, apr_uint16_t));
            }
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, sc->server, APLOGNO()
                         "Unable to configure the protocol version for %s: "
                          "neither the configured minimum version (%04x), nor any higher one is "
                         "available.", sc->server->server_hostname, sc->tls_protocol_min);
            rv = APR_ENOTIMPL; goto cleanup;
        }
    }

    rv = set_ciphers(ptemp, sc, builder);
    if (APR_SUCCESS != rv) goto cleanup;

    rr = rustls_server_config_builder_set_ignore_client_order(
        builder, sc->honor_client_order == TLS_FLAG_FALSE);
    if (RUSTLS_RESULT_OK != rr) goto cleanup;

    /* whatever we negotiate later on a connection, the base we start with is http/1.1 */
    if (1) {
        rustls_slice_bytes rsb = {
            (const unsigned char*)"http/1.1",
            sizeof("http/1.1")-1,
        };
        rr = rustls_server_config_builder_set_protocols(builder, &rsb, 1);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
    }

    sc->rustls_config = rustls_server_config_builder_build(builder);
    builder = NULL;
    if (!sc->rustls_config) {
        rv = APR_ENOMEM; goto cleanup;
    }

cleanup:
    if (builder != NULL) {
        rustls_server_config_builder_free(builder);
    }
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr;
        rv = tls_util_rustls_error(ptemp, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to configure server %s: [%d] %s",
                     sc->server->server_hostname, (int)rr, err_descr);
        goto cleanup;
    }
    return rv;
}

apr_status_t tls_core_init(apr_pool_t *p, apr_pool_t *ptemp, server_rec *base_server)
{
    tls_conf_server_t *sc = tls_conf_server_get(base_server);
    tls_conf_global_t *gc = sc->global;
    server_rec *s;
    apr_status_t rv = APR_ENOMEM;

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, base_server, "tls_core_init");
    apr_pool_cleanup_register(p, base_server, tls_core_free,
                              apr_pool_cleanup_null);

    rv = tls_proto_post_config(p, ptemp, base_server);
    if (APR_SUCCESS != rv) goto cleanup;

    for (s = base_server; s; s = s->next) {
        sc = tls_conf_server_get(s);
        if (!sc) continue;
        ap_assert(sc->global == gc);

        /* If 'TLSListen' has been configured, use those addresses to
         * decide if we are enabled on this server.
         * If not, auto-enable when 'https' is set as protocol.
         * This is done via the apache 'Listen <port> https' directive. */
        if (gc->tls_addresses) {
            sc->enabled = we_listen_on(gc, s)? TLS_FLAG_TRUE : TLS_FLAG_FALSE;
        }
        else if (sc->enabled == TLS_FLAG_UNSET
            && ap_get_server_protocol(s)
            && strcmp("https", ap_get_server_protocol(s)) == 0) {
            sc->enabled = TLS_FLAG_TRUE;
        }
        /* otherwise, we always fallback to disabled for virtual hosts */
        if (sc->enabled == TLS_FLAG_UNSET) {
            sc->enabled = s->is_virtual? TLS_FLAG_FALSE : TLS_FLAG_TRUE;
        }
    }

    /* Create server configs for enabled servers */
    for (s = base_server; s; s = s->next) {
        sc = tls_conf_server_get(s);
        rv = server_conf_setup(p, ptemp, sc);
        if (APR_SUCCESS != rv) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, "server setup failed: %s",
                s->server_hostname);
            goto cleanup;
        }
    }

    rv = tls_cache_post_config(p, ptemp, base_server);

cleanup:
    if (APR_SUCCESS != rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, base_server, "error during post_config");
    }
    return rv;
}


static apr_status_t tls_core_conn_free(void *data)
{
    tls_conf_conn_t *cc = data;

    /* free all rustls things we are owning. */
    if (cc->rustls_session) {
        rustls_server_session_free(cc->rustls_session);
        cc->rustls_session = NULL;
    }
    if (cc->rustls_config) {
        rustls_server_config_free(cc->rustls_config);
        cc->rustls_config = NULL;
    }
    return APR_SUCCESS;
}

static const rustls_certified_key *tls_conn_hello_cb(
    void* userdata, const rustls_client_hello *hello)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    size_t i, len;
    unsigned short n;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, "client hello callback invoked");
    if (!cc) goto cleanup;
    cc->client_hello_seen = 1;
    if (hello->sni_name.len > 0) {
        cc->sni_hostname = apr_pstrndup(c->pool, hello->sni_name.data, hello->sni_name.len);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "sni detected: %s", cc->sni_hostname);
    }
    else {
        cc->sni_hostname = NULL;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "no sni from client");
    }
    if (hello->signature_schemes.len > 0) {
        for (i = 0; i < hello->signature_schemes.len; ++i) {
            n = hello->signature_schemes.data[i];
            ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, c,
                "client supports signature scheme: %x", (int)n);
        }
    }
    if ((len = rustls_slice_slice_bytes_len(hello->alpn)) > 0) {
        apr_array_header_t *alpn = apr_array_make(c->pool, 5, sizeof(const char*));
        const char *protocol;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "ALPN: client proposes %d protocols", (int)len);
        for (i = 0; i < len; ++i) {
            rustls_slice_bytes rs = rustls_slice_slice_bytes_get(hello->alpn, i);
            protocol = apr_pstrndup(c->pool, (const char*)rs.data, rs.len);
            APR_ARRAY_PUSH(alpn, const char*) = protocol;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                "ALPN: client proposes `%s`", protocol);
        }
        cc->alpn = alpn;
    }
cleanup:
    return NULL;
}

int tls_core_conn_base_init(conn_rec *c)
{
    tls_conf_server_t *sc = tls_conf_server_get(c->base_server);
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    int rv = DECLINED;
    rustls_result rr = RUSTLS_RESULT_OK;

    /* Are we configured to work here? */
    if (sc->enabled != TLS_FLAG_TRUE) goto cleanup;
    if (!cc) {
        rustls_server_config_builder *builder;

        cc = apr_pcalloc(c->pool, sizeof(*cc));
        cc->server = c->base_server;
        cc->state = TLS_CONN_ST_PRE_HANDSHAKE;
        tls_conf_conn_set(c, cc);
        apr_pool_cleanup_register(c->pool, cc, tls_core_conn_free,
                                  apr_pool_cleanup_null);
        ap_log_error(APLOG_MARK, APLOG_TRACE3, 0, c->base_server,
            "tls_core_conn_init, prep for tls: %s",
            c->base_server->server_hostname);

        /* Use a generic rustls_session with its defaults, which we feed
         * the first TLS bytes from the client. Its Hello message will trigger
         * our callback where we can inspect the (possibly) supplied SNI and
         * select another server.
         */
        builder = rustls_server_config_builder_new();
        if (!builder) {
            rr = RUSTLS_RESULT_PANIC; goto cleanup;
        }
        rustls_server_config_builder_set_hello_callback(builder, tls_conn_hello_cb, c);
        cc->rustls_config = rustls_server_config_builder_build(builder);
        if (!cc->rustls_config) {
            rr = RUSTLS_RESULT_PANIC; goto cleanup;
        }
        rr = rustls_server_session_new(cc->rustls_config, &cc->rustls_session);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;

        /* copy over mutable connection properties inherited from server setting */
        cc->service_unavailable = sc->service_unavailable;
    }

    rv = OK;
cleanup:
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr = NULL;
        rv = tls_util_rustls_error(c->pool, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to init pre_session for server %s: [%d] %s",
                     sc->server->server_hostname, (int)rr, err_descr);
        c->aborted = 1;
        goto cleanup;
    }
    return rv;
}

static int find_vhost(void *sni_hostname, conn_rec *c, server_rec *s)
{
    if (tls_util_name_matches_server(sni_hostname, s)) {
        tls_conf_conn_t *cc = tls_conf_conn_get(c);
        cc->server = s;
        return 1;
    }
    return 0;
}

static apr_status_t process_alpn(
    conn_rec *c, server_rec *s, rustls_server_config_builder *builder)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    const char *proposed;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    if (cc->protocol_selected) goto cleanup;

    /* the server always has a protocol it uses. We need only to do something
     * if ALPN successfully proposes something different. */
    cc->protocol_selected = ap_get_protocol(c);
    if (cc->alpn && cc->alpn->nelts > 0
        && (proposed = ap_select_protocol(c, NULL, s, cc->alpn))
        && strcmp(proposed, cc->protocol_selected)) {
        rustls_slice_bytes rsb;

        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, c,
            "ALPN: switching protocol from `%s` to `%s`", cc->protocol_selected, proposed);
        rv = ap_switch_protocol(c, NULL, cc->server, proposed);
        if (APR_SUCCESS != rv) goto cleanup;

        rsb.data = (const unsigned char*)proposed;
        rsb.len = strlen(proposed);
        rr = rustls_server_config_builder_set_protocols(builder, &rsb, 1);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;

        cc->protocol_selected = proposed;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, c,
            "ALPN: switched connection to protocol `%s`", cc->protocol_selected);

        /* protocol was switched, this could be a challenge protocol
         * such as "acme-tls/1". Give handlers the opportunity to
         * override the certificate for this connection. */
        if (strcmp("h2", proposed) && strcmp("http/1.1", proposed)) {
            const char *cert_pem = NULL, *key_pem = NULL;
            if (ap_ssl_answer_challenge(c, cc->sni_hostname, &cert_pem, &key_pem)) {
                /* With ACME we can have challenge connections to a unknown domains
                 * that need to be answered with a special certificate and will
                 * otherwise not answer any requests. See RFC 8555 */
                apr_array_header_t *cert_specs;
                tls_certificate_t *spec;

                spec = apr_pcalloc(c->pool, sizeof(*spec));
                spec->cert_pem = cert_pem;
                spec->pkey_pem = key_pem;
                cert_specs = apr_array_make(c->pool, 1, sizeof(tls_certificate_t*));
                *(tls_certificate_t**)apr_array_push(cert_specs) = spec;

                rv = use_certificates(builder, c->pool, s, cert_specs);
                if (APR_SUCCESS != rv) goto cleanup;

                cc->service_unavailable = 1;
                /* TODO: SSL_set_verify(ssl, SSL_VERIFY_NONE, ssl_callback_SSLVerify); */
            }
        }
    }
cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = NULL;
        rv = tls_util_rustls_error(c->pool, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                     "Failed to init session for server %s: [%d] %s",
                     s->server_hostname, (int)rr, err_descr);
        c->aborted = 1;
        goto cleanup;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, c, "process_alpn done");
    return rv;
}

apr_status_t tls_core_conn_server_init(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc, *initial_sc;
    const rustls_server_config *base_config = NULL;
    rustls_server_config_builder *builder = NULL;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;
    int sni_match = 0;

    ap_assert(cc);
    initial_sc = sc = tls_conf_server_get(cc->server);

    if (cc->client_hello_seen) {
        if (cc->sni_hostname) {
            if (ap_vhost_iterate_given_conn(c, find_vhost, (void*)cc->sni_hostname)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                    "vhost_init: virtual host found for SNI '%s'", cc->sni_hostname);
                sni_match = 1;
            }
            else if (tls_util_name_matches_server(cc->sni_hostname, ap_server_conf)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                    "vhost_init: virtual host NOT found, but base server[%s] matches SNI '%s'",
                    ap_server_conf->server_hostname, cc->sni_hostname);
                cc->server = ap_server_conf;
                sni_match = 1;
            }
            else if (sc->strict_sni == TLS_FLAG_FALSE) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                    "vhost_init: no virtual host found, relaxed SNI checking enabled, SNI '%s'",
                    cc->sni_hostname);
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                    "vhost_init: no virtual host, nor base server[%s] matches SNI '%s'",
                    c->base_server->server_hostname, cc->sni_hostname);
                cc->server = sc->global->ap_server;
                rv = APR_NOTFOUND; goto cleanup;
            }
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO()
                "vhost_init: no SNI hostname provided by client");
        }

        /* reinit, we might have a new server selected */
        sc = tls_conf_server_get(cc->server);
        /* on relaxed SNI matches, we do not enforce the 503 of fallback
         * certificates. */
        cc->service_unavailable = sni_match? sc->service_unavailable : 0;

        base_config = sc->rustls_config? sc->rustls_config : initial_sc->rustls_config;
        if (!base_config) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO()
                "vhost_init: no base rustls config found, denying to serve");
            rv = APR_NOTFOUND; goto cleanup;
        }
        builder = rustls_server_config_builder_from_config(base_config);
        if (NULL == builder) {
            rv = APR_ENOMEM; goto cleanup;
        }

        rv = process_alpn(c, cc->server, builder);
        if (APR_SUCCESS != rv) goto cleanup;

        rv = tls_cache_init_conn(builder, c);
        if (APR_SUCCESS != rv) goto cleanup;

        /* if found or not, cc->server will be the server we use now to do
         * the real handshake and, if successful, the traffic after that.
         * Free the current session and create the real one for the
         * selected server. */
        rustls_server_config_free(cc->rustls_config);
        cc->rustls_config = NULL;
        rustls_server_session_free(cc->rustls_session);
        cc->rustls_session = NULL;
        cc->rustls_config = rustls_server_config_builder_build(builder);
        builder = NULL;
        rr = rustls_server_session_new(cc->rustls_config, &cc->rustls_session);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
    }

cleanup:
    if (builder != NULL) {
        rustls_server_config_builder_free(builder);
    }
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = NULL;
        rv = tls_util_rustls_error(c->pool, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to init session for server %s: [%d] %s",
                     sc->server->server_hostname, (int)rr, err_descr);
        c->aborted = 1;
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, sc->server,
                 "tls_core_conn_server_init done: %s",
                 sc->server->server_hostname);
    return rv;
}

apr_status_t tls_core_conn_post_handshake(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc = tls_conf_server_get(cc->server);
    apr_status_t rv = APR_SUCCESS;
    apr_uint16_t id;

    if (rustls_server_session_is_handshaking(cc->rustls_session)) {
        rv = APR_EGENERAL;
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, cc->server, APLOGNO()
                     "post handshake, but rustls claims to still be handshaking %s",
                     cc->server->server_hostname);
        goto cleanup;
    }

    id = rustls_server_session_get_protocol_version(cc->rustls_session);
    cc->tls_version = tls_proto_get_version_name(sc->global->proto, id, c->pool);
    id = rustls_server_session_get_negotiated_cipher(cc->rustls_session);
    cc->tls_ciphersuite = tls_proto_get_cipher_name(sc->global->proto, id, c->pool);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "post_handshake %s: %s [%s]",
        cc->server->server_hostname, cc->tls_version, cc->tls_ciphersuite);

cleanup:
    return rv;
}

/**
 * Return != 0, if a connection opened on <base> can also serve
 * requests for server <other>. From our side of TLS limited point of view.
 */
static int tls_servers_compatible(server_rec *base, server_rec *other)
{
    tls_conf_server_t *bc;
    tls_conf_server_t *oc;

    /*   - differences in certificates are the responsibility of the client.
     *     if it thinks the SNI server works for r->server, we are fine with that.
     *   - if there are differences in requirements to client certificates, we
     *     need to deny the request.
     */
    if (!base || !other) return 0;
    if (base == other) return 1;
    bc = tls_conf_server_get(base);
    oc = tls_conf_server_get(other);
    if (!bc || !oc) return 0;

    if (bc->honor_client_order != oc->honor_client_order) return 0;
    /* TODO: check config details for ciphers/protocols/client auth/etc. */
    return 1;
}

int tls_core_request_check(request_rec *r)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(r->connection);
    int rv = DECLINED; /* do not object to the request */

    /* If we are not enabled on this connection, leave. We are not renegotiating.
     * Otherwise:
     * - service is unavailable when we have only a fallback certificate or
     *   when a challenge protocol is active (ACME tls-alpn-01 for example).
     * - with vhosts configured and no SNI from the client, deny access.
     * - are servers compatible for connection sharing?
     */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                 "tls_core_request_check[%s, %d]: %s", r->hostname,
                 cc? cc->service_unavailable : 2, r->the_request);
    if (!cc || (TLS_CONN_ST_IGNORED == cc->state)) goto cleanup;
    if (cc->service_unavailable) {
        rv = HTTP_SERVICE_UNAVAILABLE; goto cleanup;
    }
    if (!cc->sni_hostname && r->connection->vhost_lookup_data) {
        rv = HTTP_FORBIDDEN; goto cleanup;
    }
    if (!tls_servers_compatible(cc->server, r->server)) {
        rv = HTTP_MISDIRECTED_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO()
                     "Connection host %s, selected via SNI, and request host %s"
                     " have incompatible TLS configurations.",
                     cc->server->server_hostname, r->hostname);
        goto cleanup;
    }
cleanup:
    return rv;
}
