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
#include <http_vhost.h>

#include "tls_defs.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_util.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


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

    return APR_SUCCESS;
}

static apr_status_t server_conf_setup(
    apr_pool_t *p, apr_pool_t *ptemp, tls_conf_server_t *sc)
{
    rustls_server_config_builder *rustls_builder;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;
    int i;
    apr_array_header_t *certified_keys = NULL;

    (void)p;
    if (!sc || sc->enabled != TLS_FLAG_TRUE) goto cleanup;

    rustls_builder = rustls_server_config_builder_new();
    if (!rustls_builder) {
        rv = APR_ENOMEM; goto cleanup;
    }

    if (sc->certificates->nelts > 0) {
        certified_keys = apr_array_make(p, 2, sizeof(rustls_cipher_certified_key *));
        for (i = 0; i < sc->certificates->nelts; ++i) {
            tls_certificate_t *spec = APR_ARRAY_IDX(sc->certificates, i, tls_certificate_t*);
            tls_util_cert_pem_t *pems;
            const rustls_cipher_certified_key *ckey = NULL;

            rv = tls_util_load_pem(ptemp, spec, &pems);
            if (APR_SUCCESS != rv) goto cleanup;
            ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, sc->server,
                "tls_core_init: loaded pem data: %s (%ld), %s (%ld)",
                spec->cert_file, (long)pems->cert_pem_len,
                spec->pkey_file, (long)pems->pkey_pem_len
                );

            rr = rustls_cipher_certified_key_build(
                pems->cert_pem_bytes, pems->cert_pem_len,
                pems->pkey_pem_bytes, pems->pkey_pem_len,
                &ckey);
            if (RUSTLS_RESULT_OK != rr) goto cleanup;
            APR_ARRAY_PUSH(certified_keys, const rustls_cipher_certified_key*) = ckey;
        }

        rr = rustls_server_config_builder_set_certified_keys(
            rustls_builder,
            (const rustls_cipher_certified_key**)certified_keys->elts,
            (size_t)certified_keys->nelts);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
    }

    if (sc->tls_proto > TLS_PROTO_AUTO) {
        /* TODO: set the minimum TLS protocol version to use. */
    }
    rustls_server_config_builder_set_ignore_client_order(rustls_builder,
        !sc->honor_client_order);

    sc->rustls_config = rustls_server_config_builder_build(rustls_builder);
    if (!sc->rustls_config) {
        rv = APR_ENOMEM; goto cleanup;
    }

cleanup:
    if (certified_keys != NULL) {
        for (i = 0; i < certified_keys->nelts; ++i) {
            rustls_cipher_certified_key *ckey = APR_ARRAY_IDX(
                certified_keys, i, rustls_cipher_certified_key*);
            rustls_cipher_certified_key_free(ckey);
        }
        apr_array_clear(certified_keys);
    }
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr;
        rv = tls_util_rustls_error(ptemp, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to configure serverr %s: [%d] %s",
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
        /* otherwise, we always fallback to disabled */
        if (sc->enabled == TLS_FLAG_UNSET) {
            sc->enabled = TLS_FLAG_FALSE;
        }
    }

    /* Collect and prepare certificates for enabled servers */

    /* Create server configs for enabled servers */
    for (s = base_server; s; s = s->next) {
        sc = tls_conf_server_get(s);
        rv = server_conf_setup(p, ptemp, sc);
        if (APR_SUCCESS != rv) goto cleanup;
    }

    rv = APR_SUCCESS;
cleanup:
    ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, base_server, "tls_core_init done.");
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
    return APR_SUCCESS;
}

static const rustls_cipher_certified_key *tls_conn_hello_cb(
    void* userdata, const rustls_client_hello *hello)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    char buffer[HUGE_STRING_LEN];
    size_t i, len;
    unsigned short n;
    const rustls_bytes *rs;

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
            rustls_cipher_get_signature_scheme_name(n, buffer, sizeof(buffer), &len);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                "client supports signature scheme: %.*s", (int)len, buffer);
        }
    }
    if (hello->alpn.len > 0) {
        for (i = 0; i < hello->alpn.len; ++i) {
            rs = &hello->alpn.data[i];
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                "client proposes alpn: %.*s", (int)rs->len, rs->data);
        }
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
    if (!sc->rustls_config) goto cleanup;
    if (!cc) {
        rustls_server_config_builder *builder;
        const rustls_server_config *config;

        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server, "tls_core_conn_init on %s",
            c->base_server->server_hostname);
        cc = apr_pcalloc(c->pool, sizeof(*cc));
        cc->server = c->base_server;
        cc->state = TLS_CONN_ST_PRE_HANDSHAKE;
        tls_conf_conn_set(c, cc);
        apr_pool_cleanup_register(c->pool, cc, tls_core_conn_free,
                                  apr_pool_cleanup_null);

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
        config = rustls_server_config_builder_build(builder);
        if (!config) {
            rr = RUSTLS_RESULT_PANIC; goto cleanup;
        }
        rr = rustls_server_session_new(config, &cc->rustls_session);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
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

apr_status_t tls_core_conn_server_init(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    ap_assert(cc);
    ap_assert(cc->rustls_session);

    if (cc->client_hello_seen) {
        if (cc->sni_hostname) {
            if (ap_vhost_iterate_given_conn(c, find_vhost, (void*)cc->sni_hostname)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                    "vhost_init: virtual host found for SNI '%s'", cc->sni_hostname);
            }
            else {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                    "vhost_init: virtual host NOT found for SNI '%s'", cc->sni_hostname);
                rv = APR_NOTFOUND; goto cleanup;
            }
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO()
                "vhost_init: no SNI hostname provided by client");
        }

        /* if found or not, cc->server will be the server we use now to do
         * the real handshake and, if successful, the traffic after that.
         * Free the current session and create the real one for the
         * selected server. */
        rustls_server_session_free(cc->rustls_session);
        cc->rustls_session = NULL;

        sc = tls_conf_server_get(cc->server);
        rr = rustls_server_session_new(sc->rustls_config, &cc->rustls_session);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = NULL;
        rv = tls_util_rustls_error(c->pool, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to init session for server %s: [%d] %s",
                     sc->server->server_hostname, (int)rr, err_descr);
        c->aborted = 1;
        goto cleanup;
    }
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
     * - with vhosts configured and no SNI from the client, deny access.
     * - are servers compatible for connection sharing?
     */
    if (!cc || TLS_CONN_ST_IGNORED == cc->state) goto cleanup;
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
