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
            if (sc->pre_config) {
                rustls_server_config_free(sc->pre_config);
                sc->pre_config = NULL;
            }
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
    rustls_server_config_builder *rustls_builder, *pre_builder;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    (void)p;
    if (!sc || sc->enabled != TLS_FLAG_TRUE) goto cleanup;

    /* We set up 2 rustls_config:
     * - 'pre_config': with all rustls default values and a ClientHello resolver
     *   that just looks at supplied SNI server_name, ALPN and sigschemes to determine
     *   which server_rec will actually be used, what ALPN protocol is to be negotiated
     *   and which certificate to select.
     * - 'rustls_config': which is the real configuration to be used against *this*
     *   very server_rec.
     *
     *   In preconfig we use rustls default values to allow for all protocol versions and supported
     *   ciphers to be initially enabled. The SNI might then switch us to a server config
     *   that has restricted ciphers or protocols or client auth, etc.
     */
    pre_builder = rustls_server_config_builder_new();
    if (!pre_builder) {
        rv = APR_ENOMEM; goto cleanup;
    }
    /* TODO: install our special client hello callback */
    sc->pre_config = rustls_server_config_builder_build(pre_builder);
    if (!sc->pre_config) {
        rv = APR_ENOMEM; goto cleanup;
    }

    rustls_builder = rustls_server_config_builder_new();
    if (!rustls_builder) {
        rv = APR_ENOMEM; goto cleanup;
    }

    /* TODO: this needs some more work */
    if (sc->certificates->nelts > 0) {
        tls_certificate_t *spec = APR_ARRAY_IDX(sc->certificates, 0, tls_certificate_t*);
        tls_util_cert_pem_t *pems;

        rv = tls_util_load_pem(ptemp, spec, &pems);
        if (APR_SUCCESS != rv) goto cleanup;
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, sc->server,
            "tls_core_init: loaded pem data: %s (%ld), %s (%ld)",
            spec->cert_file, (long)pems->cert_pem_len,
            spec->pkey_file, (long)pems->pkey_pem_len
            );

        rr = rustls_server_config_builder_set_single_cert_pem(rustls_builder,
            pems->cert_pem_bytes, pems->cert_pem_len,
            pems->pkey_pem_bytes, pems->pkey_pem_len);
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

int tls_core_conn_base_init(conn_rec *c)
{
    tls_conf_server_t *sc = tls_conf_server_get(c->base_server);
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    int rv = DECLINED;
    rustls_result rr = RUSTLS_RESULT_OK;

    /* Are we configured to work here? */
    if (!sc->pre_config) goto cleanup;
    if (!cc) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server, "tls_core_conn_init on %s",
            c->base_server->server_hostname);
        cc = apr_pcalloc(c->pool, sizeof(*cc));
        apr_pool_cleanup_register(c->pool, cc, tls_core_conn_free,
                                  apr_pool_cleanup_null);

        /* start with the base server's pre_config, SNI may update this during handshake. */
        cc->server = c->base_server;
        cc->state = TLS_CONN_ST_PRE_HANDSHAKE;
        rr = rustls_server_session_new(sc->pre_config, &cc->rustls_session);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;

        tls_conf_conn_set(c, cc);
    }

    rv = OK;
cleanup:
    if (RUSTLS_RESULT_OK != rr) {
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
    const char *err_descr = "";
    apr_status_t rv = APR_SUCCESS;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, "vhost_init: start");
    ap_assert(cc);
    ap_assert(cc->rustls_session);

    if (TLS_CONN_ST_PRE_HANDSHAKE == cc->state) {
        if (NULL == cc->sni_hostname) {
            char sni_buffer[HUGE_STRING_LEN];
            size_t blen;

            rr = rustls_server_session_get_sni_hostname(cc->rustls_session,
                (unsigned char*)sni_buffer, sizeof(sni_buffer), &blen);
            if (RUSTLS_RESULT_OK != rr) goto cleanup;
            if (0 == blen) {
                /* no SNI supported by client, we stay on c->base_server. */
                goto cleanup;
            }
            cc->sni_hostname = apr_pstrndup(c->pool, sni_buffer, blen);
        }

        if (ap_vhost_iterate_given_conn(c, find_vhost, (void*)cc->sni_hostname)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                "vhost_init: virtual host found for SNI '%s'", cc->sni_hostname);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                "vhost_init: virtual host NOT found for SNI '%s'", cc->sni_hostname);
            /* fall through which returns APR_NOTFOUND */
        }

        /* if found or not, cc->server will be the server we use now to do
         * the real handshake and, if successful, the traffic after that.
         * Free the things from (c->base_server)->pre_config and create
         * the real session for the selectd server. */
        rustls_server_session_free(cc->rustls_session);
        cc->rustls_session = NULL;

        sc = tls_conf_server_get(cc->server);
        rr = rustls_server_session_new(sc->rustls_config, &cc->rustls_session);
        if (RUSTLS_RESULT_OK != rr) goto cleanup;
        cc->state = TLS_CONN_ST_HANDSHAKE;
    }

    rv = (cc->flag_vhost_found == TLS_FLAG_TRUE)? APR_SUCCESS : APR_NOTFOUND;
cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        rv = tls_util_rustls_error(c->pool, rr, &err_descr);
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
