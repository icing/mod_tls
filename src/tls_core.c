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

apr_status_t tls_core_init(apr_pool_t *p, apr_pool_t *ptemp, server_rec *base_server)
{
    tls_conf_server_t *sc = tls_conf_server_get(base_server);
    tls_conf_global_t *gc = sc->global;
    server_rec *s;
    rustls_server_config_builder *rustls_builder;
    apr_status_t rv = APR_ENOMEM;
    rustls_result rr = RUSTLS_RESULT_OK;
    const char *err_descr;

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
        if (!sc || sc->enabled != TLS_FLAG_TRUE) continue;

        rustls_builder = rustls_server_config_builder_new();
        if (!rustls_builder) goto cleanup;

        /* TODO: this needs some more work */
        if (sc->certificates->nelts > 0) {
            tls_certificate_t *spec = APR_ARRAY_IDX(sc->certificates, 0, tls_certificate_t*);
            tls_util_cert_pem_t *pems;

            rv = tls_util_load_pem(ptemp, spec, &pems);
            if (APR_SUCCESS != rv) goto cleanup;
            ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, base_server,
                "tls_core_init: loaded pem data: %s (%ld), %s (%ld)",
                spec->cert_file, (long)pems->cert_pem_len,
                spec->pkey_file, (long)pems->pkey_pem_len
                );

            rr = rustls_server_config_builder_set_single_cert_pem(rustls_builder,
                pems->cert_pem_bytes, pems->cert_pem_len,
                pems->pkey_pem_bytes, pems->pkey_pem_len);
            if (rr != RUSTLS_RESULT_OK) {
                rv = tls_util_rustls_error(ptemp, rr, &err_descr);
                ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO()
                             "Failed to load certficates for server %s: [%d] %s",
                             s->server_hostname, (int)rr, err_descr);
                goto cleanup;
            }
        }
        rustls_server_config_builder_set_ignore_client_order(rustls_builder,
            !sc->honor_client_order);

        sc->rustls_config = rustls_server_config_builder_build(rustls_builder);
        if (!sc->rustls_config) goto cleanup;
    }

    rv = APR_SUCCESS;
cleanup:
    ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, base_server, "tls_core_init done.");
    return rv;
}


int tls_core_conn_init(conn_rec *c)
{
    tls_conf_server_t *sc = tls_conf_server_get(c->base_server);
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    int rv = DECLINED;

    /* Are we configured to work here? */
    if (!sc->rustls_config) goto cleanup;

    if (!cc) {
        rustls_result rr;
        const char *err_descr = NULL;

        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server, "tls_core_conn_init on %s",
            c->base_server->server_hostname);
        /* start with the base server, SNI may update this during handshake */
        cc = apr_pcalloc(c->pool, sizeof(*cc));
        cc->server = c->base_server;
        cc->flag_disabled = TLS_FLAG_FALSE;
        cc->flag_vhost_found = TLS_FLAG_UNSET;

        rr = rustls_server_session_new(sc->rustls_config, &cc->rustls_session);
    if (rr != RUSTLS_RESULT_OK) {
        rv = tls_util_rustls_error(c->pool, rr, &err_descr);
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, sc->server, APLOGNO()
                     "Failed to init session for server %s: [%d] %s",
                     sc->server->server_hostname, (int)rr, err_descr);
        goto cleanup;
        }
        tls_conf_conn_set(c, cc);
    }
    rv = OK;
cleanup:
    return rv;
}

static int find_vhost(void *sni_hostname, conn_rec *c, server_rec *s)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc;
    int found = 0;

    if (!tls_util_name_matches_server(sni_hostname, s)) goto cleanup;

    cc->server = s;
    found = 1;
    sc = tls_conf_server_get(s);
    /* TODO: set TLS parameter configured for the server, especially
     * the certificates configured for it.
     */
    (void)sc;

cleanup:
    return found;
}

apr_status_t tls_core_vhost_init(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    rustls_result rr = RUSTLS_RESULT_OK;
    const char *err_descr = "";
    apr_status_t rv = APR_SUCCESS;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c, "vhost_init: start");
    ap_assert(cc);
    ap_assert(cc->rustls_session);

    if (cc->flag_vhost_found == TLS_FLAG_UNSET) {
        if (NULL == cc->sni_hostname) {
            char sni_buffer[HUGE_STRING_LEN];
            size_t blen;

            rr = rustls_server_session_sni_hostname_get(cc->rustls_session,
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
            cc->flag_vhost_found = TLS_FLAG_TRUE;
            goto cleanup;
        }
        /* TODO: mod_md ACME challenge might provide a certificate.
         * This atm runs via an optional hook provided by mod_ssl. That
         * needs to become part of httpds infrastructure.
         */
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, c, APLOGNO()
                "vhost_init: virtual host NOT found for SNI '%s'", cc->sni_hostname);
            /* fall through which returns APR_NOTFOUND */
        }
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
    if (!cc || cc->flag_disabled == TLS_FLAG_TRUE) goto cleanup;
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
