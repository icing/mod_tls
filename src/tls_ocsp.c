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
#include <http_log.h>
#include <http_ssl.h>

#include <crustls.h>

#include "tls_cert.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_proto.h"
#include "tls_ocsp.h"

extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


static int prime_cert(
    void *userdata, server_rec *s, const char *cert_id, const char *cert_pem,
    const rustls_certified_key *certified_key)
{
    apr_pool_t *p = userdata;
    apr_status_t rv;

    (void)certified_key;
    rv = ap_ssl_ocsp_prime(s, p, cert_id, strlen(cert_id), cert_pem);
    ap_log_error(APLOG_MARK, APLOG_TRACE1, rv, s, "ocsp prime of cert [%s] from %s",
                 cert_id, s->server_hostname);
    return 1;
}

apr_status_t tls_ocsp_prime_certs(tls_conf_global_t *gc, apr_pool_t *p, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "ocsp priming of %d certs",
                 (int)tls_cert_reg_count(gc->cert_reg));
    tls_cert_reg_do(prime_cert, p, gc->cert_reg);
    return APR_SUCCESS;
}

typedef struct {
    conn_rec *c;
    const rustls_certified_key *key_in;
    const rustls_certified_key *key_out;
} ocsp_copy_ctx_t;

static void ocsp_clone_key(const unsigned char *der, apr_size_t der_len, void *userdata)
{
    ocsp_copy_ctx_t *ctx = userdata;
    rustls_slice_bytes rslice;
    rustls_result rr;

    rslice.data = der;
    rslice.len = der_len;

    rr = rustls_certified_key_clone_with_ocsp(ctx->key_in, der_len? &rslice : NULL, &ctx->key_out);
    if (RUSTLS_RESULT_OK != rr) {
        const char *err_descr = NULL;
        apr_status_t rv = tls_util_rustls_error(ctx->c->pool, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctx->c, APLOGNO()
                     "Failed add OCSP data to certificate: [%d] %s", (int)rr, err_descr);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctx->c,
            "provided %ld bytes of ocsp response DER data to key.", (long)der_len);
    }
}

apr_status_t tls_ocsp_update_key(
    conn_rec *c, const rustls_certified_key *certified_key,
    const rustls_certified_key **pkey_out)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc;
    const char *key_id;
    apr_status_t rv = APR_SUCCESS;
    ocsp_copy_ctx_t ctx;

    assert(cc);
    assert(cc->server);
    sc = tls_conf_server_get(cc->server);
    key_id = tls_cert_reg_get_id(sc->global->cert_reg, certified_key);
    if (!key_id) {
        rv = APR_ENOENT;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c, "certified key not registered");
        goto cleanup;
    }

    ctx.c = c;
    ctx.key_in = certified_key;
    ctx.key_out = NULL;
    rv = ap_ssl_ocsp_get_resp(cc->server, c, key_id, strlen(key_id), ocsp_clone_key, &ctx);
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c,
            "ocsp response not available for cert %s", key_id);
    }

cleanup:
    *pkey_out = (APR_SUCCESS == rv)? ctx.key_out : NULL;
    return rv;
}
