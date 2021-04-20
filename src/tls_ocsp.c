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
    ap_bytes_t id;
    apr_status_t rv;

    (void)certified_key;
    id.data = (unsigned char*)cert_id;
    id.len = strlen(cert_id);
    rv = ap_ssl_ocsp_prime(s, p, &id, cert_pem);
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

AP_DECLARE(apr_status_t) ap_ssl_ocsp_get_resp(server_rec *s, conn_rec *c,
                                              const ap_bytes_t *id,
                                              ap_ssl_ocsp_copy_resp *cb, void *userdata);

typedef struct {
    conn_rec *c;
    unsigned char *buf;
    size_t buf_len;
    size_t resp_len;
} ocsp_copy_ctx_t;

static void ocsp_copy_resp(const unsigned char *der, apr_size_t der_len, void *userdata)
{
    ocsp_copy_ctx_t *ctx = userdata;
    if (der_len > ctx->buf_len) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctx->c, APLOGNO()
            "ocsp response %ld bytes, longer than rustls buffer of %ld, not copying.",
            (long)der_len, (long)ctx->buf_len);
        return;
    }
    memcpy(ctx->buf, der, der_len);
    ctx->resp_len = der_len;
}

void tls_ocsp_provide_resp(
    void *userdata, const rustls_certified_key *certified_key,
    unsigned char *buf, size_t buf_len, size_t *out_n)
{
    conn_rec *c = userdata;
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_conf_server_t *sc;
    apr_status_t rv = APR_SUCCESS;
    const char *key_id;
    ap_bytes_t id;
    ocsp_copy_ctx_t ctx;

    assert(cc);
    assert(cc->server);
    sc = tls_conf_server_get(cc->server);
    *out_n = 0;
    key_id = tls_cert_reg_get_id(sc->global->cert_reg, certified_key);
    if (!key_id) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c, "certified key not registered");
        return;
    }

    ctx.c = c;
    ctx.buf = buf;
    ctx.buf_len = buf_len;
    ctx.resp_len = 0;
    id.data = (unsigned char*)key_id;
    id.len = strlen(key_id);
    rv = ap_ssl_ocsp_get_resp(cc->server, c, &id, ocsp_copy_resp, &ctx);
    if (APR_SUCCESS == rv) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
            "provided %ld bytes of ocsp response DER data.", (long)ctx.resp_len);
        *out_n = ctx.resp_len;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, c,
            "ocsp response not available for cert %s", key_id);
    }
}
