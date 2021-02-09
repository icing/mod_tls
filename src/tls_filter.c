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
#include <http_log.h>

#include "tls_defs.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_filter.h"
#include "tls_util.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


typedef struct {
    conn_rec *c;                         /* connection this context is for */
    tls_conf_conn_t *cc;                 /* tls module configuration of connection */
    ap_filter_t *fin_ctx;                /* Apache's entry into the input filter chain */
    apr_bucket_brigade *fin_tls_bb;      /* TLS encrypted, incoming network data */
    apr_bucket_brigade *fin_plain_bb;    /* decrypted, incoming traffic data */
    apr_read_type_e fin_block;           /* Do we block on input reads or not? */
    ap_filter_t *fout_ctx;               /* Apache's entry into the output filter chain */
    apr_bucket_brigade *fout_tls_bb;     /* TLS encrypted, outgoing network data */
} tls_filter_ctx_t;


/**
 * Provide TLS encrypted data to the rustls server_session in <fctx->cc->rustls_session>.
 *
 * If <fctx->fin_tls_bb> holds data, take it from there. Otherwise perform a
 * read via the network filters below us into that brigade.
 *
 * <fctx->fin_block> determines if we do a blocking read inititally or not.
 * If the first read did to not produce enough data, any secondary read is done
 * non-blocking.
 *
 * Had any data been added to <fctx->cc->rustls_session>, call its "processing"
 * function to handle the added data before leaving.
 */
static apr_status_t read_tls_to_rustls(
    tls_filter_ctx_t *fctx, apr_off_t len)
{
    const char *data;
    apr_size_t dlen, rlen;
    apr_off_t passed = 0;
    rustls_result rr = RUSTLS_RESULT_OK;
    const char *err_descr = "";
    apr_status_t rv = APR_SUCCESS;

    if (APR_BRIGADE_EMPTY(fctx->fin_tls_bb)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->s,
            "read_tls_to_rustls, get data from network");
        rv = ap_get_brigade(fctx->fin_ctx->next, fctx->fin_tls_bb,
            AP_MODE_READBYTES, fctx->fin_block, len);
        if (APR_SUCCESS != rv) goto cleanup;
    }

    while (!APR_BRIGADE_EMPTY(fctx->fin_tls_bb) && passed < len) {
        apr_bucket *b = APR_BRIGADE_FIRST(fctx->fin_tls_bb);

        if (APR_BUCKET_IS_EOS(b)) {
            rv = APR_EOF; goto cleanup;
        }

        rv = apr_bucket_read(b, &data, &dlen, fctx->fin_block);
        if (APR_STATUS_IS_EOF(rv)) {
            apr_bucket_delete(b);
            continue;
        }
        else if (APR_SUCCESS != rv) {
            goto cleanup;
        }

        if (dlen > 0) {
            /* got something, do not block on getting more */
            fctx->fin_block = APR_NONBLOCK_READ;

            rr = rustls_server_session_read_tls(fctx->cc->rustls_session,
                (unsigned char*)data, dlen, &rlen);
            if (rr != RUSTLS_RESULT_OK) goto cleanup;

            if (rlen >= dlen) {
                apr_bucket_delete(b);
            }
            else {
                b->start += rlen;
                b->length -= rlen;
            }
            passed += rlen;
        }
        else if (dlen == 0) {
            apr_bucket_delete(b);
        }
    }

    if (passed > 0) {
        rr = rustls_server_session_process_new_packets(fctx->cc->rustls_session);
        if (rr != RUSTLS_RESULT_OK) {
            rv = tls_util_rustls_error(fctx->c->pool, rr, &err_descr);
            goto cleanup;
        }
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        rv = tls_util_rustls_error(fctx->c->pool, rr, &err_descr);
    }
    if (APR_STATUS_IS_EOF(rv) && passed > 0) {
        /* encountering EOF while actually having read sth is a success. */
        rv = APR_SUCCESS;
    }
    if (APR_SUCCESS != rv && !APR_STATUS_IS_EAGAIN(rv)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, fctx->c, APLOGNO()
                     "read_tls_to_rustls: [%d] %s", (int)rr, err_descr);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->s,
            "read_tls_to_rustls, passed %ld bytes to rustls", (long)passed);
    }
    return rv;
}

/**
 * Read TLS encrypted data from <fctx->cc->rustls_session> and pass it down
 * Apache's filter chain to the network.
 *
 * For now, we always FLUSH the data, since that is what we need during handshakes.
 */
static apr_status_t write_tls_from_rustls(
    tls_filter_ctx_t *fctx)
{
    char data[8*1024];
    size_t dlen = sizeof(data);
    apr_status_t rv = APR_SUCCESS;
    const char *err_descr = "";
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_bucket *b;

    rr = rustls_server_session_write_tls(fctx->cc->rustls_session,
        (unsigned char*)data, dlen, &dlen);
    if (rr != RUSTLS_RESULT_OK) goto cleanup;

    b = apr_bucket_transient_create(data, dlen, fctx->fout_tls_bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);

    /* for now, flush all the time. */
    b = apr_bucket_flush_create(fctx->fout_tls_bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);

    rv = ap_pass_brigade(fctx->fout_ctx->next, fctx->fout_tls_bb);
    ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->s,
        "write_tls_from_rustls, passed %ld bytes to network", (long)dlen);

    if (APR_SUCCESS == rv && fctx->c->aborted) {
        rv = APR_ECONNRESET;
    }
    apr_brigade_cleanup(fctx->fout_tls_bb);

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        rv = tls_util_rustls_error(fctx->c->pool, rr, &err_descr);
    }
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, fctx->c, APLOGNO()
                     "write_tls_from_rustls: [%d] %s", (int)rr, err_descr);
    }
    return rv;
}

/**
 * While <fctx->cc->rustls_session> indicates that a handshake is ongoing,
 * write TLS data from and read network TLS data to the server session.
 *
 * This is safe to call at any time. When it returns ARP_SUCCESS,
 * actual traffic data is ready to be processed.
 */
static apr_status_t filter_do_handshake(
    tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;
    apr_read_type_e block = fctx->fin_block;

    if (rustls_server_session_is_handshaking(fctx->cc->rustls_session)) {
        do {
            if (rustls_server_session_wants_read(fctx->cc->rustls_session)) {
                /* keep the blocking as requested for multiple handshake ping-pongs */
                fctx->fin_block = block;
                rv = read_tls_to_rustls(fctx, 32*1024);
                if (APR_SUCCESS != rv) goto cleanup;
            }
            if (rustls_server_session_wants_write(fctx->cc->rustls_session)) {
                rv = write_tls_from_rustls(fctx);
                if (APR_SUCCESS != rv) goto cleanup;
            }
        } while (rustls_server_session_is_handshaking(fctx->cc->rustls_session));

        /* vhost_init() returns APR_SUCCESS in case the client SNI was present
         * and matched one of our vhosts, or APR_NOTFOUND otherwise.
         *
         * We continue the handshake in either case, which is what
         * <https://tools.ietf.org/html/rfc6066#page-6> recommends. */
        tls_core_vhost_init(fctx->c);
    }
cleanup:
    return rv;
}

/**
 * The connection filter converting TLS encrypted network data into plain, unencrpyted
 * traffic data to be processed by filters above it in the filter chain.
 *
 * Unfortunately, Apache's filter infrastructure places a heavy implementation
 * complexity on its input filters for the various use cases its HTTP/1.x parser
 * (mainly) finds convenient:
 *
 * <bb>      the bucket brigade to place the data into.
 * <mode>    one of
 *     - AP_MODE_READBYTES: just add up to <readbytes> data into <bb>
 *     - AP_MODE_GETLINE: make a best effort to get data up to and including a CRLF.
 *                        it can be less, but not more t than that.
 *     - AP_MODE_EATCRLF: never used, we puke on it.
 *     - AP_MODE_SPECULATIVE: read data without consuming it.
 *     - AP_MODE_EXHAUSTIVE: never used, we puke on it.
 *     - AP_MODE_INIT: called once on a connection. needs to pass down the filter
 *                      chain, giving every filter the change to "INIT".
 * <block>   do blocking or non-blocking reads
 * <readbytes> max amount of data to add to <bb>, seems to be 0 for GETLINE
 */
static apr_status_t filter_conn_input(
    ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode,
    apr_read_type_e block, apr_off_t readbytes)
{
    tls_filter_ctx_t *fctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;
    apr_off_t passed = 0;
    rustls_result rr = RUSTLS_RESULT_OK;
    const char *err_descr = "";

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->s,
        "tls_filter_conn_input, server=%s, mode=%d, block=%d, readbytes=%ld",
        fctx->cc->s->server_hostname, mode, block, (long)readbytes);

    fctx->fin_block = block;

    if (rustls_server_session_is_handshaking(fctx->cc->rustls_session)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->s,
            "tls_filter_conn_input, server=%s, do handshake",
            fctx->cc->s->server_hostname);
        rv = filter_do_handshake(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
    }

    if (AP_MODE_INIT == mode) {
        /* any potential handshake done, we leave on INIT right away. it is
         * not intended to produce any data. */
        goto cleanup;
    }

    /* If we have nothing buffered, ask the rustls_session for more plain data. */
    while (APR_BRIGADE_EMPTY(fctx->fin_plain_bb)) {
        apr_size_t rlen = 0;
        const char data[32*1024];

        rr = rustls_server_session_read(fctx->cc->rustls_session,
            (unsigned char*)data, sizeof(data), &rlen);
        if (rr != RUSTLS_RESULT_OK) goto cleanup;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "tls_filter_conn_input: got %ld plain bytes from rustls", (long)rlen);
        if (rlen > 0) {
            rv = apr_brigade_write(fctx->fin_plain_bb, NULL, NULL, data, rlen);
            if (APR_SUCCESS != rv) goto cleanup;
        }
        else {
            /* that did not produce anything either. try getting more
             * TLS data from the network into the rustls session. */
            rv = read_tls_to_rustls(fctx, 32*1024);
            if (APR_SUCCESS != rv) goto cleanup;
        }
    }

    if (AP_MODE_GETLINE == mode) {
        if (readbytes <= 0) readbytes = HUGE_STRING_LEN;
        rv = apr_brigade_split_line(bb, fctx->fin_plain_bb, block, readbytes);
        apr_brigade_length(bb, 0, &passed);
    }
    else if (AP_MODE_READBYTES == mode) {
        apr_off_t nlen;
        assert(readbytes > 0);
        rv = tls_util_brigade_transfer(bb, fctx->fin_plain_bb, readbytes, &nlen);
        if (APR_SUCCESS != rv) goto cleanup;
        passed += nlen;
    }
    else if (AP_MODE_SPECULATIVE == mode) {
        apr_off_t nlen;
        ap_assert(readbytes > 0);
        rv = tls_util_brigade_copy(bb, fctx->fin_plain_bb, readbytes, &nlen);
        if (APR_SUCCESS != rv) goto cleanup;
        passed += nlen;
    }
    else if (AP_MODE_EXHAUSTIVE == mode) {
        /* return all we have */
        APR_BRIGADE_CONCAT(bb, fctx->fin_plain_bb);
    }
    else {
        /* We do support any other mode */
        rv = APR_ENOTIMPL; goto cleanup;
    }

    if (rustls_server_session_wants_write(fctx->cc->rustls_session)) {
        rv = write_tls_from_rustls(fctx);
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        rv = tls_util_rustls_error(fctx->c->pool, rr, &err_descr);
    }
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, fctx->c, APLOGNO()
                     "tls_filter_conn_input: [%d] %s", (int)rr, err_descr);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "tls_filter_conn_input: passed %ld bytes", (long)passed);
    }
    return rv;
}

/**
 * The connection filter converting plain, unencrypted traffic data into TLS
 * encrypted bytes and send the down the Apache filter chain out to the network.
 *
 * <bb>    the data to send, including "meta data" such as FLUSH indicators
 *         to force filters to write any data set aside (an apache term for
 *         'buffering').
 *         The buckets in <bb> need to be completely consumed, e.g. <bb> will be
 *         empty on a successful return. but unless FLUSHed, filters may hold
 *         buckets back internally, for various reasons. However they always
 *         need to be processed in the order they arrive.
 */
static apr_status_t filter_conn_output(
    ap_filter_t *f, apr_bucket_brigade *bb)
{
    tls_filter_ctx_t *fctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;
    const char *data;
    apr_size_t dlen, wlen;
    rustls_result rr = RUSTLS_RESULT_OK;
    const char *err_descr = "";
    apr_off_t passed = 0;

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->s,
        "tls_filter_conn_output, server=%s", fctx->cc->s->server_hostname);

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(b)) {
            rv = APR_EOF; goto cleanup;
        }

        rv = apr_bucket_read(b, &data, &dlen, APR_BLOCK_READ);
        if (APR_STATUS_IS_EOF(rv)) {
            apr_bucket_delete(b);
            continue;
        }
        else if (APR_SUCCESS != rv) {
            goto cleanup;
        }

        if (dlen > 0) {
            rr = rustls_server_session_write(fctx->cc->rustls_session,
                (unsigned char*)data, dlen, &wlen);
            if (rr != RUSTLS_RESULT_OK) goto cleanup;
            passed += wlen;
            if (wlen >= dlen) {
                apr_bucket_delete(b);
            }
            else {
                b->start += wlen;
                b->length -= wlen;
            }
            /* write this out at once, so that rustls does not excessive buffering */
            while (rustls_server_session_wants_write(fctx->cc->rustls_session)) {
                rv = write_tls_from_rustls(fctx);
                if (APR_SUCCESS != rv) goto cleanup;
            }
        }
        else if (dlen == 0) {
            apr_bucket_delete(b);
        }
    }
    /* any last words by rustls on this attempt? */
    while (rustls_server_session_wants_write(fctx->cc->rustls_session)) {
        rv = write_tls_from_rustls(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        rv = tls_util_rustls_error(fctx->c->pool, rr, &err_descr);
    }
    if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, fctx->c, APLOGNO()
                     "tls_filter_conn_output: [%d] %s", (int)rr, err_descr);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "tls_filter_conn_output: passed %ld bytes", (long)passed);
    }
    return rv;
}

int tls_filter_conn_init(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);
    tls_filter_ctx_t *fctx;

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server,
        "tls_filter_conn_init on %s", c->base_server->server_hostname);
    ap_assert(cc);
    ap_assert(cc->rustls_session);

    fctx = apr_pcalloc(c->pool, sizeof(*fctx));
    fctx->c = c;
    fctx->cc = cc;

    /* a bit tricky: registering out filters returns the ap_filter_t*
     * that it created for it. The ->next field points always
     * to the filter "below" our filter. That will be other registered
     * filters and last, but not least, the network filter on the socket.
     *
     * Therefore, wenn we need to read/write TLS data during handshake, we can
     * pass the data to/call on ->next- Since ->next can change during the setup of
     * a connections (other modules register also sth.), we keep the ap_filter_t*
     * returned here, since httpd core will update the ->next whenever someone
     * adds a filter or removes one. This can potentially happen all the time.
     */
    fctx->fin_ctx = ap_add_input_filter(TLS_FILTER_RAW, fctx, NULL, c);
    fctx->fin_tls_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    fctx->fin_plain_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    fctx->fout_ctx = ap_add_output_filter(TLS_FILTER_RAW, fctx, NULL, c);
    fctx->fout_tls_bb = apr_brigade_create(c->pool, c->bucket_alloc);

    return OK;
}

void tls_filter_register(
    apr_pool_t *pool)
{
    (void)pool;
    ap_register_input_filter(TLS_FILTER_RAW, filter_conn_input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter(TLS_FILTER_RAW, filter_conn_output, NULL, AP_FTYPE_CONNECTION + 5);
}