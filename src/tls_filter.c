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
#include <ap_socache.h>

#include <crustls.h>

#include "tls_proto.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_filter.h"
#include "tls_util.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);


static rustls_io_result tls_read_callback(
    void *userdata, unsigned char *buf, size_t n, size_t *out_n)
{
    tls_data_t *d = userdata;
    size_t len = d->len > n? n : d->len;
    memcpy(buf, d->data, len);
    *out_n = len;
    return 0;
}

static apr_status_t write_tls_brigade(apr_bucket_brigade *bb, void *userdata)
{
    tls_filter_ctx_t *fctx = userdata;
    apr_status_t rv = APR_SUCCESS;
    apr_off_t len;

    assert(bb == fctx->fout_tls_bb);
    if (!APR_BRIGADE_EMPTY(fctx->fout_tls_bb)) {
        apr_brigade_length(fctx->fout_tls_bb, 0, &len);
        rv = ap_pass_brigade(fctx->fout_ctx->next, fctx->fout_tls_bb);
        fctx->fout_bytes_in_tls_bb = 0;
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->server,
            "brigade_tls_from_rustls, passed %ld bytes to network", (long)len);

        if (APR_SUCCESS == rv && fctx->c->aborted) {
            rv = APR_ECONNRESET;
        }
        apr_brigade_cleanup(fctx->fout_tls_bb);
    }
    return rv;
}

static rustls_io_result tls_write_callback(
    void *userdata, const unsigned char *buf, size_t n, size_t *out_n)
{
    tls_filter_ctx_t *fctx = userdata;
    apr_status_t rv;

    rv = apr_brigade_write(fctx->fout_tls_bb, NULL, NULL, (const char*)buf, n);
    ap_log_error(APLOG_MARK, APLOG_TRACE4, rv, fctx->cc->server,
        "tls_write_callback, added %ld bytes to fctx->fout_tls_bb", (long)n);
    if (APR_SUCCESS == rv) {
        fctx->fout_bytes_in_tls_bb += (apr_off_t)n;
        *out_n = n;
    }
    return APR_TO_OS_ERROR(rv);
}

/**
 * Provide TLS encrypted data to the rustls server_session in <fctx->cc->rustls_connection>.
 *
 * If <fctx->fin_tls_bb> holds data, take it from there. Otherwise perform a
 * read via the network filters below us into that brigade.
 *
 * <fctx->fin_block> determines if we do a blocking read inititally or not.
 * If the first read did to not produce enough data, any secondary read is done
 * non-blocking.
 *
 * Had any data been added to <fctx->cc->rustls_connection>, call its "processing"
 * function to handle the added data before leaving.
 */
static apr_status_t read_tls_to_rustls(
    tls_filter_ctx_t *fctx, apr_off_t len, int errors_expected)
{
    tls_data_t d;
    apr_size_t rlen;
    apr_off_t passed = 0;
    rustls_result rr = RUSTLS_RESULT_OK;
    int os_err;
    apr_status_t rv = APR_SUCCESS;
    apr_read_type_e block = fctx->fin_block;

    if (APR_BRIGADE_EMPTY(fctx->fin_tls_bb)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->server,
            "read_tls_to_rustls, get data from network, block=%d", block);
        rv = ap_get_brigade(fctx->fin_ctx->next, fctx->fin_tls_bb,
            AP_MODE_READBYTES, block, len);
        if (APR_SUCCESS != rv) {
            goto cleanup;
        }
    }

    while (!APR_BRIGADE_EMPTY(fctx->fin_tls_bb) && passed < len) {
        apr_bucket *b = APR_BRIGADE_FIRST(fctx->fin_tls_bb);

        if (APR_BUCKET_IS_EOS(b)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->server,
                "read_tls_to_rustls, EOS");
            if (fctx->fin_tls_buffer_bb) {
                apr_brigade_cleanup(fctx->fin_tls_buffer_bb);
            }
            rv = APR_EOF; goto cleanup;
        }

        rv = apr_bucket_read(b, (const char**)&d.data, &d.len, block);
        if (APR_STATUS_IS_EOF(rv)) {
            apr_bucket_delete(b);
            continue;
        }
        else if (APR_SUCCESS != rv) {
            goto cleanup;
        }

        if (d.len > 0) {
            /* got something, do not block on getting more */
            block = APR_NONBLOCK_READ;

            os_err = rustls_connection_read_tls(fctx->cc->rustls_connection,
                                tls_read_callback, &d, &rlen);
            if (os_err) {
                rv = APR_FROM_OS_ERROR(os_err);
                goto cleanup;
            }

            if (fctx->fin_tls_buffer_bb) {
                /* we buffer for later replay on the 'real' rustls_connection */
                apr_brigade_write(fctx->fin_tls_buffer_bb, NULL, NULL, (const char*)d.data, rlen);
            }
            if (rlen >= d.len) {
                apr_bucket_delete(b);
            }
            else {
                b->start += (apr_off_t)rlen;
                b->length -= rlen;
            }
            fctx->fin_bytes_in_rustls += (apr_off_t)d.len;
            passed += (apr_off_t)rlen;
        }
        else if (d.len == 0) {
            apr_bucket_delete(b);
        }
    }

    if (passed > 0) {
        rr = rustls_connection_process_new_packets(fctx->cc->rustls_connection);
        if (rr != RUSTLS_RESULT_OK) goto cleanup;
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        rv = APR_ECONNRESET;
        if (!errors_expected) {
            const char *err_descr = "";
            rv = tls_core_error(fctx->c, rr, &err_descr);
            ap_log_cerror(APLOG_MARK, APLOG_WARNING, rv, fctx->c, APLOGNO()
                         "processing TLS data: [%d] %s", (int)rr, err_descr);
        }
    }
    else if (APR_STATUS_IS_EOF(rv) && passed > 0) {
        /* encountering EOF while actually having read sth is a success. */
        rv = APR_SUCCESS;
    }
    else if (APR_SUCCESS == rv && passed == 0 && fctx->fin_block == APR_NONBLOCK_READ) {
        rv = APR_EAGAIN;
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->server,
            "read_tls_to_rustls, passed %ld bytes to rustls", (long)passed);
    }
    return rv;
}

/**
 * Read TLS encrypted data from <fctx->cc->rustls_connection> and pass it down
 * Apache's filter chain to the network.
 *
 * For now, we always FLUSH the data, since that is what we need during handshakes.
 */
static apr_status_t brigade_tls_from_rustls(
    tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;
    size_t dlen;
    int os_err;

    if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
        do {
            os_err = rustls_connection_write_tls(
                fctx->cc->rustls_connection, tls_write_callback, fctx, &dlen);
            if (os_err) {
                rv = APR_FROM_OS_ERROR(os_err);
                goto cleanup;
            }
        }
        while (rustls_connection_wants_write(fctx->cc->rustls_connection));
        fctx->fout_bytes_in_rustls = 0;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, rv, fctx->c,
            "brigade_tls_from_rustls, %ld bytes ready for network", (long)fctx->fout_bytes_in_tls_bb);
    }
cleanup:
    return rv;
}

static apr_status_t write_all_tls_from_rustls(
    tls_filter_ctx_t *fctx, int flush)
{
    apr_status_t rv;

    rv = brigade_tls_from_rustls(fctx);
    if (APR_SUCCESS != rv) goto cleanup;
    if (flush) {
        apr_bucket *b;
        b = apr_bucket_flush_create(fctx->fout_tls_bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);
    }
    rv = write_tls_brigade(fctx->fout_tls_bb, fctx);
cleanup:
    return rv;
}

static apr_status_t filter_abort(
    tls_filter_ctx_t *fctx)
{
    apr_status_t rv;

    if (fctx->cc->state != TLS_CONN_ST_DONE) {
        rustls_connection_send_close_notify(fctx->cc->rustls_connection);
        rv = write_all_tls_from_rustls(fctx, 1);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c, "filter_abort, flushed output");
        fctx->c->aborted = 1;
        fctx->cc->state = TLS_CONN_ST_DONE;
    }
    return APR_ECONNABORTED;
}

/**
 *
 */
static apr_status_t filter_do_pre_handshake(
    tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    /* This phase does nothing for outgoing connections */
    if (fctx->cc->outgoing) goto cleanup;

    if (rustls_connection_is_handshaking(fctx->cc->rustls_connection)) {
        apr_bucket_brigade *bb_tmp;

        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c, "filter_do_pre_handshake: start");
        fctx->fin_tls_buffer_bb = apr_brigade_create(fctx->c->pool, fctx->c->bucket_alloc);
        do {
            if (rustls_connection_wants_read(fctx->cc->rustls_connection)) {
                rv = read_tls_to_rustls(fctx, fctx->fin_max_in_rustls, 1);
                if (APR_SUCCESS != rv) {
                    if (fctx->cc->client_hello_seen) {
                        rv = APR_EAGAIN;  /* we got what we needed */
                        break;
                    }
                    /* Something went wrong before we saw the client hello.
                     * This is a real error on which we should not continue. */
                    goto cleanup;
                }
            }
            /* Notice: we never write here to the client. We just want to inspect
             * the client hello. */
        } while (!fctx->cc->client_hello_seen);

        /* We have seen the client hello and selected the server (vhost) to use
         * on this connection. Set up the 'real' rustls_connection based on the
         * servers 'real' rustls_config. */
        rv = tls_core_conn_seen_client_hello(fctx->c);
        if (APR_SUCCESS != rv) goto cleanup;

        bb_tmp = fctx->fin_tls_bb; /* data we have yet to feed to rustls */
        fctx->fin_tls_bb = fctx->fin_tls_buffer_bb; /* data we already fed to the pre_session */
        fctx->fin_tls_buffer_bb = NULL;
        APR_BRIGADE_CONCAT(fctx->fin_tls_bb, bb_tmp); /* all tls data from the cleint so far, reloaded */
        apr_brigade_destroy(bb_tmp);
        rv = APR_SUCCESS;
    }

cleanup:
    if (APR_SUCCESS != rv && !APR_STATUS_IS_EAGAIN(rv)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c, "filter_do_pre_handshake: abort");
        rv = filter_abort(fctx);
    }
    return rv;
}

/**
 * While <fctx->cc->rustls_connection> indicates that a handshake is ongoing,
 * write TLS data from and read network TLS data to the server session.
 *
 * @return APR_SUCCESS when the handshake is completed
 */
static apr_status_t filter_do_handshake(
    tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    if (rustls_connection_is_handshaking(fctx->cc->rustls_connection)) {
        do {
            if (rustls_connection_wants_read(fctx->cc->rustls_connection)) {
                rv = read_tls_to_rustls(fctx, fctx->fin_max_in_rustls, 0);
                if (APR_SUCCESS != rv) goto cleanup;
            }
            if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
                rv = write_all_tls_from_rustls(fctx, 1);
                if (APR_SUCCESS != rv) goto cleanup;
            }
        }
        while (rustls_connection_is_handshaking(fctx->cc->rustls_connection));

        rv = tls_core_conn_post_handshake(fctx->c);
        if (APR_SUCCESS != rv) goto cleanup;
    }
cleanup:
    if (APR_SUCCESS != rv && !APR_STATUS_IS_EAGAIN(rv)) {
        if (fctx->cc->last_error_descr) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, APR_ECONNABORTED, fctx->c, APLOGNO()
                "handshake failed: %s", fctx->cc->last_error_descr);
        }
        rv = filter_abort(fctx);
    }
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
    apr_off_t passed = 0, nlen;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_size_t in_buf_len;
    char *in_buf = NULL;

    fctx->fin_block = block;
    if (f->c->aborted) {
        rv = filter_abort(fctx); goto cleanup;
    }

    if (!fctx->cc->rustls_connection) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter_conn_input, server=%s, mode=%d, block=%d, readbytes=%ld",
        fctx->cc->server->server_hostname, mode, block, (long)readbytes);

    if (TLS_CONN_ST_PRE_HANDSHAKE == fctx->cc->state) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
            "tls_filter_conn_input, server=%s, do pre_handshake",
            fctx->cc->server->server_hostname);
        rv = filter_do_pre_handshake(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
        fctx->cc->state = TLS_CONN_ST_HANDSHAKE;
    }
    if (TLS_CONN_ST_HANDSHAKE == fctx->cc->state) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
            "tls_filter_conn_input, server=%s, do handshake",
            fctx->cc->server->server_hostname);
        rv = filter_do_handshake(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
        fctx->cc->state = TLS_CONN_ST_TRAFFIC;
    }

    if (AP_MODE_INIT == mode) {
        /* any potential handshake done, we leave on INIT right away. it is
         * not intended to produce any data. */
        goto cleanup;
    }

    /* If we have nothing buffered, try getting more input.
     * a) ask rustls_connection for decrypted data, if it has any.
     *    Note that only full records can be decrypted. We might have
     *    written TLS data to the session, but that does not mean it
     *    can give unencryted data out again.
     * b) read TLS bytes from the network and feed them to the rustls session.
     * c) go back to a) if b) added data.
     */
#if AP_MODULE_MAGIC_AT_LEAST(20200420, 1)
    ap_filter_reinstate_brigade(f, fctx->fin_plain_bb, NULL);
#endif
    while (APR_BRIGADE_EMPTY(fctx->fin_plain_bb)) {
        apr_size_t rlen = 0;
        apr_bucket *b;

        if (fctx->fin_bytes_in_rustls > 0) {
            in_buf_len = APR_BUCKET_BUFF_SIZE;
            in_buf = ap_calloc(in_buf_len, sizeof(char));
            rr = rustls_connection_read(fctx->cc->rustls_connection,
                (unsigned char*)in_buf, in_buf_len, &rlen);
            if (rr != RUSTLS_RESULT_OK) goto cleanup;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                         "tls_filter_conn_input: got %ld plain bytes from rustls", (long)rlen);
            if (rlen > 0) {
                b = apr_bucket_heap_create(in_buf, rlen, free, fctx->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(fctx->fin_plain_bb, b);
            }
            else {
                free(in_buf);
            }
            in_buf = NULL;
        }
        if (rlen == 0) {
            /* that did not produce anything either. try getting more
             * TLS data from the network into the rustls session. */
            fctx->fin_bytes_in_rustls = 0;
            rv = read_tls_to_rustls(fctx, fctx->fin_max_in_rustls, 0);
            if (APR_SUCCESS != rv) goto cleanup; /* this also leave on APR_EAGAIN */
        }
    }

    if (AP_MODE_GETLINE == mode) {
        if (readbytes <= 0) readbytes = HUGE_STRING_LEN;
        rv = tls_util_brigade_split_line(bb, fctx->fin_plain_bb, block, readbytes, &nlen);
        if (APR_SUCCESS != rv) goto cleanup;
        passed += nlen;
    }
    else if (AP_MODE_READBYTES == mode) {
        ap_assert(readbytes > 0);
        rv = tls_util_brigade_transfer(bb, fctx->fin_plain_bb, readbytes, &nlen);
        if (APR_SUCCESS != rv) goto cleanup;
        passed += nlen;
    }
    else if (AP_MODE_SPECULATIVE == mode) {
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

    write_all_tls_from_rustls(fctx, 0);

cleanup:
    if (NULL != in_buf) free(in_buf);

    if (APLOGctrace3(fctx->c)) {
        tls_util_bb_log(fctx->c, APLOG_TRACE3, "tls_input, fctx->fin_plain_bb", fctx->fin_plain_bb);
        tls_util_bb_log(fctx->c, APLOG_TRACE3, "tls_input, bb", bb);
    }
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";

        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO()
                     "tls_filter_conn_input: [%d] %s", (int)rr, err_descr);
    }
    else if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO()
                     "tls_filter_conn_input");
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "tls_filter_conn_input: passed %ld bytes", (long)passed);
    }
#if AP_MODULE_MAGIC_AT_LEAST(20200420, 1)
    if (rv == APR_SUCCESS && AP_MODE_INIT != mode) {
        rv = ap_filter_setaside_brigade(f, fctx->fin_plain_bb);
    }
#endif
    return rv;
}

static apr_status_t fout_plain_buf_to_rustls(
    tls_filter_ctx_t *fctx)
{
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    if (fctx->fout_buf_plain_len > 0) {
        apr_size_t wlen;

        rr = rustls_connection_write(fctx->cc->rustls_connection,
            (unsigned char*)fctx->fout_buf_plain, fctx->fout_buf_plain_len, &wlen);
        if (rr != RUSTLS_RESULT_OK) goto cleanup;
        fctx->fout_bytes_in_rustls += (apr_off_t)wlen;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, fctx->c,
                     "fout_plain_buf_to_rustls: %ld plain bytes written to rustls (%ld accepted)",
                     (long)fctx->fout_buf_plain_len, (long)wlen);
        if (wlen >= fctx->fout_buf_plain_len) {
            fctx->fout_buf_plain_len = 0;
        }
        else if (wlen == 0) {
            rv = APR_EAGAIN;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, fctx->c, APLOGNO()
                         "fout_plain_buf_to_rustls: not read by rustls at all");
            goto cleanup;
        }
        else {
            /* move the remaining data to the start of the buffer. We
             * could optimize this more, but this should rarely ever happen, or? */
            fctx->fout_buf_plain_len -= wlen;
            memmove(fctx->fout_buf_plain, fctx->fout_buf_plain + wlen,
                fctx->fout_buf_plain_len);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, fctx->c,
                         "fout_plain_buf_to_rustls: not wholly written to rustls"
                         ", moved %ld bytes to start of buffer", (long)fctx->fout_buf_plain_len);
        }
    }
cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";
        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO()
                     "fout_plain_buf_to_rustls to rustls: [%d] %s", (int)rr, err_descr);
    }
    return rv;
}

static apr_status_t fout_plain_buf_append(
    tls_filter_ctx_t *fctx, apr_bucket *b, apr_size_t *plen)
{
    const char *data;
    apr_size_t dlen, wlen = 0, buf_remain;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;

    dlen = b->length;
    ap_assert((apr_size_t)-1 != dlen); /* should have been read already */
    buf_remain = fctx->fout_buf_plain_size - fctx->fout_buf_plain_len;
    if (buf_remain == 0) {
        rv = fout_plain_buf_to_rustls(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
        buf_remain = fctx->fout_buf_plain_size - fctx->fout_buf_plain_len;
        ap_assert(buf_remain > 0);
    }
    /* size the bucket to the remaining space in our buffer */
    if (dlen > buf_remain) {
        apr_bucket_split(b, buf_remain);
        dlen = b->length;
    }

    if (APR_BUCKET_IS_FILE(b)) {
        /* A file bucket is a most wonderous thing. Since the dawn of time,
         * it has been subject to many optimizations for efficient handling
         * of large data in the server:
         * - unless one reads from it, it will just consist of a file handle
         *   and the offset+length information.
         * - a apr_bucket_read() will transform itself to a bucket holding
         *   some 8000 bytes of data (APR_BUCKET_BUFF_SIZE), plus a following
         *   bucket that continues to hold the file handle and updated offsets/length
         *   information.
         *   Using standard bucket brigade handling, one would send 8000 bytes
         *   chunks to the network and that is fine for many occasions.
         * - to have improved performance, the http: network handler takes
         *   the file handle directly and uses sendfile() when the OS supports it.
         * - But there is not sendfile() for TLS (netflix did some experiments).
         * So.
         * rustls willl try to collect max length traffic data into ont TLS
         * message, but it can only work with what we gave it. If we give it buffers
         * that fit what it wants to assemble already, its work is much easier.
         *
         * We can read file buckets in large chunks than APR_BUCKET_BUFF_SIZE,
         * with a bit of knowledge about how they work.
         */
        apr_bucket_file *f = (apr_bucket_file *)b->data;
        apr_file_t *fd = f->fd;
        apr_off_t offset = b->start;

        ap_assert(dlen <= buf_remain);
        rv = apr_file_seek(fd, APR_SET, &offset);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = apr_file_read(fd, (void*)(fctx->fout_buf_plain + fctx->fout_buf_plain_len), &dlen);
        if (APR_SUCCESS != rv && !APR_STATUS_IS_EOF(rv)) goto cleanup;
        fctx->fout_buf_plain_len += dlen;
        wlen = dlen;
        apr_bucket_delete(b);
    }
    else {
        rv = apr_bucket_read(b, &data, &dlen, APR_BLOCK_READ);
        if (APR_SUCCESS != rv) goto cleanup;
        if (fctx->fout_buf_plain_len == 0 &&
            (dlen >= fctx->fout_buf_plain_size || dlen > TLS_PREF_WRITE_SIZE)) {
            /* The data in the bucket is at least as large as our output buffer.
             * There is no need to copy it to the buffer, only to write the buffer
             * afterwards. Instead, write the data directly to rustls.
             */
            rr = rustls_connection_write(fctx->cc->rustls_connection,
                (unsigned char*)data, dlen, &wlen);
            if (rr != RUSTLS_RESULT_OK) goto cleanup;
            fctx->fout_bytes_in_rustls += (apr_off_t)wlen;
            if (wlen >= dlen) {
                apr_bucket_delete(b);
            }
            else {
                b->start += (apr_off_t)wlen;
                b->length -= wlen;
            }
        }
        else {
            ap_assert(dlen <= buf_remain);
            memcpy(fctx->fout_buf_plain + fctx->fout_buf_plain_len, data, dlen);
            fctx->fout_buf_plain_len += dlen;
            wlen = dlen;
            apr_bucket_delete(b);
        }
    }

cleanup:
    *plen = wlen;
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";
        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO()
                     "write_bucket_to_rustls: [%d] %s", (int)rr, err_descr);
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
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_off_t passed = 0;
    apr_size_t wlen;
    int flush = 0;

    if (f->c->aborted) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, fctx->c,
            "tls_filter_conn_output: aborted conn");
        apr_brigade_cleanup(bb);
        rv = APR_ECONNABORTED; goto  cleanup;
    }

    if (!fctx->cc->rustls_connection || (fctx->cc->state == TLS_CONN_ST_DONE)) {
        /* have done everything, just pass through */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, fctx->c,
            "tls_filter_conn_output: ssl done conn");
        rv = ap_pass_brigade(f->next, bb);
        goto cleanup;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter_conn_output, server=%s", fctx->cc->server->server_hostname);
    tls_util_bb_log(fctx->c, APLOG_TRACE3, "filter_conn_output", bb);

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_METADATA(b)) {
            /* we need to pass the meta data buckets down to the network,
             * as they may have meaning there (EOS for example).
             * Everything we have buffered needs to go to rustls and
             * from there to our fout_tls_bb bucket brigade.
             * Then we can append this meta bucket and keep the order
             * of data.
             */
            if (AP_BUCKET_IS_EOC(b)) {
                rustls_connection_send_close_notify(fctx->cc->rustls_connection);
                fctx->cc->state = TLS_CONN_ST_NOTIFIED;
            }
            else if (APR_BUCKET_IS_FLUSH(b)) {
                flush = 1;
            }

            rv = fout_plain_buf_to_rustls(fctx);
            if (APR_SUCCESS != rv) goto cleanup;
            rv = brigade_tls_from_rustls(fctx);
            if (APR_SUCCESS != rv) goto cleanup;

            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);
        }
        else {
            /* Resolve any indeterminate bucket to a "real" one by reading it. */
            if ((apr_size_t)-1 == b->length) {
                const char *data;
                apr_size_t dlen;

                rv = apr_bucket_read(b, &data, &dlen, APR_BLOCK_READ);
                if (APR_STATUS_IS_EOF(rv)) {
                    apr_bucket_delete(b);
                    continue;
                }
                else if (APR_SUCCESS != rv) goto cleanup;

            }
            rv = fout_plain_buf_append(fctx, b, &wlen);
            if (APR_SUCCESS != rv) goto cleanup;
            passed += (apr_off_t)wlen;
        }

        /* did we w supply 'enough' plain bytes to rustls? If so,
         * get the tls from rustls into our fout_tls_bb brigade.
         * If the brigade now holds 'enough' bytes, pass them to
         * the network.
         */
        if (fctx->fout_bytes_in_rustls >= fctx->fout_max_in_rustls) {
            rv = brigade_tls_from_rustls(fctx);
            if (APR_SUCCESS != rv) goto cleanup;
        }
        if (fctx->fout_bytes_in_tls_bb >= fctx->fout_max_in_rustls) {
            rv = write_all_tls_from_rustls(fctx, flush);
            if (APR_SUCCESS != rv) goto cleanup;
            flush = 0;
        }
    }

    rv = fout_plain_buf_to_rustls(fctx);
    if (APR_SUCCESS != rv) goto cleanup;
    if (passed > 0) {
        tls_util_bb_log(fctx->c, APLOG_TRACE3, "filter_conn_output, processed plain", bb);
        tls_util_bb_log(fctx->c, APLOG_TRACE3, "filter_conn_output, tls", fctx->fout_tls_bb);
    }
    /* write everything still in rustls outgoing buffers to the network */
    rv = write_all_tls_from_rustls(fctx, flush);

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";
        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO()
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
    ap_assert(cc->rustls_connection);

    fctx = apr_pcalloc(c->pool, sizeof(*fctx));
    fctx->c = c;
    fctx->cc = cc;
    cc->filter_ctx = fctx;

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
    fctx->fin_tls_buffer_bb = NULL;
    fctx->fin_plain_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    fctx->fout_ctx = ap_add_output_filter(TLS_FILTER_RAW, fctx, NULL, c);
    fctx->fout_tls_bb = apr_brigade_create(c->pool, c->bucket_alloc);
    fctx->fout_buf_plain_size = 2 * TLS_PREF_WRITE_SIZE;
    fctx->fout_buf_plain = apr_pcalloc(c->pool, fctx->fout_buf_plain_size);
    fctx->fout_buf_plain_len = 0;

    /* Let the filters have 2 max-length TLS Messages in the rustls buffers.
     * The effects we would like to achieve here are:
     * 1. pass data out, so that every bucket becomes its own TLS message.
     *    This hides, if possible, the length of response parts.
     *    If we give rustls enough plain data, it will use the max TLS message
     *    size and things are more hidden. But we can only write what the application
     *    or protocol gives us.
     * 2. max length records result in less overhead for all layers involved.
     * 3. a TLS message from the client can only be decrypted when it has
     *    completely arrived. If we provide rustls with enough data (if the
     *    network has it for us), it should always be able to decrypt at least
     *    one TLS message and we have plain bytes to forward to the protocol
     *    handler.
     */
    fctx->fout_max_in_rustls = 2 * 2 * TLS_PREF_WRITE_SIZE; /* 2 times the buffer */
    fctx->fin_max_in_rustls = 2 * TLS_PREF_TLS_WRITE_SIZE;

    return OK;
}

void tls_filter_register(
    apr_pool_t *pool)
{
    (void)pool;
    ap_register_input_filter(TLS_FILTER_RAW, filter_conn_input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter(TLS_FILTER_RAW, filter_conn_output, NULL, AP_FTYPE_CONNECTION + 5);
}