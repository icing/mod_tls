/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <errno.h>

#include <httpd.h>
#include <http_connection.h>
#include <http_core.h>
#include <http_request.h>
#include <http_log.h>
#include <ap_socache.h>

#include <rustls.h>

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

/**
 * Provide TLS encrypted data to the rustls server_session in <fctx->cc->rustls_connection>.
 *
 * If <fctx->fin_tls_bb> holds data, take it from there. Otherwise perform a
 * read via the network filters below us into that brigade.
 *
 * <fctx->fin_block> determines if we do a blocking read initially or not.
 * If the first read did to not produce enough data, any secondary read is done
 * non-blocking.
 *
 * Had any data been added to <fctx->cc->rustls_connection>, call its "processing"
 * function to handle the added data before leaving.
 */
static apr_status_t read_tls_to_rustls(
    tls_filter_ctx_t *fctx, apr_size_t len, apr_read_type_e block)
{
    apr_read_type_e caller_block = block; /* preserve caller's blocking mode */
    tls_data_t d;
    apr_size_t rlen;
    apr_off_t passed = 0;
    rustls_result rr = RUSTLS_RESULT_OK;
    int os_err;
    apr_status_t rv = APR_SUCCESS;

    if (APR_BRIGADE_EMPTY(fctx->fin_tls_bb)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->server,
            "read_tls_to_rustls, get data from network, block=%d", block);
        rv = ap_get_brigade(fctx->fin_ctx->next, fctx->fin_tls_bb,
                            AP_MODE_READBYTES, block, (apr_off_t)len);
        if (APR_SUCCESS != rv) {
            goto cleanup;
        }
    }

    while (!APR_BRIGADE_EMPTY(fctx->fin_tls_bb)) {
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
            fctx->fin_data_pending = TRUE;
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
            /* passed tracks how much data rustls actually accepted (rlen) */
            passed += (apr_off_t)rlen;
            
            /* Process packets after each successful read_tls call, as per rustls
             * documentation: "You should call process_new_packets() each time
             * a call to this function succeeds in order to empty the incoming
             * TLS data buffer." */
            if (rlen > 0) {
                rr = rustls_connection_process_new_packets(fctx->cc->rustls_connection);
                if (rr != RUSTLS_RESULT_OK) {
                    /* If processing fails, we've already passed some data to rustls. */
                    goto cleanup;
                }
            }
        }
        else if (d.len == 0) {
            apr_bucket_delete(b);
        }
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        /* Treat a peer close_notify as a graceful EOF, not a reset. */
        if (rr == RUSTLS_RESULT_ALERT_CLOSE_NOTIFY) {
            rv = APR_EOF;
        }
        else {
            /* If we already processed some bytes, return a soft error instead of reset */
            if (passed > 0) {
                rv = APR_EGENERAL;
            }
            else {
                rv = APR_ECONNRESET;
            }
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
    /* Coerce EAGAIN only for blocking callers; propagate for non-blocking */
    if ((rv == APR_EAGAIN || APR_STATUS_IS_EAGAIN(rv) || rv == APR_FROM_OS_ERROR(EAGAIN))) {
        if (caller_block == APR_BLOCK_READ) {
            if (APLOGctrace4(fctx->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE4, rv, fctx->c,
                              "read_tls_to_rustls: coerce EAGAIN->SUCCESS (blocking)");
            }
            rv = APR_SUCCESS;
        } else {
            if (APLOGctrace4(fctx->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE4, rv, fctx->c,
                              "read_tls_to_rustls: return EAGAIN (non-blocking, no progress)");
            }
            rv = APR_EAGAIN;
        }
    }
    /* Final unified trace for exit status and state */
    if (APLOGctrace1(fctx->c)) {
        int wants_r = rustls_connection_wants_read(fctx->cc->rustls_connection);
        int wants_w = rustls_connection_wants_write(fctx->cc->rustls_connection);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, rv, fctx->c,
                      "read_tls_to_rustls: return rv=%d rr=%d passed=%ld block=%d wants_read=%d wants_write=%d fin_pending=%d",
                      (int)rv, (int)rr, (long)passed, (int)block, wants_r, wants_w,
                      fctx->fin_data_pending);
    }
    return rv;
}

static apr_status_t fout_pass_tls_to_net(tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    if (!APR_BRIGADE_EMPTY(fctx->fout_tls_bb)) {
        rv = ap_pass_brigade(fctx->fout_ctx->next, fctx->fout_tls_bb);
        if (APR_SUCCESS == rv && fctx->c->aborted) {
            /* Graceful close instead of hard reset if peer closed while we flushed */
            rv = APR_EOF;
        }
        fctx->fout_bytes_in_tls_bb = 0;
        apr_brigade_cleanup(fctx->fout_tls_bb);
    }
    return rv;
}

static apr_status_t fout_pass_all_to_net(
    tls_filter_ctx_t *fctx, int flush);

/* Forward declaration to allow calls from input filter before definition */
static apr_status_t fout_pass_rustls_to_tls(tls_filter_ctx_t *fctx);

static apr_status_t filter_abort(
    tls_filter_ctx_t *fctx)
{
    apr_status_t rv;

    if (fctx->cc->state != TLS_CONN_ST_DONE) {
        if (fctx->cc->state > TLS_CONN_ST_CLIENT_HELLO) {
            rustls_connection_send_close_notify(fctx->cc->rustls_connection);
            rv = fout_pass_all_to_net(fctx, 1);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c, "filter_abort, flushed output");
        }
        fctx->c->aborted = 1;
        fctx->cc->state = TLS_CONN_ST_DONE;
    }
    return APR_ECONNABORTED;
}

static apr_status_t filter_recv_client_hello(tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter, server=%s, recv client hello", fctx->cc->server->server_hostname);
    /* only for incoming connections */
    ap_assert(!fctx->cc->outgoing);

    if (rustls_connection_is_handshaking(fctx->cc->rustls_connection)) {
        apr_bucket_brigade *bb_tmp;

        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c, "filter_recv_client_hello: start");
        fctx->fin_tls_buffer_bb = apr_brigade_create(fctx->c->pool, fctx->c->bucket_alloc);
        do {
            if (rustls_connection_wants_read(fctx->cc->rustls_connection)) {
                rv = read_tls_to_rustls(fctx, fctx->fin_max_in_rustls, APR_BLOCK_READ);
                if (APR_SUCCESS != rv) {
                    if (fctx->cc->client_hello_seen) {
                        /* We got what we needed - client hello was seen.
                         * In blocking mode, we return SUCCESS since we achieved our goal. */
                        rv = APR_SUCCESS;
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
        APR_BRIGADE_CONCAT(fctx->fin_tls_bb, bb_tmp); /* all tls data from the client so far, reloaded */
        apr_brigade_cleanup(bb_tmp);
        rv = APR_SUCCESS;
    }

cleanup:
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c, "filter_recv_client_hello: done");
    return rv;
}

static apr_status_t filter_send_client_hello(tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter, server=%s, send client hello", fctx->cc->server->server_hostname);
    /* Only for outgoing connections */
    ap_assert(fctx->cc->outgoing);
    if (rustls_connection_is_handshaking(fctx->cc->rustls_connection)) {
        while (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
            /* write flushed, so it really gets out */
            rv = fout_pass_all_to_net(fctx, 1);
            if (APR_SUCCESS != rv) goto cleanup;
        }
    }

cleanup:
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

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter, server=%s, do handshake", fctx->cc->server->server_hostname);
    if (rustls_connection_is_handshaking(fctx->cc->rustls_connection)) {
        do {
            if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
                rv = fout_pass_all_to_net(fctx, 1);
                if (APR_SUCCESS != rv) goto cleanup;
            }
            else if (rustls_connection_wants_read(fctx->cc->rustls_connection)) {
                rv = read_tls_to_rustls(fctx, fctx->fin_max_in_rustls, APR_BLOCK_READ);
                if (APR_SUCCESS != rv) goto cleanup;
            }
        }
        while (rustls_connection_is_handshaking(fctx->cc->rustls_connection));

        /* rustls reports the TLS handshake to be done, when it *internally* has
         * processed everything into its buffers. Not when the buffers have been
         * send to the other side. */
        if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
            rv = fout_pass_all_to_net(fctx, 1);
            if (APR_SUCCESS != rv) goto cleanup;
        }
    }
cleanup:
    ap_log_error(APLOG_MARK, APLOG_TRACE2, rv, fctx->cc->server,
        "tls_filter, server=%s, handshake done", fctx->cc->server->server_hostname);
    if (APR_SUCCESS != rv) {
        if (fctx->cc->last_error_descr) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, APR_ECONNABORTED, fctx->c, APLOGNO(10354)
                "handshake failed: %s", fctx->cc->last_error_descr);
        }
    }
    return rv;
}

static apr_status_t progress_tls_atleast_to(tls_filter_ctx_t *fctx, tls_conn_state_t state)
{
    apr_status_t rv = APR_SUCCESS;

    /* handle termination immediately */
    if (state == TLS_CONN_ST_DONE) {
        rv = APR_ECONNABORTED;
        goto cleanup;
    }

    if (state > TLS_CONN_ST_CLIENT_HELLO
        && TLS_CONN_ST_CLIENT_HELLO == fctx->cc->state) {
        rv = tls_core_conn_init(fctx->c);
        if (APR_SUCCESS != rv) goto cleanup;

        if (fctx->cc->outgoing) {
            rv = filter_send_client_hello(fctx);
        }
        else {
            rv = filter_recv_client_hello(fctx);
        }
        if (APR_SUCCESS != rv) goto cleanup;
        fctx->cc->state = TLS_CONN_ST_HANDSHAKE;
    }

    if (state > TLS_CONN_ST_HANDSHAKE
        && TLS_CONN_ST_HANDSHAKE== fctx->cc->state) {
        rv = filter_do_handshake(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
        rv = tls_core_conn_post_handshake(fctx->c);
        if (APR_SUCCESS != rv) goto cleanup;
        fctx->cc->state = TLS_CONN_ST_TRAFFIC;
    }

    if (state < fctx->cc->state) {
        rv = APR_ECONNABORTED;
    }

cleanup:
    if (APR_SUCCESS != rv) {
        filter_abort(fctx); /* does change the state itself */
    }
    return rv;
}

/**
 * The connection filter converting TLS encrypted network data into plain, unencrypted
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

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter_conn_input, server=%s, mode=%d, block=%d, readbytes=%ld",
        fctx->cc->server->server_hostname, mode, block, (long)readbytes);

    rv = progress_tls_atleast_to(fctx, TLS_CONN_ST_TRAFFIC);
    if (APR_SUCCESS != rv) goto cleanup; /* this also leaves on APR_EAGAIN */

    if (!fctx->cc->rustls_connection) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

#if AP_MODULE_MAGIC_AT_LEAST(20200420, 1)
    ap_filter_reinstate_brigade(f, fctx->fin_plain_bb, NULL);
#endif

    if (AP_MODE_INIT == mode) {
        /* INIT is used to trigger the handshake, it does not return any traffic data. */
        goto cleanup;
    }

    /* If we have nothing buffered, try getting more input.
     * Use a simple loop similar to filter_recv_client_hello:
     * - In blocking mode: loop until we get plaintext data or encounter an error
     * - In non-blocking mode: make one attempt and return EAGAIN if no data available
     * 
     * a) try to read decrypted data from rustls (if we have data in rustls)
     * b) if nothing, check if rustls wants to read and read TLS bytes from network
     * c) after reading TLS, try reading plaintext from rustls again
     */
    while (APR_BRIGADE_EMPTY(fctx->fin_plain_bb)) {
        apr_size_t rlen = 0;
        apr_bucket *b;
        int tls_read_attempted = 0;

        /* If rustls has pending writes, flush them to the network first.
         * This avoids stalling when peer expects TLS records (websocket full-duplex). */
        if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
            rv = fout_pass_rustls_to_tls(fctx);
            if (APR_SUCCESS != rv) goto cleanup;
        }

        /* First attempt: try to read decrypted data from rustls.
         * In blocking mode, always try to read plaintext, even if fin_bytes_in_rustls == 0,
         * because rustls may process data asynchronously after process_new_packets.
         * In non-blocking mode, only try if we have data in rustls. */
        if (fctx->fin_data_pending || block == APR_BLOCK_READ) {
            in_buf_len = APR_BUCKET_BUFF_SIZE;
            in_buf = ap_calloc(in_buf_len, sizeof(char));
            rr = rustls_connection_read(fctx->cc->rustls_connection,
                (unsigned char*)in_buf, in_buf_len, &rlen);
            if (rr == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
                rr = RUSTLS_RESULT_OK;
                rlen = 0;
                fctx->fin_data_pending = FALSE;
            }
            if (rr != RUSTLS_RESULT_OK) goto cleanup;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                         "tls_filter_conn_input: got %ld plain bytes from rustls", (long)rlen);
            if (rlen > 0) {
                b = apr_bucket_heap_create(in_buf, rlen, free, fctx->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(fctx->fin_plain_bb, b);
                in_buf = NULL;
                break; /* Got data, exit loop */
            }
            else {
                free(in_buf);
                in_buf = NULL;
            }
        }

        /* Second attempt: read TLS data from network if rustls wants to read.
         * In blocking mode, always try reading if we don't have plaintext, to avoid
         * infinite loops. In blocking mode, we must read until we get plaintext or EOF. */
        if (rlen == 0 && APR_BRIGADE_EMPTY(fctx->fin_plain_bb)) {
            int should_read_tls = 0;
            if (rustls_connection_wants_read(fctx->cc->rustls_connection)) {
                should_read_tls = 1;
            }
            else if (block == APR_BLOCK_READ) {
                /* In blocking mode, always try reading if we don't have plaintext.
                 * This prevents infinite loops when rustls needs more data but
                 * wants_read is temporarily false. */
                should_read_tls = 1;
            }

            if (should_read_tls) {
                apr_size_t read_limit;
                /* Avoid blocking brigade length checks; they may stall the input filter */
                
                /* Limit the amount of data we read and pass to rustls at once to avoid
                 * overwhelming rustls. Read at most one TLS record at a time to ensure
                 * rustls can process it. */
                /* Prefer larger pulls in non-blocking to reduce idle gaps */
                if (block == APR_NONBLOCK_READ) {
                    read_limit = fctx->fin_max_in_rustls;
                }
                else {
                    read_limit = TLS_PREF_PLAIN_CHUNK_SIZE;
                    if (fctx->fin_max_in_rustls < read_limit) {
                        read_limit = fctx->fin_max_in_rustls;
                    }
                }
                /* Do not call apr_brigade_length() here to avoid blocking */
                rv = read_tls_to_rustls(fctx, read_limit, block);
                tls_read_attempted = 1;
                if (APR_SUCCESS != rv) {
                    if (APR_STATUS_IS_EAGAIN(rv)) {
                        /* On EAGAIN: non-blocking returns up; blocking always retry loop */
                        if (block == APR_NONBLOCK_READ) {
                            goto cleanup;
                        }
                        /* Blocking mode: keep trying (do not bubble EAGAIN upward) */
                        continue;
                    }
                    /* Other errors, propagate them */
                    goto cleanup;
                }

                /* After feeding TLS bytes, if rustls wants to write (e.g., ACKs), flush them. */
                if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
                    rv = fout_pass_rustls_to_tls(fctx);
                    if (APR_SUCCESS != rv) goto cleanup;
                }
                
                /* Check if we actually read any new data. If not, and we're in blocking mode,
                 * we might be stuck. Continue the loop to try reading plaintext again. */
                if (block == APR_BLOCK_READ && !fctx->fin_data_pending &&
                    APR_BRIGADE_EMPTY(fctx->fin_tls_bb)) {
                    /* No progress and no buffered TLS data: loop again and let network provide more */
                    continue;
                }

                /* After reading TLS data, always try reading plaintext from rustls.
                 * rustls_connection_process_new_packets may have processed data and
                 * made decrypted data available. We should always try to read it,
                 * even if fin_bytes_in_rustls didn't increase (e.g., if we processed
                 * data that was already buffered in rustls). */
                if (APR_BRIGADE_EMPTY(fctx->fin_plain_bb)) {
                    in_buf_len = APR_BUCKET_BUFF_SIZE;
                    in_buf = ap_calloc(in_buf_len, sizeof(char));
                    rr = rustls_connection_read(fctx->cc->rustls_connection,
                        (unsigned char*)in_buf, in_buf_len, &rlen);
                    if (rr == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
                        rr = RUSTLS_RESULT_OK;
                        rlen = 0;
                        fctx->fin_data_pending = FALSE;
                    }
                    if (rr != RUSTLS_RESULT_OK) goto cleanup;
                    if (rlen > 0) {
                        b = apr_bucket_heap_create(in_buf, rlen, free, fctx->c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(fctx->fin_plain_bb, b);
                        in_buf = NULL;
                        break; /* Got data, exit loop */
                    }
                    else {
                        free(in_buf);
                        in_buf = NULL;
                    }
                }
            }
        }

        /* If we still have nothing after one iteration:
         * - In non-blocking mode, return EAGAIN to let event loop call us again.
         * - In blocking mode, continue the loop (similar to filter_recv_client_hello). */
        if (APR_BRIGADE_EMPTY(fctx->fin_plain_bb)) {
            if (block == APR_NONBLOCK_READ) {
                rv = APR_EAGAIN;
                goto cleanup;
            }
            /* In blocking mode, if we just read TLS data but didn't get plaintext,
             * continue the loop to try reading plaintext again (rustls may need
             * more data to complete records) or read more TLS data if needed. */
            if (tls_read_attempted) {
                /* We read TLS data but didn't get plaintext. Continue the loop
                 * to try reading plaintext again (on next iteration, fin_bytes_in_rustls
                 * will be checked) or read more TLS data if wants_read is true. */
                continue;
            }
            /* In blocking mode, check if we have buffered TLS data to process */
            if (!APR_BRIGADE_EMPTY(fctx->fin_tls_bb)) {
                continue;
            }
            /* In blocking mode, continue the loop - read_tls_to_rustls will block if needed.
             * Similar to filter_recv_client_hello, we just loop until we get data. */
            continue;
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

    /* Note: We don't flush outgoing data from input filter to avoid conflicts
     * when rustls is processing incoming data. Outgoing data will be flushed
     * from the output filter (tls_filter_conn_output) when it's ready. */

cleanup:
    if (NULL != in_buf) free(in_buf);

    if (APLOGctrace3(fctx->c)) {
        tls_util_bb_log(fctx->c, APLOG_TRACE3, "tls_input, fctx->fin_plain_bb", fctx->fin_plain_bb);
        tls_util_bb_log(fctx->c, APLOG_TRACE3, "tls_input, bb", bb);
    }
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";

        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO(10355)
                     "tls_filter_conn_input: [%d] %s", (int)rr, err_descr);
    }
    else if (APR_STATUS_IS_EAGAIN(rv) || rv == APR_FROM_OS_ERROR(EAGAIN) || rv == APR_EAGAIN) {
        /* Coerce EAGAIN only for blocking callers; propagate for non-blocking */
        if (fctx->fin_block == APR_BLOCK_READ) {
            rv = APR_SUCCESS;
        } else {
            rv = APR_EAGAIN;
        }
    }
    else if (APR_SUCCESS != rv) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO(10356)
                     "tls_filter_conn_input");
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "tls_filter_conn_input: passed %ld bytes", (long)passed);
    }

#if AP_MODULE_MAGIC_AT_LEAST(20200420, 1)
    if (APR_SUCCESS == rv || APR_STATUS_IS_EAGAIN(rv)) {
        ap_filter_setaside_brigade(f, fctx->fin_plain_bb);
    }
#endif
    /* Final guard: coerce EAGAIN only for blocking callers */
    if (APR_STATUS_IS_EAGAIN(rv) || rv == APR_FROM_OS_ERROR(EAGAIN) || rv == APR_EAGAIN) {
        if (fctx->fin_block == APR_BLOCK_READ) {
            rv = APR_SUCCESS;
        } else {
            rv = APR_EAGAIN;
        }
    }
    return rv;
}

static rustls_io_result tls_write_callback(
    void *userdata, const unsigned char *buf, size_t n, size_t *out_n)
{
    tls_filter_ctx_t *fctx = userdata;
    apr_status_t rv;

    if ((apr_off_t)n + fctx->fout_bytes_in_tls_bb >= (apr_off_t)fctx->fout_auto_flush_size) {
        apr_bucket *b = apr_bucket_transient_create((const char*)buf, n, fctx->fout_tls_bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);
        fctx->fout_bytes_in_tls_bb += (apr_off_t)n;
        rv = fout_pass_tls_to_net(fctx);
        *out_n = n;
    }
    else {
        rv = apr_brigade_write(fctx->fout_tls_bb, NULL, NULL, (const char*)buf, n);
        if (APR_SUCCESS != rv) goto cleanup;
        fctx->fout_bytes_in_tls_bb += (apr_off_t)n;
        *out_n = n;
    }
cleanup:
    ap_log_error(APLOG_MARK, APLOG_TRACE5, rv, fctx->cc->server,
        "tls_write_callback: %ld bytes", (long)n);
    return APR_TO_OS_ERROR(rv);
}

static rustls_io_result tls_write_vectored_callback(
    void *userdata, const rustls_iovec *riov, size_t count, size_t *out_n)
{
    tls_filter_ctx_t *fctx = userdata;
    const struct iovec *iov = (const struct iovec*)riov;
    apr_status_t rv;
    size_t i, n = 0;
    apr_bucket *b;

    for (i = 0; i < count; ++i, ++iov) {
        b = apr_bucket_transient_create((const char*)iov->iov_base, iov->iov_len, fctx->fout_tls_bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);
        n += iov->iov_len;
    }
    fctx->fout_bytes_in_tls_bb += (apr_off_t)n;
    rv = fout_pass_tls_to_net(fctx);
    *out_n = n;
    ap_log_error(APLOG_MARK, APLOG_TRACE5, rv, fctx->cc->server,
        "tls_write_vectored_callback: %ld bytes in %d slices", (long)n, (int)count);
    return APR_TO_OS_ERROR(rv);
}

#define TLS_WRITE_VECTORED      1
/**
 * Read TLS encrypted data from <fctx->cc->rustls_connection> and pass it down
 * Apache's filter chain to the network.
 *
 * For now, we always FLUSH the data, since that is what we need during handshakes.
 */
static apr_status_t fout_pass_rustls_to_tls(tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    if (rustls_connection_wants_write(fctx->cc->rustls_connection)) {
        size_t dlen;
        int os_err;

        if (TLS_WRITE_VECTORED) {
            do {
                os_err = rustls_connection_write_tls_vectored(
                    fctx->cc->rustls_connection, tls_write_vectored_callback, fctx, &dlen);
                if (os_err) {
                    rv = APR_FROM_OS_ERROR(os_err);
                    goto cleanup;
                }
            }
            while (rustls_connection_wants_write(fctx->cc->rustls_connection));
        }
        else {
            do {
                os_err = rustls_connection_write_tls(
                    fctx->cc->rustls_connection, tls_write_callback, fctx, &dlen);
                if (os_err) {
                    rv = APR_FROM_OS_ERROR(os_err);
                    goto cleanup;
                }
            }
            while (rustls_connection_wants_write(fctx->cc->rustls_connection));
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, rv, fctx->c,
                "fout_pass_rustls_to_tls, %ld bytes ready for network", (long)fctx->fout_bytes_in_tls_bb);
            fctx->fout_bytes_in_rustls = 0;
        }
    }
cleanup:
    return rv;
}

static apr_status_t fout_pass_buf_to_rustls(
    tls_filter_ctx_t *fctx, const char *buf, apr_size_t len)
{
    apr_status_t rv = APR_SUCCESS;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_size_t written;

    while (len) {
        /* check if we will exceed the limit of data in rustls.
         * rustls does not guarantee that it will accept all data, so we
         * iterate and flush when needed. */
        if (fctx->fout_bytes_in_rustls + (apr_off_t)len > (apr_off_t)fctx->fout_max_in_rustls) {
            rv = fout_pass_rustls_to_tls(fctx);
            if (APR_SUCCESS != rv) goto cleanup;
        }

        rr = rustls_connection_write(fctx->cc->rustls_connection,
                                     (const unsigned char*)buf, len, &written);
        if (rr != RUSTLS_RESULT_OK) goto cleanup;
        ap_assert(written <= len);
        fctx->fout_bytes_in_rustls += (apr_off_t)written;
        buf += written;
        len -= written;
        if (written == 0) {
            rv = APR_EAGAIN;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, fctx->c, APLOGNO(10357)
                         "fout_pass_buf_to_rustls: not read by rustls at all");
            goto cleanup;
        }
    }
    /* Note: We don't call fout_pass_rustls_to_tls() here to avoid conflicts.
     * TLS data will be prepared and sent through fout_pass_all_to_tls() ->
     * fout_pass_rustls_to_tls() which is called from fout_pass_all_to_net()
     * at appropriate times. This ensures a single point of TLS data preparation
     * and avoids synchronization issues. */
cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";
        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO(10358)
                     "fout_pass_buf_to_tls to rustls: [%d] %s", (int)rr, err_descr);
    }
    return rv;
}

static apr_status_t fout_pass_all_to_tls(tls_filter_ctx_t *fctx)
{
    apr_status_t rv = APR_SUCCESS;

    if (fctx->fout_buf_plain_len) {
        rv = fout_pass_buf_to_rustls(fctx, fctx->fout_buf_plain, fctx->fout_buf_plain_len);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "fout_pass_all_to_tls: %ld plain bytes written to rustls",
                     (long)fctx->fout_buf_plain_len);
        if (APR_SUCCESS != rv) goto cleanup;
        fctx->fout_buf_plain_len = 0;
    }

    rv = fout_pass_rustls_to_tls(fctx);
cleanup:
    return rv;
}

static apr_status_t fout_pass_all_to_net(tls_filter_ctx_t *fctx, int flush)
{
    apr_status_t rv;

    rv = fout_pass_all_to_tls(fctx);
    if (APR_SUCCESS != rv) goto cleanup;
    if (flush) {
        apr_bucket *b = apr_bucket_flush_create(fctx->fout_tls_bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);
    }
    rv = fout_pass_tls_to_net(fctx);
cleanup:
    return rv;
}

static apr_status_t fout_add_bucket_to_plain(tls_filter_ctx_t *fctx, apr_bucket *b)
{
    const char *data;
    apr_size_t dlen, buf_remain;
    apr_status_t rv = APR_SUCCESS;

    ap_assert((apr_size_t)-1 != b->length);
    if (b->length == 0) {
        apr_bucket_delete(b);
        goto cleanup;
    }

    buf_remain = fctx->fout_buf_plain_size - fctx->fout_buf_plain_len;
    if (buf_remain == 0) {
        rv = fout_pass_all_to_tls(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
        buf_remain = fctx->fout_buf_plain_size - fctx->fout_buf_plain_len;
        ap_assert(buf_remain > 0);
    }
    if (b->length > buf_remain) {
        apr_bucket_split(b, buf_remain);
    }
    rv = apr_bucket_read(b, &data, &dlen, APR_BLOCK_READ);
    if (APR_SUCCESS != rv) goto cleanup;
    /*if (dlen > TLS_PREF_PLAIN_CHUNK_SIZE)*/
    ap_assert(dlen <= buf_remain);
    memcpy(fctx->fout_buf_plain + fctx->fout_buf_plain_len, data, dlen);
    fctx->fout_buf_plain_len += dlen;
    apr_bucket_delete(b);
cleanup:
    return rv;
}

static apr_status_t fout_add_bucket_to_tls(tls_filter_ctx_t *fctx, apr_bucket *b)
{
    apr_status_t rv;

    rv = fout_pass_all_to_tls(fctx);
    if (APR_SUCCESS != rv) goto cleanup;
    APR_BUCKET_REMOVE(b);
    APR_BRIGADE_INSERT_TAIL(fctx->fout_tls_bb, b);
    if (AP_BUCKET_IS_EOC(b)) {
        rustls_connection_send_close_notify(fctx->cc->rustls_connection);
        fctx->cc->state = TLS_CONN_ST_NOTIFIED;
        rv = fout_pass_rustls_to_tls(fctx);
        if (APR_SUCCESS != rv) goto cleanup;
    }
cleanup:
    return rv;
}

static apr_status_t fout_append_plain(tls_filter_ctx_t *fctx, apr_bucket *b)
{
    const char *data;
    apr_size_t dlen, buf_remain;
    rustls_result rr = RUSTLS_RESULT_OK;
    apr_status_t rv = APR_SUCCESS;
    const char *lbuf = NULL;
    int flush = 0;
    int flush_nonblock = 0;

    if (b) {
        /* if our plain buffer is full, now is a good time to flush it. */
        buf_remain = fctx->fout_buf_plain_size - fctx->fout_buf_plain_len;
        if (buf_remain == 0) {
            rv = fout_pass_all_to_tls(fctx);
            if (APR_SUCCESS != rv) goto cleanup;
            buf_remain = fctx->fout_buf_plain_size - fctx->fout_buf_plain_len;
            ap_assert(buf_remain > 0);
        }

        /* Resolve any indeterminate bucket to a "real" one by reading it. */
        if ((apr_size_t)-1 == b->length) {
            rv = apr_bucket_read(b, &data, &dlen, APR_BLOCK_READ);
            if (APR_STATUS_IS_EOF(rv)) {
                apr_bucket_delete(b);
                goto maybe_flush;
            }
            else if (APR_SUCCESS != rv) goto cleanup;
        }
        /* Now `b` is the bucket that we need to append and consume */
        if (APR_BUCKET_IS_METADATA(b)) {
            /* According to Apache filter documentation, metadata buckets (especially
             * FLUSH) must be passed down the chain. FLUSH buckets force filters to
             * write any data set aside. We need to ensure all buffered data is
             * sent before passing the metadata bucket. */
            /* Flush any buffered plain data before processing metadata bucket */
            if (fctx->fout_buf_plain_len > 0) {
                rv = fout_pass_all_to_tls(fctx);
                if (APR_SUCCESS != rv) goto cleanup;
            }
            /* outgoing buckets:
             *   [PLAINDATA META PLAINDATA META META]
             * need to become:
             *   [TLSDATA META TLSDATA META META]
             * because we need to send the meta buckets down the
             * network filters. */
            rv = fout_add_bucket_to_tls(fctx, b);
            flush = 1;
        }
        else if (b->length == 0) {
            apr_bucket_delete(b);
        }
        else if (b->length < 1024 || fctx->fout_buf_plain_len > 0) {
            /* we want to buffer small chunks to create larger TLS records and
             * not leak security relevant information. So, we buffer small
             * chunks and add (parts of) later, larger chunks if the plain
             * buffer contains data. */
            rv = fout_add_bucket_to_plain(fctx, b);
            if (APR_SUCCESS != rv) goto cleanup;
            /* For full duplex websocket connections, we need to send small chunks
             * promptly to avoid blocking read operations. However, we still want
             * to batch small chunks when possible for security (larger TLS records).
             * Strategy:
             * - If buffer is nearly full (>= 75%), flush with flush bucket
             * - Always flush small chunks without blocking flush bucket to ensure
             *   timely delivery for full duplex websocket connections.
             *   Using non-blocking flush avoids breaking TLS record synchronization
             *   while ensuring data is sent promptly. */
            if (fctx->fout_buf_plain_len >= fctx->fout_buf_plain_size * 3 / 4) {
                /* Buffer is nearly full, flush with flush bucket */
                flush = 1;
            }
            else {
                /* Always flush small chunks without blocking flush bucket to ensure
                 * timely delivery for full duplex websocket connections.
                 * This is critical to avoid hanging on the first small chunk. */
                flush_nonblock = 1;
            }
        }
        else {
            /* we have a large chunk and our plain buffer is empty, write it
             * directly into rustls. */
#define TLS_FILE_CHUNK_SIZE  4 * TLS_PREF_PLAIN_CHUNK_SIZE
            if (b->length > TLS_FILE_CHUNK_SIZE) {
                apr_bucket_split(b, TLS_FILE_CHUNK_SIZE);
            }

            if (APR_BUCKET_IS_FILE(b)
                && (lbuf = malloc(b->length))) {
                /* A file bucket is a most wondrous thing. Since the dawn of time,
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
                 * rustls will try to collect max length traffic data into one TLS
                 * message, but it can only work with what we gave it. If we give it buffers
                 * that fit what it wants to assemble already, its work is much easier.
                 *
                 * We can read file buckets in large chunks than APR_BUCKET_BUFF_SIZE,
                 * with a bit of knowledge about how they work.
                 */
                apr_bucket_file *f = (apr_bucket_file *)b->data;
                apr_file_t *fd = f->fd;
                apr_off_t offset = b->start;

                dlen = b->length;
                rv = apr_file_seek(fd, APR_SET, &offset);
                if (APR_SUCCESS != rv) goto cleanup;
                rv = apr_file_read(fd, (void*)lbuf, &dlen);
                if (APR_SUCCESS != rv && !APR_STATUS_IS_EOF(rv)) goto cleanup;
                rv = fout_pass_buf_to_rustls(fctx, lbuf, dlen);
                if (APR_SUCCESS != rv) goto cleanup;
                /* For large chunks, send TLS data without blocking flush
                 * to avoid blocking read operations in full duplex mode. */
                flush_nonblock = 1;
                apr_bucket_delete(b);
            }
            else {
                rv = apr_bucket_read(b, &data, &dlen, APR_BLOCK_READ);
                if (APR_SUCCESS != rv) goto cleanup;
                rv = fout_pass_buf_to_rustls(fctx, data, dlen);
                if (APR_SUCCESS != rv) goto cleanup;
                /* For large chunks, send TLS data without blocking flush
                 * to avoid blocking read operations in full duplex mode. */
                flush_nonblock = 1;
                apr_bucket_delete(b);
            }
        }
    }

maybe_flush:
    if (flush_nonblock) {
        /* Send without blocking flush bucket for full duplex websocket */
        rv = fout_pass_all_to_net(fctx, 0);
        if (APR_SUCCESS != rv) goto cleanup;
    }
    else if (flush) {
        rv = fout_pass_all_to_net(fctx, 1);
        if (APR_SUCCESS != rv) goto cleanup;
    }

cleanup:
    if (lbuf) free((void*)lbuf);
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";
        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO(10359)
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
    int eos_seen = 0;

    /* According to Apache filter documentation, output filters should not
     * pass empty brigades down the chain. Return early if empty. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    if (f->c->aborted) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, fctx->c,
            "tls_filter_conn_output: aborted conn");
        apr_brigade_cleanup(bb);
        rv = APR_ECONNABORTED; goto  cleanup;
    }

    rv = progress_tls_atleast_to(fctx, TLS_CONN_ST_TRAFFIC);
    if (APR_SUCCESS != rv) goto cleanup; /* this also leaves on APR_EAGAIN */

    if (fctx->cc->state == TLS_CONN_ST_DONE) {
        /* have done everything, just pass through */
        ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, fctx->c,
            "tls_filter_conn_output: tls session is already done");
        rv = ap_pass_brigade(f->next, bb);
        goto cleanup;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, fctx->cc->server,
        "tls_filter_conn_output, server=%s", fctx->cc->server->server_hostname);
    if (APLOGctrace5(fctx->c)) {
        tls_util_bb_log(fctx->c, APLOG_TRACE5, "filter_conn_output", bb);
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);

        /* According to Apache filter documentation, after seeing EOS,
         * all subsequent buckets should be ignored. */
        if (eos_seen) {
            apr_bucket_delete(b);
            continue;
        }

        /* Check for EOS bucket */
        if (APR_BUCKET_IS_EOS(b)) {
            eos_seen = 1;
        }

        rv = fout_append_plain(fctx, b);
        if (APR_SUCCESS != rv) goto cleanup;
    }

    /* After consuming all plain buckets, push any pending TLS data to the network.
     * Use non-blocking flush semantics to avoid stalling full-duplex streams. */
    rv = fout_pass_all_to_net(fctx, 0);
    if (APR_SUCCESS != rv) goto cleanup;

    if (APLOGctrace5(fctx->c)) {
        tls_util_bb_log(fctx->c, APLOG_TRACE5, "filter_conn_output, processed plain", bb);
        tls_util_bb_log(fctx->c, APLOG_TRACE5, "filter_conn_output, tls", fctx->fout_tls_bb);
    }

cleanup:
    if (rr != RUSTLS_RESULT_OK) {
        const char *err_descr = "";
        rv = tls_core_error(fctx->c, rr, &err_descr);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, fctx->c, APLOGNO(10360)
                     "tls_filter_conn_output: [%d] %s", (int)rr, err_descr);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, fctx->c,
                     "tls_filter_conn_output: done");
    }
    return rv;
}

int tls_filter_pre_conn_init(conn_rec *c)
{
    tls_conf_conn_t *cc;
    tls_filter_ctx_t *fctx;

    if (OK != tls_core_pre_conn_init(c)) {
        return DECLINED;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server,
        "tls_filter_pre_conn_init on %s", c->base_server->server_hostname);

    cc = tls_conf_conn_get(c);
    ap_assert(cc);

    fctx = apr_pcalloc(c->pool, sizeof(*fctx));
    fctx->c = c;
    fctx->cc = cc;
    cc->filter_ctx = fctx;

    /* a bit tricky: registering out filters returns the ap_filter_t*
     * that it created for it. The ->next field points always
     * to the filter "below" our filter. That will be other registered
     * filters and last, but not least, the network filter on the socket.
     *
     * Therefore, when we need to read/write TLS data during handshake, we can
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
    fctx->fout_buf_plain_size = APR_BUCKET_BUFF_SIZE;
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
    fctx->fin_max_in_rustls = 4 * TLS_REC_MAX_SIZE;
    fctx->fout_max_in_rustls = 4 * TLS_PREF_PLAIN_CHUNK_SIZE;
    fctx->fout_auto_flush_size = 2 * TLS_REC_MAX_SIZE;

    return OK;
}

void tls_filter_conn_init(conn_rec *c)
{
    tls_conf_conn_t *cc = tls_conf_conn_get(c);

    if (cc && cc->filter_ctx && !cc->outgoing) {
        /* We are one in a row of hooks that - possibly - want to process this
         * connection, the (HTTP) protocol handlers among them.
         *
         * For incoming connections, we need to select the protocol to use NOW,
         * so that the later protocol handlers do the right thing.
         * Send an INIT down the input filter chain to trigger the TLS handshake,
         * which will select a protocol via ALPN. */
        apr_bucket_brigade* temp;

        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, c->base_server,
            "tls_filter_conn_init on %s, triggering handshake", c->base_server->server_hostname);
        temp = apr_brigade_create(c->pool, c->bucket_alloc);
        ap_get_brigade(c->input_filters, temp, AP_MODE_INIT, APR_BLOCK_READ, 0);
        apr_brigade_cleanup(temp);
    }
}

void tls_filter_register(
    apr_pool_t *pool)
{
    (void)pool;
    ap_register_input_filter(TLS_FILTER_RAW, filter_conn_input,  NULL, AP_FTYPE_CONNECTION + 5);
    ap_register_output_filter(TLS_FILTER_RAW, filter_conn_output, NULL, AP_FTYPE_CONNECTION + 5);
}
