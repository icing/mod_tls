/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_filter_h
#define tls_filter_h

#define TLS_FILTER_RAW    "TLS raw"

typedef struct tls_filter_ctx_t tls_filter_ctx_t;

struct tls_filter_ctx_t {
    conn_rec *c;                         /* connection this context is for */
    tls_conf_conn_t *cc;                 /* tls module configuration of connection */

    ap_filter_t *fin_ctx;                /* Apache's entry into the input filter chain */
    apr_bucket_brigade *fin_tls_bb;      /* TLS encrypted, incoming network data */
    apr_bucket_brigade *fin_tls_buffer_bb; /* TLS encrypted, incoming network data buffering */
    apr_bucket_brigade *fin_plain_bb;    /* decrypted, incoming traffic data */
    apr_read_type_e fin_block;           /* Do we block on input reads or not? */

    ap_filter_t *fout_ctx;               /* Apache's entry into the output filter chain */
    apr_bucket_brigade *fout_tls_bb;     /* TLS encrypted, outgoing network data */

    apr_off_t fin_rustls_bytes;          /* # of input TLS bytes in rustls_session */
    apr_off_t fout_rustls_bytes;         /* # of output plain bytes in rustls_session */
    apr_off_t max_rustls_out;            /* how much plain bytes we like to give to rustls */
    apr_off_t max_rustls_tls_in;         /* how much tls we like to read into rustls */
};

/**
 * Register the in-/output filters for converting TLS to application data and vice versa.
 */
void tls_filter_register(apr_pool_t *pool);

/**
 * Initialize all internal data structure needed for handling TLS in-/output
 * on a given connection.
 */
int tls_filter_conn_init(conn_rec *c);

/*
 * <https://tools.ietf.org/html/rfc8449> says:
 * "For large data transfers, small record sizes can materially affect performance."
 * and
 * "For TLS 1.2 and earlier, that limit is 2^14 octets. TLS 1.3 uses a limit of
 *  2^14+1 octets."
 * Maybe future TLS versions will raise that value, but for now these limits stand.
 * Given the choice, we would like rustls to provide with traffic data in those chunks.
 */
#define TLS_PREF_WRITE_SIZE       (16384)

/*
 * When retrieving TLS chunks for rustls, or providing it a buffer
 * to pass out TLS chunks (which are then bucketed and written to the
 * network filters), we ideally would do that in multiples of TLS
 * messages sizes.
 * That would be TLS_PREF_WRITE_SIZE + TLS Message Overhead, such as
 * MAC and padding. But these vary with protocol and ciphers chosen, so
 * we defined something which should be "large enough", but not overly
 * so.
 */
#define TLS_PREF_TLS_WRITE_SIZE   (TLS_PREF_WRITE_SIZE + 1024)

#define TLS_MAX_BUCKET_SIZE       (4 * TLS_PREF_TLS_WRITE_SIZE)

#endif /* tls_filter_h */