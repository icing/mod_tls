/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_filter_h
#define tls_filter_h

#define TLS_FILTER_RAW    "TLS raw"

void tls_filter_register(apr_pool_t *pool);

int tls_filter_conn_init(conn_rec *c);

int tls_filter_pre_connection(conn_rec *c, void *csd);

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
#define TLS_PREF_TLS_WRITE_SIZE   (TLS_PREF_WRITE_SIZE + 64)

#endif /* tls_filter_h */