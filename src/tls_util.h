/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_util_h
#define tls_util_h

#define TLS_DIM(a)      (sizeof(a)/sizeof(a[0]))


typedef struct tls_data_t tls_data_t;
struct tls_data_t {
    const unsigned char* data;
    apr_size_t len;
};

tls_data_t tls_data_from_str(const char *s);
tls_data_t *tls_data_copy(apr_pool_t *p, const tls_data_t *d);
tls_data_t tls_data_assign_copy(apr_pool_t *p, const tls_data_t *d);
const char *tls_data_to_str(apr_pool_t *p, const tls_data_t *d);

/**
 * Return != 0 if fpath is a 'real' file.
 */
int tls_util_is_file(apr_pool_t *p, const char *fpath);

/**
 * Inspect a 'rustls_result', retrieve the error description for it and
 * return the apr_status_t to use as our error status.
 */
apr_status_t tls_util_rustls_error(apr_pool_t *p, rustls_result rr, const char **perr_descr);

/**
 *  Load up to `max_len` bytes into a buffer allocated from the pool.
 *  @return ARP_SUCCESS on successful load.
 *          APR_EINVAL when the file was not a regular file or is too large.
 */
apr_status_t tls_util_file_load(
    apr_pool_t *p, const char *fpath, size_t min_len, size_t max_len, tls_data_t *data);

/**
 * Return != 0 iff the array of apr_uint16_t contains value n.
 */
int tls_util_array_uint16_contains(const apr_array_header_t* a, apr_uint16_t n);

/**
 * Remove all apr_uint16_t in `others` from array `from`.
 * Returns the new array or, if no overlap was found, the `from` array unchanged.
 */
const apr_array_header_t *tls_util_array_uint16_remove(
    apr_pool_t *pool, const apr_array_header_t* from, const apr_array_header_t* others);

/**
 * Transfer up to <length> bytes from <src> to <dest>, including all
 * encountered meta data buckets. The transfered buckets/data are
 * removed from <src>.
 * Return the actual byte count transfered in <pnout>.
 */
apr_status_t tls_util_brigade_transfer(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout);

/**
 * Copy up to <length> bytes from <src> to <dest>, including all
 * encountered meta data buckets. <src> remains semantically unchaanged,
 * meaning there might have been buckets split or changed while reading
 * their content.
 * Return the actual byte count copied in <pnout>.
 */
apr_status_t tls_util_brigade_copy(
    apr_bucket_brigade *dest, apr_bucket_brigade *src, apr_off_t length,
    apr_off_t *pnout);

/**
 * Get a line of max `length` bytes from `src` into `dest`.
 * Return the number of bytes transferred in `pnout`.
 */
apr_status_t tls_util_brigade_split_line(
    apr_bucket_brigade *dest, apr_bucket_brigade *src,
    apr_read_type_e block, apr_off_t length,
    apr_off_t *pnout);

/**
 * Return != 0 iff the given <name> matches the configured 'ServerName'
 * or one of the 'ServerAlias' name of <s>, including wildcard patterns
 * as understood by ap_strcasecmp_match().
 */
int tls_util_name_matches_server(const char *name, server_rec *s);


/**
 * Print a bucket's meta data (type and length) to the buffer.
 * @return number of characters printed
 */
apr_size_t tls_util_bucket_print(char *buffer, apr_size_t bmax,
                                 apr_bucket *b, const char *sep);

/**
 * Prints the brigade bucket types and lengths into the given buffer
 * up to bmax.
 * @return number of characters printed
 */
apr_size_t tls_util_bb_print(char *buffer, apr_size_t bmax,
                             const char *tag, const char *sep,
                             apr_bucket_brigade *bb);
/**
 * Logs the bucket brigade (which bucket types with what length)
 * to the log at the given level.
 * @param c the connection to log for
 * @param sid the stream identifier this brigade belongs to
 * @param level the log level (as in APLOG_*)
 * @param tag a short message text about the context
 * @param bb the brigade to log
 */
#define tls_util_bb_log(c, level, tag, bb) \
do { \
    char buffer[4 * 1024]; \
    const char *line = "(null)"; \
    apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]); \
    len = tls_util_bb_print(buffer, bmax, (tag), "", (bb)); \
    ap_log_cerror(APLOG_MARK, level, 0, (c), "bb_dump(%ld): %s", \
        ((c)->master? (c)->master->id : (c)->id), (len? buffer : line)); \
} while(0)



#endif /* tls_util_h */