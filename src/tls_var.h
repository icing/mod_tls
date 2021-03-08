/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_var_h
#define tls_var_h

/**
 * Callback for installation in Apache's 'ssl_var_lookup' hook to provide
 * SSL related variable lookups to other modules.
 */
const char *tls_var_lookup(
    apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *name);

/**
 * A request is ready for processing, add some TLS flavours (if this is on a TLS connection)
 */
int tls_var_request_fixup(request_rec *r);

#endif /* tls_var_h */