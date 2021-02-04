/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_util_h
#define tls_util_h

/* Return != 0 if fpath is a 'real' file */
int tls_util_is_file(apr_pool_t *p, const char *fpath);

#endif /* tls_util_h */