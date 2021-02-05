/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */
#ifndef tls_filter_h
#define tls_filter_h

int tls_filter_pre_connection(conn_rec *c, void *csd);

#endif /* tls_filter_h */