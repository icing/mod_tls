/* Copyright 2021, ISRG (https://www.abetterinternet.org)
 *
 * This software is licensed as described in the file LICENSE, which
 * you should have received as part of this distribution.
 *
 */

#include <assert.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include "tls_defs.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_filter.h"

int tls_filter_pre_connection(conn_rec *c, void *csd)
{
    tls_conf_conn_t *cc = NULL;

    (void)csd; /* mpm specific socket data, not used */
    /* are we on a primary connection and configured for it?
     * Then attach a tls_conf_conn_t to it. */
    if (c->master) return DECLINED;
    cc = tls_conf_conn_get(c);
    if (cc && cc->disabled) return DECLINED;
    return tls_core_conn_init(c);
}

