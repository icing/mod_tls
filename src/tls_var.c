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

#include "tls_defs.h"
#include "tls_conf.h"
#include "tls_core.h"
#include "tls_var.h"


extern module AP_MODULE_DECLARE_DATA tls_module;
APLOG_USE_MODULE(tls);

const char *tls_var_lookup(
    apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *name)
{
    const char *val = NULL;
    tls_conf_conn_t *cc;

    ap_assert(p);
    ap_assert(name);
    s = s? s : (c? c->base_server : (r? r->server : NULL));
    c = c? c : (r? r->connection : NULL);

    if (c) {
        cc = tls_conf_conn_get(c);
        if (strncasecmp(name, "SSL_", 4)) goto cleanup; /* not for us */
        name += 4;
        if (0 == strcasecmp(name, "PROTOCOL")) {
            val = "TLSv1.2"; /* TODO: how to ask rustls for this? */
        }
        else if (0 == strcasecmp(name, "CIPHER")) {
            val = "unknown"; /* TODO: how to ask rustls for this? */
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c, "tls lookup of var '%s' -> '%s'", name, val);
    }
    else {
        /* TODO: do we want to hand out any global vars? rustsls versions mabye? */
    }

cleanup:
    return val;
}
