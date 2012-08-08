/*
 * Copyright (c) 2010-2012 Alexander Farber. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
1) Install by running: apxs -a -i -c mod_socket_policy.c
2) Add to httpd.conf:
    Listen 843
    <VirtualHost _default_:843>
    </VirtualHost>
3) Run: semanage port -a -t http_port_t -p tcp 843
4) Run: apachectl restart
*/

#include <httpd.h>
#include <http_protocol.h>
#include <http_connection.h>
#include <http_config.h>
#include <http_log.h>

#define POLICY "<?xml version=\"1.0\"?>\n" \
               "<!DOCTYPE cross-domain-policy SYSTEM\n" \
               "\"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd\">\n" \
               "<cross-domain-policy>\n" \
               "<site-control permitted-cross-domain-policies=\"master-only\"/>\n" \
               "<allow-access-from domain=\"*\" to-ports=\"8080\"/>\n" \
               "</cross-domain-policy>\n"

static int socket_policy_handler(conn_rec *conn) {
        apr_bucket_brigade *bb;
        apr_bucket *b;
        apr_status_t rv;

        /* ignore requests to port 80 */
        if (conn->base_server->port != 843)
                return DECLINED;

        bb = apr_brigade_create(conn->pool, conn->bucket_alloc);
        /* sizeof(POLICY) is the length of the string + terminating zero */
        b = apr_bucket_immortal_create(POLICY, sizeof(POLICY), bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        b = apr_bucket_eos_create(bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
        rv = ap_pass_brigade(conn->output_filters, bb);
        if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, conn->base_server, "output error");
                return DECLINED;
        }

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, conn->base_server,
            "served socket policy to %s", conn->remote_ip);
        return OK;
}

static void register_hooks(apr_pool_t *pool) {
        ap_hook_process_connection(socket_policy_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA socket_policy_module = {
        STANDARD20_MODULE_STUFF,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        register_hooks
};

