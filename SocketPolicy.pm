package SocketPolicy;

# Copyright (c) 2010-2012 Alexander Farber. All rights reserved.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings FATAL => 'all';
use APR::Const qw(SO_NONBLOCK);
use APR::Socket();
use Apache2::ServerRec();
use Apache2::Connection();
use Apache2::Const qw(OK DECLINED);

use constant POLICY => 
qq{<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM
"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<site-control permitted-cross-domain-policies="master-only"/>
<allow-access-from domain="*" to-ports="8080"/>
</cross-domain-policy>
\0};

sub handler {
        my $conn   = shift;
        my $socket = $conn->client_socket;
        my $offset = 0;

        # ignore requests to port 80
        return DECLINED if $conn->base_server->port != 843;
        # set the socket to blocking mode
        $socket->opt_set(SO_NONBLOCK, 0);

        do {
                my $nbytes = $socket->send(substr(POLICY, $offset), length(POLICY) - $offset);
                # client connection closed or interrupted
                return DECLINED unless $nbytes;
                $offset += $nbytes;
        } while ($offset < length(POLICY));

        my $slog = $conn->base_server->log;
        $slog->notice('served socket policy to ', $conn->remote_ip);
        return OK;
}

1;

