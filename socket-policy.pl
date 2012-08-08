#!/usr/bin/perl -wT

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
use IO::Poll qw(POLLIN POLLOUT POLLERR POLLHUP);
use IO::Socket;

use constant TIMEOUT	 => 60 * 1000;
use constant MAX_IDLE    => 5 * 60;
use constant MAX_CLIENTS => 100;
use constant POLICY      => 
qq{<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM
"http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<site-control permitted-cross-domain-policies="master-only"/>
<allow-access-from domain="*" to-ports="8080"/>
</cross-domain-policy>
\0};

my $quit = 0;
my %clients = ();

$ENV{PATH} = '';
$SIG{PIPE} = $SIG{ALRM} = $SIG{HUP} = 'IGNORE';
$SIG{TERM} = $SIG{INT}  = sub { $quit = 1; };

my $socket = IO::Socket::INET->new(
        Proto     => 'tcp',
        LocalPort => 843,
        Listen    => SOMAXCONN,
        ReuseAddr => 1,
);
die "Can not create listening TCP socket: $!\n"
        unless defined $socket;
# make the listening socket nonblocking to prevent DOS attacks
die "Can not make listening TCP socket non-blocking: $!\n"
        unless defined $socket->blocking(0);

my $poll = IO::Poll->new();
$poll->mask($socket => POLLIN);

LOOP:
while (not $quit) {
        if ($poll->poll(TIMEOUT) < 0) {
                print STDERR "poll failed: $!\n";
                next LOOP;
        }

        if ($poll->events($socket) & POLLIN) {
                add_client($socket);
                next LOOP;
        }

        my $now = time();
        for my $client (values %clients) {
                my $fh = $client->{FH};

                my $idle = $now - $client->{JOINED};
                if ($idle > MAX_IDLE) {
                        remove_client($fh);
                        next LOOP;
                }

                my $mask = $poll->events($fh);
                if ($mask & (POLLERR|POLLHUP)) {
                        remove_client($fh);
                        next LOOP;
                } elsif ($mask & POLLOUT) {
                        unless (write_policy($fh)) {
                                remove_client($fh);
                                next LOOP;
                        }
                }
        }
}

sub add_client {
	my $socket      = shift;
	my ($fh, $addr) = $socket->accept();

	unless ($fh) {
		print STDERR "accept failed: $!\n";
		return;
	}

	unless (defined $fh->blocking(0)) { 
		print STDERR "Can not make socket non-blocking: $!\n";
		return;
	}

        my ($port, $packed_ip) = sockaddr_in($addr);
        my $ip = inet_ntoa($packed_ip);
        printf STDERR "Adding client %d - %s\n", $fh->fileno(), $ip;
                        
	$clients{$fh->fileno()} = {
                FH      => $fh,
                IP      => $ip,
                JOINED  => time(),
                WRITTEN => 0,
        };

        $poll->mask($fh => POLLOUT|POLLERR|POLLHUP);
	# limit reached - stop accepting new clients
	$poll->remove($socket) if keys %clients >= MAX_CLIENTS;
}

sub remove_client {
	my $fh = shift;

        printf STDERR "Removing client %d\n", $fh->fileno();

	$poll->remove($fh);
	delete $clients{$fh->fileno()};
        $fh->close();

	# start accepting new clients again
	$poll->mask($socket => POLLIN);
}

sub write_policy {
	my $fh     = shift;
        my $client = $clients{$fh->fileno()};
	my $nbytes = $fh->syswrite(POLICY, length(POLICY) - $client->{WRITTEN}, $client->{WRITTEN});

        # connection closed (0) or interrupted (undef)
        return 0 unless $nbytes;

        $client->{WRITTEN} += $nbytes;
        # complete POLICY written, disconnect the client
        return 0 if $client->{WRITTEN} >= length(POLICY);

        # try writing the rest later
	return 1;
}

