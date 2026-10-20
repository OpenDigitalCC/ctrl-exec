#!/usr/bin/perl
# t/agent-accept.t
#
# The serve loop's handling of a failed $server->accept. Before 0.12.4 the loop
# asked the LISTENING socket for its peerhost before looking at $!, which always
# sets ENOTCONN, so every failed accept - a port scanner's bad handshake, or the
# EINTR a SIGHUP reload produces - was classified fatal and the agent exited its
# serve loop (with no respawn under OpenRC). The decision now lives in a pure
# function fed the errno captured immediately after accept returned.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use Errno qw(EINTR EAGAIN ECONNABORTED ECONNRESET EPIPE EMFILE EBADF EINVAL ENOTSOCK ENOTCONN);
use IO::Socket::IP qw();

use Exec::Agent::Server qw();

my $act = \&Exec::Agent::Server::accept_failure_action;

# Interrupted / transient: go straight back to accept.
is $act->(EINTR,        ''), 'retry', 'EINTR (SIGHUP reload during accept) -> retry, not fatal';
is $act->(EAGAIN,       ''), 'retry', 'EAGAIN -> retry';
is $act->(ECONNABORTED, ''), 'retry', 'ECONNABORTED -> retry';

# Listener itself is unusable: only these end the loop.
is $act->(EBADF,    ''), 'fatal', 'EBADF -> fatal';
is $act->(EINVAL,   ''), 'fatal', 'EINVAL -> fatal';
is $act->(ENOTSOCK, ''), 'fatal', 'ENOTSOCK -> fatal';

# A peer that failed the TLS handshake, however errno looks at that moment.
is $act->(0,          'SSL accept attempt failed error:0A000418:SSL routines::tlsv1 alert unknown ca'),
   'handshake', 'SSL error with errno 0 -> handshake';
is $act->(ECONNRESET, ''), 'handshake', 'peer reset mid-handshake -> handshake, not fatal';
is $act->(EPIPE,      ''), 'handshake', 'EPIPE -> handshake';
is $act->(EMFILE,     ''), 'handshake', 'EMFILE (transient fd pressure) -> keep serving';
is $act->(ENOTCONN,   ''), 'handshake', 'ENOTCONN (the old false-fatal errno) is not fatal';
is $act->(undef, undef),   'handshake', 'undefined inputs -> handshake (never fatal by accident)';

# Document the trap the loop must avoid: peerhost on a LISTENING socket sets
# errno, so errno has to be read before anything else is called.
{
    my $srv = IO::Socket::IP->new(LocalHost => '127.0.0.1', LocalPort => 0, Listen => 1)
        or plan skip_all => "cannot open a loopback listener: $@";
    $! = 0;
    my $ph = $srv->peerhost;
    ok !defined $ph, 'peerhost on a listening socket is undef';
    is $!+0, ENOTCONN, 'and it sets errno to ENOTCONN - why errno must be captured first';
}

done_testing;
