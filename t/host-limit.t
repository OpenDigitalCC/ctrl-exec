#!/usr/bin/perl
# t/host-limit.t
#
# Unit tests for the max_hosts guard in Exec::Engine.
# Verifies that dispatch_all, ping_all, and capabilities_all croak when
# the host list exceeds the configured limit, and accept a list at the limit.
#
# No network connections are made - the croak fires before any fork.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Engine qw();

# Suppress log output during tests
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# Minimal config hashref - only needs to exist, no real cert paths required
# since croak fires before any SSL connection is attempted.
my $config = {
    cert     => '/nonexistent/dispatcher.crt',
    key      => '/nonexistent/dispatcher.key',
    ca       => '/nonexistent/ca.crt',
    cert_days => 365,
};

# Helper: build a list of N fake hostnames
sub host_list {
    my ($n) = @_;
    return [ map { "host-$_.example.com" } 1..$n ];
}

# ---------------------------------------------------------------------------
# dispatch_all
# ---------------------------------------------------------------------------

{
    eval {
        Exec::Engine::dispatch_all(
            hosts     => host_list(501),
            script    => 'check-disk',
            config    => $config,
            max_hosts => 500,
        );
    };
    like $@, qr/too many hosts/, 'dispatch_all: croaks at 501 with max_hosts=500';
}

{
    eval {
        Exec::Engine::dispatch_all(
            hosts     => host_list(501),
            script    => 'check-disk',
            config    => $config,
        );
    };
    like $@, qr/too many hosts \(max 500\)/, 'dispatch_all: default max is 500';
}

{
    eval {
        Exec::Engine::dispatch_all(
            hosts     => host_list(10),
            script    => 'check-disk',
            config    => $config,
            max_hosts => 5,
        );
    };
    like $@, qr/too many hosts \(max 5\)/, 'dispatch_all: custom max_hosts=5 croaks at 10';
}

{
    # At the limit: croak must not fire. We expect a fork/connection failure
    # (no real agent), not a "too many hosts" croak.
    eval {
        Exec::Engine::dispatch_all(
            hosts     => host_list(5),
            script    => 'check-disk',
            config    => $config,
            max_hosts => 5,
        );
    };
    unlike $@, qr/too many hosts/, 'dispatch_all: no croak at exactly the limit';
}

{
    # Zero hosts: empty result, no croak
    my $results = eval {
        Exec::Engine::dispatch_all(
            hosts     => [],
            script    => 'check-disk',
            config    => $config,
        );
    };
    unlike $@, qr/too many hosts/, 'dispatch_all: zero hosts does not croak';
    is ref $results, 'ARRAY', 'dispatch_all: zero hosts returns arrayref';
    is scalar @$results, 0,   'dispatch_all: zero hosts returns empty result';
}

# ---------------------------------------------------------------------------
# ping_all
# ---------------------------------------------------------------------------

{
    eval {
        Exec::Engine::ping_all(
            hosts     => host_list(501),
            config    => $config,
            max_hosts => 500,
        );
    };
    like $@, qr/too many hosts/, 'ping_all: croaks at 501 with max_hosts=500';
}

{
    eval {
        Exec::Engine::ping_all(
            hosts  => host_list(501),
            config => $config,
        );
    };
    like $@, qr/too many hosts \(max 500\)/, 'ping_all: default max is 500';
}

{
    eval {
        Exec::Engine::ping_all(
            hosts     => host_list(10),
            config    => $config,
            max_hosts => 5,
        );
    };
    like $@, qr/too many hosts \(max 5\)/, 'ping_all: custom max_hosts=5 croaks at 10';
}

{
    eval {
        Exec::Engine::ping_all(
            hosts     => host_list(5),
            config    => $config,
            max_hosts => 5,
        );
    };
    unlike $@, qr/too many hosts/, 'ping_all: no croak at exactly the limit';
}

{
    my $results = eval {
        Exec::Engine::ping_all(
            hosts  => [],
            config => $config,
        );
    };
    unlike $@, qr/too many hosts/, 'ping_all: zero hosts does not croak';
    is ref $results, 'ARRAY', 'ping_all: zero hosts returns arrayref';
    is scalar @$results, 0,   'ping_all: zero hosts returns empty result';
}

# ---------------------------------------------------------------------------
# capabilities_all
# ---------------------------------------------------------------------------

{
    eval {
        Exec::Engine::capabilities_all(
            hosts     => host_list(501),
            config    => $config,
            max_hosts => 500,
        );
    };
    like $@, qr/too many hosts/, 'capabilities_all: croaks at 501 with max_hosts=500';
}

{
    eval {
        Exec::Engine::capabilities_all(
            hosts  => host_list(501),
            config => $config,
        );
    };
    like $@, qr/too many hosts \(max 500\)/, 'capabilities_all: default max is 500';
}

{
    eval {
        Exec::Engine::capabilities_all(
            hosts     => host_list(10),
            config    => $config,
            max_hosts => 5,
        );
    };
    like $@, qr/too many hosts \(max 5\)/, 'capabilities_all: custom max_hosts=5 croaks at 10';
}

{
    eval {
        Exec::Engine::capabilities_all(
            hosts     => host_list(5),
            config    => $config,
            max_hosts => 5,
        );
    };
    unlike $@, qr/too many hosts/, 'capabilities_all: no croak at exactly the limit';
}

{
    my $results = eval {
        Exec::Engine::capabilities_all(
            hosts  => [],
            config => $config,
        );
    };
    unlike $@, qr/too many hosts/, 'capabilities_all: zero hosts does not croak';
    is ref $results, 'ARRAY', 'capabilities_all: zero hosts returns arrayref';
    is scalar @$results, 0,   'capabilities_all: zero hosts returns empty result';
}

done_testing;
