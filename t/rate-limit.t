#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::RateLimit qw();

# Suppress log output during tests
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# --- record_connection: initialises missing entry ---
{
    my %state;
    Exec::RateLimit::record_connection('1.2.3.4', \%state);
    ok(exists $state{'1.2.3.4'}, 'record_connection creates entry');
    is(scalar @{ $state{'1.2.3.4'}{connections} }, 1, 'record_connection adds one timestamp');
}

# --- record_failure: initialises missing entry ---
{
    my %state;
    Exec::RateLimit::record_failure('1.2.3.4', \%state);
    ok(exists $state{'1.2.3.4'}, 'record_failure creates entry');
    is(scalar @{ $state{'1.2.3.4'}{failures} }, 1, 'record_failure adds one timestamp');
}

# --- fresh IP is allowed ---
{
    my %state;
    is(Exec::RateLimit::check('10.0.0.1', \%state), 0, 'fresh IP is allowed');
}

# --- 9 connections within 60s: no volume block ---
{
    my %state;
    my $now = time();
    $state{'10.0.0.2'} = {
        connections => [ map { $now - 5 } 1..9 ],
        failures    => [],
    };
    is(Exec::RateLimit::check('10.0.0.2', \%state), 0, '9 connections does not trigger volume block');
}

# --- 10 connections within 60s: volume block triggered ---
{
    my %state;
    my $now = time();
    $state{'10.0.0.3'} = {
        connections => [ map { $now - 5 } 1..10 ],
        failures    => [],
    };
    my $log_calls = 0;
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub { $log_calls++ };
        is(Exec::RateLimit::check('10.0.0.3', \%state), 1, '10 connections triggers volume block');
    }
    ok($log_calls > 0, 'volume block logs once');
    ok(exists $state{'10.0.0.3'}{blocked_until}, 'blocked_until set after volume block');
    ok(abs($state{'10.0.0.3'}{blocked_until} - (time() + 300)) <= 2,
        'volume block duration is ~300s');
}

# --- connections older than 60s not counted toward volume ---
{
    my %state;
    my $now = time();
    # 10 connections all older than 60s but within 600s prune window
    $state{'10.0.0.4'} = {
        connections => [ map { $now - 120 } 1..10 ],
        failures    => [],
    };
    is(Exec::RateLimit::check('10.0.0.4', \%state), 0,
        'connections older than 60s not counted toward volume');
}

# --- active volume block returns 1 ---
{
    my %state;
    $state{'10.0.0.5'} = {
        connections   => [],
        failures      => [],
        blocked_until => time() + 200,
    };
    is(Exec::RateLimit::check('10.0.0.5', \%state), 1, 'active block returns 1');
}

# --- active block: no additional log on repeat call ---
{
    my %state;
    $state{'10.0.0.6'} = {
        connections   => [],
        failures      => [],
        blocked_until => time() + 200,
    };
    my $log_calls = 0;
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub { $log_calls++ };
        Exec::RateLimit::check('10.0.0.6', \%state);
        Exec::RateLimit::check('10.0.0.6', \%state);
    }
    is($log_calls, 0, 'no log on repeat check for already-blocked IP');
}

# --- expired block clears entry and returns 0 ---
{
    my %state;
    $state{'10.0.0.7'} = {
        connections   => [ time() - 10 ],
        failures      => [ time() - 10 ],
        blocked_until => time() - 1,
    };
    is(Exec::RateLimit::check('10.0.0.7', \%state), 0, 'expired block returns 0');
    ok(!exists $state{'10.0.0.7'}, 'expired block clears entire entry');
}

# --- 2 failures within 600s: no probe block ---
{
    my %state;
    my $now = time();
    $state{'10.0.0.8'} = {
        connections => [],
        failures    => [ map { $now - 60 } 1..2 ],
    };
    is(Exec::RateLimit::check('10.0.0.8', \%state), 0, '2 failures does not trigger probe block');
}

# --- 3 failures within 600s: probe block triggered ---
{
    my %state;
    my $now = time();
    $state{'10.0.0.9'} = {
        connections => [],
        failures    => [ map { $now - 60 } 1..3 ],
    };
    my $log_calls = 0;
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub { $log_calls++ };
        is(Exec::RateLimit::check('10.0.0.9', \%state), 1, '3 failures triggers probe block');
    }
    ok($log_calls > 0, 'probe block logs once');
    ok(abs($state{'10.0.0.9'}{blocked_until} - (time() + 3600)) <= 2,
        'probe block duration is ~3600s');
}

# --- failures older than 600s pruned and not counted ---
{
    my %state;
    my $now = time();
    $state{'10.0.1.0'} = {
        connections => [],
        failures    => [ map { $now - 700 } 1..3 ],
    };
    is(Exec::RateLimit::check('10.0.1.0', \%state), 0,
        'failures older than 600s are pruned and not counted');
}

# --- volume and failure counters are independent ---
{
    my %state;
    my $now = time();

    # Record a volume block
    $state{'10.0.1.1'} = {
        connections => [ map { $now - 5 } 1..10 ],
        failures    => [],
    };
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub {};
        Exec::RateLimit::check('10.0.1.1', \%state);
    }
    ok(exists $state{'10.0.1.1'}{blocked_until}, 'volume block set');

    # record_failure still works under a volume block
    Exec::RateLimit::record_failure('10.0.1.1', \%state);
    ok(@{ $state{'10.0.1.1'}{failures} } == 1, 'record_failure works under volume block');

    # Separately: probe block does not prevent record_connection
    my %state2;
    $state2{'10.0.1.2'} = {
        connections => [],
        failures    => [ map { $now - 60 } 1..3 ],
    };
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub {};
        Exec::RateLimit::check('10.0.1.2', \%state2);
    }
    ok(exists $state2{'10.0.1.2'}{blocked_until}, 'probe block set');
    Exec::RateLimit::record_connection('10.0.1.2', \%state2);
    ok(@{ $state2{'10.0.1.2'}{connections} } >= 1, 'record_connection works under probe block');
}

# --- eviction at 1000 entries ---
{
    my %state;
    my $now = time();

    # Fill with 999 entries all blocked until now+100 (higher blocked_until)
    for my $i (1..999) {
        $state{"192.168.0.$i"} = {
            connections   => [],
            failures      => [],
            blocked_until => $now + 100,
        };
    }

    # Add one entry with a lower blocked_until (now+10) - this is the minimum
    # and must be the one the sort-ascending eviction targets
    $state{'172.16.0.1'} = {
        connections   => [],
        failures      => [],
        blocked_until => $now + 10,
    };

    # %state now has 1000 entries. check() for a new IP triggers eviction
    # (>= MAX_ENTRIES) and must remove the entry with the lowest blocked_until,
    # which is 172.16.0.1 (now+10 < now+100).

    my $log_calls = 0;
    my $evict_logged = 0;
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub {
            my ($level, $fields) = @_;
            $evict_logged++ if ($fields->{ACTION} // '') eq 'rate-evict';
        };
        Exec::RateLimit::check('172.16.0.2', \%state);
    }

    is($evict_logged, 1, 'eviction logged when at 1000 entries');
    ok(!exists $state{'172.16.0.1'}, 'entry with lowest blocked_until evicted');
    ok(scalar keys %state <= 1000, 'state does not exceed 1000 entries after eviction');
}

# --- eviction bulk-reclaims entries whose block has expired (PERF-001) ---
# The single-pass eviction must drop EVERY expired-block entry in one go, not
# just one, so eviction stops re-running on every subsequent connection.
{
    my %state;
    my $now = time();

    # 600 entries whose block expired in the past + 400 still actively blocked.
    for my $i (1..600) {
        $state{"10.9.0.$i"} = { connections => [], failures => [],
                                blocked_until => $now - 50 };   # expired
    }
    for my $i (1..400) {
        $state{"10.8.0.$i"} = { connections => [], failures => [],
                                blocked_until => $now + 500 };  # active
    }
    # 1000 entries -> a new IP triggers the reclaim sweep.
    {
        no warnings 'redefine';
        local *Exec::Log::log_action = sub {};
        Exec::RateLimit::check('10.7.0.1', \%state);
    }

    my $expired_left = grep { /^10\.9\.0\./ } keys %state;
    is($expired_left, 0, 'all 600 expired-block entries reclaimed in one pass');
    ok(scalar keys %state < 1000,
        'table dropped well below capacity, so eviction will not re-run next call');
    # The actively-blocked entries must survive.
    ok(exists $state{'10.8.0.1'}, 'actively-blocked entry not evicted');
}

done_testing();
