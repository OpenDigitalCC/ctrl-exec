#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Pairing qw();

# Load the dispatcher CLI helpers (suppress main()), same pattern as
# dispatcher-cli.t, so we can unit-test the timeout validation directly.
{
    no warnings 'redefine';
    local *main::main = sub {};
    do "$Bin/../bin/ctrl-exec-dispatcher";
    die "Could not load ctrl-exec-dispatcher: $@" if $@;
}

# --- _pairing_timeout: resolution + validation -----------------------------

subtest '_pairing_timeout: default, config, and flag precedence' => sub {
    is main::_pairing_timeout({}, {}),                         600, 'defaults to 600';
    is main::_pairing_timeout({ timeout => 300 }, {}),         300, '--timeout is used';
    is main::_pairing_timeout({}, { pairing_timeout => 120 }), 120, 'config used when no flag';
    is main::_pairing_timeout({ timeout => 60 }, { pairing_timeout => 500 }),
                                                                60,  'flag overrides config';
    is main::_pairing_timeout({ timeout => 600 }, {}),         600, '600 (max) accepted';
    is main::_pairing_timeout({ timeout => 1 }, {}),           1,   '1 (min) accepted';
};

subtest '_pairing_timeout: rejects out-of-range and non-integer' => sub {
    eval { main::_pairing_timeout({ timeout => 601 }, {}) };
    like $@, qr/between 1 and 600/, 'rejects > 600 (cannot extend the window)';
    eval { main::_pairing_timeout({ timeout => 0 }, {}) };
    like $@, qr/between 1 and 600/, 'rejects 0';
    eval { main::_pairing_timeout({ timeout => 'soon' }, {}) };
    like $@, qr/integer/, 'rejects a non-integer';
};

# --- run_pairing_mode honours the absolute timeout and RETURNS (not exit) ---

subtest 'run_pairing_mode: auto-stops at the deadline' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir  = tempdir(CLEANUP => 1);
    my $cert = "$dir/d.crt";
    my $key  = "$dir/d.key";
    plan skip_all => 'openssl cert generation failed'
        unless system('openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', $key, '-out', $cert, '-days', '1', '-nodes',
            '-subj', '/CN=test-dispatcher', qw(-quiet)) == 0;

    my ($reason, $elapsed);
    {
        # run_pairing_mode prints status lines; keep TAP output clean.
        local *STDOUT;
        open STDOUT, '>', "$dir/out" or die "redirect: $!";
        my $t0 = time;
        $reason = eval {
            Exec::Pairing::run_pairing_mode(
                port        => 39444,
                cert        => $cert,
                key         => $key,
                pairing_dir => "$dir/pairing",
                timeout     => 1,
                log_fn      => sub { },
            );
        };
        $elapsed = time - $t0;
    }

    if (!defined $reason) {
        plan skip_all => "could not bind pairing listener: $@"
            if $@ && $@ =~ /Cannot start pairing server/;
        die $@ if $@;
    }

    is   $reason,  'timeout', 'returned the timeout reason instead of exiting';
    cmp_ok $elapsed, '<', 10,  'stopped promptly at the ~1s deadline';
};

done_testing;
