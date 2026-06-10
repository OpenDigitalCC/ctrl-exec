#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Pairing   qw();
use Exec::RateLimit qw();

# Suppress log output during tests (Exec::RateLimit::check logs on block).
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub {};
}

# --- build_rate_config: config parsing ---
{
    is_deeply(Exec::Pairing::build_rate_config(),   {}, 'undef config yields defaults (empty hashref)');
    is_deeply(Exec::Pairing::build_rate_config({}), {}, 'empty config yields defaults (empty hashref)');

    is_deeply(
        Exec::Pairing::build_rate_config({ pairing_rate_limit_disable => 1 }),
        { disabled => 1 },
        'disable=1 sets disabled',
    );
    is_deeply(
        Exec::Pairing::build_rate_config({ pairing_rate_limit_disable => 'yes' }),
        { disabled => 1 },
        'disable=yes sets disabled',
    );
    is_deeply(
        Exec::Pairing::build_rate_config({ pairing_rate_limit_disable => 0 }),
        {},
        'disable=0 leaves defaults',
    );

    is_deeply(
        Exec::Pairing::build_rate_config({ pairing_rate_limit_volume => '10/60/300' }),
        { volume_limit => 10, volume_window => 60, volume_block => 300 },
        'valid volume spec parsed to integer fields',
    );
}

# --- build_rate_config: malformed volume falls back to defaults ---
{
    is_deeply(
        Exec::Pairing::build_rate_config({ pairing_rate_limit_volume => 'abc' }),
        {},
        'non-numeric volume spec ignored',
    );
    is_deeply(
        Exec::Pairing::build_rate_config({ pairing_rate_limit_volume => '10/60' }),
        {},
        'incomplete volume spec (no block) ignored',
    );
}

# --- volume limiting: blocks an IP at the configured limit ---
{
    my %state;
    my $rl = Exec::Pairing::build_rate_config({ pairing_rate_limit_volume => '3/60/300' });

    Exec::RateLimit::record_connection('10.0.0.1', \%state, $rl) for 1 .. 2;
    is(Exec::RateLimit::check('10.0.0.1', \%state, $rl), 0,
        '2 connections under the limit of 3 are allowed');

    Exec::RateLimit::record_connection('10.0.0.1', \%state, $rl);
    is(Exec::RateLimit::check('10.0.0.1', \%state, $rl), 1,
        '3rd connection reaches the volume limit and is blocked');
}

# --- per-IP isolation: one blocked IP does not affect another ---
{
    my %state;
    my $rl = Exec::Pairing::build_rate_config({ pairing_rate_limit_volume => '3/60/300' });

    Exec::RateLimit::record_connection('10.0.0.2', \%state, $rl) for 1 .. 3;
    is(Exec::RateLimit::check('10.0.0.2', \%state, $rl), 1, 'first IP blocked at limit');
    is(Exec::RateLimit::check('10.0.0.3', \%state, $rl), 0, 'second IP unaffected');
}

# --- disabled: never blocks regardless of volume ---
{
    my %state;
    my $rl = Exec::Pairing::build_rate_config({
        pairing_rate_limit_disable => 1,
        pairing_rate_limit_volume  => '1/60/300',
    });

    Exec::RateLimit::record_connection('10.0.0.4', \%state, $rl) for 1 .. 5;
    is(Exec::RateLimit::check('10.0.0.4', \%state, $rl), 0,
        'rate limiting disabled: no block even past the limit');
}

done_testing;
