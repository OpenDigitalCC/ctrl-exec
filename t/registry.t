#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Registry qw();

my $dir = tempdir(CLEANUP => 1);

# --- register_agent ---

{
    eval { Exec::Registry::register_agent(registry_dir => $dir) };
    like $@, qr/hostname required/, 'register_agent: dies without hostname';
}

{
    Exec::Registry::register_agent(
        hostname     => 'host-a',
        ip           => '10.0.0.1',
        paired       => '2026-03-05T12:00:00Z',
        expiry       => 'Jun  7 13:00:00 2028 GMT',
        reqid        => 'aabbccdd',
        registry_dir => $dir,
    );
    ok -f "$dir/host-a.json", 'register_agent: creates JSON file';
}

{
    # Re-register same host - should overwrite
    Exec::Registry::register_agent(
        hostname     => 'host-a',
        ip           => '10.0.0.2',
        paired       => '2026-03-05T13:00:00Z',
        expiry       => 'Jun  7 13:00:00 2029 GMT',
        reqid        => 'eeff0011',
        registry_dir => $dir,
    );

    my $agent = Exec::Registry::get_agent(
        hostname     => 'host-a',
        registry_dir => $dir,
    );
    is $agent->{ip},     '10.0.0.2',              'register_agent: overwrites existing entry';
    is $agent->{expiry}, 'Jun  7 13:00:00 2029 GMT', 'register_agent: updates expiry on overwrite';
}

# --- update_expiry ---

{
    eval { Exec::Registry::update_expiry(registry_dir => $dir) };
    like $@, qr/hostname required/, 'update_expiry: dies without hostname';

    eval { Exec::Registry::update_expiry(hostname => 'host-a', registry_dir => $dir) };
    like $@, qr/expiry required/, 'update_expiry: dies without expiry';
}

{
    # host-a currently has ip 10.0.0.2, reqid eeff0011 from the re-register above.
    Exec::Registry::update_expiry(
        hostname     => 'host-a',
        expiry       => 'Jun  7 13:00:00 2030 GMT',
        registry_dir => $dir,
    );

    my $agent = Exec::Registry::get_agent(
        hostname     => 'host-a',
        registry_dir => $dir,
    );
    is $agent->{expiry}, 'Jun  7 13:00:00 2030 GMT', 'update_expiry: updates expiry';
    is $agent->{ip},     '10.0.0.2',  'update_expiry: preserves ip';
    is $agent->{reqid},  'eeff0011',  'update_expiry: preserves other fields';
}

# --- get_agent ---

{
    eval { Exec::Registry::get_agent(registry_dir => $dir) };
    like $@, qr/hostname required/, 'get_agent: dies without hostname';
}

{
    my $agent = Exec::Registry::get_agent(
        hostname     => 'host-a',
        registry_dir => $dir,
    );
    ok defined $agent,               'get_agent: returns record for known host';
    is $agent->{hostname}, 'host-a', 'get_agent: hostname field';
    is $agent->{reqid}, 'eeff0011',  'get_agent: reqid field';
}

{
    my $agent = Exec::Registry::get_agent(
        hostname     => 'does-not-exist',
        registry_dir => $dir,
    );
    ok !defined $agent, 'get_agent: returns undef for unknown host';
}

# --- list_agents ---

{
    # Add more agents
    for my $h (qw(host-b host-c)) {
        Exec::Registry::register_agent(
            hostname     => $h,
            ip           => '10.0.0.5',
            paired       => '2026-03-05T14:00:00Z',
            expiry       => 'Jun  7 2028',
            reqid        => 'deadbeef',
            registry_dir => $dir,
        );
    }

    my $agents = Exec::Registry::list_agents(registry_dir => $dir);
    is scalar @$agents, 3, 'list_agents: returns all registered agents';

    # Should be sorted by hostname
    is $agents->[0]{hostname}, 'host-a', 'list_agents: sorted alphabetically (first)';
    is $agents->[1]{hostname}, 'host-b', 'list_agents: sorted alphabetically (second)';
    is $agents->[2]{hostname}, 'host-c', 'list_agents: sorted alphabetically (third)';
}

{
    my $empty_dir = tempdir(CLEANUP => 1);
    my $agents = Exec::Registry::list_agents(registry_dir => $empty_dir);
    is_deeply $agents, [], 'list_agents: empty list for empty dir';
}

{
    my $no_dir = tempdir(CLEANUP => 1) . '/nonexistent';
    my $agents = Exec::Registry::list_agents(registry_dir => $no_dir);
    is_deeply $agents, [], 'list_agents: empty list when dir does not exist';
}

# --- list_hostnames ---

{
    my $hosts = Exec::Registry::list_hostnames(registry_dir => $dir);
    is scalar @$hosts, 3,        'list_hostnames: returns correct count';
    is $hosts->[0], 'host-a',    'list_hostnames: first hostname';
    is $hosts->[2], 'host-c',    'list_hostnames: last hostname';
    ok !ref($hosts->[0]),        'list_hostnames: returns plain strings not hashrefs';
}

# --- record completeness ---

{
    my $agent = Exec::Registry::get_agent(
        hostname     => 'host-b',
        registry_dir => $dir,
    );
    ok exists $agent->{hostname}, 'record: hostname field present';
    ok exists $agent->{ip},       'record: ip field present';
    ok exists $agent->{paired},   'record: paired field present';
    ok exists $agent->{expiry},   'record: expiry field present';
    ok exists $agent->{reqid},    'record: reqid field present';
}

# --- remove_agent ---

{
    eval { Exec::Registry::remove_agent(registry_dir => $dir) };
    like $@, qr/hostname required/, 'remove_agent: dies without hostname';
}

{
    eval { Exec::Registry::remove_agent(
        hostname     => 'does-not-exist',
        registry_dir => $dir,
    ) };
    like $@, qr/No registry entry/, 'remove_agent: dies for unknown host';
}

{
    # Register a host to remove
    Exec::Registry::register_agent(
        hostname     => 'host-to-remove',
        ip           => '10.0.0.99',
        paired       => '2026-03-05T15:00:00Z',
        expiry       => 'Jun  7 13:00:00 2027 GMT',
        reqid        => 'deadbeef',
        registry_dir => $dir,
    );

    my $record = Exec::Registry::remove_agent(
        hostname     => 'host-to-remove',
        registry_dir => $dir,
    );

    ok !-f "$dir/host-to-remove.json", 'remove_agent: registry file deleted';
    is $record->{hostname}, 'host-to-remove', 'remove_agent: returns deleted record';
    is $record->{expiry}, 'Jun  7 13:00:00 2027 GMT', 'remove_agent: record includes expiry';
}

{
    # Confirm removed agent no longer appears in list
    my $agents = Exec::Registry::list_agents(registry_dir => $dir);
    my @found = grep { $_->{hostname} eq 'host-to-remove' } @$agents;
    is scalar @found, 0, 'remove_agent: agent no longer in list_agents';
}

{
    # Confirm get_agent returns undef after removal
    my $agent = Exec::Registry::get_agent(
        hostname     => 'host-to-remove',
        registry_dir => $dir,
    );
    ok !defined $agent, 'remove_agent: get_agent returns undef after removal';
}

done_testing;
