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

# --- lookup_by storage + resolve_host ---

{
    my $rdir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        hostname     => 'lb-default',
        ip           => '10.1.0.1',
        registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'lb-default', registry_dir => $rdir)->{lookup_by},
       'hostname', 'register_agent: lookup_by defaults to hostname';

    Exec::Registry::register_agent(
        hostname     => 'lb-ip',
        ip           => '10.1.0.2',
        lookup_by    => 'ip',
        registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'lb-ip', registry_dir => $rdir)->{lookup_by},
       'ip', 'register_agent: stores explicit lookup_by=ip';

    Exec::Registry::register_agent(
        hostname     => 'lb-bogus',
        ip           => '10.1.0.3',
        lookup_by    => 'bogus',
        registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'lb-bogus', registry_dir => $rdir)->{lookup_by},
       'hostname', 'register_agent: invalid lookup_by normalises to hostname';

    is Exec::Registry::resolve_host(hostname => 'lb-ip', registry_dir => $rdir),
       '10.1.0.2', 'resolve_host: lookup_by=ip resolves to stored ip';
    is Exec::Registry::resolve_host(hostname => 'lb-default', registry_dir => $rdir),
       'lb-default', 'resolve_host: lookup_by=hostname resolves to hostname';
    is Exec::Registry::resolve_host(hostname => 'not-registered', registry_dir => $rdir),
       'not-registered', 'resolve_host: unregistered name passes through unchanged';

    Exec::Registry::register_agent(
        hostname     => 'lb-ip-empty',
        ip           => '',
        lookup_by    => 'ip',
        registry_dir => $rdir,
    );
    is Exec::Registry::resolve_host(hostname => 'lb-ip-empty', registry_dir => $rdir),
       'lb-ip-empty', 'resolve_host: lookup_by=ip with empty ip falls back to hostname';

    eval { Exec::Registry::resolve_host(registry_dir => $rdir) };
    like $@, qr/hostname required/, 'resolve_host: dies without hostname';
}

# --- port storage + resolve_target ---

{
    my $rdir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        hostname => 'p-default', ip => '10.2.0.1', registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'p-default', registry_dir => $rdir)->{port},
       7443, 'register_agent: port defaults to 7443';

    Exec::Registry::register_agent(
        hostname => 'p-custom', ip => '10.2.0.2', port => 7450, registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'p-custom', registry_dir => $rdir)->{port},
       7450, 'register_agent: stores explicit port';

    Exec::Registry::register_agent(
        hostname => 'p-bad', ip => '10.2.0.3', port => 'nope', registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'p-bad', registry_dir => $rdir)->{port},
       7443, 'register_agent: invalid port normalises to 7443';

    Exec::Registry::register_agent(
        hostname => 'p-range', ip => '10.2.0.4', port => 99999, registry_dir => $rdir,
    );
    is Exec::Registry::get_agent(hostname => 'p-range', registry_dir => $rdir)->{port},
       7443, 'register_agent: out-of-range port normalises to 7443';

    # resolve_target: default port -> bare address
    is Exec::Registry::resolve_target(hostname => 'p-default', registry_dir => $rdir),
       'p-default', 'resolve_target: default port yields bare hostname';

    # non-default port -> address:port
    is Exec::Registry::resolve_target(hostname => 'p-custom', registry_dir => $rdir),
       'p-custom:7450', 'resolve_target: non-default port appended';

    # lookup_by=ip + non-default port -> ip:port
    Exec::Registry::register_agent(
        hostname => 'p-ip', ip => '10.2.0.9', port => 7460,
        lookup_by => 'ip', registry_dir => $rdir,
    );
    is Exec::Registry::resolve_target(hostname => 'p-ip', registry_dir => $rdir),
       '10.2.0.9:7460', 'resolve_target: lookup_by=ip with non-default port -> ip:port';

    is Exec::Registry::resolve_target(hostname => 'not-registered', registry_dir => $rdir),
       'not-registered', 'resolve_target: unregistered name passes through';

    eval { Exec::Registry::resolve_target(registry_dir => $rdir) };
    like $@, qr/hostname required/, 'resolve_target: dies without hostname';
}

# --- _valid_agent_name ---

{
    ok  Exec::Registry::_valid_agent_name('web-01'),       'valid: simple name';
    ok  Exec::Registry::_valid_agent_name('db.example.com'),'valid: FQDN with dots';
    ok  Exec::Registry::_valid_agent_name('a_b-1'),         'valid: underscore and hyphen';
    ok !Exec::Registry::_valid_agent_name('../etc'),        'invalid: path traversal';
    ok !Exec::Registry::_valid_agent_name('a/b'),           'invalid: slash';
    ok !Exec::Registry::_valid_agent_name('.hidden'),       'invalid: leading dot';
    ok !Exec::Registry::_valid_agent_name(''),              'invalid: empty';
}

# --- edit_agent: field edits and rename ---

{
    my $rdir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        hostname => 'edit-me', ip => '10.3.0.1', reqid => 'cafe1234',
        dispatcher_serial => 'abc', registry_dir => $rdir,
    );

    eval { Exec::Registry::edit_agent(hostname => 'nope', ip => '1.1.1.1', registry_dir => $rdir) };
    like $@, qr/No registry entry/, 'edit_agent: dies for unknown agent';

    # in-place field edits preserve untouched fields (incl. serial)
    my $rec = Exec::Registry::edit_agent(
        hostname => 'edit-me', ip => '10.3.0.99', port => 7470,
        lookup_by => 'ip', registry_dir => $rdir,
    );
    is $rec->{ip},        '10.3.0.99', 'edit_agent: updates ip';
    is $rec->{port},      7470,        'edit_agent: updates port';
    is $rec->{lookup_by}, 'ip',        'edit_agent: updates lookup_by';
    is $rec->{reqid},     'cafe1234',  'edit_agent: preserves reqid';
    is $rec->{dispatcher_serial}, 'abc', 'edit_agent: preserves serial fields';

    # rename moves the record and updates the hostname field
    my $renamed = Exec::Registry::edit_agent(
        hostname => 'edit-me', new_name => 'renamed-host', registry_dir => $rdir,
    );
    is $renamed->{hostname}, 'renamed-host', 'edit_agent: rename updates hostname';
    is $renamed->{ip},       '10.3.0.99',    'edit_agent: rename preserves fields';
    ok !-f "$rdir/edit-me.json",      'edit_agent: old registry file removed';
    ok  -f "$rdir/renamed-host.json", 'edit_agent: new registry file created';
    ok !defined Exec::Registry::get_agent(hostname => 'edit-me', registry_dir => $rdir),
        'edit_agent: old name no longer resolves';

    # rename collision is refused
    Exec::Registry::register_agent(hostname => 'occupied', ip => '10.3.0.5', registry_dir => $rdir);
    eval { Exec::Registry::edit_agent(
        hostname => 'renamed-host', new_name => 'occupied', registry_dir => $rdir) };
    like $@, qr/already exists/, 'edit_agent: refuses rename onto existing agent';

    # invalid rename target is refused
    eval { Exec::Registry::edit_agent(
        hostname => 'renamed-host', new_name => '../evil', registry_dir => $rdir) };
    like $@, qr/invalid agent name/, 'edit_agent: refuses invalid rename target';
}

# --- tags: storage, update_agent_tags, filter helpers ---

{
    my $rdir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        hostname => 'tag-default', ip => '10.4.0.1', registry_dir => $rdir,
    );
    is_deeply Exec::Registry::get_agent(hostname => 'tag-default', registry_dir => $rdir)->{tags},
        {}, 'register_agent: tags default to empty hash';

    Exec::Registry::register_agent(
        hostname => 'tag-set', ip => '10.4.0.2',
        tags => { env => 'production', role => 'db' }, registry_dir => $rdir,
    );
    is_deeply Exec::Registry::get_agent(hostname => 'tag-set', registry_dir => $rdir)->{tags},
        { env => 'production', role => 'db' }, 'register_agent: stores provided tags';

    is Exec::Registry::update_agent_tags(
        hostname => 'tag-default', tags => { env => 'staging' }, registry_dir => $rdir), 1,
        'update_agent_tags: returns 1 when updated';
    is_deeply Exec::Registry::get_agent(hostname => 'tag-default', registry_dir => $rdir)->{tags},
        { env => 'staging' }, 'update_agent_tags: caches new tags';

    is Exec::Registry::update_agent_tags(
        hostname => 'not-registered', tags => { a => 'b' }, registry_dir => $rdir), 0,
        'update_agent_tags: no-op (0) for unregistered agent';
}

# --- parse_tag_filter ---

{
    is_deeply Exec::Registry::parse_tag_filter('env=production'),
        { env => 'production' }, 'parse_tag_filter: single pair';
    is_deeply Exec::Registry::parse_tag_filter('env=production,role=db'),
        { env => 'production', role => 'db' }, 'parse_tag_filter: multiple ANDed';
    is_deeply Exec::Registry::parse_tag_filter('env='),
        { env => '' }, 'parse_tag_filter: empty value allowed';

    eval { Exec::Registry::parse_tag_filter('noequals') };
    like $@, qr/invalid tag filter/, 'parse_tag_filter: rejects entry without =';
    eval { Exec::Registry::parse_tag_filter('') };
    like $@, qr/empty tag filter/, 'parse_tag_filter: rejects empty filter';
}

# --- tags_match ---

{
    my $tags = { env => 'production', role => 'db' };
    ok  Exec::Registry::tags_match($tags, { env => 'production' }),
        'tags_match: single key matches';
    ok  Exec::Registry::tags_match($tags, { env => 'production', role => 'db' }),
        'tags_match: all keys match (AND)';
    ok !Exec::Registry::tags_match($tags, { env => 'staging' }),
        'tags_match: wrong value does not match';
    ok !Exec::Registry::tags_match($tags, { zone => 'eu' }),
        'tags_match: missing key does not match';
    ok !Exec::Registry::tags_match({}, { env => 'production' }),
        'tags_match: empty tags never match a non-empty filter';
}

done_testing;
