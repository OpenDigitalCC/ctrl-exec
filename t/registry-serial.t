#!/usr/bin/perl
# t/registry-serial.t
#
# Unit tests for serial tracking fields in Exec::Registry.
#
# Covers register_agent (serial fields written and defaulted) and
# update_agent_serial_status (merge semantics, field isolation, atomicity).
#
# All tests use a tempdir injected via the `registry_dir` parameter.
# No dependency on /var/lib/ctrl-exec or any running process.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use JSON qw(decode_json encode_json);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Registry qw();

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or die "Cannot write $path: $!";
    print $fh $content;
    close $fh;
}

sub read_record {
    my ($dir, $hostname) = @_;
    my $path = "$dir/$hostname.json";
    open my $fh, '<', $path or die "Cannot read $path: $!";
    local $/;
    return decode_json(<$fh>);
}

# ---------------------------------------------------------------------------
# register_agent: serial fields
# ---------------------------------------------------------------------------

subtest 'register_agent: serial fields written when provided' => sub {
    my $dir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        registry_dir       => $dir,
        hostname           => 'agent-serial-01',
        ip                 => '192.168.1.10',
        reqid              => 'aabbccdd',
        dispatcher_serial  => 'deadbeef01234567',
        serial_status      => 'current',
        serial_confirmed   => '2025-06-01T12:00:00Z',
    );

    my $r = read_record($dir, 'agent-serial-01');
    is $r->{dispatcher_serial}, 'deadbeef01234567',     'dispatcher_serial written';
    is $r->{serial_status},     'current',              'serial_status written';
    is $r->{serial_confirmed},  '2025-06-01T12:00:00Z', 'serial_confirmed written';
    is $r->{hostname},          'agent-serial-01',      'hostname preserved';
    is $r->{ip},                '192.168.1.10',         'ip preserved';
};

subtest 'register_agent: serial_status defaults to unknown when absent' => sub {
    my $dir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        registry_dir => $dir,
        hostname     => 'agent-default-01',
        ip           => '192.168.1.11',
        reqid        => 'eeff0011',
    );

    my $r = read_record($dir, 'agent-default-01');
    ok exists $r->{serial_status},
        'serial_status field is present (not merely absent-and-defaulted)';
    is $r->{serial_status}, 'unknown',
        'serial_status defaults to unknown';
};

subtest 'register_agent: serial fields default to empty string when absent' => sub {
    my $dir = tempdir(CLEANUP => 1);

    Exec::Registry::register_agent(
        registry_dir => $dir,
        hostname     => 'agent-defaults',
        ip           => '10.0.0.1',
        reqid        => '00112233',
    );

    my $r = read_record($dir, 'agent-defaults');
    is $r->{dispatcher_serial}, '', 'dispatcher_serial defaults to empty string';
    is $r->{serial_broadcast},  '', 'serial_broadcast defaults to empty string';
    is $r->{serial_confirmed},  '', 'serial_confirmed defaults to empty string';
};

subtest 'register_agent: all serial fields round-trip through JSON correctly' => sub {
    my $dir = tempdir(CLEANUP => 1);

    my %serial_fields = (
        dispatcher_serial => 'cafebabe00ff1234',
        serial_status     => 'current',
        serial_broadcast  => '2025-06-01T11:00:00Z',
        serial_confirmed  => '2025-06-01T12:00:00Z',
    );

    Exec::Registry::register_agent(
        registry_dir => $dir,
        hostname     => 'agent-roundtrip',
        ip           => '10.0.0.1',
        reqid        => '11223344',
        %serial_fields,
    );

    my $r = read_record($dir, 'agent-roundtrip');
    for my $field (sort keys %serial_fields) {
        is $r->{$field}, $serial_fields{$field},
            "$field round-trips correctly";
    }
};

# ---------------------------------------------------------------------------
# update_agent_serial_status: merge semantics
# ---------------------------------------------------------------------------

subtest 'update_agent_serial_status: merges serial fields without touching others' => sub {
    my $dir = tempdir(CLEANUP => 1);

    write_file("$dir/agent-merge.json", encode_json({
        hostname          => 'agent-merge',
        ip                => '10.1.2.3',
        paired            => '2025-01-15T08:00:00Z',
        expiry            => '2026-01-15T08:00:00Z',
        reqid             => 'deadcafe',
        dispatcher_serial => 'oldhex0001',
        serial_status     => 'pending',
        serial_broadcast  => '2025-05-01T00:00:00Z',
        serial_confirmed  => '',
    }));

    Exec::Registry::update_agent_serial_status(
        hostname         => 'agent-merge',
        registry_dir     => $dir,
        status           => 'current',
        serial           => 'newhex0002',
        serial_confirmed => '2025-06-15T09:00:00Z',
    );

    my $r = read_record($dir, 'agent-merge');

    # Serial fields updated
    is $r->{serial_status},     'current',              'serial_status updated';
    is $r->{dispatcher_serial}, 'newhex0002',           'dispatcher_serial updated';
    is $r->{serial_confirmed},  '2025-06-15T09:00:00Z', 'serial_confirmed updated';

    # Non-serial fields untouched
    is $r->{hostname}, 'agent-merge',          'hostname preserved';
    is $r->{ip},       '10.1.2.3',             'ip preserved';
    is $r->{paired},   '2025-01-15T08:00:00Z', 'paired preserved';
    is $r->{expiry},   '2026-01-15T08:00:00Z', 'expiry preserved';
    is $r->{reqid},    'deadcafe',              'reqid preserved';
};

subtest 'update_agent_serial_status: serial not overwritten when omitted' => sub {
    my $dir = tempdir(CLEANUP => 1);

    write_file("$dir/agent-serial-keep.json", encode_json({
        hostname          => 'agent-serial-keep',
        ip                => '10.0.0.5',
        dispatcher_serial => 'shouldstay',
        serial_status     => 'pending',
    }));

    Exec::Registry::update_agent_serial_status(
        hostname     => 'agent-serial-keep',
        registry_dir => $dir,
        status       => 'stale',
        # no serial arg
    );

    my $r = read_record($dir, 'agent-serial-keep');
    is $r->{serial_status},     'stale',      'serial_status updated to stale';
    is $r->{dispatcher_serial}, 'shouldstay', 'dispatcher_serial unchanged when serial omitted';
    is $r->{ip},                '10.0.0.5',   'ip preserved';
};

subtest 'update_agent_serial_status: serial_broadcast updated when provided' => sub {
    my $dir = tempdir(CLEANUP => 1);

    write_file("$dir/agent-broadcast.json", encode_json({
        hostname         => 'agent-broadcast',
        ip               => '10.0.0.6',
        serial_status    => 'pending',
        serial_broadcast => '',
    }));

    my $ts = '2025-06-20T14:00:00Z';
    Exec::Registry::update_agent_serial_status(
        hostname         => 'agent-broadcast',
        registry_dir     => $dir,
        status           => 'pending',
        serial_broadcast => $ts,
    );

    my $r = read_record($dir, 'agent-broadcast');
    is $r->{serial_broadcast}, $ts, 'serial_broadcast updated';
};

subtest 'update_agent_serial_status: serial_broadcast not overwritten when omitted' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $original_ts = '2025-05-01T00:00:00Z';

    write_file("$dir/agent-bc-keep.json", encode_json({
        hostname         => 'agent-bc-keep',
        serial_status    => 'pending',
        serial_broadcast => $original_ts,
    }));

    Exec::Registry::update_agent_serial_status(
        hostname     => 'agent-bc-keep',
        registry_dir => $dir,
        status       => 'stale',
        # no serial_broadcast arg
    );

    my $r = read_record($dir, 'agent-bc-keep');
    is $r->{serial_broadcast}, $original_ts,
        'serial_broadcast not overwritten when omitted';
};

# ---------------------------------------------------------------------------
# update_agent_serial_status: write atomicity
# ---------------------------------------------------------------------------

subtest 'update_agent_serial_status: result is valid JSON after update' => sub {
    my $dir = tempdir(CLEANUP => 1);

    write_file("$dir/agent-atomic.json", encode_json({
        hostname      => 'agent-atomic',
        serial_status => 'pending',
    }));

    Exec::Registry::update_agent_serial_status(
        hostname     => 'agent-atomic',
        registry_dir => $dir,
        status       => 'current',
    );

    my $raw = do { local $/; open my $fh, '<', "$dir/agent-atomic.json" or die $!; <$fh> };
    my $r   = eval { decode_json($raw) };
    ok !$@,                            "record is valid JSON after update: $@";
    is $r->{serial_status}, 'current', 'status written correctly';
    is $r->{hostname}, 'agent-atomic', 'hostname present';
};

# ---------------------------------------------------------------------------
# update_agent_serial_status: absent agent
# ---------------------------------------------------------------------------

subtest 'update_agent_serial_status: absent agent creates new minimal record' => sub {
    # Absent file -> $record starts as {}, then the function writes hostname +
    # status. Rotation.pm relies on this when marking all listed agents pending
    # after rotation, so the record MUST be created (a no-create regression
    # would silently drop agents from a rotation).
    my $dir = tempdir(CLEANUP => 1);

    eval {
        Exec::Registry::update_agent_serial_status(
            hostname     => 'new-from-update',
            registry_dir => $dir,
            status       => 'pending',
        );
    };
    ok !$@, 'does not die for absent agent';

    ok -f "$dir/new-from-update.json", 'a record is created for the absent agent';
    my $r = read_record($dir, 'new-from-update');
    is $r->{serial_status}, 'pending', 'new record has the requested status';
    is $r->{hostname}, 'new-from-update', 'hostname set in new record';
};

# ---------------------------------------------------------------------------
# update_serials_bulk: many records under a single lock (PERF-006)
# ---------------------------------------------------------------------------

subtest 'update_serials_bulk: applies every update and merges per record' => sub {
    my $dir = tempdir(CLEANUP => 1);

    # Two existing records (to confirm merge preserves other fields) + one
    # absent host (to confirm it is created, as rotation's mark-pending needs).
    for my $h (qw(bulk-a bulk-b)) {
        Exec::Registry::register_agent(
            registry_dir => $dir, hostname => $h, ip => '10.0.0.9', reqid => 'aa');
    }

    my $n = Exec::Registry::update_serials_bulk([
        { hostname => 'bulk-a', status => 'current',
          serial => 'deadbeef', serial_confirmed => '2026-06-20T00:00:00Z' },
        { hostname => 'bulk-b', status => 'pending', serial_broadcast => '2026-06-20T00:00:00Z' },
        { hostname => 'bulk-new', status => 'pending' },
    ], registry_dir => $dir);

    is $n, 3, 'three updates applied';

    my $a = read_record($dir, 'bulk-a');
    is $a->{serial_status}, 'current',  'bulk-a status set';
    is $a->{dispatcher_serial}, 'deadbeef', 'bulk-a serial set';
    is $a->{ip}, '10.0.0.9', 'bulk-a ip preserved (merge, not overwrite)';

    my $b = read_record($dir, 'bulk-b');
    is $b->{serial_status}, 'pending', 'bulk-b status set';
    is $b->{serial_broadcast}, '2026-06-20T00:00:00Z', 'bulk-b broadcast time set';

    ok -f "$dir/bulk-new.json", 'absent host created by bulk update';
    is read_record($dir, 'bulk-new')->{serial_status}, 'pending', 'new record status';
};

subtest 'update_serials_bulk: empty list is a no-op' => sub {
    my $dir = tempdir(CLEANUP => 1);
    is Exec::Registry::update_serials_bulk([], registry_dir => $dir), 0,
        'empty batch applies nothing';
    ok !-e "$dir/.registry.lock", 'empty batch does not even open the lock';
};

done_testing;
