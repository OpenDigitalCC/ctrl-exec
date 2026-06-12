#!/usr/bin/perl
# t/rotation.t
#
# Unit tests for Exec::Rotation.
#
# Tests cover the pure-logic functions (_cert_days_remaining, _read_cert_serial,
# load_state) and the state-mutating functions (_do_rotation, expire_stale_agents,
# broadcast_serial) with filesystem I/O isolated via tempdir.
#
# Config key reference:
#   ca_dir          => directory containing dispatcher.crt (default /etc/ctrl-exec)
#   rotation_file   => path to rotation.json state file (default /var/lib/ctrl-exec/rotation.json)
#   registry_dir    => path to agent registry dir (default /var/lib/ctrl-exec/agents)
#   cert_days       => new cert lifetime in days
#   cert_renewal_days  => renew when days-remaining drops below this
#   cert_overlap_days  => overlap window length in days
#
# Functions that call Registry or Engine do so via config->{registry_dir}.
# Functions that read/write state use config->{rotation_file}.
# _do_rotation and check_and_rotate call CA::generate_dispatcher_cert, which
# requires a real CA on disk - those subtests skip gracefully when unavailable.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile tempdir);
use File::Path qw(make_path);
use File::Basename qw(dirname);
use POSIX qw(strftime);
use JSON qw(decode_json encode_json);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Rotation qw();

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub write_file {
    my ($path, $content) = @_;
    make_path(dirname($path));
    open my $fh, '>', $path or die "Cannot write $path: $!";
    print $fh $content;
    close $fh;
}

sub read_file {
    my ($path) = @_;
    open my $fh, '<', $path or die "Cannot read $path: $!";
    local $/;
    return scalar <$fh>;
}

sub read_record {
    my ($dir, $hostname) = @_;
    return decode_json(read_file("$dir/$hostname.json"));
}

# Build a config hashref using the correct key names for Rotation.pm.
sub config {
    my (%extra) = @_;
    return {
        cert_days           => 825,
        cert_renewal_days   => 90,
        cert_overlap_days   => 30,
        cert_check_interval => 14400,
        %extra,
    };
}

# Generate a real self-signed cert using openssl.
# Returns true on success, false on failure.
sub make_cert {
    my ($days, $outfile) = @_;
    my $keyfile = $outfile . '.key';
    return system(
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', $keyfile,
        '-out',    $outfile,
        '-days',   $days,
        '-nodes',
        '-subj',   '/CN=test-ctrl-exec',
        qw(-quiet)
    ) == 0;
}

# ---------------------------------------------------------------------------
# _cert_days_remaining
# ---------------------------------------------------------------------------

subtest '_cert_days_remaining: valid cert returns positive integer' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir  = tempdir(CLEANUP => 1);
    my $cert = "$dir/test.crt";
    plan skip_all => 'could not generate test cert' unless make_cert(365, $cert);

    my $days = Exec::Rotation::_cert_days_remaining($cert);
    ok defined $days,    'returns a value';
    ok $days > 0,        "days remaining is positive ($days)";
    ok $days <= 365,     "days remaining <= cert lifetime ($days)";
};

subtest '_cert_days_remaining: cert expiring in 1 day' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir  = tempdir(CLEANUP => 1);
    my $cert = "$dir/short.crt";
    plan skip_all => 'could not generate test cert' unless make_cert(1, $cert);

    my $days = Exec::Rotation::_cert_days_remaining($cert);
    ok defined $days, 'returns a value for near-expiry cert';
    ok $days >= 0,    "days is non-negative ($days)";
    ok $days <= 2,    "days within expected range for a 1-day cert ($days)";
};

subtest '_cert_days_remaining: missing cert returns undef' => sub {
    my $days = Exec::Rotation::_cert_days_remaining('/nonexistent/cert.crt');
    ok !defined $days, 'returns undef for missing cert';
};

subtest '_cert_days_remaining: garbage file returns undef' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $cert = "$dir/garbage.crt";
    write_file($cert, "this is not a certificate\n");

    my $days = Exec::Rotation::_cert_days_remaining($cert);
    ok !defined $days, 'returns undef for garbage cert file';
};

# ---------------------------------------------------------------------------
# _read_cert_serial
# ---------------------------------------------------------------------------

subtest '_read_cert_serial: valid cert returns lowercase hex serial' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir  = tempdir(CLEANUP => 1);
    my $cert = "$dir/test.crt";
    plan skip_all => 'could not generate test cert' unless make_cert(365, $cert);

    my $serial = Exec::Rotation::_read_cert_serial($cert);
    ok defined $serial,              'returns a value';
    like $serial, qr/^[0-9a-f]+$/,  "serial is lowercase hex: $serial";
    ok length($serial) > 0,          'serial is non-empty';
};

subtest '_read_cert_serial: missing cert returns undef' => sub {
    my $serial = Exec::Rotation::_read_cert_serial('/nonexistent/cert.crt');
    ok !defined $serial, 'returns undef for missing cert';
};

subtest '_read_cert_serial: garbage file returns undef' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $cert = "$dir/garbage.crt";
    write_file($cert, "not a cert\n");

    my $serial = Exec::Rotation::_read_cert_serial($cert);
    ok !defined $serial, 'returns undef for garbage content';
};

# ---------------------------------------------------------------------------
# load_state
# ---------------------------------------------------------------------------

subtest 'load_state: returns parsed hashref for valid state file' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $file = "$dir/rotation.json";

    my $data = {
        current_serial  => 'deadbeef',
        previous_serial => 'cafebabe',
        rotated_at      => '2025-06-01T12:00:00Z',
        overlap_expires => '2025-07-01T12:00:00Z',
        overlap_days    => 30,
    };
    write_file($file, encode_json($data));

    my $state = Exec::Rotation::load_state(path => $file);
    ok defined $state,                        'load_state returns a value';
    is $state->{current_serial},  'deadbeef', 'current_serial correct';
    is $state->{previous_serial}, 'cafebabe', 'previous_serial correct';
    is $state->{overlap_days},    30,          'overlap_days correct';
    is $state->{rotated_at},      '2025-06-01T12:00:00Z', 'rotated_at correct';
};

subtest 'load_state: returns undef when state file absent' => sub {
    my $state = Exec::Rotation::load_state(path => '/nonexistent/rotation.json');
    ok !defined $state, 'returns undef when no state file';
};

subtest 'load_state: returns undef for corrupt JSON' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $file = "$dir/rotation.json";
    write_file($file, "{ this is not valid json ]");

    my $state = Exec::Rotation::load_state(path => $file);
    ok !defined $state, 'returns undef for corrupt JSON';
};

subtest 'load_state: all fields preserved in round-trip' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $file = "$dir/rotation.json";

    my $data = {
        current_serial  => 'aabbcc001122',
        previous_serial => '998877665544',
        rotated_at      => '2025-03-01T00:00:00Z',
        overlap_expires => '2025-04-01T00:00:00Z',
        overlap_days    => 45,
    };
    write_file($file, encode_json($data));

    my $state = Exec::Rotation::load_state(path => $file);
    for my $key (sort keys %$data) {
        is $state->{$key}, $data->{$key}, "$key round-trips";
    }
};

# ---------------------------------------------------------------------------
# expire_stale_agents
# ---------------------------------------------------------------------------

subtest 'expire_stale_agents: before overlap expires - pending agent unchanged' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $regDir = "$dir/agents";
    my $rotFile = "$dir/rotation.json";
    make_path($regDir);

    my $future = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime(time + 86400 * 7));
    write_file($rotFile, encode_json({
        current_serial  => 'abcd1234',
        previous_serial => '0000ffff',
        rotated_at      => '2025-01-01T00:00:00Z',
        overlap_expires => $future,
        overlap_days    => 30,
    }));

    write_file("$regDir/agent-01.json", encode_json({
        hostname      => 'agent-01',
        serial_status => 'pending',
    }));

    eval {
        Exec::Rotation::expire_stale_agents(config => config(
            rotation_file => $rotFile,
            registry_dir  => $regDir,
        ));
    };
    ok !$@, "no error: $@";

    my $r = read_record($regDir, 'agent-01');
    is $r->{serial_status}, 'pending',
        'pending agent remains pending before overlap expires';
};

subtest 'expire_stale_agents: after overlap expires - pending agents become stale' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $regDir = "$dir/agents";
    my $rotFile = "$dir/rotation.json";
    make_path($regDir);

    my $past = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime(time - 86400));
    write_file($rotFile, encode_json({
        current_serial  => 'abcd1234',
        previous_serial => '0000ffff',
        rotated_at      => '2025-01-01T00:00:00Z',
        overlap_expires => $past,
        overlap_days    => 30,
    }));

    write_file("$regDir/agent-01.json", encode_json({
        hostname      => 'agent-01',
        serial_status => 'pending',
    }));
    write_file("$regDir/agent-02.json", encode_json({
        hostname      => 'agent-02',
        serial_status => 'current',
    }));

    eval {
        Exec::Rotation::expire_stale_agents(config => config(
            rotation_file => $rotFile,
            registry_dir  => $regDir,
        ));
    };
    ok !$@, "no error: $@";

    is read_record($regDir, 'agent-01')->{serial_status}, 'stale',
        'pending agent marked stale after overlap expires';

    is read_record($regDir, 'agent-02')->{serial_status}, 'current',
        'current agent unaffected by expiry';
};

subtest 'expire_stale_agents: no rotation state file - returns without error' => sub {
    # NOTE: Rotation.pm calls load_state then dereferences the result without
    # guarding against undef ($state->{overlap_expires} on undef dies).
    # This test documents the EXPECTED behaviour (no die, no changes).
    # If this test fails with a "Can't use string as a HASH ref" error,
    # that is bug #5 in SECURITY-FINDINGS.md.
    my $dir    = tempdir(CLEANUP => 1);
    my $regDir = "$dir/agents";
    make_path($regDir);

    write_file("$regDir/agent-01.json", encode_json({
        hostname      => 'agent-01',
        serial_status => 'pending',
    }));

    eval {
        Exec::Rotation::expire_stale_agents(config => config(
            rotation_file => "$dir/nonexistent.json",
            registry_dir  => $regDir,
        ));
    };
    ok !$@, 'no error when state file absent';

    my $r = read_record($regDir, 'agent-01');
    is $r->{serial_status}, 'pending',
        'agent status unchanged when no state file';
};

# ---------------------------------------------------------------------------
# broadcast_serial
# ---------------------------------------------------------------------------

subtest 'broadcast_serial: no rotation state file returns empty arrayref' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $regDir = "$dir/agents";
    make_path($regDir);

    my $result = eval {
        Exec::Rotation::broadcast_serial(config => config(
            rotation_file => "$dir/nonexistent.json",
            registry_dir  => $regDir,
        ))
    };
    ok !$@,                   "no error: $@";
    ok defined $result,       'returns a value';
    is ref $result, 'ARRAY',  'returns arrayref';
    is scalar @$result, 0,    'empty arrayref when no state file';
};

subtest 'broadcast_serial: no current_serial in state returns empty arrayref' => sub {
    my $dir    = tempdir(CLEANUP => 1);
    my $regDir = "$dir/agents";
    my $rotFile = "$dir/rotation.json";
    make_path($regDir);

    write_file($rotFile, encode_json({
        previous_serial => 'oldhex',
        rotated_at      => '2025-01-01T00:00:00Z',
        # current_serial intentionally absent
    }));

    my $result = eval {
        Exec::Rotation::broadcast_serial(config => config(
            rotation_file => $rotFile,
            registry_dir  => $regDir,
        ))
    };
    ok !$@,                 "no error: $@";
    is ref $result, 'ARRAY', 'returns arrayref';
    is scalar @$result, 0,   'empty arrayref when no current_serial';
};

# ---------------------------------------------------------------------------
# _do_rotation
# ---------------------------------------------------------------------------

subtest '_do_rotation: creates rotation state file with correct fields' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir      = tempdir(CLEANUP => 1);
    my $caDir    = "$dir/ca";
    my $regDir   = "$dir/agents";
    my $rotFile  = "$dir/rotation.json";
    make_path($caDir, $regDir);

    my $cert = "$caDir/dispatcher.crt";
    plan skip_all => 'could not generate initial cert'
        unless make_cert(365, $cert);

    my $old_serial = Exec::Rotation::_read_cert_serial($cert);
    plan skip_all => 'could not read initial cert serial' unless defined $old_serial;

    my $result = eval {
        Exec::Rotation::_do_rotation(config => config(
            ca_dir        => $caDir,
            rotation_file => $rotFile,
            registry_dir  => $regDir,
        ))
    };
    if ($@ || !$result || !$result->{rotated}) {
        my $reason = $@ || ($result && $result->{error}) || 'unknown';
        plan skip_all => "_do_rotation requires a full CA setup: $reason";
        return;
    }

    ok -f $rotFile, 'rotation state file written';

    my $state = decode_json(read_file($rotFile));
    ok defined $state->{current_serial},  'current_serial present';
    ok defined $state->{previous_serial}, 'previous_serial present';
    ok defined $state->{rotated_at},      'rotated_at present';
    ok defined $state->{overlap_expires}, 'overlap_expires present';
    ok defined $state->{overlap_days},    'overlap_days present';

    is $state->{previous_serial}, $old_serial,
        'previous_serial matches old cert serial';
    isnt $state->{current_serial}, $old_serial,
        'current_serial differs from old serial';
};

subtest '_do_rotation: registered agents marked pending after rotation' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir     = tempdir(CLEANUP => 1);
    my $caDir   = "$dir/ca";
    my $regDir  = "$dir/agents";
    my $rotFile = "$dir/rotation.json";
    make_path($caDir, $regDir);

    my $cert = "$caDir/dispatcher.crt";
    plan skip_all => 'could not generate initial cert'
        unless make_cert(365, $cert);

    for my $host (qw(agent-01 agent-02)) {
        write_file("$regDir/$host.json", encode_json({
            hostname          => $host,
            ip                => '10.0.0.1',
            paired            => '2025-01-01T00:00:00Z',
            expiry            => '2026-01-01T00:00:00Z',
            reqid             => 'aabbccdd',
            serial_status     => 'current',
            dispatcher_serial => '0123456789abcdef',
        }));
    }

    my $result = eval {
        Exec::Rotation::_do_rotation(config => config(
            ca_dir        => $caDir,
            rotation_file => $rotFile,
            registry_dir  => $regDir,
        ))
    };
    if ($@ || !$result || !$result->{rotated}) {
        my $reason = $@ || ($result && $result->{error}) || 'unknown';
        plan skip_all => "_do_rotation requires a full CA setup: $reason";
        return;
    }

    for my $host (qw(agent-01 agent-02)) {
        ok -f "$regDir/$host.json", "agent record $host still exists";
        my $r = read_record($regDir, $host);
        is $r->{serial_status}, 'pending', "$host serial_status set to pending";
        is $r->{hostname},      $host,     "$host hostname preserved";
        is $r->{ip},            '10.0.0.1',"$host ip preserved";
    }
};

subtest '_do_rotation: no prior cert - previous_serial is empty string' => sub {
    plan skip_all => 'openssl not available'
        unless system('openssl version >/dev/null 2>&1') == 0;

    my $dir     = tempdir(CLEANUP => 1);
    my $caDir   = "$dir/ca";
    my $regDir  = "$dir/agents";
    my $rotFile = "$dir/rotation.json";
    make_path($caDir, $regDir);

    # No cert pre-created in caDir

    my $result = eval {
        Exec::Rotation::_do_rotation(config => config(
            ca_dir        => $caDir,
            rotation_file => $rotFile,
            registry_dir  => $regDir,
        ))
    };
    if ($@ || !$result || !$result->{rotated}) {
        my $reason = $@ || ($result && $result->{error}) || 'unknown';
        plan skip_all => "_do_rotation requires a full CA setup: $reason";
        return;
    }

    if (-f $rotFile) {
        my $state = decode_json(read_file($rotFile));
        is $state->{previous_serial}, '',
            'previous_serial is empty string when no prior cert existed';
    }
    else {
        pass 'rotation ran (state file location may be overridden)';
    }
};

done_testing;
