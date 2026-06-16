#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Pairing qw();

# Helper: write a minimal pairing request JSON file
sub write_request {
    my ($dir, $id, %extra) = @_;
    my $hostname = $extra{hostname} // 'test-host';
    my $nonce    = $extra{nonce}    // '';
    my $received = $extra{received} // '2026-01-01T00:00:00Z';
    open my $fh, '>', "$dir/$id.json" or die $!;
    print $fh qq({"id":"$id","hostname":"$hostname","nonce":"$nonce","received":"$received"});
    close $fh;
}

# --- _expire_stale_requests ---

subtest '_expire_stale_requests: leaves fresh requests alone' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $path = "$dir/aabbcc001122.json";
    write_request($dir, 'aabbcc001122', hostname => 'host-a');
    Exec::Pairing::_expire_stale_requests($dir);
    ok -f $path, 'fresh request not removed';
};

subtest '_expire_stale_requests: removes stale request with no response' => sub {
    my $dir  = tempdir(CLEANUP => 1);
    my $path = "$dir/aabbcc001133.json";
    write_request($dir, 'aabbcc001133', hostname => 'host-b');
    my $old = time() - 660;
    utime $old, $old, $path;
    Exec::Pairing::_expire_stale_requests($dir);
    ok !-f $path, 'stale request removed';
};

subtest '_expire_stale_requests: preserves stale request that has .approved' => sub {
    my $dir          = tempdir(CLEANUP => 1);
    my $base         = 'aabbcc001144';
    my $json_path     = "$dir/$base.json";
    my $approved_path = "$dir/$base.approved";
    write_request($dir, $base, hostname => 'host-c');
    open my $fh, '>', $approved_path or die $!;
    print $fh '{"status":"approved"}';
    close $fh;
    my $old = time() - 660;
    utime $old, $old, $json_path;
    utime $old, $old, $approved_path;
    Exec::Pairing::_expire_stale_requests($dir);
    ok -f $json_path, 'stale request with .approved not removed';
};

subtest '_expire_stale_requests: preserves stale request that has .denied' => sub {
    my $dir         = tempdir(CLEANUP => 1);
    my $base        = 'aabbcc001155';
    my $json_path   = "$dir/$base.json";
    my $denied_path = "$dir/$base.denied";
    write_request($dir, $base, hostname => 'host-d');
    open my $fh, '>', $denied_path or die $!;
    print $fh '{"status":"denied"}';
    close $fh;
    my $old = time() - 660;
    utime $old, $old, $json_path;
    Exec::Pairing::_expire_stale_requests($dir);
    ok -f $json_path, 'stale request with .denied not removed';
};

subtest '_expire_stale_requests: ignores non-json files' => sub {
    my $dir   = tempdir(CLEANUP => 1);
    my $other = "$dir/somefile.txt";
    open my $fh, '>', $other or die $!;
    print $fh "irrelevant\n";
    close $fh;
    my $old = time() - 660;
    utime $old, $old, $other;
    Exec::Pairing::_expire_stale_requests($dir);
    ok -f $other, 'non-json files left alone';
};

subtest '_expire_stale_requests: handles missing directory gracefully' => sub {
    eval { Exec::Pairing::_expire_stale_requests('/nonexistent/path/xyz') };
    ok !$@, 'no exception for missing directory';
};

# --- list_requests: nonce stored in queue ---

subtest 'list_requests: returns request data including nonce' => sub {
    my $dir = tempdir(CLEANUP => 1);
    write_request($dir, 'aabbcc001166',
        hostname => 'host-e',
        nonce    => 'deadbeef12345678deadbeef12345678',
    );
    my $requests = Exec::Pairing::list_requests(pairing_dir => $dir);
    is scalar @$requests, 1, 'one request returned';
    is $requests->[0]{nonce}, 'deadbeef12345678deadbeef12345678', 'nonce preserved in queue';
};

subtest 'list_requests: stale requests cleaned before listing' => sub {
    my $dir = tempdir(CLEANUP => 1);

    write_request($dir, 'aabbcc001177',
        hostname => 'stale-host',
        received => '2020-01-01T00:00:00Z',
    );
    my $old = time() - 660;
    utime $old, $old, "$dir/aabbcc001177.json";

    write_request($dir, 'aabbcc001188',
        hostname => 'fresh-host',
        received => '2026-01-01T00:00:00Z',
    );

    my $requests = Exec::Pairing::list_requests(pairing_dir => $dir);
    is scalar @$requests, 1,           'only fresh request returned';
    is $requests->[0]{hostname}, 'fresh-host', 'fresh host present';
};

# --- lookup_by helpers ---

subtest '_valid_lookup_by: accepts ip/hostname, rejects others' => sub {
    is Exec::Pairing::_valid_lookup_by('ip'),       'ip',       'ip accepted';
    is Exec::Pairing::_valid_lookup_by('hostname'), 'hostname', 'hostname accepted';
    is Exec::Pairing::_valid_lookup_by('bogus'),    undef,      'invalid value rejected';
    is Exec::Pairing::_valid_lookup_by(undef),      undef,      'undef rejected';
};

subtest '_effective_lookup_by: override beats suggested beats default' => sub {
    is Exec::Pairing::_effective_lookup_by('ip', 'hostname'), 'ip',
        'operator override wins over agent-suggested value';
    is Exec::Pairing::_effective_lookup_by(undef, 'ip'), 'ip',
        'agent-suggested value used when no override';
    is Exec::Pairing::_effective_lookup_by(undef, undef), 'hostname',
        'defaults to hostname when neither given';
    is Exec::Pairing::_effective_lookup_by('bogus', 'ip'), 'ip',
        'invalid override ignored, suggested used';
    is Exec::Pairing::_effective_lookup_by(undef, 'bogus'), 'hostname',
        'invalid suggested ignored, falls to default';
};

subtest '_valid_port: accepts 1..65535, rejects others' => sub {
    is Exec::Pairing::_valid_port(7450), 7450, 'valid port accepted';
    is Exec::Pairing::_valid_port('7450'), 7450, 'numeric string coerced to int';
    is Exec::Pairing::_valid_port(0),     undef, 'port 0 rejected';
    is Exec::Pairing::_valid_port(99999), undef, 'out-of-range rejected';
    is Exec::Pairing::_valid_port('abc'), undef, 'non-numeric rejected';
    is Exec::Pairing::_valid_port(undef), undef, 'undef rejected';
};

subtest '_effective_port: override beats reported beats default' => sub {
    is Exec::Pairing::_effective_port(7450, 7443), 7450, 'operator override wins';
    is Exec::Pairing::_effective_port(undef, 7460), 7460, 'agent-reported used when no override';
    is Exec::Pairing::_effective_port(undef, undef), 7443, 'defaults to 7443';
    is Exec::Pairing::_effective_port(99999, 7460), 7460, 'invalid override ignored, reported used';
    is Exec::Pairing::_effective_port(undef, 'bad'), 7443, 'invalid reported ignored, default used';
};

subtest 'resolve_dispatcher_id' => sub {
    is Exec::Pairing::resolve_dispatcher_id({ dispatcher_id => 'automation' }),
        'automation', 'explicit dispatcher_id wins';

    # Falls back to the host name when unset (we only assert it is a valid,
    # non-empty token, not the exact hostname).
    my $derived = Exec::Pairing::resolve_dispatcher_id({});
    like $derived, qr/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/,
        'falls back to a sanitised, valid token when unset';

    is Exec::Pairing::resolve_dispatcher_id({ dispatcher_id => 'has space/slash' }),
        'has-space-slash', 'disallowed characters become hyphens';

    is Exec::Pairing::resolve_dispatcher_id({ dispatcher_id => '...weird' }),
        'weird', 'leading non-alphanumerics are stripped';

    is length(Exec::Pairing::resolve_dispatcher_id({ dispatcher_id => 'a' x 200 })),
        64, 'capped at 64 characters';
};

done_testing;
