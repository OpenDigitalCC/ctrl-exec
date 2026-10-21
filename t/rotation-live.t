#!/usr/bin/perl
# t/rotation-live.t
#
# T-069: dispatcher certificate rotation against a real agent (t/lib/AgentRig).
# The new serial must be broadcast with the certificate the agent already
# trusts - the agent accepts a serial only from a caller whose own serial it
# trusts - and the new certificate served only after that. Before T-069 the
# rotation overwrote the served certificate first, so the broadcast presented
# the new serial and every agent answered 403 "serial mismatch": one rotation
# cut the dispatcher off from the fleet. The broadcast also contacted agents by
# registry name on port 7443, ignoring their registered address and port; the
# rig agent is registered as 'agent-01' (not a resolvable name) with
# lookup_by = ip and its own port, so every broadcast here exercises that too.

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use File::Copy qw(copy);
use File::Temp qw(tempdir);
use JSON qw(decode_json encode_json);
use POSIX qw(strftime);

require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();
require NoSyslog;
require Exec::Rotation;
require Exec::Engine;
require Exec::Registry;
require Exec::CA;
require Exec::CertInfo;
require Exec::Doctor::Dispatcher;

# 2048-bit dispatcher keys: the rotation's 4096 bits only cost the test time.
my @log;
my @broadcast_certs;   # serial of the certificate each rotate_all call presented
{
    no warnings 'redefine';
    my $genrsa = \&Exec::CA::_genrsa;
    *Exec::CA::_genrsa = sub { $genrsa->($_[0], 2048) };
    my $log = \&Exec::Log::log_action;
    *Exec::Log::log_action = sub { push @log, [ @_ ]; };
    my $rotate_all = \&Exec::Engine::rotate_all;
    *Exec::Engine::rotate_all = sub {
        my %o = @_;
        push @broadcast_certs, [ $o{action}, Exec::CertInfo::serial_from_path($o{config}{cert}) ];
        return $rotate_all->(@_);
    };
}

my $OLD = '3ea';   # the rig's 'trusted' certificate, serial 1002, in the agent's map

# A dispatcher for $rig: its CA is the rig's CA, its served certificate a copy
# of the rig's 'trusted' one, and agent-01 is the rig agent at 127.0.0.1 on the
# rig's port, by IP.
sub dispatcher {
    my ($rig, %extra) = @_;
    my $d = $rig->{dir};
    my $w = tempdir(CLEANUP => 1);
    copy("$d/trusted.crt", "$w/ctrl-exec.crt") or die;
    copy("$d/trusted.key", "$w/ctrl-exec.key") or die;
    chmod 0600, "$w/ctrl-exec.key";
    my $config = {
        ca_dir => $d, ca => "$d/ca.crt",
        cert => "$w/ctrl-exec.crt", key => "$w/ctrl-exec.key",
        registry_dir => "$w/agents", rotation_file => "$w/rotation.json",
        dispatcher_id => 'test-dispatcher', service_user => scalar getpwuid($<),
        cert_overlap_days => 30, read_timeout => 15,
        %extra,
    };
    Exec::Registry::register_agent(
        hostname => 'agent-01', ip => '127.0.0.1', lookup_by => 'ip', port => $rig->{port},
        paired => '2026-01-01T00:00:00Z', expiry => '', reqid => 'r1',
        serial_status => 'current', dispatcher_serial => $OLD,
        registry_dir => $config->{registry_dir});
    return $config;
}

sub ping_ok {
    my ($config) = @_;
    my $r = Exec::Engine::ping_all(
        hosts => [ { name => 'agent-01', target => Exec::Registry::resolve_target(
                       hostname => 'agent-01', registry_dir => $config->{registry_dir}) } ],
        config => $config, renew => 0);
    return (($r->[0]{status} // '') eq 'ok', $r->[0]{error} // '');
}

# The serials the agent trusts for test-dispatcher, sorted.
sub agent_serials {
    my ($rig) = @_;
    open my $fh, '<', "$rig->{dir}/dispatchers" or return [];
    my @s;
    while (<$fh>) {
        my @f = split ' ';
        push @s, $f[-2] if @f >= 2 && $f[-1] eq 'test-dispatcher';
    }
    return [ sort @s ];
}

sub state  { decode_json(do { local (@ARGV, $/) = $_[0]{rotation_file}; <> }) }
sub served { Exec::CertInfo::serial_from_path($_[0]{cert}) }
sub status { Exec::Registry::get_agent(hostname => 'agent-01',
                                       registry_dir => $_[0]{registry_dir})->{serial_status} }
sub end_overlap {
    my ($config) = @_;
    my $s = state($config);
    $s->{overlap_expires} = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime(time - 60));
    open my $fh, '>', $config->{rotation_file} or die;
    print $fh encode_json($s);
    close $fh;
}

subtest 'rotate-cert: broadcast with the old certificate, agent stays reachable, retire' => sub {
    my $rig = AgentRig->new;
    ok $rig->start, 'agent started' or return;
    my $c = dispatcher($rig);
    my ($ok, $err) = ping_ok($c);
    ok $ok, 'before: the agent accepts the dispatcher' or diag $err;

    @broadcast_certs = ();
    my $r = Exec::Rotation::rotate(config => $c);
    ok $r->{rotated}, 'rotated' or diag explain $r;
    my $new = $r->{serial};
    is $r->{old_serial}, $OLD, 'old serial reported';
    is_deeply [ map { $_->{status} } @{ $r->{broadcast} } ], ['ok'],
        'the broadcast reached agent-01 at its registered address and port'
        or diag explain $r->{broadcast};
    is_deeply \@broadcast_certs, [ [ 'add', $OLD ] ],
        'the broadcast presented the old certificate (serial 3ea), not the new one';
    unlike $rig->log_text, qr/serial-reject/, 'the agent refused nothing';
    like $rig->log_text, qr/ACTION=rotate .*SERIAL_ACTION=add/, 'the agent logged the add';

    is served($c), $new, 'the served certificate is the new one after the broadcast';
    ok !-e "$c->{cert}.next" && !-e "$c->{key}.next", 'nothing left staged';
    is Exec::CertInfo::serial_from_path("$c->{cert}.prev"), $OLD, 'the previous certificate is kept';
    is((stat "$c->{key}.prev")[2] & 07777, 0600, 'the kept key is mode 0600');
    ok !state($c)->{staged}, 'state: switched';
    is status($c), 'current', 'registry: agent-01 current';
    is_deeply agent_serials($rig), [ sort $OLD, $new ], 'overlap: the agent trusts both serials';

    ($ok, $err) = ping_ok($c);
    ok $ok, 'after: the agent accepts the new certificate' or diag $err;

    # Overlap not over: retire does nothing.
    Exec::Rotation::retire_previous_serial(config => $c);
    is_deeply agent_serials($rig), [ sort $OLD, $new ], 'during overlap retire keeps both';

    end_overlap($c);
    @broadcast_certs = ();
    is Exec::Rotation::retire_previous_serial(config => $c), 1, 'retire after overlap: one agent';
    is_deeply \@broadcast_certs, [ [ 'remove', $new ] ], 'the removal is sent with the new certificate';
    is_deeply agent_serials($rig), [ $new ], 'after retire the agent trusts only the new serial';
    ok !-e "$c->{cert}.prev" && !-e "$c->{key}.prev", 'the previous pair is deleted';
    ($ok, $err) = ping_ok($c);
    ok $ok, 'after retire: still reachable' or diag $err;
    $rig->stop;
};

subtest 'automatic rotation (check_and_rotate, then the maintain broadcast step)' => sub {
    my $rig = AgentRig->new;
    ok $rig->start, 'agent started' or return;
    my $c = dispatcher($rig, cert_renewal_days => 100000);   # always due
    @broadcast_certs = ();
    my $r = Exec::Rotation::check_and_rotate(config => $c);
    ok $r->{rotated}, 'the expiry check rotated' or diag explain $r;
    is_deeply \@broadcast_certs, [ [ 'add', $OLD ] ], 'broadcast with the old certificate';
    is_deeply Exec::Rotation::broadcast_serial(config => $c), [],
        'the broadcast step after it has nothing left to send';
    is_deeply agent_serials($rig), [ sort $OLD, $r->{serial} ], 'the agent trusts both serials';
    my ($ok, $err) = ping_ok($c);
    ok $ok, 'the agent accepts the new certificate' or diag $err;
    $rig->stop;
};

subtest 'an agent offline during the broadcast is caught up with the previous certificate' => sub {
    my $rig = AgentRig->new;
    my $c = dispatcher($rig);   # not started: offline
    my $r = Exec::Rotation::rotate(config => $c);
    ok $r->{rotated}, 'rotated with the agent offline';
    is $r->{broadcast}[0]{status}, 'failed', 'the broadcast to it failed';
    is status($c), 'pending', 'registry: pending';
    is served($c), $r->{serial}, 'the new certificate is served anyway';

    ok $rig->start, 'the agent comes back';
    my ($ok, $err) = ping_ok($c);
    ok !$ok, 'it refuses the new certificate until caught up';
    like $err, qr/serial mismatch|403/, '...as a serial mismatch';

    @broadcast_certs = ();
    my $rep = Exec::Rotation::broadcast_serial(config => $c);   # maintain / check loop retry
    is_deeply [ map { $_->{status} } @$rep ], ['ok'], 'the retry reaches it';
    is_deeply \@broadcast_certs, [ [ 'add', $OLD ] ], 'the retry presents the previous certificate';
    is status($c), 'current', 'registry: current';
    ($ok, $err) = ping_ok($c);
    ok $ok, 'it accepts the new certificate now' or diag $err;
    $rig->stop;
};

subtest 'rotate-cert again while an agent is still pending: the pair it trusts is kept' => sub {
    my $rig = AgentRig->new;
    my $c = dispatcher($rig);   # offline for the first rotation
    my $r1 = Exec::Rotation::rotate(config => $c);
    is status($c), 'pending', 'first rotation: the agent missed it';
    ok $rig->start, 'the agent comes back';

    @broadcast_certs = ();
    my $r2 = Exec::Rotation::rotate(config => $c);   # the operator rotates again
    ok $r2->{rotated}, 'second rotation';
    is $r2->{old_serial}, $OLD, 'its previous serial is still the one the agent trusts';
    is_deeply \@broadcast_certs, [ [ 'add', $OLD ] ], 'broadcast with the kept first pair';
    is $r2->{broadcast}[0]{status}, 'ok', 'the agent took the new serial';
    is_deeply state($c)->{superseded_serials}, [ $r1->{serial} ], 'the skipped serial is recorded';
    my ($ok, $err) = ping_ok($c);
    ok $ok, 'it accepts the served certificate' or diag $err;

    end_overlap($c);
    @broadcast_certs = ();
    Exec::Rotation::retire_previous_serial(config => $c);
    is_deeply [ sort map { $_->[1] } @broadcast_certs ], [ $r2->{serial}, $r2->{serial} ],
        'retire sends two removals, with the served certificate';
    is_deeply agent_serials($rig), [ $r2->{serial} ], 'only the newest serial is left';
    ($ok, $err) = ping_ok($c);
    ok $ok, 'still reachable' or diag $err;
    $rig->stop;
};

subtest 'interrupted after staging: the served pair is untouched, the next run finishes' => sub {
    my $rig = AgentRig->new;
    ok $rig->start, 'agent started' or return;
    my $c = dispatcher($rig);
    ok Exec::Rotation::_stage($c)->{staged}, 'staged (then the process "crashed")';
    my $new = state($c)->{current_serial};
    is served($c), $OLD, 'still serving the old certificate';
    my ($ok, $err) = ping_ok($c);
    ok $ok, 'the agent is reachable meanwhile' or diag $err;

    end_overlap($c);
    Exec::Rotation::retire_previous_serial(config => $c);
    is_deeply agent_serials($rig), [ $OLD ], 'retire never removes the served serial of a staged rotation';

    my $rep = Exec::Rotation::broadcast_serial(config => $c);   # the next maintain run
    is_deeply [ map { $_->{status} } @$rep ], ['ok'], 'the broadcast is sent';
    is served($c), $new, 'and the staged certificate installed';
    ok !state($c)->{staged}, 'state: switched';
    ($ok, $err) = ping_ok($c);
    ok $ok, 'reachable with the new certificate' or diag $err;
    $rig->stop;
};

subtest 'interrupted between the two renames: rotate-cert again finishes, same serial' => sub {
    my $rig = AgentRig->new;
    ok $rig->start, 'agent started' or return;
    my $c = dispatcher($rig);
    Exec::Rotation::_stage($c);
    my $new = state($c)->{current_serial};
    rename "$c->{key}.next", $c->{key} or die;   # the key went over, the certificate did not
    my $r = Exec::Rotation::rotate(config => $c);
    ok $r->{rotated} && $r->{resumed}, 'rotate-cert resumed the staged rotation' or diag explain $r;
    is $r->{serial}, $new, 'the staged serial, not a new one';
    is_deeply [ map { $_->{status} } @{ $r->{broadcast} } ], ['ok'], 'broadcast with the kept old pair';
    is served($c), $new, 'the certificate is installed';
    my ($ok, $err) = ping_ok($c);
    ok $ok, 'the served pair matches and the agent accepts it' or diag $err;
    $rig->stop;
};

subtest 'a rotation made before T-069 (certificate already replaced): no worse, doctor says so' => sub {
    my $rig = AgentRig->new;
    ok $rig->start, 'agent started' or return;
    my $c = dispatcher($rig);
    # What 0.13.2 left behind: the served pair replaced in place, a state file
    # without 'staged', the agent pending, its broadcast refused.
    Exec::CA::generate_dispatcher_cert(ca_dir => $c->{ca_dir}, cert => $c->{cert},
        key => $c->{key}, force => 1);
    my $new = served($c);
    open my $fh, '>', $c->{rotation_file} or die;
    print $fh encode_json({ current_serial => $new, previous_serial => $OLD,
        rotated_at => '2026-10-01T00:00:00Z', overlap_expires => '2099-01-01T00:00:00Z',
        overlap_days => 30 });
    close $fh;
    Exec::Registry::update_serials_bulk([ { hostname => 'agent-01', status => 'pending' } ],
        registry_dir => $c->{registry_dir});

    my $rep = Exec::Rotation::broadcast_serial(config => $c);
    is $rep->[0]{status}, 'failed', 'the broadcast fails as it did (the old key is gone)';
    is served($c), $new, 'the served certificate is left alone';
    is status($c), 'pending', 'the agent stays pending';

    my @f = Exec::Doctor::Dispatcher::_rotation_checks($c);
    my ($cut) = grep { $_->{check} eq 'agent-missed-rotation' } @f;
    ok $cut, 'doctor reports the agent that missed the rotation' or diag explain \@f;
    like $cut->{what} // '', qr/agent-01/, '...by name';
    like $cut->{fix} // '', qr/request-pairing/, '...with the re-pairing fix';
    $rig->stop;
};

subtest 'doctor: a staged rotation, and a healthy one' => sub {
    my $rig = AgentRig->new;
    my $c = dispatcher($rig);
    is_deeply [ Exec::Doctor::Dispatcher::_rotation_checks($c) ], [], 'no rotation: nothing';
    Exec::Rotation::_stage($c);
    my @f = Exec::Doctor::Dispatcher::_rotation_checks($c);
    is_deeply [ map { $_->{check} } @f ], ['rotation-unfinished'], 'staged: rotation-unfinished'
        or diag explain \@f;
    like $f[0]{fix}, qr/maintain|rotate-cert/, '...fixed by maintain or rotate-cert';
    # Offline agent: pending with the previous pair kept is retried, not a finding.
    Exec::Rotation::broadcast_serial(config => $c);
    is status($c), 'pending', 'agent offline: pending';
    is_deeply [ Exec::Doctor::Dispatcher::_rotation_checks($c) ], [],
        'pending within the overlap with the previous pair kept: no finding';
};

done_testing;
