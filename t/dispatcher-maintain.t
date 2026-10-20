#!/usr/bin/perl
# Direct tests for mode_maintain (bin/ctrl-exec-dispatcher, `ced maintain`).
#
# The dispatcher is loaded as a modulino (its `main() unless caller` guard keeps
# main() from running) and mode_maintain is called in-process, so the real
# phases run: ping fan-out, rotate, broadcast, expire, purge.
#
# What is real: mode_maintain, Exec::Registry (a temp registry dir),
# Exec::Rotation (a temp config, no dispatcher cert), Exec::RunStore::purge (a
# temp runs dir with one aged and one fresh record).
# What is mocked: only the network edge, Exec::Engine::ping_all (it would dial
# the agents). Exec::Registry::list_agents, ::resolve_dispatch and Exec::RunStore::purge are wrapped
# to inject the temp directories (mode_maintain passes none, so it would use
# /var/lib/ctrl-exec) and then call the real function. Exec::Log::log_action is
# wrapped to record what was logged. Exec::DispatcherConfig::load_config is
# wrapped to read the temp config (the path variable is a file lexical). Failing phases are injected by dying from a
# wrapper around the real phase function.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use JSON qw(decode_json);

# mode_maintain exits non-zero when a phase failed. Trap exit so the test can
# read the status; it must be installed before the dispatcher is compiled.
BEGIN {
    *CORE::GLOBAL::exit = sub { die bless({ code => $_[0] // 0 }, 'Test::Exit') };
}

{
    no warnings qw(redefine once);
    local *main::main = sub {};
    local $SIG{__WARN__} = sub {};
    do "$Bin/../bin/ctrl-exec-dispatcher";
    die "Could not load dispatcher: $@" if $@;
}

require Exec::Log;
require Exec::Registry;
require Exec::RunStore;
require Exec::Rotation;
require Exec::Engine;

my $TMP = tempdir(CLEANUP => 1);
mkdir "$TMP/agents";
mkdir "$TMP/runs";
open my $cf, '>', "$TMP/ctrl-exec.conf" or die;
print $cf "cert = $TMP/absent.crt\nkey = $TMP/absent.key\nca = $TMP/absent-ca.crt\n"
        . "registry_dir = $TMP/agents\nrotation_file = $TMP/rotation.json\n";
close $cf;

# --- instrumentation -------------------------------------------------------
my (@log, @ping_calls, %phase_ran);
my %die_in;                 # phase name -> 1 to make that phase die
my $ping_result = sub { [] };
my $LAST_EXIT;              # exit status of the last run_maintain

{
    no warnings 'redefine';
    no strict 'refs';
    no warnings 'once';
    my $real_list  = \&Exec::Registry::list_agents;
    my $real_purge = \&Exec::RunStore::purge;
    my $real_rot   = \&Exec::Rotation::check_and_rotate;
    my $real_bc    = \&Exec::Rotation::broadcast_serial;
    my $real_exp   = \&Exec::Rotation::expire_stale_agents;

    # $CONFIG_PATH is a file lexical in the dispatcher, so redirect the real
    # loader to the temp config instead.
    my $real_load = \&Exec::DispatcherConfig::load_config;
    *Exec::DispatcherConfig::load_config = sub { $real_load->("$TMP/ctrl-exec.conf") };
    *Exec::Log::log_action = sub { push @log, [ @_ ] };
    *Exec::Registry::list_agents = sub { $real_list->(@_, registry_dir => "$TMP/agents") };
    my $real_res = \&Exec::Registry::resolve_dispatch;
    *Exec::Registry::resolve_dispatch = sub { $real_res->(@_, registry_dir => "$TMP/agents") };
    *Exec::Engine::ping_all = sub {
        my %a = @_;
        push @ping_calls, \%a;
        $phase_ran{ping}++;
        die "ping boom\n" if $die_in{ping};
        return $ping_result->(%a);
    };
    *Exec::Rotation::check_and_rotate = sub {
        $phase_ran{rotate}++;  die "rotate boom\n" if $die_in{rotate};
        $real_rot->(@_) };
    *Exec::Rotation::broadcast_serial = sub {
        $phase_ran{broadcast}++; die "broadcast boom\n" if $die_in{broadcast};
        $real_bc->(@_) };
    *Exec::Rotation::expire_stale_agents = sub {
        $phase_ran{expire}++;  die "expire boom\n" if $die_in{expire};
        $real_exp->(@_) };
    *Exec::RunStore::purge = sub {
        $phase_ran{purge}++;   die "purge boom\n" if $die_in{purge};
        $real_purge->("$TMP/runs", 3600) };
}

sub reset_run { @log = (); @ping_calls = (); %phase_ran = (); %die_in = (); }

sub run_maintain {
    my ($opts) = @_;
    my $out = '';
    my $ok;
    my $code = 0;
    {
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        $ok = eval { main::mode_maintain($opts); 1 };
    }
    my $err = $@;
    if (!$ok && ref $err eq 'Test::Exit') {     # exit() was called: not a die
        $code = $err->{code};
        $ok   = 1;
        $err  = '';
    }
    $LAST_EXIT = $code;
    return ($ok, $err, $out);
}

sub errs { grep { $_->[0] eq 'ERR' } @log }
sub err_phases { sort map { $_->[1]{PHASE} } errs() }

sub add_agent {
    my ($name) = @_;
    open my $fh, '>', "$TMP/agents/$name.json" or die;
    print $fh qq({"hostname":"$name","ip":"10.0.0.1","serial_status":"unknown"});
    close $fh;
}

# --- empty registry --------------------------------------------------------
subtest 'empty registry: runs, harmless, exits normally' => sub {
    reset_run();
    my ($ok, $err, $out) = run_maintain({});
    ok $ok, 'mode_maintain returns without dying' or diag $err;
    is scalar(@ping_calls), 0, 'no agents -> ping fan-out not attempted';
    is_deeply [ err_phases() ], [], 'no phase logged an error';
    is $phase_ran{$_}, 1, "phase $_ still ran" for qw(rotate broadcast expire purge);
    like $out, qr/^Maintenance run: 0\/0 agents pinged, dispatcher cert checked\.$/,
        'text summary reports 0/0';

    reset_run();
    ($ok, $err, $out) = run_maintain({ json => 1 });
    ok $ok, 'json run does not die' or diag $err;
    is_deeply decode_json($out), { ok => 1, agents => 0, pinged => 0, failed => [] },
        'empty registry json: ok, 0 agents, 0 pinged, no failed phases';
    is $LAST_EXIT, 0, 'exit status 0';
};

# --- json shape ------------------------------------------------------------
subtest '--json output shape' => sub {
    reset_run();
    add_agent($_) for qw(host-a host-b);
    $ping_result = sub { [ { ok => 1 }, { ok => 1 } ] };
    my ($ok, $err, $out) = run_maintain({ json => 1 });
    ok $ok, 'does not die' or diag $err;
    is scalar(() = $out =~ /\n/g), 1, 'exactly one line of output';
    like $out, qr/\n\z/, 'newline terminated';
    my $j = eval { decode_json($out) };
    ok ref $j eq 'HASH', 'output is a JSON object' or return diag $out;
    is_deeply [ sort keys %$j ], [ qw(agents failed ok pinged) ], 'exact key set';
    like $out, qr/"ok":1\b/,      'ok is a JSON number 1, not a string';
    like $out, qr/"agents":2\b/,  'agents is a JSON number';
    like $out, qr/"pinged":2\b/,  'pinged is a JSON number';
    is_deeply $j, { ok => 1, agents => 2, pinged => 2, failed => [] }, 'values';
    like $out, qr/"failed":\[\]/, 'failed is an empty JSON array when all phases pass';
    is $LAST_EXIT, 0, 'all phases pass: exit status 0';
    is_deeply [ sort map { $_->{name} } @{ $ping_calls[0]{hosts} } ], [ qw(host-a host-b) ],
        'ping_all received the registered hosts';

    # Without --json the output is the human summary, not JSON.
    reset_run();
    ($ok, $err, $out) = run_maintain({});
    like $out, qr/^Maintenance run: 2\/2 agents pinged, dispatcher cert checked\.$/, 'text mode summary';
    unlike $out, qr/failed/i, 'text mode names no failed phase when all pass';
    is $LAST_EXIT, 0, 'text mode, all pass: exit status 0';
    unlike $out, qr/^\{/, 'text mode is not JSON';
};

# --- phase isolation -------------------------------------------------------
subtest 'phase isolation: one failing phase does not stop the others' => sub {
    my @steps = qw(rotate broadcast expire purge);
    for my $bad (qw(ping rotate broadcast expire purge)) {
        reset_run();
        $ping_result = sub { [ { ok => 1 }, { ok => 1 } ] };
        $die_in{$bad} = 1;
        my ($ok, $err, $out) = run_maintain({ json => 1 });
        ok $ok, "$bad dies: mode_maintain itself does not die" or diag $err;
        is $LAST_EXIT, 1, "$bad dies: exit status 1";
        is $phase_ran{$_}, 1, "$bad dies: phase $_ ran" for 'ping', @steps;
        is_deeply [ err_phases() ], [ $bad ], "$bad dies: only $bad logged as ERR";
        my ($e) = errs();
        like $e->[1]{ERROR}, qr/\Q$bad\E boom/, "$bad dies: ERR carries the cause";
        is $e->[1]{ACTION}, 'maintain', "$bad dies: ERR is tagged ACTION=maintain";
        my $j = eval { decode_json($out) } || {};
        is $j->{ok}, 0, "$bad dies: json ok is 0";
        is_deeply $j->{failed}, [ $bad ], "$bad dies: json failed lists $bad";
        is $j->{agents}, 2, "$bad dies: json still reports agents";
        is $j->{pinged}, ($bad eq 'ping' ? 0 : 2), "$bad dies: pinged count reflects ping outcome";
        ok scalar(grep { $_->[0] eq 'INFO' && $_->[1]{ACTION} eq 'maintain' } @log),
            "$bad dies: closing INFO summary still logged";
    }

    # Every phase failing at once: all reported, all attempted.
    reset_run();
    %die_in = map { $_ => 1 } qw(ping rotate broadcast expire purge);
    my ($ok, undef, $out) = run_maintain({ json => 1 });
    ok $ok, 'all phases failing: still no die';
    is_deeply [ err_phases() ], [ sort qw(ping rotate broadcast expire purge) ],
        'all phases failing: each one reported';
    is $LAST_EXIT, 1, 'all phases failing: exit status 1';
    my $aj = eval { decode_json($out) } || {};
    is $aj->{ok}, 0, 'all phases failing: json ok is 0';
    is_deeply $aj->{failed}, [ qw(ping rotate broadcast expire purge) ],
        'all phases failing: json lists every phase, in run order';
    ok scalar(grep { $_->[0] eq 'INFO' && $_->[1]{ACTION} eq 'maintain' } @log),
        'all phases failing: closing INFO summary still logged';

    # Text mode names the failed phases and still exits non-zero.
    reset_run();
    %die_in = map { $_ => 1 } qw(rotate purge);
    ($ok, undef, $out) = run_maintain({});
    is $LAST_EXIT, 1, 'text mode: exit status 1';
    like $out, qr/^Maintenance run: 2\/2 agents pinged, dispatcher cert checked\.$/m,
        'text mode: summary line kept';
    like $out, qr/^Maintenance FAILED in phase\(s\): rotate, purge$/m,
        'text mode: failed phases named';
};

# --- real phases against the temp tree --------------------------------------
subtest 'real phases: purge reaps expired run records only' => sub {
    reset_run();
    for my $f (qw(old fresh)) {
        open my $fh, '>', "$TMP/runs/$f.json" or die; print $fh '{}'; close $fh;
    }
    utime time() - 86400, time() - 86400, "$TMP/runs/old.json";
    # Real rotation/expire/broadcast run against a config with no cert/state.
    delete @phase_ran{qw(rotate broadcast expire)};
    my ($ok, $err) = run_maintain({});
    ok $ok, 'runs' or diag $err;
    is $LAST_EXIT, 0, 'real phases: exit status 0';
    ok !-e "$TMP/runs/old.json", 'expired record purged';
    ok -e "$TMP/runs/fresh.json", 'fresh record kept';
    is_deeply [ err_phases() ], [], 'real rotate/broadcast/expire/purge raised no ERR';
};

done_testing;
