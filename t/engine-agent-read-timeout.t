#!/usr/bin/perl
# t/engine-agent-read-timeout.t
#
# T-094: a per-agent read timeout. The registry record may carry
# read_timeout (seconds); the dispatcher waits that long for that agent and the
# global read_timeout for every other. Set with edit-agent/approve --read-timeout,
# refused when not a positive whole number; a bad value already on disk falls
# back to the global value with a logged warning. list-agents shows it.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use JSON qw(decode_json encode_json);

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

require Exec::Registry;
require Exec::Engine;
require Exec::Log;

my $TMP = tempdir(CLEANUP => 1);
my $dir = "$TMP/agents";
mkdir $dir;

# The dispatcher's CLI modes use the default registry dir; point them at ours.
my @log;
{
    no warnings qw(redefine once);
    no strict "refs";
    for my $fn (qw(edit_agent list_agents)) {
        my $real = \&{"Exec::Registry::$fn"};
        *{"Exec::Registry::$fn"} = sub { $real->(@_, registry_dir => $dir) };
    }
    *Exec::Log::log_action = sub { push @log, [@_] };
}

sub reg { Exec::Registry::register_agent(hostname => $_[0], ip => '10.0.0.1',
    registry_dir => $dir, @_[1 .. $#_]) }
sub rec { Exec::Registry::get_agent(hostname => $_[0], registry_dir => $dir) }
sub out (&) {
    my $code = shift;
    open my $save, '>&', \*STDOUT or die;
    close STDOUT;
    my $buf = '';
    open STDOUT, '>', \$buf or die;
    my $ok = eval { $code->(); 1 };
    my $err = $@;
    close STDOUT;
    open STDOUT, '>&', $save or die;
    return ($buf, $ok ? '' : $err);
}

my $cfg = { registry_dir => $dir, read_timeout => 45 };

reg('agent-01');
reg('agent-02', read_timeout => 600);

# --- the timeout the engine uses ---
is(Exec::Engine::_build_ua($cfg, 'agent-01')->timeout, 45, 'unset: the global read_timeout');
is(Exec::Engine::_build_ua($cfg, 'agent-02')->timeout, 600, 'set: the agent value');
is(Exec::Engine::_build_ua($cfg, 'unknown')->timeout, 45, 'not in the registry: the global value');
is(Exec::Engine::_build_ua($cfg)->timeout, 45, 'no name: the global value');
is(Exec::Engine::_build_ua({ registry_dir => $dir }, 'agent-01')->timeout, 60, 'no global either: 60');
is(Exec::Engine::_build_ua({ registry_dir => $dir, timeout => 20 }, 'agent-01')->timeout, 20,
    'deprecated global alias still honoured');
is(Exec::Engine::_build_ua({ registry_dir => $dir, read_timeout => 5 }, 'agent-02')->timeout, 600,
    'the agent value wins over a lower global one');

# --- validation ---
ok(Exec::Registry::valid_read_timeout($_), "valid: $_") for (1, 30, '300');
ok(!Exec::Registry::valid_read_timeout($_), 'invalid: ' . (defined $_ ? "'$_'" : 'undef'))
    for (0, -5, '1.5', 'abc', '', '10s', '0x10', ' 5', undef, [], {});

# --- edit-agent ---
my (undef, $err) = out { main::mode_edit_agent({ read_timeout => '300' }, 'agent-01') };
is $err, '', 'edit-agent --read-timeout 300 accepted';
is rec('agent-01')->{read_timeout}, 300, 'stored in the record';
is(Exec::Engine::_build_ua($cfg, 'agent-01')->timeout, 300, 'and used');
is rec('agent-01')->{ip}, '10.0.0.1', 'other fields untouched';

for my $bad (qw(0 -1 abc 1.5 10s), '') {
    (undef, $err) = out { main::mode_edit_agent({ read_timeout => $bad }, 'agent-01') };
    like $err, qr/--read-timeout must be a positive whole number/, "refused: '$bad'";
}
is rec('agent-01')->{read_timeout}, 300, 'a refused value changes nothing';

(undef, $err) = out { main::mode_edit_agent({ read_timeout => 'default' }, 'agent-01') };
is $err, '', "'default' accepted";
ok !exists rec('agent-01')->{read_timeout}, 'removes the field';
is(Exec::Engine::_build_ua($cfg, 'agent-01')->timeout, 45, 'back to the global value');

# --- approve refuses a bad value before doing anything ---
(undef, $err) = out { main::mode_approve({ read_timeout => 'x' }, 'deadbeef') };
like $err, qr/--read-timeout must be a positive whole number/, 'approve refuses a bad value';

# --- a bad value already on disk: global value, logged, never a crash ---
for my $bad ('soon', 0, -3, 1.5, [60]) {
    my $r = rec('agent-02');
    $r->{read_timeout} = $bad;
    open my $fh, '>', "$dir/agent-02.json" or die;
    print $fh encode_json($r);
    close $fh;
    @log = ();
    my $t = eval { Exec::Engine::_build_ua($cfg, 'agent-02')->timeout };
    is $t, 45, 'bad on disk (' . (ref $bad ? 'array' : $bad) . '): the global value, no crash';
    is scalar(grep { $_->[0] eq 'WARNING' && $_->[1]{ACTION} eq 'read-timeout-invalid'
                     && $_->[1]{AGENT} eq 'agent-02' } @log), 1, '  and a warning is logged';
}

# --- an older dispatcher reading a record that carries the field ---
# (the field is plain JSON beside the others; readers take what they know)
reg('agent-03', read_timeout => 90);
my $r = rec('agent-03');
is $r->{read_timeout}, 90, 'register_agent stores it';
is $r->{lookup_by}, 'hostname', 'alongside the usual fields';
eval { reg('agent-04', read_timeout => 'zero') };
like $@, qr/invalid read_timeout/, 'register_agent refuses a bad value';

# --- list-agents ---
my ($text) = out { main::mode_list_agents({}) };
like $text, qr/^agent-03 .*read_timeout=90s$/m, 'list-agents text shows the value when set';
unlike $text, qr/^agent-01 .*read_timeout/m, 'and nothing when unset';
my ($json) = out { main::mode_list_agents({ json => 1 }) };
my %by = map { $_->{hostname} => $_ } @{ decode_json($json) };
is $by{'agent-03'}{read_timeout}, 90, '--json: the field is added';
ok !exists $by{'agent-01'}{read_timeout}, '--json: absent when unset';
is $by{'agent-03'}{lookup_by}, 'hostname', '--json: existing fields unchanged';

done_testing;
