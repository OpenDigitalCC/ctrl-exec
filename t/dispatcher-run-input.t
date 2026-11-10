#!/usr/bin/perl
# t/dispatcher-run-input.t  (T-086)
#
# `ced run --input-file / --input-field / --input-json` on the direct path
# (bin/ctrl-exec-dispatcher): the request carries the input to Exec::Engine as
# the API's does, Exec::Input validates it before the auth hook, the lock and
# any dispatch, and the values reach nothing but dispatch: not the hook (names
# and size only), not a log line, not the run store, not argv. The socket route
# is in t/dispatcher-api-socket.t.
#
# Auth, lock, registry, config and dispatch are stubbed; each run is a forked
# child (mode_run exits) with its stdin and stdout redirected.

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use File::Find qw(find);
use JSON::PP ();

{
    no warnings qw(redefine once);
    local *main::main = sub {};
    local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /^Subroutine main redefined/ };
    do "$Bin/../bin/ctrl-exec-dispatcher";
    die "Could not load ctrl-exec-dispatcher: $@" if $@;
}

my $SECRET = 'SECRET-SENTINEL-ced86-7d2f';
my $tmp    = tempdir(CLEANUP => 1);
my $log    = "$tmp/log";
my $seen   = "$tmp/seen";      # what the stubs received, one JSON line each
my $runs   = "$tmp/runs";

sub spew { open my $fh, '>', $_[0] or die "$_[0]: $!"; binmode $fh; print $fh $_[1]; close $fh }
sub slurp { open my $fh, '<', $_[0] or return ''; binmode $fh; local $/; my $c = <$fh>; $c // '' }

{
    no warnings qw(redefine once);
    *Exec::Log::log_action = sub {
        open my $fh, '>>', $log or die; print {$fh} join(' ', $_[0], map { "$_=" . ($_[1]{$_} // '') } sort keys %{$_[1]}), "\n";
    };
    *main::_load_config = sub { return { max_input_bytes => 100 } };
    *Exec::Auth::check = sub (%o) {
        open my $fh, '>>', $seen or die;
        print {$fh} JSON::PP::encode_json({ auth => { map { $_ => $o{$_} } qw(input_names input_bytes) },
                                            has_input => exists $o{input} ? 1 : 0 }), "\n";
        return { ok => 1 };
    };
    *Exec::Lock::check_available = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => [ @{ $_[0] } ] } };
    *Exec::Engine::dispatch_all = sub (%o) {
        open my $fh, '>>', $seen or die;
        print {$fh} JSON::PP::encode_json({ dispatch => { input => $o{input}, async => $o{async} } }), "\n";
        return [ { host => 'agent-01', exit => 0, rtt => '1ms', reqid => 'r1', stdout => "ok\n", stderr => '' } ];
    };
    my $rs = \&Exec::RunStore::record_sync;
    *Exec::RunStore::record_sync = sub { $rs->(@_, runs_dir => $runs) };
}

# Run mode_run in a child with the given stdin text; returns (stdout, stderr, exit).
sub run_ced {
    my ($stdin, $opts, @args) = @_;
    unlink $seen;
    spew("$tmp/stdin", $stdin // '');
    my $pid = fork() // die;
    if (!$pid) {
        open STDIN,  '<', "$tmp/stdin" or die;
        open STDOUT, '>', "$tmp/out"   or die;
        open STDERR, '>', "$tmp/err"   or die;
        eval { main::mode_run($opts, @args) };
        print STDERR $@ if $@;
        exit 1 if $@;
        exit 0;
    }
    waitpid $pid, 0;
    return (slurp("$tmp/out"), slurp("$tmp/err"), $? >> 8);
}
sub seen { [ map { JSON::PP::decode_json($_) } grep { length } split /\n/, slurp($seen) ] }
sub dispatched { my ($d) = grep { $_->{dispatch} } @{ seen() }; $d && $d->{dispatch} }

# --- raw from a file: field 'input' by default ---
spew("$tmp/doc", "line1\n$SECRET\n");
my ($out, $err, $rc) = run_ced('', { input_file => "$tmp/doc" }, 'agent-01', 'store');
is $rc, 0, 'file: exit 0' or diag $err;
is_deeply dispatched()->{input}, { input => "line1\n$SECRET\n" }, 'file: one field named input, whole content';
my ($auth) = grep { $_->{auth} } @{ seen() };
is_deeply $auth->{auth}{input_names}, ['input'], 'hook gets the field name';
is $auth->{auth}{input_bytes}, length("line1\n$SECRET\n"), 'and the size';
ok !$auth->{has_input}, 'never the value';

# --- from stdin, named field ---
($out, $err, $rc) = run_ced("from-stdin-$SECRET", { input_file => '-', input_field => 'key' }, 'agent-01', 'store');
is $rc, 0, 'stdin: exit 0' or diag $err;
is_deeply dispatched()->{input}, { key => "from-stdin-$SECRET" }, 'stdin, named field';

# --- UTF-8 text survives ---
spew("$tmp/u", "caf\xc3\xa9");
run_ced('', { input_file => "$tmp/u" }, 'agent-01', 'store');
is dispatched()->{input}{input}, "caf\x{e9}", 'UTF-8 decoded to characters';

# --- fields JSON ---
spew("$tmp/f.json", JSON::PP::encode_json({ approval => 'a1', secret => $SECRET }));
($out, $err, $rc) = run_ced('', { input_json => "$tmp/f.json" }, 'agent-01', 'store');
is $rc, 0, 'json: exit 0' or diag $err;
is_deeply dispatched()->{input}, { approval => 'a1', secret => $SECRET }, 'json: fields as given';
($out, $err, $rc) = run_ced(JSON::PP::encode_json({ a => 'b' }), { input_json => '-' }, 'agent-01', 'store');
is_deeply dispatched()->{input}, { a => 'b' }, 'json from stdin';

# --- refusals happen before auth, lock and dispatch ---
my @refusals = (
    [ 'both options',     '',     { input_file => "$tmp/doc", input_json => "$tmp/f.json" }, qr/mutually exclusive/ ],
    [ 'field without file', '',   { input_field => 'x' },                                    qr/--input-field needs --input-file/ ],
    [ 'async',            '',     { input_file => "$tmp/doc", async => 1 },                  qr/not available with --async/ ],
    [ 'invalid JSON',     "{ nope $SECRET", { input_json => '-' },                           qr/not valid JSON/ ],
    [ 'JSON not object',  '["x"]', { input_json => '-' },                                    qr/JSON object of string fields/ ],
    [ 'non-string value', '{"a":["x"]}', { input_json => '-' },                                  qr/field 'a' must be a string/ ],
    [ 'bad field name',   '{"a b":"x"}', { input_json => '-' },                              qr/field name is invalid/ ],
    [ 'empty object',     '{}',   { input_json => '-' },                                     qr/no fields/ ],
    [ 'over the limit',   'x' x 101, { input_file => '-' },                                  qr/input exceeds 100 bytes/ ],
    [ 'bad --input-field name', 'x', { input_file => '-', input_field => '../x' },           qr/field name is invalid/ ],
    [ 'missing file',     '',     { input_file => "$tmp/absent" },                           qr/cannot read/ ],
    [ 'not UTF-8',        "\xff\xfe", { input_file => '-' },                                 qr/not valid UTF-8/ ],
);
for my $c (@refusals) {
    my ($name, $stdin, $o, $re) = @$c;
    my ($so, $se, $r) = run_ced($stdin, $o, 'agent-01', 'store');
    isnt $r, 0, "$name: refused";
    like $se, $re, "$name: says why";
    is_deeply seen(), [], "$name: no hook, no dispatch";
    unlike $so . $se, qr/\Q$SECRET\E/, "$name: the value is not echoed";
}

# --- no input: nothing sent, as before ---
($out, $err, $rc) = run_ced('', {}, 'agent-01', 'store');
is $rc, 0, 'no input: exit 0';
ok !exists dispatched()->{input} || !defined dispatched()->{input}, 'no input key sent';
($auth) = grep { $_->{auth} } @{ seen() };
is_deeply $auth->{auth}{input_names}, [], 'hook sees no names';

# --- the value is nowhere else ---
run_ced('', { input_file => "$tmp/doc" }, 'agent-01', 'store');
unlike slurp($log), qr/\Q$SECRET\E/, 'not in any log line';
my $stored = '';
find({ no_chdir => 1, wanted => sub { $stored .= slurp($_) if -f $_ } }, $runs) if -d $runs;
unlike $stored, qr/\Q$SECRET\E/, 'not in the run store';

done_testing;
