#!/usr/bin/perl
# t/dispatcher-run-output.t  (T-053)
#
# Confidential output on the `ced run` path (bin/ctrl-exec-dispatcher): the
# operator sees the output of a script whose agent marks it output_confidential,
# nothing is written under the runs dir and no log line carries it. An async
# run of such a script, refused by the agent, is recorded as an error with no
# output. `ced status` reads the record through Exec::RunStore::aggregate, whose
# handling of a confidential fetched result is in t/run-store.t.
#
# The agent UA, auth, lock, registry and config are stubbed; the run store is
# redirected to a temporary directory; each run is a forked child (mode_run
# exits).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use File::Temp qw(tempdir);
use File::Find qw(find);
use JSON::PP ();
use POSIX ();

{
    no warnings qw(redefine once);
    local *main::main = sub {};
    local $SIG{__WARN__} = sub { warn @_ unless $_[0] =~ /^Subroutine main redefined/ };
    do "$Bin/../bin/ctrl-exec-dispatcher";
    die "Could not load ctrl-exec-dispatcher: $@" if $@;
}

my $S_OUT = 'OUT-SENTINEL-ced53-5e8b';
my $S_ERR = 'ERR-SENTINEL-ced53-0c4d';
my $tmp      = tempdir(CLEANUP => 1);
my $runs_dir = "$tmp/runs";
my $log_file = "$tmp/log";

{
    package MockUA;
    sub new { bless {}, shift }
    sub post {
        my ($s, $url, %h) = @_;
        my $req = JSON::PP::decode_json($h{Content});
        my $body = $req->{async}
            ? { script => 'secret', exit => -1, reqid => $req->{reqid},
                error => "script 'secret' is output=confidential: its output is never stored, "
                       . 'so it cannot run async; run it synchronously' }
            : { script => 'secret', exit => 0, stdout => "$S_OUT\n", stderr => "$S_ERR\n",
                reqid => $req->{reqid}, output_confidential => JSON::PP::true };
        return HTTP::Response->new(200, 'OK', [ 'Content-Type' => 'application/json' ],
                                   JSON::PP::encode_json($body));
    }
}
require HTTP::Response;

{
    no warnings qw(redefine once);
    *Exec::Log::log_action = sub {
        my ($level, $fields) = @_;
        open my $fh, '>>', $log_file or die "$log_file: $!";
        print {$fh} join(' ', $level, map { "$_=" . ($fields->{$_} // '') } sort keys %$fields), "\n";
        close $fh;
    };
    *main::_load_config = sub { return {} };
    *Exec::Auth::check = sub { return { ok => 1 } };
    *Exec::Lock::check_available = sub { return { ok => 1 } };
    *Exec::Registry::resolve_dispatch = sub { return { ok => 1, hosts => [ @{ $_[0] } ] } };
    *Exec::Engine::_build_ua = sub { MockUA->new };
    my $rs = \&Exec::RunStore::record_sync;
    my $ra = \&Exec::RunStore::record_async;
    *Exec::RunStore::record_sync  = sub { $rs->(@_, runs_dir => $runs_dir) };
    *Exec::RunStore::record_async = sub { $ra->(@_, runs_dir => $runs_dir) };
}

sub slurp { open my $fh, '<', $_[0] or return ''; local $/; my $c = <$fh>; return $c // '' }
sub stored_files {
    my %f;
    find({ no_chdir => 1, wanted => sub { $f{$_} = slurp($_) if -f $_ } }, $runs_dir) if -d $runs_dir;
    return \%f;
}

# Run main::mode_run in a child; return (exit code, stdout).
sub ced_run {
    my ($opts, @args) = @_;
    unlink $log_file;
    my $out = "$tmp/out";
    my $pid = fork // die "fork: $!";
    if (!$pid) {
        open STDOUT, '>', $out or POSIX::_exit(99);
        open STDERR, '>', "$tmp/err" or POSIX::_exit(99);
        eval { main::mode_run($opts, @args) };
        POSIX::_exit(98);
    }
    waitpid $pid, 0;
    return ($? >> 8, slurp($out));
}

for my $json (0, 1) {
    my $label = $json ? 'ced run --json' : 'ced run';
    subtest "$label, sync: the operator sees the output; nothing stores or logs it" => sub {
        my ($code, $out) = ced_run({ json => $json }, 'h1', 'secret');
        is $code, 0, 'exit 0';
        like $out, qr/\Q$S_OUT\E/, 'stdout shown';
        like $out, qr/\Q$S_ERR\E/, 'stderr shown';
        my $files = stored_files();
        is scalar(grep { /\Q$S_OUT\E|\Q$S_ERR\E/ } values %$files), 0, 'no file under the runs dir holds it';
        my $log = slurp($log_file);
        like $log, qr/ACTION=run /, 'the run is logged';
        unlike $log, qr/\Q$S_OUT\E|\Q$S_ERR\E/, 'no log line holds it';
    };
}

subtest 'ced run --async: refused by the agent, recorded as an error' => sub {
    my ($code, $out) = ced_run({ async => 1, json => 1 }, 'h1', 'secret');
    is $code, 1, 'exit 1 (nothing accepted)';
    like $out, qr/run it synchronously/, 'the reason is shown';
    my $files = stored_files();
    is scalar(keys %$files), 1, 'one record';
    my ($rec) = map { JSON::PP::decode_json($_) } values %$files;
    is $rec->{hosts}{h1}{status}, 'error', 'host stored as error';
    ok $rec->{complete}, 'complete: nothing to fetch later';
    my $log = slurp($log_file);
    like $log, qr/ACTION=run-async .*STATUS=error/, 'logged STATUS=error';
    unlike $log, qr/STATUS=accepted/, 'not logged as accepted';
};

done_testing;
