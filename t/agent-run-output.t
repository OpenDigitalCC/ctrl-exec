#!/usr/bin/perl
# t/agent-run-output.t  (T-053)
#
# Confidential output at the agent: a script declared output=confidential in
# scripts.conf has its stdout and stderr returned to the caller, marked
# output_confidential so the dispatcher does not store them, with and without
# the executor (an unprivileged test build of src/ctrl-exec-executor.c, as in
# t/exec-input.t). No agent log line or executor log line carries the output,
# an async run of such a script is refused before anything is started or
# recorded, a normal script is unmarked and its async result stored as before,
# and a bad output= value skips the script in the front end and the executor.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Find qw(find);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

use Exec::Agent::Config     qw();
use Exec::Agent::Server     qw();
use Exec::Agent::ExecClient qw();
use Exec::Log               qw();

my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}
my $JSON = JSON::PP->new->canonical;

my $OUT = 'OUT-SENTINEL-53a1c9-privkey';
my $ERR = 'ERR-SENTINEL-53b7e2-privkey';

umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $dir = tempdir(CLEANUP => 1);
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
mkdir "$dir/s" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
sub slurp { my ($p) = @_; open my $fh, '<', $p or return undef; local $/; my $c = <$fh>; return $c }

# Both scripts print the sentinels on stdout and stderr and exit 3.
for my $n (qw(secret plain)) {
    write_file("$dir/s/$n.sh", "#!/bin/sh\ntouch '$dir/ran.$n'\necho '$OUT'\necho '$ERR' >&2\nexit 3\n", 0755);
}

write_file("$dir/scripts.conf", <<"CONF");
secret = $dir/s/secret.sh output=confidential
plain  = $dir/s/plain.sh
stored = $dir/s/plain.sh  output=stored
bad1   = $dir/s/secret.sh output=secret
bad2   = $dir/s/secret.sh output=
CONF
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full("$dir/scripts.conf", ["$dir/s"]);
}

my %config = (script_dirs => ["$dir/s"]);

sub post {
    my ($payload, %cfg) = @_;
    my $body = $JSON->encode($payload);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $cfg{allowlist} // $allowlist,
        { %config, map { $_ eq 'allowlist' ? () : ($_ => $cfg{$_}) } keys %cfg }, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    my ($head, $json) = split /\r\n\r\n/, $resp, 2;
    my ($code) = $head =~ m{^HTTP/\S+ (\d+)};
    return (JSON::PP::decode_json($json), $code);
}
sub run { my ($script, %o) = @_;
    @logs = ();
    my ($r) = post({ script => $script, args => [], reqid => 'r1', username => 'u', %o });
    return $r;
}
sub no_secret_in_logs {
    my ($label) = @_;
    unlike $JSON->encode(\@logs), qr/\Q$OUT\E|\Q$ERR\E/, "$label: no agent log line carries the output";
}
# Every regular file under $root, as path => content.
sub files_under {
    my ($root) = @_;
    my %f;
    find({ no_chdir => 1, wanted => sub { $f{$_} = slurp($_) // '' if -f $_ } }, $root) if -d $root;
    return \%f;
}

subtest 'parsing: output= stored|confidential, anything else skips the script' => sub {
    is Exec::Agent::Config::script_output_mode('secret', $allowlist), 'confidential', 'confidential';
    is Exec::Agent::Config::script_output_mode('plain',  $allowlist), 'stored', 'absent is stored';
    is Exec::Agent::Config::script_output_mode('stored', $allowlist), 'stored', 'explicit stored';
    ok !exists $allowlist->{bad1}, 'output=secret skipped';
    ok !exists $allowlist->{bad2}, 'empty output= skipped';
    is $skipped->{bad1}, "its output mode 'secret' is not one of stored, confidential", 'reason names the value';
    my $r = run('bad1');
    is $r->{exit}, -1, 'a run of a skipped entry is refused';
    like $r->{error}, qr/^script not permitted: its output mode 'secret'/, 'and says why';
};

subtest 'direct mode, sync: the caller gets the output, marked confidential' => sub {
    my $r = run('secret');
    is $r->{exit}, 3, 'ran';
    like $r->{stdout}, qr/\Q$OUT\E/, 'stdout reaches the caller';
    like $r->{stderr}, qr/\Q$ERR\E/, 'stderr reaches the caller';
    is $r->{output_confidential}, JSON::PP::true, 'marked output_confidential';
    no_secret_in_logs('direct');
    ok scalar(grep { ($_->{ACTION} // '') eq 'run' && ($_->{EXIT} // '') eq '3' } @logs), 'the run is logged (exit only)';
};

subtest 'a normal script is unmarked, its output returned as before' => sub {
    for my $s (qw(plain stored)) {
        my $r = run($s);
        is $r->{exit}, 3, "$s: ran";
        like $r->{stdout}, qr/\Q$OUT\E/, "$s: stdout returned";
        ok !exists $r->{output_confidential}, "$s: no output_confidential field";
    }
};

subtest 'async: refused for a confidential script, nothing started or recorded' => sub {
    my $runs = "$dir/runs";
    unlink "$dir/ran.secret";
    my ($r, $code) = post({ script => 'secret', args => [], reqid => 'aabbccdd53', async => JSON::PP::true },
                          async_runs_dir => $runs);
    is $code, 200, 'answered (not 202)';
    is $r->{exit}, -1, 'refused';
    ok !defined $r->{status}, 'not accepted';
    like $r->{error}, qr/output=confidential: its output is never stored, so it cannot run async; run it synchronously/,
        'the error says why and what to do';
    ok !-d $runs || !%{ files_under($runs) }, 'no record written in the agent run store';
    select undef, undef, undef, 0.3;
    ok !-e "$dir/ran.secret", 'the script was not started';
    no_secret_in_logs('async refused');
};

subtest 'async: a normal script is still stored agent-side as before' => sub {
    my $runs = "$dir/runs";
    my ($r, $code) = post({ script => 'plain', args => [], reqid => 'aabbccdd54', async => JSON::PP::true },
                          async_runs_dir => $runs);
    is $code, 202, 'accepted';
    my $rec;
    for (1 .. 100) {
        $rec = Exec::Agent::AsyncRunner::result('aabbccdd54', $runs, 'disp-1');
        last if $rec && ($rec->{status} // '') eq 'done';
        select undef, undef, undef, 0.05;
    }
    is $rec->{status}, 'done', 'done';
    like $rec->{stdout}, qr/\Q$OUT\E/, 'stdout stored as before';
};

subtest '/capabilities reports each script\'s output mode' => sub {
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die;
    print $client "GET /capabilities HTTP/1.0\r\n\r\n";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, \%config, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped);
    $server->close;
    local $/; my $resp = <$client>; $resp =~ s/\A.*?\r\n\r\n//s;
    my %mode = map { $_->{name} => $_->{output} } @{ JSON::PP::decode_json($resp)->{scripts} };
    is_deeply \%mode, { secret => 'confidential', plain => 'stored', stored => 'stored' }, 'modes reported';
};

# --- through the executor (unprivileged test build) ---------------------------

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
SKIP: {
    skip 'gcc not available', 1 unless $cc && -x $cc;
    my $BIN = "$dir/ctrl-exec-executor";
    skip 'could not compile src/ctrl-exec-executor.c', 1
        unless system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0;

    my $agent_conf = "$dir/agent.conf";
    write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $dir/s\n[profile default]\n");
    # The executor's own scripts.conf: as the agent's, plus an entry the agent
    # reads as valid but the executor's copy gives a bad output= value.
    my $exec_conf = "$dir/exec-scripts.conf";
    write_file($exec_conf, slurp("$dir/scripts.conf") . "drift = $dir/s/plain.sh output=nope\n");
    my $sock     = "$dir/exec.sock";
    my $exec_log = "$dir/executor.log";
    my $epid = fork // die "fork: $!";
    if (!$epid) {
        open STDERR, '>>', $exec_log or POSIX::_exit(127);
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $dir;
        exec($BIN, 'serve', $sock, $agent_conf, $exec_conf, scalar getpwuid($>))
            or POSIX::_exit(127);
    }
    my $up = 0;
    for (1 .. 100) { if (-S $sock) { $up = 1; last } select undef, undef, undef, 0.05 }

    subtest 'executor mode, sync: the caller gets the output, marked; no log carries it' => sub {
        ok $up, 'executor created its socket' or return;
        @logs = ();
        my ($r) = post({ script => 'secret', args => [], reqid => 'r2' }, executor_socket => $sock);
        is $r->{exit}, 3, 'ran through the executor';
        like $r->{stdout}, qr/\Q$OUT\E/, 'stdout reaches the caller';
        like $r->{stderr}, qr/\Q$ERR\E/, 'stderr reaches the caller';
        is $r->{output_confidential}, JSON::PP::true, 'marked output_confidential';
        no_secret_in_logs('executor');
        unlike slurp($exec_log) // '', qr/\Q$OUT\E|\Q$ERR\E/, "not in the executor's log";

        my ($p) = post({ script => 'plain', args => [], reqid => 'r3' }, executor_socket => $sock);
        is $p->{exit}, 3, 'a normal script runs through the executor';
        ok !exists $p->{output_confidential}, 'and is unmarked';

        my ($ar) = post({ script => 'secret', args => [], reqid => 'aabbccdd55', async => JSON::PP::true },
                        executor_socket => $sock, async_runs_dir => "$dir/runs2");
        like $ar->{error}, qr/output=confidential/, 'async of a confidential script is refused with the executor too';
    };

    subtest 'executor mode: a bad output= in the executor\'s scripts.conf skips the script there' => sub {
        ok $up, 'executor up' or return;
        my %al = (%$allowlist, drift => { path => "$dir/s/plain.sh", profile => 'default',
                                          input => 'context', output => 'stored' });
        my ($r) = post({ script => 'drift', args => [], reqid => 'r4' },
                       executor_socket => $sock, allowlist => \%al);
        is $r->{exit}, -1, 'not run';
        like $r->{stderr}, qr/executor: script not permitted/, 'the executor refuses it';
    };

    kill 'TERM', $epid; waitpid $epid, 0; unlink $sock;
}

done_testing;
