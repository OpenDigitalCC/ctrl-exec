#!/usr/bin/perl
# t/exec-script-dispatchers.t  (T-063)
#
# The C executor enforces scripts.conf 'dispatchers=' from its own read of
# scripts.conf, as it does input=: a limited script runs only when the frame's
# dispatcher id (the id the agent resolved from its trusted map for the
# connection) is in the list. Unprivileged test build (CE_TEST_SEAM,
# CTRL_EXEC_EXEC_ALLOW_UNPRIV). Frames are sent directly (bypassing the agent's
# own check) and through the agent front end with a stale allowlist, so the
# executor's refusal is shown to stand on its own.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

use Exec::Agent::Config     qw();
use Exec::Agent::Server     qw();
use Exec::Agent::ExecClient qw();
use Exec::Log               qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { };
}

umask 022;
my $dir = ChildGuard::dir(tempdir(CLEANUP => 1));
my $BIN = "$dir/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
mkdir "$dir/s" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }

for my $n (qw(open lim)) {
    write_file("$dir/s/$n.sh", "#!/bin/sh\necho ran-$n\n", 0755);
}
my $agent_conf = "$dir/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $dir/s\n[profile default]\n");
my $scripts_conf = "$dir/scripts.conf";
write_file($scripts_conf, <<"CONF");
open = $dir/s/open.sh
lim  = $dir/s/lim.sh dispatchers=d1,d-3
late = $dir/s/open.sh
CONF

my $sock = "$dir/exec.sock";
my $epid;
sub start_executor {
    $epid = ChildGuard::guarded_fork() // die "fork: $!";
    if (!$epid) {
        open STDERR, '>>', "$dir/executor.log" or POSIX::_exit(127);
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $dir;
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, scalar getpwuid($>))
            or POSIX::_exit(127);
    }
    for (1 .. 100) { return 1 if -S $sock; select undef, undef, undef, 0.05 }
    return 0;
}
END { local $?; if ($epid) { kill 'TERM', $epid; waitpid $epid, 0 } }
ok start_executor(), 'executor created its socket' or do { done_testing; exit };

sub frame {
    my ($script, $disp, %o) = @_;
    return Exec::Agent::ExecClient::run(socket => $sock, reqid => 'r1', script => $script,
        stdin => '{}', (defined $disp ? (dispatcher_id => $disp) : ()), %o);
}

subtest 'a listed dispatcher runs the script' => sub {
    for my $d (qw(d1 d-3)) {
        my $r = frame('lim', $d);
        is $r->{exit}, 0, "$d runs lim" or diag explain $r;
        like $r->{stdout}, qr/ran-lim/, 'it ran';
    }
};

subtest 'any other dispatcher id is refused by the executor' => sub {
    my $r = frame('lim', 'd2');
    is $r->{exit}, -1, 'd2 refused';
    is $r->{stderr}, "executor: script not permitted for dispatcher 'd2'\n", 'names the dispatcher';
    is $r->{stdout}, '', 'nothing ran';
    for my $c (['', 'empty'], [undef, 'absent'], ["d1\0x", 'NUL inside'], ['d1,d2', 'a list'],
               ['D1', 'case differs'], ['d', 'a prefix'], ['d1 ', 'trailing space'],
               ['x' x 65, 'too long']) {
        my ($d, $lbl) = @$c;
        my $r = frame('lim', $d);
        is $r->{exit}, -1, "$lbl: refused";
        like $r->{stderr}, qr/^executor: script not permitted/, "$lbl: not permitted";
        unlike $r->{stdout}, qr/ran-/, "$lbl: nothing ran";
    }
};

subtest 'the v2 frame (run input) is held to the same limit' => sub {
    my $r = frame('lim', 'd2', context => '{}', input => { k => 'v' });
    is $r->{exit}, -1, 'refused';
    is $r->{stderr}, "executor: script not permitted for dispatcher 'd2'\n", 'names the dispatcher';
    $r = frame('lim', 'd1', context => '{}', input => { k => 'v' });
    is $r->{exit}, 0, 'd1 runs it with input';
};

subtest 'no dispatchers= = every dispatcher, as before' => sub {
    for my $d ('d1', 'd2', '', undef) {
        my $r = frame('open', $d);
        is $r->{exit}, 0, 'open runs for ' . ($d // 'no id') or diag explain $r;
    }
};

subtest 'the executor refuses even when the agent allowed the run' => sub {
    # The agent loaded scripts.conf before 'late' was limited (a stale
    # allowlist): it lets d2 through; the executor reads the file afresh.
    my ($allowlist, $skipped);
    {
        local $SIG{__WARN__} = sub {};
        ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$dir/s"]);
    }
    open my $fh, '>>', $scripts_conf or die; print $fh "late = $dir/s/open.sh dispatchers=d1\n"; close $fh;

    my $body = '{"script":"late","args":[],"reqid":"r2"}';
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist,
        { script_dirs => ["$dir/s"], executor_socket => $sock }, {},
        { bb02 => 'd2' }, 'bb02', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $resp =~ s/\A.*?\r\n\r\n//s;
    my $r = JSON::PP::decode_json($resp);
    is $r->{exit}, -1, 'refused';
    is $r->{stderr}, "executor: script not permitted for dispatcher 'd2'\n",
        'by the executor, naming the id the agent resolved';
};

done_testing;
