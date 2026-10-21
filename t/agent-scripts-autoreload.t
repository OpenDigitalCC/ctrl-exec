#!/usr/bin/perl
# t/agent-scripts-autoreload.t  (T-059)
#
# A running agent picks up an edit to scripts.conf (and agent.conf) at the next
# connection, with no SIGHUP, so it and the executor - which reads both files
# afresh for every run - act on the same file. In the field a context script
# was refused after input=fields was edited into scripts.conf, because the
# agent still held the copy it loaded at start-up ("takes input=fields but the
# agent sent no input"). Unprivileged: a real agent (t/lib/AgentRig) with
# executor_socket set to a test build of the executor (CTRL_EXEC_EXEC_ALLOW_UNPRIV)
# reading the same agent.conf and scripts.conf. Also: an entry naming an
# undefined profile skips only that entry, and a line pasted with non-breaking
# spaces just works (one config-nonascii-space notice per load).

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use JSON::PP ();
use POSIX qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;
require AgentRig;
plan skip_all => 'openssl not available' unless AgentRig::available();

umask 022;
my $rig = AgentRig->new;
my $d   = $rig->{dir};
my $BIN = "$d/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';

sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
mkdir "$d/s" or die;
for my $n (qw(ctx added)) {
    write_file("$d/s/$n.sh", qq{#!/bin/sh\necho "$n mode=\${CTRL_EXEC_INPUT:+fields}\${CTRL_EXEC_INPUT:-context}"\n}, 0755);
}
my $sock = "$d/exec.sock";
$rig->set_conf("executor_socket = $sock\nscript_dirs = $d/s\n");
sub scripts { write_file($rig->{allow}, $_[0]) }
scripts("ctx = $d/s/ctx.sh\n");

my $epid = ChildGuard::guarded_fork() // die "fork: $!";
if (!$epid) {
    open STDERR, '>>', "$d/executor.log" or POSIX::_exit(127);
    $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
    $ENV{CE_TEST_TRUSTED_UID} = $>;
    $ENV{CE_TEST_TRUSTED_TOP} = $d;
    exec($BIN, 'serve', $sock, $rig->{conf}, $rig->{allow}, scalar getpwuid($>))
        or POSIX::_exit(127);
}
for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.05 }
ok -S $sock, 'executor started' or BAIL_OUT('executor did not start');
ok $rig->start, 'agent started' or BAIL_OUT('agent did not start: ' . $rig->log_text);

my $JSON = JSON::PP->new;
my $n = 0;
sub run_script {
    my ($script) = @_;
    my ($status, $body) = $rig->call(POST => '/run',
        $JSON->encode({ script => $script, args => [], reqid => 'r' . ++$n }));
    my $data = eval { $JSON->decode($body // '') } // {};
    return { http => $status // 0, %$data };
}

my $r = run_script('ctx');
is $r->{exit}, 0, 'ctx runs before any edit';
like $r->{stdout}, qr/ctx mode=context/, 'as input=context';

subtest 'input=fields edited in and a script added: used by the next run, no reload' => sub {
    my $from = $rig->log_len;
    scripts("ctx = $d/s/ctx.sh input=fields\nadded = $d/s/added.sh\n");
    my $r = run_script('ctx');
    is $r->{exit}, 0, 'ctx runs' or diag explain $r;
    like $r->{stdout}, qr/ctx mode=fields/, 'with the edited mode: the executor made the fields directory';
    unlike $r->{stderr} // '', qr/scripts\.conf declares|no input/, 'no mismatch refusal';
    ok $rig->wait_log(qr/ACTION=allowlist-reload REASON=changed/, 5, $from), 'the reload is logged';
    $r = run_script('added');
    is $r->{exit}, 0, 'the added script runs';
    my ($status, $body) = $rig->call(GET => '/capabilities');
    like $body // '', qr/"added"/, 'and is in the capabilities';
    my $log = substr($rig->log_text, $from);
    is scalar(() = $log =~ /ACTION=allowlist-reload REASON=changed/g), 1,
        'one reload for one edit, not one per connection';
};

subtest 'a script removed: refused at the next run' => sub {
    scripts("ctx = $d/s/ctx.sh input=fields\n");
    my $r = run_script('added');
    is $r->{exit}, -1, 'refused';
    like $r->{error} // '', qr/script not permitted: not in scripts\.conf/, 'not in scripts.conf';
};

subtest 'an undefined profile skips only that entry' => sub {
    my $from = $rig->log_len;
    scripts("ctx = $d/s/ctx.sh\nbad = $d/s/added.sh profile=ghost\nadded = $d/s/added.sh\n");
    my $r = run_script('bad');
    is $r->{exit}, -1, 'that entry is refused';
    like $r->{error} // '', qr/script not permitted: profile 'ghost' is not defined in agent\.conf/,
        'with the reason';
    ok $rig->wait_log(qr/ACTION=allowlist-skip REASON="profile 'ghost' is not defined in agent\.conf" SCRIPT=bad/, 5, $from),
        'logged as a skipped entry';
    unlike substr($rig->log_text, $from), qr/reload-fail/, 'the reload did not fail';
    $r = run_script('added');
    is $r->{exit}, 0, 'the other entries load and run';
    like run_script('ctx')->{stdout} // '', qr/ctx mode=context/, 'ctx back to context';
};

subtest 'a line pasted with non-breaking spaces just works' => sub {
    my $from = $rig->log_len;
    scripts("ctx\xC2\xA0=\xC2\xA0$d/s/ctx.sh\xE2\x80\xAFinput=fields\xC2\xA0\n");
    my $r = run_script('ctx');
    is $r->{exit}, 0, 'runs' or diag explain $r;
    like $r->{stdout}, qr/ctx mode=fields/, 'input=fields read through the NBSPs, by both parsers';
    my $log = $rig->wait_log(qr/ACTION=config-nonascii-space/, 5, $from) // '';
    like $log, qr/ACTION=config-nonascii-space FILE=\Q$rig->{allow}\E LINES=1/, 'one notice for the file';
    run_script('ctx');
    is scalar(() = substr($rig->log_text, $from) =~ /config-nonascii-space/g), 1,
        'once per load, not per run';
};

subtest 'SIGHUP still reloads' => sub {
    my $from = $rig->log_len;
    $rig->hup;
    ok $rig->wait_log(qr/ACTION=allowlist-reload REASON=signal/, 5, $from), 'logged';
    is run_script('ctx')->{exit}, 0, 'still serving';
};

$rig->stop;
kill 'TERM', $epid; waitpid $epid, 0;
done_testing;
