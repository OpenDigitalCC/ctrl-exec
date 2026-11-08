#!/usr/bin/perl
# t/exec-script-path.t  (T-074)
#
# The PATH an action gets under the executor. Unset script_path: the fixed
# default, exactly as before. A valid script_path in the executor's own
# agent.conf: that PATH. An invalid one: the default, and a warning on the
# executor's stderr - the executor still starts and serves. A changed
# agent.conf is re-read (mtime) and the new PATH applies to the next run.
# Nothing from the request (args, stdin, input fields) or the executor's own
# environment reaches PATH.
#
# Runs unprivileged (CTRL_EXEC_EXEC_ALLOW_UNPRIV, the 'default' profile with no
# run_as), so no root is needed. The front end's parse of the same values is
# compared with the executor's in t/exec-conformance.t.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib", "$Bin/lib";
use ChildGuard ();
use POSIX      qw();

use Exec::Agent::ExecClient qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my $DEFAULT = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

my $TMP = ChildGuard::dir(tempdir(CLEANUP => 1));
umask 022;
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';

sub write_file { my ($p, $c) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh }

# The probe prints its PATH, then its arguments and stdin, so a test can see
# that a request value reached the script but not PATH.
my $probe = "$TMP/probe.sh";
write_file($probe, "#!/bin/sh\nprintf 'PATH=[%s]\\n' \"\$PATH\"\n");
chmod 0755, $probe;

my $scripts_conf = "$TMP/scripts.conf";
write_file($scripts_conf, "probe = $probe\nfields = $probe input=fields\n");

my $agent_conf = "$TMP/agent.conf";
my $mtime = time;
sub set_conf {
    my ($extra) = @_;
    write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP\n"
                          . $extra . "[profile default]\n");
    $mtime += 10;                      # a distinct mtime: the serve loop reloads on change
    utime $mtime, $mtime, $agent_conf;
}

my $sock = "$TMP/exec.sock";
my $err  = "$TMP/executor.err";
my $user = getpwuid($>);

sub start {
    unlink $sock;
    my $pid = ChildGuard::guarded_fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) {
        # The executor's own environment, polluted: none of it may reach the action.
        $ENV{PATH} = '/evil/inherited:' . ($ENV{PATH} // '');
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $TMP;
        open STDERR, '>>', $err or POSIX::_exit(127);
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, $user) or POSIX::_exit(127);
    }
    for (1 .. 100) { last if -S $sock; select undef, undef, undef, 0.05 }
    return $pid;
}
sub stop { my ($pid) = @_; kill 'TERM', $pid; waitpid $pid, 0 }

sub path_of {
    my (%o) = @_;
    my $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'p', script => 'probe',
                                         args => [], %o);
    my ($p) = ($r->{stdout} // '') =~ /^PATH=\[(.*)\]$/m;
    return ($p, $r);
}
sub slurp { open my $fh, '<', $_[0] or return ''; local $/; scalar <$fh> }

subtest 'script_path unset: the fixed default PATH, as before' => sub {
    set_conf('');
    my $pid = start();
    ok -S $sock, 'executor serving' or return stop($pid);
    my ($p, $r) = path_of();
    is $r->{exit}, 0, 'the probe ran' or diag explain $r;
    is $p, $DEFAULT, 'PATH is the default';
    stop($pid);
};

subtest 'script_path set: the action gets it; a reload follows a change' => sub {
    set_conf("script_path = /run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin\n");
    my $pid = start();
    ok -S $sock, 'executor serving' or return stop($pid);
    my ($p) = path_of();
    is $p, '/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin', 'PATH is script_path';

    set_conf("script_path = /opt/tools/bin:/usr/bin:/bin\n");
    ($p) = path_of();
    is $p, '/opt/tools/bin:/usr/bin:/bin', 'a changed script_path applies to the next run';

    set_conf('');
    ($p) = path_of();
    is $p, $DEFAULT, 'removed again: back to the default';
    stop($pid);
};

subtest 'no request value reaches PATH' => sub {
    set_conf("script_path = /usr/bin:/bin\n");
    my $pid = start();
    ok -S $sock, 'executor serving' or return stop($pid);
    my ($p, $r) = path_of(args => ['PATH=/evil/arg'], stdin => qq({"PATH":"/evil/stdin"}\n),
                          context => qq({"PATH":"/evil/context"}));
    is $p, '/usr/bin:/bin', 'args, stdin and context leave PATH alone';
    unlike $r->{stdout}, qr{/evil}, 'nothing of the request or the executor env in PATH';

    my $f = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'f', script => 'fields',
        args => [], context => '{}', input => { PATH => '/evil/field' });
    my ($fp) = ($f->{stdout} // '') =~ /^PATH=\[(.*)\]$/m;
    is $fp, '/usr/bin:/bin', 'an input field named PATH leaves PATH alone'
        or diag explain $f;
    stop($pid);
};

# Each invalid value: the executor starts, serves, and the action gets the
# default; the reason is on the executor's stderr.
my @bad = (
    ['relative entry',        'usr/bin:/bin',        'entry 1 is not an absolute path'],
    ['empty entry',           '/usr/bin::/bin',      'entry 2 is empty'],
    ['trailing colon',        '/usr/bin:',           'entry 2 is empty'],
    ['dot-dot component',     '/usr/bin:/opt/../bin', 'entry 2 has a . or .. component'],
    ['space inside',          '/usr/my bin',         'entry 1 has a character outside A-Z a-z 0-9 / . _ + -'],
    ['too long',              '/' . ('a' x 4090),    'longer than 4090 bytes'],
);
for my $b (@bad) {
    my ($label, $value, $why) = @$b;
    subtest "invalid script_path ($label): default PATH, a warning, still serving" => sub {
        unlink $err;
        set_conf("script_path = $value\n");
        my $pid = start();
        ok -S $sock, 'executor serving (an invalid script_path does not stop it)' or return stop($pid);
        my ($p, $r) = path_of();
        is $r->{exit}, 0, 'the probe ran' or diag explain $r;
        is $p, $DEFAULT, 'PATH is the default';
        stop($pid);
        like slurp($err), qr{invalid script_path in '\Q$agent_conf\E' \(\Q$why\E\) - using the default PATH},
            'the reason is on stderr';
    };
}

done_testing;
