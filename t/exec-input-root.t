#!/usr/bin/perl
# t/exec-input-root.t  (T-013 piece 3)
#
# Confidential run input through the executor as root, under run_as profiles,
# with and without `writable` (the read-only mount namespace). Driven through
# the agent front end (Exec::Agent::Server with executor_socket), so the frame
# is the one the agent really sends. Checks, per mode and profile, what the
# action sees and as whom; that the run_as user can read its input files and
# another unprivileged user cannot; that the directory is gone after a normal
# exit, after the action is killed from outside (as a timeout would), and -
# after the handler itself is killed - at the next executor start-up; that the
# removal never follows a link the action made; and that the value is absent
# from every process's argv and environment while the action runs, and from the
# executor's log. Skips unless root (run it in tools/wedge-rig, or sudo prove).

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

plan skip_all => 'must run as root (run_as and the mount namespace need it)' unless $> == 0;
my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;
my @nobody = getpwnam('nobody');
plan skip_all => 'no "nobody" user to drop to' unless @nobody;
my ($RUN_UID, $RUN_GID) = @nobody[2, 3];
my @other;
for my $u (qw(ctrl-exec-agent daemon bin)) {
    my @pw = getpwnam($u);
    if (@pw && $pw[2] != 0 && $pw[2] != $RUN_UID) { @other = @pw; last }
}
plan skip_all => 'no second unprivileged user' unless @other;

require Exec::Agent::Config;
require Exec::Agent::Server;
require Exec::Log;
my @logs;
{
    no warnings qw(redefine once);
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}
my $JSON = JSON::PP->new->canonical;
my $SENTINEL = 'SENTINEL-root-5d0b2e-k3y-material-WV';

# /run, not /tmp: a `writable` profile mounts a private tmpfs on /tmp. The
# executor's input directory is <socket dir>/input, so the socket dir must be
# traversable by the run_as user (0755) and owned by root.
umask 022;
my $TMP = tempdir(DIR => '/run', CLEANUP => 1);
chmod 0755, $TMP;
my $BIN = "$TMP/ctrl-exec-executor";
system($cc, '-O2', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile the executor';
my $W = "$TMP/w";               # records from the actions; the writable carve-out
mkdir $W; chmod 0777, $W;
mkdir "$TMP/s";
my $base = "$TMP/input";

sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
sub slurp { my ($p) = @_; open my $fh, '<', $p or return undef; local $/; my $c = <$fh>; return $c }

my $record = <<'SH';
out="@W@/seen.$NAME"
{
  echo "--UID--"; id -u
  echo "--ARGV--"; for a in "$@"; do echo "$a"; done
  echo "--ENV--"; env
  echo "--STDIN--"; cat
  echo "--DIR--"
  if [ -n "$CTRL_EXEC_INPUT" ]; then
    stat -c '%a %u %n' "$CTRL_EXEC_INPUT"
    for f in "$CTRL_EXEC_INPUT"/*; do stat -c '%a %u %n' "$f"; echo "[$(cat "$f")]"; done
    if touch "$CTRL_EXEC_INPUT/new" 2>/dev/null; then echo "DIRWRITE=ok"; else echo "DIRWRITE=denied"; fi
  fi
} > "$out" 2>&1
SH
$record =~ s/\@W\@/$W/g;

my %body = (
    rec   => '',
    hold  => qq{echo \$\$ > "$W/pid.\$NAME"; echo "\$CTRL_EXEC_INPUT" > "$W/dir.\$NAME"\n}
           . qq{i=0; while [ ! -e "$W/go.\$NAME" ] && [ \$i -lt 600 ]; do sleep 0.1; i=\$((i+1)); done\n},
    links => qq{ln -s "$TMP/victim" "\$CTRL_EXEC_INPUT/link"\n}
           . qq{mkdir "\$CTRL_EXEC_INPUT/sub"; ln -s "$TMP/victimdir" "\$CTRL_EXEC_INPUT/sub/d"\n},
);
my $sc = '';
for my $kind (sort keys %body) {
    for my $prof (qw(plain conf)) {
        for my $mode ($kind eq 'rec' ? qw(ctx raw flds) : qw(flds)) {
            my $name = "$kind-$mode-$prof";
            write_file("$TMP/s/$name.sh", "#!/bin/sh\nNAME=$name\n$record$body{$kind}", 0755);
            my $im = { ctx => 'context', raw => 'raw:key', flds => 'fields' }->{$mode};
            $sc .= "$name = $TMP/s/$name.sh profile=$prof input=$im\n";
        }
    }
}
write_file("$TMP/victim", "keep me\n", 0644);
mkdir "$TMP/victimdir"; write_file("$TMP/victimdir/f", "keep me too\n", 0644);

my $agent_conf = "$TMP/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $TMP/s\n"
                      . "[profile default]\nrun_as = nobody\n"
                      . "[profile plain]\nrun_as = nobody\n"
                      . "[profile conf]\nrun_as = nobody\nwritable = $W\n");
my $scripts_conf = "$TMP/scripts.conf";
write_file($scripts_conf, $sc);
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$TMP/s"]);
}
is scalar(keys %$allowlist), 10, 'all test scripts allowlisted' or diag explain $skipped;

my $sock = "$TMP/exec.sock";
my $exec_log = "$TMP/exec.log";
my $epid;
sub start_executor {
    $epid = fork // die "fork: $!";
    if (!$epid) {
        open STDERR, '>>', $exec_log or POSIX::_exit(127);
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, 'root') or POSIX::_exit(127);
    }
    for (1 .. 100) { return 1 if -S $sock; select undef, undef, undef, 0.05 }
    return 0;
}
sub stop_executor { kill 'TERM', $epid; waitpid $epid, 0; unlink $sock }
ok start_executor(), 'executor created its socket' or do { done_testing; exit };

sub post {
    my ($payload) = @_;
    my $body = $JSON->encode($payload);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { script_dirs => ["$TMP/s"], executor_socket => $sock },
        {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return JSON::PP::decode_json($resp);
}
sub run { my ($script, %o) = @_;
    unlink "$W/seen.$script";
    return post({ script => $script, args => ['argone'], reqid => 'rr1', username => 'u',
                  token => 'tok', input => { key => $SENTINEL }, %o });
}
sub section { my ($text, $name) = @_; $text =~ /--\Q$name\E--\n(.*?)(?=--[A-Z]+--\n|\z)/s; return $1 // '' }
sub leftovers { opendir my $d, $base or return -1; my @e = grep { !/^\.\.?\z/ } readdir $d; return scalar @e }

# Read a file as another uid in a child; returns the content or 'DENIED:<errno>'.
sub read_as {
    my ($uid, $gid, $path) = @_;
    pipe my $r, my $w or die;
    my $pid = fork // die;
    if (!$pid) {
        close $r;
        POSIX::setgid($gid); $) = "$gid $gid"; POSIX::setuid($uid);
        my ($fh, $out);
        if ($> != $uid || $< != $uid)     { $out = 'NODROP' }
        elsif (open $fh, '<', $path)       { local $/; $out = <$fh> // '' }
        else                               { $out = 'DENIED:' . ($! + 0) }
        print $w $out; close $w; POSIX::_exit(0);
    }
    close $w; local $/; my $got = <$r>; waitpid $pid, 0;
    return $got;
}

# Every process's argv and environment, searched for the value.
sub value_in_proc {
    my @hits;
    opendir my $d, '/proc' or return ('/proc unreadable');
    for my $p (grep { /^\d+\z/ } readdir $d) {
        for my $f (qw(cmdline environ)) {
            my $c = slurp("/proc/$p/$f") // next;
            push @hits, "$p/$f" if index($c, $SENTINEL) >= 0;
        }
    }
    return @hits;
}

for my $prof (qw(plain conf)) {
    subtest "context, profile $prof: input on stdin, as the run_as user" => sub {
        my $r = run("rec-ctx-$prof");
        is $r->{exit}, 0, 'ran' or diag explain $r;
        my $seen = slurp("$W/seen.rec-ctx-$prof") // '';
        is section($seen, 'UID'), "$RUN_UID\n", 'ran as run_as';
        my $ctx = eval { JSON::PP::decode_json(section($seen, 'STDIN')) } // {};
        is $ctx->{input}{key}, $SENTINEL, 'stdin JSON carries input';
        unlike section($seen, 'ENV'), qr/^CTRL_EXEC_/m, 'no CTRL_EXEC_* variables';
    };
    subtest "raw:key, profile $prof: the field on stdin" => sub {
        my $r = run("rec-raw-$prof");
        is $r->{exit}, 0, 'ran' or diag explain $r;
        my $seen = slurp("$W/seen.rec-raw-$prof") // '';
        is section($seen, 'UID'), "$RUN_UID\n", 'ran as run_as';
        is section($seen, 'STDIN'), $SENTINEL, 'stdin is the field';
        my ($ctx) = section($seen, 'ENV') =~ /^CTRL_EXEC_CONTEXT=(.*)$/m;
        my $c = eval { JSON::PP::decode_json($ctx // '') } // {};
        is $c->{script}, "rec-raw-$prof", 'CTRL_EXEC_CONTEXT set';
        ok !exists $c->{token} && !exists $c->{input}, 'without token and input';
        unlike section($seen, 'ENV') . section($seen, 'ARGV'), qr/\Q$SENTINEL\E/, 'value not in env or argv';
    };
    subtest "fields, profile $prof: files owned by run_as, dir removed" => sub {
        my $r = run("rec-flds-$prof");
        is $r->{exit}, 0, 'ran' or diag explain $r;
        my $seen = slurp("$W/seen.rec-flds-$prof") // '';
        is section($seen, 'UID'), "$RUN_UID\n", 'ran as run_as';
        is section($seen, 'STDIN'), '', 'stdin empty';
        my $dirs = section($seen, 'DIR');
        my ($d) = $dirs =~ m{^700 \Q$RUN_UID\E (\Q$base\E/rr1\.[0-9a-f]{16})$}m;
        ok defined $d, 'directory 0700 owned by run_as' or diag $dirs;
        $d //= 'none';
        like $dirs, qr{^600 \Q$RUN_UID\E \Q$d\E/key\n\[\Q$SENTINEL\E\]$}m, 'file 0600 owned by run_as, readable by it';
        like $dirs, qr{^DIRWRITE=\Q${\ ($prof eq 'conf' ? 'denied' : 'ok')}\E$}m,
            $prof eq 'conf' ? 'read-only inside the writable profile\'s namespace' : 'its own directory';
        ok !-e $d, 'directory removed after normal exit';
        is leftovers(), 0, 'nothing left';
        unlike section($seen, 'ENV') . section($seen, 'ARGV'), qr/\Q$SENTINEL\E/, 'value not in env or argv';
    };
}

# A held run: the action waits for a go file so the test can look while it runs.
sub start_hold {
    my ($name) = @_;
    unlink "$W/pid.$name", "$W/dir.$name", "$W/go.$name", "$TMP/res.$name";
    my $pid = fork // die;
    if (!$pid) {
        my $r = run($name, reqid => "hold-$name");
        write_file("$TMP/res.$name", $JSON->encode($r));
        POSIX::_exit(0);
    }
    for (1 .. 200) { last if -s "$W/dir.$name" && -s "$W/pid.$name"; select undef, undef, undef, 0.05 }
    my $d = slurp("$W/dir.$name") // ''; chomp $d;
    my $p = slurp("$W/pid.$name") // ''; chomp $p;
    return ($pid, $d, $p);
}
sub finish_hold {
    my ($name, $pid) = @_;
    waitpid $pid, 0;
    return JSON::PP::decode_json(slurp("$TMP/res.$name") // '{}');
}

for my $prof (qw(plain conf)) {
    subtest "fields, profile $prof: run_as reads, another user cannot; value in no argv/env" => sub {
        my $name = "hold-flds-$prof";
        my ($pid, $d, $apid) = start_hold($name);
        like $d, qr{^\Q$base\E/hold-\Q$name\E\.[0-9a-f]{16}$}, 'action running with its directory';
        is read_as($RUN_UID, $RUN_GID, "$d/key"), $SENTINEL, 'the run_as user reads its file';
        like read_as(@other[2, 3], "$d/key"), qr/^DENIED:13$/, "another user ($other[0]) cannot (EACCES)";
        like read_as(@other[2, 3], "$base/"), qr/^DENIED:/, 'nor list the input directory';
        is_deeply [value_in_proc()], [], 'the value is in no process\'s argv or environment';
        my @st = stat $d;
        is sprintf('%o %d', $st[2] & 07777, $st[4]), "700 $RUN_UID", 'directory 0700 run_as (seen from outside)';
        write_file("$W/go.$name", '');
        my $r = finish_hold($name, $pid);
        is $r->{exit}, 0, 'finished';
        ok !-e $d, 'directory removed';
    };
}

subtest 'the action killed from outside (as a timeout kill): directory removed' => sub {
    my $name = 'hold-flds-plain';
    my ($pid, $d, $apid) = start_hold($name);
    ok -d $d, 'directory present while it runs';
    ok kill('KILL', $apid), 'SIGKILL the action';
    my $r = finish_hold($name, $pid);
    is $r->{exit}, 126, 'reported as killed';
    ok !-e $d, 'directory removed after the kill';
    is leftovers(), 0, 'nothing left';
};

subtest 'removal never follows a link the action made' => sub {
    my $r = run('links-flds-plain');
    is $r->{exit}, 0, 'ran' or diag explain $r;
    is leftovers(), 0, 'directory, links and subdirectory removed';
    is slurp("$TMP/victim"), "keep me\n", 'root file a link pointed at is intact';
    is slurp("$TMP/victimdir/f"), "keep me too\n", 'root directory a nested link pointed at is intact';
};

subtest 'handler killed mid-run: the next start-up removes the directory' => sub {
    my $name = 'hold-flds-plain';
    my ($pid, $d, $apid) = start_hold($name);
    ok -d $d, 'directory present';
    my ($handler) = (slurp("/proc/$apid/stat") // '') =~ /^\d+ \(.*\) \S (\d+)/;
    ok $handler, "handler pid $handler";
    kill 'KILL', $handler, $apid, $epid;
    waitpid $epid, 0;
    finish_hold($name, $pid);
    unlink $sock;
    ok -d $d, 'a crash leaves the directory behind';
    ok start_executor(), 'executor restarted';
    ok !-e $d, 'start-up sweep removed it';
    is leftovers(), 0, 'nothing left';
    like slurp($exec_log), qr/removed 1 stale input directory/, 'sweep logged as a count';
};

stop_executor();
unlike slurp($exec_log) // '', qr/\Q$SENTINEL\E/, 'the value is not in the executor log';
unlike $JSON->encode(\@logs), qr/\Q$SENTINEL\E/, 'the value is not in any agent log line';
done_testing;
