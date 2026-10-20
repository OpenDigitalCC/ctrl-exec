#!/usr/bin/perl
# t/exec-input.t  (T-013 piece 3)
#
# Confidential run input through the C executor, unprivileged (a test build,
# CTRL_EXEC_EXEC_ALLOW_UNPRIV, profiles without run_as; the run_as and
# `writable` paths are in t/exec-input-root.t). The agent front end
# (Exec::Agent::Server) is driven with executor_socket set, so the whole path is
# exercised: Server -> ExecClient frame v2 -> executor -> script. For each
# input= mode the script sees exactly the designed stdin, environment and files;
# the value is nowhere else (argv, other environment, the executor's own log,
# replies, agent log lines, the hook); the fields directory is gone after a
# normal exit and after a kill; the executor sweeps leftovers at start-up and
# never follows a link while removing. The frame's bounds are checked in C, the
# mode comes from the executor's own scripts.conf, and an old executor is
# reported cleanly.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP ();
use POSIX qw();

use Exec::Agent::Config     qw();
use Exec::Agent::Server     qw();
use Exec::Agent::ExecClient qw();
use Exec::Log               qw();

my $cc = `command -v gcc 2>/dev/null`; chomp $cc;
plan skip_all => 'gcc not available' unless $cc && -x $cc;

my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}
my $JSON = JSON::PP->new->canonical;

my $SENTINEL = 'SENTINEL-c41e07-s3cr3t-XK';
my $OTHER    = 'SECOND-9a2f61-v4lu3-QM';

umask 022;   # nothing group-writable: the executor refuses it (T-045)
my $dir = tempdir(CLEANUP => 1);
my $BIN = "$dir/ctrl-exec-executor";
system($cc, '-O2', '-DCE_TEST_SEAM', '-o', $BIN, "$Bin/../src/ctrl-exec-executor.c", '-lcap') == 0
    or plan skip_all => 'could not compile src/ctrl-exec-executor.c';
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
mkdir "$dir/s" or die;
mkdir "$dir/out" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }
sub slurp { my ($p) = @_; open my $fh, '<', $p or return undef; local $/; my $c = <$fh>; return $c }

# Every script records what it saw in $dir/out/seen.<name>: argv, the whole
# environment, stdin, and (when CTRL_EXEC_INPUT is set) each file with its mode.
for my $n (qw(ctx rawone rawnamed flds killed links)) {
    my $extra = $n eq 'killed' ? qq{kill -9 \$\$\n}
              : $n eq 'links'  ? qq{ln -s "$dir/victim" "\$CTRL_EXEC_INPUT/link"\n}
                               . qq{mkdir "\$CTRL_EXEC_INPUT/sub"; ln -s "$dir/victimdir" "\$CTRL_EXEC_INPUT/sub/d"\n}
                               . qq{mkfifo "\$CTRL_EXEC_INPUT/fifo"\n}
                               : '';
    write_file("$dir/s/$n.sh", <<"SH", 0755);
#!/bin/sh
out="$dir/out/seen.$n"
{
  echo "--ARGV--"; for a in "\$@"; do echo "\$a"; done
  echo "--ENV--"; env
  echo "--STDIN--"; cat
  echo "--DIR--"
  if [ -n "\$CTRL_EXEC_INPUT" ]; then
    stat -c '%a %n' "\$CTRL_EXEC_INPUT"
    for f in "\$CTRL_EXEC_INPUT"/*; do stat -c '%a %n' "\$f"; echo "[\$(cat "\$f")]"; done
    echo "\$CTRL_EXEC_INPUT" > "$dir/out/lastdir.$n"
  fi
} > "\$out" 2>&1
$extra
SH
}
write_file("$dir/victim", "keep me\n", 0644);
mkdir "$dir/victimdir"; write_file("$dir/victimdir/f", "keep me too\n", 0644);

my $agent_conf = "$dir/agent.conf";
write_file($agent_conf, "port = 7443\ncert = /x\nkey = /y\nca = /z\nscript_dirs = $dir/s\n[profile default]\n");
my $scripts_conf = "$dir/scripts.conf";
write_file($scripts_conf, <<"CONF");
ctx      = $dir/s/ctx.sh
rawone   = $dir/s/rawone.sh   input=raw
rawnamed = $dir/s/rawnamed.sh input=raw:key
flds     = $dir/s/flds.sh     input=fields
killed   = $dir/s/killed.sh   input=fields
links    = $dir/s/links.sh    input=fields
CONF
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full($scripts_conf, ["$dir/s"]);
}

# An auth hook that records its environment and stdin JSON.
write_file("$dir/hook.sh", <<"SH", 0755);
#!/bin/sh
{ env; echo "--STDIN--"; cat; } > "$dir/out/hook.seen"
exit 0
SH

my $sock    = "$dir/exec.sock";
my $exec_log = "$dir/out/executor.log";
my $base    = "$dir/input";
my $epid;
sub start_executor {
    $epid = fork // die "fork: $!";
    if (!$epid) {
        open STDERR, '>>', $exec_log or POSIX::_exit(127);
        $ENV{CTRL_EXEC_EXEC_ALLOW_UNPRIV} = 1;
        $ENV{CE_TEST_TRUSTED_UID} = $>;
        $ENV{CE_TEST_TRUSTED_TOP} = $dir;
        exec($BIN, 'serve', $sock, $agent_conf, $scripts_conf, scalar getpwuid($>))
            or POSIX::_exit(127);
    }
    for (1 .. 100) { return 1 if -S $sock; select undef, undef, undef, 0.05 }
    return 0;
}
sub stop_executor { kill 'TERM', $epid; waitpid $epid, 0; unlink $sock }
ok start_executor(), 'executor created its socket' or do { done_testing; exit };

my %config = (script_dirs => ["$dir/s"], auth_hook => "$dir/hook.sh",
              executor_socket => $sock);

sub post {
    my ($payload, %cfg) = @_;
    my $body = $JSON->encode($payload);
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { %config, %cfg }, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/;
    my $resp = <$client> // '';
    $client->close;
    $resp =~ s/\A.*?\r\n\r\n//s;
    return JSON::PP::decode_json($resp);
}
sub run { my ($script, $input, %o) = @_;
    unlink "$dir/out/seen.$script", "$dir/out/hook.seen";
    @logs = ();
    return post({ script => $script, args => ['argone'], reqid => 'r1', username => 'u',
                  token => 'tok-abc', (defined $input ? (input => $input) : ()), %o });
}
sub section { my ($text, $name) = @_; $text =~ /--\Q$name\E--\n(.*?)(?=--[A-Z]+--\n|\z)/s; return $1 // '' }
sub leftovers { opendir my $d, $base or return -1; my @e = grep { !/^\.\.?\z/ } readdir $d; return scalar @e }

# Nothing but the designed channels may carry a value.
sub not_elsewhere {
    my ($script, $label, $r) = @_;
    my $seen = slurp("$dir/out/seen.$script") // '';
    unlike section($seen, 'ARGV'), qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in argv";
    unlike section($seen, 'ENV'),  qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in the script's environment";
    my $hook = slurp("$dir/out/hook.seen") // '';
    ok length $hook, "$label: the hook ran";
    unlike $hook, qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in the hook's environment or stdin";
    unlike $JSON->encode(\@logs), qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in any agent log line";
    unlike slurp($exec_log) // '', qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in the executor's log";
    unlike $JSON->encode($r), qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in the reply";
}

subtest 'start-up: the input directory exists, 0711, owned by the executor user' => sub {
    my @st = stat $base;
    ok @st && -d _, "$base exists";
    is sprintf('%o', $st[2] & 07777), '711', 'mode 0711: reachable by name, not listable';
    is $st[4], $>, 'owned by the executor user';
};

subtest 'context: the input rides in the stdin JSON, with the token' => sub {
    my $r = run('ctx', { key => $SENTINEL, other => $OTHER });
    is $r->{exit}, 0, 'ran' or diag explain $r;
    my $seen = slurp("$dir/out/seen.ctx");
    my $ctx = JSON::PP::decode_json(section($seen, 'STDIN'));
    is_deeply $ctx->{input}, { key => $SENTINEL, other => $OTHER }, 'stdin JSON has input';
    is $ctx->{token}, 'tok-abc', 'context mode keeps the token on stdin';
    unlike section($seen, 'ENV'), qr/^CTRL_EXEC_(?:CONTEXT|INPUT)=/m, 'no CTRL_EXEC_* variables';
    unlike section($seen, 'ENV'), qr/\Q$SENTINEL\E/, 'value not in env';
    unlike section($seen, 'ARGV'), qr/\Q$SENTINEL\E/, 'value not in argv';
    unlike slurp($exec_log) // '', qr/\Q$SENTINEL\E/, 'value not in the executor log';
};

subtest 'context without input: the old frame, unchanged stdin' => sub {
    my $r = run('ctx', undef);
    is $r->{exit}, 0, 'ran';
    my $ctx = JSON::PP::decode_json(section(slurp("$dir/out/seen.ctx"), 'STDIN'));
    ok !exists $ctx->{input}, 'no input key';
    is $ctx->{script}, 'ctx', 'context JSON on stdin';
};

subtest 'raw: stdin is the one field; context in CTRL_EXEC_CONTEXT, no token' => sub {
    my $r = run('rawone', { only => "$SENTINEL\nline2\0bin" });
    is $r->{exit}, 0, 'ran' or diag explain $r;
    my $seen = slurp("$dir/out/seen.rawone");
    is section($seen, 'STDIN'), "$SENTINEL\nline2\0bin", 'stdin is exactly the field bytes (NUL included)';
    my ($ctx) = section($seen, 'ENV') =~ /^CTRL_EXEC_CONTEXT=(.*)$/m;
    ok defined $ctx, 'CTRL_EXEC_CONTEXT set';
    my $c = JSON::PP::decode_json($ctx);
    is $c->{script}, 'rawone', 'context names the script';
    is_deeply $c->{args}, ['argone'], 'context has the args';
    ok !exists $c->{input}, 'no input in it';
    ok !exists $c->{token}, 'no token in it';
    unlike section($seen, 'ENV'), qr/^CTRL_EXEC_INPUT=/m, 'no CTRL_EXEC_INPUT';
    not_elsewhere('rawone', 'raw', $r);
};

subtest 'raw: the executor requires exactly one field (its own check)' => sub {
    # Frame sent directly, bypassing the agent's own check.
    for my $in ({}, { a => 'x', b => 'y' }) {
        my $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'r', script => 'rawone',
            stdin => '{}', context => '{}', input => $in);
        is $r->{exit}, -1, 'refused';
        like $r->{stderr}, qr/exactly one input field is required, got ${\ scalar keys %$in}/, 'says why';
    }
};

subtest 'raw:<name>: that field; a missing one is named (agent and executor)' => sub {
    my $r = run('rawnamed', { key => $SENTINEL, other => $OTHER });
    is $r->{exit}, 0, 'ran';
    is section(slurp("$dir/out/seen.rawnamed"), 'STDIN'), $SENTINEL, 'stdin is the named field';
    not_elsewhere('rawnamed', 'raw:key', $r);

    $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'r', script => 'rawnamed',
        stdin => '{}', context => '{}', input => { other => $OTHER });
    is $r->{exit}, -1, 'executor refuses a frame without the field';
    like $r->{stderr}, qr/input=raw:key but input field 'key' is missing/, 'names the field';
    unlike $r->{stderr}, qr/\Q$OTHER\E/, 'never the value';
};

subtest 'fields: files in a private dir, empty stdin, dir removed after' => sub {
    my $r = run('flds', { key => $SENTINEL, 'b.pem' => "$OTHER\n" });
    is $r->{exit}, 0, 'ran' or diag explain $r;
    my $seen = slurp("$dir/out/seen.flds");
    is section($seen, 'STDIN'), '', 'stdin empty';
    my $dirs = section($seen, 'DIR');
    my ($d) = $dirs =~ m{^700 (\Q$base\E/r1\.[0-9a-f]{16})$}m;
    ok defined $d, 'per-run directory <base>/<reqid>.<random>, mode 0700' or diag $dirs;
    $d //= 'none';
    like $dirs, qr{^600 \Q$d\E/key\n\[\Q$SENTINEL\E\]$}m, 'key file is 0600 with the value';
    like $dirs, qr{^600 \Q$d\E/b\.pem\n\[\Q$OTHER\E\]$}m, 'second file';
    my ($env_in) = section($seen, 'ENV') =~ /^CTRL_EXEC_INPUT=(.*)$/m;
    is $env_in, $d, 'CTRL_EXEC_INPUT is the directory path';
    my ($ctx) = section($seen, 'ENV') =~ /^CTRL_EXEC_CONTEXT=(.*)$/m;
    my $c = JSON::PP::decode_json($ctx);
    ok !exists $c->{input} && !exists $c->{token}, 'CTRL_EXEC_CONTEXT has no input and no token';
    not_elsewhere('flds', 'fields', $r);
    ok !-e $d, 'directory removed after normal exit';
    is leftovers(), 0, 'nothing left in the input directory';
};

subtest 'fields without input: an empty directory' => sub {
    my $r = run('flds', undef);
    is $r->{exit}, 0, 'ran';
    like section(slurp("$dir/out/seen.flds"), 'DIR'), qr{^700 \Q$base\E/}m, 'directory given';
    is leftovers(), 0, 'removed';
};

subtest 'fields: directory removed after the action is killed' => sub {
    my $r = run('killed', { key => $SENTINEL });
    is $r->{exit}, 126, 'killed by signal reports 126';
    my $d = slurp("$dir/out/lastdir.killed") // ''; chomp $d;
    like $d, qr{^\Q$base\E/}, 'it had a directory';
    ok !-e $d, 'directory removed after a kill';
    is leftovers(), 0, 'nothing left';
};

subtest 'cleanup never follows a link the action made' => sub {
    my $r = run('links', { key => $SENTINEL });
    is $r->{exit}, 0, 'ran';
    is leftovers(), 0, 'directory, links, subdirectory and fifo removed';
    is slurp("$dir/victim"), "keep me\n", 'file a link pointed at is intact';
    is slurp("$dir/victimdir/f"), "keep me too\n", 'directory a nested link pointed at is intact';
};

subtest 'the mode comes from the executor\'s scripts.conf, not the agent' => sub {
    # The agent's allowlist says ctx is input=context; the executor's own
    # scripts.conf now says fields. The executor delivers per its own file.
    my $orig = slurp($scripts_conf);
    write_file($scripts_conf, $orig =~ s{^ctx\s+=.*$}{ctx = $dir/s/ctx.sh input=fields}mr);
    my $r = run('ctx', { key => $SENTINEL });
    is $r->{exit}, 0, 'ran';
    my $seen = slurp("$dir/out/seen.ctx");
    is section($seen, 'STDIN'), '', 'stdin empty: fields, as the executor\'s file says';
    like section($seen, 'DIR'), qr{^600 \S+/key\n\[\Q$SENTINEL\E\]$}m, 'delivered as a file';
    # A v1 frame (no input; the agent believes context) for a script the
    # executor has as fields is refused, not run without its context.
    $r = run('ctx', undef);
    is $r->{exit}, -1, 'v1 frame for a fields script refused';
    like $r->{stderr}, qr/takes input=fields but the agent sent no input/, 'says why';
    write_file($scripts_conf, $orig);
    is leftovers(), 0, 'nothing left';
};

# Raw frames, to reach the executor's bounds without the agent's own checks.
sub raw_frame {
    my ($inner) = @_;
    my $s = IO::Socket::UNIX->new(Peer => $sock, Type => IO::Socket::UNIX::SOCK_STREAM()) or die $!;
    binmode $s;
    $s->syswrite(pack('N', length $inner) . $inner);
    my $buf = ''; while ($s->sysread(my $c, 65536)) { $buf .= $c }
    return undef if length $buf < 12;
    my ($ex, $ol) = unpack 'l> N', $buf;
    my $el = unpack 'N', substr($buf, 8 + $ol, 4);
    return { exit => $ex, stdout => substr($buf, 8, $ol), stderr => substr($buf, 12 + $ol, $el) };
}
sub f { pack('N', length $_[0]) . $_[0] }
sub v2 {
    my (%o) = @_;
    my @f = @{ $o{fields} // [] };
    return pack('N', 0xCE0E0002) . f('r') . f('d') . f($o{script} // 'flds') . f('{}') . f('{"script":"x"}')
         . pack('N', 0) . pack('N', $o{count} // @f / 2) . join('', map { f($_) } @f) . ($o{trail} // '');
}

subtest 'the executor bounds the frame itself (names, count, size, layout)' => sub {
    my $r = raw_frame(v2(fields => [map { ("f$_" => 'x') } 1 .. 33]));
    like $r->{stderr}, qr/more than 32 fields/, '33 fields refused';
    $r = raw_frame(v2(count => 0xFFFFFFFF));
    like $r->{stderr}, qr/more than 32 fields/, 'a huge count is refused before anything is read';
    for my $bad ('', '.', '..', 'a/b', 'x' x 65, "a\0b", 'caf' . "\xc3\xa9") {
        $r = raw_frame(v2(fields => [$bad => $SENTINEL]));
        like $r->{stderr}, qr/input field name is invalid/, 'bad name refused: ' . JSON::PP->new->ascii->encode([$bad]);
        unlike $r->{stderr}, qr/\Q$SENTINEL\E/, 'value not echoed';
    }
    $r = raw_frame(v2(fields => [key => $SENTINEL, key => 'y']));
    like $r->{stderr}, qr/input field 'key' appears more than once/, 'duplicate refused, named';
    $r = raw_frame(v2(fields => [a => 'x' x (2 * 1024 * 1024), b => 'y' x (2 * 1024 * 1024 + 1)]));
    like $r->{stderr}, qr/exceeds the executor's limit of 4194304 bytes/, 'over the ceiling refused';
    $r = raw_frame(v2(fields => [a => 'x' x (2 * 1024 * 1024), b => 'y' x (2 * 1024 * 1024)]));
    is $r->{exit}, 0, 'exactly the ceiling runs';
    $r = raw_frame(v2(fields => [a => 'x'], trail => 'junk'));
    like $r->{stderr}, qr/malformed input frame/, 'trailing bytes refused';
    $r = raw_frame(v2(fields => [a => 'x'], count => 2));
    like $r->{stderr}, qr/malformed input frame/, 'count beyond the frame refused';
    $r = raw_frame(pack('N', 0xCE0E0002) . f('r') . f('d') . f('rawone') . f('{}') . f("a\0b")
                   . pack('N', 0) . pack('N', 1) . f('k') . f('v'));
    like $r->{stderr}, qr/malformed input frame/, 'a NUL in the context refused';
    $r = raw_frame(pack('N', 0xCE0E0002) . f('r') . f('d') . f('rawone') . f('{}') . f('')
                   . pack('N', 0) . pack('N', 1) . f('k') . f('v'));
    like $r->{stderr}, qr/malformed input frame/, 'raw without a context refused';
    is leftovers(), 0, 'nothing created for any refusal';
    $r = Exec::Agent::ExecClient::run(socket => $sock, reqid => 'ok', script => 'ctx', stdin => "{}");
    is $r->{exit}, 0, 'the executor still serves afterwards';
};

subtest 'the agent refuses a frame the executor would drop' => sub {
    my $r = Exec::Agent::ExecClient::run(socket => $sock, script => 'flds', context => '{}',
                                          input => { a => 'x' x (17 * 1024 * 1024) });
    is $r->{exit}, -1, 'refused';
    like $r->{error}, qr/request too large for the executor/, 'says why';
};

subtest 'start-up sweep removes what a crash left, without following links' => sub {
    stop_executor();
    mkdir "$base/stale.0123456789abcdef" or die $!;
    write_file("$base/stale.0123456789abcdef/key", $SENTINEL, 0600);
    mkdir "$base/stale.0123456789abcdef/sub";
    symlink "$dir/victimdir", "$base/stale.0123456789abcdef/sub/d";
    symlink "$dir/victim", "$base/stale-link";
    ok start_executor(), 'executor restarted';
    is leftovers(), 0, 'stale directory and link removed';
    is slurp("$dir/victim"), "keep me\n", 'link target intact';
    is slurp("$dir/victimdir/f"), "keep me too\n", 'nested link target intact';
    like slurp($exec_log), qr/removed 2 stale input directories/, 'logged as a count';
    unlike slurp($exec_log), qr/\Q$SENTINEL\E/, 'no value in the log';
};

stop_executor();

subtest 'an executor without input support is reported, not misread' => sub {
    # A stand-in for an executor that predates frame v2: it answers every frame
    # as the old parser answers a v2 frame.
    my $old = "$dir/old.sock";
    my $srv = IO::Socket::UNIX->new(Local => $old, Type => IO::Socket::UNIX::SOCK_STREAM(), Listen => 5)
        or die "listen: $!";
    my $spid = fork // die;
    if (!$spid) {
        while (my $c = $srv->accept) {
            my $hdr = ''; $c->sysread($hdr, 4);
            my $n = unpack 'N', $hdr; my $got = '';
            while (length $got < $n) { $c->sysread(my $b, $n - length $got) or last; $got .= $b }
            my $magic = unpack 'N', $got;
            my $msg = $magic == 0xCE0E0002 ? "executor: malformed request\n" : "ran v1\n";
            my $ex  = $magic == 0xCE0E0002 ? -1 : 0;
            $c->syswrite(pack('l>', $ex) . f($ex ? '' : 'ok') . f($msg));
            close $c;
        }
        POSIX::_exit(0);
    }
    @logs = ();
    my $rr = post({ script => 'flds', args => [], reqid => 'r1', input => { key => $SENTINEL } },
                  executor_socket => $old);
    is $rr->{exit}, -1, 'refused';
    like $rr->{error}, qr/ctrl-exec-executor does not support run input: it is older than this agent/,
        'clean refusal naming the executor';
    unlike $JSON->encode([$rr, \@logs]), qr/\Q$SENTINEL\E/, 'no value in reply or logs';
    my $ok = post({ script => 'ctx', args => [], reqid => 'r2' }, executor_socket => $old);
    is $ok->{exit}, 0, 'a context run without input still works with the old executor (v1 frame)';
    kill 'TERM', $spid; waitpid $spid, 0;
};

done_testing;
