#!/usr/bin/perl
# t/agent-run-input.t  (T-013 piece 2)
#
# Confidential run input at the agent, direct mode (no executor): the three
# scripts.conf input= modes deliver exactly the designed stdin/env/files, the
# value appears nowhere else (argv, other environment, logs, either auth hook's
# environment or stdin, the async record), the fields directory is gone after a
# normal exit and after the script is killed, and bad shapes are refused before
# any hook or exec with a reason that names fields, never values.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();
use JSON::PP ();

use Exec::Agent::Config qw();
use Exec::Agent::Server qw();
use Exec::Log           qw();

my @logs;
{
    no warnings 'redefine';
    *Exec::Log::log_action = sub { push @logs, { level => $_[0], %{ $_[1] } } };
}
my $JSON = JSON::PP->new->canonical;

my $SENTINEL = 'SENTINEL-7f3a9c-pa55w0rd-ZQ';
my $OTHER    = 'SECOND-b81d4e-v4lu3-KT';

my $dir = tempdir(CLEANUP => 1);
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $dir;
umask 022;
mkdir "$dir/s" or die;
mkdir "$dir/tmp" or die;
sub write_file { my ($p, $c, $m) = @_; open my $fh, '>', $p or die "$p: $!"; print $fh $c; close $fh; chmod $m, $p if $m }

# Every script records what it saw in $dir/seen.<name>: argv, the whole
# environment, stdin, and (when CTRL_EXEC_INPUT is set) each file with its mode.
for my $n (qw(ctx rawone rawnamed flds killed)) {
    my $extra = $n eq 'killed'
        ? qq{echo "\$CTRL_EXEC_INPUT" > "$dir/killed.dir"\nkill -9 \$\$\n} : '';
    write_file("$dir/s/$n.sh", <<"SH", 0755);
#!/bin/sh
out="$dir/seen.$n"
{
  echo "--ARGV--"; for a in "\$@"; do echo "\$a"; done
  echo "--ENV--"; env
  echo "--STDIN--"; cat
  echo "--DIR--"
  if [ -n "\$CTRL_EXEC_INPUT" ]; then
    stat -c '%a %n' "\$CTRL_EXEC_INPUT"
    for f in "\$CTRL_EXEC_INPUT"/*; do stat -c '%a %n' "\$f"; echo "[\$(cat "\$f")]"; done
    echo "\$CTRL_EXEC_INPUT" > "$dir/lastdir.$n"
  fi
} > "\$out" 2>&1
$extra
SH
}
write_file("$dir/s/badmode.sh", "#!/bin/sh\n", 0755);

write_file("$dir/scripts.conf", <<"CONF");
ctx      = $dir/s/ctx.sh
rawone   = $dir/s/rawone.sh   input=raw
rawnamed = $dir/s/rawnamed.sh input=raw:key
flds     = $dir/s/flds.sh     input=fields
killed   = $dir/s/killed.sh   input=fields
bad1     = $dir/s/badmode.sh  input=bogus
bad2     = $dir/s/badmode.sh  input=
bad3     = $dir/s/badmode.sh  input=raw:a/b
bad4     = $dir/s/badmode.sh  input=Raw
CONF
my ($allowlist, $skipped);
{
    local $SIG{__WARN__} = sub {};
    ($allowlist, $skipped) = Exec::Agent::Config::load_allowlist_full("$dir/scripts.conf", ["$dir/s"]);
}

# An auth hook that records its environment and stdin JSON.
write_file("$dir/hook.sh", <<"SH", 0755);
#!/bin/sh
{ env; echo "--STDIN--"; cat; } > "$dir/hook.seen"
exit 0
SH

my %config = (script_dirs => ["$dir/s"], input_dir => "$dir/tmp", auth_hook => "$dir/hook.sh");

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
sub slurp { my ($p) = @_; open my $fh, '<', $p or return undef; local $/; my $c = <$fh>; return $c }
sub run { my ($script, $input, %o) = @_;
    unlink "$dir/seen.$script", "$dir/hook.seen";
    @logs = ();
    return post({ script => $script, args => ['argone'], reqid => 'r1', username => 'u',
                  (defined $input ? (input => $input) : ()), %o });
}
sub section { my ($text, $name) = @_; $text =~ /--\Q$name\E--\n(.*?)(?=--[A-Z]+--\n|\z)/s; return $1 // '' }
sub leftovers { opendir my $d, "$dir/tmp" or return -1; my @e = grep { !/^\./ } readdir $d; return scalar @e }

# Nothing but the designed channels may carry the sentinel.
sub not_elsewhere {
    my ($script, $label, %allow) = @_;
    my $seen = slurp("$dir/seen.$script") // '';
    my $argv = section($seen, 'ARGV');
    my $env  = section($seen, 'ENV');
    unlike $argv, qr/\Q$SENTINEL\E/, "$label: not in argv";
    unlike $env,  qr/\Q$SENTINEL\E/, "$label: not in the script's environment";
    my $hook = slurp("$dir/hook.seen") // '';
    ok length $hook, "$label: the hook ran";
    unlike $hook, qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in the hook's environment or stdin";
    unlike $JSON->encode(\@logs), qr/\Q$SENTINEL\E|\Q$OTHER\E/, "$label: not in any log line";
}

subtest 'context mode: input rides in the stdin JSON only' => sub {
    my $r = run('ctx', { key => $SENTINEL, other => $OTHER });
    is $r->{exit}, 0, 'ran';
    my $seen  = slurp("$dir/seen.ctx");
    my $stdin = JSON::PP::decode_json(section($seen, 'STDIN') =~ s/\n\z//r);
    is_deeply $stdin->{input}, { key => $SENTINEL, other => $OTHER }, 'stdin context carries the input object';
    is $stdin->{script}, 'ctx', 'and the usual context';
    unlike section($seen, 'ENV'), qr/CTRL_EXEC_(CONTEXT|INPUT)/, 'no CTRL_EXEC_* env';
    not_elsewhere('ctx', 'context');
    my $hook = slurp("$dir/hook.seen");
    like $hook, qr/ENVEXEC_INPUT_NAMES_JSON=\["key","other"\]/, 'hook got the names';
    like $hook, qr/ENVEXEC_INPUT_BYTES=\d+/, 'and the size';
};

subtest 'context mode without input: stdin has no input key' => sub {
    my $r = run('ctx', undef);
    is $r->{exit}, 0, 'ran';
    my $stdin = JSON::PP::decode_json(section(slurp("$dir/seen.ctx"), 'STDIN') =~ s/\n\z//r);
    ok !exists $stdin->{input}, 'no input key';
    $r = run('ctx', {});
    $stdin = JSON::PP::decode_json(section(slurp("$dir/seen.ctx"), 'STDIN') =~ s/\n\z//r);
    ok !exists $stdin->{input}, 'an empty object is no input';
    like slurp("$dir/hook.seen"), qr/ENVEXEC_INPUT_NAMES_JSON=\[\]\n/, 'hook sees no names';
};

subtest 'raw: stdin is the field bytes; context moves to CTRL_EXEC_CONTEXT' => sub {
    my $r = run('rawone', { whatever => $SENTINEL }, token => 'TOKEN-7f3a');
    is $r->{exit}, 0, 'ran';
    my $seen = slurp("$dir/seen.rawone");
    is section($seen, 'STDIN'), $SENTINEL, 'stdin is exactly the value';
    my ($ctx) = section($seen, 'ENV') =~ /^CTRL_EXEC_CONTEXT=(.*)$/m;
    ok defined $ctx, 'CTRL_EXEC_CONTEXT set';
    my $c = JSON::PP::decode_json($ctx);
    is $c->{script}, 'rawone', 'context JSON';
    ok !exists $c->{input}, 'without input';
    ok !exists $c->{token}, 'without the token';
    unlike section($seen, 'ENV'), qr/TOKEN-7f3a/, 'token nowhere in the environment';
    unlike section($seen, 'ENV'), qr/CTRL_EXEC_INPUT/, 'no CTRL_EXEC_INPUT';
    not_elsewhere('rawone', 'raw');
};

subtest 'raw: exactly one field' => sub {
    my $r = run('rawone', undef);
    is $r->{exit}, -1, 'none refused';
    like $r->{error}, qr/^invalid input: .*input=raw.*exactly one input field.*got 0/, 'says why';
    ok !-e "$dir/seen.rawone", 'script not started';
    ok !-e "$dir/hook.seen", 'hook not asked';
    $r = run('rawone', { a => $SENTINEL, b => $OTHER });
    is $r->{exit}, -1, 'two refused';
    like $r->{error}, qr/got 2/, 'counts';
    unlike $JSON->encode([$r, \@logs]), qr/\Q$SENTINEL\E|\Q$OTHER\E/, 'no value in reply or logs';
};

subtest 'raw:<name>: that field; a missing one is named' => sub {
    my $r = run('rawnamed', { key => $SENTINEL, extra => $OTHER });
    is $r->{exit}, 0, 'ran';
    is section(slurp("$dir/seen.rawnamed"), 'STDIN'), $SENTINEL, 'stdin is the named field';
    not_elsewhere('rawnamed', 'raw:key');
    $r = run('rawnamed', { nokey => $SENTINEL });
    is $r->{exit}, -1, 'refused';
    like $r->{error}, qr/input field 'key' is missing/, 'names the missing field';
    ok !-e "$dir/seen.rawnamed", 'script not started';
    unlike $JSON->encode([$r, \@logs]), qr/\Q$SENTINEL\E/, 'no value in reply or logs';
};

subtest 'fields: files in a private dir, empty stdin, dir removed after' => sub {
    my $r = run('flds', { key => $SENTINEL, 'b.pem' => $OTHER });
    is $r->{exit}, 0, 'ran';
    my $seen = slurp("$dir/seen.flds");
    is section($seen, 'STDIN'), '', 'stdin empty';
    my $dirs = section($seen, 'DIR');
    my ($d) = $dirs =~ m{^700 (\Q$dir\E/tmp/\S+)$}m;
    ok defined $d, 'per-run directory is 0700 under input_dir';
    like $dirs, qr{^600 \Q$d\E/key\n\[\Q$SENTINEL\E\]$}m, 'key file is 0600 with the value';
    like $dirs, qr{^600 \Q$d\E/b\.pem\n\[\Q$OTHER\E\]$}m, 'second file';
    my ($env_in) = section($seen, 'ENV') =~ /^CTRL_EXEC_INPUT=(.*)$/m;
    is $env_in, $d, 'CTRL_EXEC_INPUT is the directory path';
    my ($ctx) = section($seen, 'ENV') =~ /^CTRL_EXEC_CONTEXT=(.*)$/m;
    ok !exists JSON::PP::decode_json($ctx)->{input}, 'CTRL_EXEC_CONTEXT has no input';
    unlike section($seen, 'ENV'), qr/\Q$SENTINEL\E|\Q$OTHER\E/, 'values not in env';
    not_elsewhere('flds', 'fields');
    ok !-e $d, 'directory removed after normal exit';
    is leftovers(), 0, 'nothing left in input_dir';
};

subtest 'fields: directory removed after the script is killed' => sub {
    my $r = run('killed', { key => $SENTINEL });
    is $r->{exit}, 126, 'killed by signal reports 126';
    my $d = slurp("$dir/killed.dir"); chomp $d;
    like $d, qr{^\Q$dir\E/tmp/}, 'it had a directory';
    ok !-e $d, 'directory removed after a kill';
    is leftovers(), 0, 'nothing left in input_dir';
};

subtest 'the body limit admits a full-size input and refuses beyond it' => sub {
    my $big  = 'a' x 1_048_576;   # exactly max_input_bytes: body is over 1 MiB
    my $body = $JSON->encode({ script => 'ctx', args => [], reqid => 'big', username => 'u',
                               input => { key => $big } });
    ok length($body) > 1_048_576, 'body is larger than the old 1 MiB limit';
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    my $pid = fork // die "fork: $!";
    if (!$pid) {   # writer: the request is larger than the socket buffer
        $server->close;
        print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
        $client->shutdown(1);
        local $/; my $resp = <$client> // '';
        $resp =~ s/\A.*?\r\n\r\n//s;
        my $r = eval { JSON::PP::decode_json($resp) } // {};
        exit(defined $r->{exit} && $r->{exit} == 0 ? 0 : 1);
    }
    $client->close;
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, \%config, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    waitpid $pid, 0;
    is $? >> 8, 0, 'a 1 MiB input runs';

    ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die "socketpair: $!";
    print $client "POST /run HTTP/1.0\r\nContent-Length: " . (2 * 1_048_576 + 1) . "\r\n\r\n";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, \%config, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped,
    );
    $server->close;
    local $/; my $resp = <$client> // '';
    like $resp, qr/\A\S+ 413 /, 'beyond 1 MiB plus max_input_bytes: 413 before reading';
};

subtest 'bad shapes are refused before the hook and exec' => sub {
    my %bad = (
        'not an object'   => [ ['a'], qr/must be an object/ ],
        'string'          => [ 'x', qr/must be an object/ ],
        'bad name'        => [ { 'a/b' => 'v' }, qr/field name is invalid/ ],
        'dotdot name'     => [ { '..' => 'v' }, qr/field name is invalid/ ],
        'non-string value' => [ { k => [1] }, qr/input field 'k' must be a string/ ],
        'null value'      => [ { k => undef }, qr/input field 'k' must be a string/ ],
        'too many'        => [ { map { ("f$_" => 'v') } 1 .. 33 }, qr/more than 32 fields/ ],
    );
    for my $label (sort keys %bad) {
        my ($in, $re) = @{ $bad{$label} };
        my $r = run('ctx', $in);
        is $r->{exit}, -1, "$label: refused";
        like $r->{error}, qr/^invalid input: /, "$label: named reason";
        like $r->{error}, $re, "$label: right reason";
        ok !-e "$dir/seen.ctx" && !-e "$dir/hook.seen", "$label: no hook, no exec";
    }
    my $r = run('ctx', { k => 'x' x 20 }, );
    is $r->{exit}, 0, 'small input fine at default limit';
    $r = post({ script => 'ctx', args => [], input => { k => $SENTINEL . ('x' x 50) } }, max_input_bytes => 40);
    is $r->{exit}, -1, 'over the configured max_input_bytes refused';
    like $r->{error}, qr/input exceeds 40 bytes/, 'says the limit';
    unlike $JSON->encode($r), qr/\Q$SENTINEL\E/, 'reply holds no value';
};

subtest 'a bad input= mode skips the script with a reason' => sub {
    like $skipped->{bad1}, qr/^its input mode 'bogus' is not one of context, raw, raw:<name>, fields$/, 'unknown mode';
    like $skipped->{bad2}, qr/^its input mode '' is not one of/, 'empty';
    like $skipped->{bad3}, qr/^its input=raw:<name> field name is not valid/, 'bad field name';
    like $skipped->{bad4}, qr/input mode 'Raw'/, 'case matters';
    ok !exists $allowlist->{bad1}, 'not allowlisted';
    my $r = run('bad1', undef);
    like $r->{error}, qr/^script not permitted: its input mode 'bogus'/, 'run reports the reason';
};

subtest 'the allowlist records each mode; /capabilities reports it' => sub {
    is Exec::Agent::Config::script_input_mode('ctx', $allowlist), 'context', 'default context';
    is Exec::Agent::Config::script_input_mode('rawnamed', $allowlist), 'raw:key', 'raw:key';
    my ($client, $server) = IO::Socket::UNIX->socketpair(
        IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die;
    print $client "GET /capabilities HTTP/1.0\r\n\r\n";
    $client->shutdown(1);
    Exec::Agent::Server::handle_connection(
        $server, '10.0.0.5', $allowlist, { %config, auth_hook => undef }, {},
        { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9', $skipped);
    $server->close;
    local $/; my $resp = <$client>; $resp =~ s/\A.*?\r\n\r\n//s;
    my %mode = map { $_->{name} => $_->{input} } @{ JSON::PP::decode_json($resp)->{scripts} };
    is_deeply \%mode, { ctx => 'context', rawone => 'raw', rawnamed => 'raw:key',
                        flds => 'fields', killed => 'fields' }, 'modes reported';
};

subtest 'with an executor configured, input is refused, not dropped' => sub {
    my %ex = (executor_socket => "$dir/no.sock");
    for my $c (['ctx', { key => $SENTINEL }], ['flds', undef], ['flds', { key => $SENTINEL }]) {
        my ($s, $in) = @$c;
        unlink "$dir/seen.$s", "$dir/hook.seen";
        @logs = ();
        my $r = post({ script => $s, args => [], (defined $in ? (input => $in) : ()) }, %ex);
        is $r->{exit}, -1, "$s: refused";
        is $r->{error}, 'input requires executor support; not yet available', "$s: says so";
        ok !-e "$dir/hook.seen", "$s: hook not asked";
        unlike $JSON->encode([$r, \@logs]), qr/\Q$SENTINEL\E/, "$s: no value in reply or logs";
    }
    # context mode without input reaches the executor path exactly as before
    my $r = post({ script => 'ctx', args => [] }, %ex);
    like $r->{stderr} // '', qr/./, 'ctx without input goes to the executor client (unavailable here)';
    isnt $r->{error} // '', 'input requires executor support; not yet available', 'not refused';
};

subtest 'async: the record never holds input; the job still receives it' => sub {
    my $runs = "$dir/runs";
    unlink "$dir/seen.flds", "$dir/hook.seen";
    @logs = ();
    my $r = post({ script => 'flds', args => [], reqid => 'aabbccdd11', async => JSON::PP::true,
                   input => { key => $SENTINEL } }, async_runs_dir => $runs);
    is $r->{status}, 'accepted', 'accepted';
    my $rec;
    for (1 .. 100) {
        my $f = "$runs/disp-1/aabbccdd11.json";
        $rec = slurp($f);
        last if defined $rec && $rec =~ /"done"/;
        select undef, undef, undef, 0.1;
    }
    ok defined $rec && $rec =~ /"done"/, 'job finished';
    unlike $rec, qr/\Q$SENTINEL\E/, 'record holds no value';
    my @all = glob("$runs/*/* $runs/*");
    for my $f (grep { -f } @all) {
        unlike slurp($f), qr/\Q$SENTINEL\E/, "no value in $f";
    }
    like slurp("$dir/seen.flds"), qr/\[\Q$SENTINEL\E\]/, 'the job did receive the file';
    unlike $JSON->encode(\@logs), qr/\Q$SENTINEL\E/, 'no log line';
    is leftovers(), 0, 'async fields dir removed';
};

done_testing;
