#!/usr/bin/perl
# t/auth-hook-args.t
#
# Tests for etc/auth-hook-args.example, the optional agent auth hook that
# validates a run request's arguments against the script's schema sidecar.
#
# The hook is run as a real subprocess with the environment the agent gives
# it (ENVEXEC_*), and its exit code and audit line are checked. A final
# subtest wires it into the agent's real /run handler to show a denied
# argument never reaches the script.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON qw(encode_json);
use FindBin qw($Bin);
use lib "$Bin/../lib";
use IO::Socket::UNIX qw();

use Exec::Agent::Server qw();
use Exec::Log           qw();

my $HOOK = "$Bin/../etc/auth-hook-args.example";
plan skip_all => 'hook not present' unless -x $HOOK;

my $DIR = tempdir(CLEANUP => 1);
# Scripts in a tempdir owned by the test user under a world-writable /tmp: trust
# that user and the tempdir's ancestors (test seam, T-045), and create nothing
# group-writable, so the ownership rule lets the run through.
@Exec::Agent::Config::TRUSTED_OWNERS = (0, $>);
$Exec::Agent::Config::TRUSTED_TOP    = $DIR;
umask 022;
my $LOG = "$DIR/hook.log";
mkdir "$DIR/scripts" or die;
mkdir "$DIR/allowed" or die;
mkdir "$DIR/outside" or die;
symlink "$DIR/outside", "$DIR/allowed/escape" or die;
mkdir "$DIR/allowed/sub" or die;

my @conf;

sub add_script {
    my ($name, $sidecar) = @_;
    my $path = "$DIR/scripts/$name";
    open my $fh, '>', $path or die; print $fh "#!/bin/sh\nexit 0\n"; close $fh;
    chmod 0755, $path;
    if (defined $sidecar) {
        open my $sh, '>', "$path.schema.json" or die;
        print $sh ref $sidecar ? encode_json($sidecar) : $sidecar;
        close $sh;
    }
    push @conf, "$name = $path";
    open my $c, '>', "$DIR/scripts.conf" or die;
    print $c join("\n", @conf), "\n"; close $c;
    return $path;
}

# Run the hook; returns (exit code, audit text).
sub hook {
    my ($script, $args, %env) = @_;
    unlink $LOG;
    my $pid = fork() // die;
    if (!$pid) {
        %ENV = (
            PATH                           => $ENV{PATH},
            ENVEXEC_ACTION                 => $env{action} // 'run',
            ENVEXEC_SCRIPT                 => $script,
            ENVEXEC_ARGS_JSON              => $env{raw} // encode_json($args),
            CTRL_EXEC_ARGHOOK_SCRIPTS_CONF => "$DIR/scripts.conf",
            CTRL_EXEC_ARGHOOK_LOGFILE      => $LOG,
            (defined $env{no_sidecar} ? (CTRL_EXEC_ARGHOOK_NO_SIDECAR => $env{no_sidecar}) : ()),
        );
        exec { $HOOK } $HOOK;
        exit 99;
    }
    waitpid $pid, 0;
    my $log = '';
    if (open my $fh, '<', $LOG) { local $/; $log = <$fh>; close $fh }
    return (($? >> 8), $log);
}

sub allowed ($$$;%) {
    my ($script, $args, $name, %env) = @_;
    my ($rc, $log) = hook($script, $args, %env);
    is $rc, 0, "$name: allowed" or diag $log;
}

sub denied ($$$$;%) {
    my ($script, $args, $rule, $name, %env) = @_;
    my ($rc, $log) = hook($script, $args, %env);
    is $rc, 3, "$name: denied (exit 3)";
    like $log, qr/failed rule '\Q$rule\E'/, "$name: audit names the rule";
    for my $a (@$args) {
        unlike $log, qr/\Q$a\E/, "$name: audit does not contain the value '$a'"
            if length $a > 2 && $a !~ /\A(?:true|false|--\w+)\z/ && $rule !~ /\Q$a\E/;
    }
}

# --- a fully constrained script ---------------------------------------------

add_script('svc', {
    argv => [ { arg => 'file' }, { arg => 'mode' }, { arg => 'count' },
              { arg => 'tag' }, { arg => 'service', repeat => true() } ],
    arguments => {
        type => 'object',
        required => [ 'file', 'mode', 'count' ],
        properties => {
            file    => { type => 'string', 'x-path-prefixes' => [ "$DIR/allowed" ] },
            mode    => { type => 'string', enum => [ 'start', 'restart' ] },
            count   => { type => 'integer', minimum => 1, maximum => 10 },
            tag     => { type => 'string', pattern => '^[a-z]{2,5}$' },
            service => { type => 'string', pattern => '^[a-z0-9_-]+$', maxItems => 2 },
        },
    },
});
sub true { JSON::true() }

my $f = "$DIR/allowed/compose.yml";
allowed 'svc', [ $f, 'restart', '3', 'abc' ], 'all constraints met, no repeat values';
allowed 'svc', [ $f, 'start', '10', 'abc', 'web', 'db' ], 'repeat values within maxItems';
allowed 'svc', [ "$DIR/allowed/sub/new-file.yml", 'start', '1', 'abc' ], 'path that does not exist yet, under the prefix';

denied 'svc', [ $f, 'restart', 'three', 'abc' ], 'type integer', 'wrong type';
denied 'svc', [ $f, 'stop', '3', 'abc' ], 'enum', 'value outside enum';
denied 'svc', [ $f, 'start', '11', 'abc' ], 'maximum', 'above maximum';
denied 'svc', [ $f, 'start', '3', 'ABCDEF' ], 'pattern', 'pattern mismatch';
denied 'svc', [ $f, 'start', '3', "abc\n" ], 'control character', 'trailing newline cannot satisfy a $ anchor';
denied 'svc', [ "$DIR/outside/compose.yml", 'start', '3', 'abc' ], 'path-prefix', 'path outside the prefix';
denied 'svc', [ "$DIR/allowed/../outside/x", 'start', '3', 'abc' ], 'path-prefix', 'dotdot out of the prefix';
denied 'svc', [ "$DIR/allowed-evil/x", 'start', '3', 'abc' ], 'path-prefix', 'sibling sharing the prefix string';
denied 'svc', [ "$DIR/allowed/escape/x.yml", 'start', '3', 'abc' ], 'path-prefix', 'symlink inside the prefix pointing outside';
denied 'svc', [ "allowed/compose.yml", 'start', '3', 'abc' ], 'path not absolute', 'relative path';
denied 'svc', [ $f, 'start', '3', 'abc', 'a', 'b', 'c' ], 'maxItems', 'too many repeat values';
denied 'svc', [ $f, 'start' ], 'required', 'too few arguments';
denied 'svc', [], 'required', 'no arguments';

# a symlink to a real file outside the prefix
open my $o, '>', "$DIR/outside/real.yml" or die; close $o;
symlink "$DIR/outside/real.yml", "$DIR/allowed/link.yml" or die;
denied 'svc', [ "$DIR/allowed/link.yml", 'start', '3', 'abc' ], 'path-prefix', 'file symlink pointing outside the prefix';
symlink "$DIR/nowhere", "$DIR/allowed/dangling.yml" or die;
denied 'svc', [ "$DIR/allowed/dangling.yml", 'start', '3', 'abc' ], 'path unresolvable', 'dangling symlink';

# --- too many / too few on a plain positional script ------------------------

add_script('two', {
    argv => [ 'run', { arg => 'a' }, { arg => 'b' } ],
    arguments => { type => 'object', required => ['a'],
        properties => { a => { type => 'string' }, b => { type => 'string' } } },
});
allowed 'two', [ 'run', 'x', 'y' ], 'literal token plus two values';
allowed 'two', [ 'run', 'x' ],      'optional trailing value omitted';
denied  'two', [ 'run', 'x', 'y', 'z' ], 'too many arguments', 'one argument too many';
denied  'two', [ 'run' ], 'required', 'required value missing';
denied  'two', [ 'other', 'x' ], 'fixed token mismatch', 'literal token differs';
denied  'two', [], 'too few arguments', 'literal token missing';

# --- flags and booleans -------------------------------------------------------

add_script('flags', {
    argv => [ { arg => 'force', flag => '--force' }, { arg => 'level', flag => '--level' } ],
    arguments => { type => 'object', properties => {
        force => { type => 'boolean' },
        level => { type => 'string', enum => [ 'low', 'high' ] } } },
});
allowed 'flags', [], 'both flags absent';
allowed 'flags', [ '--force', '--level', 'high' ], 'flags present';
denied  'flags', [ '--level', 'mid' ], 'enum', 'flag value outside enum';
denied  'flags', [ '--level' ], 'missing value', 'flag without a value';
denied  'flags', [ '--bogus' ], 'too many arguments', 'unknown flag';

# --- sidecar absent / unconstrained / malformed ------------------------------

add_script('bare');
allowed 'bare', [ 'anything' ], 'no sidecar, default allow';
allowed 'bare', [ 'anything' ], 'no sidecar, explicit allow', no_sidecar => 'allow';
denied  'bare', [ 'anything' ], 'sidecar required (no sidecar)', 'no sidecar, deny setting', no_sidecar => 'deny';

add_script('meta', { description => 'metadata only' });
allowed 'meta', [ 'x' ], 'sidecar without argv/arguments is unconstrained under allow';
denied  'meta', [ 'x' ], 'sidecar required (no constraints)', 'unconstrained sidecar under deny', no_sidecar => 'deny';

add_script('noargv', { arguments => { type => 'object', properties => { a => { type => 'string' } } } });
denied 'noargv', [ 'x' ], 'sidecar has arguments but no argv mapping', 'arguments without argv fails closed';

add_script('nothing', { arguments => { type => 'object', properties => {} } });
allowed 'nothing', [], 'declared no inputs, none given';
denied  'nothing', [ 'x' ], 'too many arguments', 'declared no inputs, one given';

for my $case (
    [ 'bad-json',   '{ not json' ],
    [ 'not-object', '[1,2]' ],
    [ 'bad-type',   '{"argv":[{"arg":"a"}],"arguments":{"properties":{"a":{"type":"bogus"}}}}' ],
    [ 'bad-pat',    '{"argv":[{"arg":"a"}],"arguments":{"properties":{"a":{"pattern":"(["}}}}' ],
    [ 'code-pat',   '{"argv":[{"arg":"a"}],"arguments":{"properties":{"a":{"pattern":"(?{ system(1) })"}}}}' ],
    [ 'argv-shape', '{"argv":"nope","arguments":{}}' ],
) {
    my ($n, $body) = @$case;
    add_script($n, $body);
    for my $setting (qw(allow deny)) {
        my ($rc) = hook($n, ['v'], no_sidecar => $setting);
        is $rc, 1, "malformed sidecar '$n' fails closed (exit 1) under no_sidecar=$setting";
    }
}

# oversize sidecar
add_script('big', '{"description":"' . ('x' x 70000) . '"}');
{ my ($rc) = hook('big', []); is $rc, 1, 'oversize sidecar fails closed'; }

# --- request-level failures: fail closed -------------------------------------

{
    my ($rc) = hook('nosuch', []);        is $rc, 1, 'script absent from scripts.conf fails closed';
    ($rc) = hook('svc', undef, raw => 'not json');   is $rc, 1, 'bad ENVEXEC_ARGS_JSON fails closed';
    ($rc) = hook('svc', undef, raw => '{"a":1}');    is $rc, 1, 'args JSON not an array fails closed';
    ($rc) = hook('svc', undef, raw => '[["nested"]]'); is $rc, 1, 'non-scalar argument fails closed';
    ($rc) = hook('svc', undef, raw => encode_json([ ('a') x 300 ])); is $rc, 1, 'over 256 arguments fails closed';
    ($rc) = hook('svc', undef, raw => encode_json([ 'a' x 5000 ]));  is $rc, 1, 'over-long argument fails closed';
    ($rc) = hook('svc', undef, raw => '[' . ('"a",' x 20000) . '"a"]'); is $rc, 1, 'oversize args JSON fails closed';
    ($rc) = hook('../etc', []);           is $rc, 1, 'bad script name fails closed';
    ($rc) = hook('svc', [], action => 'ping'); is $rc, 0, 'ping is not constrained';
    ($rc) = hook('svc', [], action => 'bogus'); is $rc, 1, 'unknown action fails closed';
    ($rc) = hook('svc', [], no_sidecar => 'maybe'); is $rc, 1, 'invalid no_sidecar setting fails closed';
}

{
    # Missing scripts.conf
    local $ENV{X} = 1;
    my $pid = fork(); die unless defined $pid;
    if (!$pid) {
        %ENV = ( ENVEXEC_ACTION => 'run', ENVEXEC_SCRIPT => 'svc', ENVEXEC_ARGS_JSON => '[]',
                 CTRL_EXEC_ARGHOOK_SCRIPTS_CONF => "$DIR/missing.conf", CTRL_EXEC_ARGHOOK_LOGFILE => $LOG );
        exec { $HOOK } $HOOK; exit 99;
    }
    waitpid $pid, 0;
    is $? >> 8, 1, 'unreadable scripts.conf fails closed';
}

# --- no output on stdout/stderr ----------------------------------------------

{
    my $out = "$DIR/out.txt";
    my $rc = system("env ENVEXEC_ACTION=run ENVEXEC_SCRIPT=svc "
        . "ENVEXEC_ARGS_JSON='[\"x\"]' CTRL_EXEC_ARGHOOK_SCRIPTS_CONF='$DIR/scripts.conf' "
        . "CTRL_EXEC_ARGHOOK_LOGFILE='$LOG' '$HOOK' >'$out' 2>&1");
    is $rc >> 8, 3, 'denial exit code when run through a shell redirect';
    is -s $out, 0, 'hook wrote nothing to stdout or stderr';
}

# --- through the agent's real /run handler ------------------------------------

subtest 'a denied argument never reaches the script; an allowed one runs' => sub {
    {
        no warnings 'redefine';
        *Exec::Log::log_action = sub {};
    }
    my $marker = "$DIR/ran.marker";
    my $real = "$DIR/scripts/real";
    open my $fh, '>', $real or die;
    print $fh "#!/bin/sh\necho \"\$1\" >> '$marker'\nexit 0\n";
    close $fh; chmod 0755, $real;
    open my $sh, '>', "$real.schema.json" or die;
    print $sh encode_json({
        argv => [ { arg => 'mode' } ],
        arguments => { type => 'object', required => ['mode'],
            properties => { mode => { type => 'string', enum => [ 'start', 'restart' ] } } },
    });
    close $sh;
    push @conf, "real = $real";
    open my $c, '>', "$DIR/scripts.conf" or die; print $c join("\n", @conf), "\n"; close $c;

    # The hook runs in a child of the agent process; give it its settings via
    # the environment, as an operator would.
    local $ENV{CTRL_EXEC_ARGHOOK_SCRIPTS_CONF} = "$DIR/scripts.conf";
    local $ENV{CTRL_EXEC_ARGHOOK_LOGFILE}      = $LOG;

    my $run = sub {
        my ($mode) = @_;
        my $body = encode_json({ script => 'real', args => [$mode], reqid => 'r1' });
        my ($client, $server) = IO::Socket::UNIX->socketpair(
            IO::Socket::AF_UNIX(), IO::Socket::SOCK_STREAM(), 0) or die;
        print $client "POST /run HTTP/1.0\r\nContent-Length: " . length($body) . "\r\n\r\n$body";
        $client->shutdown(1);
        Exec::Agent::Server::handle_connection(
            $server, '10.0.0.5',
            { real => { path => $real, profile => 'default' } },
            { auth_hook => $HOOK },
            {}, { deadbeef => 'disp-1' }, 'deadbeef', {}, '9.9.9');
        $server->close;
        local $/; my $resp = <$client> // ''; $client->close;
        return $resp;
    };

    my $resp = $run->('destroy');
    like $resp, qr/"exit":-1/, 'denied run reports exit -1';
    like $resp, qr/not authorised/, 'denied run reports not authorised';
    ok !-e $marker, 'the script did not run for the denied argument';

    $resp = $run->('restart');
    like $resp, qr/"exit":0/, 'allowed run exits 0';
    ok -e $marker, 'the script ran for the allowed argument';
    open my $m, '<', $marker or die; local $/; my $got = <$m>;
    is $got, "restart\n", 'the script received the argument unchanged';
};

done_testing;
