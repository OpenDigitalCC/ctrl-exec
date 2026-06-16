#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin    qw($Bin);
use lib "$Bin/../lib";

use Exec::Auth qw();

# Silence syslog during tests - Log falls back to stderr if not init'd,
# redirect stderr to suppress that noise
open my $saved_stderr, '>&', \*STDERR;
open STDERR, '>', '/dev/null';

my $tmpdir = tempdir(CLEANUP => 1);

# Helper: write an executable hook script
sub make_hook {
    my ($name, $content) = @_;
    my $path = "$tmpdir/$name";
    open my $fh, '>', $path or die "Cannot write $path: $!";
    print $fh "#!/bin/bash\n$content\n";
    close $fh;
    chmod 0755, $path;
    return $path;
}

# --- no hook configured ---

{
    my $result = Exec::Auth::check(
        action => 'run',
        caller => 'cli',
        config => {},
    );
    ok $result->{ok}, 'no hook: authorised by default';
}

{
    my $result = Exec::Auth::check(
        action => 'ping',
        caller => 'cli',
        config => {},
    );
    ok $result->{ok}, 'no hook: ping authorised by default';
}

{
    my $result = Exec::Auth::check(
        action => 'run',
        caller => 'cli',
        config => { auth_hook => '' },
    );
    ok $result->{ok}, 'empty hook path: authorised by default';
}

# --- hook not found / not executable ---

{
    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => "$tmpdir/does-not-exist" },
    );
    ok !$result->{ok}, 'missing hook: denied';
    like $result->{reason}, qr/not found or not executable/, 'missing hook: reason';
}

{
    my $path = "$tmpdir/not-exec";
    open my $fh, '>', $path or die $!;
    print $fh "#!/bin/bash\nexit 0\n";
    close $fh;
    chmod 0644, $path;   # not executable

    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $path },
    );
    ok !$result->{ok}, 'non-executable hook: denied';
}

# --- hook exit codes ---

{
    my $hook = make_hook('allow', 'exit 0');
    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $hook },
    );
    ok $result->{ok}, 'exit 0: authorised';
}

{
    my $hook = make_hook('deny-generic', 'exit 1');
    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $hook },
    );
    ok !$result->{ok},            'exit 1: denied';
    is $result->{code},   1,      'exit 1: code';
    is $result->{reason}, 'denied', 'exit 1: reason';
}

{
    my $hook = make_hook('deny-creds', 'exit 2');
    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $hook },
    );
    ok !$result->{ok},                  'exit 2: denied';
    is $result->{code},   2,            'exit 2: code';
    is $result->{reason}, 'bad credentials', 'exit 2: reason';
}

{
    my $hook = make_hook('deny-priv', 'exit 3');
    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $hook },
    );
    ok !$result->{ok},                        'exit 3: denied';
    is $result->{code},   3,                  'exit 3: code';
    is $result->{reason}, 'insufficient privilege', 'exit 3: reason';
}

{
    my $hook = make_hook('deny-other', 'exit 99');
    my $result = Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $hook },
    );
    ok !$result->{ok},                    'exit 99: denied';
    like $result->{reason}, qr/hook exited 99/, 'exit 99: reason contains code';
}

# --- environment variables passed to hook ---

{
    my $hook = make_hook('check-env', <<'HOOK');
[[ "$ENVEXEC_ACTION" == "run" ]]   || exit 1
[[ "$ENVEXEC_SCRIPT" == "backup" ]] || exit 2
[[ "$ENVEXEC_HOSTS"  == "host-a,host-b" ]] || exit 3
[[ "$ENVEXEC_USERNAME" == "stuart" ]] || exit 4
[[ "$ENVEXEC_SOURCE_IP" == "10.0.0.1" ]] || exit 5
exit 0
HOOK

    my $result = Exec::Auth::check(
        action    => 'run',
        script    => 'backup',
        hosts     => ['host-a', 'host-b'],
        username  => 'stuart',
        source_ip => '10.0.0.1',
        config    => { auth_hook => $hook },
    );
    ok $result->{ok}, 'env vars: all passed correctly to hook';
}

# --- token passed to hook ---

{
    my $hook = make_hook('check-token', <<'HOOK');
[[ "$ENVEXEC_TOKEN" == "secret123" ]] || exit 2
exit 0
HOOK

    my $result = Exec::Auth::check(
        action => 'run',
        token  => 'secret123',
        config => { auth_hook => $hook },
    );
    ok $result->{ok}, 'token: passed to hook via env';
}

{
    my $hook = make_hook('check-token-bad', <<'HOOK');
[[ "$ENVEXEC_TOKEN" == "secret123" ]] || exit 2
exit 0
HOOK

    my $result = Exec::Auth::check(
        action => 'run',
        token  => 'wrongtoken',
        config => { auth_hook => $hook },
    );
    ok !$result->{ok},               'token: bad token denied';
    is $result->{code}, 2,           'token: bad token returns code 2';
}

# --- JSON stdin passed to hook ---

{
    # Hook reads JSON from stdin and checks a field
    my $hook = make_hook('check-json', <<'HOOK');
input=$(cat)
echo "$input" | grep -q '"action":"run"' || exit 1
echo "$input" | grep -q '"script":"deploy"' || exit 1
exit 0
HOOK

    my $result = Exec::Auth::check(
        action => 'run',
        script => 'deploy',
        config => { auth_hook => $hook },
    );
    ok $result->{ok}, 'JSON stdin: hook reads action and script from stdin';
}

# --- argument validation ---

{
    eval { Exec::Auth::check(config => {}) };
    like $@, qr/action required/, 'check: dies without action';
}

{
    eval { Exec::Auth::check(action => 'run') };
    like $@, qr/config required/, 'check: dies without config';
}

{
    eval { Exec::Auth::check(action => 'run', config => {}, hosts => 'bad') };
    like $@, qr/hosts must be an arrayref/, 'check: dies if hosts not arrayref';
}

# --- ENVEXEC_ARGS_JSON ---

{
    # Hook checks that ENVEXEC_ARGS_JSON is a valid JSON array
    # and that ENVEXEC_ARGS is the space-joined form
    my $hook = make_hook('check-args-json', <<'HOOK');
echo "$ENVEXEC_ARGS_JSON" | grep -q '^\["hello world","two"\]' || exit 1
[[ "$ENVEXEC_ARGS" == "hello world two" ]] || exit 2
exit 0
HOOK

    my $result = Exec::Auth::check(
        action => 'run',
        args   => ['hello world', 'two'],
        config => { auth_hook => $hook },
    );
    ok $result->{ok}, 'ENVEXEC_ARGS_JSON: valid JSON array passed to hook';
}

# --- auth_deny_generic: generic_denials_enabled + deny_fields ---

{
    ok !Exec::Auth::generic_denials_enabled({}),
        'generic_denials_enabled: off by default (absent)';
    ok !Exec::Auth::generic_denials_enabled({ auth_deny_generic => '0' }),
        'generic_denials_enabled: off for 0';
    ok  Exec::Auth::generic_denials_enabled({ auth_deny_generic => '1' }),
        'generic_denials_enabled: on for 1';
    ok  Exec::Auth::generic_denials_enabled({ auth_deny_generic => 'yes' }),
        'generic_denials_enabled: on for yes';

    my $denied = { ok => 0, reason => 'insufficient privilege', code => 3 };

    my $detailed = Exec::Auth::deny_fields($denied, {});
    is $detailed->{error}, 'insufficient privilege', 'deny_fields: detailed reason when off';
    is $detailed->{code},  3,                         'deny_fields: detailed code when off';

    my $generic = Exec::Auth::deny_fields($denied, { auth_deny_generic => '1' });
    is $generic->{error}, 'forbidden', 'deny_fields: generic message when on';
    ok !exists $generic->{code},       'deny_fields: no code disclosed when on';
    ok !exists $generic->{reason},     'deny_fields: no reason disclosed when on';
}

# --- dispatcher identity reaches the hook environment ---
{
    my $envfile = "$tmpdir/hook-env.out";
    my $hook = make_hook('dump-env', "env > '$envfile'\nexit 0");

    my $result = Exec::Auth::check(
        action            => 'run',
        config            => { auth_hook => $hook },
        script            => 'backup',
        dispatcher        => 'automation',
        dispatcher_serial => 'deadbeef01',
    );
    ok $result->{ok}, 'hook authorises and runs';

    my $env = do { local $/; open my $fh, '<', $envfile or die $!; <$fh> };
    like $env, qr/^ENVEXEC_DISPATCHER=automation$/m,
        'ENVEXEC_DISPATCHER carries the stable identity';
    like $env, qr/^ENVEXEC_DISPATCHER_SERIAL=deadbeef01$/m,
        'ENVEXEC_DISPATCHER_SERIAL carries the cert serial';
}

# --- dispatcher identity defaults to empty when not supplied ---
{
    my $envfile = "$tmpdir/hook-env-empty.out";
    my $hook = make_hook('dump-env-empty', "env > '$envfile'\nexit 0");

    Exec::Auth::check(
        action => 'run',
        config => { auth_hook => $hook },
        script => 'backup',
    );

    my $env = do { local $/; open my $fh, '<', $envfile or die $!; <$fh> };
    like $env, qr/^ENVEXEC_DISPATCHER=$/m,
        'ENVEXEC_DISPATCHER present but empty when no dispatcher resolved';
}

# Restore stderr
open STDERR, '>&', $saved_stderr;

done_testing;
