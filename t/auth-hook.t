#!/usr/bin/perl
# t/auth-hook.t
#
# Unit tests for Exec::Auth::check.
#
# Tests the hook runner in isolation: exit code handling, reason string
# mapping, environment variable delivery, stdin content, SIGPIPE safety,
# api_auth_default behaviour, and failure modes.
#
# No running ctrl-exec or agent required.

use strict;
use warnings;
use Test::More;
use File::Temp qw(tempfile tempdir);
use JSON qw(decode_json encode_json);
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Exec::Auth qw();

unless (system('bash --version >/dev/null 2>&1') == 0) {
    plan skip_all => 'bash not available';
}

my $DIR = tempdir(CLEANUP => 1);
my $_seq = 0;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub make_hook {
    my ($exit_code, %opts) = @_;
    my $body = $opts{body} // '';
    my $path = sprintf '%s/hook-%03d.sh', $DIR, ++$_seq;
    open my $fh, '>', $path or die "Cannot write hook: $!";
    print $fh "#!/bin/bash\n$body\nexit $exit_code\n";
    close $fh;
    chmod 0755, $path;
    return $path;
}

sub make_recording_hook {
    my ($env_out, $stdin_out) = @_;
    my $path = sprintf '%s/hook-%03d.sh', $DIR, ++$_seq;
    open my $fh, '>', $path or die $!;
    print $fh "#!/bin/bash\nenv > '$env_out'\ncat > '$stdin_out'\nexit 0\n";
    close $fh;
    chmod 0755, $path;
    return $path;
}

sub run_args {
    my (%extra) = @_;
    return (
        action    => 'run',
        script    => 'backup-mysql',
        hosts     => ['web-01'],
        args      => ['--db', 'myapp'],
        username  => 'alice',
        token     => 'tok-test',
        source_ip => '127.0.0.1',
        %extra,
    );
}

# ---------------------------------------------------------------------------
# No hook configured - CLI caller
# ---------------------------------------------------------------------------

subtest 'no hook, cli caller: passes unconditionally' => sub {
    my $r = Exec::Auth::check(action => 'run', config => {}, caller => 'cli',
        run_args());
    is $r->{ok}, 1, 'cli passes with no hook';
};

subtest 'no hook, cli caller: ping also passes' => sub {
    my $r = Exec::Auth::check(action => 'ping', config => {}, caller => 'cli',
        hosts => ['web-01'], source_ip => '127.0.0.1');
    is $r->{ok}, 1, 'ping passes for cli with no hook';
};

# ---------------------------------------------------------------------------
# No hook configured - API caller
# ---------------------------------------------------------------------------

subtest 'no hook, api caller, api_auth_default = deny: request denied' => sub {
    my $r = Exec::Auth::check(action => 'run', caller => 'api',
        config => { api_auth_default => 'deny' }, run_args());
    is $r->{ok}, 0, 'api denied when no hook and default=deny';
    ok defined $r->{reason}, "reason present: $r->{reason}";
};

subtest 'no hook, api caller, default omitted: denied (default is deny)' => sub {
    my $r = Exec::Auth::check(action => 'run', caller => 'api',
        config => {}, run_args());
    is $r->{ok}, 0, 'api denied when no hook and no default (implicit deny)';
};

subtest 'no hook, api caller, api_auth_default = allow: request passes' => sub {
    my $r = Exec::Auth::check(action => 'run', caller => 'api',
        config => { api_auth_default => 'allow' }, run_args());
    is $r->{ok}, 1, 'api passes when no hook and default=allow';
};

# ---------------------------------------------------------------------------
# Hook exit codes
# ---------------------------------------------------------------------------

subtest 'hook exit 0: authorised' => sub {
    my $r = Exec::Auth::check(config => { auth_hook => make_hook(0) }, run_args());
    is $r->{ok}, 1, 'ok => 1 for exit 0';
    ok !defined $r->{reason}, 'no reason on pass';
};

subtest 'hook exit 1: denied - generic' => sub {
    my $r = Exec::Auth::check(config => { auth_hook => make_hook(1) }, run_args());
    is $r->{ok},   0, 'ok => 0';
    is $r->{code}, 1, 'code => 1';
    like $r->{reason}, qr/denied/i, "reason mentions denial: $r->{reason}";
};

subtest 'hook exit 2: bad credentials' => sub {
    my $r = Exec::Auth::check(config => { auth_hook => make_hook(2) }, run_args());
    is $r->{ok},   0, 'ok => 0';
    is $r->{code}, 2, 'code => 2';
    like $r->{reason}, qr/credential|bad/i, "reason mentions credentials: $r->{reason}";
};

subtest 'hook exit 3: insufficient privilege' => sub {
    my $r = Exec::Auth::check(config => { auth_hook => make_hook(3) }, run_args());
    is $r->{ok},   0, 'ok => 0';
    is $r->{code}, 3, 'code => 3';
    like $r->{reason}, qr/privilege|insuffi/i, "reason mentions privilege: $r->{reason}";
};

subtest 'hook exit 127: denied, no crash' => sub {
    my $r = eval { Exec::Auth::check(config => { auth_hook => make_hook(127) }, run_args()) };
    ok !$@, "no exception: $@";
    is $r->{ok}, 0, 'ok => 0 for exit 127';
};

subtest 'hook exit 42 (unexpected): denied' => sub {
    my $r = eval { Exec::Auth::check(config => { auth_hook => make_hook(42) }, run_args()) };
    ok !$@, 'no exception for unexpected exit';
    is $r->{ok}, 0, 'ok => 0 for unexpected exit code';
};

# ---------------------------------------------------------------------------
# Environment variables delivered to hook
# ---------------------------------------------------------------------------

subtest 'hook receives correct env vars' => sub {
    my $env_out   = "$DIR/env-vars.txt";
    my $stdin_out = "$DIR/stdin-vars.txt";
    my $hook      = make_recording_hook($env_out, $stdin_out);

    Exec::Auth::check(
        config    => { auth_hook => $hook },
        action    => 'run',
        script    => 'deploy-app',
        hosts     => ['web-01', 'web-02'],
        args      => ['--env', 'prod'],
        username  => 'bob',
        token     => 'secret-token',
        source_ip => '10.0.0.5',
        caller    => 'cli',
    );

    ok -f $env_out, 'hook was called';
    my $env = do { local $/; open my $fh, '<', $env_out or die $!; <$fh> };

    like $env, qr/ENVEXEC_ACTION=run/,        'ENVEXEC_ACTION=run';
    like $env, qr/ENVEXEC_SCRIPT=deploy-app/, 'ENVEXEC_SCRIPT';
    like $env, qr/ENVEXEC_USERNAME=bob/,      'ENVEXEC_USERNAME';
    like $env, qr/ENVEXEC_SOURCE_IP=10\.0\.0\.5/, 'ENVEXEC_SOURCE_IP';
    like $env, qr/ENVEXEC_HOSTS=.*web-01/,    'ENVEXEC_HOSTS contains web-01';
    like $env, qr/ENVEXEC_TOKEN=secret-token/, 'ENVEXEC_TOKEN delivered';

    if ($env =~ /ENVEXEC_ARGS_JSON=(.+)/) {
        my $json_str = $1; chomp $json_str;
        my $args = eval { decode_json($json_str) };
        ok !$@, 'ENVEXEC_ARGS_JSON is valid JSON';
        is ref $args, 'ARRAY', 'ENVEXEC_ARGS_JSON is array';
        ok grep { $_ eq '--env' } @$args, 'contains --env';
        ok grep { $_ eq 'prod'  } @$args, 'contains prod';
    }
    else {
        fail 'ENVEXEC_ARGS_JSON not found in env';
    }
};

subtest 'ENVEXEC_TOKEN not in STDOUT/STDERR from Auth module' => sub {
    my $env_out   = "$DIR/env-token.txt";
    my $stdin_out = "$DIR/stdin-token.txt";
    my $hook      = make_recording_hook($env_out, $stdin_out);

    my ($out, $err) = ('', '');
    {
        local *STDOUT; local *STDERR;
        open STDOUT, '>', \$out;
        open STDERR, '>', \$err;
        Exec::Auth::check(
            config    => { auth_hook => $hook },
            action    => 'run', script => 'deploy', hosts => ['web-01'],
            token     => 'should-not-appear',
            source_ip => '127.0.0.1', caller => 'cli',
        );
    }
    unlike $out . $err, qr/should-not-appear/,
        'token does not appear in module STDOUT/STDERR';
};

# ---------------------------------------------------------------------------
# stdin content delivered to hook
# ---------------------------------------------------------------------------

subtest 'hook receives full request context as JSON on stdin' => sub {
    my $env_out   = "$DIR/env-stdin.txt";
    my $stdin_out = "$DIR/stdin-ctx.json";
    my $hook      = make_recording_hook($env_out, $stdin_out);

    Exec::Auth::check(
        config    => { auth_hook => $hook },
        action    => 'run', script => 'backup', hosts => ['db-01'],
        args      => ['--full'], username => 'carol',
        token     => 'tok-stdin', source_ip => '10.1.2.3', caller => 'cli',
    );

    ok -f $stdin_out, 'stdin written';
    my $raw = do { local $/; open my $fh, '<', $stdin_out or die $!; <$fh> };
    my $ctx = eval { decode_json($raw) };
    ok !$@, "stdin is valid JSON: $@";

    is $ctx->{action},    'run',       'stdin.action';
    is $ctx->{script},    'backup',    'stdin.script';
    is $ctx->{username},  'carol',     'stdin.username';
    is $ctx->{token},     'tok-stdin', 'stdin.token';
    is $ctx->{source_ip}, '10.1.2.3', 'stdin.source_ip';
    is ref $ctx->{hosts}, 'ARRAY',     'stdin.hosts is array';
    is ref $ctx->{args},  'ARRAY',     'stdin.args is array';
    is $ctx->{args}[0],   '--full',    'stdin.args[0]';
};

# ---------------------------------------------------------------------------
# SIGPIPE safety: hook that ignores stdin
# ---------------------------------------------------------------------------

subtest 'hook ignoring stdin does not raise SIGPIPE' => sub {
    my $hook = make_hook(0, body => '# exits without reading stdin');
    my $result = eval {
        local $SIG{PIPE} = sub { die "SIGPIPE\n" };
        Exec::Auth::check(
            config    => { auth_hook => $hook },
            action    => 'run', script => 'script', hosts => ['h1'],
            args      => [ ('--arg') x 100 ],
            source_ip => '127.0.0.1', caller => 'cli',
        );
    };
    ok !$@, "SIGPIPE not raised: $@";
    is $result->{ok}, 1, 'authorised';
};

# ---------------------------------------------------------------------------
# Missing / non-executable hook
# ---------------------------------------------------------------------------

subtest 'missing hook executable: denied, no crash' => sub {
    my $r = eval {
        Exec::Auth::check(
            config    => { auth_hook => '/nonexistent/hook.sh' },
            action    => 'run', script => 'deploy', hosts => ['web-01'],
            source_ip => '127.0.0.1', caller => 'cli',
        );
    };
    ok !$@, "no exception: $@";
    is $r->{ok}, 0, 'denied (fail-safe)';
    ok defined $r->{reason}, "reason present: $r->{reason}";
};

subtest 'non-executable hook file: denied, no crash' => sub {
    my ($fh, $path) = tempfile(DIR => $DIR, SUFFIX => '.sh', UNLINK => 1);
    print $fh "#!/bin/bash\nexit 0\n";
    close $fh;
    chmod 0644, $path;

    my $r = eval {
        Exec::Auth::check(
            config    => { auth_hook => $path },
            action    => 'run', script => 'deploy', hosts => ['web-01'],
            source_ip => '127.0.0.1', caller => 'cli',
        );
    };
    ok !$@, "no exception: $@";
    is $r->{ok}, 0, 'denied';
};

# ---------------------------------------------------------------------------
# Ping action
# ---------------------------------------------------------------------------

subtest 'hook exit 0 for ping action' => sub {
    my $r = Exec::Auth::check(
        config => { auth_hook => make_hook(0) },
        action => 'ping', hosts => ['web-01'], source_ip => '127.0.0.1', caller => 'cli',
    );
    is $r->{ok}, 1, 'ping authorised';
};

subtest 'hook receives ENVEXEC_ACTION=ping' => sub {
    my $env_out   = "$DIR/env-ping.txt";
    my $stdin_out = "$DIR/stdin-ping.txt";
    my $hook      = make_recording_hook($env_out, $stdin_out);

    Exec::Auth::check(
        config => { auth_hook => $hook },
        action => 'ping', hosts => ['web-01'], source_ip => '127.0.0.1', caller => 'cli',
    );

    my $env = do { local $/; open my $fh, '<', $env_out or die $!; <$fh> };
    like $env, qr/ENVEXEC_ACTION=ping/, 'ENVEXEC_ACTION=ping';
    if ($env =~ /ENVEXEC_SCRIPT=(.*)/) {
        my $val = $1; chomp $val;
        is $val, '', 'ENVEXEC_SCRIPT empty for ping';
    }
};

# ---------------------------------------------------------------------------
# Confidential input (T-013): names and size only, never values
# ---------------------------------------------------------------------------

subtest 'input names and bytes reach the hook; values cannot' => sub {
    my $env_f   = "$DIR/env-input.txt";
    my $stdin_f = "$DIR/stdin-input.txt";
    my $hook = make_recording_hook($env_f, $stdin_f);
    my $r = Exec::Auth::check(config => { auth_hook => $hook },
        run_args(input_names => ['key', 'cert'], input_bytes => 2048));
    is $r->{ok}, 1, 'authorised';
    open my $ef, '<', $env_f or die; my $env = do { local $/; <$ef> }; close $ef;
    like $env, qr/^ENVEXEC_INPUT_NAMES_JSON=\["key","cert"\]$/m, 'names in env';
    like $env, qr/^ENVEXEC_INPUT_BYTES=2048$/m, 'bytes in env';
    open my $sf, '<', $stdin_f or die; my $ctx = decode_json(do { local $/; <$sf> }); close $sf;
    is_deeply $ctx->{input_names}, ['key', 'cert'], 'names in stdin JSON';
    is $ctx->{input_bytes}, 2048, 'bytes in stdin JSON';

    my $r2 = Exec::Auth::check(config => { auth_hook => $hook }, run_args());
    open $ef, '<', $env_f or die; $env = do { local $/; <$ef> }; close $ef;
    like $env, qr/^ENVEXEC_INPUT_NAMES_JSON=\[\]$/m, 'no input: empty names';
    like $env, qr/^ENVEXEC_INPUT_BYTES=0$/m, 'no input: zero bytes';

    ok !eval { Exec::Auth::check(config => { auth_hook => $hook },
        run_args(input => { key => 'SECRET' })); 1 }, 'passing values croaks';
    like $@, qr/never be passed/, 'with a clear reason';
};

done_testing;
