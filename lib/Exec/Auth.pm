package Exec::Auth;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON  qw(encode_json);
use Carp  qw(croak);
use POSIX qw(strftime);

use Exec::Log qw();


# Exit codes returned by auth hooks
use constant {
    AUTH_OK          => 0,
    AUTH_DENIED      => 1,
    AUTH_BAD_CREDS   => 2,
    AUTH_INSUFFICIENT => 3,
};

my %CODE_REASON = (
    AUTH_DENIED,       'denied',
    AUTH_BAD_CREDS,    'bad credentials',
    AUTH_INSUFFICIENT, 'insufficient privilege',
);

# Check authorisation for a request by running the configured auth hook.
#
# If no hook is configured (auth_hook absent or empty in config), the call
# is unconditionally authorised. This preserves backwards compatibility for
# CLI use without a hook configured.
#
# Required opts:
#   action    => 'run' | 'ping'
#   config    => \%config          (may contain auth_hook path)
#
# Optional opts:
#   script    => $name             (empty string for ping)
#   hosts     => \@hosts           (default [])
#   args      => \@args            (default [])
#   username  => $str              (default '')
#   token     => $str              (default '')
#   source_ip => $str              (default '127.0.0.1')
#   dispatcher        => $str      (calling dispatcher's stable identity, default '')
#   dispatcher_serial => $str      (calling dispatcher's cert serial, default '')
#
# Returns:
#   { ok => 1 }
#   { ok => 0, reason => $str, code => $n }
sub check (%opts) {
    my $action    = $opts{action}    or croak "action required";
    my $config    = $opts{config}    or croak "config required";
    my $script    = $opts{script}    // '';
    my $hosts     = $opts{hosts}     // [];
    my $args      = $opts{args}      // [];
    my $username  = $opts{username}  // '';
    my $token     = $opts{token}     // '';
    my $source_ip = $opts{source_ip} // '127.0.0.1';
    my $caller    = $opts{caller}    // 'api';   # 'api' | 'cli'
    my $dispatcher        = $opts{dispatcher}        // '';
    my $dispatcher_serial = $opts{dispatcher_serial} // '';
    # For result-access ('status') checks: the run id being read, and the
    # recorded submitter, so a hook can owner-gate (compare the caller to who
    # submitted the run).
    my $reqid     = $opts{reqid}     // '';
    my $submitter = $opts{submitter};   # hashref { username, source_ip } or undef

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';
    croak "args must be an arrayref"  unless ref $args  eq 'ARRAY';

    my $hook = $config->{auth_hook} // '';

    # No hook configured.
    # CLI callers (bin/ctrl-exec-dispatcher modes) are already gated by system user
    # permissions - unconditional pass preserves the original CLI behaviour.
    # API callers apply api_auth_default (default: deny) so that an API
    # endpoint without a hook fails closed rather than open.
    unless ($hook) {
        if ($caller eq 'cli') {
            Exec::Log::log_action('INFO', {
                ACTION     => 'auth',
                RESULT     => 'pass',
                REASON     => 'no-hook-cli',
                AUTHACTION => $action,
                USER       => $username || '(none)',
                DISPATCHER => $dispatcher,
                IP         => $source_ip,
            });
            return { ok => 1 };
        }

        my $default = lc($config->{api_auth_default} // 'deny');
        if ($default eq 'allow') {
            Exec::Log::log_action('INFO', {
                ACTION     => 'auth',
                RESULT     => 'pass',
                REASON     => 'no-hook-allow',
                AUTHACTION => $action,
                USER       => $username || '(none)',
                DISPATCHER => $dispatcher,
                IP         => $source_ip,
            });
            return { ok => 1 };
        }
        else {
            Exec::Log::log_action('WARNING', {
                ACTION     => 'auth',
                RESULT     => 'deny',
                REASON     => 'no-hook-deny',
                AUTHACTION => $action,
                USER       => $username || '(none)',
                DISPATCHER => $dispatcher,
                IP         => $source_ip,
            });
            return { ok => 0, reason => 'no auth hook configured', code => AUTH_DENIED };
        }
    }

    unless (-f $hook && -x $hook) {
        Exec::Log::log_action('ERR', {
            ACTION => 'auth',
            RESULT => 'error',
            REASON => 'hook-not-executable',
            HOOK   => $hook,
        });
        return { ok => 0, reason => "auth hook not found or not executable: $hook", code => AUTH_DENIED };
    }

    my $context = _build_context(
        action            => $action,
        script            => $script,
        hosts             => $hosts,
        args              => $args,
        username          => $username,
        token             => $token,
        source_ip         => $source_ip,
        dispatcher        => $dispatcher,
        dispatcher_serial => $dispatcher_serial,
        reqid             => $reqid,
        submitter         => $submitter,
    );

    my $hook_timeout = $config->{auth_hook_timeout} // 10;
    my $exit_code = _run_hook($hook, $context, $hook_timeout);

    if ($exit_code == AUTH_OK) {
        Exec::Log::log_action('INFO', {
            ACTION     => 'auth',
            RESULT     => 'pass',
            AUTHACTION => $action,
            USER       => $username || '(none)',
            IP         => $source_ip,
        });
        return { ok => 1 };
    }

    my $reason = $CODE_REASON{$exit_code} // "hook exited $exit_code";

    Exec::Log::log_action('WARNING', {
        ACTION     => 'auth',
        RESULT     => 'deny',
        REASON     => $reason,
        AUTHACTION => $action,
        USER       => $username || '(none)',
        IP         => $source_ip,
    });

    return { ok => 0, reason => $reason, code => $exit_code };
}

# Whether generic (reason-less) auth denials are enabled. When the config flag
# auth_deny_generic is on, denial responses to callers omit the specific reason
# and code, reducing information disclosure to unauthorised callers. The full
# reason is still logged server-side by check(). Default off.
sub generic_denials_enabled ($config) {
    my $v = $config->{auth_deny_generic} // '';
    return ($v =~ /^\s*[1y]/i) ? 1 : 0;
}

# Disclosable fields for a denied auth result, to be merged into a 403 body.
# With auth_deny_generic off (default): the specific reason and code. With it
# on: a generic message only. Returns a hashref (no 'ok' key - the caller adds
# it with its own JSON false value).
sub deny_fields ($auth, $config) {
    return { error => 'forbidden' } if generic_denials_enabled($config);
    return { error => $auth->{reason}, code => $auth->{code} };
}

# --- private ---

# Build the context hashref passed to the hook as env vars and JSON stdin
sub _build_context (%opts) {
    return {
        action            => $opts{action},
        script            => $opts{script},
        hosts             => $opts{hosts},
        args              => $opts{args},
        username          => $opts{username},
        token             => $opts{token},
        source_ip         => $opts{source_ip},
        dispatcher        => $opts{dispatcher}        // '',
        dispatcher_serial => $opts{dispatcher_serial} // '',
        reqid             => $opts{reqid}             // '',
        submitter         => $opts{submitter},
        timestamp         => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime),
    };
}

# Run the hook, passing context as env vars and JSON on stdin.
# Returns the hook's exit code.
# On exec failure returns AUTH_DENIED.
sub _run_hook ($hook, $context, $timeout = undef) {
    $timeout //= 10;

    my $json_in = encode_json($context);

    # Build environment for hook
    local %ENV = %ENV;
    $ENV{ENVEXEC_ACTION}    = $context->{action};
    $ENV{ENVEXEC_SCRIPT}    = $context->{script};
    $ENV{ENVEXEC_HOSTS}     = join(',', @{ $context->{hosts} });
    $ENV{ENVEXEC_ARGS}      = join(' ', @{ $context->{args} });   # DEPRECATED: lossy if args contain spaces or newlines; use ENVEXEC_ARGS_JSON
    $ENV{ENVEXEC_ARGS_JSON} = encode_json($context->{args});       # reliable JSON array
    $ENV{ENVEXEC_USERNAME}  = $context->{username};
    $ENV{ENVEXEC_TOKEN}     = $context->{token};
    $ENV{ENVEXEC_SOURCE_IP} = $context->{source_ip};
    # The calling dispatcher's stable identity (and its cert serial). Hooks
    # author per-dispatcher policy against ENVEXEC_DISPATCHER, never the serial,
    # which rotates. Empty when the caller did not resolve a dispatcher.
    $ENV{ENVEXEC_DISPATCHER}        = $context->{dispatcher}        // '';
    $ENV{ENVEXEC_DISPATCHER_SERIAL} = $context->{dispatcher_serial} // '';
    # Result-access ('status') context: the run id being read and who submitted
    # it, so a hook can owner-gate (e.g. deny unless the caller matches the
    # submitter). Empty on non-status actions and on runs recorded before this.
    $ENV{ENVEXEC_REQID}        = $context->{reqid} // '';
    $ENV{ENVEXEC_SUBMITTER}    = ($context->{submitter} && $context->{submitter}{username})  // '';
    $ENV{ENVEXEC_SUBMITTER_IP} = ($context->{submitter} && $context->{submitter}{source_ip}) // '';
    $ENV{ENVEXEC_TIMESTAMP} = $context->{timestamp};

    # Fork: child execs hook with JSON on stdin, parent waits.
    # Block SIGCHLD before forking so the API server reaper cannot collect
    # the hook child between fork() and waitpid(). local restores on scope exit.
    local $SIG{CHLD} = 'DEFAULT';

    pipe my $stdin_r, my $stdin_w or return AUTH_DENIED;

    my $pid = fork();
    return AUTH_DENIED unless defined $pid;

    if ($pid == 0) {
        close $stdin_w;
        open STDIN, '<&', $stdin_r or exit AUTH_DENIED;
        close $stdin_r;

        # Redirect hook stdout/stderr to /dev/null - hook must not produce
        # output; logging is the ctrl-exec's responsibility
        open STDOUT, '>', '/dev/null';
        open STDERR, '>', '/dev/null';

        exec { $hook } $hook;
        exit AUTH_DENIED;   # only reached if exec fails
    }

    close $stdin_r;
    # Guard against SIGPIPE if the hook exits before reading all of stdin.
    # Without this, a broken pipe would kill the current process (the forked
    # API request handler). The write simply fails silently instead.
    local $SIG{PIPE} = 'IGNORE';

    # Bound the hook's run time. A hook that hangs - e.g. blocking on an
    # unreachable identity service - must not wedge the forked request handler
    # forever. On timeout the hook is killed and the request fails closed.
    my $exit_code;
    my $ok = eval {
        local $SIG{ALRM} = sub { die "hook-timeout\n" };
        alarm($timeout);
        print $stdin_w $json_in;
        close $stdin_w;
        waitpid $pid, 0;
        alarm(0);
        # If waitpid was raced (ret -1), $? is -1 and ($? >> 8) & 0xff = 255 -
        # guarded against by the local SIGCHLD = DEFAULT above.
        $exit_code = ($? >> 8) & 0xff;
        1;
    };
    alarm(0);

    unless ($ok) {
        # Timeout (or any unexpected die): KILL the hook - uncatchable, so the
        # reap returns promptly and leaves no zombie - and deny.
        kill 'KILL', $pid;
        waitpid $pid, 0;
        Exec::Log::log_action('WARNING', {
            ACTION  => 'auth-hook-timeout',
            TIMEOUT => $timeout,
        });
        return AUTH_DENIED;
    }

    return $exit_code;
}

1;
