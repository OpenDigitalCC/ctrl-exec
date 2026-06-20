package Exec::Agent::Runner;

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use JSON   qw(encode_json);
use POSIX  qw(WIFEXITED WEXITSTATUS EINTR EAGAIN);
use Fcntl  qw(F_GETFL F_SETFL O_NONBLOCK);
use Exec::Log qw();   # _write_stdin logs a stdin-timeout; load it directly rather
                      # than relying on a caller having pulled it in first.


# Execute a script with no shell, capture stdout/stderr/exit.
# Pipes full request context as JSON to the script's stdin.
#
# Arguments:
#   $script_path  - absolute path to executable (caller does allowlist check)
#   $args         - arrayref of positional arguments (may be empty)
#   $context      - optional hashref piped as JSON to stdin
#                   Keys: script, args, reqid, peer_ip, username, token, timestamp
#                   If undef, stdin is closed immediately (empty).
#
# Returns hashref: { stdout => '', stderr => '', exit => N }
#   exit  0+    script exit code
#   exit  126   killed by signal or exec failed
#   exit  -1    fork or pipe failure (error in stderr)
sub run_script ($script_path, $args = undef, $context = undef, $timeout = undef) {
    $args    //= [];
    $timeout //= 10;

    # Pipes for stdin (JSON context), stdout, and stderr
    pipe my $stdin_r,  my $stdin_w  or return _error("pipe(stdin): $!");
    pipe my $stdout_r, my $stdout_w or return _error("pipe(stdout): $!");
    pipe my $stderr_r, my $stderr_w or return _error("pipe(stderr): $!");

    my $pid = fork();
    return _error("fork failed: $!") unless defined $pid;

    if ($pid == 0) {
        # Child
        close $stdin_w;
        close $stdout_r;
        close $stderr_r;
        open STDIN,  '<&', $stdin_r  or POSIX::_exit(127);
        open STDOUT, '>&', $stdout_w or POSIX::_exit(127);
        open STDERR, '>&', $stderr_w or POSIX::_exit(127);
        binmode STDIN,  ':utf8';
        binmode STDOUT, ':utf8';
        binmode STDERR, ':utf8';
        close $stdin_r;
        close $stdout_w;
        close $stderr_w;

        _sanitise_env();

        # exec without shell - args passed as list
        exec { $script_path } $script_path, @$args
            or POSIX::_exit(127);
    }

    # Parent
    close $stdin_r;
    close $stdout_w;
    close $stderr_w;

    # Write context JSON to script stdin with timeout, then close to signal EOF
    if ($context) {
        _write_stdin($stdin_w, encode_json($context), $timeout);
    }
    close $stdin_w;

    my $stdout = _slurp_utf8($stdout_r);
    my $stderr = _slurp_utf8($stderr_r);
    close $stdout_r;
    close $stderr_r;

    waitpid $pid, 0;
    my $exit = WIFEXITED($?) ? WEXITSTATUS($?) : 126;

    return {
        stdout => $stdout,
        stderr => $stderr,
        exit   => $exit,
    };
}

# Write to the script's stdin pipe with a timeout.
# Uses O_NONBLOCK + select to avoid blocking indefinitely if the script
# does not read stdin. On timeout or unrecoverable error, closes the write
# end and returns — the script receives EOF and may exit normally or with
# a JSON parse error. Either is preferable to the agent child hanging.
sub _write_stdin ($fh, $data, $timeout = undef) {
    $timeout //= 10;

    my $flags = fcntl($fh, F_GETFL, 0) or return;
    fcntl($fh, F_SETFL, $flags | O_NONBLOCK) or return;

    my $deadline = time + $timeout;
    my $offset   = 0;
    my $len      = length $data;

    while ($offset < $len) {
        if (time >= $deadline) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'stdin-timeout',
                BYTES  => $len - $offset,
            });
            return;
        }

        my $ready = '';
        vec($ready, fileno($fh), 1) = 1;
        my $found = select undef, $ready, undef, ($deadline - time);
        next if $found == -1 && $! == EINTR;
        last unless $found;

        my $n = syswrite $fh, $data, $len - $offset, $offset;
        if (!defined $n) {
            next if $! == EAGAIN || $! == EINTR;
            last;    # real error — close and let script see EOF
        }
        $offset += $n;
    }
}

sub _slurp_utf8 ($fh) {
    binmode $fh, ':utf8';
    local $/;
    return scalar <$fh> // '';
}

sub _error ($msg) {
    return { stdout => '', stderr => $msg, exit => -1 };
}

# Replace the environment with a minimal, known-safe set before exec. The agent
# runs no shell, but allowlisted scripts are commonly shell/perl/python, for
# which an inherited PATH/LD_*/BASH_ENV/IFS/PERL5LIB would be live attack
# surface. Request context reaches the script on stdin (JSON), never via env.
# A small whitelist is preserved from the agent's own (operator-controlled,
# systemd-supplied) environment; everything else, including the dangerous
# loader/shell variables, is dropped.
sub _sanitise_env {
    my %keep;
    for my $k (qw(HOME LANG LC_ALL TZ TERM USER LOGNAME)) {
        $keep{$k} = $ENV{$k} if exists $ENV{$k};
    }
    %ENV = (
        PATH => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        %keep,
    );
}

1;
