package Exec::Agent::Runner;

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use JSON   qw(encode_json);
use File::Path qw(remove_tree);
use File::Temp qw(tempdir);
use File::Spec qw();
use Encode     qw();
use Fcntl  qw(O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
use POSIX  qw(WIFEXITED WEXITSTATUS EINTR EAGAIN EPIPE);
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
#   $timeout      - seconds allowed for writing stdin (default 10)
#   $in           - optional hashref, confidential run input (T-013):
#                     mode   => 'context' | 'raw' | 'raw:<name>' | 'fields'
#                               (default 'context'; the caller has already
#                               checked the input fits the mode)
#                     input  => hashref of named string fields (may be empty)
#                     tmpdir => parent for the 'fields' directory (default the
#                               system temp dir)
#                   context: the stdin JSON gains an 'input' object (only when
#                   there is input). raw: stdin is the one field's bytes and the
#                   context JSON (without input or token) is in CTRL_EXEC_CONTEXT.
#                   fields: stdin is empty, each field is a 0600 file in a 0700
#                   per-run directory named by CTRL_EXEC_INPUT (CTRL_EXEC_CONTEXT
#                   as for raw), removed once the script has been reaped
#                   whatever way it ended. Input values go nowhere else.
#
# Returns hashref: { stdout => '', stderr => '', exit => N }
#   exit  0+    script exit code
#   exit  126   killed by signal or exec failed
#   exit  -1    fork or pipe failure (error in stderr)
sub run_script ($script_path, $args = undef, $context = undef, $timeout = undef, $in = undef) {
    $args    //= [];
    $timeout //= 10;

    my $mode  = $in->{mode}  // 'context';
    my $input = $in->{input} // {};
    my $has_input = %$input ? 1 : 0;

    # Decide what goes to stdin and the environment before forking.
    my ($stdin_data, %extra_env, $fields_dir);
    if ($mode eq 'context') {
        if ($context || $has_input) {
            $stdin_data = encode_json($has_input ? { %{ $context // {} }, input => $input } : $context);
        }
    }
    else {
        # The environment reaches every child the script starts, so the
        # caller's token stays out of it (it is on stdin only, in context mode).
        my %ctx = %{ $context // {} };
        delete $ctx{token};
        $extra_env{CTRL_EXEC_CONTEXT} = encode_json(\%ctx);
        if ($mode eq 'fields') {
            $fields_dir = eval { _make_fields_dir($input, $in->{tmpdir}) };
            unless (defined $fields_dir) {
                (my $why = $@) =~ s/\s+\z//;
                return _error("cannot prepare input files: $why");
            }
            $extra_env{CTRL_EXEC_INPUT} = $fields_dir;
        }
        else {
            # raw / raw:<name>: the caller guaranteed which field it is.
            my ($field) = $mode =~ /\Araw:(.*)\z/s;
            $field = (sort keys %$input)[0] unless defined $field;
            my $bytes = $input->{$field} // '';
            utf8::encode($bytes);
            $stdin_data = $bytes;
        }
    }

    my $result = _run_forked($script_path, $args, $stdin_data, \%extra_env, $timeout);
    # The directory goes whether the script exited, was killed by a signal or
    # failed to start.
    remove_tree($fields_dir) if defined $fields_dir;
    return $result;
}

sub _run_forked ($script_path, $args, $stdin_data, $extra_env, $timeout) {

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
        close $stdin_r;
        close $stdout_w;
        close $stderr_w;

        _sanitise_env();
        $ENV{$_} = $extra_env->{$_} for keys %$extra_env;

        # An ignored SIGPIPE survives exec. If the agent was started with it
        # ignored (systemd does), put the default back so the script sees
        # ordinary pipe semantics.
        $SIG{PIPE} = 'DEFAULT';

        # exec without shell - args passed as list
        exec { $script_path } $script_path, @$args
            or POSIX::_exit(127);
    }

    # Parent
    close $stdin_r;
    close $stdout_w;
    close $stderr_w;

    # Write context JSON to script stdin with timeout, then close to signal EOF
    if (defined $stdin_data) {
        _write_stdin($stdin_w, $stdin_data, $timeout);
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

# The per-run directory for input=fields: created by the agent as its own user,
# mode 0700 (File::Temp, unpredictable name), one 0600 file per field. Only the
# agent user (and root) can enter it. Any failure removes what was made.
sub _make_fields_dir ($input, $parent) {
    $parent //= File::Spec->tmpdir;
    my $dir = tempdir('ctrl-exec-input-XXXXXXXXXX', DIR => $parent, CLEANUP => 0);
    chmod 0700, $dir;
    my $ok = eval {
        for my $name (sort keys %$input) {
            my $bytes = $input->{$name};
            utf8::encode($bytes);
            sysopen(my $fh, "$dir/$name", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
                or die "cannot create input file '$name': $!\n";
            chmod 0600, $fh;
            my $off = 0;
            while ($off < length $bytes) {
                my $n = syswrite($fh, $bytes, length($bytes) - $off, $off);
                die "cannot write input file '$name': $!\n" unless defined $n;
                $off += $n;
            }
            close $fh or die "cannot write input file '$name': $!\n";
        }
        1;
    };
    unless ($ok) {
        my $err = $@;
        remove_tree($dir);
        die $err;
    }
    return $dir;
}

# Write to the script's stdin pipe with a timeout.
# Uses O_NONBLOCK + select to avoid blocking indefinitely if the script
# does not read stdin. On timeout or unrecoverable error, closes the write
# end and returns — the script receives EOF and may exit normally or with
# a JSON parse error. Either is preferable to the agent child hanging.
#
# A script that exits (or closes stdin) without reading its context leaves the
# write with no reader: EPIPE, and SIGPIPE at its default would kill this
# process. SIGPIPE is ignored for the duration of the write only, and EPIPE is
# taken to mean "the script did not read its input" - not an error (T-038).
sub _write_stdin ($fh, $data, $timeout = undef) {
    $timeout //= 10;
    local $SIG{PIPE} = 'IGNORE';

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
            last if $! == EPIPE;    # script did not read its input; not an error
            last;    # real error — close and let script see EOF
        }
        $offset += $n;
    }
}

# Script output as text: read the bytes, decode UTF-8 once, and replace any
# byte sequence that is not UTF-8 with U+FFFD, so the JSON reply always
# encodes (a malformed string made encode_json die). Exec::Agent::ExecClient
# decodes executor output the same way.
sub _slurp_utf8 ($fh) {
    binmode $fh, ':raw';
    local $/;
    my $bytes = <$fh> // '';
    return Encode::decode('UTF-8', $bytes);
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
