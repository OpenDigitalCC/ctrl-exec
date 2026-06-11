package Exec::Agent::AsyncRunner;

use strict;
use warnings;
use JSON       qw(encode_json decode_json);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use File::Basename qw(dirname);
use POSIX      qw(setsid strftime);
use Carp       qw(croak);

use Exec::Agent::Runner qw();
use Exec::Log qw();


my $DEFAULT_RUNS_DIR = '/var/lib/ctrl-exec-agent/runs';
my $DEFAULT_TTL      = 86400;   # seconds; results older than this are purged


# Start an allowlisted script detached and persist its result, keyed by reqid,
# in the agent's run store. Returns immediately after recording the 'running'
# state - the script runs in a detached grandchild that survives this process
# (and the connection that triggered it) and writes the 'done' result when the
# script exits.
#
# NOTE: detachment here is setsid + double-fork, which survives the triggering
# connection and this handler process. Surviving `systemctl restart
# ctrl-exec-agent` additionally requires the job to run in its own cgroup (a
# systemd transient scope) - that is layered on in a later step; this is the
# store + detached-exec foundation.
#
# Required opts:
#   reqid       => $hex      (the dispatch request id; used as the store key)
#   script_path => $path     (absolute path; caller has done the allowlist check)
#
# Optional opts:
#   script      => $name     (allowlist name, for the record)
#   args        => \@args     (default [])
#   context     => \%context  (JSON piped to the script's stdin)
#   runs_dir    => $path      (default /var/lib/ctrl-exec-agent/runs)
#   stdin_timeout => $sec     (passed to Runner::run_script)
#
# Returns 1 once the job is spawned, 0 if it could not be spawned.
sub submit {
    my (%opts) = @_;
    my $reqid       = $opts{reqid}       or croak "reqid required";
    my $script_path = $opts{script_path} or croak "script_path required";
    croak "invalid reqid '$reqid'" unless $reqid =~ /^[A-Za-z0-9_-]+\z/;

    my $args     = $opts{args}     // [];
    my $context  = $opts{context};
    my $script   = $opts{script}   // '';
    my $runs_dir = $opts{runs_dir} // $DEFAULT_RUNS_DIR;
    my $timeout  = $opts{stdin_timeout};

    make_path($runs_dir) unless -d $runs_dir;
    my $started = _now();

    # Record 'running' before spawning so a fetch between spawn and completion
    # sees a pending result rather than a missing one.
    _write_record($runs_dir, $reqid, {
        reqid   => $reqid,
        status  => 'running',
        script  => $script,
        started => $started,
    });

    return _spawn_detached(sub {
        my $result = Exec::Agent::Runner::run_script(
            $script_path, $args, $context, $timeout,
        );
        _write_record($runs_dir, $reqid, {
            reqid    => $reqid,
            status   => 'done',
            script   => $script,
            started  => $started,
            finished => _now(),
            exit     => $result->{exit},
            stdout   => $result->{stdout},
            stderr   => $result->{stderr},
        });
    });
}

# Return the stored result record for a reqid, or undef if none.
sub result {
    my ($reqid, $runs_dir) = @_;
    $runs_dir //= $DEFAULT_RUNS_DIR;
    my $file = "$runs_dir/$reqid.json";
    return undef unless -f $file;
    return eval { decode_json(_slurp($file)) };
}

# Delete result records older than $ttl seconds (by mtime). Returns the count
# removed. Safe to call when the dir does not exist.
sub purge_expired {
    my ($runs_dir, $ttl) = @_;
    $runs_dir //= $DEFAULT_RUNS_DIR;
    $ttl      //= $DEFAULT_TTL;
    return 0 unless -d $runs_dir;
    my $cutoff = time() - $ttl;
    my $removed = 0;
    opendir my $dh, $runs_dir or return 0;
    while (my $entry = readdir $dh) {
        next unless $entry =~ /^[A-Za-z0-9_-]+\.json\z/;
        my $path = "$runs_dir/$entry";
        next unless (stat $path)[9] < $cutoff;
        $removed++ if unlink $path;
    }
    closedir $dh;
    return $removed;
}

# --- private ---

# Run $worker in a detached grandchild (double-fork + setsid) so it survives
# this process and the connection that triggered it. Returns 1 on spawn.
sub _spawn_detached {
    my ($worker) = @_;

    my $pid = fork();
    return 0 unless defined $pid;
    if ($pid) {
        waitpid $pid, 0;   # reap the intermediate child immediately
        return 1;
    }

    # Intermediate child: detach from the controlling session, fork again, and
    # exit so the grandchild is reparented away from this handler.
    POSIX::setsid();
    my $pid2 = fork();
    if (!defined $pid2 || $pid2) {
        POSIX::_exit(0);
    }

    # Grandchild: detach std handles so it holds nothing of the caller (e.g.
    # the agent's client socket), then run the job and exit.
    open STDIN,  '<', '/dev/null';
    open STDOUT, '>', '/dev/null';
    open STDERR, '>', '/dev/null';
    eval { $worker->() };
    POSIX::_exit(0);
}

sub _now {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
}

sub _write_record {
    my ($runs_dir, $reqid, $record) = @_;
    my $path = "$runs_dir/$reqid.json";
    my $dir  = dirname($path);
    make_path($dir) unless -d $dir;
    my ($fh, $tmp) = tempfile(DIR => $dir, SUFFIX => '.tmp', UNLINK => 0);
    print {$fh} encode_json($record);
    close $fh;
    chmod 0640, $tmp;
    unless (rename $tmp, $path) {
        unlink $tmp;
        Exec::Log::log_action('ERR', {
            ACTION => 'async-store-fail',
            REQID  => $reqid,
            ERROR  => "cannot write $path: $!",
        });
    }
}

sub _slurp {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    local $/;
    return scalar <$fh>;
}

1;
