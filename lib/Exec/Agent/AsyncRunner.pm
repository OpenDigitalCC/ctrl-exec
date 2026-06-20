package Exec::Agent::AsyncRunner;

use strict;
use warnings;
use JSON       qw(encode_json decode_json);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use File::Basename qw(dirname);
use Fcntl      qw(LOCK_EX LOCK_NB);
use POSIX      qw(setsid strftime);
use Carp       qw(croak);
use Exec::FileUtil qw(slurp_maybe);

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
# ctrl-exec-agent` additionally requires `KillMode=process` on the agent unit so
# the restart kills only the main process and leaves the detached grandchild
# running - that is wired in at the packaging step; this is the store +
# detached-exec foundation.
#
# Concurrency: a second async run of the SAME script is refused while one is
# still detached. This is enforced agent-side with a per-script flock held by
# the detached grandchild for the job's lifetime (the dispatcher lock releases
# as soon as the async submit returns, so it cannot cover the job). The lock fd
# is inherited across the double-fork and shared via the open file description,
# so the lock stays held until the grandchild exits.
#
# Required opts:
#   reqid       => $hex      (the dispatch request id; used as the store key)
#   script_path => $path     (absolute path; caller has done the allowlist check)
#
# Optional opts:
#   script      => $name     (allowlist name; the concurrency key and record tag)
#   args        => \@args     (default [])
#   context     => \%context  (JSON piped to the script's stdin)
#   owner       => $id        (submitting dispatcher's stable identity; the run
#                              is stored in this owner's namespace and the
#                              /result owner-gate enforces it. Must be a safe
#                              token; empty stores flat. See _record_path)
#   runs_dir    => $path      (default /var/lib/ctrl-exec-agent/runs)
#   stdin_timeout => $sec     (passed to Runner::run_script)
#
# Returns a hashref:
#   { ok => 1 }                       job spawned and recorded 'running'
#   { ok => 0, reason => 'busy' }     same script already running (no record written)
#   { ok => 0, reason => 'error' }    fork failed; could not spawn
sub submit {
    my (%opts) = @_;
    my $reqid       = $opts{reqid}       or croak "reqid required";
    my $script_path = $opts{script_path} or croak "script_path required";
    croak "invalid reqid '$reqid'" unless $reqid =~ /^[A-Za-z0-9_-]+\z/;

    my $args     = $opts{args}     // [];
    my $context  = $opts{context};
    my $script   = $opts{script}   // '';
    my $owner    = $opts{owner}    // '';
    my $runs_dir = $opts{runs_dir} // $DEFAULT_RUNS_DIR;
    my $timeout  = $opts{stdin_timeout};

    # The owner (submitting dispatcher's identity) becomes a directory component
    # under which this run is stored, so it must be a safe token. An empty owner
    # stores flat in $runs_dir (legacy / no-dispatcher callers).
    croak "invalid owner '$owner'"
        if length $owner && $owner !~ /^[A-Za-z0-9][A-Za-z0-9._-]*\z/;

    make_path($runs_dir) unless -d $runs_dir;

    # Opportunistic TTL sweep on each new submit so the result store cannot grow
    # unbounded (the common case needs no separate timer). Bounded to async-submit
    # frequency; uses the default 24h TTL.
    purge_expired($runs_dir);

    # Acquire the per-script concurrency lock before writing any record. If a
    # job for this script is already detached, refuse without clobbering the
    # store. A blank script name carries no concurrency guarantee (callers
    # always pass the allowlist name); skip the lock in that case.
    my $lock_fh;
    if (length $script) {
        $lock_fh = _acquire_script_lock($runs_dir, $script);
        return { ok => 0, reason => 'busy' } unless $lock_fh;
    }

    my $started = _now();

    # Record 'running' before spawning so a fetch between spawn and completion
    # sees a pending result rather than a missing one.
    _write_record($runs_dir, $owner, $reqid, {
        reqid   => $reqid,
        status  => 'running',
        script  => $script,
        owner   => $owner,
        started => $started,
    });

    my $spawned = _spawn_detached(sub {
        my $result = Exec::Agent::Runner::run_script(
            $script_path, $args, $context, $timeout,
        );
        _write_record($runs_dir, $owner, $reqid, {
            reqid    => $reqid,
            status   => 'done',
            script   => $script,
            owner    => $owner,
            started  => $started,
            finished => _now(),
            exit     => $result->{exit},
            stdout   => $result->{stdout},
            stderr   => $result->{stderr},
        });
        # The lock is released when this grandchild exits and its inherited fd
        # closes. Reference it here so it stays open for the job's lifetime.
        undef $lock_fh;
    });

    return $spawned ? { ok => 1 } : { ok => 0, reason => 'error' };
}

# Return the stored result record for a reqid, or undef if none. The store is
# partitioned by owner: a run submitted by dispatcher $owner lives under its own
# subdirectory, so a lookup scoped to $owner can only ever see that dispatcher's
# runs. This makes cross-dispatcher isolation structural - a different
# dispatcher's reqid is simply not present in this owner's namespace - rather
# than a field check after the fact. An empty/omitted $owner reads the flat
# layout (legacy / no-dispatcher callers).
sub result {
    my ($reqid, $runs_dir, $owner) = @_;
    $runs_dir //= $DEFAULT_RUNS_DIR;
    my $file = _record_path($runs_dir, $owner, $reqid);
    return undef unless -f $file;
    return eval { decode_json(slurp_maybe($file)) };
}

# True if a run record belongs to the dispatcher whose stable identity is $id.
# The /result owner-gate uses this so a run's output is disclosed only to the
# dispatcher that submitted it. Fails closed: a record carrying no owner (length
# 0) is owned by nobody and matches no dispatcher. Records are never written
# without an owner under the multi-dispatcher model, so this only rejects
# malformed or pre-upgrade records.
sub owned_by {
    my ($record, $id) = @_;
    return 0 unless ref $record eq 'HASH';
    my $owner = $record->{owner};
    return 0 unless defined $owner && length $owner;
    return 0 unless defined $id    && length $id;
    return $owner eq $id ? 1 : 0;
}

# Delete result records older than $ttl seconds (by mtime). Returns the count
# removed. Safe to call when the dir does not exist. Records live either flat in
# $runs_dir (legacy / no-owner) or one level down in a per-owner subdirectory;
# both are swept. The .locks dir is skipped.
sub purge_expired {
    my ($runs_dir, $ttl) = @_;
    $runs_dir //= $DEFAULT_RUNS_DIR;
    $ttl      //= $DEFAULT_TTL;
    return 0 unless -d $runs_dir;
    my $cutoff = time() - $ttl;

    # The run store: $runs_dir itself (flat records) plus each per-owner subdir.
    my @dirs = ($runs_dir);
    if (opendir my $top, $runs_dir) {
        while (my $e = readdir $top) {
            next if $e eq '.' || $e eq '..' || $e eq '.locks';
            my $sub = "$runs_dir/$e";
            push @dirs, $sub if -d $sub;
        }
        closedir $top;
    }

    my $removed = 0;
    for my $dir (@dirs) {
        opendir my $dh, $dir or next;
        while (my $entry = readdir $dh) {
            next unless $entry =~ /^[A-Za-z0-9_-]+\.json\z/;
            my $path = "$dir/$entry";
            next unless (stat $path)[9] < $cutoff;
            $removed++ if unlink $path;
        }
        closedir $dh;
    }
    return $removed;
}

# --- private ---

# Acquire the per-script concurrency lock non-blocking. Returns the open
# filehandle (caller keeps it in scope to hold the lock) or undef if the lock
# is already held by another running job. The lock files live in a sibling
# `.locks` dir under the run store; the flock is released when the last fd
# referring to it closes (i.e. when the detached grandchild exits).
sub _acquire_script_lock {
    my ($runs_dir, $script) = @_;
    my $lock_dir = "$runs_dir/.locks";
    make_path($lock_dir) unless -d $lock_dir;
    (my $safe = $script) =~ s/[^\w.\-]/_/g;
    my $path = "$lock_dir/$safe.lock";
    open my $fh, '>>', $path or return undef;
    unless (flock $fh, LOCK_EX | LOCK_NB) {
        close $fh;
        return undef;
    }
    return $fh;
}

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

# Path to a run record, partitioned by owner: "$runs_dir/$owner/$reqid.json"
# when an owner is given, else flat "$runs_dir/$reqid.json". The owner is
# validated to a safe token at submit time, so it cannot escape $runs_dir.
sub _record_path {
    my ($runs_dir, $owner, $reqid) = @_;
    return (defined $owner && length $owner)
        ? "$runs_dir/$owner/$reqid.json"
        : "$runs_dir/$reqid.json";
}

sub _write_record {
    my ($runs_dir, $owner, $reqid, $record) = @_;
    my $path = _record_path($runs_dir, $owner, $reqid);
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

1;
