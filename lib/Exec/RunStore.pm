package Exec::RunStore;

use strict;
use warnings;
use JSON       qw(encode_json decode_json);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use Carp       qw(croak);

use Exec::Log    qw();
use Exec::Engine qw();


my $DEFAULT_RUNS_DIR = '/var/lib/ctrl-exec/runs';
my $DEFAULT_TTL      = 86400;   # seconds; records older than this are purged

# Terminal per-host states need no further fetching; pending ones are re-fetched
# on the next status aggregation.
my %PENDING = map { $_ => 1 } qw(accepted running);


# Record a synchronous run result, keyed by reqid. This preserves the existing
# dispatcher store shape (reqid/script/hosts/results/completed) and adds
# mode/complete so async and sync records are read uniformly.
#
#   reqid    => $hex
#   script   => $name
#   hosts    => \@hostnames        (as dispatched)
#   results  => \@result_hashrefs  (from dispatch_all)
#   runs_dir => $path              (default /var/lib/ctrl-exec/runs)
sub record_sync {
    my (%opts) = @_;
    my $reqid    = $opts{reqid}   or croak "reqid required";
    _valid_reqid($reqid) or croak "invalid reqid '$reqid'";
    my $runs_dir = $opts{runs_dir} // $DEFAULT_RUNS_DIR;

    _write($runs_dir, $reqid, {
        reqid     => $reqid,
        script    => $opts{script} // '',
        mode      => 'sync',
        hosts     => $opts{hosts}   // [],
        results   => $opts{results} // [],
        completed => time(),
        complete  => JSON::true,
    });
    return 1;
}

# Record an asynchronous dispatch, keyed by reqid. Captures the host list and
# the per-host acceptance state so a later status aggregation knows which hosts
# to fetch results from.
#
#   reqid             => $hex
#   script            => $name
#   dispatch_results  => \@results   (from dispatch_all with async => 1; each is
#                                      { host, status => accepted|busy|error })
#   runs_dir          => $path
#
# Per-host status after recording:
#   accepted -> job is running on the agent (pending; will be fetched)
#   busy     -> agent refused a concurrent run (terminal; no job)
#   error    -> submit failed, no job was started (terminal)
sub record_async {
    my (%opts) = @_;
    my $reqid    = $opts{reqid}   or croak "reqid required";
    _valid_reqid($reqid) or croak "invalid reqid '$reqid'";
    my $results  = $opts{dispatch_results} or croak "dispatch_results required";
    my $runs_dir = $opts{runs_dir} // $DEFAULT_RUNS_DIR;

    my %hosts;
    for my $r (@$results) {
        my $host = $r->{host} // next;
        $hosts{$host} = { status => $r->{status} // 'error' };
        $hosts{$host}{error} = $r->{error} if defined $r->{error};
    }

    my $record = {
        reqid   => $reqid,
        script  => $opts{script} // '',
        mode    => 'async',
        hosts   => \%hosts,
        created => time(),
    };
    _summarise($record);
    _write($runs_dir, $reqid, $record);
    return 1;
}

# Load a stored record by reqid, or undef if absent/corrupt.
sub load {
    my ($reqid, $runs_dir) = @_;
    $runs_dir //= $DEFAULT_RUNS_DIR;
    return undef unless _valid_reqid($reqid);
    my $file = "$runs_dir/$reqid.json";
    return undef unless -f $file;
    return eval { decode_json(_slurp($file)) };
}

# Aggregate the current status of an async run: fetch results from every host
# still pending, merge them into the stored record, persist, and return the
# updated record. A sync record (already complete) is returned unchanged.
#
#   reqid    => $hex
#   config   => \%config        (cert/key/ca for the mTLS fetch)
#   runs_dir => $path
#   port     => $default_port
#   resolver => sub { my $host = shift; return $connect_target }
#               (default: Exec::Registry::resolve_target; lets the dispatcher
#                connect to a resolved IP/port while keying by registry name)
#
# Per-host transitions when fetched:
#   done    -> terminal, with exit/stdout/stderr
#   running -> still pending (re-fetched next time)
#   unknown -> expired (the agent purged the result, or never held it)
#   error   -> transient fetch failure; status kept, fetch_error annotated
# Returns the record, or undef if no such reqid.
sub aggregate {
    my (%opts) = @_;
    my $reqid    = $opts{reqid}  or croak "reqid required";
    my $config   = $opts{config} or croak "config required";
    my $runs_dir = $opts{runs_dir} // $DEFAULT_RUNS_DIR;
    my $port     = $opts{port};
    my $resolver = $opts{resolver} // \&_default_resolver;

    my $record = load($reqid, $runs_dir) or return undef;
    return $record unless ($record->{mode} // '') eq 'async';

    my @pending = grep { $PENDING{ $record->{hosts}{$_}{status} // '' } }
                  sort keys %{ $record->{hosts} };

    if (@pending) {
        my @entries = map { { name => $_, target => $resolver->($_) } } @pending;
        my $fetched = Exec::Engine::result_all(
            hosts  => \@entries,
            config => $config,
            reqid  => $reqid,
            ($port ? (port => $port) : ()),
        );

        for my $f (@$fetched) {
            my $host  = $f->{host} // next;
            my $entry = $record->{hosts}{$host} or next;
            my $st    = $f->{status} // 'error';

            if ($st eq 'done') {
                %$entry = (
                    status => 'done',
                    exit   => $f->{exit},
                    stdout => $f->{stdout},
                    stderr => $f->{stderr},
                );
            }
            elsif ($st eq 'running') {
                $entry->{status} = 'running';
                delete $entry->{fetch_error};
            }
            elsif ($st eq 'unknown') {
                $entry->{status} = 'expired';
                delete $entry->{fetch_error};
            }
            else {
                # Transient fetch failure (host down, TLS error). Keep the host
                # pending and annotate so the next poll retries it.
                $entry->{fetch_error} = $f->{error} // 'fetch failed';
            }
        }
    }

    _summarise($record);
    _write($runs_dir, $reqid, $record);
    return $record;
}

# Remove records older than $ttl seconds (by mtime). Returns the count removed.
sub purge {
    my ($runs_dir, $ttl) = @_;
    $runs_dir //= $DEFAULT_RUNS_DIR;
    $ttl      //= $DEFAULT_TTL;
    return 0 unless -d $runs_dir;
    my $cutoff  = time() - $ttl;
    my $removed = 0;
    opendir my $dh, $runs_dir or return 0;
    while (my $entry = readdir $dh) {
        next unless $entry =~ /^[A-Za-z0-9_-]+\.json\z/;
        my $path = "$runs_dir/$entry";
        next unless ((stat $path)[9] // 0) < $cutoff;
        $removed++ if unlink $path;
    }
    closedir $dh;
    return $removed;
}

# --- private ---

# Recompute the run-level summary: complete (no host still pending) and the
# sorted list of hosts still pending.
sub _summarise {
    my ($record) = @_;
    my @pending = grep { $PENDING{ $record->{hosts}{$_}{status} // '' } }
                  keys %{ $record->{hosts} };
    $record->{pending}  = [ sort @pending ];
    $record->{complete} = @pending ? JSON::false : JSON::true;
    return $record;
}

sub _default_resolver {
    my ($host) = @_;
    require Exec::Registry;
    return Exec::Registry::resolve_target(hostname => $host);
}

sub _valid_reqid {
    my ($reqid) = @_;
    return defined $reqid && $reqid =~ /^[A-Za-z0-9_-]+\z/;
}

sub _write {
    my ($runs_dir, $reqid, $record) = @_;
    unless (-d $runs_dir) {
        eval { make_path($runs_dir, { mode => 0750 }) };
        if ($@) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'run-store-fail',
                REQID  => $reqid,
                ERROR  => "cannot create $runs_dir: $@",
            });
            return;
        }
    }

    my $path = "$runs_dir/$reqid.json";
    my ($fh, $tmp) = tempfile(DIR => $runs_dir, SUFFIX => '.tmp', UNLINK => 0);
    print {$fh} encode_json($record);
    close $fh;
    chmod 0640, $tmp;
    unless (rename $tmp, $path) {
        unlink $tmp;
        Exec::Log::log_action('WARNING', {
            ACTION => 'run-store-fail',
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
