package Exec::Registry;

use strict;
use warnings;
use JSON      qw(encode_json decode_json);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use File::Basename qw(dirname);
use Fcntl     qw(:flock);
use Carp      qw(croak);


my $REGISTRY_DIR = '/var/lib/ctrl-exec/agents';
my $DEFAULT_PORT = 7443;

# Write or overwrite the registry entry for an agent.
# Called by Exec::Pairing::approve_request at pairing time.
#
# Required opts:
#   hostname => $str
#   ip       => $str
#   paired   => $iso8601
#   expiry   => $str      (openssl notAfter string, may be '')
#   reqid    => $str
#
# Optional serial tracking opts (written at pairing time):
#   dispatcher_serial => $hex    (serial agent has stored)
#   serial_status     => $str    (current|pending|stale|unknown)
#   serial_broadcast  => $iso8601
#   serial_confirmed  => $iso8601
#
# Optional dispatch-resolution opts:
#   lookup_by => 'ip' | 'hostname'   how dispatch resolves the connect
#       address for this agent. Default 'hostname'. Any other value
#       normalises to 'hostname'. See resolve_host / resolve_target.
#   port      => $int   the agent's operational port. Default 7443. Used by
#       resolve_target so non-default-port agents are reachable without a
#       per-command --port. Out-of-range values normalise to 7443.
sub register_agent {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    valid_agent_name($hostname)
        or croak "invalid hostname '$hostname' - refusing to use as a registry key";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;

    make_path($dir) unless -d $dir;

    my $record = {
        hostname          => $hostname,
        ip                => $opts{ip}                // '',
        paired            => $opts{paired}            // '',
        expiry            => $opts{expiry}            // '',
        reqid             => $opts{reqid}             // '',
        lookup_by         => _norm_lookup_by($opts{lookup_by}),
        port              => _norm_port($opts{port}),
        tags              => (ref $opts{tags} eq 'HASH' ? $opts{tags} : {}),
        dispatcher_serial => $opts{dispatcher_serial} // '',
        serial_status     => $opts{serial_status}     // 'unknown',
        serial_broadcast  => $opts{serial_broadcast}  // '',
        serial_confirmed  => $opts{serial_confirmed}  // '',
    };

    _write_atomic("$dir/$hostname.json", encode_json($record));
}

# Update serial tracking fields for an existing agent record.
# Merges the provided fields into the existing record without touching
# other fields (hostname, ip, paired, expiry, etc.).
#
# Required opts:
#   hostname => $str
#   status   => 'current' | 'pending' | 'stale' | 'unknown'
#
# Optional opts:
#   serial           => $hex      (update stored serial)
#   serial_broadcast => $iso8601
#   serial_confirmed => $iso8601
# Serialize registry read-modify-write so concurrent updates do not lost-update.
# The atomic temp+rename in _write_atomic gives torn-free reads, but two
# processes that load the same record, change different fields and write both
# would lose one change. A single registry-wide lock is enough: registry writes
# (rotation broadcast, renewal expiry, discovery tags) are infrequent, not hot.
# Best-effort: if the lock file cannot be opened the update proceeds unlocked.
sub _locked {
    my ($dir, $code) = @_;
    open my $lk, '>>', "$dir/.registry.lock" or return $code->();
    flock $lk, LOCK_EX;
    my @r = eval { $code->() };
    my $err = $@;
    flock $lk, LOCK_UN;
    close $lk;
    die $err if $err;
    return wantarray ? @r : $r[0];
}

sub update_agent_serial_status {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    my $status   = $opts{status}   or croak "status required";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    _locked($dir, sub {
        my $record = -f $path
            ? (eval { decode_json(_slurp($path)) } // {})
            : {};

        $record->{hostname}      = $hostname;
        $record->{serial_status} = $status;
        $record->{dispatcher_serial}  = $opts{serial}           if defined $opts{serial};
        $record->{serial_broadcast}   = $opts{serial_broadcast} if defined $opts{serial_broadcast};
        $record->{serial_confirmed}   = $opts{serial_confirmed} if defined $opts{serial_confirmed};

        _write_atomic($path, encode_json($record));
    });
}

# Update the cert expiry for an existing agent record. Merges the new expiry
# into the existing record without touching other fields. Called by
# Exec::Engine::_renew_one after a successful cert renewal so list-agents
# reflects the new expiry.
#
# Required opts:
#   hostname => $str
#   expiry   => $str    (openssl notAfter string)
sub update_expiry {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    croak "expiry required" unless defined $opts{expiry};
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    _locked($dir, sub {
        my $record = -f $path
            ? (eval { decode_json(_slurp($path)) } // {})
            : {};

        $record->{hostname} = $hostname;
        $record->{expiry}   = $opts{expiry};

        _write_atomic($path, encode_json($record));
    });
}

# Refresh the cached tags for an existing agent. Tags are reported live by the
# agent in /capabilities; discovery calls this to cache them in the registry so
# list-agents --tags can filter offline (Option C). Replaces the tags field.
# No-op (returns 0) if the agent is not registered; returns 1 when updated.
#
# Required opts:
#   hostname => $str
#   tags     => \%hash   (non-hash normalises to {})
sub update_agent_tags {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    return 0 unless -f $path;
    return _locked($dir, sub {
        my $record = eval { decode_json(_slurp($path)) } or return 0;
        $record->{tags} = (ref $opts{tags} eq 'HASH' ? $opts{tags} : {});
        _write_atomic($path, encode_json($record));
        return 1;
    });
}

# Return a list of all registered agents as an arrayref of hashrefs,
# sorted by hostname.
#
# Optional opts:
#   registry_dir => $path
sub list_agents {
    my (%opts) = @_;
    my $dir = $opts{registry_dir} // $REGISTRY_DIR;

    return [] unless -d $dir;

    my @agents;
    opendir my $dh, $dir or croak "Cannot open registry dir '$dir': $!";
    while (my $f = readdir $dh) {
        next unless $f =~ /^(.+)\.json$/;
        my $data = eval { decode_json(_slurp("$dir/$f")) };
        next if $@;
        push @agents, $data;
    }
    closedir $dh;

    return [ sort { $a->{hostname} cmp $b->{hostname} } @agents ];
}

# Resolve an operator-supplied agent name to the full connect target
# ("address" or "address:port") dispatch should use. Like resolve_host, but
# also appends the agent's stored operational port when it differs from the
# default 7443, so agents on non-standard ports are reachable without a
# per-command --port. Returns the supplied name unchanged when it is not a
# registered agent.
#
# Required opts:
#   hostname => $str
sub resolve_target {
    my (%opts) = @_;
    my $name = $opts{hostname};
    croak "hostname required" unless defined $name && length $name;
    my $dir  = $opts{registry_dir} // $REGISTRY_DIR;

    my $record = eval { get_agent(hostname => $name, registry_dir => $dir) };
    return $name unless $record;

    my $addr = _record_address($record, $name);
    my $port = _norm_port($record->{port});
    return $port == $DEFAULT_PORT ? $addr : "$addr:$port";
}

# The single addressing path for dispatch (ping / run / discovery / status).
# Resolves a list of operator-supplied agent references to connect targets,
# registry-only: every reference MUST be a registered agent. An unregistered
# reference is reported back, never silently treated as a DNS name - so all
# verbs address agents the same way and an unknown name fails loudly rather
# than leaking out to whatever DNS resolves it to. An optional ":<port>" suffix
# overrides the agent's stored operational port for that one call.
#
#   resolve_dispatch(\@refs)
#     -> { ok => 1, hosts => [ { name => <registry name>, target => <addr[:port]> }, ... ] }
#     -> { ok => 0, unknown => [ <ref>, ... ] }     one or more not registered
sub resolve_dispatch {
    my ($refs, %opts) = @_;
    my $dir = $opts{registry_dir} // $REGISTRY_DIR;
    my (@hosts, @unknown);
    for my $ref (@$refs) {
        my ($name, $oport) = $ref =~ /^(.+):(\d+)$/ ? ($1, $2) : ($ref, undef);
        my $record = eval { get_agent(hostname => $name, registry_dir => $dir) };
        unless ($record) { push @unknown, $ref; next; }
        my $addr = _record_address($record, $name);
        my $port = defined $oport ? _norm_port($oport) : _norm_port($record->{port});
        push @hosts, {
            name   => $name,
            target => ($port == $DEFAULT_PORT ? $addr : "$addr:$port"),
        };
    }
    return { ok => 0, unknown => \@unknown } if @unknown;
    return { ok => 1, hosts => \@hosts };
}

# Return the registry record for a single agent, or undef if not found.
#
# Required opts:
#   hostname => $str
sub get_agent {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    return undef unless -f $path;
    return eval { decode_json(_slurp($path)) };
}

# Remove a registered agent from the registry.
# Returns the deleted record so the caller can log details.
# Dies if the agent is not found.
#
# Required opts:
#   hostname => $str
#
# Note: the agent's certificate remains valid until its natural expiry.
# The cert is not revoked - the agent should be decommissioned promptly.
sub remove_agent {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    croak "No registry entry for '$hostname'" unless -f $path;

    my $record = eval { decode_json(_slurp($path)) } // {};
    unlink $path or croak "Cannot remove registry entry '$path': $!";

    return $record;
}

# Edit a registered agent's dispatch-relevant fields in place, and/or rename
# it, without re-pairing. Only ip, port, and lookup_by are editable here;
# cert/serial fields are managed by pairing and rotation and are left intact.
# Dies if the agent is not found, if a rename target name is invalid, or if a
# rename would clobber an existing agent. Returns the updated record.
#
# Required opts:
#   hostname => $str        the agent to edit
#
# Optional opts (at least one expected by callers):
#   new_name  => $str       rename: move the record to this name
#   ip        => $str       new address
#   port      => $int       new operational port (normalised)
#   lookup_by => $str       'ip' | 'hostname' (normalised)
sub edit_agent {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    return _locked($dir, sub {
        croak "No registry entry for '$hostname'" unless -f $path;
        my $record = eval { decode_json(_slurp($path)) }
            or croak "Registry entry for '$hostname' is unreadable";

        $record->{ip}        = $opts{ip}                       if defined $opts{ip};
        $record->{port}      = _norm_port($opts{port})         if defined $opts{port};
        $record->{lookup_by} = _norm_lookup_by($opts{lookup_by}) if defined $opts{lookup_by};

        my $new = $opts{new_name};
        if (defined $new && length $new && $new ne $hostname) {
            valid_agent_name($new)
                or croak "invalid agent name '$new' (use letters, digits, '.', '-', '_')";
            croak "agent '$new' already exists" if -f "$dir/$new.json";

            $record->{hostname} = $new;
            _write_atomic("$dir/$new.json", encode_json($record));
            unlink $path or croak "Cannot remove old registry entry '$path': $!";
            return $record;
        }

        _write_atomic($path, encode_json($record));
        return $record;
    });
}

# Parse a --tags filter string into a hashref of wanted tag key => value.
# Accepts "key=value" or comma-separated "k1=v1,k2=v2"; all pairs must match
# (AND). Dies on a malformed entry (no '=' or empty key) or an empty filter.
sub parse_tag_filter {
    my ($spec) = @_;
    my %want;
    for my $pair (split /,/, ($spec // '')) {
        next unless length $pair;
        my ($k, $v) = split /=/, $pair, 2;
        croak "invalid tag filter '$pair' (expected key=value)"
            unless defined $k && length $k && defined $v;
        $want{$k} = $v;
    }
    croak "empty tag filter (expected key=value[,key=value...])" unless %want;
    return \%want;
}

# True if an agent's cached tags satisfy the filter: every wanted key is
# present with the exact value.
sub tags_match {
    my ($tags, $want) = @_;
    $tags //= {};
    for my $k (keys %$want) {
        return 0 unless defined $tags->{$k} && $tags->{$k} eq $want->{$k};
    }
    return 1;
}

# Return list of hostnames only - convenience for building host lists
# to pass to Engine functions.
sub list_hostnames {
    my (%opts) = @_;
    my $agents = list_agents(%opts);
    return [ map { $_->{hostname} } @$agents ];
}

# --- private ---

# Normalise a lookup_by value to 'ip' or the default 'hostname'.
sub _norm_lookup_by {
    my ($v) = @_;
    return (defined $v && $v eq 'ip') ? 'ip' : 'hostname';
}

# Validate an agent name/hostname for use as a registry key (filename
# component). Must start with an alphanumeric and contain only letters,
# digits, dot, hyphen, underscore - which excludes '/' and a leading '.', so
# it cannot escape the registry directory. Public so the pairing path can
# reject a hostile agent-supplied hostname before it becomes a filename.
sub valid_agent_name {
    my ($name) = @_;
    return defined $name && $name =~ /^[A-Za-z0-9][A-Za-z0-9._-]*\z/;
}

# Normalise a port to an integer in 1..65535, or the default 7443.
sub _norm_port {
    my ($v) = @_;
    return (defined $v && $v =~ /^\d+$/ && $v >= 1 && $v <= 65535)
        ? int($v) : $DEFAULT_PORT;
}

# Connect address from a record, honouring lookup_by (see resolve_host).
sub _record_address {
    my ($record, $fallback) = @_;
    if (_norm_lookup_by($record->{lookup_by}) eq 'ip'
        && defined $record->{ip} && length $record->{ip}) {
        return $record->{ip};
    }
    return $record->{hostname} // $fallback;
}

sub _slurp {
    my ($path) = @_;
    open my $fh, '<', $path or croak "Cannot read '$path': $!";
    local $/;
    return scalar <$fh>;
}

sub _write_atomic {
    my ($path, $content) = @_;
    my $dir = dirname($path);
    make_path($dir) unless -d $dir;

    my ($tmp_fh, $tmp_path) = tempfile(DIR => $dir, UNLINK => 0);
    print $tmp_fh $content;
    close $tmp_fh;
    chmod 0644, $tmp_path;

    rename $tmp_path, $path
        or do { unlink $tmp_path; croak "Cannot write registry entry '$path': $!" };
}

1;
