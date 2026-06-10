package Exec::Registry;

use strict;
use warnings;
use JSON      qw(encode_json decode_json);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use File::Basename qw(dirname);
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
sub update_agent_serial_status {
    my (%opts) = @_;
    my $hostname = $opts{hostname} or croak "hostname required";
    my $status   = $opts{status}   or croak "status required";
    my $dir      = $opts{registry_dir} // $REGISTRY_DIR;
    my $path     = "$dir/$hostname.json";

    my $record = -f $path
        ? (eval { decode_json(_slurp($path)) } // {})
        : {};

    $record->{hostname}      = $hostname;
    $record->{serial_status} = $status;
    $record->{dispatcher_serial}  = $opts{serial}           if defined $opts{serial};
    $record->{serial_broadcast}   = $opts{serial_broadcast} if defined $opts{serial_broadcast};
    $record->{serial_confirmed}   = $opts{serial_confirmed} if defined $opts{serial_confirmed};

    _write_atomic($path, encode_json($record));
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

    my $record = -f $path
        ? (eval { decode_json(_slurp($path)) } // {})
        : {};

    $record->{hostname} = $hostname;
    $record->{expiry}   = $opts{expiry};

    _write_atomic($path, encode_json($record));
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

# Resolve an operator-supplied agent name to the address dispatch should
# connect to, honouring the record's lookup_by field:
#   lookup_by 'ip'       -> stored ip (falls back to hostname if ip is empty)
#   lookup_by 'hostname' -> stored hostname (default)
# Returns the supplied name unchanged when it is not a registered agent (or
# the registry cannot be read), preserving support for ad-hoc targets. This
# lets dispatch reach an agent by its stored IP when its reported hostname
# does not resolve from the dispatcher.
#
# Required opts:
#   hostname => $str
sub resolve_host {
    my (%opts) = @_;
    my $name = $opts{hostname};
    croak "hostname required" unless defined $name && length $name;
    my $dir  = $opts{registry_dir} // $REGISTRY_DIR;

    my $record = eval { get_agent(hostname => $name, registry_dir => $dir) };
    return $name unless $record;
    return _record_address($record, $name);
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
