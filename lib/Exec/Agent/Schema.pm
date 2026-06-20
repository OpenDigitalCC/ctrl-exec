package Exec::Agent::Schema;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON       qw(decode_json);
use Carp       qw();

use Exec::Log    qw();
use Exec::Digest qw();


# Implements the agent side of the script schema sidecar contract
# (docs/SCHEMA-SIDECAR.md): read the optional sidecar beside each allowlisted
# script, derive a stable schema_version, and hand both back for advertisement
# on /capabilities. Core only transports the body - it never interprets
# 'arguments'/'argv' or validates the schema; that is the consumer's job.

my $MAX_SIDECAR_BYTES = 65536;                  # 64 KiB cap
my $VERSION_RE        = qr/^[A-Za-z0-9._-]{1,64}\z/;


# Load schema sidecars for the scripts in an allowlist.
#
#   $allowlist : { name => /abs/path/to/script }
#
# Returns a hashref keyed by script name, containing only scripts with a usable
# sidecar:
#   { name => { schema => \%body, schema_version => $string } }
#
# A script with no sidecar, or an unreadable/oversize/invalid one, is simply
# absent from the result (and logged) - it remains callable, just untyped.
sub load_for_allowlist ($allowlist) {
    my %out;

    for my $name (sort keys %$allowlist) {
        my $entry   = $allowlist->{$name};
        my $path    = ref $entry eq 'HASH' ? $entry->{path} : $entry;
        my $sidecar = "$path.schema.json";
        next unless -e $sidecar;

        my ($body, $err) = _read_sidecar($sidecar);
        unless ($body) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'schema-skip',
                SCRIPT => $name,
                REASON => $err,
            });
            next;
        }

        $out{$name} = {
            schema         => $body,
            schema_version => _derive_version($body, $name),
        };
    }

    return \%out;
}

# Derive the schema_version string for a parsed sidecar body, per the contract:
#   1. an explicit, well-formed `version` that does not use the reserved
#      "sha256:" prefix is used verbatim;
#   2. otherwise "sha256:" + first 12 hex of the SHA-256 of the canonical JSON
#      (sorted keys) so cosmetic reformatting does not churn the identity.
sub _derive_version ($body, $name) {
    my $v = $body->{version};
    if (defined $v && !ref $v) {
        return $v if $v =~ $VERSION_RE && $v !~ /^sha256:/;
        Exec::Log::log_action('WARNING', {
            ACTION => 'schema-version-derive',
            SCRIPT => ($name // ''),
            REASON => 'explicit version invalid or reserved - deriving hash',
        });
    }

    my $canonical = JSON->new->canonical(1)->encode($body);
    my $hex       = _sha256_hex($canonical) // '';
    return 'sha256:' . substr($hex, 0, 12);
}

# --- private ---

# Returns ($body_hashref, undef) on success, or (undef, $reason) on any reason
# the sidecar must be treated as absent.
sub _read_sidecar ($sidecar) {
    my $size = -s $sidecar;
    return (undef, "oversize: $size > $MAX_SIDECAR_BYTES bytes")
        if defined $size && $size > $MAX_SIDECAR_BYTES;

    open my $fh, '<', $sidecar or return (undef, "cannot read: $!");
    local $/;
    my $raw = <$fh>;
    close $fh;

    my $body = eval { decode_json($raw) };
    return (undef, "invalid JSON: $@") if $@ || !defined $body;
    return (undef, 'not a JSON object') unless ref $body eq 'HASH';

    return ($body, undef);
}

# SHA-256 of $data as lowercase hex, via openssl - matching the agent's
# existing dependency-light approach (no Digest::SHA on minimal installs).
# Returns undef if the digest cannot be computed.
sub _sha256_hex ($data) {
    return Exec::Digest::sha256_hex($data);
}

1;
