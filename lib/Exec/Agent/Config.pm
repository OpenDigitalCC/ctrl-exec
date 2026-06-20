package Exec::Agent::Config;

use strict;
use warnings;
use Carp qw(croak);
use Cwd  qw(abs_path);
use Exec::Log qw();
use Exec::RateLimit qw();


# Load and validate agent.conf
# Returns hashref of config values or dies with error
sub load_config {
    my ($path) = @_;
    $path //= '/etc/ctrl-exec-agent/agent.conf';

    open my $fh, '<', $path
        or croak "Cannot open config '$path': $!";

    my %config;
    my $section = '';      # current section name; '' means top-level
    my $cur_profile;       # name of the [profile <name>] currently being read

    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*#/;   # skip comments
        next if $line =~ /^\s*$/;   # skip blank lines

        # Section header: [name], or [profile <name>] which carries a sub-name.
        if ($line =~ /^\s*\[\s*(\w+)(?:\s+([\w.-]+))?\s*\]\s*$/) {
            my ($sect, $sub) = (lc $1, $2);
            if ($sect eq 'profile') {
                croak "Profile section needs a name ([profile <name>]) in '$path'"
                    unless defined $sub && length $sub;
                $section     = 'profile';
                $cur_profile = $sub;
                $config{profiles}{$sub} //= {};
            }
            else {
                $section     = $sect;
                $cur_profile = undef;
            }
            next;
        }

        if ($line =~ /^\s*(\w+[\w-]*)\s*=\s*(.+?)\s*$/) {
            my ($k, $v) = ($1, $2);
            if ($section eq 'tags') {
                $config{tags}{$k} = $v;
            }
            elsif ($section eq 'profile') {
                # Raw value; normalised in _validate_config.
                $config{profiles}{$cur_profile}{$k} = $v;
            }
            elsif ($section eq '') {
                $config{$k} = $v;
            }
            # silently ignore keys in unrecognised sections
        }
        else {
            croak "Malformed config line in '$path': $line";
        }
    }
    close $fh;

    _validate_config(\%config, $path);
    return \%config;
}

sub _validate_config {
    my ($config, $path) = @_;
    my @required = qw(port cert key ca);
    for my $key (@required) {
        croak "Missing required config key '$key' in '$path'"
            unless exists $config->{$key};
    }
    croak "port must be numeric in '$path'"
        unless $config->{port} =~ /^\d+$/;

    # Parse script_dirs from colon-separated string into arrayref
    if (defined $config->{script_dirs} && length $config->{script_dirs}) {
        $config->{script_dirs} = [
            grep { length $_ } split /:/, $config->{script_dirs}
        ];
    }
    else {
        delete $config->{script_dirs};   # absent = no restriction
    }

    # KEEP IN SYNC WITH src/ctrl-exec-exec.c (set_profile_field / parse_agent_conf).
    # The executor re-derives the same security decision from this same config; if
    # the two parsers diverge, the executor applies a different privilege than this
    # front-end authorised. t/exec-conformance.t gates that they agree.
    #
    # Normalise security profiles ([profile <name>] blocks): caps -> arrayref of
    # CAP_* names, writable -> arrayref of absolute dirs, run_as validated,
    # no_new_privileges -> bool (default on). The executor enforces all of these
    # before exec: caps, run_as, no_new_privileges, and - when `writable` is set -
    # a read-only filesystem with those paths carved out read-write (plus a private
    # /tmp). The implicit most-restrictive 'default' profile is supplied by the
    # agent and need not be defined here (defining [profile default] overrides it).
    if (ref $config->{profiles} eq 'HASH') {
        for my $pname (sort keys %{ $config->{profiles} }) {
            my $p = $config->{profiles}{$pname};

            $p->{caps} = [ grep { length } split /[,\s]+/, ($p->{caps} // '') ];
            for my $c (@{ $p->{caps} }) {
                next if $c =~ /^CAP_[A-Z0-9_]+$/;
                # A token starting with '#' almost always means the operator put
                # an inline comment after the value - which this format does not
                # support (whole-line comments only). Say so, instead of the bare
                # "invalid capability '#'".
                my $hint = $c =~ /^#/
                    ? " - inline '# ...' comments are not supported on value lines;"
                      . " put the comment on its own line"
                    : '';
                croak "Profile '$pname': invalid capability '$c' (expected CAP_*) "
                    . "in '$path'$hint";
            }

            $p->{writable} = [ grep { length } split /:/, ($p->{writable} // '') ];
            for my $w (@{ $p->{writable} }) {
                croak "Profile '$pname': writable path must be absolute: '$w' in '$path'"
                    unless $w =~ m{^/};
            }

            if (defined $p->{run_as} && length $p->{run_as}) {
                croak "Profile '$pname': invalid run_as '$p->{run_as}' in '$path'"
                    unless $p->{run_as} =~ /^(?:[A-Za-z_][A-Za-z0-9_-]*|\d+)$/;
                # Bound a numeric uid/gid to 32 bits, matching the C executor
                # (ctrl-exec-exec.c set_profile_field): a value that does not fit
                # uid_t would be rejected by the executor at load, so reject it
                # here too rather than let the two parsers disagree.
                croak "Profile '$pname': run_as '$p->{run_as}' out of range in '$path'"
                    if $p->{run_as} =~ /^\d+$/ && $p->{run_as} > 0xFFFFFFFF;
            }
            else {
                delete $p->{run_as};
            }

            $p->{no_new_privileges} =
                (!defined $p->{no_new_privileges}
                 || $p->{no_new_privileges} =~ /^(?:1|y|yes|true|on)$/i) ? 1 : 0;
        }
    }

    # Parse allowed_ips from comma-separated string into arrayref.
    # Validate CIDR prefix lengths AND the dotted-quad itself at load time,
    # rejecting invalid entries with a warning so ip_allowed only ever sees
    # well-formed, canonical entries. Canonicalising the octets here (stripping
    # leading zeros) is what makes ip_allowed's string-eq match safe: the live
    # peer IP from the socket is canonical, so a zero-padded config entry like
    # "10.00.0.0/16" would otherwise compare "00" ne "0" and silently never
    # match - failing open by omission. We normalise instead, or warn-and-drop.
    if (my $raw = $config->{allowed_ips}) {
        my @candidates = grep { length } map { s/^\s+|\s+$//gr } split /,/, $raw;
        my @entries;
        for my $entry (@candidates) {
            my ($addr, $prefix_len);
            if ($entry =~ m{/}) {
                ($addr, $prefix_len) = split m{/}, $entry, 2;
                unless (defined $prefix_len && $prefix_len =~ /^\d+$/ &&
                        grep { $prefix_len == $_ } (8, 16, 24)) {
                    Exec::Log::log_action('WARNING', {
                        ACTION => 'config-warn',
                        ENTRY  => $entry,
                        MSG    => 'unsupported prefix length',
                    });
                    next;
                }
            }
            else {
                $addr = $entry;
            }
            my $canon_addr = _normalize_ipv4($addr);
            unless (defined $canon_addr) {
                Exec::Log::log_action('WARNING', {
                    ACTION => 'config-warn',
                    ENTRY  => $entry,
                    MSG    => 'malformed IPv4 address',
                });
                next;
            }
            push @entries,
                defined $prefix_len ? "$canon_addr/$prefix_len" : $canon_addr;
        }
        if (@entries) {
            $config->{allowed_ips} = \@entries;
        }
        else {
            delete $config->{allowed_ips};
        }
    }
    else {
        delete $config->{allowed_ips};
    }

    # Parse rate limit configuration.
    # rate_limit_disable = 1  disables rate limiting entirely (testing only).
    # rate_limit_volume  = <limit>/<window>/<block>  e.g. 10/60/300
    # rate_limit_probe   = <limit>/<window>/<block>  e.g. 3/600/3600
    # Absent or invalid values leave defaults in place (current constants).
    {
        my %rl;
        if ($config->{rate_limit_disable} && $config->{rate_limit_disable} =~ /^[1y]/i) {
            $rl{disabled} = 1;
        }
        for my $param (qw(volume probe)) {
            my $key = "rate_limit_$param";
            if (my $raw = $config->{$key}) {
                if (my $t = Exec::RateLimit::parse_limit_spec($raw)) {
                    @rl{"${param}_limit", "${param}_window", "${param}_block"} = @$t;
                }
                else {
                    Exec::Log::log_action('WARNING', {
                        ACTION => 'config-warn',
                        KEY    => $key,
                        MSG    => 'invalid format, expected limit/window/block - using defaults',
                    });
                }
            }
        }
        $config->{rate_limit} = \%rl if %rl;
    }

    # Validate auth_hook if present
    if (defined $config->{auth_hook} && length $config->{auth_hook}) {
        croak "auth_hook '$config->{auth_hook}' is not executable in '$path'"
            unless -f $config->{auth_hook} && -x $config->{auth_hook};
    }
    else {
        delete $config->{auth_hook};   # absent = no hook
    }
}

# Load and parse scripts.conf allowlist
# Returns hashref: { script_name => /absolute/path }
# Dies on parse errors; unknown/bad entries are skipped with a warning
#
# Optional opts:
#   script_dirs => \@dirs   (arrayref of approved directories; undef = no restriction)
sub load_allowlist {
    my ($path, $script_dirs) = @_;
    $path //= '/etc/ctrl-exec-agent/scripts.conf';

    open my $fh, '<', $path
        or croak "Cannot open allowlist '$path': $!";

    my %allowlist;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*#/;
        next if $line =~ /^\s*$/;
        if ($line =~ /^\s*([\w-]+)\s*=\s*(.+?)\s*$/) {
            my ($name, $rest) = ($1, $2);

            # The value is the absolute script path plus optional, order-
            # independent key=value annotations (profile=, future schema=/
            # timeout=). The lone bare token is the path; key=value tokens are
            # annotations - so 'profile=' may appear before or after the path.
            my ($script_path, $extra_path, %annot);
            for my $tok (split /\s+/, $rest) {
                if ($tok =~ /^([a-z_]+)=(.*)$/) {
                    $annot{$1} = $2;
                }
                elsif (defined $script_path) {
                    $extra_path = $tok;
                }
                else {
                    $script_path = $tok;
                }
            }

            unless (defined $script_path) {
                warn "Allowlist: skipping '$name' - no script path\n";
                next;
            }
            if (defined $extra_path) {
                warn "Allowlist: skipping '$name' - more than one path on the line\n";
                next;
            }
            unless ($script_path =~ m{^/}) {
                warn "Allowlist: skipping '$name' - path must be absolute: $script_path\n";
                next;
            }
            if ($script_dirs && !_path_in_dirs($script_path, $script_dirs)) {
                warn "Allowlist: skipping '$name' - path not in approved script_dirs: $script_path\n";
                next;
            }
            $allowlist{$name} = {
                path    => $script_path,
                profile => ($annot{profile} // 'default'),
            };
        }
        else {
            warn "Allowlist: skipping malformed line: $line\n";
        }
    }
    close $fh;

    return \%allowlist;
}

# Check whether a script name is permitted
# Returns the script path if permitted, undef otherwise
#
# Optional: script_dirs => \@dirs  re-validates path at execution time
sub validate_script {
    my ($name, $allowlist, $script_dirs) = @_;
    return unless defined $name && $name =~ /^[\w-]+$/;
    my $entry = $allowlist->{$name};
    return unless defined $entry;
    # Entries are { path, profile } records; tolerate a bare path string in case
    # an older caller still passes one.
    my $path = ref $entry eq 'HASH' ? $entry->{path} : $entry;
    return unless defined $path;
    if ($script_dirs && !_path_in_dirs($path, $script_dirs)) {
        warn "validate_script: '$name' path rejected at execution time - not in script_dirs: $path\n";
        return;
    }
    return $path;
}

# The profile name assigned to a script in the allowlist ('default' when unset).
sub script_profile {
    my ($name, $allowlist) = @_;
    my $entry = $allowlist->{$name};
    return undef unless defined $entry;
    return ref $entry eq 'HASH' ? ($entry->{profile} // 'default') : 'default';
}

# Cross-check the allowlist against the defined profiles: every script's profile
# must be defined in agent.conf, or be the implicit 'default'. Returns a list of
# "script -> profile" strings for any that are not (empty when all resolve).
# Fail-closed: callers (serve startup, self-check) treat a non-empty result as a
# fatal config error rather than silently running an undefined - possibly
# over-permissive - profile.
sub validate_profiles {
    my ($allowlist, $config) = @_;
    my %defined = (default => 1, %{ $config->{profiles} // {} });
    my @unknown;
    for my $name (sort keys %$allowlist) {
        my $p = script_profile($name, $allowlist) // 'default';
        push @unknown, "$name -> $p" unless exists $defined{$p};
    }
    return @unknown;
}

# Return true if $path is under any directory in @$dirs.
#
# When the script exists - the case that matters at execution time - the path
# and each directory are resolved with abs_path so symlinks and '..' are
# collapsed: an allowlist entry pointing at a symlink that escapes an approved
# directory, or one using '..' to climb out, is then correctly rejected (a
# plain string prefix would miss both). When the path does not exist (e.g. a
# not-yet-installed script being filtered at config load time) it falls back
# to the literal path; such an entry cannot be executed anyway, and once the
# file exists the execution-time check resolves it.
sub _path_in_dirs {
    my ($path, $dirs) = @_;
    my $real = abs_path($path) // $path;
    for my $dir (@$dirs) {
        my $rdir = abs_path($dir) // $dir;
        $rdir =~ s{/+$}{};   # strip trailing slash
        return 1 if $real eq $rdir || index($real, "$rdir/") == 0;
    }
    return 0;
}

# Canonicalise an IPv4 dotted-quad: exactly four numeric octets, each 0-255,
# with insignificant leading zeros stripped ("10.00.0.0" -> "10.0.0.0"). Returns
# the canonical string, or undef if the address is not a well-formed IPv4. Used
# at config load so ip_allowed only ever compares canonical octets.
sub _normalize_ipv4 {
    my ($addr) = @_;
    return undef unless defined $addr;
    my @oct = split /\./, $addr, -1;
    return undef unless @oct == 4;
    for my $o (@oct) {
        return undef unless $o =~ /^\d{1,3}$/ && $o <= 255;
    }
    return join '.', map { $_ + 0 } @oct;
}

# Check whether a peer IP is permitted by the allowed_ips list.
# Returns 1 if the IP matches any entry, 0 otherwise.
# Supports exact IPs and CIDR prefixes /8, /16, /24 only.
# Invalid entries are filtered out and canonicalised at config load time, so
# every entry here is a well-formed dotted-quad with no leading zeros; the live
# peer IP from the socket is likewise canonical, so string-eq octet matching is
# sound. IPv6 addresses (containing ':') return 0 silently.
sub ip_allowed {
    my ($ip, $allowed_ref) = @_;

    # IPv6: not supported - return 0 silently
    return 0 if $ip =~ /:/;

    for my $entry (@$allowed_ref) {
        if ($entry !~ m{/}) {
            # Exact IP match
            return 1 if $ip eq $entry;
        }
        else {
            my ($network, $prefix_len) = split m{/}, $entry, 2;

            # Unsupported prefix lengths were filtered at load time; skip silently
            next unless defined $prefix_len && $prefix_len =~ /^\d+$/ &&
                        grep { $prefix_len == $_ } (8, 16, 24);

            my @ip_oct  = split /\./, $ip,      4;
            my @net_oct = split /\./, $network,  4;

            if ($prefix_len == 8) {
                return 1 if $ip_oct[0] eq $net_oct[0];
            }
            elsif ($prefix_len == 16) {
                return 1 if $ip_oct[0] eq $net_oct[0]
                         && $ip_oct[1] eq $net_oct[1];
            }
            elsif ($prefix_len == 24) {
                return 1 if $ip_oct[0] eq $net_oct[0]
                         && $ip_oct[1] eq $net_oct[1]
                         && $ip_oct[2] eq $net_oct[2];
            }
        }
    }

    return 0;
}

1;
