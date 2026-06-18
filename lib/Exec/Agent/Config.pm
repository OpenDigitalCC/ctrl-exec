package Exec::Agent::Config;

use strict;
use warnings;
use Carp qw(croak);
use Cwd  qw(abs_path);
use Exec::Log qw();


# Load and validate agent.conf
# Returns hashref of config values or dies with error
sub load_config {
    my ($path) = @_;
    $path //= '/etc/ctrl-exec-agent/agent.conf';

    open my $fh, '<', $path
        or croak "Cannot open config '$path': $!";

    my %config;
    my $section = '';   # current section name; '' means top-level

    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*#/;   # skip comments
        next if $line =~ /^\s*$/;   # skip blank lines

        if ($line =~ /^\s*\[(\w+)\]\s*$/) {
            $section = lc $1;
            next;
        }

        if ($line =~ /^\s*(\w+[\w-]*)\s*=\s*(.+?)\s*$/) {
            my ($k, $v) = ($1, $2);
            if ($section eq 'tags') {
                $config{tags}{$k} = $v;
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

    # Parse writable_paths from colon-separated string into arrayref. These are
    # the paths scripts must be able to write to under the systemd sandbox;
    # 'ctrl-exec-agent apply-config' renders them into a unit drop-in as
    # ReadWritePaths (the agent process cannot relax the sandbox itself). The
    # serve path also test-writes them at startup and warns on any that are
    # read-only, flagging config that has not been applied. Absent = none.
    if (defined $config->{writable_paths} && length $config->{writable_paths}) {
        $config->{writable_paths} = [
            grep { length $_ } split /:/, $config->{writable_paths}
        ];
    }
    else {
        delete $config->{writable_paths};
    }

    # Validate the sandbox level. Absent = strict (the shipped unit default).
    if (defined $config->{sandbox}) {
        my $lvl = lc $config->{sandbox};
        croak "sandbox must be one of strict|moderate|off in '$path'"
            unless $lvl =~ /^(?:strict|moderate|off)$/;
        $config->{sandbox} = $lvl;
    }

    # Parse allowed_ips from comma-separated string into arrayref.
    # Validate CIDR prefix lengths at load time; reject invalid entries with a
    # warning so ip_allowed only ever sees well-formed entries.
    if (my $raw = $config->{allowed_ips}) {
        my @candidates = grep { length } map { s/^\s+|\s+$//gr } split /,/, $raw;
        my @entries;
        for my $entry (@candidates) {
            if ($entry =~ m{/}) {
                my (undef, $prefix_len) = split m{/}, $entry, 2;
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
            push @entries, $entry;
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
                my ($limit, $window, $block) = split m{/}, $raw, 3;
                if (defined $limit  && $limit  =~ /^\d+$/ &&
                    defined $window && $window =~ /^\d+$/ &&
                    defined $block  && $block  =~ /^\d+$/) {
                    $rl{"${param}_limit"}  = int($limit);
                    $rl{"${param}_window"} = int($window);
                    $rl{"${param}_block"}  = int($block);
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
        if ($line =~ /^\s*([\w-]+)\s*=\s*(\S+)\s*$/) {
            my ($name, $script_path) = ($1, $2);
            unless ($script_path =~ m{^/}) {
                warn "Allowlist: skipping '$name' - path must be absolute: $script_path\n";
                next;
            }
            if ($script_dirs && !_path_in_dirs($script_path, $script_dirs)) {
                warn "Allowlist: skipping '$name' - path not in approved script_dirs: $script_path\n";
                next;
            }
            $allowlist{$name} = $script_path;
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
    my $path = $allowlist->{$name};
    return unless defined $path;
    if ($script_dirs && !_path_in_dirs($path, $script_dirs)) {
        warn "validate_script: '$name' path rejected at execution time - not in script_dirs: $path\n";
        return;
    }
    return $path;
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

# Check whether a peer IP is permitted by the allowed_ips list.
# Returns 1 if the IP matches any entry, 0 otherwise.
# Supports exact IPs and CIDR prefixes /8, /16, /24 only.
# Invalid entries are filtered out at config load time; none reach here.
# IPv6 addresses (containing ':') return 0 silently.
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
