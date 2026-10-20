package Exec::Agent::Config;

use strict;
use warnings;
use feature qw(signatures);
no warnings qw(experimental::signatures);
use Carp qw(croak);
use Cwd  qw(abs_path);
use Fcntl qw();
use Exec::Log qw();
use Exec::RateLimit qw();


# Return the first of the given paths that cannot be read because of a
# permission error (EACCES - the file itself, or a directory on the way to it),
# or undef when none is. Lets a CLI command that was not run as root say so,
# rather than reporting a missing file or a configuration error. A path that
# does not exist (ENOENT) is not a permission problem and is not reported.
sub unreadable_path (@paths) {
    for my $p (@paths) {
        next unless defined $p && length $p;
        if (open my $fh, '<', $p) { close $fh; next; }
        return $p if $!{EACCES};
    }
    return undef;
}

# Storage limits of the C executor (src/ctrl-exec-executor.c: MAX_PROFILES, MAX_CAPS,
# MAX_WRITABLE, MAX_DIRS, NAMELEN, VALLEN). The executor rejects a config that
# exceeds them rather than truncating a name or path, so this parser rejects the
# same configs - otherwise the front end would authorise a file the executor
# refuses to load. KEEP IN SYNC WITH src/ctrl-exec-executor.c.
use constant {
    MAX_PROFILES => 64,
    MAX_CAPS     => 32,
    MAX_WRITABLE => 32,
    MAX_DIRS     => 32,
    NAMELEN      => 128,    # a value must be shorter than this
    VALLEN       => 4096,   # a path must be shorter than this
};

# Load and validate agent.conf
# Returns hashref of config values or dies with error
sub load_config ($path = undef) {
    $path //= '/etc/ctrl-exec-agent/agent.conf';

    open my $fh, '<', $path
        or croak "Cannot open config '$path': $!";

    my %config;
    my $section = '';      # current section name; '' means top-level
    my $cur_profile;       # name of the [profile <name>] currently being read

    while (my $line = <$fh>) {
        chomp $line;
        # The executor reads lines as C strings; a NUL would hide the rest of
        # the line from it. Refuse rather than let the two parsers see
        # different values.
        croak "Malformed config line in '$path': contains a NUL byte"
            if index($line, "\0") >= 0;
        next if $line =~ /^\s*#/;   # skip comments
        next if $line =~ /^\s*$/;   # skip blank lines

        # Section header: [name], or [profile <name>] which carries a sub-name.
        if ($line =~ /^\s*\[\s*(\w+)(?:\s+([\w.-]+))?\s*\]\s*$/) {
            my ($sect, $sub) = (lc $1, $2);
            if ($sect eq 'profile') {
                croak "Profile section needs a name ([profile <name>]) in '$path'"
                    unless defined $sub && length $sub;
                croak "Profile name too long in '$path': $sub"
                    if length $sub >= NAMELEN;
                $section     = 'profile';
                $cur_profile = $sub;
                $config{profiles}{$sub} //= {};
                croak "Too many profiles in '$path' (max " . MAX_PROFILES . ")"
                    if keys %{ $config{profiles} } > MAX_PROFILES;
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
                # These names hold the parsed sections below; a plain top-level
                # key of the same name would clobber them (and the executor
                # rejects them too).
                croak "Reserved config key '$k' in '$path'"
                    if $k eq 'profiles' || $k eq 'tags';
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

sub _validate_config ($config, $path) {
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
        # NB: a value that yields no directories (":::") stays an empty list,
        # which restricts every script out - the executor does the same.
        croak "Too many script_dirs in '$path' (max " . MAX_DIRS . ")"
            if @{ $config->{script_dirs} } > MAX_DIRS;
        for my $d (@{ $config->{script_dirs} }) {
            croak "script_dirs entry too long in '$path'" if length $d >= VALLEN;
        }
    }
    else {
        delete $config->{script_dirs};   # absent = no restriction
    }

    # KEEP IN SYNC WITH src/ctrl-exec-executor.c (set_profile_field / parse_agent_conf).
    # The executor re-derives the same security decision from this same config; if
    # the two parsers diverge, the executor applies a different privilege than this
    # front-end authorised. t/exec-conformance.t gates that they agree.
    #
    # Normalise security profiles ([profile <name>] blocks): caps -> arrayref of
    # CAP_* names, writable -> arrayref of absolute dirs, run_as validated,
    # no_new_privileges -> bool (default on). The executor enforces all of these
    # before exec: caps, run_as, no_new_privileges, and - when `writable` is set -
    # a read-only filesystem with those paths carved out read-write (plus a private
    # /tmp). Every profile must be defined here, including 'default' (the profile
    # an unannotated script resolves to) - there is no implicit built-in. A script
    # whose profile is undefined makes the agent refuse to serve (fail-closed), so
    # nothing ever runs under an unstated - possibly root - context.
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
            croak "Profile '$pname': too many caps in '$path' (max " . MAX_CAPS . ")"
                if @{ $p->{caps} } > MAX_CAPS;
            for my $c (@{ $p->{caps} }) {
                croak "Profile '$pname': capability name too long in '$path'"
                    if length $c >= NAMELEN;
            }

            $p->{writable} = [ grep { length } split /:/, ($p->{writable} // '') ];
            for my $w (@{ $p->{writable} }) {
                croak "Profile '$pname': writable path must be absolute: '$w' in '$path'"
                    unless $w =~ m{^/};
                croak "Profile '$pname': writable path too long in '$path'"
                    if length $w >= VALLEN;
            }
            croak "Profile '$pname': too many writable paths in '$path' (max " . MAX_WRITABLE . ")"
                if @{ $p->{writable} } > MAX_WRITABLE;

            if (defined $p->{run_as} && length $p->{run_as}) {
                croak "Profile '$pname': invalid run_as '$p->{run_as}' in '$path'"
                    unless $p->{run_as} =~ /^(?:[A-Za-z_][A-Za-z0-9_-]*|\d+)\z/
                        && length $p->{run_as} < NAMELEN;
                # Bound a numeric uid/gid to 32 bits, matching the C executor
                # (ctrl-exec-executor.c set_profile_field): a value that does not fit
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
# Returns hashref: { script_name => { path, profile } }
# Dies on parse errors; unknown/bad entries are skipped with a warning
#
# Optional opts:
#   script_dirs => \@dirs   (arrayref of approved directories; undef = no restriction)
sub load_allowlist ($path = undef, $script_dirs = undef) {
    my ($allowlist) = load_allowlist_full($path, $script_dirs);
    return $allowlist;
}

# As load_allowlist, but also returns the entries that were skipped and why:
#   ($allowlist, $skipped) = load_allowlist_full($path, $script_dirs)
# $skipped is { script_name => "reason" }, the text a refused run reports as
# "script not permitted: <reason>" (T-044). A line with no usable name (NUL
# byte, malformed) cannot be keyed by name and is only warned about.
sub load_allowlist_full ($path = undef, $script_dirs = undef) {
    $path //= '/etc/ctrl-exec-agent/scripts.conf';

    open my $fh, '<', $path
        or croak "Cannot open allowlist '$path': $!";

    my (%allowlist, %skipped);
    while (my $line = <$fh>) {
        chomp $line;
        if (index($line, "\0") >= 0) {
            warn "Allowlist: skipping line containing a NUL byte\n";
            next;
        }
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
                $skipped{$name} = 'its scripts.conf entry has no script path';
                warn "Allowlist: skipping '$name' - no script path\n";
                next;
            }
            if (defined $extra_path) {
                $skipped{$name} = "its scripts.conf entry has more than one path"
                                . " ('$script_path' and '$extra_path')";
                warn "Allowlist: skipping '$name' - more than one path on the line\n";
                next;
            }
            if (length $script_path >= VALLEN) {
                $skipped{$name} = 'its path is too long (' . length($script_path)
                                . ' characters; the limit is ' . (VALLEN - 1) . ')';
                warn "Allowlist: skipping '$name' - path or profile name too long\n";
                next;
            }
            if (length($annot{profile} // '') >= NAMELEN) {
                $skipped{$name} = 'its profile name is too long (' . length($annot{profile})
                                . ' characters; the limit is ' . (NAMELEN - 1) . ')';
                warn "Allowlist: skipping '$name' - path or profile name too long\n";
                next;
            }
            unless ($script_path =~ m{^/}) {
                $skipped{$name} = "'$script_path' is not an absolute path";
                warn "Allowlist: skipping '$name' - path must be absolute: $script_path\n";
                next;
            }
            if ($script_dirs && !_path_in_dirs($script_path, $script_dirs)) {
                $skipped{$name} = not_in_dirs_reason($script_path, $script_dirs);
                warn "Allowlist: skipping '$name' - path not in approved script_dirs: $script_path\n";
                next;
            }
            if (defined(my $why = script_owner_problem($script_path))) {
                $skipped{$name} = $why;
                warn "Allowlist: skipping '$name' - $why\n";
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

    return (\%allowlist, \%skipped);
}

# The reason text for a path outside script_dirs, shared by the load-time skip
# and the execution-time re-check.
sub not_in_dirs_reason ($path, $dirs) {
    return "'$path' is not under script_dirs (" . join(':', @$dirs) . ')';
}

# Why a run of $name is refused, for "script not permitted: <reason>":
# the recorded skip reason, an execution-time script_dirs rejection, or
# 'not in scripts.conf' for a name the allowlist has never heard of.
sub not_permitted_reason ($name, $allowlist, $skipped = undef, $script_dirs = undef) {
    return 'not in scripts.conf' unless defined $name && $name =~ /^[\w-]+$/;
    return $skipped->{$name} if $skipped && defined $skipped->{$name};
    my $entry = $allowlist->{$name};
    return 'not in scripts.conf' unless defined $entry;
    my $path = ref $entry eq 'HASH' ? $entry->{path} : $entry;
    if (defined $path && $script_dirs && !_path_in_dirs($path, $script_dirs)) {
        return not_in_dirs_reason($path, $script_dirs);
    }
    if (defined $path && defined(my $why = script_owner_problem($path))) {
        return $why;
    }
    return 'not in scripts.conf';
}

# ---- script ownership (T-045) ------------------------------------------------
#
# An allowlisted script, and every directory from / down to it, must be owned by
# root and writable by neither group nor other, and the script must be a regular
# file - otherwise a user who can write any of them can change what root (or a
# run_as profile) runs. This holds whatever the profile's run_as: scripts.conf
# is root's policy, so its scripts are root's files.
#
# The privileged executor enforces this rule before every run (it is the
# authority; src/ctrl-exec-executor.c script_trust_check). The front end applies
# the SAME rule at allowlist load and before each run, so a refused script is
# reported early ("script not permitted: <reason>", self-check) and, without an
# executor (direct mode), is never run. KEEP IN SYNC WITH the C walk: the same
# path walk, the same check order, the same reason texts
# (t/exec-ownership-parity.t compares the two).
#
# Symbolic links on the path are followed, but only once the directory holding
# the link has passed the rule (so only root can have made or changed the link);
# the link's target is then walked with the same rule. More than MAX_SYMLINKS
# links is refused, as the kernel does.

use constant MAX_SYMLINKS => 40;

# Test seams - never set outside tests. Owners trusted in place of root, and a
# directory whose ancestors are not checked (tests cannot create a root-owned
# directory chain without root).
our @TRUSTED_OWNERS = (0);
our $TRUSTED_TOP;

# The reason text when one node on the path breaks the rule, or undef. $want is
# 'dir' or 'file'. Order of checks: type, owner, world-writable, group-writable.
sub _owner_node_problem ($shown, $st, $want, $exempt) {
    my ($dev, $ino, $mode, $uid) = @{$st}[0, 1, 2, 4];
    if ($want eq 'file') {
        return "'$shown' is not a regular file" unless Fcntl::S_ISREG($mode);
    }
    else {
        return "'$shown' is not a directory" unless Fcntl::S_ISDIR($mode);
        return undef if $exempt->{"$dev:$ino"};
    }
    return "'$shown' is owned by uid $uid, not root"
        unless grep { $_ == $uid } @TRUSTED_OWNERS;
    return "'$shown' is world-writable" if $mode & 0002;
    return "'$shown' is group-writable" if $mode & 0020;
    return undef;
}

# dev:ino of each strict ancestor of $TRUSTED_TOP (test seam), else empty.
sub _owner_exempt_dirs () {
    return {} unless defined $TRUSTED_TOP;
    my $top = abs_path($TRUSTED_TOP) // return {};
    my %ex;
    my @parts = grep { length } split m{/}, $top;
    pop @parts;
    my $p = '';
    for my $d ('', @parts) {
        $p .= "/$d" if length $d;
        my @st = stat(length $p ? $p : '/') or last;
        $ex{"$st[0]:$st[1]"} = 1;
    }
    return \%ex;
}

# The full verdict on a script path:
#   ('ok')               the path passes the rule
#   ('deny', $reason)    it breaks the rule; $reason names the path and the rule
#   ('unknown', $error)  it cannot be examined (missing, or a directory this
#                        process cannot search) - the front end gives no verdict
#                        and leaves the decision to the executor (or to the
#                        exec, which fails for the same reason)
sub script_owner_check ($path) {
    return ('unknown', "'$path' is not an absolute path") unless $path =~ m{^/};
    my $exempt = _owner_exempt_dirs();
    my @todo   = grep { length } split m{/}, $path;
    my $cur    = '/';
    my $links  = 0;

    my @st = lstat '/' or return ('unknown', "'/': $!");
    if (defined(my $p = _owner_node_problem('/', \@st, 'dir', $exempt))) {
        return ('deny', $p);
    }
    my $final;
    while (@todo) {
        my $c = shift @todo;
        my $want = @todo ? 'dir' : 'file';
        next if $c eq '.';
        my $next;
        if ($c eq '..') {
            ($next = $cur) =~ s{/[^/]*$}{};
            $next = '/' unless length $next;
        }
        else {
            $next = $cur eq '/' ? "/$c" : "$cur/$c";
        }
        @st = lstat $next or return ('unknown', "'$next': $!");
        if (Fcntl::S_ISLNK($st[2])) {
            return ('deny', "'$next' has too many levels of symbolic links")
                if ++$links > MAX_SYMLINKS;
            my $t = readlink $next;
            return ('unknown', "'$next': $!") unless defined $t;
            if ($t =~ m{^/}) {
                $cur = '/';
                @st = lstat '/' or return ('unknown', "'/': $!");
                if (defined(my $p = _owner_node_problem('/', \@st, 'dir', $exempt))) {
                    return ('deny', $p);
                }
            }
            unshift @todo, grep { length } split m{/}, $t;
            next;
        }
        if (Fcntl::S_ISDIR($st[2]) || $want eq 'dir') {
            # A directory to descend into; a non-directory with more to come is
            # refused here as "not a directory".
            if (defined(my $p = _owner_node_problem($next, \@st, 'dir', $exempt))) {
                return ('deny', $p);
            }
            $cur = $next;
            next;
        }
        if (defined(my $p = _owner_node_problem($next, \@st, 'file', $exempt))) {
            return ('deny', $p);
        }
        $final = $next;
    }
    # The walk ended on a directory ("/", "dir/", "dir/.", "dir/..").
    return ('deny', "'$cur' is not a regular file") unless defined $final;
    return ('ok');
}

# The reason a script path breaks the ownership rule, or undef when it passes
# or cannot be examined here (see script_owner_check).
sub script_owner_problem ($path) {
    my ($verdict, $why) = script_owner_check($path);
    return $verdict eq 'deny' ? $why : undef;
}

# Log each skipped scripts.conf entry once (the caller calls this once per load:
# at start-up and on each reload), with the reason a run of it will be given.
sub log_skipped ($skipped) {
    for my $name (sort keys %{ $skipped // {} }) {
        Exec::Log::log_action('WARNING', {
            ACTION => 'allowlist-skip',
            SCRIPT => $name,
            REASON => $skipped->{$name},
        });
    }
}

# Check whether a script name is permitted
# Returns the script path if permitted, undef otherwise
#
# Optional: script_dirs => \@dirs  re-validates path at execution time
sub validate_script ($name, $allowlist, $script_dirs = undef) {
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
sub script_profile ($name, $allowlist) {
    my $entry = $allowlist->{$name};
    return undef unless defined $entry;
    return ref $entry eq 'HASH' ? ($entry->{profile} // 'default') : 'default';
}

# Cross-check the allowlist against the defined profiles: every script's profile
# must be defined in agent.conf. This includes 'default' (the profile an
# unannotated script resolves to) - there is NO implicit built-in default, so an
# unannotated script with no [profile default] configured is reported here.
# Returns a list of "script -> profile" strings for any that are not defined
# (empty when all resolve). Fail-closed: callers (serve startup, self-check)
# treat a non-empty result as a fatal config error rather than silently running
# an undefined - possibly over-permissive - profile.
sub validate_profiles ($allowlist, $config) {
    my %defined = %{ $config->{profiles} // {} };
    my @unknown;
    for my $name (sort keys %$allowlist) {
        my $p = script_profile($name, $allowlist) // 'default';
        push @unknown, "$name -> $p" unless exists $defined{$p};
    }
    return @unknown;
}

# Settings the running process has already acted on and cannot change without a
# restart: the listener is bound to 'port' and holds the TLS identity loaded from
# 'cert', 'key' and 'ca'. A reload keeps the running value of these and says so.
use constant RESTART_ONLY_KEYS => qw(port cert key ca);

# Plan a SIGHUP reload of agent.conf (and the allowlist it must agree with).
# Nothing is applied here: the caller swaps the result in only when this returns.
#
#   reload_plan($config_path, $allowlist_path, $old_config, $old_allowlist, $old_skipped)
#     -> { config => \%new, allowlist => \%allow, skipped => \%why, notes => [ ... ] }
#
# Dies, leaving the caller's old config in force, when agent.conf cannot be
# parsed or validated, or when the allowlist that would be in force names a
# profile the new agent.conf does not define (fail-closed, as at startup). A
# scripts.conf that cannot be read does not by itself block the reload: the
# previous allowlist stays and the plan says so in notes. Restart-only settings
# that changed keep their running value in the returned config and add a note.
sub reload_plan ($config_path, $allowlist_path, $old_config, $old_allowlist, $old_skipped = undef) {
    my $config = load_config($config_path);   # dies on parse/validation error
    my @notes;

    my ($allowlist, $skipped) = eval { load_allowlist_full($allowlist_path, $config->{script_dirs}) };
    unless ($allowlist) {
        my $err = $@ || 'unknown error'; chomp $err;
        push @notes, "allowlist reload failed, keeping the previous allowlist: $err";
        $allowlist = $old_allowlist;
        $skipped   = $old_skipped // {};
    }

    if (my @bad = validate_profiles($allowlist, $config)) {
        die "script(s) reference an undefined profile: " . join(', ', @bad) . "\n";
    }

    for my $k (RESTART_ONLY_KEYS) {
        my ($old, $new) = ($old_config->{$k}, $config->{$k});
        next if !defined $old && !defined $new;
        next if defined $old && defined $new && $old eq $new;
        push @notes, "'$k' changed in agent.conf but needs a restart to take effect;"
                   . " keeping the running value";
        if   (defined $old) { $config->{$k} = $old }
        else                { delete $config->{$k} }
    }

    return { config => $config, allowlist => $allowlist, skipped => $skipped, notes => \@notes };
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
sub _path_in_dirs ($path, $dirs) {
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
sub _normalize_ipv4 ($addr) {
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
sub ip_allowed ($ip, $allowed_ref) {
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
