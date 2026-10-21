package Exec::DispatcherConfig;

# The dispatcher's flat INI config loader (key = value, '#' comments), shared by
# ctrl-exec-dispatcher and ctrl-exec-api, which carried byte-identical copies.
# Requires cert/key/ca. The agent's richer sectioned config (profiles, tags) is a
# deliberately separate parser - Exec::Agent::Config.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Exporter qw(import);
use Cwd      qw(abs_path);
use File::Basename qw(dirname);

our @EXPORT_OK = qw(load_config conf_dir conf_path legacy_dir_error
                    conf_dir_state migrate_legacy_dir startup_check);

# The dispatcher's config directory (ctrl-exec.conf, the CA, the dispatcher
# cert/key, auth-hook). It was /etc/ctrl-exec before 0.13. The two package
# variables are the seam the tests use.
#
# Which directory holds the real config is decided by content, not by which
# path exists: "real" is ctrl-exec.conf plus the CA key (ca.key). The image
# and the packages seed /etc/ctrl-exec-dispatcher with an example config and
# no CA, so running on that beside a real old directory would mean the wrong
# auth or a second CA (T-047). So:
#
#   old absent, or the migration symlink to the new dir   -> new (no change)
#   old real, new absent or seeded (no CA)                 -> old, in place (T-065)
#   old ctrl-exec.conf without ca.key, new absent          -> old, in place (no
#     ambiguity: a CA kept elsewhere via ca =, or not yet initialised; the
#     installers moved this before 0.14 too)
#   anything else with the old path present                -> refused (T-047)
#
# Running in place never moves anything: the move is done only by the
# installers (deb postinst, install.sh) through migrate_legacy_dir(), as root,
# once, while no second copy of it can run. ced, ctrl-exec-api and the
# maintenance timer may start together, so none of them touches the
# directories; they read whichever one holds the real config.
our $CONF_DIR   = '/etc/ctrl-exec-dispatcher';
our $LEGACY_DIR = '/etc/ctrl-exec';

# Seams for the tests: the mount point check and rename.
our $IS_MOUNT = \&_is_mount_point;
our $RENAME   = sub ($from, $to) { rename $from, $to };

# A directory holds a real dispatcher config: ctrl-exec.conf and the CA key.
# Only existence is checked, so the unprivileged API (group ctrl-exec, which
# can search but not read ca.key) sees the same answer as root.
sub _is_real ($dir) {
    return -d $dir && -f "$dir/ctrl-exec.conf" && -e "$dir/ca.key";
}

# True when $path is a mount point: another device than its parent, or listed
# in /proc/self/mountinfo (a bind mount from the same filesystem).
sub _is_mount_point ($path) {
    my @st = stat $path       or return 0;
    my @up = stat dirname($path) or return 0;
    return 1 if $st[0] != $up[0];
    my $want = abs_path($path) // $path;
    open my $fh, '<', '/proc/self/mountinfo' or return 0;
    while (my $line = <$fh>) {
        my $mp = (split ' ', $line)[4] // next;
        $mp =~ s/\\([0-7]{3})/chr oct $1/ge;
        return 1 if $mp eq $want;
    }
    return 0;
}

# Where the config is, as a hashref:
#   action  'new' | 'in-place' | 'refuse'
#   dir     the directory to use (not for 'refuse')
#   mount   true when the old directory is a mount point ('in-place' only)
#   message the refusal text ('refuse' only)
# Doctor and the log notice read this too.
sub conf_dir_state () {
    my ($old, $new) = ($LEGACY_DIR, $CONF_DIR);
    return { action => 'new', dir => $new } unless -e $old || -l $old;
    if (-l $old) {
        my $o = abs_path($old);
        my $n = abs_path($new);
        return { action => 'new', dir => $new } if defined $o && defined $n && $o eq $n;
    }
    elsif ((_is_real($old) && !_is_real($new))
        || (-d $old && -f "$old/ctrl-exec.conf" && !-e $new && !-l $new)) {
        return { action => 'in-place', dir => $old, mount => $IS_MOUNT->($old) ? 1 : 0 };
    }
    return { action => 'refuse', message => _refusal($old, $new) };
}

sub _refusal ($old, $new) {
    my $both = (!-l $old && _is_real($old) && _is_real($new))
        ? "Both $old and $new hold a dispatcher config with a CA (ca.key); "
        . "ctrl-exec cannot tell which one is in use.\n"
        : '';
    return "ctrl-exec: refusing to start: the old config directory $old "
         . "exists and is not a symlink to $new.\n"
         . $both
         . "The dispatcher's config now lives in $new, and running on "
         . "either directory while the other exists could use the wrong "
         . "configuration or create a second CA.\n"
         . "To migrate: stop ctrl-exec-api, move the directory "
         . "(mv $old $new; if $new already exists, merge "
         . "what you need into it and remove $old), then change the "
         . "paths inside $new/ctrl-exec.conf (cert, key, ca, auth_hook, "
         . "...) from $old/ to $new/.\n"
         . "In a container: mount the volume at $new instead of "
         . "$old, edit those paths on the volume, and recreate the "
         . "container.\n";
}

# The refusal message when the directories are ambiguous (see above), else
# undef.
sub legacy_dir_error () {
    my $s = conf_dir_state();
    return $s->{action} eq 'refuse' ? $s->{message} : undef;
}

# The directory to use. Dies with the refusal when the old path blocks it;
# otherwise the old directory when the config is still there (in place), else
# the new one, whether or not it exists yet (a fresh install creates it).
sub conf_dir () {
    my $s = conf_dir_state();
    die $s->{message} if $s->{action} eq 'refuse';
    return $s->{dir};
}

# Default location of ctrl-exec.conf under the directory conf_dir() picked.
sub conf_path () {
    return conf_dir() . '/ctrl-exec.conf';
}

# Called first by ced and ctrl-exec-api, after Exec::Log::init: a refusal is
# logged, printed on stderr and exits 78 (EX_CONFIG) before any mode runs; a
# config still at the old path is logged (never printed, stdout and stderr are
# parsed by automation) and used in place. Returns the directory.
sub startup_check () {
    require Exec::Log;
    my $s = conf_dir_state();
    if ($s->{action} eq 'refuse') {
        Exec::Log::log_action('ERR', {
            ACTION => 'config-dir',
            RESULT => 'refused',
            OLD    => $LEGACY_DIR,
            NEW    => $CONF_DIR,
        });
        print STDERR $s->{message};
        exit 78;
    }
    if ($s->{action} eq 'in-place') {
        Exec::Log::log_action($s->{mount} ? 'INFO' : 'WARNING', {
            ACTION => 'config-dir',
            RESULT => 'in-place',
            OLD    => $LEGACY_DIR,
            NEW    => $CONF_DIR,
            MOUNT  => $s->{mount},
            REASON => $s->{mount}
                ? "config is a mount at $LEGACY_DIR; it works there, and can be mounted at $CONF_DIR at leisure"
                : "config not yet moved to $CONF_DIR; the package upgrade or install.sh moves it",
        });
    }
    return $s->{dir};
}

# The installers' move (deb postinst, install.sh), run as root. Only the old
# layout is touched: a real config at the old path and the new path absent or
# seeded, or an old ctrl-exec.conf without ca.key and no new path; never a
# mount point. Then:
#   1. a seeded new directory is renamed aside to <new>.seeded (kept, not
#      deleted);
#   2. the old directory is renamed to the new path - one rename(2) within
#      /etc, so the data is either wholly at the old path or wholly at the new
#      one, never half-moved; if it fails, step 1 is undone and the host runs
#      in place;
#   3. a symlink is left at the old path, for anything outside ctrl-exec that
#      still names it;
#   4. paths under the old directory in ctrl-exec.conf are pointed at the new
#      one (previous file kept as ctrl-exec.conf.pre-0.13), written to a temp
#      file and renamed over.
# A cross-filesystem move (copy, verify, remove) is never needed: the old path
# can only be on another filesystem than /etc when it is a mount point, which
# is left in place. Never dies. Returns { result => 'none' | 'migrated' |
# 'in-place' | 'refused', message => text for the installer to print }.
sub migrate_legacy_dir () {
    my ($old, $new) = ($LEGACY_DIR, $CONF_DIR);
    my $s = conf_dir_state();
    return { result => 'none' } if $s->{action} eq 'new';
    return { result => 'refused', message => $s->{message} } if $s->{action} eq 'refuse';

    my $stay = sub ($why) {
        return { result => 'in-place', message =>
            "ctrl-exec: the dispatcher config stays at $old ($why); "
          . "ced and ctrl-exec-api use it there.\n" };
    };
    return $stay->("a mount point; mount it at $new at leisure") if $s->{mount};
    return $stay->("$new is a symlink") if -l $new;

    my $aside;
    if (-e $new) {
        $aside = "$new.seeded";
        return $stay->("$aside already exists") if -e $aside || -l $aside;
        $RENAME->($new, $aside)
            or return $stay->("could not move the seeded $new aside: $!");
    }
    unless ($RENAME->($old, $new)) {
        my $err = "$!";
        rename $aside, $new if defined $aside;
        return $stay->("could not move it to $new: $err");
    }
    my @notes;
    symlink $new, $old
        or push @notes, "could not leave a symlink at $old: $!";
    my $conf = "$new/ctrl-exec.conf";
    my $rw   = _rewrite_paths($conf, $old, $new);
    push @notes, $rw if defined $rw && $rw ne 'rewritten';

    eval {
        require Exec::Log;
        Exec::Log::init('ctrl-exec-dispatcher');
        Exec::Log::log_action('INFO', {
            ACTION => 'config-migrated',
            OLD    => $old,
            NEW    => $new,
            (defined $aside ? (SEEDED => $aside) : ()),
        });
    };
    my $msg = "ctrl-exec: moved the dispatcher config $old to $new "
            . "(symlink left at $old)"
            . (defined $aside ? "; the seeded $new is kept as $aside" : '')
            . (defined $rw && $rw eq 'rewritten'
                ? "; paths in $conf updated (previous copy $conf.pre-0.13)" : '')
            . ".\n";
    $msg .= "ctrl-exec: $_\n" for @notes;
    return { result => 'migrated', message => $msg };
}

# Point "key = <old>/..." values in ctrl-exec.conf at <new>/. Returns undef when
# nothing needed changing, 'rewritten', or a note on failure (the file is then
# left as it was; the symlink still resolves the old paths).
sub _rewrite_paths ($conf, $old, $new) {
    open my $in, '<', $conf or return;
    my @lines = <$in>;
    close $in;
    my $n = 0;
    for (@lines) { $n++ if s{(=\s*)\Q$old\E/}{$1$new/} }
    return unless $n;
    my @st  = stat $conf;
    my $bak = "$conf.pre-0.13";
    my $tmp = "$conf.migrate.$$";
    my $ok = eval {
        unless (-e $bak) {
            open my $b, '>', $bak or die "$bak: $!\n";
            print {$b} do { open my $i, '<', $conf or die "$conf: $!\n"; local $/; <$i> };
            close $b or die "$bak: $!\n";
            chmod $st[2] & 07777, $bak;
            chown $st[4], $st[5], $bak;
        }
        open my $out, '>', $tmp or die "$tmp: $!\n";
        print {$out} @lines;
        close $out or die "$tmp: $!\n";
        chmod $st[2] & 07777, $tmp;
        chown $st[4], $st[5], $tmp;
        rename $tmp, $conf or die "$conf: $!\n";
        1;
    };
    return 'rewritten' if $ok;
    unlink $tmp;
    return "could not update the paths in $conf ($@); they still resolve through the symlink";
}

# Installer entry point, with the old and new directories as arguments:
#   perl -MExec::DispatcherConfig -e 'Exec::DispatcherConfig::installer_migrate()' OLD NEW
# Prints what happened (installer output, not parsed) and always exits 0, so a
# package configure never fails over it; ced and ctrl-exec-api decide at start.
sub installer_migrate () {
    local $LEGACY_DIR = $ARGV[0] if defined $ARGV[0];
    local $CONF_DIR   = $ARGV[1] if defined $ARGV[1];
    my $r = eval { migrate_legacy_dir() }
        // { message => "ctrl-exec: config directory migration skipped: $@" };
    if (($r->{result} // '') eq 'refused') {
        print "ctrl-exec: leaving $LEGACY_DIR alone: it is not the layout an upgrade "
            . "moves (ctrl-exec.conf and ca.key there with $CONF_DIR absent or without a CA, "
            . "or ctrl-exec.conf there and no $CONF_DIR).\n"
            . "ctrl-exec: ced and ctrl-exec-api refuse to start until it is resolved:\n";
    }
    print $r->{message} if defined $r->{message};
    exit 0;
}

sub load_config ($path) {
    open my $fh, '<', $path
        or die "Cannot open config '$path': $!\n";
    my %config;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*[#\s]/;
        $config{$1} = $2 if $line =~ /^\s*(\w+)\s*=\s*(.+?)\s*$/;
    }
    close $fh;
    for my $k (qw(cert key ca)) {
        die "Missing '$k' in $path\n" unless $config{$k};
    }
    return \%config;
}

1;
