package Exec::Doctor::Dispatcher;

# The checks of 'ctrl-exec-dispatcher doctor' (T-055): the config directory
# (T-047/T-065, Exec::DispatcherConfig::conf_dir_state), ctrl-exec.conf, the
# dispatcher's certificate and CA, the auth hook, the API listener settings
# (Exec::API::listen_plan, as ctrl-exec-api checks them at start) and its unix
# socket, and the agent registry (agents whose certificate another
# dispatcher's CA issued, T-062). Report only, except under --fix.
#
# The automatic fixes (--fix), and why each is safe:
#   api-socket-mode   the API's unix socket gets mode 0660 again, the mode
#       ctrl-exec-api gives it at every start: it narrows access (no 'other'
#       bits), and only back to what the next start of the API sets anyway.
#   api-socket-group  the socket gets api_socket_group again, as the API sets
#       it at every start; same reasoning.
# Everything else is reported with its fix and left alone: moving the config
# directory is the installers' job (only they run while nothing else can), and
# auth, certificates and agents need the operator's decision.

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Exec::Doctor           qw();
use Exec::DispatcherConfig qw();
use Exec::Agent::Config    qw();
use Exec::CertInfo         qw();
use Exec::Registry         qw();

use constant EXPIRY_PROBLEM_DAYS => 30;

sub _err ($e) {
    $e //= 'unknown error';
    $e =~ s/ at \S+ line \d+\.?\s*$//;
    $e =~ s/\s+\z//;
    return $e;
}

sub _q ($p) { return $p =~ m{\A[\w./:+@%=-]+\z} ? $p : "'" . ($p =~ s/'/'\\''/gr) . "'" }

sub _days_left ($expiry) {
    my $epoch = Exec::CertInfo::expiry_epoch($expiry);
    return defined $epoch ? int(($epoch - time) / 86400) : undef;
}

# How the installers' move is re-run on this host: the package's configure,
# or install.sh for a tarball install. Seam for tests.
our $DPKG_INFO = '/var/lib/dpkg/info/ctrl-exec-dispatcher.list';
sub _rerun_installer () {
    return -e $DPKG_INFO ? 'sudo dpkg-reconfigure ctrl-exec-dispatcher'
                         : 'sudo ./install.sh --dispatcher (from the release tarball)';
}

# A hook that authorises everything: after comments and blank lines, nothing
# but 'exit 0' (or true, or ':'). The shipped auth-hook.example is one.
sub hook_allows_all ($text) {
    my @cmd = grep { /\S/ && !/^\s*#/ } split /\n/, $text;
    return !grep { !/^\s*(?:exit\s+0|true|:)\s*;?\s*$/ } @cmd;
}

# checks(config => <ctrl-exec.conf or undef for the default>)
# Returns an arrayref of findings (Exec::Doctor).
sub checks (%o) {
    my @f;
    my $P = \&Exec::Doctor::problem;
    my $N = \&Exec::Doctor::note;
    my ($old, $new) = ($Exec::DispatcherConfig::LEGACY_DIR, $Exec::DispatcherConfig::CONF_DIR);
    my $as_root = 'sudo ctrl-exec-dispatcher doctor';

    # Which directory holds the config (T-047/T-065). A directory this user
    # cannot search would be judged absent, so say so instead of guessing.
    for my $d ($old, $new) {
        next unless -d $d && !-x _;
        push @f, $N->('access', "Could not search $d (permission denied), so nothing else was checked.",
                      $as_root);
        return \@f;
    }
    my $state = Exec::DispatcherConfig::conf_dir_state();
    if ($state->{action} eq 'refuse') {
        my $both = $state->{message} =~ /^Both /m ? ' Both hold a CA (ca.key).' : '';
        push @f, $P->('config-dir', "ced and ctrl-exec-api refuse to start (exit 78): $old exists and is"
            . " not a symlink to $new, and it is not the layout an upgrade moves.$both",
            "keep the directory whose CA your agents trust: merge it into $new, then: sudo rm -r $old,"
            . " and change $old/ to $new/ in $new/ctrl-exec.conf");
        return \@f unless defined $o{config};
    }
    elsif ($state->{action} eq 'in-place') {
        if ($state->{mount}) {
            push @f, $N->('config-dir-in-place', "The dispatcher config is a mount at $old and is used"
                . ' there; it works as it is.',
                "mount the volume at $new instead, change $old/ to $new/ in its ctrl-exec.conf, and"
                . ' recreate the container');
        }
        else {
            my $first = -l $new ? "sudo rm $new (a symlink), then: "
                      : (-e "$new.seeded" || -l "$new.seeded") ? "sudo rm -r $new.seeded, then: "
                      : '';
            push @f, $N->('config-dir-in-place', "The dispatcher config is still at $old and is used"
                . " there; it works as it is, but has not been moved to $new.",
                $first . _rerun_installer() . " (moves it and leaves a symlink at $old)");
        }
    }

    my $path = $o{config} // "$state->{dir}/ctrl-exec.conf";
    if (defined(my $p = Exec::Agent::Config::unreadable_path($path))) {
        push @f, $N->('access', "Could not read $p (permission denied), so nothing else was checked.",
                      $as_root);
        return \@f;
    }
    my $config = eval { Exec::DispatcherConfig::load_config($path) };
    unless ($config) {
        push @f, $P->('config', "$path cannot be loaded: " . _err($@) . '.', 'sudoedit ' . _q($path));
        return \@f;
    }

    push @f, _cert_checks($config);
    push @f, _auth_checks($config, $path);
    push @f, _api_checks($config, $path);
    push @f, _registry_checks($config);
    return \@f;
}

sub _cert_checks ($config) {
    my @f;
    my $P = \&Exec::Doctor::problem;
    # A fresh install: no CA, no dispatcher certificate, no agent registered.
    my $agents = eval { Exec::Registry::list_agents(registry_dir => _registry_dir($config)) } // [];
    if (!-e $config->{ca} && !-e $config->{cert} && !@$agents) {
        return Exec::Doctor::note('not-set-up', 'This dispatcher has no CA and no certificate yet'
            . ' (a fresh install): it cannot pair or reach agents until it has.',
            'sudo ctrl-exec-dispatcher setup-ca, then: sudo ctrl-exec-dispatcher setup-ctrl-exec');
    }
    unless (-e $config->{ca}) {
        push @f, $P->('ca-cert', "The CA certificate $config->{ca} is missing: agents cannot be"
            . ' verified or paired.', 'restore it from a backup of this dispatcher (a new CA, setup-ca,'
            . ' means re-pairing every agent)');
    }
    my $cert = $config->{cert};
    unless (-e $cert) {
        push @f, $P->('dispatcher-cert', "The dispatcher certificate $cert is missing: no agent can be reached.",
                      'sudo ctrl-exec-dispatcher setup-ctrl-exec');
        return @f;
    }
    my $expiry = Exec::CertInfo::expiry_from_path($cert);
    my $days   = _days_left($expiry);
    # Rotation (maintain) renews it cert_renewal_days (default 90) before
    # expiry; closer than that and 30 days, it has not been happening.
    my $renew  = $config->{cert_renewal_days} // 90;
    my $limit  = $renew =~ /^\d+$/ && $renew < EXPIRY_PROBLEM_DAYS ? $renew : EXPIRY_PROBLEM_DAYS;
    if (defined $days && $days < $limit) {
        push @f, $P->('dispatcher-cert-expiry', "The dispatcher certificate $cert "
            . ($days < 0 ? "expired on $expiry" : "expires on $expiry ($days days)")
            . ': rotation has not renewed it (is ctrl-exec-maintenance.timer running?).',
            'sudo ctrl-exec-dispatcher rotate-cert');
    }
    # T-068: issued before 0.14 on an OpenSSL 1.1 host. It works with every
    # agent except one that also trusts another CA with this CA's name.
    if (defined(my $aki = Exec::CertInfo::has_aki_path($cert))) {
        push @f, Exec::Doctor::note('dispatcher-cert-no-aki', "The dispatcher certificate $cert"
            . ' predates 0.14: it has no Authority Key Identifier, so an agent that also trusts'
            . " another CA with the same name as this dispatcher's CA refuses it at the TLS handshake.",
            'sudo ctrl-exec-dispatcher rotate-cert (then pair again any agent that refused it)')
            unless $aki;
    }
    return @f;
}

sub _auth_checks ($config, $path) {
    my $hook = $config->{auth_hook};
    return () unless defined $hook && length $hook;
    my $P = \&Exec::Doctor::problem;
    my $off = "comment out auth_hook in $path (then api_auth_default applies)";
    return $P->('auth-hook-missing', "auth_hook names $hook, which does not exist: every request,"
        . ' CLI and API, is denied.', "install the hook there, or $off") unless -e $hook;
    return $P->('auth-hook-not-executable', "The auth hook $hook is not executable: every request,"
        . ' CLI and API, is denied.', 'sudo chmod 755 ' . _q($hook)) unless -x $hook;
    if (defined(my $p = Exec::Agent::Config::unreadable_path($hook))) {
        return Exec::Doctor::note('access', "Could not read $p (permission denied): the auth hook's"
            . ' rules were not checked.', 'sudo ctrl-exec-dispatcher doctor');
    }
    my $text = do { open my $fh, '<', $hook or return (); local $/; <$fh> } // '';
    return () unless hook_allows_all($text);
    return $P->('auth-hook-allow-all', "The auth hook $hook allows every request (it is the shipped"
        . ' example, or does nothing but exit 0): every API and CLI request is authorised.',
        'add real rules (examples: /usr/share/ctrl-exec/examples/auth-hook.example): sudoedit '
        . _q($hook) . "; or $off");
}

sub _api_checks ($config, $path) {
    require Exec::API;
    my @f;
    my $P = \&Exec::Doctor::problem;
    my $plan = Exec::API::listen_plan($config);
    unless ($plan->{ok}) {
        return $P->('api-config', "ctrl-exec-api refuses to start (exit 78): $plan->{error}.",
                    'sudoedit ' . _q($path));
    }
    my $s = $plan->{socket} or return ();
    my $sock = $s->{path};
    unless (-S $sock) {
        return Exec::Doctor::note('api-socket-absent', "The API socket $sock does not exist:"
            . ' ctrl-exec-api is not running (or not on this host).', 'sudo systemctl start ctrl-exec-api');
    }
    my @st = stat $sock;
    my $mode = $st[2] & 07777;
    if ($mode & ~0660) {
        push @f, $P->('api-socket-mode', sprintf("The API socket %s is mode %04o: %s; ctrl-exec-api"
            . ' creates it 0660.', $sock, $mode,
            ($mode & 0007) ? 'every local user can call the API' : 'it is wider than the API makes it'),
            "sudo chmod 0660 " . _q($sock),
            autofix => sub { chmod(0660, $sock) ? undef : "chmod: $!" });
    }
    if (defined $s->{gid} && $st[5] != $s->{gid}) {
        my $want = getgrgid($s->{gid}) // $s->{gid};
        my $has  = getgrgid($st[5]) // $st[5];
        push @f, $P->('api-socket-group', "The API socket $sock has group $has, not api_socket_group"
            . " $want: the members of $want cannot call the API, and those of $has can.",
            "sudo chgrp $want " . _q($sock),
            autofix => sub { chown(-1, $s->{gid}, $sock) ? undef : "chgrp: $!" });
    }
    return @f;
}

sub _registry_dir ($config) { return $config->{registry_dir} // '/var/lib/ctrl-exec/agents' }

sub _registry_checks ($config) {
    my @f;
    my $dir = _registry_dir($config);
    if (-d $dir && !(-r _ && -x _)) {
        return Exec::Doctor::note('access', "Could not read $dir (permission denied): the registered"
            . ' agents were not checked.', 'sudo ctrl-exec-dispatcher doctor');
    }
    my $agents = eval { Exec::Registry::list_agents(registry_dir => $dir) } // [];
    for my $a (@$agents) {
        my $h    = $a->{hostname} // '?';
        my $days = _days_left($a->{expiry});
        next unless defined $days;
        if (length($a->{agent_ca_fpr} // '')) {
            # Keep-certificate pairing (T-062): the dispatcher that issued the
            # agent's certificate renews it; this one never does.
            next unless $days < EXPIRY_PROBLEM_DAYS;
            push @f, Exec::Doctor::problem('agent-cert-pinned-expiry', "Agent '$h' keeps a certificate"
                . ' issued by another dispatcher\'s CA ('
                . Exec::CertInfo::format_sha256_fingerprint($a->{agent_ca_fpr}) . '), which this'
                . ' dispatcher never renews; it ' . ($days < 0 ? 'expired' : 'expires') . " on $a->{expiry}"
                . ($days < 0 ? '' : " ($days days)") . '.',
                "renew it on the dispatcher that issued it (sudo ctrl-exec-dispatcher maintain there),"
                . " or re-key it with this one: on $h: sudo ctrl-exec-agent request-pairing --dispatcher"
                . ' <this-host> --rekey');
        }
        elsif ($days < 0) {
            push @f, Exec::Doctor::problem('agent-cert-expired', "Agent '$h': its certificate expired on"
                . " $a->{expiry}, so this dispatcher can no longer reach it.",
                "re-pair it: on $h: sudo ctrl-exec-agent request-pairing --dispatcher <this-host>,"
                . ' then: sudo ctrl-exec-dispatcher approve <reqid>');
        }
    }
    return @f;
}

1;
