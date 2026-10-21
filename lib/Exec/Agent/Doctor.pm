package Exec::Agent::Doctor;

# The checks of 'ctrl-exec-agent doctor' (T-055): every problem the agent's
# files show, each with the command that fixes it. Built on the parsers and
# checks serve and self-check use (load_config, load_scripts, script_warnings,
# ExecClient::probe, the trust-map and CA-bundle readers), so doctor reports
# what the running agent does with the same files. Report only: nothing here
# writes, except the autofix of a finding, which runs only under --fix
# (Exec::Doctor::apply_fixes).
#
# The automatic fixes (--fix), and why each is safe:
#   trust-map-old-format  the pre-0.14 trusted-map lines are upgraded in place,
#       exactly as serve does at start (load_trusted_dispatchers with the CA
#       bundle): each line keeps the CA(s) it was accepted under, so no
#       dispatcher gains or loses access.
#   trust-ca-unused       a CA in the bundle that no trusted-map entry is under
#       and that did not issue the agent's own certificate is removed from the
#       bundle. Trust only narrows: no dispatcher can be served under that CA
#       (the map has no entry for it), so the only effect is that a stranger's
#       certificate from it no longer completes the TLS handshake. The CA
#       certificate is public; pairing that dispatcher again brings it back.
#       Never the last CA in the bundle (the listener needs one).
# Everything else is reported with its fix and left alone: tightening
# ownership or permissions of a script directory, for example, can stop the
# operators who write there (existing-estates rule).

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use Exec::Doctor              qw();
use Exec::Agent::Config       qw();
use Exec::Agent::AgentPairing qw();
use Exec::CertInfo            qw();

# Days before expiry at which a certificate no dispatcher can renew becomes a
# problem rather than a note.
use constant EXPIRY_PROBLEM_DAYS => 30;

my $DISPATCHER = '<dispatcher-host>';

sub _err ($e) {
    $e //= 'unknown error';
    $e =~ s/ at \S+ line \d+\.?\s*$//;
    $e =~ s/\s+\z//;
    return $e;
}

# A path as it goes into a shell command: quoted only when it has to be.
sub _q ($p) { return $p =~ m{\A[\w./:+@%=-]+\z} ? $p : "'" . ($p =~ s/'/'\\''/gr) . "'" }

sub _fpr ($f) { return Exec::CertInfo::format_sha256_fingerprint($f) }

sub _days_left ($expiry) {
    my $epoch = Exec::CertInfo::expiry_epoch($expiry);
    return defined $epoch ? int(($epoch - time) / 86400) : undef;
}

# The command that fixes an ownership-rule reason, or ''.
sub ownership_fix ($reason) {
    return 'sudo chmod g-w ' . _q($1) if $reason =~ /\A'(.+)' is group-writable\z/;
    return 'sudo chmod o-w ' . _q($1) if $reason =~ /\A'(.+)' is world-writable\z/;
    return 'sudo chown root ' . _q($1) if $reason =~ /\A'(.+)' is owned by uid \d+, not root\z/;
    return '';
}

# The fix for a skipped scripts.conf entry, from its reason.
sub _skip_fix ($name, $reason, $conf_path, $allow_path) {
    my $edit = "correct the '$name' line: sudoedit " . _q($allow_path);
    return "add a [profile $1] block to agent.conf (sudoedit " . _q($conf_path)
         . "), or $edit" if $reason =~ /\Aprofile '(.+)' is not defined in agent\.conf\z/;
    if (length(my $own = ownership_fix($reason))) {
        return "$own (or set script_ownership = warn in agent.conf: the script then runs with a warning)";
    }
    return "move the script under script_dirs, or add its directory to script_dirs in agent.conf"
         . " (sudoedit " . _q($conf_path) . ")" if $reason =~ /is not under script_dirs/;
    return $edit;
}

# checks(config => <agent.conf>, allowlist => <scripts.conf>,
#        listening => sub ($port) { ... }, start_command => '<cmd>')
# Returns an arrayref of findings (Exec::Doctor).
sub checks (%o) {
    my $conf_path  = $o{config};
    my $allow_path = $o{allowlist};
    my @f;
    my $P = \&Exec::Doctor::problem;
    my $N = \&Exec::Doctor::note;
    my $as_root = 'sudo ctrl-exec-agent doctor';

    # agent.conf: without it nothing else is known (paths, ports).
    if (defined(my $p = Exec::Agent::Config::unreadable_path($conf_path))) {
        push @f, $N->('access', "Could not read $p (permission denied), so nothing else was checked.",
                      $as_root);
        return \@f;
    }
    my $config = eval { Exec::Agent::Config::load_config($conf_path) };
    unless ($config) {
        push @f, $P->('agent-conf', 'agent.conf cannot be loaded, so the agent does not start: '
                      . _err($@) . '.', 'sudoedit ' . _q($conf_path) . ', then: sudo ctrl-exec-agent self-check');
        return \@f;
    }

    push @f, _script_checks($config, $conf_path, $allow_path);
    push @f, _executor_checks($config, $conf_path);
    push @f, _cert_and_trust_checks($config, %o);
    return \@f;
}

sub _script_checks ($config, $conf_path, $allow_path) {
    my @f;
    my $P = \&Exec::Doctor::problem;
    my $N = \&Exec::Doctor::note;
    if (defined(my $p = Exec::Agent::Config::unreadable_path($allow_path))) {
        return $N->('access', "Could not read $p (permission denied): scripts were not checked.",
                    'sudo ctrl-exec-agent doctor');
    }
    # The loader warns on stderr for each entry it skips or warns about; doctor
    # reports each as a finding instead.
    my ($allowlist, $skipped) = do {
        local $SIG{__WARN__} = sub { };
        eval { Exec::Agent::Config::load_scripts($allow_path, $config) };
    };
    unless ($allowlist) {
        return $P->('scripts-conf', 'scripts.conf cannot be read, so the agent does not start: '
                    . _err($@) . '.', 'sudoedit ' . _q($allow_path));
    }

    for my $name (sort keys %$skipped) {
        push @f, $P->('script-skipped', "scripts.conf entry '$name' is skipped and does not run: "
                      . "$skipped->{$name}.", _skip_fix($name, $skipped->{$name}, $conf_path, $allow_path));
    }

    my $paired = Exec::Agent::Config::paired_dispatcher_ids($config);
    my (%by_reason, @per_script);
    for my $name (sort keys %$allowlist) {
        my $path = Exec::Agent::Config::validate_script($name, $allowlist);
        if (!-e $path) {
            push @f, $P->('script-missing', "Script '$name': $path does not exist, so a run of it fails.",
                          "install it there, or remove the '$name' line: sudoedit " . _q($allow_path));
        }
        elsif (!-x $path) {
            push @f, $P->('script-not-executable', "Script '$name': $path is not executable, so a run of it fails.",
                          'sudo chmod +x ' . _q($path));
        }
        for my $w (Exec::Agent::Config::script_warnings($name, $allowlist, $paired)) {
            if ($w->{kind} eq 'ownership') {
                push @{ $by_reason{ $w->{value} } }, $name;
            }
            elsif ($w->{kind} eq 'unknown-dispatcher') {
                my $known = %$paired ? join(', ', sort keys %$paired) : 'none';
                push @per_script, $N->('script-unknown-dispatcher',
                    "scripts.conf entry '$name' names dispatcher '$w->{value}' in dispatchers=, which"
                    . " is not in the trusted map: it runs for that id once a dispatcher with it is paired.",
                    "pair it (sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER), or correct"
                    . " the id (paired: $known): sudoedit " . _q($allow_path));
            }
            else {
                push @per_script, $N->('script-unknown-option',
                    "scripts.conf entry '$name' has an unknown option '$w->{value}=', which is ignored.",
                    "correct or remove it on the '$name' line: sudoedit " . _q($allow_path));
            }
        }
    }
    # The ownership rule under script_ownership = warn (T-054): one note per
    # reason, naming the scripts it covers. The scripts run; strict would
    # refuse them. The fix is the operator's to make: it can stop whoever
    # writes there.
    for my $reason (sort keys %by_reason) {
        my @n = @{ $by_reason{$reason} };
        my $fix = ownership_fix($reason);
        $fix .= ', once nobody needs to write there (or leave it: the scripts run as they are)'
            if length $fix;
        push @f, $N->('script-ownership',
            "$reason: " . (@n == 1 ? "script '$n[0]' runs" : scalar(@n) . ' scripts run ('
            . join(', ', @n) . ')') . ' with a warning (script_ownership = warn); script_ownership'
            . ' = strict would refuse ' . (@n == 1 ? 'it' : 'them') . '.', $fix);
    }
    push @f, @per_script;

    if (my @p = Exec::Agent::Config::profiled_without_executor($config, $allowlist)) {
        push @f, $P->('profiles-not-applied', scalar(@p) . ' script(s) declare a profile, but'
            . ' executor_socket is not set, so the profile is not applied and they run as the agent'
            . ' user: ' . join(', ', @p) . '.',
            'set executor_socket = /run/ctrl-exec-agent/exec.sock in agent.conf (sudoedit '
            . _q($conf_path) . ') and run: sudo systemctl enable --now ctrl-exec-executor');
    }
    return @f;
}

sub _executor_checks ($config, $conf_path) {
    return () unless $config->{executor_socket};
    require Exec::Agent::ExecClient;
    my $problem = Exec::Agent::ExecClient::probe($config->{executor_socket});
    return () unless defined $problem;
    my ($why) = $problem =~ /\A(ctrl-exec-executor is not available \(.*?\))/;
    return Exec::Doctor::problem('executor',
        ($why // $problem) . ': executor_socket is set, so every run fails.',
        -d '/run/systemd/system' ? 'sudo systemctl start ctrl-exec-executor'
            : 'start ctrl-exec-executor, or comment out executor_socket in agent.conf');
}

sub _cert_and_trust_checks ($config, %o) {
    my @f;
    my $P = \&Exec::Doctor::problem;
    my $N = \&Exec::Doctor::note;
    my ($cert, $ca) = @$config{qw(cert ca)};

    for my $file ($config->{cert}, $config->{key}, $config->{ca}) {
        next if -e $file;
        return $N->('not-paired', "This agent is not paired ($file is missing): it does not start until it is.",
                    "sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER");
    }
    if (defined(my $p = Exec::Agent::Config::unreadable_path($cert, $ca))) {
        return $N->('access', "Could not read $p (permission denied): certificates and trust were not checked.",
                    'sudo ctrl-exec-agent doctor');
    }

    my $expiry = Exec::CertInfo::expiry_from_path($cert);
    my $days   = _days_left($expiry);
    if (defined $days && $days < 0) {
        push @f, $P->('agent-cert-expired', "This agent's certificate $cert expired on $expiry:"
            . ' no dispatcher can connect.',
            "re-pair: sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER --rekey");
    }

    my $port = $config->{port};
    if ($o{listening} && defined $port && !$o{listening}->($port)) {
        push @f, $N->('agent-not-running', "The agent is not running (nothing listens on port $port).",
                      $o{start_command} // 'sudo systemctl start ctrl-exec-agent');
    }

    push @f, trust_checks(
        map_path     => Exec::Agent::Config::trusted_dispatchers_path($config),
        ca_path      => $ca,
        cert_path    => $cert,
        revoked_path => Exec::Agent::Config::revoked_serials_path($config),
        cert_expiry  => $expiry,
    );
    return @f;
}

# The agent's trust state (T-061..T-064): the trusted-dispatcher map against the
# CA bundle and the agent's own certificate, and the revocation list. The map
# is read without the bundle, so this never rewrites it.
# Opts: map_path, ca_path, cert_path, revoked_path, cert_expiry.
sub trust_checks (%o) {
    my @f;
    my $P = \&Exec::Doctor::problem;
    my $N = \&Exec::Doctor::note;
    my ($map, $ca) = @o{qw(map_path ca_path)};
    if (defined(my $p = Exec::Agent::Config::unreadable_path($map))) {
        return $N->('access', "Could not read $p (permission denied): the trusted dispatchers were not checked.",
                    'sudo ctrl-exec-agent doctor');
    }

    my $trusted = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map);
    my @bundle  = Exec::Agent::AgentPairing::ca_bundle_fingerprints($ca);
    my %in_bundle = map { $_ => 1 } @bundle;
    my @legacy  = sort grep { !/ / } keys %$trusted;
    my %ids_under;    # CA fingerprint -> { id => 1 }
    for my $k (grep { / / } keys %$trusted) {
        my ($fpr) = split / /, $k;
        $ids_under{$fpr}{ $trusted->{$k} } = 1;
    }
    my %own = map { $_ => 1 } Exec::Agent::AgentPairing::agent_cert_issuers(
        cert_path => $o{cert_path}, ca_path => $ca);

    unless (@bundle) {
        push @f, $P->('ca-bundle', "$ca holds no readable CA certificate: the agent cannot verify any dispatcher.",
                      "re-pair: sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER --rekey");
    }

    if (@legacy) {
        my %ids = map { $trusted->{$_} => 1 } @legacy;
        push @f, $N->('trust-map-old-format', scalar(@legacy) . " trusted-map line(s) in $map are in the"
            . ' pre-0.14 form (<serial> <id>, dispatcher(s) ' . join(', ', sort keys %ids) . '),'
            . ' accepted under any CA in the bundle; the agent upgrades them to <ca-fingerprint>'
            . ' <serial> <id> when it starts.',
            'sudo ctrl-exec-agent doctor --fix (or restart the agent)',
            (@bundle ? (autofix => sub {
                Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map, ca_path => $ca);
                my $after = Exec::Agent::AgentPairing::load_trusted_dispatchers(path => $map);
                return (grep { !/ / } keys %$after) ? "$map could not be rewritten" : undef;
            }) : ()));
    }

    for my $fpr (sort keys %ids_under) {
        next if $in_bundle{$fpr};
        my @ids = sort keys %{ $ids_under{$fpr} };
        push @f, $P->('trust-ca-missing', 'Dispatcher(s) ' . join(', ', map { "'$_'" } @ids)
            . ' are trusted under CA ' . _fpr($fpr) . ", which is not in $ca: the TLS listener"
            . ' refuses their certificates.',
            "re-pair: sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER; or stop trusting: "
            . join('; ', map { "sudo ctrl-exec-agent remove-dispatcher $_" } @ids));
    }

    # A CA no entry is under (and that did not issue the agent's certificate):
    # nothing the agent serves needs it. Not judged while un-upgraded lines,
    # which match under every CA, remain; never the last CA in the bundle.
    unless (@legacy) {
        my @unused = grep { !$ids_under{$_} && !$own{$_} } @bundle;
        if (@unused && @unused < @bundle) {
            for my $fpr (@unused) {
                push @f, $N->('trust-ca-unused', 'CA ' . _fpr($fpr) . " in $ca is not used by any"
                    . " trusted dispatcher and did not issue this agent's certificate: a certificate"
                    . ' it signs completes the TLS handshake (and is then refused).',
                    'sudo ctrl-exec-agent doctor --fix (removes it from the bundle)',
                    autofix => sub {
                        my @gone = Exec::Agent::AgentPairing::remove_from_ca_bundle(
                            path => $ca, fprs => [ $fpr ]);
                        return @gone ? undef : "it is no longer in $ca";
                    });
            }
        }
    }

    if (!%$trusted) {
        push @f, $N->('trust-none', 'No dispatcher is trusted: the agent starts and answers, but refuses'
            . ' every caller.', "pair one: sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER");
    }
    elsif (!%own && @bundle) {
        push @f, $P->('agent-cert-issuer', "This agent's certificate $o{cert_path} was not issued by any"
            . " CA in $ca: self-ping fails and no dispatcher can renew it.",
            "re-key with a dispatcher: sudo ctrl-exec-agent request-pairing --dispatcher $DISPATCHER --rekey");
    }
    elsif (!@legacy && !grep { $ids_under{$_} } keys %own) {
        # T-064: the dispatcher that issued the certificate was removed.
        my $days = _days_left($o{cert_expiry});
        my $soon = !defined $days || $days < EXPIRY_PROBLEM_DAYS;
        push @f, ($soon ? $P : $N)->('agent-cert-issuer-untrusted', "This agent's certificate was"
            . ' issued by CA ' . join(', ', map { _fpr($_) } sort keys %own) . ', which no trusted'
            . ' dispatcher uses (its dispatcher was removed): no dispatcher can renew it, and it expires on '
            . ($o{cert_expiry} // 'an unknown date') . (defined $days ? " ($days days)" : '') . '.',
            "before then, re-key with a remaining dispatcher: sudo ctrl-exec-agent request-pairing"
            . " --dispatcher $DISPATCHER --rekey, restart the agent, then re-pair each other"
            . ' dispatcher without --rekey');
    }

    push @f, _revocation_checks($o{revoked_path}, scalar @bundle);
    return @f;
}

# A pre-0.14 revocation line names a serial alone and revokes it under every
# CA. That never loosens anything, and there is nothing to upgrade; it is
# worth a note only when the bundle holds several CAs, where it also refuses a
# certificate of that serial from another dispatcher's CA.
sub _revocation_checks ($path, $ncas) {
    return () unless defined $path && -f $path && $ncas > 1;
    if (defined(my $p = Exec::Agent::Config::unreadable_path($path))) {
        return Exec::Doctor::note('access', "Could not read $p (permission denied): revocations were not checked.",
                                  'sudo ctrl-exec-agent doctor');
    }
    my $revoked = Exec::Agent::AgentPairing::load_revoked_serials(path => $path);
    my @any = sort grep { !/ / } keys %$revoked;
    return () unless @any;
    return Exec::Doctor::note('revoked-any-ca', scalar(@any) . " line(s) in $path revoke a serial under"
        . ' every CA (' . join(', ', @any) . '; the pre-0.14 form): with ' . $ncas . ' dispatcher CAs'
        . ' trusted, a certificate with that serial from any of them is refused.',
        'to revoke under one CA only, write the line as <ca-fingerprint> <serial> (fingerprints:'
        . ' sudo ctrl-exec-agent list-dispatchers): sudoedit ' . _q($path));
}

1;
