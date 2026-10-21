package Exec::Rotation;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON        qw(encode_json decode_json);
use POSIX       qw(strftime);
use Carp        qw(croak);
use Exec::CertInfo qw();
use Exec::FileUtil qw(slurp);

use Exec::CA       qw();
use Exec::Registry qw();
use Exec::Engine   qw();
use Exec::Pairing  qw();
use Exec::Log      qw();
use Exec::DispatcherConfig qw();


my $ROTATION_FILE  = '/var/lib/ctrl-exec/rotation.json';
sub _default_ca_dir () { return Exec::DispatcherConfig::conf_dir() }

# Default configuration values - overridden by ctrl-exec.conf
my $DEFAULT_CERT_DAYS       = 825;   # dispatcher cert lifetime (matches CA.pm default)
my $DEFAULT_RENEWAL_DAYS    = 90;    # renew when this many days remain
my $DEFAULT_OVERLAP_DAYS    = 30;    # keep old serial trusted this long after rotation
my $DEFAULT_CHECK_INTERVAL  = 14400; # seconds between internal expiry checks (4 hours)


# Check whether the dispatcher cert needs renewal and rotate if so.
# Called on startup and periodically by the internal check loop.
#
# Required opts:
#   config => \%config
#
# Returns:
#   { rotated => 0 }                         - no action needed
#   { rotated => 1, serial => $hex, ... }    - rotation performed
#   { rotated => 0, error => $str }          - check failed non-fatally
sub check_and_rotate (%opts) {
    my $config = $opts{config} or croak "config required";

    my $renewal_days = $config->{cert_renewal_days} // $DEFAULT_RENEWAL_DAYS;
    my $ca_dir       = $config->{ca_dir}            // _default_ca_dir();
    # The cert this dispatcher serves with (ctrl-exec.conf 'cert') is the single
    # source of truth - never a hardcoded name.
    my $disp_crt     = $config->{cert}
        or return { rotated => 0, error => "no 'cert' configured" };

    unless (-f $disp_crt) {
        return { rotated => 0, error => "dispatcher cert not found at $disp_crt" };
    }

    my $days_left = _cert_days_remaining($disp_crt);
    unless (defined $days_left) {
        return { rotated => 0, error => "cannot read cert expiry from $disp_crt" };
    }

    Exec::Log::log_action('INFO', {
        ACTION    => 'cert-check',
        DAYS_LEFT => $days_left,
        THRESHOLD => $renewal_days,
    });

    if ($days_left > $renewal_days) {
        return { rotated => 0, days_left => $days_left };
    }

    # Within renewal window - rotate
    Exec::Log::log_action('INFO', {
        ACTION    => 'cert-renewal-start',
        DAYS_LEFT => $days_left,
    });

    return _do_rotation(config => $config);
}

# Perform rotation unconditionally - called by 'ctrl-exec-dispatcher rotate-cert'
# and by check_and_rotate when the threshold is reached.
#
# Required opts:
#   config => \%config
sub rotate (%opts) {
    my $config = $opts{config} or croak "config required";
    return _do_rotation(config => $config);
}

# Return the current rotation state, or undef if no rotation has occurred.
sub load_state (%opts) {
    my $path = $opts{path} // $ROTATION_FILE;
    return unless -f $path;
    my $data = eval { decode_json(slurp($path)) };
    if ($@) {
        Exec::Log::log_action('ERR', {
            ACTION => 'rotation-state-corrupt',
            PATH   => $path,
            ERROR  => $@,
            REASON => 'JSON parse failed - rotation state unreadable',
        });
        return;
    }
    return $data;
}

# Mark any pending agents whose overlap window has expired as stale.
# Called on startup and after each broadcast attempt.
sub expire_stale_agents (%opts) {
    my $config = $opts{config} or croak "config required";

    my $state = load_state(path => $config->{rotation_file});
    return unless $state && $state->{overlap_expires};

    my $now     = time();
    my $expires = _parse_iso8601($state->{overlap_expires});
    return unless defined $expires && $now > $expires;

    my $agents = Exec::Registry::list_agents(
        registry_dir => $config->{registry_dir},
    );
    my @stale = grep { ($_->{serial_status} // '') eq 'pending' } @$agents;
    Exec::Registry::update_serials_bulk(
        [ map { { hostname => $_->{hostname}, status => 'stale' } } @stale ],
        registry_dir => $config->{registry_dir},
    );
    for my $agent (@stale) {
        Exec::Log::log_action('WARNING', {
            ACTION   => 'serial-stale',
            AGENT    => $agent->{hostname},
            REASON   => 'overlap window expired without confirmation',
        });
    }
}

# Broadcast the current dispatcher serial to all pending agents, then finish a
# staged rotation (install the new certificate) if one is waiting.
# Calls each agent's built-in /rotate-serial control-plane op (Engine::rotate_all)
# to ADD the new serial. Updates registry on success. Reports results.
#
# The broadcast is authenticated with the certificate the agents already trust:
# the previous one (kept as '<cert>.prev' / '<key>.prev' from the rotation until
# the old serial is retired), never the new one, whose serial no pending agent
# trusts yet. An agent accepts a serial only from a caller whose own serial it
# already trusts (Exec::Agent::Server::handle_rotate_serial); this side meets
# that check, it does not get around it. Each agent is contacted at its
# registered address and port (Exec::Registry::resolve_target).
#
# Required opts:
#   config => \%config
#
# Returns arrayref of { hostname, status => 'ok'|'failed', error? }
sub broadcast_serial (%opts) {
    my $config = $opts{config} or croak "config required";

    my $state = load_state(path => $config->{rotation_file});
    unless ($state && $state->{current_serial}) {
        return [];
    }

    if ($state->{staged} && !_staged_usable($config, $state)) {
        # The staged certificate is gone and was never installed: its serial
        # can never be presented, so it is not broadcast. rotate-cert (or the
        # automatic rotation near expiry) starts a new rotation.
        Exec::Log::log_action('ERR', {
            ACTION => 'cert-switch-fail',
            SERIAL => $state->{current_serial},
            ERROR  => "staged certificate $config->{cert}.next is missing or not the"
                    . " staged serial - run 'ctrl-exec-dispatcher rotate-cert'",
        });
        return [];
    }

    my $report = _broadcast($config, $state);

    # Install the new certificate once the round has run. Agents that confirmed
    # trust both serials now; the rest stay 'pending' and are retried with the
    # previous certificate until the overlap window closes.
    _switch($config, $state) if $state->{staged};

    return $report;
}

sub _broadcast ($config, $state) {
    my $serial  = $state->{current_serial};
    # The agent maps the broadcast serial to this dispatcher's stable identity,
    # so a rotated serial lands under the same identity it was paired with -
    # trust and attribution carry over without re-pairing.
    my $dispatcher_id = Exec::Pairing::resolve_dispatcher_id($config);
    my $agents  = Exec::Registry::list_agents(
        registry_dir => $config->{registry_dir},
    );
    my @pending = grep {
        my $s = $_->{serial_status} // 'unknown';
        $s eq 'pending' || $s eq 'unknown'
    } @$agents;

    return [] unless @pending;

    my @hostnames = map { $_->{hostname} } @pending;
    my $creds     = _broadcast_config($config, $state);

    Exec::Log::log_action('INFO', {
        ACTION     => 'serial-broadcast',
        HOSTS      => join(',', @hostnames),
        SERIAL     => $serial,
        DISPATCHER => $dispatcher_id,
        CERT       => $creds->{cert},
    });

    # Tell each pending agent to ADD the new serial via the built-in
    # /rotate-serial control-plane operation (no script, works with or without
    # the executor). The agent maps it to THIS dispatcher's identity, derived
    # from our authenticated (previous) serial - we do not send the id.
    # retire_previous_serial removes the old one after the overlap window.
    my $results = eval {
        Exec::Engine::rotate_all(
            hosts  => _targets($config, \@hostnames),
            serial => $serial,
            action => 'add',
            config => $creds,
        );
    };
    if ($@) {
        Exec::Log::log_action('ERR', {
            ACTION => 'serial-broadcast-error',
            ERROR  => $@,
        });
        return [];
    }

    my @report;
    my @confirmed;
    my $confirmed_at = _now_iso8601();
    for my $r (@$results) {
        my $host = $r->{host};
        if (($r->{exit} // -1) == 0) {
            push @confirmed, {
                hostname         => $host,
                status           => 'current',
                serial           => $serial,
                serial_confirmed => $confirmed_at,
            };
            push @report, { hostname => $host, status => 'ok' };
            Exec::Log::log_action('INFO', {
                ACTION => 'serial-confirmed',
                AGENT  => $host,
            });
        }
        else {
            my $err = $r->{error} // "exit ${\($r->{exit} // -1)}";
            push @report, { hostname => $host, status => 'failed', error => $err };
            Exec::Log::log_action('WARNING', {
                ACTION => 'serial-broadcast-fail',
                AGENT  => $host,
                ERROR  => $err,
            });
        }
    }

    # Persist every confirmation under one registry lock.
    Exec::Registry::update_serials_bulk(
        \@confirmed, registry_dir => $config->{registry_dir});

    return \@report;
}

# Retire the previous (pre-rotation) dispatcher serial once the overlap window
# has elapsed - the "remove" half of add-then-remove rotation. Removes the old
# serial from the trusted-dispatcher map of every agent that has adopted the new
# one (serial_status 'current'), so the retired cert is no longer trusted. Agents
# still 'pending' never received the new serial and keep the old one untouched.
# Idempotent: clears previous_serial from the rotation state after one attempt so
# it does not repeat. No-op until a rotation's overlap window has passed.
#
# Required opts:
#   config => \%config
sub retire_previous_serial (%opts) {
    my $config = $opts{config} or croak "config required";

    my $state = load_state(path => $config->{rotation_file});
    return unless $state
              && defined $state->{previous_serial}
              && length $state->{previous_serial};

    # A staged rotation has not installed its new certificate: the dispatcher
    # still presents the previous serial, and removing it would cut every agent
    # off. The switch (broadcast_serial) comes first.
    return if $state->{staged};

    my $expires = _parse_iso8601($state->{overlap_expires} // '');
    return unless defined $expires && time() > $expires;

    my $old = $state->{previous_serial};

    # A serial replaced by a rotation made inside the last one's overlap window
    # (see _stage) goes with it.
    my @old = ($old, grep { defined && length } @{ $state->{superseded_serials} // [] });

    # Never retire the serial this dispatcher presents (a state file that does
    # not match the served certificate, e.g. restored from a backup).
    my $served = ($config->{cert} && _read_cert_serial($config->{cert})) // '';
    if (grep { $_ eq $served } @old) {
        Exec::Log::log_action('ERR', {
            ACTION => 'serial-retire-error',
            SERIAL => $served,
            ERROR  => "the served certificate $config->{cert} still has the serial to retire",
        });
        return;
    }

    my $agents  = Exec::Registry::list_agents(registry_dir => $config->{registry_dir});
    my @current = grep { ($_->{serial_status} // '') eq 'current' } @$agents;

    if (@current) {
        my @hostnames = map { $_->{hostname} } @current;
        for my $serial (@old) {
            Exec::Log::log_action('INFO', {
                ACTION => 'serial-retire',
                HOSTS  => join(',', @hostnames),
                SERIAL => $serial,
            });
            eval {
                Exec::Engine::rotate_all(
                    hosts  => _targets($config, \@hostnames),
                    serial => $serial,
                    action => 'remove',
                    config => $config,
                );
            };
            Exec::Log::log_action('WARNING', { ACTION => 'serial-retire-error', ERROR => $@ })
                if $@;
        }
    }

    # Mark the previous serial retired (drop it, stamp when) so this runs once.
    # Preserve the rest of the rotation state.
    my %retired = %$state;
    delete $retired{previous_serial};
    delete $retired{superseded_serials};
    $retired{previous_retired} = _now_iso8601();
    _write_atomic($config->{rotation_file} // $ROTATION_FILE, encode_json(\%retired));

    # The previous certificate and key served only to broadcast to agents that
    # still trusted nothing newer; with the old serial retired they go.
    if ($config->{cert} && $config->{key}) {
        unlink "$config->{cert}.prev", "$config->{key}.prev";
    }

    return scalar @current;
}

# Run the internal renewal check loop. Blocks indefinitely.
# Called from the ctrl-exec serve loop in a separate process or thread.
# In practice called via a forked child in bin/ctrl-exec-dispatcher.
#
# Required opts:
#   config => \%config
sub run_check_loop (%opts) {
    my $config   = $opts{config} or croak "config required";
    my $interval = $config->{cert_check_interval} // $DEFAULT_CHECK_INTERVAL;

    while (1) {
        sleep $interval;

        eval { expire_stale_agents(config => $config) };
        Exec::Log::log_action('WARNING', { ACTION => 'expire-stale-error', ERROR => $@ })
            if $@;

        # Remove the previous serial from agents that adopted the new one, once
        # the overlap window has passed (add-then-remove rotation).
        eval { retire_previous_serial(config => $config) };
        Exec::Log::log_action('WARNING', { ACTION => 'serial-retire-loop-error', ERROR => $@ })
            if $@;

        my $result = eval { check_and_rotate(config => $config) };
        if ($@) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'cert-check-error',
                ERROR  => $@,
            });
            next;
        }

        if ($result->{rotated}) {
            # The rotation broadcast the new serial and installed the new
            # certificate itself (_do_rotation).
        }
        elsif ($result->{error}) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'cert-check-warn',
                ERROR  => $result->{error},
            });
        }
        else {
            # No rotation needed - retry any pending agents on each check, and
            # finish a staged rotation that was interrupted.
            my $agents   = Exec::Registry::list_agents(
                registry_dir => $config->{registry_dir},
            );
            my @pending  = grep { ($_->{serial_status} // '') eq 'pending' } @$agents;
            my $state    = load_state(path => $config->{rotation_file});
            if (@pending || ($state && $state->{staged})) {
                eval { broadcast_serial(config => $config) };
                Exec::Log::log_action('WARNING', { ACTION => 'broadcast-retry-error', ERROR => $@ })
                    if $@;
            }
        }
    }
}

# --- private ---

# A rotation runs in three steps, so that the broadcast is authenticated with a
# certificate the agents already trust:
#
#   1. stage   - the new key and certificate are written to '<key>.next' and
#                '<cert>.next'; the served pair is copied to '<key>.prev' and
#                '<cert>.prev'; rotation.json records both serials with
#                staged => 1; every agent is marked 'pending'. Nothing served
#                has changed yet.
#   2. broadcast - each pending agent is told to ADD the new serial, over mTLS
#                with the previous certificate (broadcast_serial).
#   3. switch  - '<key>.next' and '<cert>.next' are renamed over the served
#                pair, and staged is dropped from rotation.json.
#
# A crash at any point leaves a state the next run finishes: before the state
# file says staged, nothing served changed and a new rotation starts afresh;
# after it, broadcast_serial (run by maintain, the check loop and the pairing
# listener's startup) or rotate-cert broadcasts again (adding a serial an agent
# already has is a no-op) and renames whichever '.next' file is still there.
# Agents that missed the broadcast are retried with the previous certificate
# until the overlap window closes; retire_previous_serial then removes the old
# serial from the agents that confirmed and deletes the '.prev' pair.
sub _do_rotation (%opts) {
    my $config = $opts{config};
    $config->{cert} or return { rotated => 0, error => "no 'cert' configured" };
    $config->{key}  or return { rotated => 0, error => "no 'key' configured" };

    # An interrupted rotation is finished, not replaced: its new serial may
    # already be in some agents' maps.
    my $state = load_state(path => $config->{rotation_file});
    my $resumed = 0;
    if ($state && $state->{staged} && _staged_usable($config, $state)) {
        $resumed = 1;
        Exec::Log::log_action('INFO', {
            ACTION     => 'cert-rotation-resume',
            NEW_SERIAL => $state->{current_serial},
        });
    }
    else {
        my $staged = _stage($config);
        return $staged if $staged->{error};
        $state = load_state(path => $config->{rotation_file});
    }

    my $pending = grep {
        my $s = $_->{serial_status} // 'unknown';
        $s eq 'pending' || $s eq 'unknown'
    } @{ Exec::Registry::list_agents(registry_dir => $config->{registry_dir}) };

    my $report = broadcast_serial(config => $config);

    my $after = load_state(path => $config->{rotation_file}) // {};
    if ($after->{staged}) {
        return { rotated => 0, error => "the new certificate (serial $state->{current_serial})"
            . " is staged but not installed - see the ctrl-exec log (ACTION=cert-switch-fail);"
            . " the next maintenance run retries" };
    }

    return {
        rotated          => 1,
        resumed          => $resumed,
        serial           => $state->{current_serial},
        old_serial       => $state->{previous_serial} // '',
        overlap_expires  => $state->{overlap_expires},
        agents_pending   => $pending,   # the agents the broadcast was sent to
        broadcast        => $report,
    };
}

# Step 1 of a rotation (see above). Returns { staged => 1 } or { error => ... }.
sub _stage ($config) {
    my $ca_dir       = $config->{ca_dir}            // _default_ca_dir();
    my $cert_days    = $config->{cert_days}         // $DEFAULT_CERT_DAYS;
    my $overlap_days = $config->{cert_overlap_days} // $DEFAULT_OVERLAP_DAYS;
    # Re-key the cert this dispatcher actually serves with (ctrl-exec.conf
    # 'cert'/'key'), so the new serial is the one agents will see on connect.
    my ($disp_crt, $disp_key) = @$config{qw(cert key)};
    my %p = _paths($config);

    my $old_serial = -f $disp_crt ? (_read_cert_serial($disp_crt) // '') : '';

    unlink $p{next_crt}, $p{next_key};
    my $new_serial = eval {
        Exec::CA::generate_dispatcher_cert(
            ca_dir    => $ca_dir,
            cert      => $p{next_crt},
            key       => $p{next_key},
            days      => $cert_days,
            force     => 1,
            key_owner => $config->{service_user} // 'ctrl-exec',
        );
        _read_cert_serial($p{next_crt})
            // die "cannot read the new certificate's serial from $p{next_crt}\n";
    };
    unless (defined $new_serial) {
        my $err = $@ || 'unknown error';
        unlink $p{next_crt}, $p{next_key};
        Exec::Log::log_action('ERR', {
            ACTION => 'cert-rotation-fail',
            ERROR  => $err,
        });
        return { error => "cert generation failed: $err" };
    }

    # Keep the served pair: the broadcast authenticates with it. Except when
    # the last rotation is still in its overlap window with agents that have
    # not taken its serial: they trust only the pair kept from it, so that pair
    # stays, and authenticates this broadcast too (every agent that took the
    # last serial still trusts the one before it). The serial being replaced
    # is then retired with it.
    my $prev_serial = $old_serial;
    my @superseded;
    if (my $last = _prev_still_needed($config)) {
        $prev_serial = $last->{previous_serial};
        @superseded  = (@{ $last->{superseded_serials} // [] }, $old_serial);
    }
    elsif (length $old_serial && -f $disp_key) {
        my $ok = eval {
            _copy_keeping_mode($disp_key, $p{prev_key});
            _copy_keeping_mode($disp_crt, $p{prev_crt});
            1;
        };
        unless ($ok) {
            my $err = $@;
            unlink $p{next_crt}, $p{next_key};
            Exec::Log::log_action('ERR', { ACTION => 'cert-rotation-fail', ERROR => $err });
            return { error => "cannot keep the current certificate for the broadcast: $err" };
        }
    }

    my $now          = _now_iso8601();
    my $overlap_exp  = strftime('%Y-%m-%dT%H:%M:%SZ',
                          gmtime(time() + $overlap_days * 86400));

    # From here on the rotation is recorded: a crash is finished by the next
    # broadcast_serial (see above).
    _write_atomic($config->{rotation_file} // $ROTATION_FILE, encode_json({
        current_serial   => $new_serial,
        previous_serial  => $prev_serial,
        (@superseded ? (superseded_serials => \@superseded) : ()),
        rotated_at       => $now,
        overlap_expires  => $overlap_exp,
        overlap_days     => $overlap_days,
        staged           => 1,
    }));

    # Mark all agents as pending - they need to receive the new serial.
    # Rotation is seamless (no re-pair) via add-then-remove against the agent's
    # trusted-dispatcher map: broadcast_serial ADDS the new serial to each agent
    # (mapped to this dispatcher's stable identity) while the old serial stays
    # trusted through the overlap window. retire_previous_serial REMOVES the old
    # serial from confirmed agents once the overlap window passes. The overlap
    # window therefore bounds how long both serials are trusted, and how long
    # the dispatcher keeps retrying (with the previous certificate) before
    # declaring an agent (one offline throughout) stale; a stale agent missed
    # the rotation and must be re-paired. All endpoints (/run, /ping, /result,
    # /capabilities) gate on the map, so a confirmed agent never sees a gap.
    my $agents = Exec::Registry::list_agents(
        registry_dir => $config->{registry_dir},
    );
    # One lock acquisition for the whole fleet, not one per agent.
    Exec::Registry::update_serials_bulk(
        [ map { {
            hostname         => $_->{hostname},
            status           => 'pending',
            serial_broadcast => $now,
        } } @$agents ],
        registry_dir => $config->{registry_dir},
    );

    Exec::Log::log_action('INFO', {
        ACTION          => 'cert-rotated',
        OLD_SERIAL      => $old_serial,
        NEW_SERIAL      => $new_serial,
        (@superseded ? (KEPT_PREVIOUS => $prev_serial) : ()),
        OVERLAP_EXPIRES => $overlap_exp,
        AGENTS          => scalar @$agents,
    });
    return { staged => 1 };
}

# Step 3 of a rotation: install the staged pair. Each rename is atomic and
# renames only what is still there, so running it again after a crash between
# the two finishes the job. Returns 1 when the served certificate has the new
# serial and the state says so; logs and returns 0 otherwise.
sub _switch ($config, $state) {
    my %p = _paths($config);
    my $ok = eval {
        _install($p{next_key}, $config->{key})  if -e $p{next_key};
        _install($p{next_crt}, $config->{cert}) if -e $p{next_crt};
        my $live = _read_cert_serial($config->{cert}) // '';
        die "the served certificate $config->{cert} has serial '$live', not the staged"
          . " $state->{current_serial}\n" unless $live eq $state->{current_serial};
        my %switched = %$state;
        delete $switched{staged};
        $switched{switched_at} = _now_iso8601();
        _write_atomic($config->{rotation_file} // $ROTATION_FILE, encode_json(\%switched));
        1;
    };
    unless ($ok) {
        my $err = $@ || 'unknown error'; chomp $err;
        Exec::Log::log_action('ERR', {
            ACTION => 'cert-switch-fail',
            SERIAL => $state->{current_serial},
            ERROR  => $err,
        });
        return 0;
    }
    # Long-running processes pick the new pair up without a restart: every
    # outbound mTLS connection (Engine::_build_ua) loads the files named in
    # ctrl-exec.conf when it is made.
    Exec::Log::log_action('INFO', {
        ACTION     => 'cert-switch',
        NEW_SERIAL => $state->{current_serial},
        CERT       => $config->{cert},
    });
    return 1;
}

# The staged rotation in $state can still be finished: its new certificate is
# either waiting at '<cert>.next' or already served.
sub _staged_usable ($config, $state) {
    return 0 unless defined $config->{cert} && defined $config->{key};
    my %p = _paths($config);
    my $want = $state->{current_serial} // return 0;
    for my $c ($p{next_crt}, $config->{cert}) {
        return 1 if -f $c && (_read_cert_serial($c) // '') eq $want;
    }
    return 0;
}

# The state of the last rotation when its kept previous pair is still needed:
# its overlap window is open, some agent is still 'pending', and the kept
# certificate is the previous serial's. Else undef.
sub _prev_still_needed ($config) {
    my $state = load_state(path => $config->{rotation_file}) or return;
    return if $state->{staged};
    my $prev = $state->{previous_serial} // '';
    return unless length $prev;
    my $expires = _parse_iso8601($state->{overlap_expires} // '');
    return unless defined $expires && time() <= $expires;
    my $agents = Exec::Registry::list_agents(registry_dir => $config->{registry_dir});
    return unless grep { ($_->{serial_status} // '') eq 'pending' } @$agents;
    my %p = _paths($config);
    return unless -f $p{prev_key} && (_read_cert_serial($p{prev_crt}) // '') eq $prev;
    return $state;
}

# The config to broadcast with: the previous certificate and key when they are
# still kept and are the previous serial's, else the served pair (a rotation
# made before the previous pair was kept, or the first certificate).
sub _broadcast_config ($config, $state) {
    return $config unless defined $config->{cert} && defined $config->{key};
    my %p    = _paths($config);
    my $prev = $state->{previous_serial} // '';
    if (length $prev && -f $p{prev_crt} && -f $p{prev_key}
        && (_read_cert_serial($p{prev_crt}) // '') eq $prev) {
        return { %$config, cert => $p{prev_crt}, key => $p{prev_key} };
    }
    return $config;
}

sub _paths ($config) {
    my ($crt, $key) = @$config{qw(cert key)};
    return (next_crt => "$crt.next", next_key => "$key.next",
            prev_crt => "$crt.prev", prev_key => "$key.prev");
}

# Registry names to { name, target } entries: each agent's registered address
# and port, as every other dispatch path uses (a plain name would be contacted
# on 7443 by name, ignoring lookup_by and port).
sub _targets ($config, $names) {
    return [ map { {
        name   => $_,
        target => Exec::Registry::resolve_target(
            hostname => $_, registry_dir => $config->{registry_dir}),
    } } @$names ];
}

# Move $from over $to. A rename, unless $to cannot be replaced (a file bind
# mount): then its content is overwritten in place, which keeps its owner and
# mode.
sub _install ($from, $to) {
    return if rename $from, $to;
    require File::Copy;
    File::Copy::copy($from, $to) or die "cannot install $from as $to: $!\n";
    unlink $from;
}

# Copy $from to $to with $from's mode and owner (a key stays 0600 and owned by
# the service user), written to a temporary name and renamed into place.
sub _copy_keeping_mode ($from, $to) {
    require File::Copy;
    my @st  = stat $from or die "cannot stat $from: $!\n";
    my $tmp = "$to.tmp$$";
    unlink $tmp;
    my $old_umask = umask 0077;
    my $ok = File::Copy::copy($from, $tmp);
    umask $old_umask;
    $ok or do { unlink $tmp; die "cannot copy $from to $tmp: $!\n" };
    chown $st[4], $st[5], $tmp;   # best effort: only root can give a file away
    chmod $st[2] & 07777, $tmp;
    rename $tmp, $to or do { unlink $tmp; die "cannot rename $tmp to $to: $!\n" };
}

sub _read_cert_serial ($cert_path) {
    return Exec::CertInfo::serial_from_path($cert_path);
}

sub _cert_days_remaining ($cert_path) {
    my $expiry = Exec::CertInfo::expiry_epoch(
        Exec::CertInfo::expiry_from_path($cert_path));
    return unless defined $expiry;
    return int(($expiry - time()) / 86400);
}

sub _parse_iso8601 ($str) {
    return unless defined $str;
    if ($str =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/) {
        require Time::Local;
        return Time::Local::timegm($6, $5, $4, $3, $2 - 1, $1 - 1900);
    }
    return;
}

sub _now_iso8601 () {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
}

sub _write_atomic ($path, $content) {
    return Exec::FileUtil::write_atomic($path, $content, mode => 0640);
}

1;
