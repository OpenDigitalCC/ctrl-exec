package Exec::Rotation;

use strict;
use warnings;
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


my $ROTATION_FILE  = '/var/lib/ctrl-exec/rotation.json';
my $CA_DIR         = '/etc/ctrl-exec';

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
sub check_and_rotate {
    my (%opts) = @_;
    my $config = $opts{config} or croak "config required";

    my $renewal_days = $config->{cert_renewal_days} // $DEFAULT_RENEWAL_DAYS;
    my $ca_dir       = $config->{ca_dir}            // $CA_DIR;
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
sub rotate {
    my (%opts) = @_;
    my $config = $opts{config} or croak "config required";
    return _do_rotation(config => $config);
}

# Return the current rotation state, or undef if no rotation has occurred.
sub load_state {
    my (%opts) = @_;
    my $path = $opts{path} // $ROTATION_FILE;
    return undef unless -f $path;
    my $data = eval { decode_json(slurp($path)) };
    if ($@) {
        Exec::Log::log_action('ERR', {
            ACTION => 'rotation-state-corrupt',
            PATH   => $path,
            ERROR  => $@,
            REASON => 'JSON parse failed - rotation state unreadable',
        });
        return undef;
    }
    return $data;
}

# Mark any pending agents whose overlap window has expired as stale.
# Called on startup and after each broadcast attempt.
sub expire_stale_agents {
    my (%opts) = @_;
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

# Broadcast the current dispatcher serial to all pending agents.
# Calls each agent's built-in /rotate-serial control-plane op (Engine::rotate_all)
# to ADD the new serial. Updates registry on success. Reports results.
#
# Required opts:
#   config => \%config
#
# Returns arrayref of { hostname, status => 'ok'|'failed', error? }
sub broadcast_serial {
    my (%opts) = @_;
    my $config = $opts{config} or croak "config required";

    my $state = load_state(path => $config->{rotation_file});
    unless ($state && $state->{current_serial}) {
        return [];
    }

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

    Exec::Log::log_action('INFO', {
        ACTION     => 'serial-broadcast',
        HOSTS      => join(',', @hostnames),
        SERIAL     => $serial,
        DISPATCHER => $dispatcher_id,
    });

    # Tell each pending agent to ADD the new serial via the built-in
    # /rotate-serial control-plane operation (no script, works with or without
    # the executor). The agent maps it to THIS dispatcher's identity, derived
    # from our authenticated (still-current) serial - we do not send the id.
    # retire_previous_serial removes the old one after the overlap window.
    my $results = eval {
        Exec::Engine::rotate_all(
            hosts  => \@hostnames,
            serial => $serial,
            action => 'add',
            config => $config,
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
sub retire_previous_serial {
    my (%opts) = @_;
    my $config = $opts{config} or croak "config required";

    my $state = load_state(path => $config->{rotation_file});
    return unless $state
              && defined $state->{previous_serial}
              && length $state->{previous_serial};

    my $expires = _parse_iso8601($state->{overlap_expires} // '');
    return unless defined $expires && time() > $expires;

    my $old = $state->{previous_serial};

    my $agents  = Exec::Registry::list_agents(registry_dir => $config->{registry_dir});
    my @current = grep { ($_->{serial_status} // '') eq 'current' } @$agents;

    if (@current) {
        my @hostnames = map { $_->{hostname} } @current;
        Exec::Log::log_action('INFO', {
            ACTION => 'serial-retire',
            HOSTS  => join(',', @hostnames),
            SERIAL => $old,
        });
        eval {
            Exec::Engine::rotate_all(
                hosts  => \@hostnames,
                serial => $old,
                action => 'remove',
                config => $config,
            );
        };
        Exec::Log::log_action('WARNING', { ACTION => 'serial-retire-error', ERROR => $@ })
            if $@;
    }

    # Mark the previous serial retired (drop it, stamp when) so this runs once.
    # Preserve the rest of the rotation state.
    my %retired = %$state;
    delete $retired{previous_serial};
    $retired{previous_retired} = _now_iso8601();
    _write_atomic($config->{rotation_file} // $ROTATION_FILE, encode_json(\%retired));

    return scalar @current;
}

# Run the internal renewal check loop. Blocks indefinitely.
# Called from the ctrl-exec serve loop in a separate process or thread.
# In practice called via a forked child in bin/ctrl-exec-dispatcher.
#
# Required opts:
#   config => \%config
sub run_check_loop {
    my (%opts) = @_;
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
            # Broadcast immediately after rotation
            eval { broadcast_serial(config => $config) };
            Exec::Log::log_action('WARNING', { ACTION => 'broadcast-error', ERROR => $@ })
                if $@;
        }
        elsif ($result->{error}) {
            Exec::Log::log_action('WARNING', {
                ACTION => 'cert-check-warn',
                ERROR  => $result->{error},
            });
        }
        else {
            # No rotation needed - retry any pending agents on each check
            my $agents   = Exec::Registry::list_agents(
                registry_dir => $config->{registry_dir},
            );
            my @pending  = grep { ($_->{serial_status} // '') eq 'pending' } @$agents;
            if (@pending) {
                eval { broadcast_serial(config => $config) };
                Exec::Log::log_action('WARNING', { ACTION => 'broadcast-retry-error', ERROR => $@ })
                    if $@;
            }
        }
    }
}

# --- private ---

sub _do_rotation {
    my (%opts) = @_;
    my $config      = $opts{config};
    my $ca_dir      = $config->{ca_dir}         // $CA_DIR;
    my $cert_days   = $config->{cert_days}       // $DEFAULT_CERT_DAYS;
    my $overlap_days = $config->{cert_overlap_days} // $DEFAULT_OVERLAP_DAYS;
    # Re-key the cert this dispatcher actually serves with (ctrl-exec.conf
    # 'cert'/'key'), so the new serial is the one agents will see on connect.
    my $disp_crt    = $config->{cert}
        or return { rotated => 0, error => "no 'cert' configured" };
    my $disp_key    = $config->{key}
        or return { rotated => 0, error => "no 'key' configured" };

    # Read old serial before overwriting
    my $old_serial = '';
    if (-f $disp_crt) {
        $old_serial = _read_cert_serial($disp_crt) // '';
    }

    # Generate new cert - force overwrites existing key and cert files.
    # Note: the running ctrl-exec process holds the old key/cert in memory
    # for active mTLS connections. It will use the new files on next restart.
    # In normal operation this is acceptable - the ctrl-exec binary is
    # typically short-lived (CLI invocations). For long-running pairing-mode
    # processes, schedule a restart after the broadcast confirms all agents
    # have received the new serial.
    eval {
        Exec::CA::generate_dispatcher_cert(
            ca_dir    => $ca_dir,
            cert      => $disp_crt,
            key       => $disp_key,
            days      => $cert_days,
            force     => 1,
            key_owner => $config->{service_user} // 'ctrl-exec',
        );
    };
    if ($@) {
        Exec::Log::log_action('ERR', {
            ACTION => 'cert-rotation-fail',
            ERROR  => $@,
        });
        return { rotated => 0, error => "cert generation failed: $@" };
    }

    my $new_serial = _read_cert_serial($disp_crt);
    unless (defined $new_serial) {
        return { rotated => 0, error => "cannot read new cert serial after rotation" };
    }

    my $now          = _now_iso8601();
    my $overlap_secs = $overlap_days * 86400;
    my $overlap_exp  = strftime('%Y-%m-%dT%H:%M:%SZ',
                          gmtime(time() + $overlap_secs));

    # Persist rotation state
    my $rotation_file = $config->{rotation_file} // $ROTATION_FILE;
    _write_atomic($rotation_file, encode_json({
        current_serial   => $new_serial,
        previous_serial  => $old_serial,
        rotated_at       => $now,
        overlap_expires  => $overlap_exp,
        overlap_days     => $overlap_days,
    }));

    # Mark all agents as pending - they need to receive the new serial.
    # Rotation is seamless (no re-pair) via add-then-remove against the agent's
    # trusted-dispatcher map: broadcast_serial ADDS the new serial to each agent
    # (mapped to this dispatcher's stable identity) while the old serial stays
    # trusted through the overlap window, so the dispatcher's live cert - old
    # before restart, new after - is accepted throughout. retire_previous_serial
    # REMOVES the old serial from confirmed agents once the overlap window
    # passes. The overlap window therefore bounds how long both serials are
    # trusted, and how long the ctrl-exec keeps retrying before declaring an
    # agent (one offline during the broadcast) stale; a stale agent missed the
    # rotation and must be re-paired. All endpoints (/run, /ping, /result,
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
        OVERLAP_EXPIRES => $overlap_exp,
        AGENTS          => scalar @$agents,
    });

    return {
        rotated          => 1,
        serial           => $new_serial,
        old_serial       => $old_serial,
        overlap_expires  => $overlap_exp,
        agents_pending   => scalar @$agents,
    };
}

sub _read_cert_serial {
    my ($cert_path) = @_;
    return Exec::CertInfo::serial_from_path($cert_path);
}

sub _cert_days_remaining {
    my ($cert_path) = @_;
    my $expiry = Exec::CertInfo::expiry_epoch(
        Exec::CertInfo::expiry_from_path($cert_path));
    return unless defined $expiry;
    return int(($expiry - time()) / 86400);
}

sub _parse_iso8601 {
    my ($str) = @_;
    return unless defined $str;
    if ($str =~ /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/) {
        require Time::Local;
        return Time::Local::timegm($6, $5, $4, $3, $2 - 1, $1 - 1900);
    }
    return;
}

sub _now_iso8601 {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
}

sub _write_atomic {
    my ($path, $content) = @_;
    return Exec::FileUtil::write_atomic($path, $content, mode => 0640);
}

1;
