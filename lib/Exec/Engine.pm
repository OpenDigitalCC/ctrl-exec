package Exec::Engine;

use strict;
use warnings;
use JSON  qw(encode_json decode_json);
use Carp  qw(croak);
use POSIX qw(WNOHANG);

use Exec::Log qw();


my $DEFAULT_PORT = 7443;

# Run a script on one or more hosts in parallel.
# Each host gets a forked child; results are collected via pipes.
#
# Required opts:
#   hosts   => \@host_strings   (may include host:port)
#   script  => $name
#   config  => \%config         (cert, key, ca, optional timeout)
#
# Optional opts:
#   args     => \@script_args   (default [])
#   reqid    => $id             (generated if absent)
#   port     => $default_port   (default 7443)
#   username => $str            (forwarded to agent for downstream use)
#   token    => $str            (forwarded to agent for downstream use)
#   async    => $bool           (submit detached; collect acceptance, not result)
#
# Returns arrayref of result hashrefs. Synchronous (default):
#   { host, script, exit, stdout, stderr, reqid, rtt }
#   { host, script, exit => -1, error, reqid, rtt }
# Asynchronous (async => 1) - the agent runs the script detached and the
# result is fetched later via result_all():
#   { host, script, status => 'accepted', reqid, rtt }
#   { host, script, status => 'busy',  error, reqid, rtt }
#   { host, script, status => 'error', error, reqid, rtt }
sub dispatch_all {
    my (%opts) = @_;
    my $hosts    = $opts{hosts}    or croak "hosts required";
    my $script   = $opts{script}   or croak "script required";
    my $config   = $opts{config}   or croak "config required";
    my $args     = $opts{args}     // [];
    my $reqid    = $opts{reqid}    // gen_reqid();
    my $port     = $opts{port}     // $DEFAULT_PORT;
    my $username = $opts{username} // '';
    my $token    = $opts{token}    // '';
    my $async    = $opts{async}    // 0;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';
    croak "args must be an arrayref"  unless ref $args  eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    Exec::Log::log_action('INFO', {
        ACTION => 'dispatch',
        SCRIPT => $script,
        HOSTS  => join(',', map { $_->[0] } @entries),
        REQID  => $reqid,
        MODE   => $async ? 'async' : 'sync',
    });

    my @results;
    my %pipes;

    for my $entry (@entries) {
        my ($name, $target) = @$entry;
        my ($host, $hport)  = parse_host($target, $port);
        pipe my $r, my $w or die "pipe: $!";

        my $pid = fork();
        die "fork: $!" unless defined $pid;

        if ($pid == 0) {
            close $r;
            my $result = _dispatch_one(
                host     => $host,
                port     => $hport,
                script   => $script,
                args     => $args,
                reqid    => $reqid,
                config   => $config,
                username => $username,
                token    => $token,
                async    => $async,
            );
            print $w encode_json($result);
            close $w;
            exit 0;
        }

        close $w;
        $pipes{$pid} = { fh => $r, name => $name, target => $target };
    }

    while (%pipes) {
        my $pid = waitpid -1, 0;
        last if $pid <= 0;
        next unless exists $pipes{$pid};

        my $fh   = $pipes{$pid}{fh};
        my $name = $pipes{$pid}{name};
        my $raw  = do { local $/; <$fh> };
        close $fh;

        my $result = eval { decode_json($raw) }
            // { script => $script, exit => -1,
                 error => 'no response from child', reqid => $reqid };
        _canonicalise($result, $name);
        push @results, $result;
        delete $pipes{$pid};
    }

    return \@results;
}

# Fetch the result of an async dispatch from one or more hosts in parallel.
# Each host is queried with GET /result/<reqid>; the reqid is the one returned
# by an async dispatch_all(). Used by the dispatcher to poll a still-pending
# async run and aggregate per-host state.
#
# Required opts:
#   hosts   => \@host_strings   (the hosts the reqid was dispatched to)
#   config  => \%config
#   reqid   => $id              (the async request id; the agent store key)
#
# Optional opts:
#   port    => $default_port
#
# Returns arrayref of result hashrefs:
#   { host, status => 'running', reqid, rtt }
#   { host, status => 'done', exit, stdout, stderr, script, reqid, rtt }
#   { host, status => 'unknown', reqid, rtt }   (agent has no such record)
#   { host, status => 'error', error, reqid, rtt }
sub result_all {
    my (%opts) = @_;
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $config = $opts{config} or croak "config required";
    my $reqid  = $opts{reqid}  or croak "reqid required";
    my $port   = $opts{port}   // $DEFAULT_PORT;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my @results;
    my %pipes;

    for my $entry (@entries) {
        my ($name, $target) = @$entry;
        my ($host, $hport)  = parse_host($target, $port);
        pipe my $r, my $w or die "pipe: $!";

        my $pid = fork();
        die "fork: $!" unless defined $pid;

        if ($pid == 0) {
            close $r;
            my $result = _result_one(
                host   => $host,
                port   => $hport,
                reqid  => $reqid,
                config => $config,
            );
            print $w encode_json($result);
            close $w;
            exit 0;
        }

        close $w;
        $pipes{$pid} = { fh => $r, name => $name, target => $target };
    }

    while (%pipes) {
        my $pid = waitpid -1, 0;
        last if $pid <= 0;
        next unless exists $pipes{$pid};

        my $fh  = $pipes{$pid}{fh};
        my $raw = do { local $/; <$fh> };
        close $fh;

        my $result = eval { decode_json($raw) }
            // { status => 'error', error => 'no response from child', reqid => $reqid };
        _canonicalise($result, $pipes{$pid}{name});
        push @results, $result;
        delete $pipes{$pid};
    }

    return \@results;
}

# Ping one or more hosts in parallel.
#
# Required opts:
#   hosts   => \@host_strings
#   config  => \%config
#
# Optional opts:
#   reqid   => $id
#   port    => $default_port
#
# Returns arrayref of result hashrefs:
#   { host, status => 'ok', version, expiry, rtt, reqid }
#   { host, status => 'error', error, rtt }
sub ping_all {
    my (%opts) = @_;
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $config = $opts{config} or croak "config required";
    my $reqid  = $opts{reqid}  // gen_reqid();
    my $port   = $opts{port}   // $DEFAULT_PORT;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my @results;
    my %pipes;

    for my $entry (@entries) {
        my ($name, $target) = @$entry;
        my ($host, $hport)  = parse_host($target, $port);
        pipe my $r, my $w or die "pipe: $!";

        my $pid = fork();
        die "fork: $!" unless defined $pid;

        if ($pid == 0) {
            close $r;
            my $result = _ping_one(
                host   => $host,
                port   => $hport,
                reqid  => $reqid,
                config => $config,
            );
            print $w encode_json($result);
            close $w;
            exit 0;
        }

        close $w;
        $pipes{$pid} = { fh => $r, name => $name, target => $target };
    }

    while (%pipes) {
        my $pid = waitpid -1, 0;
        last if $pid <= 0;
        next unless exists $pipes{$pid};

        my $fh  = $pipes{$pid}{fh};
        my $raw = do { local $/; <$fh> };
        close $fh;

        my $result = eval { decode_json($raw) }
            // { status => 'error', error => 'no response from child' };

        # Trigger cert renewal if cert is past half-life. Renewal connects to
        # the resolved target, not the canonical name.
        if (($result->{status} // '') eq 'ok' && $result->{expiry}) {
            my $cert_days = $config->{cert_days} // 365;
            if (_renewal_due($result->{expiry}, $cert_days)) {
                my ($rhost, $rport) = parse_host($pipes{$pid}{target}, $port);
                eval {
                    _renew_one(
                        host   => $rhost,
                        port   => $rport,
                        config => $config,
                        reqid  => gen_reqid(),
                    );
                };
                if ($@) {
                    Exec::Log::log_action('ERR', {
                        ACTION => 'renew',
                        TARGET => "$rhost:$rport",
                        ERROR  => $@,
                    });
                }
            }
        }

        _canonicalise($result, $pipes{$pid}{name});
        push @results, $result;
        delete $pipes{$pid};
    }

    return \@results;
}

# Query one or more hosts for their capabilities (allowlisted scripts) in parallel.
#
# Required opts:
#   hosts   => \@host_strings
#   config  => \%config
#
# Optional opts:
#   port    => $default_port
#
# Returns arrayref of result hashrefs:
#   { host, status => 'ok', version, scripts => [{name, path, executable},...] }
#   { host, status => 'error', error }
sub capabilities_all {
    my (%opts) = @_;
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $config = $opts{config} or croak "config required";
    my $port   = $opts{port}   // $DEFAULT_PORT;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my @results;
    my %pipes;

    for my $entry (@entries) {
        my ($name, $target) = @$entry;
        my ($host, $hport)  = parse_host($target, $port);
        pipe my $r, my $w or die "pipe: $!";

        my $pid = fork();
        die "fork: $!" unless defined $pid;

        if ($pid == 0) {
            close $r;
            my $result = _capabilities_one(
                host   => $host,
                port   => $hport,
                config => $config,
            );
            print $w encode_json($result);
            close $w;
            exit 0;
        }

        close $w;
        $pipes{$pid} = { fh => $r, name => $name, target => $target };
    }

    while (%pipes) {
        my $pid = waitpid -1, 0;
        last if $pid <= 0;
        next unless exists $pipes{$pid};

        my $fh  = $pipes{$pid}{fh};
        my $raw = do { local $/; <$fh> };
        close $fh;

        my $result = eval { decode_json($raw) }
            // { status => 'error', error => 'no response from child' };
        _canonicalise($result, $pipes{$pid}{name});
        push @results, $result;
        delete $pipes{$pid};
    }

    return \@results;
}

# Normalise a host entry into (canonical_name, connect_target). An entry may
# be a plain string (the name is also the connect target) or a hashref
# { name => $canonical, target => $connect_target }. The canonical name is
# what results are keyed/displayed by; the target is what we connect to. This
# lets callers address an agent by its registry name while connecting to a
# resolved IP/port (see Exec::Registry::resolve_target).
sub _host_entry {
    my ($entry) = @_;
    if (ref $entry eq 'HASH') {
        my $name   = $entry->{name}   // $entry->{target};
        my $target = $entry->{target} // $entry->{name};
        return ($name, $target);
    }
    return ($entry, $entry);
}

# Set a result's canonical host to the name it was addressed by (the registry
# name), and keep the agent-reported hostname only when it differs. Callers
# display $result->{host} as canonical and may show reported_hostname in
# brackets when present.
sub _canonicalise {
    my ($result, $name) = @_;
    $result->{host} = $name;
    if (defined $result->{reported_hostname}
        && (!length $result->{reported_hostname}
            || $result->{reported_hostname} eq $name)) {
        delete $result->{reported_hostname};
    }
    return $result;
}

# Parse a host string into (host, port).
# Accepts "hostname" or "hostname:port".
sub parse_host {
    my ($host_str, $default_port) = @_;
    if ($host_str =~ /^(.+):(\d+)$/) {
        return ($1, $2);
    }
    return ($host_str, $default_port // $DEFAULT_PORT);
}

# Generate a cryptographically random 16-hex-character request ID.
sub gen_reqid {
    open my $fh, '<:raw', '/dev/urandom'
        or return sprintf '%08x%08x', int(rand(0xffffffff)), int(rand(0xffffffff));
    my $buf;
    sysread $fh, $buf, 8;
    close $fh;
    return unpack 'H*', $buf;
}

# --- private ---

sub _dispatch_one {
    my (%opts) = @_;
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};
    my $async  = $opts{async} // 0;

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config);

    my %body = (
        script   => $opts{script},
        args     => $opts{args} // [],
        reqid    => $reqid,
        username => $opts{username} // '',
        token    => $opts{token}    // '',
    );
    $body{async} = JSON::true if $async;
    my $payload = encode_json(\%body);

    my $resp = eval {
        $ua->post(
            "https://$host:$port/run",
            'Content-Type' => 'application/json',
            Content        => $payload,
        );
    };

    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        # In async mode a 409 is not a transport failure: the agent is up and
        # refusing because the same script is already running. Surface it as a
        # distinct 'busy' status rather than a generic error.
        if ($async && $resp && $resp->code == 409) {
            my $body = eval { decode_json($resp->content) } // {};
            Exec::Log::log_action('WARNING', {
                ACTION => 'run-async',
                SCRIPT => $opts{script},
                TARGET => "$host:$port",
                STATUS => 'busy',
                RTT    => $rtt,
                REQID  => $reqid,
            });
            return {
                host   => $host,
                script => $opts{script},
                status => 'busy',
                error  => $body->{error} // 'script already running',
                rtt    => $rtt,
                reqid  => $reqid,
            };
        }

        my $err;
        if ($resp && $resp->code == 403) {
            my $body = eval { decode_json($resp->content) } // {};
            $err = 'forbidden: ' . ($body->{error} // $resp->status_line);
        }
        elsif ($resp && $resp->code == 413) {
            $err = 'request too large';
        }
        else {
            my $raw_err = $@ || ($resp ? $resp->status_line : 'no response');
            my $timeout = $config->{read_timeout} // $config->{timeout} // 60;
            $err = ($raw_err =~ /timeout|read timeout/i)
                ? "read timeout after ${timeout}s"
                : $raw_err;
        }
        Exec::Log::log_action('ERR', {
            ACTION => $async ? 'run-async' : 'run',
            SCRIPT => $opts{script},
            TARGET => "$host:$port",
            ERROR  => $err,
            RTT    => $rtt,
            REQID  => $reqid,
        });
        return {
            host   => $host,
            script => $opts{script},
            ($async ? (status => 'error') : (exit => -1)),
            error  => $err,
            rtt    => $rtt,
            reqid  => $reqid,
        };
    }

    my $decoded = eval { decode_json($resp->content) };

    if ($async) {
        # The agent returns 202 { status => 'accepted', reqid } - the job is
        # detached. No exit/stdout/stderr yet; those come from result_all().
        my $result = $decoded // { status => 'error', error => 'invalid JSON response' };
        $result->{rtt}    = $rtt;
        $result->{reqid} //= $reqid;
        Exec::Log::log_action('INFO', {
            ACTION => 'run-async',
            SCRIPT => $opts{script},
            TARGET => "$host:$port",
            STATUS => $result->{status} // 'accepted',
            RTT    => $rtt,
            REQID  => $reqid,
        });
        return $result;
    }

    my $result  = $decoded // { exit => -1, error => 'invalid JSON response' };

    # Keep the agent's self-reported hostname; the caller sets the canonical
    # host from the name the agent was addressed by.
    $result->{reported_hostname} = $decoded->{host}
        if $decoded && defined $decoded->{host} && length $decoded->{host};
    $result->{rtt}     = $rtt;
    $result->{reqid} //= $reqid;

    Exec::Log::log_action('INFO', {
        ACTION => 'run',
        SCRIPT => $opts{script},
        TARGET => "$host:$port",
        EXIT   => $result->{exit},
        RTT    => $rtt,
        REQID  => $reqid,
    });

    return $result;
}

sub _result_one {
    my (%opts) = @_;
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config);

    my $resp = eval {
        $ua->get("https://$host:$port/result/$reqid");
    };

    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        # 404 is an expected outcome, not a transport error: the agent has no
        # record for this reqid - it was never run there, or it has been
        # TTL-purged. The dispatcher distinguishes purged-vs-never from its own
        # registry; here it is reported uniformly as 'unknown'.
        if ($resp && $resp->code == 404) {
            return {
                host   => $host,
                status => 'unknown',
                reqid  => $reqid,
                rtt    => $rtt,
            };
        }

        my $err;
        if ($resp && $resp->code == 403) {
            my $body = eval { decode_json($resp->content) } // {};
            $err = 'forbidden: ' . ($body->{error} // $resp->status_line);
        }
        else {
            $err = $@ || ($resp ? $resp->status_line : 'no response');
        }
        Exec::Log::log_action('ERR', {
            ACTION => 'result',
            TARGET => "$host:$port",
            ERROR  => $err,
            RTT    => $rtt,
            REQID  => $reqid,
        });
        return {
            host   => $host,
            status => 'error',
            error  => $err,
            reqid  => $reqid,
            rtt    => $rtt,
        };
    }

    my $decoded = eval { decode_json($resp->content) };
    my $result  = $decoded // { status => 'error', error => 'invalid JSON' };
    $result->{rtt}    = $rtt;
    $result->{reqid} //= $reqid;

    Exec::Log::log_action('INFO', {
        ACTION => 'result',
        TARGET => "$host:$port",
        STATUS => $result->{status} // 'unknown',
        RTT    => $rtt,
        REQID  => $reqid,
    });

    return $result;
}

sub _ping_one {
    my (%opts) = @_;
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config);

    my $resp = eval {
        $ua->post(
            "https://$host:$port/ping",
            'Content-Type' => 'application/json',
            Content        => encode_json({ reqid => $reqid }),
        );
    };

    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        my $err;
        if ($resp && $resp->code == 403) {
            my $body = eval { decode_json($resp->content) } // {};
            $err = 'forbidden: ' . ($body->{error} // $resp->status_line);
        }
        elsif ($resp && $resp->code == 413) {
            $err = 'request too large';
        }
        else {
            $err = $@ || ($resp ? $resp->status_line : 'no response');
        }
        Exec::Log::log_action('ERR', {
            ACTION => 'ping',
            TARGET => "$host:$port",
            ERROR  => $err,
            RTT    => $rtt,
            REQID  => $reqid,
        });
        return { host => $host, status => 'error', error => $err, rtt => $rtt };
    }

    my $decoded = eval { decode_json($resp->content) };
    my $result  = $decoded // { status => 'error', error => 'invalid JSON' };

    $result->{reported_hostname} = $decoded->{host}
        if $decoded && defined $decoded->{host} && length $decoded->{host};
    $result->{rtt}  = $rtt;

    Exec::Log::log_action('INFO', {
        ACTION => 'ping',
        TARGET => "$host:$port",
        RESULT => 'ok',
        RTT    => $rtt,
        REQID  => $reqid,
    });

    return $result;
}

sub _capabilities_one {
    my (%opts) = @_;
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config);

    my $resp = eval {
        $ua->get("https://$host:$port/capabilities");
    };

    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        my $err = $@ || ($resp ? $resp->status_line : 'no response');
        Exec::Log::log_action('ERR', {
            ACTION => 'capabilities',
            TARGET => "$host:$port",
            ERROR  => $err,
            RTT    => $rtt,
        });
        return { host => $host, status => 'error', error => $err, rtt => $rtt };
    }

    my $decoded = eval { decode_json($resp->content) };
    my $result  = $decoded // { status => 'error', error => 'invalid JSON' };

    $result->{reported_hostname} = $decoded->{host}
        if $decoded && defined $decoded->{host} && length $decoded->{host};
    $result->{rtt}  = $rtt;

    Exec::Log::log_action('INFO', {
        ACTION  => 'capabilities',
        TARGET  => "$host:$port",
        SCRIPTS => scalar @{ $result->{scripts} // [] },
        RTT     => $rtt,
    });

    return $result;
}

sub _build_ua {
    my ($config) = @_;
    require LWP::UserAgent;
    require IO::Socket::SSL;
    require Exec::TLS;

    # LWP's ssl_opts hash does not pass SSL_cert_file/SSL_key_file through
    # to IO::Socket::SSL for client cert presentation. Set them as global
    # SSL defaults so every outbound connection uses the dispatcher cert.
    # Exec::TLS::hardening adds the shared cipher/version policy.
    IO::Socket::SSL::set_defaults(
        SSL_cert_file    => $config->{cert},
        SSL_key_file     => $config->{key},
        SSL_ca_file      => $config->{ca},
        SSL_verify_mode  => 0x01,
        Exec::TLS::hardening(),
    );

    my $ua = LWP::UserAgent->new(
        ssl_opts => {
            SSL_ca_file     => $config->{ca},
            SSL_verify_mode => 0x01,
            verify_hostname => 0,   # verified by CA, not hostname
        },
        timeout => $config->{read_timeout} // $config->{timeout} // 60,
    );
    return $ua;
}

# Returns true if the cert should be renewed.
# Renewal is due when remaining validity is less than half of cert_days.
# Returns false (safe default) if the expiry string cannot be parsed.
sub _renewal_due {
    my ($expiry_str, $cert_days) = @_;
    return 0 unless $expiry_str;

    require Time::Piece;
    my $expiry_epoch = eval {
        Time::Piece->strptime($expiry_str, '%b %d %H:%M:%S %Y %Z')->epoch;
    };
    return 0 unless $expiry_epoch;

    my $remaining  = $expiry_epoch - time();
    my $half_life  = ($cert_days / 2) * 86400;
    return $remaining < $half_life ? 1 : 0;
}

# Perform cert renewal for a single agent over the existing mTLS connection.
# POSTs /renew to get a CSR, signs it, POSTs /renew-complete to deliver.
# Updates the registry expiry on success. Dies on any failure.
sub _renew_one {
    my (%opts) = @_;
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};

    require Exec::CA;
    require Exec::Registry;

    Exec::Log::log_action('INFO', {
        ACTION => 'renew',
        TARGET => "$host:$port",
        REQID  => $reqid,
        STATUS => 'starting',
    });

    my $ua = _build_ua($config);

    # Request CSR from agent
    my $resp = $ua->post(
        "https://$host:$port/renew",
        'Content-Type' => 'application/json',
        Content        => encode_json({ reqid => $reqid }),
    );
    die "renew request failed: " . $resp->status_line unless $resp->is_success;

    my $data = eval { decode_json($resp->content) }
        or die "invalid JSON in renew response";
    my $csr_pem = $data->{csr} or die "no CSR in renew response";

    # Sign the CSR
    my $cert_pem = Exec::CA::sign_csr(
        csr_pem => $csr_pem,
        ca_dir  => $config->{ca_dir} // '/etc/ctrl-exec',
        days    => $config->{cert_days} // 365,
    );
    my $ca_pem = Exec::CA::read_ca_cert(
        ca_dir => $config->{ca_dir} // '/etc/ctrl-exec',
    );

    # Deliver new cert
    my $resp2 = $ua->post(
        "https://$host:$port/renew-complete",
        'Content-Type' => 'application/json',
        Content        => encode_json({
            cert  => $cert_pem,
            ca    => $ca_pem,
            reqid => $reqid,
        }),
    );
    die "renew-complete failed: " . $resp2->status_line unless $resp2->is_success;

    # Extract new expiry and update registry
    my $expiry = _extract_expiry($cert_pem) // 'unknown';
    Exec::Registry::update_expiry(hostname => $host, expiry => $expiry);

    Exec::Log::log_action('INFO', {
        ACTION => 'renew-complete',
        TARGET => "$host:$port",
        REQID  => $reqid,
        EXPIRY => $expiry,
    });
}

# Extract notAfter date string from a PEM cert via openssl subprocess.
sub _extract_expiry {
    my ($cert_pem) = @_;
    require File::Temp;
    my ($fh, $path) = File::Temp::tempfile(UNLINK => 1);
    print $fh $cert_pem;
    close $fh;
    my $out = `openssl x509 -noout -enddate -in "$path" 2>/dev/null`;
    chomp $out;
    return $out =~ /^notAfter=(.+)$/ ? $1 : undef;
}

1;
