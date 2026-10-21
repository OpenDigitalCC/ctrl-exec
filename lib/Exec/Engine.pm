package Exec::Engine;

use strict;
use warnings;
use feature      qw(signatures);
no warnings      qw(experimental::signatures);
use JSON  qw(encode_json decode_json);
use Carp  qw(croak);
use Exec::CertInfo qw();
use Exec::Random   qw();

use Exec::Log qw();
use Exec::DispatcherConfig qw();


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
#   input    => \%fields       (confidential named string fields, already
#                               validated by Exec::Input; sent unchanged to
#                               every host as the request body's 'input'; never
#                               logged or recorded)
#
# Returns arrayref of result hashrefs. Synchronous (default):
#   { host, script, exit, stdout, stderr, reqid, rtt }
#   { host, script, exit => -1, error, reqid, rtt }
# Asynchronous (async => 1) - the agent runs the script detached and the
# result is fetched later via result_all():
#   { host, script, status => 'accepted', reqid, rtt }
#   { host, script, status => 'busy',  error, reqid, rtt }
#   { host, script, status => 'error', error, reqid, rtt }
sub dispatch_all (%opts) {
    my $hosts    = $opts{hosts}    or croak "hosts required";
    my $script   = $opts{script}   or croak "script required";
    my $config   = $opts{config}   or croak "config required";
    my $args     = $opts{args}     // [];
    my $reqid    = $opts{reqid}    // gen_reqid();
    my $port     = $opts{port}     // $DEFAULT_PORT;
    my $username = $opts{username} // '';
    my $token    = $opts{token}    // '';
    my $async    = $opts{async}    // 0;
    my $input    = $opts{input};

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';
    croak "args must be an arrayref"  unless ref $args  eq 'ARRAY';
    croak "input must be a hashref"   if defined $input && ref $input ne 'HASH';

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

    my $max_par = $opts{max_parallel} // $config->{max_parallel} // 64;
    my $fanned  = _fan_out(\@entries, $max_par, sub ($name, $target) {
        my ($host, $hport)  = parse_host($target, $port);
        return _dispatch_one(
            name     => $name,   # registry name: its pinned CA, if any
            host     => $host,
            port     => $hport,
            script   => $script,
            args     => $args,
            reqid    => $reqid,
            config   => $config,
            username => $username,
            token    => $token,
            async    => $async,
            (defined $input ? (input => $input) : ()),
        );
    });

    my @results;
    for my $f (@$fanned) {
        my $result = $f->{result}
            // { script => $script, exit => -1,
                 error => 'no response from child' . _lost($f), reqid => $reqid };
        _canonicalise($result, $f->{name});
        push @results, $result;
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
sub result_all (%opts) {
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $config = $opts{config} or croak "config required";
    my $reqid  = $opts{reqid}  or croak "reqid required";
    my $port   = $opts{port}   // $DEFAULT_PORT;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my $max_par = $opts{max_parallel} // $config->{max_parallel} // 64;
    my $fanned  = _fan_out(\@entries, $max_par, sub ($name, $target) {
        my ($host, $hport)  = parse_host($target, $port);
        return _result_one(
            name     => $name,   # registry name: its pinned CA, if any
            host   => $host,
            port   => $hport,
            reqid  => $reqid,
            config => $config,
        );
    });

    my @results;
    for my $f (@$fanned) {
        my $result = $f->{result}
            // { status => 'error', error => 'no response from child' . _lost($f), reqid => $reqid };
        _canonicalise($result, $f->{name});
        push @results, $result;
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
sub ping_all (%opts) {
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $config = $opts{config} or croak "config required";
    my $reqid  = $opts{reqid}  // gen_reqid();
    my $port   = $opts{port}   // $DEFAULT_PORT;
    # Whether to trigger cert renewal for aging certs as a side effect of pinging.
    # Renewal signs a CSR, which needs the root-owned CA key - so callers without
    # it (the unprivileged API server) pass renew => 0. The root CLI/maintenance
    # paths leave it at the default.
    my $renew  = $opts{renew}  // 1;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my $max_par = $opts{max_parallel} // $config->{max_parallel} // 64;
    my $fanned  = _fan_out(\@entries, $max_par, sub ($name, $target) {
        my ($host, $hport)  = parse_host($target, $port);
        return _ping_one(
            name     => $name,   # registry name: its pinned CA, if any
            host   => $host,
            port   => $hport,
            reqid  => $reqid,
            config => $config,
        );
    });

    my @results;
    for my $f (@$fanned) {
        my $result = $f->{result}
            // { status => 'error', error => 'no response from child' . _lost($f) };

        # Trigger cert renewal if the cert is past half-life. Renewal connects to
        # the resolved target, not the canonical name. Skip when the agent already
        # has a renewed cert staged (awaiting its next restart): its live expiry
        # still reads old, so re-renewing each run would just re-sign and re-stage
        # redundantly until the agent restarts.
        # An agent whose CA is pinned (keep-certificate pairing, T-062) holds a
        # certificate another dispatcher issued; that dispatcher renews it.
        # Renewing it here would sign with this dispatcher's CA, which the agent
        # refuses (renewal stays with the issuing CA). The expiry it reports is
        # recorded, so list-agents follows the issuing dispatcher's renewals.
        my $pinned = defined _pinned_ca($config, $f->{name});
        if ($pinned && ($result->{status} // '') eq 'ok'
                && defined Exec::CertInfo::expiry_epoch($result->{expiry})) {
            my $rec = eval { Exec::Registry::get_agent(hostname => $f->{name},
                registry_dir => $config->{registry_dir}) } // {};
            eval { Exec::Registry::update_expiry(hostname => $f->{name},
                expiry => $result->{expiry}, registry_dir => $config->{registry_dir}) }
                if ($rec->{expiry} // '') ne $result->{expiry};
        }
        if ($renew && !$pinned && ($result->{status} // '') eq 'ok' && $result->{expiry}
                && !$result->{staged}) {
            my $cert_days = $config->{cert_days} // 365;
            if (_renewal_due($result->{expiry}, $cert_days)) {
                my ($rhost, $rport) = parse_host($f->{target}, $port);
                eval {
                    _renew_one(
                        host   => $rhost,
                        port   => $rport,
                        name   => $f->{name},   # registry key, not the resolved address
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

        _canonicalise($result, $f->{name});
        push @results, $result;
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
sub capabilities_all (%opts) {
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $config = $opts{config} or croak "config required";
    my $port   = $opts{port}   // $DEFAULT_PORT;

    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';

    my $max_hosts = $opts{max_hosts} // 500;
    croak "too many hosts (max $max_hosts)" if @$hosts > $max_hosts;

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my $max_par = $opts{max_parallel} // $config->{max_parallel} // 64;
    my $fanned  = _fan_out(\@entries, $max_par, sub ($name, $target) {
        my ($host, $hport)  = parse_host($target, $port);
        return _capabilities_one(
            name     => $name,   # registry name: its pinned CA, if any
            host   => $host,
            port   => $hport,
            config => $config,
        );
    });

    my @results;
    for my $f (@$fanned) {
        my $result = $f->{result}
            // { status => 'error', error => 'no response from child' . _lost($f) };
        _canonicalise($result, $f->{name});
        push @results, $result;
    }

    return \@results;
}

# Normalise a host entry into (canonical_name, connect_target). An entry may
# be a plain string (the name is also the connect target) or a hashref
# { name => $canonical, target => $connect_target }. The canonical name is
# what results are keyed/displayed by; the target is what we connect to. This
# lets callers address an agent by its registry name while connecting to a
# resolved IP/port (see Exec::Registry::resolve_target).
sub _host_entry ($entry) {
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
sub _canonicalise ($result, $name) {
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
sub parse_host ($host_str, $default_port = undef) {
    if ($host_str =~ /^(.+):(\d+)$/) {
        return ($1, $2);
    }
    return ($host_str, $default_port // $DEFAULT_PORT);
}

# Generate a cryptographically random 16-hex-character request ID. Delegates to
# the one urandom reader (Exec::Random) - no rand() fallback, because a reqid is
# the unguessable capability that gates async result fetches.
sub gen_reqid () {
    return Exec::Random::hex_bytes(8);
}

# --- private ---

# Fan out a per-host worker across @$entries (each [name, target]) with at most
# $max children alive at once, collecting each child's JSON result. This bounds
# the fork/fd/memory cost of a large fleet: a 500-host operation no longer forks
# 500 TLS clients simultaneously (which would exhaust the default 1024 fd limit
# before the host cap). $worker->($name, $target) runs in the child and returns
# a result hashref, JSON-encoded over a pipe. Returns an arrayref of
# { name => $name, target => $target, result => $decoded_or_undef } in completion
# order; callers supply their own fallback for an undef result and canonicalise.
sub _fan_out ($entries, $max, $worker) {
    $max = 1 unless $max && $max >= 1;

    # Preload the HTTP/TLS stack ONCE in the parent so every forked worker
    # inherits it (copy-on-write) instead of each compiling LWP and
    # IO::Socket::SSL afresh - for a large fan-out that is N-1 redundant module
    # compiles saved. Every worker in this codebase is an HTTP client, so this is
    # always wanted. (Reusing a TLS session across hosts - a persistent worker
    # pool - is a larger change left as future work.)
    eval { require LWP::UserAgent; require IO::Socket::SSL; require Exec::TLS; 1 };

    my @pending = @$entries;
    my %pipes;       # pid => { fh, name, target }
    my @out;

    while (@pending || %pipes) {
        while (@pending && keys(%pipes) < $max) {
            my ($name, $target) = @{ shift @pending };
            pipe my $r, my $w or die "pipe: $!";
            my $pid = fork();
            die "fork: $!" unless defined $pid;
            if ($pid == 0) {
                close $r;
                # The worker inherits the API server's INT/TERM handlers (which
                # exit 0 silently) and Perl's default SIGPIPE (terminate). Either
                # would end it with an empty pipe and no trace of why. Let a
                # signal death show up in the wait status instead, and turn a
                # die inside the worker into a message the parent can report.
                local $SIG{PIPE} = 'IGNORE';
                local $SIG{INT}  = 'DEFAULT';
                local $SIG{TERM} = 'DEFAULT';
                my $result = eval { $worker->($name, $target) };
                $result = { _worker_died => "$@" } if $@;
                $result //= { _worker_died => 'worker returned no result' };
                print $w encode_json($result);
                close $w;
                exit 0;
            }
            close $w;
            $pipes{$pid} = { fh => $r, name => $name, target => $target };
        }

        my $pid = waitpid -1, 0;
        if ($pid <= 0) {
            # Nothing to collect although workers are outstanding (ECHILD: they
            # were reaped elsewhere, e.g. by an inherited SIGCHLD reaper). Report
            # each as lost, with the errno, instead of dropping them silently.
            my $why = "waitpid: $!";
            for my $p (sort keys %pipes) {
                close $pipes{$p}{fh};
                push @out, {
                    name    => $pipes{$p}{name},
                    target  => $pipes{$p}{target},
                    result  => undef,
                    failure => $why,
                };
            }
            %pipes = ();
            last;
        }
        next unless exists $pipes{$pid};
        my $status = $?;
        my $fh  = $pipes{$pid}{fh};
        my $raw = do { local $/; <$fh> };
        close $fh;
        $raw //= '';
        my $decoded = length $raw ? scalar eval { decode_json($raw) } : undef;
        my ($result, $failure) = _worker_outcome($decoded, $status, length $raw);
        push @out, {
            name   => $pipes{$pid}{name},
            target => $pipes{$pid}{target},
            result => $result,
            (defined $failure ? (failure => $failure) : ()),
        };
        delete $pipes{$pid};
    }

    return \@out;
}

# Reduce a reaped worker's decoded pipe output and wait status to
# (result, failure). result is the worker's hashref on success, else undef with
# failure saying why - so the caller's "no response from child" carries the
# reason ("worker killed by signal 13", "worker exited 1 with no output",
# "worker died: ...") instead of leaving the next incident to guesswork.
sub _worker_outcome ($decoded, $status, $len) {
    if (ref $decoded eq 'HASH') {
        return ($decoded, undef) unless exists $decoded->{_worker_died};
        my $msg = $decoded->{_worker_died} // '';
        $msg =~ s/\s+\z//;
        return (undef, "worker died: $msg");
    }
    my $sig  = $status & 127;
    return (undef, "worker killed by signal $sig") if $sig;
    my $code = $status >> 8;
    return (undef, "worker exited $code with no output") unless $len;
    return (undef, "worker exited $code with unparseable output");
}

# Decode an agent response body, returning a hashref or undef. Agents always
# answer with a JSON object; a scalar/array/invalid body must not become a
# "Not a HASH reference" die inside a fan-out worker (which would surface as an
# empty result), it becomes the ordinary 'invalid JSON response' error.
sub _json_hash ($content) {
    my $d = eval { decode_json($content // '') };
    return ref $d eq 'HASH' ? $d : undef;
}

# An agent result with exit -1 is the agent's own failure, never a script's exit
# code (those are 0-255): the executor transport ("executor closed before
# responding"), a fork/pipe failure, a malformed request. The agent reports the
# reason in stderr only, so a caller reading `error` saw it empty (T-034). Copy
# the stderr text into `error` when the agent gave none; stdout and stderr are
# left exactly as the agent sent them.
sub _error_from_stderr ($result) {
    return unless defined $result->{exit} && "$result->{exit}" eq '-1';
    return if defined $result->{error} && length $result->{error};
    my $why = $result->{stderr} // '';
    $why =~ s/\s+\z//;
    $result->{error} = length $why ? $why : 'agent reported exit -1 with no reason';
    return;
}

# The suffix a caller appends to its 'no response from child' fallback.
sub _lost ($f) {
    return defined $f->{failure} ? ": $f->{failure}" : '';
}

sub _dispatch_one (%opts) {
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};
    my $async  = $opts{async} // 0;

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config, $opts{name});

    my %body = (
        script   => $opts{script},
        args     => $opts{args} // [],
        reqid    => $reqid,
        username => $opts{username} // '',
        token    => $opts{token}    // '',
    );
    $body{async} = JSON::true if $async;
    $body{input} = $opts{input} if defined $opts{input};
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
            my $body = _json_hash($resp->content) // {};
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
            my $body = _json_hash($resp->content) // {};
            $err = 'forbidden: ' . ($body->{error} // $resp->status_line);
        }
        elsif ($resp && $resp->code == 413) {
            $err = 'request too large';
        }
        else {
            my $raw_err = $@ || ($resp ? $resp->status_line : 'no response');
            my $timeout = $config->{read_timeout} // $config->{timeout} // 60;
            $err = ($raw_err =~ /read timeout/i)
                ? "read timeout after ${timeout}s"
                : _transport_error($raw_err, $host, $port, $config);
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

    my $decoded = _json_hash($resp->content);

    if ($async) {
        # The agent returns 202 { status => 'accepted', reqid } - the job is
        # detached. No exit/stdout/stderr yet; those come from result_all().
        my $result = $decoded // { status => 'error', error => 'invalid JSON response' };
        $result->{rtt}    = $rtt;
        $result->{reqid} //= $reqid;
        # An agent that refuses the run (e.g. an output=confidential script,
        # T-053) answers with an error and no status: that is not an
        # acceptance, and the run store and CLI already read it as 'error'.
        Exec::Log::log_action('INFO', {
            ACTION => 'run-async',
            SCRIPT => $opts{script},
            TARGET => "$host:$port",
            STATUS => $result->{status} // 'error',
            RTT    => $rtt,
            REQID  => $reqid,
        });
        return $result;
    }

    my $result  = $decoded // { exit => -1, error => 'invalid JSON response' };
    _error_from_stderr($result);

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

sub _result_one (%opts) {
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config, $opts{name});

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

        my $err = _classify_error($resp, $@, $host, $port, $config);
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

    my $decoded = _json_hash($resp->content);
    my $result  = $decoded // { status => 'error', error => 'invalid JSON' };
    _error_from_stderr($result);
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

sub _ping_one (%opts) {
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};
    my $reqid  = $opts{reqid};

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config, $opts{name});

    my $resp = eval {
        $ua->post(
            "https://$host:$port/ping",
            'Content-Type' => 'application/json',
            Content        => encode_json({ reqid => $reqid }),
        );
    };

    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        my $err = ($resp && $resp->code == 413)
            ? 'request too large'
            : _classify_error($resp, $@, $host, $port, $config);
        Exec::Log::log_action('ERR', {
            ACTION => 'ping',
            TARGET => "$host:$port",
            ERROR  => $err,
            RTT    => $rtt,
            REQID  => $reqid,
        });
        return { host => $host, status => 'error', error => $err, rtt => $rtt };
    }

    my $decoded = _json_hash($resp->content);
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

sub _capabilities_one (%opts) {
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $config = $opts{config};

    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config, $opts{name});

    my $resp = eval {
        $ua->get("https://$host:$port/capabilities");
    };

    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        my $err = _transport_error($@ || ($resp ? $resp->status_line : 'no response'),
                                   $host, $port, $config);
        Exec::Log::log_action('ERR', {
            ACTION => 'capabilities',
            TARGET => "$host:$port",
            ERROR  => $err,
            RTT    => $rtt,
        });
        return { host => $host, status => 'error', error => $err, rtt => $rtt };
    }

    my $decoded = _json_hash($resp->content);
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

# Classify a failed agent response into an error string: a 403 surfaces the
# agent's forbidden reason (its trusted-serial gate), anything else is a
# transport-level failure. Shared by the per-host workers with this exact
# 403-or-transport split (ping/rotate/result); callers handle any
# endpoint-specific code (a ping's 413, a result's 404) before calling this.
# $at is the request eval's $@, captured at the call site before the decode
# below can clobber it.
sub _classify_error ($resp, $at, $host, $port, $config = undef) {
    if ($resp && $resp->code == 403) {
        my $body = _json_hash($resp->content) // {};
        return 'forbidden: ' . ($body->{error} // $resp->status_line);
    }
    return _transport_error($at || ($resp ? $resp->status_line : 'no response'),
                            $host, $port, $config);
}

# Translate a raw transport failure (LWP status_line or $@) into a concise,
# status-like message: a connection failure arrives as a 5xx whose status_line
# embeds the socket reason in parentheses ("500 Can't connect to host:port
# (Connection refused)"), which reads like a crash rather than a reachability
# status. Rewrite only recognised transport causes; anything else (including a
# genuine HTTP status such as 403) is returned unchanged, so this never mislabels
# an authorisation response as a network problem.
#
# $config (ctrl-exec.conf) is optional: with it, a handshake failure is followed
# by the hint of _old_cert_hint when this dispatcher's certificate predates 0.14.
sub _transport_error ($raw, $host, $port, $config = undef) {
    $raw  //= '';
    $host //= 'host';

    return "host '$host' did not resolve - check the name or use an IP address"
        if $raw =~ /bad \s* hostname | name \s or \s service \s not \s known |
                    nodename \s nor \s servname | temporary \s failure \s in \s name |
                    cannot \s resolve | no \s address \s associated/xi;

    return "host '$host' did not respond on port $port - connection refused "
         . "(agent not running, or wrong port?)"
        if $raw =~ /connection \s refused/xi;

    return "host '$host' is unreachable - no route to host or network down"
        if $raw =~ /no \s route \s to \s host | network \s is \s unreachable |
                    host \s is \s unreachable/xi;

    return "host '$host' did not respond - connection timed out"
        if $raw =~ /timed \s out | \btimeout\b/xi;

    return "TLS handshake with '$host' failed - certificate or trust mismatch"
         . _old_cert_hint($config)
        if $raw =~ /ssl \s connect | \bssl\b | \btls\b | certificate | handshake |
                    verify \s failed/xi;

    # Under TLS 1.3 the client's side of the handshake is over before the agent
    # checks the client certificate, so an agent refusing it reaches LWP as a
    # connection closed with no reply (T-068). Older LWP (Debian 11, Ubuntu
    # 20.04) words the same close "Status read failed", or "read failed" when
    # the request body was written first.
    return $raw . _old_cert_hint($config)
        if $raw =~ /closed \s connection \s without \s sending \s any \s data |
                    \bread \s failed/xi;

    return "agent rate-limited this dispatcher (HTTP 429) - its certificate serial "
         . "is not in the agent's trusted-dispatcher map (pair it), or raise "
         . "rate_limit_volume on the agent"
        if $raw =~ /^\s*429\b/;

    return $raw;   # unrecognised - leave as-is (may be a real HTTP status)
}

# The text added to a failed handshake with an agent when this dispatcher's own
# certificate (ctrl-exec.conf 'cert') has no Authority Key Identifier, else ''
# (T-068). Such a certificate was issued before 0.14 on an OpenSSL 1.1 host. An
# agent that trusts this dispatcher's CA and another CA with the same name (the
# pre-0.14 default "ctrl-exec CA") checks it against the first CA of that name
# and refuses it when that is the other one. The dispatcher cannot see which CAs
# the agent trusts, so the hint says when it applies; the agent's tls-failure
# log line says whether it did. rotate-cert issues a certificate with the AKI;
# the agent then needs pairing again, as the rotation broadcast cannot reach
# an agent that refuses this certificate.
sub _old_cert_hint ($config) {
    return '' unless ref $config eq 'HASH' && defined $config->{cert};
    my $has = Exec::CertInfo::has_aki_path($config->{cert});
    return '' unless defined $has && !$has;
    return " - this dispatcher's certificate predates 0.14 (it has no Authority Key Identifier):"
         . ' an agent that trusts another CA with the same name as this dispatcher\'s CA refuses it;'
         . " run 'ctrl-exec-dispatcher rotate-cert', then pair that agent again";
}

# Broadcast a trusted-serial change to agents during cert rotation. POSTs to the
# agent's /rotate-serial control-plane endpoint (no script, no executor): the
# agent derives the dispatcher identity from the caller's authenticated serial
# and adds/removes the given serial under it. Returns an arrayref of per-host
# { host, status, exit, error?, rtt } (exit 0 == success), mirroring dispatch_all.
sub rotate_all (%opts) {
    my $hosts  = $opts{hosts}  or croak "hosts required";
    my $serial = $opts{serial} or croak "serial required";
    my $action = $opts{action} // 'add';
    my $config = $opts{config} or croak "config required";
    my $port   = $opts{port}   // $DEFAULT_PORT;
    croak "hosts must be an arrayref" unless ref $hosts eq 'ARRAY';
    croak "action must be add or remove" unless $action eq 'add' || $action eq 'remove';

    my @entries = map { [ _host_entry($_) ] } @$hosts;

    my $max_par = $opts{max_parallel} // $config->{max_parallel} // 64;
    my $fanned  = _fan_out(\@entries, $max_par, sub ($name, $target) {
        my ($host, $hport)  = parse_host($target, $port);
        return _rotate_one(
            name     => $name,   # registry name: its pinned CA, if any
            host => $host, port => $hport,
            serial => $serial, action => $action, config => $config,
        );
    });

    my @results;
    for my $f (@$fanned) {
        my $result = $f->{result}
            // { status => 'error', exit => -1, error => 'no response from child' . _lost($f) };
        $result->{host} = $f->{name};     # report by the registry name, not the resolved address
        push @results, $result;
    }
    return \@results;
}

sub _rotate_one (%opts) {
    my ($host, $port, $config) = @opts{qw(host port config)};
    require Time::HiRes;
    my $t0 = Time::HiRes::time();
    my $ua = _build_ua($config, $opts{name});

    my $payload = encode_json({ serial => $opts{serial}, action => $opts{action} });
    my $resp = eval {
        $ua->post("https://$host:$port/rotate-serial",
            'Content-Type' => 'application/json', Content => $payload);
    };
    my $rtt = sprintf '%.0fms', (Time::HiRes::time() - $t0) * 1000;

    if ($@ || !$resp || !$resp->is_success) {
        my $err = _classify_error($resp, $@, $host, $port, $config);
        return { host => $host, status => 'error', exit => -1, error => $err, rtt => $rtt };
    }

    my $decoded = _json_hash($resp->content)
        // { status => 'error', error => 'invalid JSON' };
    $decoded->{rtt}  = $rtt;
    $decoded->{exit} //= (($decoded->{status} // '') eq 'ok') ? 0 : -1;
    return $decoded;
}

# The agent's TLS certificate is verified against this dispatcher's CA
# (ctrl-exec.conf 'ca'), unless the agent's registry entry pins another CA
# (keep-certificate pairing, T-062): then against that CA alone, for that agent
# alone - never a bundle shared by every agent, so one agent's CA cannot vouch
# for another agent. $name is the agent's registry name; undef, or a name with
# no registry entry, uses the dispatcher's CA as before.
sub _build_ua ($config, $name = undef) {
    require LWP::UserAgent;
    require IO::Socket::SSL;
    require Exec::TLS;

    my %ca = (SSL_ca_file => $config->{ca}, SSL_ca => undef);
    if (defined(my $pem = _pinned_ca($config, $name))) {
        my $x509 = _x509_cached($pem)
            // die "the CA pinned for agent '$name' in the registry is unreadable\n";
        %ca = (SSL_ca_file => undef, SSL_ca => [ $x509 ]);
    }

    # LWP's ssl_opts hash does not pass SSL_cert_file/SSL_key_file through
    # to IO::Socket::SSL for client cert presentation. Set them as global
    # SSL defaults so every outbound connection uses the dispatcher cert.
    # Exec::TLS::hardening adds the shared cipher/version policy. The CA
    # options are set on every call (both of them), so a pinned CA from an
    # earlier call in this process never carries over.
    IO::Socket::SSL::set_defaults(
        SSL_cert_file    => $config->{cert},
        SSL_key_file     => $config->{key},
        %ca,
        SSL_verify_mode  => 0x01,
        Exec::TLS::hardening(),
    );

    my $ua = LWP::UserAgent->new(
        ssl_opts => {
            %ca,
            SSL_verify_mode => 0x01,
            verify_hostname => 0,   # verified by CA, not hostname
        },
        timeout => $config->{read_timeout} // $config->{timeout} // 60,
    );
    return $ua;
}

# The CA certificate (PEM) pinned in agent $name's registry entry, or undef
# when it has none (an ordinary agent of this dispatcher) or $name is not a
# registered agent.
sub _pinned_ca ($config, $name) {
    return unless defined $name && length $name;
    require Exec::Registry;
    return unless Exec::Registry::valid_agent_name($name);
    my $rec = eval {
        Exec::Registry::get_agent(hostname => $name, registry_dir => $config->{registry_dir})
    } or return;
    my $pem = $rec->{agent_ca};
    return (defined $pem && !ref $pem && length $pem) ? $pem : undef;
}

# A parsed CA certificate for SSL_ca, kept for the life of the process (the
# context that loads it takes its own reference).
my %X509_CACHE;
sub _x509_cached ($pem) {
    return $X509_CACHE{$pem} if $X509_CACHE{$pem};
    my $bio = Net::SSLeay::BIO_new(Net::SSLeay::BIO_s_mem()) or return;
    Net::SSLeay::BIO_write($bio, $pem);
    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);
    return $x509 ? ($X509_CACHE{$pem} = $x509) : undef;
}

# Returns true if the cert should be renewed.
# Renewal is due when remaining validity is less than half of cert_days.
# Returns false (safe default) if the expiry string cannot be parsed.
sub _renewal_due ($expiry_str, $cert_days) {
    my $expiry_epoch = Exec::CertInfo::expiry_epoch($expiry_str);
    return 0 unless defined $expiry_epoch;

    my $remaining  = $expiry_epoch - time();
    my $half_life  = ($cert_days / 2) * 86400;
    return $remaining < $half_life ? 1 : 0;
}

# Perform cert renewal for a single agent over the existing mTLS connection.
# POSTs /renew to get a CSR, signs it, POSTs /renew-complete to deliver.
# Updates the registry expiry on success. Dies on any failure.
sub _renew_one (%opts) {
    my $host   = $opts{host};
    my $port   = $opts{port};
    my $name   = $opts{name} // $host;   # registry key for the expiry update
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

    my $ua = _build_ua($config, $opts{name});

    # Request CSR from agent
    my $resp = $ua->post(
        "https://$host:$port/renew",
        'Content-Type' => 'application/json',
        Content        => encode_json({ reqid => $reqid }),
    );
    die "renew request failed: " . $resp->status_line unless $resp->is_success;

    my $data = _json_hash($resp->content)
        or die "invalid JSON in renew response";
    my $csr_pem = $data->{csr} or die "no CSR in renew response";

    # Sign the CSR, binding the subject CN to the agent's known identity (its
    # registry name == its cert CN by the pairing invariant). This stops a
    # compromised agent returning a CSR for a different identity and having it
    # signed - the renewal would then fail closed rather than mint a cert that
    # impersonates another host.
    my $cert_pem = Exec::CA::sign_csr(
        csr_pem     => $csr_pem,
        ca_dir      => $config->{ca_dir} // Exec::DispatcherConfig::conf_dir(),
        days        => $config->{cert_days} // 365,
        expected_cn => $name,
    );
    my $ca_pem = Exec::CA::read_ca_cert(
        ca_dir => $config->{ca_dir} // Exec::DispatcherConfig::conf_dir(),
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

    # Extract new expiry and update registry by the canonical name (not the
    # resolved connect address, which under lookup_by=ip would create a stray
    # IP-keyed record).
    my $expiry = _extract_expiry($cert_pem) // 'unknown';
    Exec::Registry::update_expiry(hostname => $name, expiry => $expiry,
        registry_dir => $config->{registry_dir});

    Exec::Log::log_action('INFO', {
        ACTION => 'renew-complete',
        TARGET => "$host:$port",
        REQID  => $reqid,
        EXPIRY => $expiry,
    });
}

# Extract notAfter date string from a PEM cert via openssl subprocess.
sub _extract_expiry ($cert_pem) {
    return Exec::CertInfo::expiry_from_pem($cert_pem);
}

1;
