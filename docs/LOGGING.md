---
title: ctrl-exec - Logging Reference
subtitle: Complete reference for structured syslog output from ctrl-exec and ctrl-exec-agent
brand: odcc
---

# ctrl-exec - Logging Reference

This document is the authoritative reference for every structured log line
emitted by `ctrl-exec` and `ctrl-exec-agent`. It is intended for operators
building log pipelines, alerting rules, SIEM integrations, or audit tooling.

For configuration reference, see REFERENCE.md. For alerting recommendations
and security-relevant actions, see SECURITY-OPERATIONS.md.


## Format Overview

Both binaries emit structured log lines as `key=value` pairs to syslog via
`Sys::Syslog`, using the `daemon` facility. `ACTION=` always appears first.
Remaining fields are in definition order for the emitting code path; their
presence varies by action.

Example lines as they appear in syslog:

```
Mar 13 12:00:01 host ctrl-exec[12345]: ACTION=dispatch SCRIPT=backup HOSTS=db-01,db-02 REQID=a1b2c3d4e5f60001
Mar 13 12:00:02 host ctrl-exec-agent[6789]: ACTION=run SCRIPT=backup EXIT=0 PEER=10.0.0.1 REQID=a1b2c3d4e5f60001
```

Syslog tag
: `ctrl-exec` for lines from the `ctrl-exec` binary and `ctrl-exec-api`.
  `ctrl-exec-agent` for lines from `ctrl-exec-agent`.

Facility
: `daemon` (numeric 3). Priority is `daemon.info`, `daemon.warning`, or
  `daemon.err` depending on severity.

`ACTION=`
: Always first. Identifies the event type. Every other field is
  action-specific.

`REQID=`
: A 16-character lowercase hex string generated per dispatch operation by
  `Engine::gen_reqid()`. The same REQID appears in both the ctrl-exec log
  and the corresponding agent log, making cross-host correlation possible
  with a single grep. Not present on all actions — see per-action field
  lists below.


## REQID Correlation

To trace a single operation across both sides:

```bash
grep 'REQID=a1b2c3d4e5f60001' /var/log/syslog
```

On the ctrl-exec side, `ACTION=dispatch` is logged at the start of a
multi-host operation with a shared REQID. Each per-host `ACTION=run` or
`ACTION=ping` uses the same REQID. On the agent side, `ACTION=run` and
`ACTION=ping` are logged with the same REQID when the operation completes.

There is no `ACTION=run` entry on the agent side at the start of script
execution — only at completion. If the ctrl-exec's `read_timeout` fires
before the script exits, the ctrl-exec logs an error, but no agent log
entry appears until the script eventually exits. An operator cannot
determine from syslog alone that a script is currently running.


## Remote Forwarding

ctrl-exec writes to the local syslog socket via `Sys::Syslog`; getting those
lines to a central collector is a syslog-daemon concern, not an application
one. Because everything is emitted on the `daemon` facility (see *Format
Overview*), a single selector — `daemon.*` — captures all ctrl-exec,
ctrl-exec-api, and ctrl-exec-agent logging. The `REQID` correlation field is
part of the message text, so it survives forwarding intact: a `grep REQID=…`
at the collector traces an operation across every host that forwarded to it.

On a bare-metal or VM install there is nothing ctrl-exec-specific to do — the
host's existing rsyslog or syslog-ng forwards `daemon.*` like any other
facility. Point it at the collector and ctrl-exec logs follow.

### TLS forwarding with rsyslog

`Sys::Syslog` has no native TLS, so when the transport to the collector must
be encrypted, forward through rsyslog rather than connecting from the
application. rsyslog reads the local socket and forwards `daemon.*` over TLS,
and also buffers on disk if the collector is briefly unreachable. The
forwarding action:

```
global(
    defaultNetstreamDriver="gtls"
    defaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
)

daemon.* action(
    type="omfwd"
    target="<collector-host>"
    port="6514"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="<collector-host>"
    template="RSYSLOG_SyslogProtocol23Format"
)
```

Port 6514 is the syslog-over-TLS port. `x509/name` validates the collector's
certificate against the system CA bundle and checks its name, so a
publicly-trusted (e.g. Let's Encrypt) collector certificate needs no custom
CA or client certificate when the collector is configured for server-only
(`anon`) authentication.

In containers there is no host syslog daemon, so rsyslog is run inside the
image and configured from `SYSLOG_HOST` / `SYSLOG_PORT` on start. See
`DOCKER.md` (*Remote syslog forwarding*) for the dispatcher and agent
container setup, including why an in-container rsyslog is used in preference
to a direct connection.


## ctrl-exec-Side Actions

These actions are emitted by `bin/ctrl-exec` and `bin/ctrl-exec-api` via
`Exec::Engine`, `Exec::Auth`, `Exec::Lock`, and
`Exec::Log`.

### dispatch

Emitted at the start of a multi-host `run` operation, before any per-host
connection is attempted.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `dispatch` |
| SCRIPT | string | Script name from the allowlist |
| HOSTS | string | Comma-separated list of target host strings |
| REQID | hex | Request ID shared across all per-host operations |

```
ACTION=dispatch SCRIPT=backup HOSTS=db-01,db-02 REQID=a1b2c3d4e5f60001
```

### ping (success)

Emitted on successful response to a `/ping` request to one agent.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `ping` |
| TARGET | string | `host:port` of the agent |
| RESULT | string | `ok` |
| RTT | string | Round-trip time, e.g. `42ms` |
| REQID | hex | Request ID |

```
ACTION=ping TARGET=web-01:7443 RESULT=ok RTT=42ms REQID=a1b2c3d4e5f60001
```

### ping (error)

Emitted when a `/ping` request fails or the agent returns an error response.

Priority
: ERR

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `ping` |
| TARGET | string | `host:port` |
| ERROR | string | Error description |
| RTT | string | Round-trip time at point of failure |
| REQID | hex | Request ID |

```
ACTION=ping TARGET=web-01:7443 ERROR="read timeout after 60s" RTT=60001ms REQID=a1b2c3d4e5f60001
```

### run (success)

Emitted when a script completes on one agent and a response is received by
the ctrl-exec. Logged once per host, regardless of the script's exit code.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `run` |
| SCRIPT | string | Script name |
| TARGET | string | `host:port` |
| EXIT | integer | Script exit code |
| RTT | string | Round-trip time including script execution |
| REQID | hex | Request ID |

```
ACTION=run SCRIPT=backup TARGET=db-01:7443 EXIT=0 RTT=1203ms REQID=a1b2c3d4e5f60001
```

### run (error)

Emitted when the ctrl-exec cannot reach the agent, the connection fails, or
the response cannot be parsed. The script may or may not have run.

Priority
: ERR

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `run` |
| SCRIPT | string | Script name |
| TARGET | string | `host:port` |
| ERROR | string | Error description |
| RTT | string | Round-trip time at point of failure |
| REQID | hex | Request ID |

```
ACTION=run SCRIPT=backup TARGET=db-01:7443 ERROR="read timeout after 60s" RTT=60001ms REQID=a1b2c3d4e5f60001
```

### lock-acquire

Emitted in the ctrl-exec child process when a concurrency lock is
successfully acquired for a `host:script` pair before dispatch.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `lock-acquire` |
| HOST | string | Agent hostname |
| SCRIPT | string | Script name |

```
ACTION=lock-acquire HOST=db-01 SCRIPT=backup
```

For a multi-host dispatch, one `lock-acquire` entry is emitted per host
locked. A dispatch to `db-01` and `db-02` produces two `lock-acquire`
lines. The corresponding `lock-release` names all released hosts in a
single entry.

### lock-release

Emitted when all locks held for a dispatch operation are released after
results have been collected.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `lock-release` |
| HOSTS | string | Comma-separated list of hosts whose locks are released |
| SCRIPT | string | Script name |

```
ACTION=lock-release HOSTS=db-01,db-02 SCRIPT=backup
```

### lock-conflict

Emitted when a dispatch is rejected because the script is already locked
on one or more of the requested hosts.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `lock-conflict` |
| CONFLICTS | string | Comma-separated `host:script` pairs that are locked |

```
ACTION=lock-conflict CONFLICTS=db-01:backup,db-02:backup
```

### renew

Emitted at the start of an automatic agent cert renewal operation. Renewal
is triggered from `ping_all` when a cert is past half-life.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `renew` |
| TARGET | string | `host:port` |
| STATUS | string | `starting` |
| REQID | hex | Request ID for this renewal |

```
ACTION=renew TARGET=web-01:7443 STATUS=starting REQID=b2c3d4e5f6a70002
```

If renewal fails, an ERR entry is emitted instead with an `ERROR` field
and no `STATUS`.

### renew-complete

Emitted when agent cert renewal completes successfully and the new expiry
has been recorded in the registry.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `renew-complete` |
| TARGET | string | `host:port` |
| EXPIRY | string | New cert expiry as returned by openssl (e.g. `Mar 13 12:00:00 2027 GMT`) |
| REQID | hex | Request ID |

```
ACTION=renew-complete TARGET=web-01:7443 EXPIRY="Mar 13 12:00:00 2027 GMT" REQID=b2c3d4e5f6a70002
```

### capabilities (error)

Emitted when a capabilities query to an agent fails.

Priority
: ERR

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `capabilities` |
| TARGET | string | `host:port` |
| ERROR | string | Error description |
| RTT | string | Round-trip time |

```
ACTION=capabilities TARGET=web-01:7443 ERROR="connection refused" RTT=5ms
```

On success, `capabilities` is logged at INFO with `SCRIPTS` (count) and
`RTT` in place of `ERROR`.

### auth (ctrl-exec-side)

The ctrl-exec-side auth hook is called before every `run` and `ping`
operation. Results are logged by `Exec::Auth`. All variants use the
`auth` action.

Priority
: INFO (pass), WARNING (deny), ERR (error)

Fields present on all auth log lines

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `auth` |
| RESULT | string | `pass`, `deny`, or `error` |
| AUTHACTION | string | The ctrl-exec operation: `run` or `ping` |
| USER | string | Username from the request, or `(none)` if absent |
| IP | string | Source IP (`127.0.0.1` for CLI callers) |

Additional fields by variant

`RESULT=pass, REASON=no-hook-cli`
: No hook configured; caller is the CLI. CLI access is gated by system
  permissions. Unconditional pass.

`RESULT=pass, REASON=no-hook-allow`
: No hook configured; `api_auth_default = allow` in `ctrl-exec.conf`.
  API caller authorised without a hook.

`RESULT=deny, REASON=no-hook-deny`
: No hook configured; `api_auth_default = deny` (the default). All API
  requests are rejected until a hook is configured.

`RESULT=pass` (hook ran, exit 0)
: Hook executed and returned 0. No REASON field.

`RESULT=deny, REASON=<text>` (hook ran, non-zero exit)
: Hook returned a non-zero exit code. REASON values: `denied` (exit 1),
  `bad credentials` (exit 2), `insufficient privilege` (exit 3), or
  `hook exited N` for other exit codes.

`RESULT=error, REASON=hook-not-executable`
: The configured hook file is missing or not executable. Additional field:
  `HOOK=<path>`. Priority is ERR.

```
ACTION=auth RESULT=pass AUTHACTION=run USER=alice IP=127.0.0.1
ACTION=auth RESULT=deny REASON=denied AUTHACTION=run USER=alice IP=127.0.0.1
ACTION=auth RESULT=error REASON=hook-not-executable HOOK=/etc/ctrl-exec/auth-hook IP=127.0.0.1
```

### pair-denied (ctrl-exec-side)

Emitted by the ctrl-exec binary when a pairing request approval is
explicitly denied.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-denied` |
| REQID | hex | Pairing request ID |

### pair-timeout (ctrl-exec-side)

Emitted in background pairing mode when the timeout expires before approval
arrives.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-timeout` |
| REQID | hex | Pairing request ID |

### pairing-mode-start

Emitted when `ctrl-exec pairing-mode` starts and the listener is ready
on port 7444.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pairing-mode-start` |
| PORT | integer | Port the pairing listener is bound to |

```
ACTION=pairing-mode-start PORT=7444
```

### pairing-mode-stop

Emitted when `ctrl-exec pairing-mode` is stopped (Ctrl-C, SIGTERM, or
the operator types `quit`).

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pairing-mode-stop` |

```
ACTION=pairing-mode-stop
```

### pair-request

Emitted when an agent submits a pairing CSR and the request is accepted
into the queue.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-request` |
| AGENT | string | Hostname supplied by the agent |
| IP | string | Source IP of the agent connection |
| REQID | hex | Pairing request ID |
| STATUS | string | `pending` |

```
ACTION=pair-request AGENT=web-01 IP=10.0.0.5 REQID=a1b2c3d4e5f60001 STATUS=pending
```

### pair-reject

Emitted when an incoming pairing connection is refused because the queue
is at the `pairing_max_queue` limit. The connection is closed immediately.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-reject` |
| IP | string | Source IP of the rejected connection |
| REASON | string | `queue-full` |

```
ACTION=pair-reject IP=10.0.0.5 REASON=queue-full
```

### pair-approve

Emitted when the operator approves a pending pairing request. The signed
cert is written for the waiting agent connection to pick up.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-approve` |
| AGENT | string | Hostname of the approved agent |
| REQID | hex | Pairing request ID |

```
ACTION=pair-approve AGENT=web-01 REQID=a1b2c3d4e5f60001
```

### pair-deny

Emitted when the operator explicitly denies a pending pairing request.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-deny` |
| AGENT | string | Hostname of the denied agent |
| REQID | hex | Pairing request ID |

```
ACTION=pair-deny AGENT=web-01 REQID=a1b2c3d4e5f60001
```

### unpair

Emitted when an agent is removed from the registry via `ctrl-exec unpair`.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `unpair` |
| AGENT | string | Hostname of the removed agent |
| EXPIRY | string | Cert expiry date — the window during which the cert remains valid |

```
ACTION=unpair AGENT=db-01 EXPIRY="Mar 13 12:00:00 2026 GMT"
```


## API-Side Actions

These actions are emitted by `bin/ctrl-exec-api` via `Exec::API`
under the syslog tag `ctrl-exec`.

### api-start

Emitted once when `ctrl-exec-api` starts and the HTTP server is ready.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `api-start` |
| PORT | integer | Port the API is listening on |
| BIND | string | Address the API is bound to (e.g. `127.0.0.1` or `0.0.0.0`) |
| TLS | string | `yes` if TLS is active, `no` for plain HTTP |

```
ACTION=api-start PORT=7445 BIND=127.0.0.1 TLS=no
```

### api-stop

Emitted when `ctrl-exec-api` receives SIGTERM or SIGINT and exits cleanly.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `api-stop` |

```
ACTION=api-stop
```

### api-request

Emitted for every incoming HTTP request, before auth is evaluated.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `api-request` |
| METHOD | string | HTTP method (`GET`, `POST`) |
| PATH | string | Request path (e.g. `/run`, `/ping`) |
| PEER | string | Source IP of the caller |
| LEN | integer | `Content-Length` of the request body (0 for GET) |

```
ACTION=api-request METHOD=POST PATH=/run PEER=127.0.0.1 LEN=87
```

### run-store-fail

Emitted when the result of a `/run` operation cannot be written to the
result store at `/var/lib/ctrl-exec/runs/`. The run itself succeeded;
only the stored result for `GET /status/{reqid}` is unavailable.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `run-store-fail` |
| REQID | hex | Request ID of the affected run |
| ERROR | string | Error description |

```
ACTION=run-store-fail REQID=a1b2c3d4e5f60001 ERROR="No space left on device"
```


## Agent-Side Actions

These actions are emitted by `bin/ctrl-exec-agent` and the modules it
calls: `Exec::Auth`, `Exec::Agent::Config`,
`Exec::RateLimit`, and `Exec::Agent::Runner`.

### start

Emitted once when the agent starts and begins listening.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `start` |
| PORT | integer | Port the agent is listening on |

```
ACTION=start PORT=7443
```

### ping (agent-side)

Emitted on each successful `/ping` request received and processed by the
agent.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `ping` |
| PEER | string | IP address of the connecting ctrl-exec |
| REQID | hex | Request ID from the ctrl-exec |

```
ACTION=ping PEER=10.0.0.1 REQID=a1b2c3d4e5f60001
```

### run (agent-side)

Emitted when a script exits. Logged at script completion, not at the start
of execution.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `run` |
| SCRIPT | string | Script name from the allowlist |
| EXIT | integer | Script exit code |
| PEER | string | IP address of the connecting ctrl-exec |
| REQID | hex | Request ID from the ctrl-exec |

```
ACTION=run SCRIPT=backup EXIT=0 PEER=10.0.0.1 REQID=a1b2c3d4e5f60001
```

A non-zero `EXIT` value is still logged at INFO priority — the agent
reports what the script returned, not whether the operator considers it a
failure. Alert on the `EXIT` value itself, not on the priority level. The
agent-side log is the authoritative source for exit codes; the
ctrl-exec-side `run` entry may show a transport-level error in the
`ERROR` field instead of the script's exit code if the connection was
interrupted.

### auth (agent-side)

The agent-side auth hook is called after allowlist validation on every
`/run` request. The same action name and field structure as the
ctrl-exec-side auth log. See the auth description under ctrl-exec-Side
Actions for the full field and variant reference.

On the agent side:

- `AUTHACTION` is always `run` (the agent hook is not called for `/ping`)
- `IP` is the ctrl-exec's source IP, not `127.0.0.1`
- `REASON=no-hook-cli` does not occur — the agent has no CLI caller path

### deny

Emitted when a `/run` request is rejected. Two distinct causes produce this
action: the script name is not in the allowlist, or the agent-side auth
hook denied the request.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `deny` |
| SCRIPT | string | Script name from the request |
| PEER | string | IP address of the connecting ctrl-exec |
| REQID | hex | Request ID |
| REASON | string | Present only when denied by auth hook; contains the hook denial reason |

Allowlist denial (no REASON field):

```
ACTION=deny SCRIPT=unknown-script PEER=10.0.0.1 REQID=a1b2c3d4e5f60001
```

Auth hook denial (REASON field present):

```
ACTION=deny REASON=denied SCRIPT=backup PEER=10.0.0.1 REQID=a1b2c3d4e5f60001
```

To distinguish between the two in log processing: allowlist denials have
no REASON field; hook denials always have one.

### serial-reject

Emitted when the ctrl-exec's cert serial does not match the stored value
on the agent. Applied to both `/run` and `/ping` requests.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `serial-reject` |
| PEER | string | IP address of the connecting host |
| REQID | hex | Request ID, or `(none)` if not yet read from the request body |

```
ACTION=serial-reject PEER=10.0.0.1 REQID=(none)
```

This should not occur during normal operation after a complete rotation
broadcast. Treat as a security signal requiring investigation.

### revoked-cert

Emitted when a connecting peer presents a certificate whose serial appears
in the agent's revocation list (`revoked_serials`).

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `revoked-cert` |
| PEER | string | IP address of the connecting host |
| SERIAL | string | Lowercase hex serial of the revoked cert |

```
ACTION=revoked-cert PEER=10.0.0.1 SERIAL=deadbeef01234567
```

### tls-failure

Emitted when a TLS handshake fails. The peer may be an unauthenticated
host, a host with an expired cert, or a host whose cert was not signed by
the deployment CA.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `tls-failure` |
| PEER | string | IP address of the connecting host (pre-handshake) |
| REASON | string | SSL error string from `IO::Socket::SSL` |

```
ACTION=tls-failure PEER=203.0.113.5 REASON="SSL accept attempt failed error:..."
```

TLS failures also update the probe rate counter for the peer IP. If the
probe threshold is crossed, a subsequent `rate-block` is emitted.

### accept-fatal

Emitted when the server socket's `accept()` call returns a fatal error
(not a TLS handshake failure). A fatal accept error causes the agent's
main loop to exit.

Priority
: ERR

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `accept-fatal` |
| PEER | string | Peer address at point of failure, or `unknown` |
| REASON | string | System error string from `$!` |

```
ACTION=accept-fatal PEER=unknown REASON="Bad file descriptor"
```

### ip-block

Emitted when a connecting IP is not in the `allowed_ips` list configured
in `agent.conf`. The connection is dropped before the TLS handshake.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `ip-block` |
| PEER | string | IP address of the blocked connection |

```
ACTION=ip-block PEER=203.0.113.5
```

### rate-block

Emitted when a source IP is blocked by the volume or probe rate limiter.
One entry is logged when the threshold is first crossed; subsequent
connections from the same IP during the block window are silently dropped
without additional log entries.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `rate-block` |
| PEER | string | IP address of the blocked source |
| REASON | string | `volume` or `probe` |

```
ACTION=rate-block PEER=10.0.0.1 REASON=volume
ACTION=rate-block PEER=10.0.0.1 REASON=probe
```

Volume threshold: more than `rate_limit_volume` connections within the
volume window. Default: 10 connections in 60 seconds, 5-minute block.

Probe threshold: more than `rate_limit_probe` TLS handshake failures within
the probe window. Default: 3 failures in 600 seconds, 1-hour block.

### rate-evict

Emitted when an entry is removed from the in-memory rate limit table to
make room for a new source IP (LRU eviction). The rate limit table has a
maximum of 1000 entries. The evicted entry is the one with the earliest
`blocked_until` timestamp (or no block at all).

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `rate-evict` |
| COUNT | integer | The table capacity ceiling that triggered eviction (always 1000) |

```
ACTION=rate-evict COUNT=1000
```

### capabilities (agent-side, deny)

Emitted when a `/capabilities` request is rejected. Two variants exist.

`capabilities-deny` — serial mismatch:

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `capabilities-deny` |
| PEER | string | IP address of the connecting host |
| PEER_SERIAL | string | Serial of the connecting cert |
| REASON | string | `serial-mismatch` |

`capabilities-deny` — auth hook denied:

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `capabilities-deny` |
| PEER | string | IP address |
| REASON | string | Hook denial reason |

```
ACTION=capabilities-deny PEER=10.0.0.1 PEER_SERIAL=deadbeef REASON=serial-mismatch
ACTION=capabilities-deny PEER=10.0.0.1 REASON=denied
```

### capabilities-no-serial

Emitted when the agent has no stored ctrl-exec serial and the serial check
on `/capabilities` is therefore skipped. The request proceeds but the
restriction is not enforced.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `capabilities-no-serial` |
| PEER | string | IP address |
| REASON | string | `no ctrl-exec serial stored - re-pair to enable restriction` |

```
ACTION=capabilities-no-serial PEER=10.0.0.1 REASON="no ctrl-exec serial stored - re-pair to enable restriction"
```

Re-pair the agent to write the ctrl-exec serial and enable the restriction.

### capabilities (agent-side, success)

Emitted when a `/capabilities` request is processed and a response is sent.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `capabilities` |
| PEER | string | IP address |
| SCRIPTS | integer | Number of scripts in the allowlist response |

```
ACTION=capabilities PEER=10.0.0.1 SCRIPTS=5
```

### pair-complete

Emitted by the agent when a pairing request is approved and the certificate
is stored successfully.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-complete` |
| STATUS | string | `approved` |
| DISPATCHER | string | Hostname or IP of the ctrl-exec that was contacted |

```
ACTION=pair-complete STATUS=approved DISPATCHER=ctrl-exec.example.com
```

### pair-denied (agent-side)

Emitted in background pairing mode when the ctrl-exec explicitly denies
the request.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-denied` |
| REQID | hex | Pairing request ID |
| REASON | string | Denial reason from the ctrl-exec response |

```
ACTION=pair-denied REQID=00c9845e0001 REASON=denied
```

### pair-timeout (agent-side)

Emitted in background pairing mode when the timeout expires before approval
arrives.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `pair-timeout` |
| REQID | hex | Pairing request ID |

```
ACTION=pair-timeout REQID=00c9845e0001
```

### config-warn

Emitted at startup (or SIGHUP reload) when `agent.conf` or `scripts.conf`
contains an entry that is invalid but non-fatal. The problematic entry is
skipped and loading continues.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `config-warn` |
| ENTRY or KEY | string | The offending entry or config key |
| MSG | string | Description of the problem |

Two variants:

`allowed_ips` entry with an unsupported CIDR prefix length:

```
ACTION=config-warn ENTRY=10.0.0.0/20 MSG="unsupported prefix length"
```

`rate_limit_volume` or `rate_limit_probe` with invalid format:

```
ACTION=config-warn KEY=rate_limit_volume MSG="invalid format, expected limit/window/block - using defaults"
```

### stdin-timeout

Emitted when the agent times out writing the JSON context to a script's
stdin pipe. The script did not consume the pipe buffer within
`stdin_timeout` seconds (default 10). The write end is closed, delivering
EOF to the script. The script continues running.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `stdin-timeout` |
| BYTES | integer | Number of bytes that were not written at timeout |

```
ACTION=stdin-timeout BYTES=1024
```

Occasional occurrences from scripts that discard stdin are harmless.
Repeated occurrences from the same script indicate the script is hanging
before reading stdin or the context payload is unusually large.

### revoked-serials-absent

Emitted at agent startup when the file specified by `revoked_serials` in
`agent.conf` does not exist. The agent proceeds normally, treating the
absent file as an empty revocation list.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `revoked-serials-absent` |
| PATH | string | The configured path that was not found |
| REASON | string | `file not found - no serials revoked` |

```
ACTION=revoked-serials-absent PATH=/etc/ctrl-exec-agent/revoked-serials REASON="file not found - no serials revoked"
```

This is informational. An absent file is the expected state on a freshly
paired agent. `config-warn` is produced only for malformed entries within
the file if it does exist.


## Rotation Actions

These actions are emitted by `Exec::Rotation` under the syslog tag
`ctrl-exec`. They cover the ctrl-exec cert lifecycle: expiry checking,
rotation, and serial broadcast to agents.

### cert-check

Emitted each time the internal check loop evaluates the ctrl-exec cert
expiry. Frequency is controlled by `cert_check_interval` (default 4 hours).

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `cert-check` |
| DAYS_LEFT | integer | Days remaining on the ctrl-exec cert |
| THRESHOLD | integer | `cert_renewal_days` threshold from config |

```
ACTION=cert-check DAYS_LEFT=120 THRESHOLD=90
```

### cert-renewal-start

Emitted when the cert expiry check finds the cert within the renewal
threshold and initiates rotation.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `cert-renewal-start` |
| DAYS_LEFT | integer | Days remaining at the point rotation was triggered |

```
ACTION=cert-renewal-start DAYS_LEFT=85
```

### cert-rotated

Emitted on successful completion of a cert rotation. The new cert has been
written and all agents have been marked pending for serial broadcast.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `cert-rotated` |
| OLD_SERIAL | string | Lowercase hex serial of the previous cert |
| NEW_SERIAL | string | Lowercase hex serial of the new cert |
| OVERLAP_EXPIRES | string | ISO 8601 UTC timestamp when the overlap window closes |
| AGENTS | integer | Number of agents marked pending for serial broadcast |

```
ACTION=cert-rotated OLD_SERIAL=09abcdef NEW_SERIAL=0a1b2c3d OVERLAP_EXPIRES=2026-04-13T14:30:00Z AGENTS=12
```

### cert-rotation-fail

Emitted when cert generation fails during a rotation attempt.

Priority
: ERR

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `cert-rotation-fail` |
| ERROR | string | Error description from the failing operation |

```
ACTION=cert-rotation-fail ERROR="openssl x509 failed: ..."
```

### serial-broadcast

Emitted when `broadcast_serial` begins dispatching `update-ctrl-exec-serial`
to pending agents.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `serial-broadcast` |
| HOSTS | string | Comma-separated list of agents receiving the broadcast |
| SERIAL | string | The serial being broadcast |

```
ACTION=serial-broadcast HOSTS=web-01,db-01,db-02 SERIAL=0a1b2c3d
```

### serial-confirmed

Emitted for each agent that successfully receives and acknowledges the
new serial via `update-ctrl-exec-serial`.

Priority
: INFO

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `serial-confirmed` |
| AGENT | string | Hostname of the confirming agent |

```
ACTION=serial-confirmed AGENT=web-01
```

### serial-broadcast-fail

Emitted for each agent where the serial broadcast attempt fails (non-zero
exit from `update-ctrl-exec-serial` or connection error).

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `serial-broadcast-fail` |
| AGENT | string | Hostname of the agent that could not be reached |
| ERROR | string | Error description or exit code |

```
ACTION=serial-broadcast-fail AGENT=db-02 ERROR="exit 1"
```

Failed agents are retried on the next check loop iteration, until the
overlap window expires.

### serial-stale

Emitted when an agent's overlap window expires without serial confirmation.
The agent's registry status is updated to `stale`. Re-pairing is required
to restore normal operation for that agent.

Priority
: WARNING

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `serial-stale` |
| AGENT | string | Hostname of the agent marked stale |
| REASON | string | `overlap window expired without confirmation` |

```
ACTION=serial-stale AGENT=db-02 REASON="overlap window expired without confirmation"
```

### rotation-state-corrupt

Emitted when `rotation.json` exists but cannot be parsed as valid JSON.
The rotation state is unreadable; manual intervention is required.

Priority
: ERR

Fields

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | `rotation-state-corrupt` |
| PATH | string | Path to the corrupt file |
| ERROR | string | JSON parse error |
| REASON | string | `JSON parse failed - rotation state unreadable` |

```
ACTION=rotation-state-corrupt PATH=/var/lib/ctrl-exec/rotation.json ERROR="..." REASON="JSON parse failed - rotation state unreadable"
```


## Field Glossary

| Field | Type | Description |
| --- | --- | --- |
| ACTION | string | Event type identifier. Always first. |
| AGENT | string | Agent hostname (used in `unpair`, `pair-approve`, `pair-deny`, `serial-confirmed`, `serial-stale`) |
| AGENTS | integer | Count of agents marked pending for serial broadcast (used in `cert-rotated`) |
| AUTHACTION | string | ctrl-exec operation being authorised: `run`, `ping`, or `api` |
| BIND | string | Network address the API is bound to (used in `api-start`) |
| BYTES | integer | Byte count (used in `stdin-timeout`) |
| CONFLICTS | string | Comma-separated `host:script` pairs in lock conflict |
| COUNT | integer | Table capacity ceiling that triggered eviction (used in `rate-evict`) |
| DAYS_LEFT | integer | Days remaining on the ctrl-exec cert (used in `cert-check`, `cert-renewal-start`) |
| DISPATCHER | string | ctrl-exec hostname as contacted by agent during pairing |
| ENTRY | string | Offending config entry (used in `config-warn`) |
| ERROR | string | Error description for failure actions |
| EXIT | integer | Script exit code |
| EXPIRY | string | Cert expiry date string as returned by openssl |
| HOOK | string | Path to the auth hook (used in `auth` error variant) |
| HOST | string | Single agent hostname (used in `lock-acquire`) |
| HOSTS | string | Comma-separated agent hostname list |
| IP | string | Source IP address (used in `pair-request`, `pair-reject`, and `auth` log lines) |
| KEY | string | Config key name (used in `config-warn`) |
| LEN | integer | Content-Length of an API request body (used in `api-request`) |
| METHOD | string | HTTP method (used in `api-request`) |
| MSG | string | Human-readable description of a warning |
| NEW_SERIAL | string | Lowercase hex serial of the new ctrl-exec cert (used in `cert-rotated`) |
| OLD_SERIAL | string | Lowercase hex serial of the previous ctrl-exec cert (used in `cert-rotated`) |
| OVERLAP_EXPIRES | string | ISO 8601 UTC timestamp when the rotation overlap window closes |
| PATH | string | HTTP request path or filesystem path depending on action |
| PEER | string | IP address of the remote party (ctrl-exec connecting to agent, or agent connecting to ctrl-exec) |
| PEER_SERIAL | string | Lowercase hex cert serial of the connecting peer |
| PORT | integer | Listening port number |
| REASON | string | Textual description of a denial, error, or warning |
| REQID | hex | 16-character lowercase hex request ID |
| RESULT | string | Outcome of an operation: `ok`, `pass`, `deny`, `error` |
| RTT | string | Round-trip time in milliseconds, e.g. `42ms` |
| SCRIPT | string | Script name from the allowlist |
| SCRIPTS | integer | Count of scripts in a capabilities response |
| SERIAL | string | Lowercase hex cert serial (used in `revoked-cert`, `serial-broadcast`) |
| STATUS | string | State indicator: `ok`, `starting`, `approved`, `pending`, etc. |
| TARGET | string | `host:port` of the agent as addressed by the ctrl-exec |
| THRESHOLD | integer | `cert_renewal_days` value from config (used in `cert-check`) |
| TLS | string | `yes` or `no` indicating TLS state of the API listener |
| USER | string | Username from the request, or `(none)` |


## Priority Levels

| Priority | Syslog level | Used for |
| --- | --- | --- |
| INFO | `daemon.info` | Normal operations: `start`, `run`, `ping`, `dispatch`, `lock-acquire`, `lock-release`, `renew`, `renew-complete`, `auth` pass, `pair-complete`, `pair-approve`, `pair-deny`, `pair-request`, `pair-reject`, `pairing-mode-start`, `pairing-mode-stop`, `capabilities` success, `rate-evict`, `unpair`, `api-start`, `api-stop`, `api-request`, `cert-check`, `cert-renewal-start`, `cert-rotated`, `serial-broadcast`, `serial-confirmed`, `revoked-serials-absent` |
| WARNING | `daemon.warning` | Security and access events requiring attention: `deny`, `serial-reject`, `revoked-cert`, `tls-failure`, `ip-block`, `rate-block`, `capabilities-deny`, `capabilities-no-serial`, `pair-denied`, `pair-timeout`, `lock-conflict`, `config-warn`, `stdin-timeout`, `auth` deny, `serial-broadcast-fail`, `serial-stale` |
| ERR | `daemon.err` | Failures requiring investigation: `accept-fatal`, `renew` failure, `capabilities` error, `ping` error, `run` error, `auth` error (hook not executable), `cert-rotation-fail`, `rotation-state-corrupt`, `run-store-fail` |


## Alert Pattern Reference

The following patterns are recommended starting points for alerting rules.
Match against the `ACTION=` field after the syslog tag. For normal monitoring,
filter to WARNING and ERR priority and reserve INFO for REQID-based audit
traces — high-volume fleets will see significant INFO traffic from `run`,
`ping`, and `dispatch` on every operation.

Security events

| Pattern | Meaning | Response |
| --- | --- | --- |
| `ACTION=rate-block REASON=volume` | Source IP exceeded connection volume threshold | Investigate source IP; sustained occurrences indicate scanning or connection flooding |
| `ACTION=rate-block REASON=probe` | Source IP exceeded TLS handshake failure threshold | Investigate source IP; consistent probe failures indicate certificate probing or brute-force attempts |
| `ACTION=serial-reject` | ctrl-exec cert serial mismatch on agent | Check rotation broadcast status; run `ctrl-exec serial-status`; should not occur during normal post-rotation operation |
| `ACTION=revoked-cert` | Revoked cert presented to agent | Treat as a security event; investigate source IP immediately |
| `ACTION=ip-block` | Connection from IP outside `allowed_ips` | Review `allowed_ips` config; unexpected occurrences indicate traffic from an unrecognised source |
| `ACTION=deny` (repeated, same PEER) | Script not in allowlist or hook denying repeatedly | Check agent allowlist; may indicate misconfiguration or probing for available scripts |
| `ACTION=capabilities-deny REASON=serial-mismatch` | Capabilities restricted by serial check failing | Check rotation state via `ctrl-exec serial-status`; re-pair if serial is permanently stale |

Execution failures

| Pattern | Meaning | Response |
| --- | --- | --- |
| `ACTION=run EXIT=<non-zero>` (agent-side) | Script exited with a failure code | The non-zero exit is logged at INFO priority on both sides; correlate with REQID to find output; check script behaviour |
| `ACTION=run ERROR=` (ctrl-exec-side) | ctrl-exec could not reach agent or parse response | Check agent reachability and cert validity |
| `ACTION=ping ERROR=` | Ping failed | Agent unreachable or cert issue; cert renewal will not trigger until ping succeeds |
| `ACTION=renew ERROR=` | Cert renewal failed | Check agent connectivity; cert will expire if renewals continue to fail |
| `ACTION=cert-rotation-fail` | ctrl-exec cert rotation failed | Investigate immediately; rotation retried on next check interval |

Rotation events

| Pattern | Meaning | Response |
| --- | --- | --- |
| `ACTION=serial-broadcast-fail` (for same AGENT, repeated) | Agent not receiving serial update | Check agent connectivity; agent will be marked stale after overlap window expires |
| `ACTION=serial-stale` | Agent overlap window expired without confirmation | Re-pair the agent; it will reject `/capabilities` from the current ctrl-exec cert until re-paired |
| `ACTION=rotation-state-corrupt` | `rotation.json` unreadable | Manual intervention required; rotation state must be restored before the next rotation attempt |
| All agents `ACTION=serial-reject` simultaneously after rotation | Rotation broadcast failed or cert not synced across HA nodes | Run `ctrl-exec serial-status` and `ctrl-exec rotate-cert` immediately |

Configuration problems

| Pattern | Meaning | Response |
| --- | --- | --- |
| `ACTION=config-warn` | Invalid config entry at load time | Review `agent.conf`; fix or remove the offending entry; should not occur in a healthy deployment after initial setup |
| `ACTION=accept-fatal` | Agent main loop exiting | Agent will stop serving; investigate and restart immediately |
| `ACTION=auth RESULT=error REASON=hook-not-executable` | Auth hook missing or not executable | Fix hook path and permissions; all requests are failing until resolved |
| `ACTION=capabilities-no-serial` | Agent lacks stored ctrl-exec serial | Re-pair agent to enable serial-based restriction on `/capabilities` |
| `ACTION=run-store-fail` | API result cannot be stored | Check disk space on ctrl-exec host; `GET /status/{reqid}` will return 404 for affected requests |

Pairing events

| Pattern | Meaning | Response |
| --- | --- | --- |
| `ACTION=pair-approve` | Operator approved a pairing request | Informational; confirm expected agent if unattended |
| `ACTION=pair-complete` | Agent stored the signed cert | Informational; confirm expected if unattended pairing |
| `ACTION=pair-denied` (agent-side) | Pairing request denied | Confirm intentional; re-run `request-pairing` if denial was in error |
| `ACTION=pair-timeout` | Pairing approval window expired | Re-run `request-pairing`; increase `--timeout` if approval latency is high |
| `ACTION=pair-reject REASON=queue-full` | Pairing queue at capacity | Review pending requests via `ctrl-exec list-requests`; deny stale entries to free queue |
| `ACTION=stdin-timeout` (repeated, same SCRIPT) | Script not consuming stdin context | Review script startup behaviour; add `exec 0</dev/null` if stdin is not needed, or increase `stdin_timeout` in `agent.conf` |
