---
title: Logging Reference
subtitle: Every ACTION= value emitted by ctrl-exec-dispatcher and ctrl-exec-agent, with fields and alert patterns.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/LOGGING.md
current_page: /logging
---

# Log Format

All log lines follow `ACTION=value KEY=value KEY=value` with `ACTION` always first. Values containing spaces are quoted. Syslog facility is `daemon` throughout.

Syslog tags:

- `ctrl-exec-dispatcher` — emitted by both `ced` and `ctrl-exec-api`
- `ctrl-exec-agent` — emitted by `cea`

Every operation generates a 16-character cryptographically random request ID (`REQID`). The same `REQID` appears in both the dispatcher and agent log entries for the same operation, enabling cross-host correlation:

```bash
grep 'REQID=a1b2c3d4' /var/log/syslog
```

To filter to WARNING and above:

```bash
journalctl -u ctrl-exec-agent -p warning
journalctl -u ctrl-exec-dispatcher -p warning
```

# Remote Forwarding

Because everything is on the `daemon` facility, a single `daemon.*` selector captures all ctrl-exec logging, and the `REQID` field survives forwarding so an operation can be traced at a central collector. On bare metal the host's existing rsyslog/syslog-ng forwards `daemon.*` like any other facility — nothing ctrl-exec-specific is required.

`Sys::Syslog` has no native TLS, so when the link to the collector must be encrypted, forward through rsyslog rather than from the application:

```
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

In containers, rsyslog runs inside the image and is configured from `SYSLOG_HOST` / `SYSLOG_PORT` at start — see the Docker deployment guide for the dispatcher and agent setup.

# Dispatcher-Side Actions

| Action | Priority | Key Fields | When |
| --- | --- | --- | --- |
| `dispatch` | INFO | `HOSTS`, `SCRIPT`, `REQID` | Dispatch begins |
| `run` | INFO or ERR | `EXIT`, `SCRIPT`, `TARGET`, `RTT`, `REQID` | Script result received |
| `ping` | INFO or ERR | `TARGET`, `STATUS`, `RTT`, `REQID` | Ping result received |
| `lock-acquire` | INFO | `SCRIPT`, `HOST` | Concurrency lock taken |
| `lock-release` | INFO | `SCRIPT`, `HOSTS` | Lock released after results collected |
| `lock-conflict` | WARNING | `SCRIPT`, `HOSTS` | Dispatch rejected — script already running |
| `renew` | INFO | `TARGET`, `STATUS=starting`, `REQID` | Cert renewal triggered |
| `renew-complete` | INFO | `TARGET`, `EXPIRY`, `REQID` | Cert renewal complete |
| `auth` | INFO/WARNING/ERR | `RESULT`, `AUTHACTION`, `USER`, `IP` | Auth hook result |
| `pairing-mode-start` | INFO | `PORT` | Pairing listener ready |
| `pairing-mode-stop` | INFO | — | Pairing listener stopped |
| `pair-request` | INFO | `AGENT`, `IP`, `REQID`, `STATUS=pending` | Agent CSR received |
| `pair-reject` | INFO | `IP`, `REASON=queue-full` | Request refused — queue full |
| `pair-approve` | INFO | `AGENT`, `REQID` | Operator approved a request |
| `pair-deny` | INFO | `AGENT`, `REQID` | Operator denied a request |
| `unpair` | INFO | `AGENT`, `EXPIRY` | Agent removed from registry |
| `cert-check` | INFO | `DAYS_LEFT`, `THRESHOLD` | Internal expiry check |
| `cert-renewal-start` | INFO | `DAYS_LEFT` | Rotation threshold reached |
| `cert-rotated` | INFO | `OLD_SERIAL`, `NEW_SERIAL`, `OVERLAP_EXPIRES`, `AGENTS` | Rotation complete |
| `cert-rotation-fail` | ERR | `ERROR` | Rotation failed |
| `serial-broadcast` | INFO | `HOSTS`, `SERIAL` | Serial broadcast begins |
| `serial-confirmed` | INFO | `AGENT` | Agent confirmed new serial |
| `serial-broadcast-fail` | WARNING | `AGENT`, `ERROR` | Agent unreachable during broadcast |
| `serial-stale` | WARNING | `AGENT`, `REASON` | Overlap window expired without confirmation |

# API-Side Actions

| Action | Priority | Key Fields | When |
| --- | --- | --- | --- |
| `api-start` | INFO | `PORT`, `BIND`, `TLS` | API server ready |
| `api-stop` | INFO | — | API server exiting |
| `api-request` | INFO | `METHOD`, `PATH`, `PEER`, `LEN` | Incoming request (before auth) |
| `run-store-fail` | WARNING | `REQID`, `ERROR` | Run result could not be stored |

# Agent-Side Actions

| Action | Priority | Key Fields | When |
| --- | --- | --- | --- |
| `start` | INFO | `PORT` | Agent listening |
| `ping` | INFO | `PEER`, `REQID` | Ping processed |
| `run` | INFO | `SCRIPT`, `EXIT`, `PEER`, `REQID` | Script completed — non-zero EXIT is still INFO |
| `deny` | WARNING | `SCRIPT`, `PEER`, `REQID`, `REASON?` | Script not in allowlist, or hook denied |
| `auth` | INFO/WARNING/ERR | `RESULT`, `AUTHACTION`, `USER`, `IP` | Agent hook result |
| `serial-reject` | WARNING | `PEER`, `REQID` | dispatcher serial mismatch |
| `revoked-cert` | WARNING | `PEER`, `SERIAL` | Revoked cert presented |
| `tls-failure` | WARNING | `PEER`, `REASON` | TLS handshake failed |
| `ip-block` | WARNING | `PEER` | Source IP not in `allowed_ips` |
| `rate-block` | WARNING | `PEER`, `REASON` | Rate limit triggered — `REASON` is `volume` or `probe` |
| `rate-evict` | INFO | `COUNT` | Rate limit table at capacity (LRU eviction) |
| `capabilities-deny` | WARNING | `PEER`, `REASON` | Capabilities request rejected |
| `accept-fatal` | ERR | `PEER`, `REASON` | Fatal error in accept loop — agent will stop serving |
| `config-warn` | WARNING | `ENTRY` or `KEY`, `MSG` | Invalid but non-fatal config entry at load |
| `stdin-timeout` | WARNING | `BYTES` | Script did not consume stdin within timeout |
| `revoked-serials-absent` | INFO | `PATH`, `REASON` | Revocation list file not found — normal on a fresh agent |
| `pair-complete` | INFO | `PEER`, `REQID` | Agent stored cert after pairing |
| `pair-denied` | WARNING | `REQID`, `REASON` | Pairing denied by the dispatcher |
| `pair-timeout` | WARNING | `REQID` | Approval window expired |

# Field Glossary

`ACTION`
: Always present. The event type. Always the first field.

`AGENT`
: Agent hostname as recorded in the registry.

`AUTHACTION`
: The action passed to the auth hook (`run`, `ping`, `api`).

`BIND`
: Address the API server bound to.

`BYTES`
: Number of bytes consumed before timeout.

`COUNT`
: Number of entries evicted from the rate limit table.

`DAYS_LEFT`
: Days of certificate validity remaining at the time of a cert check.

`ERROR`
: Error message. Quoted if it contains spaces.

`EXPIRY`
: Certificate expiry date in OpenSSL format.

`EXIT`
: Script exit code. `0` = success; positive = script failure; `-1` = dispatcher-side failure; `126` = exec failed or killed by signal.

`HOSTS`
: Comma-separated list of target hosts for this dispatch.

`IP`
: Source IP address of the caller.

`LEN`
: Request body length in bytes.

`METHOD`
: HTTP method (`GET`, `POST`).

`MSG`
: Human-readable description of a config warning.

`NEW_SERIAL`
: The new dispatcher certificate serial after rotation.

`OLD_SERIAL`
: The previous dispatcher certificate serial.

`OVERLAP_EXPIRES`
: Unix timestamp after which agents that have not confirmed the new serial are marked stale.

`PATH`
: HTTP request path, or filesystem path for config warnings.

`PEER`
: IP address of the connecting peer.

`PORT`
: Listening port.

`REASON`
: Short reason code for a denial or block. Values include `queue-full`, `volume`, `probe`, `not-in-allowlist`, `hook-denied`, `hook-not-executable`.

`REQID`
: 16-character cryptographically random request ID. Present on all run, ping, and pairing events. Identical in both dispatcher and agent log entries for the same operation.

`RESULT`
: Auth hook outcome: `allow`, `deny`, `deny-credentials`, `deny-privilege`, or `error`.

`RTT`
: Round-trip time for the operation, including connection setup and script execution.

`SCRIPT`
: Script name as specified in the allowlist.

`SERIAL`
: Certificate serial number.

`STATUS`
: Ping status (`ok` or `error`), or pairing state (`pending`).

`TARGET`
: Agent hostname targeted by a run or ping.

`THRESHOLD`
: Cert renewal threshold in days.

`TLS`
: `1` if the API server is listening with TLS; `0` otherwise.

`USER`
: Username from the request context, as forwarded to the auth hook.

# Alert Patterns

## Security Events

| Pattern | Response |
| --- | --- |
| `ACTION=rate-block REASON=volume` | Investigate source IP for connection flooding |
| `ACTION=rate-block REASON=probe` | Investigate source IP for TLS probing |
| `ACTION=serial-reject` | Check rotation broadcast status — run `ced serial-status` |
| `ACTION=revoked-cert` | Treat as a security event — investigate source IP immediately |
| `ACTION=ip-block` | Review `allowed_ips` config — investigate unexpected sources |
| `ACTION=deny` repeated from same PEER | Check agent allowlist — may indicate misconfiguration or probing |

## Rotation Events

| Pattern | Response |
| --- | --- |
| `ACTION=serial-stale` | Re-pair the agent |
| `ACTION=serial-broadcast-fail` repeated for same agent | Check connectivity — agent will be marked stale after overlap window expires |
| `ACTION=cert-rotation-fail` | Investigate immediately — rotation retried on next check interval |
| All agents returning `ACTION=serial-reject` after rotation | Run `ced serial-status` and `ced rotate-cert` |

## Configuration Problems

| Pattern | Response |
| --- | --- |
| `ACTION=config-warn` | Review `agent.conf` — fix the offending entry |
| `ACTION=accept-fatal` | Agent will stop serving — investigate and restart immediately |
| `ACTION=auth RESULT=error REASON=hook-not-executable` | Fix hook path and permissions — all requests are failing |
