---
title: Security Operations
subtitle: Certificate lifecycle, revocation, CA recovery, hook hardening, and monitoring.
updated: 2026-03-16
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/SECURITY-OPERATIONS.md
current_page: /security-ops
---

# Certificate Lifecycle and Renewal

Agent certificates are renewed automatically. Renewal is triggered after every successful ping when the agent's remaining certificate validity falls below half the configured `cert_days` (default: 365 days — renewal begins at approximately 182 days remaining).

No operator action is needed during normal operation. To check certificate status:

```bash
ced ping host-a host-b            # CERT EXPIRY column
sudo cea pairing-status           # on the agent host
```

Renewal failure is logged at ERR and retried on the next ping. A certificate that fails repeatedly will eventually expire and require re-pairing.

To change certificate lifetime, update `cert_days` in `ctrl-exec.conf`. Existing certificates are unaffected until their next renewal cycle.

# Revocation Procedures

## Revoking a decommissioned agent

1. Obtain the serial from the agent certificate:
   ```bash
   openssl x509 -noout -serial -in /etc/ctrl-exec-agent/agent.crt
   ```

2. Add the serial to the revocation list on every agent that the decommissioned host could reach, then reload:
   ```bash
   echo "serial=DEADBEEF" >> /etc/ctrl-exec-agent/revoked-serials
   sudo systemctl kill --signal=HUP ctrl-exec-agent
   ```

3. Use `ced run` to push the serial append to all remaining agents at once:
   ```bash
   ced run host-a host-b revoke-serial -- DEADBEEF
   ```
   Requires a `revoke-serial` script on each agent. See the `ctrl-exec-plugins` repository for a reference implementation.

4. Remove the agent from the registry:
   ```bash
   ced unpair <hostname>
   ```

The revocation list is checked on every incoming mTLS connection before any request is processed.

## Revoking the dispatcher certificate

If the dispatcher certificate is compromised or needs replacement:

1. Run `ced rotate-cert` to generate a new certificate.
2. Rotation updates each agent's trusted-dispatcher map automatically over the run channel, with no re-pairing, via add-then-remove: the dispatcher broadcasts the new serial under its stable `dispatcher_id` and each reachable agent adds it; the old serial stays trusted through the overlap window, so the dispatcher's live certificate is accepted throughout, and is removed once the window closes. Only an agent that was offline during the broadcast (later marked `serial-stale`) needs re-pairing.
3. Add the old serial to `revoked-serials` on each agent if you need to prevent any use of the old certificate.

# CA Compromise Recovery

If the CA key is suspected compromised:

1. Take the dispatcher offline immediately:
   ```bash
   sudo systemctl stop ctrl-exec-api
   ```

2. Back up existing state:
   ```bash
   sudo cp -a /etc/ctrl-exec /etc/ctrl-exec.compromised.$(date +%Y%m%d)
   ```

3. Generate a new CA:
   ```bash
   sudo ced setup-ca
   sudo ced setup-ctrl-exec
   ```

4. Distribute the new CA certificate to all agents. This cannot be done via the dispatcher — the agents no longer trust the new dispatcher certificate. Use out-of-band tooling to push `/etc/ctrl-exec/ca.crt` to `/etc/ctrl-exec-agent/ca.crt` on each agent.

5. Re-pair all agents.

After recovery, audit access to `/etc/ctrl-exec/ca.key` to determine the scope of the compromise. Consider restricting access with filesystem permissions and audit logging.

# Auth Hook Hardening

Use `ENVEXEC_ARGS_JSON` for argument inspection, not `ENVEXEC_ARGS`
: `ENVEXEC_ARGS` is space-joined and ambiguous for arguments containing spaces or newlines. Using it for argument policy decisions can be bypassed with a carefully crafted argument.

Do not log environment variables wholesale
: Tokens are never logged by the dispatcher or the agent. Hooks that log `env` or `printenv` output will write tokens to the audit log. Log only specific fields.

Pass tokens via the environment, not `--token`
: ```bash
  ENVEXEC_TOKEN=mytoken ced run host-a backup-mysql
  ```
  Using `--token` on the command line exposes the value in `ps` output.

Validate usernames only via tokens or external authentication
: `ENVEXEC_USERNAME` is caller-supplied and not verified by the dispatcher. Treat it as advisory metadata, not a verified identity.

Use syslog for audit logging from hooks
: Hook stdout and stderr are discarded. Write audit events to syslog:
  ```bash
  logger -t ctrl-exec-hook "RESULT=deny USER=$ENVEXEC_USERNAME SCRIPT=$ENVEXEC_SCRIPT"
  ```

Use absolute paths for all file references in hooks
: The hook's working directory is not guaranteed.

::: examplebox
Rate-limiting the cert-rotation operation with a hook:

```bash
#!/bin/bash
RATE_DIR="/var/lib/ctrl-exec/hook-rate"
mkdir -p "$RATE_DIR"

if [ "$ENVEXEC_ACTION" != "rotate" ]; then
    exit 0
fi

if [ "$ENVEXEC_TOKEN" != "$TOKEN_ROTATION" ]; then
    exit 2
fi

STATE_FILE="$RATE_DIR/$(echo "$DISPATCHER_HOST" | tr -cd 'a-zA-Z0-9._-').last"
NOW=$(date +%s)
if [ -f "$STATE_FILE" ]; then
    LAST=$(cat "$STATE_FILE")
    ELAPSED=$(( NOW - LAST ))
    [ "$ELAPSED" -lt 300 ] && exit 3
fi
echo "$NOW" > "$STATE_FILE"
exit 0
```
:::

# Monitoring and Alerting

## Security events

| Pattern | Response |
| --- | --- |
| `ACTION=rate-block REASON=volume` | Investigate source IP for connection flooding |
| `ACTION=rate-block REASON=probe` | Investigate source IP for TLS probing |
| `ACTION=serial-reject` | Connecting serial not in the agent's trusted-dispatcher map — re-pair the agent if it was offline during a rotation and is now `serial-stale`; otherwise investigate the source |
| `ACTION=revoked-cert` | Treat as a security event — investigate source IP immediately |
| `ACTION=ip-block` | Review `allowed_ips` — investigate unexpected sources |
| `ACTION=deny` repeated from same PEER | Check agent allowlist — may indicate misconfiguration or probing |

## Rotation events

| Pattern | Response |
| --- | --- |
| `ACTION=serial-stale` | Re-pair the agent |
| `ACTION=serial-broadcast-fail` repeated for same agent | Check connectivity — agent will be marked stale after overlap window |
| `ACTION=cert-rotation-fail` | Investigate immediately — rotation retried on next check interval |
| A reachable agent returning `ACTION=serial-reject` after rotation | Rotation updates trust automatically; an agent that was offline/missed the broadcast (see `serial-stale`) needs re-pairing — otherwise investigate the source |

## Configuration problems

| Pattern | Response |
| --- | --- |
| `ACTION=config-warn` | Review `agent.conf` — fix the offending entry |
| `ACTION=accept-fatal` | Agent will stop serving — investigate and restart immediately |
| `ACTION=auth RESULT=error REASON=hook-not-executable` | Fix hook path and permissions — all requests are failing |

See [Logging Reference](/logging) for the complete field reference and all `ACTION=` values.
