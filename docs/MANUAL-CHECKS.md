---
title: ctrl-exec - Manual Verification Checks
subtitle: Checks that cannot be automated and should be run after install or significant changes
brand: odcc
---

# ctrl-exec - Manual Verification Checks

Some behaviours cannot be verified by the automated test suite. These checks
should be performed after initial installation, after upgrades, and after any
change to the systemd unit, agent configuration, or certificate infrastructure.

Each check identifies what to verify, how to verify it, and what a passing
result looks like.


## 1. Agent Syslog Output

Confirms the agent can write to syslog and that entries are reaching the
system log. Silent syslog failures are a known failure mode — `Sys::Syslog`'s
`openlog()` does not raise an error when the socket is unavailable.

Known cause on Debian/systemd: `PrivateDevices=yes` in the unit file prevents
access to `/dev/log`. Fix: `PrivateDevices=no` and add `AF_UNIX` to
`RestrictAddressFamilies`. OpenWrt is not affected (procd does not implement
`PrivateDevices`).

On each agent host, trigger a ping and check the log:

```bash
# From the dispatcher host
sudo ced ping <agent>

# On the agent host (Debian/systemd)
sudo journalctl -u ctrl-exec-agent --since "1 minute ago"

# On the agent host (OpenWrt)
logread | grep ctrl-exec-agent | tail -10
```

Pass
: `ACTION=ping PEER=<dispatcher-ip> REQID=<hex>` appears within a few seconds
  of the ping.

Fail
: No entry appears. Check `PrivateDevices` and `RestrictAddressFamilies` in
  the unit file. Restart after any change: `systemctl restart ctrl-exec-agent`.


## 2. Agent Self-Ping — Live Network Verification

Confirms the agent is listening on port 7443, the TLS stack is functional,
and the agent is actively enforcing serial policy. Requires the agent to be
running and paired. Run this check on the agent host directly — no dispatcher
access is needed.

```bash
sudo ctrl-exec-agent self-ping
```

Pass
: Output shows port listening, mTLS handshake OK, and `403 serial mismatch
  (expected)`. The 403 is the correct result — the agent's own cert is not
  a dispatcher cert, and the agent correctly rejects it.

Fail — port not listening
: The agent service is not running or is bound to a different port. Check
  `systemctl status ctrl-exec-agent` and the `port` setting in `agent.conf`.

Fail — mTLS handshake error
: TLS configuration is broken. Check cert and CA paths in `agent.conf` and
  confirm the cert files are readable by the agent process.

Fail — unexpected response or no response
: The agent accepted the connection but did not respond as expected. Check
  the agent syslog for errors. Also run `self-check` to confirm the
  configuration is valid.

Run this check after initial installation and after any change to the agent
service, port configuration, or cert files.


## 3. Systemd Unit Hardening — AF_UNIX Present

Confirms `RestrictAddressFamilies` includes `AF_UNIX`. Omitting it silently
blocks all syslog output because `Sys::Syslog` uses a Unix domain socket to
reach journald.

```bash
systemctl cat ctrl-exec-agent | grep RestrictAddressFamilies
```

Pass
: Output contains `AF_UNIX AF_INET AF_INET6`.

Fail
: `AF_UNIX` is absent. Add it to the unit file, reload systemd, restart the
  agent. Verify syslog output (check 1) after correcting.


## 4. Auth Hook Invocation

Confirms the auth hook is called for every `run` and `ping` request, and that
its exit code is respected.

For deployments with SSH access to the agent, test 08 (`08-auth-hook.sh`) in
the integration suite covers hook invocation and denial end-to-end.

For deployments without SSH access, test 15 (`15-agent-auth-context.sh`)
provides equivalent coverage using a pre-installed hook and a dedicated
allowlisted script to retrieve results via dispatch. Install it with:

```bash
sudo bash t/integration/setup-agent-scripts.sh --install-auth-test
sudo bash t/integration/15-agent-auth-context.sh
```

For a quick manual check on any deployment, configure a minimal hook that logs
to syslog and permits all requests:

```bash
cat > /etc/ctrl-exec/auth-hook << 'EOF'
#!/bin/sh
logger -t ctrl-exec-auth "hook called: SCRIPT=$ENVEXEC_SCRIPT USER=$ENVEXEC_USERNAME"
exit 0
EOF
chmod 755 /etc/ctrl-exec/auth-hook
```

Run a script, then check the log on the agent host:

```bash
sudo ced run <agent> env-dump
sudo journalctl -t ctrl-exec-auth --since "1 minute ago"
```

Pass
: Log entry appears for the run request. Changing `exit 0` to `exit 1` causes
  all subsequent requests to return a permission error.

Fail
: No log entry. Check `auth_hook` path in `agent.conf` and that the hook is
  executable.


## 5. Allowlist SIGHUP Reload

Confirms the agent reloads `scripts.conf` on SIGHUP without restarting, and
that newly added entries take effect immediately.

```bash
# Add a new entry to scripts.conf on the agent
echo "reload-test = /opt/ctrl-exec-scripts/env-dump.sh" \
    >> /etc/ctrl-exec-agent/scripts.conf

# Reload without restart
systemctl reload ctrl-exec-agent   # or: /etc/init.d/ctrl-exec-agent reload

# Attempt to run the new entry from the dispatcher
sudo ced run <agent> reload-test
```

Pass
: The script runs successfully without restarting the agent.

Fail
: Request is rejected as not permitted. Check that SIGHUP is delivered
  (`ExecReload=/bin/kill -HUP $MAINPID` in the unit file) and that the new
  entry is syntactically correct in `scripts.conf`.


## 6. Rate Limit Block and Recovery

Confirms the volume rate limiter blocks a source IP after exceeding the
threshold and that the block expires correctly. The unit test (`t/rate-limit.t`)
covers the logic; this check verifies end-to-end behaviour on a live agent.

Not suitable for automated suite runs — it requires deliberately triggering and
waiting out a 5-minute block.

```bash
# Fire 11 rapid pings from the dispatcher to one agent
for i in $(seq 1 11); do sudo ced ping <agent>; done

# The 11th should fail or return an error
# Check the agent log for the rate-block entry
sudo journalctl -u ctrl-exec-agent --since "1 minute ago" | grep rate-block
```

Pass
: `ACTION=rate-block PEER=<dispatcher-ip> REASON=volume` appears in the log.
  Subsequent pings fail with `no response from child` for approximately 5
  minutes, then recover automatically.

Fail
: No block occurs. Check `rate_limit_disable` is not set in `agent.conf` on
  a production agent.

Note
: Set `rate_limit_disable = 1` in `agent.conf` before running the integration
  test suite, and remove it when done.


## 7. Pairing Flow — Fresh Agent

Confirms the full pairing sequence works end-to-end: agent submits CSR,
dispatcher displays the pairing code, operator approves, agent stores certs.

Run on a host that has not previously been paired, or after clearing
`/etc/ctrl-exec-agent/agent.{key,crt}`:

```bash
# On the agent host
sudo ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>

# On the dispatcher host (in a separate terminal)
sudo ced list-requests
# Verify the hostname, source IP, and 6-digit pairing code match
# what the agent displayed, then approve:
sudo ced approve <agent-hostname>

# Confirm the agent accepted the cert
sudo ced ping <agent-hostname>
```

Pass
: `ACTION=pair-complete` appears in the agent log. `ced ping` returns ok.

Fail
: Pairing code mismatch - reject and investigate. Nonce mismatch - check for
  clock skew or concurrent pairing requests. Writability failure - check
  `/etc/ctrl-exec-agent` permissions.


## 8. Cert Rotation Broadcast

Confirms that `ced rotate-cert` reaches all registered agents and that
each agent updates its stored dispatcher serial.

```bash
sudo ced rotate-cert
sudo ced serial-status
```

Pass
: All agents show `current` in `serial-status` output. `ACTION=serial-update`
  appears in the log on each agent.

Fail
: One or more agents remain `pending`. The agent was unreachable during the
  broadcast. Re-run `rotate-cert` after restoring connectivity. If the overlap
  window expires, the agent requires re-pairing.


## 9. Revocation Takes Effect

Confirms that adding a serial to `revoked-serials` on an agent causes
subsequent connections from that cert to be rejected, without restarting the
agent.

```bash
# Obtain the dispatcher cert serial
openssl x509 -noout -serial -in /etc/ctrl-exec/ctrl-exec.crt \
    | sed 's/serial=//' | tr 'A-F' 'a-f'

# Add to revoked-serials on the agent and reload
echo "<serial>" >> /etc/ctrl-exec-agent/revoked-serials
systemctl reload ctrl-exec-agent

# Attempt a ping - should fail
sudo ced ping <agent>

# Check the agent log
sudo journalctl -u ctrl-exec-agent --since "1 minute ago" | grep revoked
```

Pass
: `ACTION=cert-revoked` or similar appears in the log. Ping fails.

Restore
: Remove the serial from `revoked-serials` and reload before returning to
  normal operation.


## 10. Agent Restart Recovery

Confirms the agent restarts cleanly after a crash and that `Restart=on-failure`
in the unit file is functioning.

```bash
# On the agent host, kill the agent process abruptly
sudo kill -9 $(systemctl show -p MainPID ctrl-exec-agent | cut -d= -f2)

# Wait 5 seconds (RestartSec=5) then check
sleep 6
systemctl is-active ctrl-exec-agent
sudo ced ping <agent>
```

Pass
: Agent returns to `active` within a few seconds. Ping succeeds.

Fail
: Agent remains in `failed` state. Check `journalctl -u ctrl-exec-agent` for
  the failure reason. Common causes: cert file permissions changed, config
  parse error introduced since last start.


## 11. OpenWrt — procd Restart and logread

OpenWrt-specific. Confirms the agent runs under procd, survives a restart, and
logs to the ring buffer readable via `logread`.

```bash
# On the OpenWrt agent
/etc/init.d/ctrl-exec-agent restart
sleep 3
/etc/init.d/ctrl-exec-agent status

# From the dispatcher host
sudo ced ping <openwrt-agent>

# On the OpenWrt agent
logread | grep ctrl-exec-agent | tail -10
```

Pass
: Status shows running. Ping succeeds. `ACTION=ping` entry appears in `logread`
  output.

Fail
: Agent does not start. Check `/etc/init.d/ctrl-exec-agent` script for correct
  interpreter path. OpenWrt may have Perl in a non-standard location — verify
  with `which perl` and ensure the shebang line in `ctrl-exec-agent` matches.


## When to Run These Checks

After initial installation
: Checks 1, 2, 3, 7, 10 (and 11 if OpenWrt agents are present).

After a unit file or agent.conf change
: Checks 1, 2, 3, 5, 6 as applicable to what changed.

After a cert rotation or renewal
: Checks 8, 9.

Before a production release
: All checks on at least one Debian agent and one OpenWrt agent.

After any security incident or suspected compromise
: Checks 7, 8, 9 as a minimum. Consider full re-pairing of affected agents.
