---
title: ctrl-exec - Security Operations
subtitle: Operational security guidance, monitoring, incident response, and known limitations
brand: odcc
---

# ctrl-exec - Security Operations

This document covers the operational security posture of a running ctrl-exec
deployment: what to monitor, how to respond to incidents, known limitations,
and deployment-specific guidance. For the system's security model and
architecture, see SECURITY.md.


## dispatcher host Security

The security of the entire fleet depends on the security of the dispatcher
host. The CA key, dispatcher cert and key, full agent registry, and lock files
all reside there. An attacker with root access to the dispatcher host can issue
arbitrary agent certificates and connect to any agent.

Treat the dispatcher host as a privileged infrastructure node:

- Restrict interactive login to named administrators only; no shared accounts
- Audit all access via system auth logs (`/var/log/auth.log` or equivalent)
- Keep the dispatcher host off the general network; access via bastion or VPN
- Apply OS-level hardening (no unnecessary services, up-to-date packages)
- Do not run untrusted workloads on the dispatcher host

The `ctrl-exec` group grants CLI access to the dispatcher binary and read
access to the agent registry at `/var/lib/ctrl-exec/agents/`. This includes
each agent's hostname and IP address. Membership of the `ctrl-exec` group
is a privilege; treat it accordingly.


## Token and Credential Lifecycle

ctrl-exec has no built-in token management. Tokens are arbitrary strings that
callers include in requests; they are forwarded to the auth hook as
`ENVEXEC_TOKEN` and to agents via the request body. All token issuance,
validation, expiry, and revocation logic lives in the auth hook.

The `username` field is a caller-supplied string with no structural meaning
within ctrl-exec. The dispatcher does not authenticate it, and it is not
verified to match any local or remote identity. Its purpose is to carry an
identity assertion that an auth hook can forward to an external authentication
service alongside the token. A hook that grants elevated permissions based
solely on the value of `username`, without verifying it through the token or
another mechanism, can be trivially bypassed by any caller that sets the field
to a privileged value.

The recommended pattern for identity-bearing requests:

- The caller supplies a `token` that encodes or binds to an identity (e.g. a
  signed JWT, an opaque token registered in an identity service, or an API key
  issued to a specific service account)
- The caller also supplies `username` as an advisory hint
- The hook validates the token against an identity service; the service returns
  the authorised identity associated with that token
- The hook compares the authorised identity against the asserted `username`
  only as an additional consistency check, not as the primary access control
  basis
- Privilege decisions are made on the validated token identity, not the
  asserted username

This pattern allows hooks to go beyond static local accounts: any identity
service that can validate a token can be used. The hook does not need to
maintain its own user database; it delegates to the identity service.

Token revocation for a compromised service: update the auth hook to reject the
service's token. If the hook validates against a central service, revoke the
token there. No dispatcher restart is required; the hook's own logic takes
effect on the next request.


## Auth Hook Security

Hook update path
: Do not push auth hook updates via `ced run`. If the hook is replaced
  by a script that a compromised token can invoke, the hook that validates that
  token can be overwritten. Update hooks through direct filesystem access,
  configuration management tooling (Ansible, Salt, Puppet), or a dedicated
  privileged deployment channel that does not pass through ctrl-exec itself.

Token exposure in hook logging
: The token is available in the hook's `ENVEXEC_TOKEN` environment variable
  and in the JSON object on stdin. Do not log environment variables within the
  hook; log only specific fields from stdin. A hook that logs `env` output
  exposes the token in syslog, where it may be accessible to non-root users
  depending on syslog permissions.

External validation service availability
: If the hook validates tokens against an external service, failure to reach
  that service must result in a denied request (exit code 1 or 2). Do not
  fail open. The operational impact of blocking all requests during a
  validation service outage is preferable to authorising unvalidated requests.
  Design the validation service for high availability if ctrl-exec operations
  are time-critical.

Two-token pattern
: The dispatcher-side hook and the agent-side hook are independent and can
  validate different tokens. A higher-assurance deployment can issue separate
  credentials for the dispatcher-to-hook path and the agent-to-hook path.
  The dispatcher validates a dispatcher-level token; the agent validates a
  forwarded per-operation token. This is a supported configuration - the
  token is forwarded from dispatcher to agent in the request body and is
  available to both hooks.

Agent hook scope
: The agent hook only runs for `run` requests. `ping` requests do not invoke
  the agent hook. An agent hook cannot restrict which sources may call the
  `ping` endpoint; source-based restrictions on the agent use `allowed_ips`
  in `agent.conf` or `ENVEXEC_SOURCE_IP` in the hook for `run` requests.
  The absence of a `hosts` field on the agent side is intentional: the agent
  is unaware of which other agents are targeted in the same invocation.

Allowlist information in hook responses
: The agent hook is called after allowlist validation. A denied hook response
  therefore confirms to the caller that the script name exists in the allowlist
  (a non-existent script would have been rejected earlier with a different
  error code). This is a known characteristic of the execution order. Operators
  who need to conceal allowlist contents should note that hook denial does not
  prevent an authorised caller from querying `/capabilities` to enumerate the
  full allowlist.


## Sensitive Script Output

Scripts that return credentials, key material, or other sensitive data will
have that data included in the API response and stored in the result file at
`/var/lib/ctrl-exec/runs/<reqid>.json` for 24 hours. The result directory
is 0770 root:ctrl-exec - readable by all members of the `ctrl-exec` group.

Options for handling sensitive output:

- Write sensitive data to a local file on the agent rather than stdout; return
  only a status code and path from the script
- Have the script encrypt the output before writing to stdout; the caller
  decrypts client-side
- Restrict `GET /status/{reqid}` callers to the original caller only via the
  auth hook (not built in; hook logic required)

Result retrieval at `GET /status/{reqid}` is not currently logged with the
caller's identity. All authenticated API callers can retrieve any result by
reqid. A hook that restricts this must infer the original caller from the
token and compare it to the stored result's caller context (not provided by
the API directly - requires a lookup in the hook's own store).

## Script privilege and filesystem access (privilege separation)

> A fuller treatment of the privilege-separation model lands with the security
> documentation rewrite; this is the operational summary.

ctrl-exec does not blanket-sandbox the agent into being unable to do its job.
A managed script runs with the privilege its work requires - governed by **which
script** (the allowlist), **who** invoked it (mTLS + the auth hook), and **its
security profile** - not by a filesystem wall the operator has to fight.

With privilege separation enabled (`executor_socket` in `agent.conf`, plus the
`ctrl-exec-exec.service` running), each synchronous run goes to the privileged
executor, which runs the script under the profile named in `scripts.conf`:

- `run_as` - the user the script runs as (ordinary Unix DAC governs its writes).
- `caps` - the Linux capabilities it holds (e.g. `CAP_CHOWN`).
- The agent's **control and state directories** (`/etc/ctrl-exec-agent`,
  `/var/lib/ctrl-exec-agent`) are **read-only** to every action, including
  `run_as=root` ones - so an action can never tamper with the controls or audit.

So "let a cert-deploy script write `/srv/certificates`" is just: give it a
profile with the right `run_as` (and the directory owned/writable by that user).
See the `[profile <name>]` documentation in `agent.conf.example`.

Without `executor_socket`, the agent runs scripts directly in its own
(unprivileged) process - no profiles, no privilege change.


## Cert-Rotation (`/rotate-serial`) Security

Cert rotation is a built-in operation handled by the agent front-end
(`ctrl-exec-agent`), not an allowlisted script: a caller POSTs to
`/rotate-serial`. It is gated by the same trusted-dispatcher serial check as
`/run` — the caller's cert serial must already be in the trusted map — plus the
auth hook, which sees `ENVEXEC_ACTION=rotate`, an empty `ENVEXEC_SCRIPT`, and
`ENVEXEC_ARGS_JSON` of `["add","<serial>"]` or `["remove","<serial>"]`.

The agent's rotate handler validates that the serial argument is a hex string of
8–40 characters before editing the trusted-dispatcher map at
`/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`. Arguments that fail the hex
pattern check or fall outside the length range are rejected and the map is not
changed.

The dispatcher identity is **derived from the caller's authenticated cert
serial** — it is never sent in the request. A dispatcher can therefore only
add or retire serials under its **own** identity, and the currently-trusted
serial is what authorises the next one, so the trust chain stays rooted in the
original human-supervised pairing approval. (This closes a spoofing gap in the
former rotation script, which took the dispatcher id as a command-line argument
that a compromised dispatcher could forge.)

Despite the serial validation, an API caller able to reach `/rotate-serial` can
still add or remove a plausible-looking serial in the map. A serial is inert
without a CA-signed certificate bearing it, so the CA trust model bounds the
risk; even so, the auth hook should restrict the `rotate` operation to
privileged tokens only. A standard operator token should not be able to invoke
it. Use a separate token issued to the dispatcher's own rotation machinery, and
block it for all other callers in the hook.

Seamless rotation (0.9.0)
: As of 0.9.0 the agent keys dispatcher trust on the trusted-dispatcher map at
  `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`, in the agent-writable state
  directory. Cert rotation updates each reachable agent's map automatically over
  the run channel, with no re-pairing, via add-then-remove: the broadcast adds
  the new serial (against the stable `dispatcher_id`), the old serial stays
  trusted through the overlap window, and after the window the dispatcher
  broadcasts removal of the old serial (`retire_previous_serial`, logged as
  `serial-retire`). Only an agent that was *offline* during the broadcast misses
  the update and needs re-pairing once the overlap window expires. The operation's
  behaviour and its token-restriction guidance are unchanged.

### Call rate limiting per agent

Even with token restriction, a rotation machinery bug or misconfigured caller
could issue rapid successive calls to `/rotate-serial`. Each call
writes the serial file and sends SIGHUP, clearing all rate-limit state on the
agent. The following hook pattern adds a per-agent time-window limit on top of
the token restriction.

The hook uses a state file in a directory writable only by the hook's runtime
user. The state file records the last accepted call time per agent hostname.
Calls within the window are rejected with exit code 1 (deny, hook error logged).

```bash
#!/bin/bash
# Auth hook with rate-limit on the rotate operation

TOKEN_ROTATION="${ROTATION_TOKEN:-}"   # set in hook environment or config
RATE_DIR="/var/lib/ctrl-exec/hook-rate"
WINDOW_SECONDS=300   # one call per agent per 5 minutes

# Only apply rate-limit logic to the rotate operation
if [ "$ENVEXEC_ACTION" != "rotate" ]; then
    # Pass all other actions through to normal token validation
    if [ "$ENVEXEC_TOKEN" = "$TOKEN_ROTATION" ]; then exit 0; fi
    exit 1
fi

# Rotation token required
if [ "$ENVEXEC_TOKEN" != "$TOKEN_ROTATION" ]; then
    exit 1
fi

# Rate limit: one successful call per agent per window
mkdir -p "$RATE_DIR"
STATE_FILE="$RATE_DIR/${DISPATCHER_HOST//[^a-zA-Z0-9._-]/_}.last"
NOW=$(date +%s)

if [ -f "$STATE_FILE" ]; then
    LAST=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
    ELAPSED=$(( NOW - LAST ))
    if [ "$ELAPSED" -lt "$WINDOW_SECONDS" ]; then
        echo "rate-limited: last call ${ELAPSED}s ago, window ${WINDOW_SECONDS}s" >&2
        exit 1
    fi
fi

echo "$NOW" > "$STATE_FILE"
exit 0
```

`DISPATCHER_HOST` is the target agent hostname as recorded in the registry —
it is not caller-supplied and cannot be spoofed. The state directory should
be `0700` owned by the user the hook runs as. The hook should be set `0700`
with root ownership; its parent directory should not be writable by the
dispatcher process.

Note that the `SIGHUP` sent by the built-in rotate handler clears rate-limit
state in the *agent's* connection limiter, not in this hook's state file. The
two mechanisms are independent.


## CA Compromise Recovery

If the CA private key is compromised, every cert signed by it must be treated
as untrusted. An attacker with the CA key can issue valid agent certificates
and connect to any agent as if they were the dispatcher.

Recovery procedure:

1. Take agents offline or isolate them immediately from all network sources.
   The priority is preventing the attacker from using newly-issued certs before
   recovery completes.

2. On the dispatcher host, regenerate the CA:

   ```bash
   # Back up the compromised material first for forensics
   cp -a /etc/ctrl-exec /etc/ctrl-exec.compromised.$(date +%Y%m%d)

   ced setup-ca   # generates new CA key and cert
   ced setup-ctrl-exec  # generates new dispatcher cert signed by new CA
   ```

3. Distribute the new CA cert to all agents. This cannot be done via ctrl-exec
   (the agents do not trust the new CA yet). Use SSH or configuration
   management tooling to push `/etc/ctrl-exec/ca.crt` to
   `/etc/ctrl-exec-agent/ca.crt` on each agent.

4. Re-pair every agent. The agent certs signed by the old CA are no longer
   valid:

   ```bash
   # On each agent host
   rm /etc/ctrl-exec-agent/agent.{key,crt}
   ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>
   ```

5. Once all agents are re-paired, decommission the compromised CA material.
   Ensure the old CA cert is removed from all trust stores.

6. Investigate how the CA key was accessed: review dispatcher host auth logs,
   check for unauthorised access to `/etc/ctrl-exec/ca.key`, and determine
   the scope of the compromise before returning to normal operations.

This procedure affects the entire fleet. Test the re-pairing path before a
real incident - the orchestrated pairing flow (`--background` mode) is
designed for bulk re-pairing scenarios.


## Monitoring and Alerting

ctrl-exec's structured logging provides the data for detection. Alerting
must be configured in the operator's log management tooling (Graylog,
Elasticsearch, Loki, syslog-ng filters, etc.). ctrl-exec does not include
a monitoring component.

The complete alert pattern reference — covering security events, execution
failures, rotation events, and configuration problems — is in LOGGING.md.

Key security-relevant actions to alert on: `rate-block`,
`serial-reject` (carries `PEER_SERIAL`), `result-deny` (REASON=not-owner,
a dispatcher requesting another dispatcher's result), `revoked-cert`,
`ip-block`, `deny` (repeated, same PEER). Run/ping/capabilities/result actions
carry `DISPATCHER=<id>` for per-dispatcher attribution. Key rotation
signals: `serial-stale`, `serial-broadcast-fail` (repeated for same agent),
`cert-rotation-fail`. These are documented in full in LOGGING.md.

Operational signals worth alerting on:

- All agents returning `ACTION=serial-reject` simultaneously after a rotation
  indicates the rotation broadcast failed or was corrupted. Run
  `ced serial-status` and `ced rotate-cert` immediately.
- A sudden increase in `ACTION=run EXIT=non-zero` across multiple agents may
  indicate a script was modified or a dependency broke. Correlate with
  deployment events. Note that non-zero exit is logged at INFO priority on
  both dispatcher and agent — alert on the EXIT value itself, not the
  log priority level.

`cert_overlap_days` calibration
: The default overlap window is 30 days. If agents in your fleet are routinely
  offline for maintenance or hibernation longer than this, `stale` status
  becomes normal background noise rather than a signal. Set `cert_overlap_days`
  in `ctrl-exec.conf` to a value above the maximum observed downtime for your
  fleet. A stale alert only has diagnostic value if it is unexpected.


## Known Limitations

Request result access
: `GET /status/{reqid}` returns stored run results to any authenticated caller,
  not only the original submitter. Result access is not logged with the caller's
  identity. Reqid format provides limited enumeration resistance (see reqid
  entropy below). Sensitive results should not be left in the result store;
  design scripts to minimise what they return via stdout if the results will be
  stored. This limitation applies to the dispatcher-side API result store. The
  agent-side async result store is different: as of 0.9.0 it is partitioned per
  owner and the agent's `GET /result/<reqid>` is owner-gated, returning
  `404 unknown` to any dispatcher other than the one that submitted the run.

Rate state persistence
: Rate limit state is held in memory and cleared on SIGHUP or agent restart.
  the built-in `/rotate-serial` handler sends SIGHUP as part of normal rotation,
  which clears all rate blocks. The window between the SIGHUP and the next connection
  is milliseconds in practice - not operationally meaningful - but operators
  should be aware that a serial update resets rate state on all agents.
  Persistent rate state across reloads is not currently supported.

`MemoryDenyWriteExecute` and JIT runtimes
: The agent systemd unit sets `MemoryDenyWriteExecute=yes`. This is safe for
  the current bash-only script inventory but will cause silent failures if a
  JIT-compiled runtime (Java, Node.js, Python with JIT) is added to the
  allowlist. There is no mechanism to detect this conflict at allowlist load
  time. When adding a new script whose interpreter is a JIT runtime, remove
  `MemoryDenyWriteExecute=yes` from the unit file before deploying.

No dispatcher-side agent cert revocation
: The revocation list on agents covers certs presented *to* the agent. There
  is no equivalent mechanism on the dispatcher side to block a stolen agent
  cert from connecting to the dispatcher. An agent that has been decommissioned
  via `ced unpair` has its cert left technically valid until natural
  expiry. See Unpairing and Decommission below for the recommended workflow
  to close this window promptly.


## Unpairing and Decommission

`ced unpair <hostname>` removes the agent from the registry. The agent
will no longer receive cert renewals and will become stale when the overlap
window expires. However, the agent's certificate remains cryptographically
valid until its natural expiry date, which is printed by the unpair command.
During that window, a host holding a copy of the agent cert and key can still
connect to the dispatcher on port 7443.

The recommended workflow after unpairing is:

1. Run `ced unpair <hostname>`. Note the expiry date printed.

2. Obtain the agent cert serial:

   ```bash
   openssl x509 -noout -serial -in /etc/ctrl-exec-agent/agent.crt
   ```

   If you no longer have access to the agent host, retrieve the serial from
   the registry record before unpairing, or from the dispatcher's CA serial
   log if available.

3. Add the serial to the revocation list on every agent that the decommissioned
   host could have reached. The format `serial=DEADBEEF` (direct openssl output)
   is accepted as-is:

   ```bash
   echo "serial=DEADBEEF" >> /etc/ctrl-exec-agent/revoked-serials
   systemctl reload ctrl-exec-agent
   ```

   For fleet-wide distribution, use `ced run` to push the serial append
   and SIGHUP to all remaining agents before the unpairing takes effect.

4. Verify the serial appears in the revocation list on the affected agents:

   ```bash
   grep -i DEADBEEF /etc/ctrl-exec-agent/revoked-serials
   ```

5. Decommission or reimage the host promptly. Do not leave a host with a valid
   agent cert and key accessible after unpairing — revocation on the agents
   closes the inbound path, but the cert could be extracted and used elsewhere
   if the host is not secured.

If the agent cert and key have been confirmed destroyed (host reimaged, disk
wiped), steps 2–4 are optional but recommended as defence in depth.

The revocation list is checked on every incoming mTLS connection before any
request is processed. Once the reload completes on each agent, the decommissioned
cert is blocked immediately on reconnect. Any in-flight connection established
before the reload completes will run to completion — restart the agent service
rather than reloading if in-flight connections must also be terminated.


## Docker-Specific Security

Docker socket access
: Any user or process with access to the Docker socket on the dispatcher host
  can start a container with the `ctrl-exec-data` volume mounted and read the
  CA private key. Restrict Docker socket access to root and any explicitly
  designated operators. Do not grant Docker socket access to services running
  on the dispatcher host that do not require it. This is the most significant
  additional risk of a containerised deployment versus a bare-metal install.

Stale pairing request
: The dispatcher's pairing queue automatically cleans up requests older than
  10 minutes. In the Docker workflow, the agent container exits after sending
  its pairing request and must be restarted by the operator after approval.
  If the 10-minute window expires before the container is restarted and
  re-triggers the pairing, the request is silently deleted. Recovery: restart
  the agent container; it will send a fresh pairing request.

`DISPATCHER_HOST` trust
: The `DISPATCHER_HOST` environment variable in the agent container determines
  which host receives the pairing request including the agent's CSR. If this
  variable is misconfigured to point at an attacker-controlled host, the
  attacker receives the CSR and can return a certificate signed by their own
  CA. The agent stores whatever cert is returned. All subsequent operations use
  the attacker's CA as the trust anchor. Verify `DISPATCHER_HOST` points at
  the correct dispatcher before starting agent containers. For production
  deployments, consider setting `DISPATCHER_HOST` in a compose file under
  version control rather than passing it as a runtime variable.

`allowed_ips` in containerised deployments
: In a Docker network, all containers on the same network can reach port 7443
  on the agent container. Set `allowed_ips` in `agent.conf` to the dispatcher
  container's IP or subnet to limit which containers can connect to the agent.
  The dispatcher container's IP is stable within a compose deployment (Docker
  assigns IPs deterministically by service name). Example:

  ```ini
  allowed_ips = 172.18.0.0/16
  ```

  For tighter control, use Docker network policies or pin the dispatcher
  container's IP in the compose file and use an exact IP in `allowed_ips`.

Volume backup
: All persistent state is on named volumes. Back up both `ctrl-exec-data`
  (CA key, dispatcher cert) and `ctrl-exec-registry` (agent registry) on the
  dispatcher side. On the agent side, `agent-data` contains the agent cert and
  key. Loss of `agent-data` requires re-pairing that agent. Loss of
  `ctrl-exec-data` requires regenerating the CA and re-pairing the entire
  fleet. Treat volume backup with the same priority as the CA key backup
  described in SECURITY.md.
