---
title: ctrl-exec - Security Model
subtitle: Trust boundaries, threat model, file permissions, and operational guidance
brand: odcc
---

# ctrl-exec - Security Model


## The invariant

ctrl-exec is built around one guarantee:

> A holder of a valid dispatcher certificate can invoke the approved actions and
> nothing else, and cannot alter the controls (allowlist, auth hook, config,
> trust) or the audit trail - **even with full control of the dispatcher**.
> Within that, an action runs with whatever privilege the operator gave its
> profile.

Security is enforced at ctrl-exec's own layer - the **allowlist**, **mTLS
identity**, **argument schemas**, the **auth hook** policy engine, **per-script
profiles**, and the **audit** - not by crippling the agent's ability to do its
job. A managed script runs with the privilege its work needs; what is controlled
is *which* script, invoked by *whom*, with *what arguments*, and recorded.

This is what makes ctrl-exec a sound replacement for `ssh + sudo`: it does the
same operational work, but the surface is a fixed set of named, reviewed,
argument-constrained, cryptographically-authenticated, audited operations - and
there is no shell.


## Enforcement model: two boundaries

Think of two boundaries an attacker would have to cross, and what each enforces.

**First boundary - the dispatcher / API.** The dispatcher (and its optional HTTP
API) is where requests originate. It is authenticated, authorised by the auth
hook, rate-limited, and exposes only `run`/`ping`/discovery. Security here does
**not** depend on the protocol being secret - it is assumed known.

**Second boundary - the agent.** This is the real enforcement point. Even an
attacker who bypasses the dispatcher entirely and speaks the mTLS protocol
directly to an agent still needs a CA-signed dispatcher certificate, and **even
with one** is bound by the agent to exactly the approved action set: the
allowlist (only named scripts), per-script profiles (the privilege each runs
with), schema validation (constrained arguments), and the auth hook. It cannot
extend the allowlist, edit the hook/config, change trust, or erase audit - the
executor runs every action with the agent's control and state directories
read-only (see *Allowlist and Execution Security*).

The headline: **the dispatcher is a control and convenience layer, not a trusted
one. The agent is the enforcement boundary, and its guarantees hold under full
dispatcher compromise.**

### Worked scenario: a compromised autonomous agent

Suppose an advanced AI drives the dispatcher's API and is taken over by a bad
actor - with API access, and even read access to the source.

- Reading the source gains nothing: security is not by obscurity; the protocol
  is assumed public.
- Through the API, the attacker can do only what the dispatcher is authorised to
  do - bounded by the auth hook and rate limits, and every call is attributed
  and logged.
- If it bypasses the API and speaks mTLS protocol straight to agents, it is held
  to the **same** bound by each agent: the approved, profiled, schema-checked,
  audited action set, at the declared privilege - and it cannot touch the
  agents' controls or audit.

So compromising the dispatcher (or the AI driving it) does **not** escalate
beyond the action set the operator already approved. The blast radius is
"everything the dispatcher was allowed to do" - fully recorded - and no more.


## Trust Model

ctrl-exec uses a private CA for all mTLS trust. The CA is created once on
the dispatcher host. All agent certificates are signed by this CA. Neither
the dispatcher nor any agent trusts certs from public CAs or other sources for
the operational port - only certs from the private CA are accepted.

The CA private key never leaves the dispatcher host. Loss of the CA key means
all agent certs must be reissued via re-pairing.


## Ports and Authentication

Port 7443 - operational (mTLS)
: All `run`, `ping`, `capabilities`, and cert renewal traffic. Both dispatcher
  and agent must present a valid cert signed by the private CA.
  `SSL_verify_mode => SSL_VERIFY_PEER` is set on both sides - there is no
  fallback to unauthenticated. An agent with no cert, an expired cert, or a
  cert from a different CA cannot connect.

Port 7444 - pairing
: Bootstrap port. The agent has no cert yet when it first connects, so client
  cert is not required. This is a deliberate bootstrap exception. Mitigations:
  the operator reviews the displayed hostname and IP before approving; the port
  is only open while `pairing-mode` is actively running; a random nonce
  prevents misrouted or replayed approvals (see below). Close the pairing port
  promptly after completing the pairing session.

Port 7445 - API
: No mTLS. All endpoints pass through the auth hook. The default behaviour
  when no hook is configured is controlled by `api_auth_default` in
  `ctrl-exec.conf`. The shipped default is `deny` - all requests are
  rejected until a hook is configured. Set to `allow` only on isolated
  networks where no credential checking is needed.

  The API binds to `127.0.0.1` by default (`api_bind` in `ctrl-exec.conf`).
  It is not reachable from the network unless `api_bind` is explicitly changed.
  For internet-facing deployments, place the API behind a reverse proxy that
  handles authentication and TLS termination rather than binding directly to
  an external interface.


## Pairing Security

Pairing code verification
: Each pairing request includes a 6-digit confirmation code derived from a
  SHA-256 hash of the agent's CSR. The agent displays this code at submission
  time. The dispatcher displays the same code alongside the hostname and IP
  in the approval prompt. The operator verifies both sides match before
  approving. This closes the social engineering path where an attacker submits
  a CSR with a spoofed hostname and the operator approves without checking the
  source. The code is computed independently on both sides from the CSR
  content - no extra network round-trip is required.

Nonce verification
: Each pairing request includes a 32-hex-character random nonce generated by
  the agent. The dispatcher stores it with the pending request and echoes it in
  the approval response. The agent verifies the nonce matches before storing
  any certs. This prevents a race condition where an approval for a different
  concurrent pairing request is accepted by the wrong agent.

Preflight writability check
: `ctrl-exec-agent request-pairing` checks that `/etc/ctrl-exec-agent` is
  writable before making any network connection. If not writable, it dies
  immediately rather than leaving a stale pending request in the dispatcher's
  pairing queue.

Stale request cleanup
: Pending requests older than 10 minutes with no approval or denial are
  automatically deleted from the pairing queue.

Hostname validation
: The agent-supplied hostname becomes the agent's registry key (a filename).
  It is validated against `^[A-Za-z0-9][A-Za-z0-9._-]*$` before the request is
  queued and again before the registry entry is written, so a hostile pairing
  client cannot use a crafted hostname (e.g. `../../...`) to write outside the
  registry directory on approval. The same validation guards `edit-agent`
  renames.

Queue depth limit
: The pairing queue is capped at 10 pending requests by default (configurable
  via `pairing_max_queue` in `ctrl-exec.conf`). Once the cap is reached,
  further connection attempts are rejected immediately with a structured error
  response. Stale expiry runs before the count is checked, so aged-out entries
  do not consume quota. This prevents a flood of pairing requests from an
  attacker across multiple source IPs from burying a legitimate request in
  `list-requests` output.

Operator review
: The operator is the last line of defence for pairing. Always verify the
  hostname and source IP displayed in `list-requests` or the interactive prompt
  before approving.


## Cert Renewal Security

Renewal uses the already-authenticated mTLS connection on port 7443. No new
trust is established - the renewal exchange is carried entirely within a session
that both sides have already authenticated.

The agent reuses its existing private key across renewals. Only the cert is
replaced. This preserves key continuity and means a renewal does not require
generating or protecting new key material.

The dispatcher only renews certs for hosts in its registry. An agent that has
been unpaired cannot receive a renewal.


## Allowlist and Execution Security

Script name validation
: All script names are validated against `/^[\w-]+$/` before allowlist lookup.
  This pattern excludes `/`, `.`, spaces, and shell metacharacters. Path
  traversal is impossible at the name level.

No shell execution
: Scripts are executed via `exec { $path } $path, @args` - the two-argument
  form that bypasses PATH lookup and invokes `execve()` directly. No shell is
  involved. Shell metacharacters in arguments have no effect.

Script directory restriction
: With `script_dirs` set in `agent.conf`, any allowlist entry pointing outside
  an approved directory is rejected at load time. The check is repeated at
  execution time, guarding against allowlist modifications between agent startup
  and a run request. At execution time the path is resolved with `abs_path`
  before the comparison, so an entry that uses `..` or a symlink to escape an
  approved directory is rejected on the real, canonical path. When `script_dirs`
  is not set, any absolute path is accepted.

Allowlist is server-enforced
: The allowlist is validated on the agent, not trusted from the dispatcher
  request. A dispatcher cannot request a script that is not in the agent's
  allowlist regardless of what it sends.

Privilege separation and per-script profiles (optional, recommended)
: With `executor_socket` set in `agent.conf`, the network-facing agent runs
  unprivileged and hands each authorised run to a small, root, no-network
  **executor** (`ctrl-exec-exec`) over a unix socket. The socket is owned by the
  agent user, mode `0600`, and the executor rejects any connection whose
  `SO_PEERCRED` uid is not the agent (a defence-in-depth check on top of the
  permissions). The executor **re-derives** the script path and its security
  profile from its own root-owned config - it trusts nothing in the request - so
  even a compromised front-end can only run an allowlisted script with its pinned
  profile, never an arbitrary command. It then applies the profile before
  `exec`: a mount namespace in which `/etc/ctrl-exec-agent` and
  `/var/lib/ctrl-exec-agent` (the control and state directories) are **read-only**
  - so even a `run_as=root` action cannot tamper with the allowlist, hook,
  config, trust map, or audit - the capability set the profile lists, `run_as`,
  and `no_new_privileges`. Every profile must be defined in `agent.conf`,
  including `default` (the profile an unannotated script resolves to) - there is
  no built-in fallback, so a script whose profile is undefined is a fatal config
  error (fail-closed) rather than running under an implicit context. The shipped
  `agent.conf.example` defines `[profile default]` as `run_as=nobody`; the rule
  is that **nothing runs as root unless a profile explicitly sets `run_as=root`**.
  Without `executor_socket`, the agent runs scripts directly in its own
  unprivileged process (no profiles). Profiles are defined in `agent.conf`
  (`[profile <name>]`) and referenced from `scripts.conf` (`profile=<name>`); see
  `agent.conf.example`.

  This split is what bounds a front-end compromise (e.g. an RCE in the
  network-facing code): the only thing that can act with privilege is the small,
  audited executor, and it can run only allowlisted scripts under their declared
  profiles. The privileged surface is kept deliberately tiny.

Schema sidecars are advertised, never executed
: A script's optional `<script>.schema.json` sidecar (see REFERENCE.md) is read
  only for allowlisted scripts, capped at 64 KiB, and treated as opaque data:
  the agent advertises it on `/capabilities` but never parses its `arguments` /
  `argv`, never validates against it, and never lets it influence execution. The
  allowlist remains the sole gate on what runs - a sidecar cannot widen the
  callable surface, and a sidecar beside a non-allowlisted script is never read.
  This is what lets the schema be safely consumed by an LLM via the MCP bridge:
  the model can only select an operator-approved script and fill
  operator-defined argument fields, never invent operations.

JSON context on stdin
: Scripts receive full request context as JSON on stdin (script name, args,
  reqid, peer IP, username, token, timestamp). The agent writes this context
  with a non-blocking write loop and a configurable timeout (`stdin_timeout`
  in `agent.conf`, default 10 seconds). If the script does not read stdin and
  the pipe buffer fills, the agent logs `ACTION=stdin-timeout` and closes the
  write end, delivering EOF to the script. The script continues to execute.
  Scripts that do not use stdin context do not need any special handling.


## Auth Hook

Two separate hooks exist with different scopes.

The dispatcher-side hook (configured via `auth_hook` in `ctrl-exec.conf`)
is called before every `run`, `ping`, `capabilities`, and API request. It
is the sole access control policy engine for the dispatcher — the dispatcher
has no built-in ACLs.

The agent-side hook (configured via `auth_hook` in `agent.conf`) is called
after allowlist validation on the agent, before script execution. It covers
`run` requests only — `ping` and `capabilities` requests do not invoke the
agent hook. The hooks are independent: both can be configured simultaneously,
or only one, or neither.

Default auth mode
: When no hook is configured, behaviour depends on the caller. CLI invocations
  (`ced run`, `ced ping`) unconditionally pass - CLI access is
  already gated by system user and group permissions. API callers are governed
  by `api_auth_default` in `ctrl-exec.conf`. The default is `deny` - all API
  requests are rejected without a hook. Set to `allow` for isolated networks
  where credential checking is not needed. This setting has no effect when a
  hook is configured.

`username` is advisory
: The `username` field is a caller-supplied string. The dispatcher does not
  authenticate it or verify it matches any local or remote account. It is
  forwarded unchanged to the hook and to the agent. Its intended purpose is
  to carry an identity assertion that the hook can forward to an external
  authentication service alongside the token - the service validates whether
  the claimed identity is consistent with the token's authority. A hook that
  grants elevated permissions based solely on `username` without validating
  it via the token or an external mechanism can be bypassed by any caller
  that sets the field to a privileged value. See SECURITY-OPERATIONS.md for
  the recommended pattern.

Argument inspection
: Always use `ENVEXEC_ARGS_JSON` in hook scripts to inspect script
  arguments. This is a reliable JSON array. `ENVEXEC_ARGS` (space-joined)
  is set for backward compatibility but is deprecated - it is lossy for
  arguments containing spaces or newlines, and naive pattern-matching on it
  can be bypassed by crafted argument values.

Per-dispatcher identity
: Auth hooks receive `ENVEXEC_DISPATCHER` (the stable dispatcher id) and
  `ENVEXEC_DISPATCHER_SERIAL` (the connecting cert serial). Per-dispatcher
  policy must key on `ENVEXEC_DISPATCHER`, never on the serial, because
  serials rotate while the id is stable.

Token forwarding
: Tokens are included in the JSON payload sent from the dispatcher to the
  agent, and in the JSON context piped to scripts on stdin. This supports
  token validation at every stage of an execution pipeline. Each hop can
  independently verify the token is still valid and still authorised for the
  stated purpose, without trusting the previous hop.

Hook isolation
: The hook executable is run via fork/exec. `local $SIG{CHLD} = 'DEFAULT'` is
  set before forking to prevent the API server's SIGCHLD reaper from collecting
  the hook process before `waitpid` can. stdout and stderr of the hook are
  redirected to `/dev/null` - output from the hook does not reach the caller.

Token logging
: Tokens are never logged by the dispatcher or the agent. They appear in the
  hook's environment and in JSON stdin. Do not log environment variables within
  the hook; log only specific fields from stdin. A hook that logs `env` output
  exposes the token in syslog.

Token in CLI
: Pass tokens via `ENVEXEC_TOKEN` environment variable rather than `--token`
  to prevent the value appearing in `ps` output.

Hook must not produce output
: The hook's stdout and stderr are discarded. Audit logging within the hook
  should use syslog.

Agent-side hook
: The agent-side hook (configured via `auth_hook` in `agent.conf`) runs
  after allowlist validation, before script execution. It covers `run`
  requests only — `ping` and `capabilities` do not invoke it. The hook
  receives the same request context including the forwarded `username` and
  `token`. It does not receive a `hosts` field; the agent is unaware of
  which other agents are targeted in the same invocation. For
  source-based restriction on the agent, use `allowed_ips` in `agent.conf`
  or `ENVEXEC_SOURCE_IP` in the hook. If no agent hook is configured,
  the agent authorises unconditionally at the agent level, relying on
  mTLS and the allowlist as its primary controls.


## File Permissions

```
/etc/ctrl-exec/ca.key              0600  root         CA private key
/etc/ctrl-exec/ca.crt              0644  root         CA certificate
/etc/ctrl-exec/dispatcher.key      0600  ctrl-exec    dispatcher private key (API service user reads it; root also can)
/etc/ctrl-exec/dispatcher.crt      0644  root         dispatcher certificate
/etc/ctrl-exec/auth-hook           0755  root         Auth hook executable
/etc/ctrl-exec/                    0750  root:ctrl-exec

/etc/ctrl-exec-agent/agent.key     0640  root:ctrl-exec-agent
/etc/ctrl-exec-agent/agent.crt     0640  root:ctrl-exec-agent
/etc/ctrl-exec-agent/ca.crt        0644  root
/etc/ctrl-exec-agent/agent.conf    0640  root:ctrl-exec-agent
/etc/ctrl-exec-agent/scripts.conf  0640  root:ctrl-exec-agent
/etc/ctrl-exec-agent/              0750  root:ctrl-exec-agent

/var/lib/ctrl-exec-agent/                    0750  ctrl-exec-agent:ctrl-exec-agent
/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers 0644 ctrl-exec-agent  trusted-dispatcher map (public serials + ids; agent-writable for rotation)

/opt/ctrl-exec-scripts/            0750  root:ctrl-exec-agent
/opt/ctrl-exec-scripts/*.sh        0750  root:ctrl-exec-agent
/opt/ctrl-exec-scripts/*.schema.json 0640 root:ctrl-exec-agent  schema sidecar (data, not executed)

/var/lib/ctrl-exec/                0770  root:ctrl-exec
/var/lib/ctrl-exec/pairing/        0770  root:ctrl-exec
/var/lib/ctrl-exec/agents/         2770  root:ctrl-exec          setgid: files inherit the ctrl-exec group
/var/lib/ctrl-exec/locks/          2770  root:ctrl-exec          setgid; lock files 0660 so root CLI + ctrl-exec API can both flock
/var/lib/ctrl-exec/runs/           2770  root:ctrl-exec          setgid; dispatcher run/status records
/var/lib/ctrl-exec/runs/*.json     0640  root:ctrl-exec

/var/lib/ctrl-exec-agent/runs/     0750  ctrl-exec-agent         async result store (agent side)
/var/lib/ctrl-exec-agent/runs/<dispatcher-id>/ 0750 ctrl-exec-agent  per-owner partition
/var/lib/ctrl-exec-agent/runs/<dispatcher-id>/*.json 0640 ctrl-exec-agent
```

The `ctrl-exec-agent` system user has no login shell and no home directory.
The `ctrl-exec` group grants non-root operators read access to the registry and
run records, so the monitoring commands (`list-agents`, `status`, `list-locks`)
run without sudo. Operations that use a private key still require root: `run` and
`ping` read the dispatcher key (`0600 ctrl-exec` - readable only by the API
service user and root, never the `ctrl-exec` group), and `maintain`,
`pairing-mode`, `rotate-cert`, `approve`/`deny` and `setup-*` use the CA key
(`0600 root`). The API server runs as the unprivileged `ctrl-exec` user, which
owns the dispatcher key; it never needs the CA key (cert renewal is driven by
`ced maintain`, which runs as root), so an RCE in the network-facing API is not
root and cannot sign new certificates.

Both run stores hold script stdout/stderr at rest, the same sensitivity as a
live run's output. They are not world-readable (records `0640`, directories
`0750`) and are purged 24 hours after a run completes. The agent-side store is
owned by the unprivileged `ctrl-exec-agent` user because the agent process
writes it directly; the dispatcher store is owned by `root:ctrl-exec`.


## Systemd Hardening

The network-facing units - the agent front-end (`ctrl-exec-agent`) and the API -
are heavily sandboxed:

```
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
```

The API unit additionally sets `ReadWritePaths=/var/lib/ctrl-exec` to
restrict filesystem write access to the runtime directory only.

Under privilege separation the agent front-end **does not execute privileged
scripts** - it does network, mTLS, allowlist, schema, and auth-hook work, then
hands the run to the executor - so this tight sandbox costs nothing and shrinks
the blast radius of an RCE in the network-facing code. Write-bearing or
privileged scripts run via the executor, not the front-end (see below).

The executor unit (`ctrl-exec-exec`) is deliberately **not** sandboxed: it is
root and needs `CAP_SYS_ADMIN` (to build each action's mount namespace),
`setuid`, and full filesystem reach to do its job. Its protection is its small,
audited surface, the peer-cred check on its socket, and the fact that it runs
only allowlisted scripts under their profiles - not an OS sandbox. Enable it only
alongside `executor_socket` in `agent.conf`.

> Legacy mode (no `executor_socket`): the front-end runs scripts directly, so
> they inherit the front-end's sandbox above - suitable for read-only/diagnostic
> scripts. For scripts that must write or hold privilege, enable the executor and
> give them a profile; that is the supported path, and it keeps the front-end
> locked down.

The agent unit sets `StateDirectory=ctrl-exec-agent`, which creates and owns
`/var/lib/ctrl-exec-agent` (mode `0750`) and is the only path the agent may
write under `ProtectSystem=strict` — the async result store lives there. It
also sets `KillMode=process` so that stopping or restarting the agent signals
only the main process: detached async jobs keep running to completion rather
than being killed with the control group, and the restarted agent serves their
results from the store. This widens nothing — detached jobs were already
children of the agent and run with the same unprivileged identity and the same
allowlist constraints; `KillMode=process` only changes which processes receive
the stop signal.

The agent unit applies additional containment:

```
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
```

`CapabilityBoundingSet=` (empty) drops all capabilities from the bounding
set, preventing any allowlisted script from acquiring capabilities regardless
of file capability bits. `MemoryDenyWriteExecute=yes` is safe for the current
bash-only script inventory but must be removed if a JIT-compiled runtime
(Java, Node.js, Python with JIT) is added to the allowlist - there is no
detection mechanism for this conflict at load time; the operator must review
this directive when adding new allowlist entries. `AF_UNIX` is required
in `RestrictAddressFamilies` because the agent connects to `/dev/log` via a
Unix domain socket to deliver syslog messages - omitting it silently blocks
all logging.


## Trusted-Dispatcher Map and Cert Rotation

The agent no longer stores a single trusted dispatcher serial. Instead it
stores a *trusted-dispatcher map* at
`/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers` (path configurable via
`trusted_dispatchers_path` in `agent.conf`, default
`/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`). The map lives in the
agent-writable state directory — not under `/etc/ctrl-exec-agent`, which
holds only secrets (the agent key, cert, and CA) — so the agent, running as
the unprivileged service user, can rewrite trusted serials in place during
cert rotation. Holding the map in the agent-writable state directory does not
weaken the lateral-reconnaissance protection: a serial is inert without a
CA-signed cert bearing it (the CA key is operator-held), and an attacker on a
compromised peer host cannot write *this* host's map. The map holds one line per
trusted dispatcher in the format `<hex-serial> <dispatcher-id>`; lines
beginning with `#` are comments. The map is loaded at startup and reloaded on
SIGHUP. This key replaces the former `dispatcher_serial_path` /
`ctrl-exec-serial` single-serial file.

On every `/run`, `/ping`, `/result`, and `/capabilities` request, the agent
checks whether the connecting client cert's serial is a *key* in the map. A
request whose peer serial is not a key is rejected with a 403. When the serial
matches, the dispatcher *identity* recorded against that key is used for
permission decisions and attribution. If the map is empty (an unpaired or
legacy agent that has not yet been re-paired), `/capabilities` logs
`capabilities-no-serial` and skips the restriction; `/run`, `/ping`, and
`/result` still hard-deny.

Each trusted dispatcher has a stable `dispatcher_id`, set via `dispatcher_id`
in `ctrl-exec.conf` (defaulting to the dispatcher's hostname) and delivered to
the agent at pairing. Per-dispatcher policy must key on this id, never on the
serial: serials rotate, the id is stable.

Native multi-dispatcher support
: An agent can serve more than one dispatcher. Pairing *appends* a dispatcher
  to the map rather than replacing the existing entry, so re-pairing to enrol
  an additional dispatcher leaves existing dispatchers trusted. Each dispatcher
  presents its own cert; all dispatcher certs and the agent cert chain to a
  shared CA root. Independent per-dispatcher CAs with SNI are explicitly out of
  scope. A dedicated single-operator agent instance remains available as
  optional defence-in-depth, but it is not the multi-dispatcher mechanism.

Async result ownership
: Runs are stored partitioned by owner at
  `/var/lib/ctrl-exec-agent/runs/<dispatcher-id>/<reqid>.json`. A
  `GET /result/<reqid>` returns a run only to the dispatcher that submitted it.
  Another dispatcher receives `404 unknown` with no disclosure of the run's
  existence or output. The agent logs `result-deny` (REASON=not-owner) when a
  dispatcher requests another dispatcher's result.

`/renew` and `/renew-complete` are intentionally exempt from the map check.
During cert rotation, the dispatcher presents its new cert before agents
receive the updated serial. Applying the map check to the renewal endpoints
would cause every agent to reject the serial broadcast, breaking the rotation
mechanism. The renewal endpoints require a valid CA-signed cert (mTLS still
applies) but do not require the peer serial to be a key in the map. See Cert
Rotation below.

The window during which these endpoints are reachable by any CA-signed cert is
the duration of the serial broadcast - on a well-connected fleet this is
seconds; on a slow fleet it is bounded by the dispatcher's connection timeout.
A host with a valid CA-signed cert calling `/renew-complete` during this window
could attempt to deliver a replacement cert, but only if it already holds a
cert signed by the private CA. If an attacker has a CA-signed cert, `/run` is
the more direct path; `/renew` abuse does not represent a meaningful
escalation.

The dispatcher cert is renewed automatically before expiry. The renewal
process and the serial tracking work together to rotate credentials without
disrupting the fleet:

Renewal trigger
: The dispatcher checks its own cert expiry at startup and every 4 hours
  (configurable via `cert_check_interval`). When fewer than `cert_renewal_days`
  remain (default: 90), it generates a new cert automatically.

Broadcast
: Immediately after generating the new cert, the dispatcher POSTs to each
  registered agent's built-in `/rotate-serial` operation in parallel, carrying
  the new serial. The agent's rotate handler adds the new serial to its
  trusted-dispatcher map and sends itself SIGHUP. The dispatcher identity is
  derived from the caller's authenticated cert serial — it is never sent in the
  request — so an agent only ever adds a serial under the calling dispatcher's
  own identity. Agents that respond successfully are marked `current` in the
  registry.

  Trust chain
  : Each new serial is authorised by the currently-trusted (previous) serial,
    which chains back to the original human-supervised pairing approval. Any
    number of rotations therefore stays rooted in that one human approval, and
    no rotation can introduce a serial that was not vouched for by an
    already-trusted one.

  Seamless rotation (0.9.0)
  : Cert rotation updates each agent's trusted-dispatcher map automatically
    over the run channel, with no re-pairing, via add-then-remove. On rotation
    the dispatcher broadcasts the *new* serial together with its stable
    `dispatcher_id`; each reachable agent *adds* it to the map against that
    identity. The *old* serial stays trusted through the overlap window, so the
    dispatcher's live cert — the old one before its process restarts, the new
    one after — is accepted throughout. After the overlap window the dispatcher
    broadcasts removal of the old serial (`retire_previous_serial`, logged as
    `serial-retire`), so the retired cert stops being trusted. Because
    `dispatcher_id` is stable across rotation, trust and attribution carry over;
    the agent can rewrite its own map because the map lives in the
    agent-writable state directory. An agent that was *offline* during the
    broadcast misses the new serial and, once the overlap window expires, is
    marked `stale` and does need re-pairing — rotation is seamless only for
    agents reachable during the broadcast.

Overlap window
: Agents that were offline during the broadcast are marked `pending`. The
  dispatcher retries them on each subsequent check interval. After
  `cert_overlap_days` (default: 30, configurable) the overlap expires and
  any remaining `pending` agents are marked `stale`. A stale agent needs
  re-pairing - it has missed the rotation window. `/run`, `/ping`, and
  `/result` deny with 403 once the new serial is not a key in the map;
  `/capabilities` warns but allows.

`ced serial-status`
: Shows the current and previous dispatcher serial, rotation timestamp,
  overlap expiry, and per-agent serial state (current/pending/stale/unknown).
  Use this to identify agents that need attention after a rotation.

`ced rotate-cert`
: Manual rotation trigger. Runs the same logic as the automatic check,
  broadcasts immediately, and reports per-agent results. Use after a suspected
  compromise or to test the rotation path.

dispatcher re-keying
: Running `setup-ctrl-exec` again generates a new cert with a new serial
  and marks all agents as pending. The dispatcher binary checks the registry
  before proceeding and displays the number of agents that will require
  re-pairing if the overlap window is missed.

Built-in `/rotate-serial` operation
: Cert rotation is handled by the agent front-end (`ctrl-exec-agent`) as a
  first-class control-plane operation — no `scripts.conf` allowlist entry is
  required, and the work runs in the front-end rather than through the executor.
  This is deliberate: with privilege separation enabled the executor mounts the
  agent's control/state directories read-only for every action, so a script
  could not write the trusted-dispatcher map; the front-end can, which is why
  rotation works identically whether or not the executor is enabled. The handler
  adds the broadcast serial to the trusted-dispatcher map (and, at retirement,
  removes the old one) and sends SIGHUP. Access is gated by the same
  trusted-dispatcher serial check as `/run`, plus the auth hook (which sees
  `ENVEXEC_ACTION=rotate`).

## Certificate Revocation

The agent maintains a revocation list at `/etc/ctrl-exec-agent/revoked-serials`
(path configurable via `revoked_serials` in `agent.conf`). On every incoming
mTLS connection, after the handshake verifies the CA signature, the peer cert
serial is checked against this list. A revoked cert is rejected with a 403
and a syslog warning before any request is processed.

The file contains one serial per line. All of the following formats are accepted
and normalised to lowercase hex on load:

- Plain hex: `deadbeef`
- Colon-separated: `DE:AD:BE:EF` (as returned by some tools and `IO::Socket::SSL`)
- `0x`-prefixed: `0xdeadbeef`
- `serial=`-prefixed: `serial=DEADBEEF` (direct output of `openssl x509 -serial`)
- Decimal integer: `3735928559`

Lines beginning with `#` are treated as comments. A missing or empty file means
no certs are revoked - the normal state for a new installation.

The revocation list is loaded at agent startup and reloaded on SIGHUP without
restarting the agent or dropping active connections:

```bash
systemctl reload ctrl-exec-agent
```

To revoke a cert:

1. Obtain the serial: `openssl x509 -noout -serial -in /etc/ctrl-exec/dispatcher.crt`
2. Append the output directly to `/etc/ctrl-exec-agent/revoked-serials` on each
   affected agent - no format conversion needed, `serial=DEADBEEF` is accepted as-is
3. Reload: `systemctl reload ctrl-exec-agent`

For fleet-wide revocation, run a ctrl-exec script that appends the serial and
sends SIGHUP on each agent. A `revoke-cert` script is a natural entry in the
agent allowlist for this purpose.

Unpairing and revocation
: `ced unpair <hostname>` removes the agent from the registry and
  prevents further cert renewal. The agent cert remains technically valid until
  natural expiry. To immediately close this window, add the agent cert serial
  to the dispatcher's own revocation check (if implemented) or decommission
  the host promptly. The revocation list on the agent only covers certs
  presented *to* the agent - it does not prevent a stolen agent cert from
  connecting to the dispatcher.

What revocation closes
: A compromised dispatcher cert that has been revoked cannot connect to any
  agent that has been updated, even though it was signed by the CA and has not
  expired. A compromised agent cert cannot be revoked via this mechanism on
  the dispatcher side - that requires the dispatcher-side equivalent (serial
  tracking work, next phase).

What revocation does not close
: A compromised cert that reaches an agent before the revocation list is updated.
  The list is only as current as the last SIGHUP. For time-critical revocation,
  restart the agent service rather than reloading - the connection is still
  rejected on reconnect but any in-flight connection from a revoked cert may
  complete if it was established before the reload.


## CA Key Protection

The CA key is the root of trust for the entire deployment. If it is
compromised, an attacker can issue valid agent certs and connect to any agent.

Recommended practices:

- Back up `/etc/ctrl-exec/ca.key` to encrypted offline storage immediately
  after `setup-ca`
- Restrict access to the dispatcher host itself; the CA key should not be
  accessible over the network
- For redundant ctrl-exec deployments, transfer the CA key over an encrypted
  channel with host key verification (`scp` with known_hosts, not
  `StrictHostKeyChecking=no`)
- Audit access to the dispatcher host via system auth logs


## Connection Hardening

Connection rate limiting
: The agent tracks connection attempts per source IP in memory. A source
  that establishes more than 10 connections within 60 seconds is blocked for
  5 minutes (volume threshold). A source that causes more than 3 TLS handshake
  failures within 600 seconds is blocked for 1 hour (probe threshold). Blocks
  are held in the agent process memory and cleared on SIGHUP. The block state
  is logged at the point the threshold is crossed; repeat checks are silent.
  Rate state is not persisted across reloads - the built-in `/rotate-serial`
  handler sends SIGHUP as part of normal rotation and clears all rate blocks as
  a side effect. A legitimate dispatcher that triggers the probe block due to a
  cert misconfiguration can be unblocked immediately with
  `systemctl reload ctrl-exec-agent`. Thresholds are configurable via
  `rate_limit_volume` and `rate_limit_probe` in `agent.conf`.

IP allowlist
: If `allowed_ips` is set in `agent.conf`, the agent enforces an IP allowlist
  before the rate check and before any request is processed. Any source IP not
  in the list is rejected immediately with the connection closed and an
  `ACTION=ip-block` syslog entry. The allowlist supports exact IPs and /8,
  /16, /24 CIDR prefixes. Invalid entries are filtered at load time with a
  warning; the agent starts normally with the remaining valid entries. When
  `allowed_ips` is absent, all source IPs are permitted.

TLS version and cipher restriction
: TLS 1.2 and TLS 1.3 only - TLS 1.0/1.1 (and SSLv3) are disabled explicitly
  via `SSL_version`, not left to the system OpenSSL policy. For TLS 1.2, only
  ECDHE cipher suites using AES-GCM are permitted; CBC mode, RC4, export-grade,
  and anonymous ciphers are excluded. TLS 1.3 suites are AEAD-only. This policy
  is defined once in `Exec::TLS::hardening` and applied to every TLS endpoint -
  the agent operational server, the dispatcher client, the pairing listener,
  and the API server (when TLS is enabled) - so it cannot drift between them.

Request body size limit
: The agent limits incoming request bodies to 1 MB. Any request declaring a
  `Content-Length` above this threshold is rejected with HTTP 413 before the
  body is read. No legitimate dispatcher request approaches this limit - the
  largest legitimate body (a `/renew-complete` cert delivery) is under 10 KB.

HTTP header count limit
: The agent limits incoming requests to 32 header lines. Any request exceeding
  this is rejected with HTTP 431 before the body is read or any handler is
  invoked. This applies to all connections including those from peers with a
  valid CA-signed cert.

Argument validation scope
: The dispatcher does not validate script argument values. Validation of arguments
  is the responsibility of the allowlisted script itself and the auth hook.
  The hook receives arguments as a JSON array via `ENVEXEC_ARGS_JSON` and
  on stdin; the script receives them directly as `@ARGV`. Neither path involves
  shell interpretation.


## API Deployment Guidance

The API binds to `127.0.0.1` by default and is not reachable from the network
without an explicit `api_bind` change in `ctrl-exec.conf`. For any deployment
where the API is reachable from outside the dispatcher host:

- Configure an auth hook. Without a hook, `api_auth_default = deny` blocks all
  requests. Set `api_auth_default = allow` only on isolated networks.
- Place the API behind a reverse proxy (nginx, caddy) that handles TLS
  termination and request rate limiting. The API has no built-in rate limiting
  and no host count cap - a reverse proxy is the appropriate layer for both.
- Enable TLS on the API by setting `api_cert` and `api_key` in
  `ctrl-exec.conf` - use a cert from a public CA if external clients will
  not have the private CA cert.

`GET /health` bypasses auth and returns the API version string. This endpoint
is publicly accessible on any externally-bound deployment. Version disclosure
is low risk in a private deployment but should be considered for
internet-facing deployments - place the API behind a proxy that strips or
restricts the `/health` path if version disclosure is a concern.

For operational security guidance (monitoring, incident response, known
limitations, Docker-specific notes), see SECURITY-OPERATIONS.md.


## Threat Summary

| Threat | Mitigation |
| --- | --- |
| Unauthenticated agent connection | mTLS on port 7443, both sides verify CA |
| Rogue dispatcher connecting to agent | Agent verifies dispatcher cert against CA |
| Pairing replay or misrouting | Nonce verified before cert storage |
| Pairing CSR injection / social engineering | 6-digit pairing code verified by operator on both sides |
| Lateral reconnaissance via capabilities | `/capabilities` restricted to the trusted-dispatcher map (per-dispatcher serial); hard deny on unknown serial; re-pair to activate |
| Script execution by non-current dispatcher cert | `/run`, `/ping`, and `/result` restricted to the trusted-dispatcher map (per-dispatcher serial); hard deny on unknown serial |
| Cross-dispatcher result disclosure | Runs partitioned per owner; `GET /result/<reqid>` owner-gated, `404 unknown` to other dispatchers (`result-deny`, REASON=not-owner) |
| Compromised dispatcher (or AI driving its API) | Bounded by each agent to the allowlisted, profiled, schema-checked, audited action set; cannot extend the allowlist, edit hook/config/trust, or erase audit |
| RCE in the agent front-end (network-facing code) | Privilege separation: the front-end is unprivileged; only the small executor can act, and it runs only allowlisted scripts under their pinned profiles (re-derived from its own root-owned config) |
| Action tampering with agent controls or audit | Executor runs every action with `/etc/ctrl-exec-agent` and `/var/lib/ctrl-exec-agent` read-only - including `run_as=root` profiles |
| Arbitrary script execution via run | Agent-side allowlist, name pattern validation |
| Path traversal in script name | `/^[\w-]+$/` excludes `/` and `.` |
| Shell injection via arguments | `exec` without shell, args passed as list |
| Argument bypass via ENVEXEC_ARGS | Use `ENVEXEC_ARGS_JSON`; `ENVEXEC_ARGS` is deprecated |
| Script outside approved directories | `script_dirs` check at load and exec time |
| Connection flood from valid cert | Rate limiting: volume block at 10 conn/60s (5 min), probe block at 3 failures/600s (1 hr) |
| Pairing queue flood | Queue depth capped at 10 (configurable via `pairing_max_queue`); stale expiry runs first |
| Header flood from valid cert | HTTP 431 after 32 header lines; connection closed before body is read |
| API host count exhaustion | 500-host ceiling per request (fixed Engine limit; not user-configurable) |
| Port scan or TLS probe from unexpected host | IP allowlist (`allowed_ips` in `agent.conf`); connection closed before any request |
| TLS downgrade or weak cipher negotiation | TLS 1.2 minimum; ECDHE+AEAD ciphers only; CBC, RC4, export-grade excluded |
| Memory exhaustion via large request body | Body size limit: 1 MB ceiling checked before read; 413 returned on excess |
| Privilege escalation via allowlisted script | Per-script profile bounds run_as + capabilities (executor); on the front-end, empty `CapabilityBoundingSet`, `MemoryDenyWriteExecute`, restricted syscall filter |
| Namespace escape from agent process | `RestrictNamespaces=yes` in agent systemd unit |
| Unauthorised API access (no hook) | `api_auth_default = deny` blocks all requests by default |
| Unauthorised API access (network) | API binds to `127.0.0.1` by default; external bind is opt-in |
| API script inventory exposure | All endpoints including `/openapi-live.json` pass through auth |
| CA key theft | 0600 root-only, offline backup, host access controls |
| Cert remaining valid after unpair | Revocation list on agent; add serial and reload |
| Compromised dispatcher cert | Add serial to revoked-serials on all agents; reload |
| Token leaking via logs | Tokens never logged by dispatcher or agent |
| Token leaking via ps | Use `ENVEXEC_TOKEN` env var not `--token` flag |


## Further Reading

SECURITY-OPERATIONS.md covers the operational side of a running deployment:
monitoring and alerting recommendations, dispatcher host security requirements,
token and credential lifecycle, auth hook operational guidance, CA compromise
recovery procedure, known limitations, and Docker-specific security notes.
