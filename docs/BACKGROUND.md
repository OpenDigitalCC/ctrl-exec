---
title: ctrl-exec - Project Background Notes
subtitle: Problem context, design decisions, and current state
brand: odcc
---

# ctrl-exec - Project Background Notes


## The Problem

Managing a fleet of servers - hosting provider infrastructure, a mix of
application and service hosts. Need to run scripts on remote hosts regularly:
maintenance tasks, health checks, backups, service restarts, config pushes.

The obvious tool is SSH. But SSH at scale has friction:

- Key distribution and rotation across hosts
- Every operator needs shell access to every host they might need to touch
- Shell access means broad access - hard to restrict to specific operations
- Audit trail is incomplete - you can log SSH sessions but not easily log
  "operator X ran backup script on host Y at time Z with these arguments"
- SSH is designed for interactive use; scripted SSH is workable but feels wrong


## Options Evaluated

Traditional configuration management (Ansible / Salt / Puppet)

The obvious enterprise answer. Evaluated and rejected for this use case:

- Significant operational overhead for a small fleet
- Heavyweight dependency footprint - Python, additional packages, control plane
  infrastructure
- Designed for configuration management, not lightweight task execution
- Complexity disproportionate to the problem size
- Our infrastructure philosophy: keep host systems minimal and clean;
  avoid large dependency trees

Fabric / Paramiko (Python SSH wrappers)

- Still SSH underneath - inherits the key management and access control problems
- Python dependency on all hosts
- No built-in access control model

Custom SSH with ForceCommand

- Restricts SSH sessions to a specific command - closer to the right model
- Still requires SSH key management
- ForceCommand is per-key, not per-operation - restricts what a key can do but
  does not give per-script granularity easily
- No structured logging of operations
- Awkward to extend or maintain

HTTP APIs on each host

- Considered briefly - each service exposing its own management API
- Per-service, not general purpose - does not solve the "run arbitrary
  maintenance scripts" problem
- No consistent auth or logging model across services


## Why Something New

The use case is specific enough that nothing fitted cleanly:

- Small fleet (tens of hosts, not hundreds)
- Operator-initiated, not scheduled/automated (initially)
- Need strict control over what can be executed
- Structured audit logging is a hard requirement
- Minimal host footprint - runs lean, no heavyweight agents
- Perl is the house language - readable, maintainable, no additional runtime
- European infrastructure - supply chain matters, dependency on external package
  registries kept minimal
- Debian trixie system packages only - no CPAN, no pip, nothing that requires
  internet access at install time

The core insight: what was actually needed was not remote shell access but
remote procedure call - a specific, named operation, with known arguments, on a
known host, authorised by a known identity, logged completely.


## What ctrl-exec Is

A purpose-built mTLS-authenticated RPC system for script execution. Each agent
exposes exactly the scripts the operator has allowed. Nothing else is reachable.

- The allowlist is the primary security control - defined on the agent, not the
  caller. It controls what scripts exist and are permitted to be called at all.
  No allowlist entry means the script cannot be called regardless of any token
  or credential.
- The auth hook is the policy engine for who is authorised to call a permitted
  script, with what token, with what arguments. It runs after the allowlist
  check. Both the ctrl-exec and the agent can run independent hooks -
  operator-written, operator-maintained, enforcing any access model (token,
  user, script pattern, argument content, source IP). The two layers are
  complementary: the allowlist restricts the available surface; the hook
  controls access to that surface.
- Token forwarding through the pipeline means each hop (ctrl-exec hook, agent
  hook, script itself) can independently verify that a token is still valid for
  the stated purpose - ctrl-exec does not assume its own check is the last word
- Structured syslog on both sides means every operation is auditable with a
  correlated request ID
- No persistent agent on the ctrl-exec side - the CLI is stateless; the API
  server is optional
- Pairing is a deliberate one-time ceremony - the operator reviews and approves
  each agent before it joins the fleet


## What It Is Not

- Not a configuration management system
- Not a scheduler or cron replacement (though it could be called from one)
- Not designed for hundreds of hosts or high-frequency automation (yet)
- Not a general-purpose SSH replacement


## Current State

Fully functional for the primary use case. The system has:

- mTLS pairing and operational communication
- Per-host script allowlists with argument passthrough
- Script directory restriction (`script_dirs`) for defence against allowlist
  misconfiguration
- Parallel execution across multiple hosts
- Auth hook for pluggable access control - both ctrl-exec-side and agent-side
- Token and username forwarding through the full execution pipeline to scripts
- Full request context piped as JSON to script stdin for downstream inspection
- Automatic cert renewal over the live mTLS connection - no operator involvement
  during normal operation
- Concurrency locking (prevents duplicate concurrent runs of the same script)
- Persistent agent registry with cert expiry tracking
- Agent tags for grouping and discovery filtering
- HTTP REST API for integration with external tools
- Agent capability discovery
- Interactive pairing mode with approve/deny prompt; non-interactive via
  separate `approve`/`deny` commands
- Unpairing (`ctrl-exec unpair`) for decommissioning agents
- Structured syslog throughout with correlated request IDs
- Systemd service units for both agent and API server
- Installer for Debian/Ubuntu (apt) and Alpine Linux (apk) with automatic
  platform detection; systemd is optional and skipped gracefully when absent
- Docker deployment support with documented entrypoint patterns and
  compose configuration (see `DOCKER.md`)
- RPM-based systems (RHEL, Rocky, Alma) are not yet supported by the
  installer; the note in install.sh points to DEVELOPER.md for manual setup


## The Broader Context

Designed for users who specialises in managed hosting of open source applications on
European infrastructure. The ethos is: use open tools, keep things simple,
maintain full control of the stack. ctrl-exec reflects that - it is a small,
focused tool built from standard Perl and system packages, doing exactly one
thing well, with no external dependencies and no unnecessary complexity.

The project was also an exploration of what modern Perl looks like for
infrastructure tooling - not the Perl of legacy sysadmin scripts, but
structured, testable, modular code using current idioms. That aspect may be
worth covering separately.

The Alpine and Docker support adds a useful deployment dimension: the
ctrl-exec API can be containerised and run as a thin control-plane service,
with agents running either on bare metal or in their own containers. The
separation of the CA and registry onto a persistent volume keeps the container
itself stateless - an image rebuild does not affect any paired agents.


## Future Directions

### Asynchronous (long-running) execution

A job that runs longer than `read_timeout` currently fails on the dispatcher
side while the script keeps running on the agent, and its result is lost (the
agent finishes the script and then writes to a closed connection). The agreed
direction is **true async**: decouple job duration from connection lifetime by
persisting results on the agent and fetching them later. The synchronous path
remains the default; async is opt-in.

**Caller contract (front-end, stable):**

- `ced run --async <hosts> <script>` / `POST /run {"async":true}` returns a
  `reqid` immediately (`202 Accepted`), does not block.
- `ced status <reqid>` / `GET /status/<reqid>` returns `pending` while running,
  then the per-host result (exit/stdout/stderr).
- `ced wait <reqid> [--timeout N]` is client-side polling of `status`.

**Protocol (back-end):**

- *Submit.* The dispatcher auths + locks + mints the reqid as today, then posts
  `/run` to each agent with an `async` flag. The agent validates (serial,
  allowlist, agent hook), starts the script **detached** (it must survive the
  connection close and the agent reloading), returns `{status:"accepted",
  reqid}`, and closes the connection. The dispatcher records its own
  `runs/<reqid>.json` with the host list and per-host `pending`, and returns
  the reqid to the caller.
- *Run + persist.* A detached reaper on the agent waits for the script and
  writes the result to an agent-side store `/var/lib/ctrl-exec-agent/runs/
  <reqid>.json` (`running` then `done` with exit/stdout/stderr). Root-owned
  0750, TTL-purged, same at-rest sensitivity as the dispatcher store.
- *Fetch.* New agent endpoint `GET /result/<reqid>` (mTLS + serial-checked,
  same gate as `/run`) returns the stored result, `pending`, or 404. On
  `status`, the dispatcher fetches from each still-pending host, updates its
  store, and aggregates. reqid is 64-bit urandom, so an agent only returns a
  result for a reqid it actually ran.

**Resolved decisions:**

1. *Surviving agent restart* - each async job runs in its own systemd
   transient scope (`systemd-run --scope --unit ce-job-<reqid> -- ...`), so it
   is independent of the agent unit and survives `systemctl restart
   ctrl-exec-agent`. On hosts without systemd (procd/Alpine, containers) the
   agent falls back to `setsid` + double-fork, where restart-survival is
   best-effort and documented as such.
2. *Concurrency* - enforced agent-side: the agent refuses a second concurrent
   run of the same script while one is detached (the dispatcher lock releases
   when the async submit returns, so it cannot cover the job's lifetime).
3. *status re-auth* - `GET /status/<reqid>` re-runs the auth hook, mirroring
   `/run`; it is not just a store read.
4. *Multi-host* - one reqid spans several agents; `status` fetches from each
   still-pending host and aggregates per-host pending/done.
5. *Retention/TTL* - the agent result store mirrors the dispatcher's 24h purge;
   once a result is purged, `status` reports it as expired rather than 404.

**Build order (incremental, reviewable):**

1. Agent: result store + detached exec + `running`/`done` persistence (no
   endpoint yet) - exercised by a local unit test.
2. Agent: `GET /result/<reqid>` (serial-checked) + `async` flag on `/run`.
3. Engine: `dispatch_all` async mode (collect `accepted`) + `result_all`
   (fetch by reqid).
4. Dispatcher reqid->host registry in `runs/<reqid>.json`; `status`
   aggregation + fetch.
5. API `POST /run {async}` + `GET /status` async semantics; CLI `run --async`,
   `status`, `wait`.
6. Install/packaging (new agent runs dir, systemd `ReadWritePaths`/`KillMode`),
   docs (REFERENCE/API/SECURITY/website), tests across the lifecycle.
