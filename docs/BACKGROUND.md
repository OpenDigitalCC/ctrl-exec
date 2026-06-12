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
  check. Both the dispatcher and the agent can run independent hooks -
  operator-written, operator-maintained, enforcing any access model (token,
  user, script pattern, argument content, source IP). The two layers are
  complementary: the allowlist restricts the available surface; the hook
  controls access to that surface.
- Token forwarding through the pipeline means each hop (dispatcher hook, agent
  hook, script itself) can independently verify that a token is still valid for
  the stated purpose - the dispatcher does not assume its own check is the last word
- Structured syslog on both sides means every operation is auditable with a
  correlated request ID
- No persistent agent on the dispatcher side - the CLI is stateless; the API
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
- Auth hook for pluggable access control - both dispatcher-side and agent-side
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
- Unpairing (`ced unpair`) for decommissioning agents
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
  <reqid>.json` (`running` then `done` with exit/stdout/stderr). The store dir
  is `0750` owned by the unprivileged agent user (the agent process writes it
  directly), records `0640`, TTL-purged, same at-rest sensitivity as the
  dispatcher store.
- *Fetch.* New agent endpoint `GET /result/<reqid>` (mTLS + serial-checked,
  same gate as `/run`) returns the stored result, `pending`, or 404. On
  `status`, the dispatcher fetches from each still-pending host, updates its
  store, and aggregates. reqid is 64-bit urandom, so an agent only returns a
  result for a reqid it actually ran.

**Resolved decisions:**

1. *Surviving agent restart* - jobs run detached via `setsid` + double-fork,
   and the agent systemd unit sets `KillMode=process` so a restart/stop kills
   only the main process and leaves detached jobs running to completion. This
   needs no privilege. (A systemd transient scope per job - `systemd-run
   --scope` - was considered for its own cgroup, but a *system* scope cannot be
   created by the non-root agent user without polkit/linger setup, so it was
   rejected in favour of the simpler KillMode=process.) On non-systemd hosts
   (procd/Alpine, containers) setsid still survives connection loss; full
   restart-survival there is best-effort and documented as such.
2. *Concurrency* - enforced agent-side: the agent refuses a second concurrent
   run of the same script while one is detached (the dispatcher lock releases
   when the async submit returns, so it cannot cover the job's lifetime).
3. *status re-auth* - `GET /status/<reqid>` re-runs the auth hook, mirroring
   `/run`; it is not just a store read.
4. *Multi-host* - one reqid spans several agents; `status` fetches from each
   still-pending host and aggregates per-host pending/done.
5. *Retention/TTL* - the agent result store mirrors the dispatcher's 24h purge;
   once a result is purged, `status` reports it as expired rather than 404.

**Build order (incremental, reviewable) — all six steps implemented on
branch `claude/async`:**

1. Agent: result store + detached exec + `running`/`done` persistence
   (`Exec::Agent::AsyncRunner`, `t/async-runner.t`).
2. Agent: `GET /result/<reqid>` (serial-checked) + `async` flag on `/run`,
   with agent-side per-script concurrency.
3. Engine: `dispatch_all` async mode (collect `accepted`) + `result_all`
   (fetch by reqid).
4. Dispatcher reqid->host registry in `runs/<reqid>.json` + `status`
   aggregation/fetch (`Exec::RunStore`, `t/run-store.t`).
5. API `POST /run {async}` (202) + `GET /status` async semantics; CLI
   `run --async`, `status`, `wait`.
6. Install/packaging (agent runs dir, systemd `KillMode=process` +
   `StateDirectory`), docs (REFERENCE/API/SECURITY/openapi/website), and a
   lifecycle integration test.


### Model Context Protocol (MCP) bridge

Make ctrl-exec callable by LLM agents through MCP, so an operator's fleet of
allowlisted scripts becomes a set of tools an AI client (Claude Desktop, an
agent runtime) can discover and invoke. The headline is a security property,
not a feature: the **allowlist and the per-script argument schema constrain the
callable surface**, so an LLM can only select operator-approved scripts with
operator-defined argument shapes - it cannot invent operations. The auth hook
gates *who* may call; the allowlist gates *what* exists; the schema gates *how*
each is shaped. This is novel relative to the typical MCP server, which exposes
hand-written tools with no equivalent operator-owned execution boundary.

**Architecture - the core invariant: core transports the schema, the bridge
interprets it.** Core gains one small, MCP-agnostic capability ("self-describing
scripts"); everything that knows the word "MCP" - JSON-RPC, tools, transports,
versioned tool synthesis - lives in the bridge, a *management-interface plugin*
in the `ctrl-exec-plugins` ecosystem that consumes `ctrl-exec-api` over HTTP and
never links `Exec::Engine`. Keeping the (fast-moving) MCP spec out of core lets
the bridge iterate on its own cadence.

**Self-describing scripts (the only part in core):**

- Optional sidecar `<script>.schema.json` beside each allowlisted script.
  *Neutral name, neutral content*: a JSON Schema (2020-12) for the script's
  arguments plus protocol-agnostic metadata - `description` and the behavioural
  flags `read_only` / `destructive` / `idempotent`. No MCP vocabulary in the
  file, so the same schema is reusable by `/openapi-live.json` arg typing, a
  web-form renderer, or auth-hook validation - which is why this earns its place
  in core on its own merit, independent of MCP. (MCP has no filesystem discovery
  of its own - a client only learns tools via the `tools/list` RPC - so the
  filename is a private agent<->bridge detail; any "MCP-ready" signal, if wanted,
  is a `/capabilities` wire field, never a filename.)
- The agent reads the sidecar **only for allowlisted scripts** (no directory
  scanning), parses it as untrusted, size-capped data (parse failure -> advertise
  the script with no schema and log a warning), derives a schema version, and
  includes `schema` + `schema_version` in the `/capabilities` response. Reloaded
  on SIGHUP with the allowlist.
- *Schema version identity*: an explicit `version`/`$id` in the sidecar if
  present, else a short sha256 over the canonical-JSON schema. Two hosts
  declaring the same version with different content is an operator error the
  bridge surfaces loudly - it is never silently reconciled.
- `/discovery` carries the schema fields through unchanged.
- The schema is **advertised data, never executed**. The allowlist still governs
  what runs; surfacing a schema changes nothing about execution.

**Tool model - versioned Model A.** One MCP tool per *(script name, schema
version)* group - not one per script (which would silently reconcile divergent
schemas across a drifted fleet), and not one per host x script (which explodes
with fleet size and discards parallel dispatch). The bridge pulls `/discovery`,
collects `(host, script, schema, version)` tuples, groups by `(script,
version)`, and emits one tool per group with that group's faithful schema and a
`hosts` argument enum-scoped to the hosts running that version. A homogeneous
fleet yields one tool per script (identical to plain Model A); a tool splits
into `name@v1` / `name@v2` only while the fleet genuinely runs two versions,
making drift *visible to the LLM* rather than reconciled away. List size is
`O(scripts)` steady-state, `O(scripts x versions-in-flight)` mid-rollout. This
keeps the LLM-facing tool list small and stable while preserving parallel
multi-host dispatch (one `tools/call` -> many hosts) - the system's defining
strength.

**Bridge behaviour (caller contract):**

- *tools/list*: the synthesised versioned tools above; the behavioural flags map
  to MCP annotations (`read_only`->`readOnlyHint`, `destructive`->
  `destructiveHint`, `idempotent`->`idempotentHint`). `notifications/
  tools/list_changed` fires when discovery changes.
- *tools/call*: validate the LLM's arguments against the group schema (fail
  fast), then `POST /run` with the chosen hosts + script + args using the
  **async path** (`run {async}` + poll `/status`) so a long job is not bound by
  the dispatcher `read_timeout`; optionally emit MCP progress notifications while
  polling. This reuses the long-running-jobs machinery directly.
- *Result mapping*: stdout -> MCP text content; JSON stdout -> structured content
  (a script convention, not a protocol change). A multi-host run returns one
  result carrying per-host blocks with each host's exit/status. `isError` is true
  only for total failure (no host succeeded, dispatch error, or auth denial); a
  partial success returns `isError:false` with the per-host breakdown so the
  model sees which hosts failed.
- *Transports*: stdio and Streamable HTTP. The translation core is shared; the
  transports differ mainly in identity.
- *Identity*: the bridge adds **no** auth policy - it transports identity to
  ctrl-exec's existing auth hook, the single policy point. stdio inherits the
  operator on the dispatcher host and their configured ctrl-exec credentials; HTTP
  authenticates the MCP client and maps it to a ctrl-exec `username` + `token`
  forwarded to `/run`. Scope is MCP **tools only** - no resources, prompts, or
  sampling in v1.

**Resolved decisions:**

1. The bridge is wholly a management-interface plugin consuming `ctrl-exec-api`
   over HTTP; it does not link `Exec::Engine`. The only core change is generic
   schema advertisement.
2. The sidecar is neutral-named (`<script>.schema.json`) and neutral-content
   (args JSON Schema + `description` + `read_only`/`destructive`/`idempotent`).
   The filename is a private agent<->bridge detail.
3. Versioned Model A: one tool per `(script, schema-version)`; fleet drift is
   surfaced, never silently reconciled.
4. Schema is transported by core, interpreted and validated by the bridge, and
   never executed.
5. Both transports (stdio + Streamable HTTP) from the start; identity is mapped
   onto the existing auth hook, the bridge adds no policy.
6. `tools/call` dispatches via the async path and polls, reusing the
   long-running-jobs machinery so MCP calls are not bound by `read_timeout`.

**Build order (incremental, reviewable):**

Core (`ce`) - a small point release, useful independent of MCP:

1. Sidecar contract + version-identity rule (spec/docs) - drafted in
   `docs/SCHEMA-SIDECAR.md`. This `/capabilities` schema field is the **seam**
   between the two halves - ratify its field names, version rule, collision
   behaviour, and empty-sidecar fallback first, then core and bridge can proceed
   in parallel.
2. Agent: read sidecars for allowlisted scripts, derive the version, advertise
   `schema`/`schema_version` in `/capabilities`; SIGHUP reload; graceful on
   missing/invalid; unit tests.
3. `/discovery` passthrough of the schema fields (and optional
   `/openapi-live.json` arg typing); tests.
4. Docs: REFERENCE / PLUGINS / SECURITY (the convention, the version rule, the
   advertised-not-executed property).

Bridge (`ctrl-exec-plugins` repo):

5. JSON-RPC 2.0 core + `initialize` / `tools/list` / `tools/call`.
6. Discovery client + versioned tool synthesis + `list_changed`.
7. `tools/call` -> async `/run` + poll `/status`; result/error mapping; optional
   progress notifications.
8. Transports: stdio first, then Streamable HTTP with client-identity ->
   ctrl-exec token mapping.
9. Argument validation against the schema; packaging + example client configs
   (Claude Desktop stdio, HTTP endpoint).

**Deferred / out of scope (v1):** MCP resources, prompts, and sampling;
`outputSchema`; HTTP-transport rate limiting and multi-tenant identity beyond
token forwarding.
