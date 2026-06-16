# Changelog

High-level release history for ctrl-exec. This is a summary extract — full
detail lives in the git log; each entry is anchored to the commit ref (or the
release commit) it lands at, not a date. Bullets mark what was **added**,
**changed**, or **removed** at the level of the area touched.

## 0.9.0 — native multi-dispatcher and seamless rotation

Lands at the `release: 0.9.0` commit.

- **Added** native multi-dispatcher support: an agent serves more than one
  dispatcher. Trust is keyed on a per-dispatcher map (`<serial> <id>` entries)
  at `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`; pairing *appends* a
  dispatcher rather than replacing the previous one.
- **Added** a stable dispatcher identity (`dispatcher_id`, defaults to the
  dispatcher hostname), delivered at pairing and rotation; permission and
  attribution key on the identity, never the rotating serial.
- **Added** per-call attribution: a `DISPATCHER` field on agent
  run/ping/result/capabilities logs, and `ENVEXEC_DISPATCHER` /
  `ENVEXEC_DISPATCHER_SERIAL` in the agent auth-hook environment.
- **Added** an owner-partitioned async result store
  (`runs/<dispatcher-id>/<reqid>.json`) with an owner-gated `GET /result/<reqid>`
  — a run's output is returned only to the dispatcher that submitted it.
- **Changed** cert rotation to seamless add-then-remove against the trusted map
  (broadcast the new serial under the stable identity, keep the old through the
  overlap window, then retire it) — no re-pairing for reachable agents.
- **Changed** the trusted store from a single dispatcher serial in `/etc` to the
  agent-writable map in the state dir, so rotation can update trust in place;
  legacy single-serial installs are migrated automatically on upgrade.
- **Removed** the single-trusted-serial model (`ctrl-exec-serial`,
  `dispatcher_serial_path`, `load_dispatcher_serial`).
- **Fixed** packaging: the dispatcher `.deb` now ships
  `ctrl-exec-api.service` (the named systemd unit was previously dropped by
  `dh_installsystemd`).

## 0.8.x — MCP, async jobs, and the dispatcher/agent split

Release commits through `v0.8.14`.

- **Added** MCP integration: self-describing script schema sidecars in core and
  the `ctrl-exec-mcp` bridge plugin.
- **Added** asynchronous / long-running jobs — detached execution with a
  result store polled via `status` / `wait`.
- **Added** `.deb` packaging tracked in-repo with stale-version pruning.
- **Changed** naming throughout to the dispatcher/agent split: the control-host
  binary and package became `ctrl-exec-dispatcher`, cert files
  `dispatcher.{crt,key}`, cert CN `ctrl-exec-dispatcher`.
- **Changed** pairing/dispatch addressing: register the agent's real IP behind
  NAT, resolve every verb through one registry path, and fail loudly on unknown
  agents.
- **Added** pairing-mode session timeout and start/stop subcommands.

## 0.7.x and earlier

Release commits through `v0.7.7` and the `v0.1`–`v0.6` series. Foundational
work, summarised by theme (see the git log for per-tag detail):

- **Added** the core mTLS control plane: dispatcher CA, agent pairing with a
  6-digit confirmation code, and the allowlisted `/run` / `/ping` /
  `/capabilities` agent endpoints.
- **Added** the auth-hook trust model (default-deny), rate limiting, IP
  allowlisting, cert revocation, and the agent-side serial restriction on
  `/capabilities`.
- **Added** cert rotation with an overlap window, the agent registry, tag-based
  discovery, and the optional `ctrl-exec-api` HTTP API with an OpenAPI spec.
- **Added** the CycloneDX SBOM, the release tooling (`make-release.sh`), and
  brand repackaging.
