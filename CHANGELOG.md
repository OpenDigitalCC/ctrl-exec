# Changelog

High-level release history for ctrl-exec. This is a summary extract — full
detail lives in the git log; each entry is anchored to the commit ref (or the
release commit) it lands at, not a date. Bullets mark what was **added**,
**changed**, or **removed** at the level of the area touched.

## 0.9.1 — explicit serve mode

- **Changed** `ctrl-exec-agent` (`cea`) invoked with no mode: it now prints the
  usage summary and exits instead of defaulting to `serve`. A bare invocation
  previously launched the foreground server with no terminal output, which read
  as a hang. Start the server with an explicit `ctrl-exec-agent serve`; the
  systemd and procd units already do this, so service-managed agents are
  unaffected.
- **Added** a `--version` flag to `ctrl-exec-agent` (`cea`) and
  `ctrl-exec-dispatcher` (`ced`), printing the installed release version.
- **Fixed** `.deb` upgrades leaving old code running: the agent and dispatcher
  postinsts now restart `ctrl-exec-agent.service` / `ctrl-exec-api.service` on
  upgrade when already active, so the new code takes effect. Fresh installs are
  still left stopped (the agent cannot serve until paired), and a stopped or
  unconfigured service is not started.
- **Changed** the serve pre-flight to exit `78` (EX_CONFIG) instead of `1` when
  the agent is not paired, and added `RestartPreventExitStatus=78` to the unit.
  An enabled-but-unpaired agent now fails once with the "not paired" message
  instead of respawning every `RestartSec`. A genuine crash still restarts.
- **Changed** the agent to register its **fully-qualified** hostname at pairing
  (`Net::Domain::hostfqdn()`, falling back to the short name only when no domain
  is configured), instead of the bare short hostname. The short name does not
  resolve across subdomains, so a dispatcher on another network could not reach
  the agent by its registry name; the FQDN resolves consistently and survives a
  dispatcher move. Pairing now warns if no FQDN could be determined. Re-pair
  existing agents to update their registry key. The agent's self-reported host
  in run/capabilities responses is the FQDN too, for consistency.
- **Added** post-pairing enable/start instructions: a successful interactive
  pairing now prints the init-appropriate `enable`/`start` commands, since the
  agent is paired but not yet running.
- **Added** config-driven sandbox management for the agent. `agent.conf` now
  takes `sandbox = strict|moderate|off` (filesystem-protection level) and
  `writable_paths = …` (colon-separated dirs to open under the sandbox);
  `ctrl-exec-agent apply-config` renders these into a generated systemd drop-in
  (`…/50-ctrl-exec-sandbox.conf`) and reloads systemd, so writable-path policy is
  managed from `agent.conf` instead of hand-edited units (a restart applies it,
  since systemd builds the namespace before the agent starts). `serve` test-writes
  each `writable_paths` entry at startup and warns on any that are read-only,
  flagging an unapplied config. Default stays `strict`, matching the shipped unit.
- **Added** a `hint` field on run/result responses when a script's stderr shows
  "Read-only file system" (EROFS): it names the systemd sandbox as the cause -
  not permissions or a full disk - and points at `writable_paths`/`apply-config`
  and the new "Granting scripts a writable path" docs. The script's own stderr is
  left untouched.
- **Fixed** the dispatcher cert path being hardcoded as `dispatcher.crt` in the
  cert-lifecycle paths instead of honouring `ctrl-exec.conf` `cert`/`key` - the
  one place that names the cert the dispatcher actually presents. On a
  deployment whose cert is named otherwise (e.g. `ctrl-exec.crt`), `approve`
  read the serial from the absent `dispatcher.crt`, so the agent paired but
  trusted no serial and rejected every request as a "serial mismatch". The
  configured `cert`/`key` are now the single source of truth across `approve`
  (reads the serial there, and warns loudly if it cannot), `setup-ctrl-exec`
  (creates them there), and `rotate-cert` (re-keys them in place);
  `generate_dispatcher_cert` requires explicit paths with no hardcoded default.
  No migration code - existing deployments work as-is because every path now
  follows the config.
- **Fixed** a post-re-pair "serial mismatch": a running agent loads its
  trusted-dispatcher map once at startup (refreshed only on SIGHUP), so a
  re-pair that writes a new dispatcher serial to disk does not take effect until
  the agent is reloaded/restarted. The post-pairing message now detects an
  already-running agent and tells the operator to `systemctl restart
  ctrl-exec-agent` so the new certificate and serial are adopted.
- **Fixed** `serial_to_hex` not stripping an insignificant leading `00` byte in
  its plain-hex branch (the colon-separated branch already did). A dispatcher
  serial migrated from a pre-0.9.0 single-serial file as `00aabb...` never
  matched the live `aabb...` the agent reads from the cert, rejecting every
  request as a serial mismatch. All forms now canonicalise to minimal hex.
- **Added** pairing identity diagnostics on the dispatcher. When a request is
  queued the dispatcher now records a forward-confirmed reverse-DNS lookup of the
  agent's source IP (bounded by a short timeout). `list-requests` and the
  interactive approve prompt show the reported name, source IP, and reverse-DNS
  name, plus a recommendation (register the resolvable FQDN via `edit-agent
  --rename`, or fall back to `--lookup-by ip`) for when the reported short name
  will not resolve from the dispatcher - the common DHCP/network-managed-FQDN
  case. After approve, the dispatcher prints exactly what was registered (name,
  lookup_by, address) and the `edit-agent` command to change it without
  re-pairing (dispatch auth is CA-based, so no new certificate is needed).

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
