---
title: Agents
subtitle: What an agent is, how it registers, the allowlist model, and agent modes.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/AGENTS.md
current_page: /agents
---

# What an Agent Is

![ctrl-exec fleet model — agents, allowlists, and tag-based grouping](ctrl-exec-fleet-model.svg)

`ctrl-exec-agent` (`cea`) is a lightweight daemon that runs on each managed host. It listens on port 7443 over mTLS, enforces a local script allowlist, and executes scripts on request from an authorised dispatcher instance.

An agent holds no state that cannot be reconstructed from its configuration files. It does not contact the dispatcher except when responding to incoming requests — there is no polling, no keepalive, and no persistent connection.

# Agent Registration

An agent joins the fleet through the pairing protocol. Pairing is a one-time ceremony that establishes mutual trust:

- The agent receives a CA-signed certificate identifying it to the dispatcher.
- The agent records the approving dispatcher — its certificate serial and stable id — in its trusted-dispatcher map, which it checks on every subsequent connection.
- The dispatcher records the agent in the registry at `/var/lib/ctrl-exec/agents/`.

After pairing, the agent is identified by its certificate serial. The registry entry contains the hostname, IP, pairing timestamp, certificate expiry, serial confirmation state, the dispatch fields `lookup_by` (resolve by `hostname` or `ip`) and operational `port`, and the agent's cached tags.

An agent can be paired with more than one dispatcher. Re-pairing against a further dispatcher appends an entry to the trusted-dispatcher map; existing dispatchers stay trusted. Each dispatcher presents its own certificate chaining to the shared CA root and is identified by a stable `dispatcher_id`. This is the supported way to give operators of differing trust classes access to a single host — keyed per dispatcher in the auth hook and attributed in the logs — rather than running separate agent instances.

Dispatch resolves a registered agent to its stored address (`lookup_by`) and `port`, so an agent on a non-default port — or one whose reported hostname does not resolve from the dispatcher host — is reachable without per-command flags. These dispatch fields can be changed without re-pairing using `ced edit-agent` (rename, address, port, lookup mode); the certificate is unaffected.

See [Pairing](/pairing) for the full protocol and the `--lookup-by` / `--agent-port` options at approval.

# The Allowlist

The allowlist is defined in `/etc/ctrl-exec-agent/scripts.conf`. It maps short names to absolute script paths:

```ini
backup-mysql  = /opt/ctrl-exec-scripts/backup-mysql.sh
check-disk    = /opt/ctrl-exec-scripts/check-disk.sh
restart-app   = /opt/ctrl-exec-scripts/restart-app.sh
```

Only names present in this file can be requested from this agent. The allowlist is the agent's primary security boundary — not a filter on top of broad access, but the complete definition of what is possible.

Script name rules:

- Must match `[\w-]+` — alphanumeric, underscore, and hyphen only.
- No slashes, dots, or shell metacharacters.
- Names are case-sensitive.

The `script_dirs` configuration key adds a second layer: if set, only scripts under the approved directories are permitted regardless of what the allowlist says. This guards against allowlist entries pointing to unintended locations.

The allowlist and `agent.conf` reload on SIGHUP without restarting:

```bash
sudo systemctl kill --signal=HUP ctrl-exec-agent
# or on OpenWrt:
/etc/init.d/ctrl-exec-agent reload
```

# Capabilities Response

When the dispatcher calls `/discovery` on an agent, the agent returns its current capabilities: the list of allowlisted scripts (name, path, and whether the path is executable) and its tags.

This is used by `ctrl-exec-api`'s `/openapi-live.json` endpoint to generate a live OpenAPI spec reflecting the actual scripts installed on each connected agent. It is also used by `ced list-agents` to show what each agent can do.

A script that exists in the allowlist but whose path is not executable or not present is reported with `"executable": false`. Such scripts will fail at execution time.

# Agent Tags

Tags are arbitrary key/value pairs set in the `[tags]` section of `agent.conf`. They are returned in discovery and capabilities responses and can be used by external tooling to target logical groups of agents.

```ini
[tags]
env  = production
role = database
site = london
```

Tags are reloaded on SIGHUP. ctrl-exec does not interpret tag values — they are metadata for callers and integrations.

The dispatcher caches each agent's tags in the registry, refreshed from the live capabilities response on every `discovery`. `ced list-agents --tags key=value[,key=value...]` filters on the cache (AND across pairs), so the filter is fast and works offline; an agent shows no tags until the first discovery against it.

# Agent Modes

## serve

Normal operation. Listens for incoming mTLS connections from the dispatcher and serves requests.

```bash
ctrl-exec-agent serve
ctrl-exec-agent serve --config /etc/ctrl-exec-agent/agent.conf
```

## self-ping

Connects to `127.0.0.1:7443` using the agent's own certificate. Confirms the port is listening and mTLS is functional. The expected response is `403 serial mismatch` — the agent's own certificate is not a dispatcher certificate, and the agent correctly rejects it. Any other result indicates a configuration problem.

```bash
ctrl-exec-agent self-ping
```

## self-check

Validates the agent configuration without making any network connections. Checks certificate files, configuration keys, and allowlist entries. Useful for validating a new configuration before reloading.

```bash
ctrl-exec-agent self-check
```

## pairing-status

Shows the agent's current certificate, expiry date, and its trusted-dispatcher map — the serial and stable id of each dispatcher the agent trusts.

```bash
ctrl-exec-agent pairing-status
```

# Certificate Renewal

Agent certificates are renewed automatically. Renewal is triggered after every successful ping when the agent's remaining certificate validity falls below half the configured `cert_days` (default: 365 days, threshold at approximately 182 days remaining).

No operator action is needed during normal operation. Renewal failure is logged at ERR and retried on the next ping. A certificate that fails repeatedly will eventually expire and require re-pairing.

# Cert Serial Tracking

The agent holds a trusted-dispatcher map at `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers` — one line per trusted dispatcher, `<hex-serial> <dispatcher-id>`. Every incoming connection is checked against the map: a serial not present is rejected with 403 and logged as `ACTION=serial-reject`. When the serial matches, the resolved `dispatcher_id` drives permission and attribution.

After a dispatcher certificate rotation (`ced rotate-cert`), the map is updated automatically over the run channel, with no re-pairing, via add-then-remove. The dispatcher broadcasts the new serial under its stable `dispatcher_id` and each reachable agent adds it; the old serial stays trusted through the overlap window, so the dispatcher's live certificate is accepted throughout, and the old serial is removed once the window closes. Because `dispatcher_id` is stable across rotation, trust and attribution carry over. The agent rewrites the map in place, which is why it lives in the agent-writable state directory.

An agent that was offline during the broadcast misses the new serial and is later marked `serial-stale`; that agent reports `serial-reject` once the old serial is retired and should be re-paired against the dispatcher's new certificate.
