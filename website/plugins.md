---
title: Plugins
subtitle: The ctrl-exec-plugins repository — ready-built scripts, auth hooks, and management interfaces.
updated: 2026-03-16
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/PLUGINS.md
current_page: /plugins
---

# What a Plugin Is

A plugin is a script deployable to an agent's allowlist. Plugins are not compiled or installed — they are ordinary scripts that an operator adds to `/opt/ctrl-exec-scripts/` on an agent and registers in `scripts.conf`.

The `ctrl-exec-plugins` repository provides a collection of ready-built plugins covering common infrastructure tasks. They are starting points: review, adapt, and test each one in your environment before deploying to production.

Repository: [github.com/OpenDigitalCC/ctrl-exec-plugins](https://github.com/OpenDigitalCC/ctrl-exec-plugins)

# Repository Structure

The repository is organised into three categories:

Agent scripts
: Scripts deployed to agent hosts and added to the allowlist. Common tasks across Linux systems, OpenWrt, databases, and web servers.

Auth hooks
: Hook implementations for common identity systems: LDAP, OIDC, token registries, time-of-day restrictions. Drop into `/etc/ctrl-exec/hooks/` or `/etc/ctrl-exec-agent/hooks/` and configure `auth_hook` in the relevant conf file.

Management interfaces
: Browser-based API UIs, client libraries, and OpenAPI collection files. Run on the control host or externally. Consume `ctrl-exec-api`.

# Using a Plugin

1. Review the script source. Understand what it does and what arguments it accepts.
2. Copy it to the agent host:
   ```bash
   scp plugins/agent/check-disk.sh agent-host:/opt/ctrl-exec-scripts/
   ssh agent-host chmod +x /opt/ctrl-exec-scripts/check-disk.sh
   ```
3. Add it to the allowlist on the agent:
   ```ini
   check-disk = /opt/ctrl-exec-scripts/check-disk.sh
   ```
4. Reload the agent:
   ```bash
   ced run agent-host reload-config
   # or directly on the agent:
   sudo systemctl kill --signal=HUP ctrl-exec-agent
   ```
5. Verify the script is available:
   ```bash
   ced ping agent-host --json
   ```

# Writing a Plugin

A plugin is any executable script. It receives request context on stdin as a JSON object and as `ENVEXEC_*` environment variables. Arguments are passed on the command line.

Minimum requirements:

- Executable (`chmod +x`)
- Exits with 0 on success, non-zero on failure
- Produces useful output on stdout (captured and returned to the caller)
- Does not depend on interactive input

Example — a minimal disk check plugin:

```bash
#!/bin/bash
set -euo pipefail
THRESHOLD=${1:-90}
USAGE=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$USAGE" -ge "$THRESHOLD" ]; then
    echo "CRITICAL: disk usage ${USAGE}% >= threshold ${THRESHOLD}%"
    exit 1
fi
echo "OK: disk usage ${USAGE}%"
exit 0
```

Register it in `scripts.conf`:

```ini
check-disk = /opt/ctrl-exec-scripts/check-disk.sh
```

Call it with a custom threshold:

```bash
ced run host-a check-disk -- 85
```

## Describing arguments (optional schema sidecar)

A plugin can ship an optional schema sidecar so tools — notably the MCP bridge, but also a UI or the live OpenAPI spec — can present its arguments in a typed, self-describing way. Drop a JSON file beside the script with `.schema.json` appended:

```
/opt/ctrl-exec-scripts/check-disk.sh
/opt/ctrl-exec-scripts/check-disk.sh.schema.json
```

```json
{
  "version": "2",
  "description": "Check disk usage against a threshold",
  "read_only": true,
  "arguments": {
    "type": "object",
    "properties": { "threshold": { "type": "integer", "minimum": 1, "maximum": 100 } }
  },
  "argv": [ { "arg": "threshold" } ]
}
```

The `arguments` block is a JSON Schema for the named inputs; `argv` maps those named inputs onto the script's positional arguments; the `read_only` / `destructive` / `idempotent` flags describe the operation. The sidecar is entirely optional — a script without one stays callable, just untyped. It is advertised in the agent's capabilities response and reloaded on SIGHUP. See the [schema sidecar contract](https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/SCHEMA-SIDECAR.md) for the full format and rules.

# Capabilities Advertising

When ctrl-exec calls `/discovery` on an agent, the agent returns its current allowlist as a capabilities response. This is how `ctrl-exec-api`'s `/openapi-live.json` endpoint knows which scripts are available on each agent at any given time. When a script has a schema sidecar, its `schema` and `schema_version` are included in the response (and surfaced in `/openapi-live.json` under `x-ctrl-exec-scripts`).

A script listed in `scripts.conf` that does not exist or is not executable is reported with `"executable": false`. It will fail at execution time. Run `cea self-check` to validate the allowlist before reloading.

# Distributing Plugins Across a Fleet

Use `ced run` to push plugins to multiple agents at once. Add a `deploy-plugin` script to your management host's allowlist that copies a named plugin from a shared location and reloads the allowlist. Then deploy across the fleet:

```bash
ced run host-a host-b host-c deploy-plugin -- check-disk
```
