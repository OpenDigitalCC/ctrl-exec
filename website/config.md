---
title: Configuration Reference
subtitle: All configuration keys for ctrl-exec.conf, agent.conf, and the ENVEXEC_ hook interface.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/CONFIG.md
current_page: /config
---

# /etc/ctrl-exec/ctrl-exec.conf

| Key | Default | Description |
| --- | --- | --- |
| `port` | `7443` | mTLS port agents connect to |
| `cert` | — | Path to the ctrl-exec TLS certificate |
| `key` | — | Path to the ctrl-exec private key |
| `ca` | — | Path to the CA certificate |
| `auth_hook` | — | Path to the auth hook executable. Optional. |
| `api_port` | `7445` | HTTP port for `ctrl-exec-api` |
| `api_cert` | — | TLS certificate for the API server. Enables TLS when set. |
| `api_key` | — | TLS private key for the API server |
| `api_bind` | `127.0.0.1` | Address the API server binds to |
| `api_auth_default` | `deny` | API behaviour when no hook is configured: `deny` or `allow` |
| `auth_deny_generic` | `0` | When `1`/`yes`, API denials return a generic `403` (`forbidden`) without the specific reason or code |
| `cert_days` | `365` | Lifetime in days for new and renewed agent certificates |
| `cert_renewal_days` | `90` | Begin cert renewal when this many days of validity remain |
| `cert_overlap_days` | `30` | Days to retry serial broadcast before marking an agent stale |
| `cert_check_interval` | `14400` | Seconds between internal cert expiry checks (4 hours) |
| `read_timeout` | `60` | Seconds to wait for a response from an agent |
| `pairing_port` | `7444` | Port for the pairing listener |
| `pairing_max_queue` | `10` | Maximum pending pairing requests held at once |
| `registry_dir` | `/var/lib/ctrl-exec/agents/` | Agent registry directory |

# /etc/ctrl-exec-agent/agent.conf

| Key | Default | Description |
| --- | --- | --- |
| `port` | `7443` | Port the agent listens on |
| `cert` | — | Path to the agent TLS certificate |
| `key` | — | Path to the agent private key |
| `ca` | — | Path to the CA certificate (for verifying ctrl-exec connections) |
| `auth_hook` | — | Path to the agent-side auth hook executable. Optional. |
| `script_dirs` | — | Colon-separated list of approved script directories. If set, only scripts under these directories are permitted regardless of the allowlist. |
| `revoked_serials` | `/etc/ctrl-exec-agent/revoked-serials` | Path to the certificate serial revocation list |
| `dispatcher_serial_path` | `/etc/ctrl-exec-agent/dispatcher-serial` | Path to the stored ctrl-exec serial number |
| `allowed_ips` | — | Comma-separated IP addresses or CIDR prefixes permitted to connect. All IPs permitted if unset. |
| `rate_limit_volume` | `10/60/300` | Volume threshold: `limit/window_seconds/block_seconds` |
| `rate_limit_probe` | `3/600/3600` | Probe threshold (TLS failures): `limit/window_seconds/block_seconds` |
| `stdin_timeout` | `10` | Seconds to wait for a script to consume stdin context |
| `pairing_port` | `7444` | Port to connect to on ctrl-exec during pairing |
| `disable_rate_limit` | `0` | Set to `1` to disable rate limiting. Only for test environments. |

## Agent Tags

The `[tags]` section in `agent.conf` sets arbitrary key/value metadata returned in discovery and capabilities responses. Tags are reloaded on SIGHUP.

```ini
[tags]
env  = production
role = database
site = london
```

## scripts.conf

The allowlist is a separate file at `/etc/ctrl-exec-agent/scripts.conf`. Each line maps a short name to an absolute script path:

```ini
backup-mysql  = /opt/ctrl-exec-scripts/backup-mysql.sh
check-disk    = /opt/ctrl-exec-scripts/check-disk.sh
restart-app   = /opt/ctrl-exec-scripts/restart-app.sh
```

Script names must match `[\w-]+`. The file reloads on SIGHUP.

# ENVEXEC_* Environment Variables

These variables are passed to auth hooks by ctrl-exec and by the agent. They use the `ENVEXEC_` prefix in all distributions — this prefix is never substituted by `make-release`.

| Variable | Type | Description |
| --- | --- | --- |
| `ENVEXEC_ACTION` | string | Operation type: `run`, `ping`, or `api` |
| `ENVEXEC_SCRIPT` | string | Script name requested. Empty for ping. |
| `ENVEXEC_HOSTS` | string | Comma-separated list of target hosts |
| `ENVEXEC_ARGS` | string | Space-joined arguments. Ambiguous for arguments containing spaces — use `ENVEXEC_ARGS_JSON` instead. |
| `ENVEXEC_ARGS_JSON` | JSON string | Arguments as a JSON array. Reliable for all argument values. |
| `ENVEXEC_USERNAME` | string | Username from the request. Caller-supplied; not verified by ctrl-exec. |
| `ENVEXEC_TOKEN` | string | Auth token from the request |
| `ENVEXEC_SOURCE_IP` | string | `127.0.0.1` for CLI callers; caller IP for API callers |
| `ENVEXEC_TIMESTAMP` | string | ISO 8601 UTC timestamp of the request |

# Docker Environment Variable

| Variable | Description |
| --- | --- |
| `DISPATCHER_HOST` | Hostname or IP of the ctrl-exec instance, used in agent container entrypoints during pairing |
