---
title: ced — CLI Reference
subtitle: Complete command reference for ctrl-exec-dispatcher.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/CLI.md
current_page: /cli
---

`ced` is the shortcut for `ctrl-exec-dispatcher`. All commands below work with either name.

# Global Options

`--config <path>`
: Path to `ctrl-exec.conf`. Default: `/etc/ctrl-exec/ctrl-exec.conf`.

`--port <n>`
: Override the default agent port (7443) for all hosts in this invocation. Individual hosts can also specify a port with `<host>:<port>` syntax.

`--json`
: Output results as JSON. Applies to `run`, `ping`, and `list-agents`.

`--username <name>`
: Username to include in the request context. Defaults to `$USER`. Advisory — forwarded to auth hooks and scripts but not verified by ctrl-exec.

`--token <token>`
: Auth token to include in the request context. Defaults to `$ENVEXEC_TOKEN` environment variable if set. Prefer passing via the environment to prevent the value appearing in `ps` output.

`--version`
: Print the installed version and exit.

# run

```
ced run [options] <host> [<host>...] <script> [-- <args>]
```

Dispatches `<script>` to one or more agents in parallel. Everything after `--` is passed to the script as positional arguments.

Exit code is 0 if all hosts returned exit 0. Non-zero if any host failed or was unreachable.

```bash
ced run host-a backup-mysql
ced run host-a host-b check-disk
ced run host-a logger -- -t app "deployment complete"
ced run host-a:7450 backup-mysql --json
ENVEXEC_TOKEN=mytoken ced run host-a backup-mysql
```

A host argument that matches a registered agent is resolved from the registry — its stored address (by the agent's `lookup_by`: hostname, or the IP recorded at pairing) and its operational port. A `<host>:<port>` argument, or one that is not a registered agent, is used verbatim. Results are keyed by the registry name; if the agent reports a different hostname for itself it is shown in brackets, e.g. `web-01 (vm-7a3f)`. The same resolution applies to `ping`.

## Asynchronous runs

For jobs longer than the dispatcher read timeout, add `--async`. The agent runs the script detached and `run` returns immediately with a request id instead of blocking; retrieve results later with `status` or `wait`.

```bash
ced run db-01 db-02 long-reindex --async
```

Each host reports `accepted`, `BUSY` (the agent is already running that script), or `ERROR`. The detached job survives the connection close and an agent restart (the agent unit uses `KillMode=process`); its result is held on the agent for 24 hours and fetched on demand.

# status

```
ced status <reqid>
```

Shows the current per-host state of an async run (`done` with output, `running`, `EXPIRED`, `BUSY`, or `ERROR`) and whether the run is `COMPLETE`. Each call fetches results from any host still running. Exit code 0 if the request is known, 1 if not.

# wait

```
ced wait <reqid> [--timeout <seconds>]
```

Polls `status` (every 2s) until every host finishes or the timeout elapses (default 300s), then prints the final result. Exit code: `0` all hosts succeeded, `1` some host failed, `2` timed out still pending.

```bash
reqid=$(ced run db-01 long-reindex --async --json | jq -r .reqid)
ced wait "$reqid" --timeout 600
```

# ping

```
ced ping [options] <host> [<host>...]
```

Pings one or more agents in parallel. Returns status, round-trip time, certificate expiry, and agent version for each host.

```bash
ced ping host-a
ced ping host-a host-b host-c
ced ping host-a --json
```

# pairing-mode

```
ced pairing-mode [--port <n>]
```

Opens the pairing listener on the pairing port (default: 7444) and waits for incoming agent CSR submissions.

Interactive when run in a terminal — requests are displayed with a prompt to approve or deny.

| Command | Action |
| --- | --- |
| `a` | Approve the current request |
| `d` | Deny the current request |
| `a1` / `d2` | Approve or deny by queue position |
| `list` | Redisplay all pending requests |
| `quit` | Exit pairing mode |

```bash
sudo ced pairing-mode
sudo ced pairing-mode --port 7444
```

# list-requests

```
ced list-requests
```

Lists pending pairing requests with hostname, source IP, received timestamp, and request ID.

# approve / deny

```
ced approve <reqid> [--lookup-by ip|hostname] [--agent-port <n>]
ced deny <reqid>
```

Approves or denies a pending pairing request by ID. Used from a separate terminal while `pairing-mode` is running, or in automated pairing workflows.

`--lookup-by`
: How dispatch resolves this agent — by its registered hostname (default) or by the IP recorded at pairing. Use `ip` when the agent-reported hostname does not resolve from the control host.

`--agent-port <n>`
: The agent's operational port (default 7443), recorded so dispatch reaches it without a per-command port.

Both override any value the agent suggested at `request-pairing`.

# list-agents

```
ced list-agents [--json] [--tags <key=value[,key=value...]>]
```

Lists all paired agents with hostname, IP, operational port, lookup mode, pairing timestamp, and certificate expiry.

`--tags` filters to agents whose cached tags match every given `key=value` pair (AND). Tags are read from the registry cache — refreshed by `discovery`, not by querying agents live — so the filter is fast and works offline. An agent shows no tags until the first discovery against it.

```bash
ced list-agents
ced list-agents --tags env=production
ced list-agents --tags env=production,role=database
```

# edit-agent

```
ced edit-agent <name> [--rename <new>] [--ip <addr>] [--agent-port <n>] [--lookup-by ip|hostname]
```

Edits a registered agent's dispatch fields, or renames it, without re-pairing. Only the dispatch-relevant fields change; the certificate and serial tracking are untouched. Renaming or re-addressing needs no re-pairing because mTLS validates the agent certificate against the CA, not the connect address. At least one change flag is required.

```bash
ced edit-agent host-a --ip 10.0.0.42
ced edit-agent host-a --agent-port 7450 --lookup-by ip
ced edit-agent old-name --rename new-name
```

# unpair

```
ced unpair <hostname>
```

Removes an agent from the registry. The agent certificate remains valid until natural expiry — decommission or reimage the host promptly and add the serial to `revoked-serials` on remaining agents.

# setup-ca

```
sudo ced setup-ca
```

Initialises the CA. One-time operation on a new ctrl-exec installation. Writes `ca.key` and `ca.crt` to `/etc/ctrl-exec/`. The CA key is the root of trust for the deployment — back it up to encrypted offline storage immediately after creation.

# setup-ctrl-exec

```
sudo ced setup-ctrl-exec
```

Generates the ctrl-exec's own TLS certificate signed by the CA. Run once after `setup-ca`. Also required on a secondary ctrl-exec in a redundant HA setup.

# rotate-cert

```
sudo ced rotate-cert
```

Generates a new ctrl-exec certificate, broadcasts the new serial to all registered agents, and tracks per-agent confirmation in the registry. For use in scheduled certificate rotation or after a certificate compromise.

The overlap window (`cert_overlap_days`, default 30 days) is the time allowed for offline agents to receive the update before they are marked stale.

# serial-status

```
ced serial-status
```

Shows the current certificate rotation state and per-agent serial confirmation status. Use after `rotate-cert` to confirm all agents have received the new serial.

# Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success — all hosts returned exit 0 |
| `1` | One or more hosts failed or were unreachable |
| `2` | Configuration or invocation error |
| `3` | Auth hook denied the request |
| `4` | Lock conflict |
