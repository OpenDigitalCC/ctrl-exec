---
title: ctrl-exec API
subtitle: HTTP REST API reference, OpenAPI spec, and live spec generator
brand: odcc
---

This document covers the HTTP REST API exposed by `ctrl-exec-api`, the
OpenAPI specification, and the live spec generator that augments the spec
with discovered host and script data.

For installation and configuration of the API server, see INSTALL.md. For
the agent-side wire format (the mTLS protocol between dispatcher and agents),
see DEVELOPER.md.


## Overview

`ctrl-exec-api` exposes the same run, ping, and discovery operations as the
dispatcher CLI, as HTTP endpoints with JSON request and response bodies. The
auth hook and lock checking apply identically to CLI and API requests.

Endpoints: `GET /`, `GET /health`, `POST /ping`, `POST /run`,
`GET /discovery`, `POST /discovery`, `GET /status/{reqid}`,
`GET /openapi.json`, `GET /openapi-live.json`.

The server listens on `api_port` (default 7445). TLS is enabled if `api_cert`
and `api_key` are set in `ctrl-exec.conf`; plain HTTP is used otherwise.

The server uses a fork-per-request model: the parent accepts connections and
forks a child per request. The child handles the request and exits. The parent
reaps children with a SIGCHLD handler calling `waitpid(-1, WNOHANG)`.


## Endpoints

### `GET /`

Returns a JSON index of all endpoints. Use this to discover available
endpoints and spec URLs programmatically.

```json
{
  "name": "ctrl-exec-api",
  "version": "0.2.8",
  "spec": "/openapi.json",
  "live_spec": "/openapi-live.json",
  "endpoints": [
    { "method": "GET",  "path": "/health"           },
    { "method": "POST", "path": "/ping"              },
    { "method": "POST", "path": "/run"               },
    { "method": "GET",  "path": "/discovery"         },
    { "method": "POST", "path": "/discovery"         },
    { "method": "GET",  "path": "/status/{reqid}"    },
    { "method": "GET",  "path": "/openapi.json"      },
    { "method": "GET",  "path": "/openapi-live.json" }
  ]
}
```

---

### `GET /health`

Returns the API server version. Use for liveness checks.

```json
{ "ok": true, "version": "0.2.8" }
```

---

### `POST /ping`

Runs the auth hook, then pings all specified hosts in parallel via
`Engine::ping_all`. Returns per-host connectivity, cert expiry, and version.
Individual host failures are reported inline; they do not produce an HTTP
error response.

Request body:

```json
{ "hosts": ["web-01", "web-02"], "username": "alice", "token": "mytoken" }
```

`hosts`
: Required. Array of agent hostnames. Each entry may be `hostname` or
  `hostname:port`; port defaults to 7443.

`username`, `token`
: Optional. Passed to the auth hook. See Auth hook below.

Response:

```json
{
  "ok": true,
  "results": [
    { "host": "web-01", "status": "ok",    "rtt": "12ms", "expiry": "Jan 15 12:00:00 2026 GMT", "version": "0.2.8" },
    { "host": "web-02", "status": "error", "rtt": "60001ms", "error": "read timeout after 60s" }
  ]
}
```

---

### `POST /run`

Runs the auth hook, checks locks via `Lock::check_available`, then dispatches
a script to all specified hosts in parallel via `Engine::dispatch_all`.
Individual host failures are reported inline via the `exit` and `error` fields.

Request body:

```json
{
  "hosts":    ["db-01", "db-02"],
  "script":   "pg-backup",
  "args":     ["--database", "myapp"],
  "username": "alice",
  "token":    "mytoken"
}
```

`hosts`
: Required. Non-empty array of agent hostnames.

`script`
: Required. Allowlisted script name. Alphanumeric and hyphens only. Must
  match an entry in the agent's `scripts.conf`.

`args`
: Optional. Array of positional arguments passed to the script.

`username`, `token`
: Optional. Passed to auth hook and forwarded to the agent as request context.

`async`
: Optional boolean (default `false`). When `true`, each agent starts the
  script detached and the API returns **202** with a `reqid` immediately
  instead of blocking for results. Use for jobs that run longer than
  `read_timeout`. Fetch results later from `GET /status/{reqid}`. See
  *Asynchronous runs* below.

Response (success):

```json
{
  "ok": true,
  "reqid": "a1b2c3d4",
  "results": [
    { "host": "db-01", "exit": 0, "stdout": "Backup complete\n", "stderr": "", "rtt": "4210ms", "reqid": "a1b2c3d4" },
    { "host": "db-02", "exit": -1, "error": "read timeout after 60s", "rtt": "60001ms", "reqid": "a1b2c3d5" }
  ]
}
```

`reqid`
: Request ID at the top level of the response. Matches `REQID` in syslog on
  both dispatcher and agent. Use to poll `GET /status/{reqid}` or to
  correlate log entries across both sides.

`exit`
: Script exit code. 0 = success. Positive = script failure. -1 = dispatcher-side
  failure (connection error, timeout). 126 = killed by signal or exec failed.

Response (lock conflict):

```json
{ "ok": false, "error": "locked", "code": 4, "conflicts": ["db-01"] }
```

Response (async submission, `"async": true`): **202 Accepted**

```json
{
  "ok": true,
  "async": true,
  "reqid": "a1b2c3d4e5f60718",
  "results": [
    { "host": "db-01", "status": "accepted", "reqid": "a1b2c3d4e5f60718", "rtt": "12ms" },
    { "host": "db-02", "status": "busy", "error": "script already running", "rtt": "9ms" }
  ]
}
```

Each host reports `accepted` (job started detached), `busy` (the agent
refused because the same script is already running there), or `error` (the
submission failed). Poll `GET /status/{reqid}` for results.

---

### `GET /status/{reqid}`

Returns the stored record for a run. Records are persisted to
`/var/lib/ctrl-exec/runs/<reqid>.json` and purged 24 hours after the run
completes. The response shape depends on how the run was submitted.

**Synchronous run** (the default). The record carries the completed
per-host `results` array:

```json
{
  "ok": true,
  "reqid": "a1b2c3d4",
  "script": "pg-backup",
  "mode": "sync",
  "complete": true,
  "hosts": ["db-01", "db-02"],
  "completed": 1737123456,
  "results": [
    { "host": "db-01", "exit": 0, "stdout": "Backup complete\n", "stderr": "", "rtt": "4210ms", "reqid": "a1b2c3d4" }
  ]
}
```

**Asynchronous run** (`"async": true` on `/run`). On each `GET /status`
the API fetches results from every still-pending host, merges them, and
returns a per-host `hosts` map plus a `complete` flag and `pending` list:

```json
{
  "ok": true,
  "reqid": "a1b2c3d4e5f60718",
  "script": "pg-backup",
  "mode": "async",
  "complete": false,
  "pending": ["db-02"],
  "hosts": {
    "db-01": { "status": "done", "exit": 0, "stdout": "Backup complete\n", "stderr": "" },
    "db-02": { "status": "running" }
  }
}
```

Per-host `status` values: `accepted`/`running` (still in progress), `done`
(finished, with `exit`/`stdout`/`stderr`), `expired` (the agent purged its
result before it was fetched), `busy`/`error` (the job never ran on that
host). A transient fetch failure leaves the host pending and adds a
`fetch_error` field; the next poll retries it.

`complete`
: `true` once no host is still pending. `pending` lists the hosts still
  running. Poll until `complete` is `true`.

Response (not found): 404 with `{ ok: false, error: "not found", detail: "no result for reqid <id>" }`.

A 404 means either the reqid never existed or the whole record was purged
after 24 hours. (A single host whose agent-side result was purged shows as
`expired` within an otherwise-present record, not a 404.)

#### Asynchronous runs

Submit with `"async": true`, record the top-level `reqid`, then poll
`GET /status/{reqid}` until `complete` is `true`. The agent runs each job
detached, so it survives the connection close and an agent restart
(`KillMode=process`); results are held agent-side and fetched on demand.
The calling programme controls the polling cadence; there is no push or
callback. The CLI `ced wait <reqid>` implements this poll loop.

---

### `GET /discovery` or `POST /discovery`

Returns all registered agents and their allowlisted scripts. Auth uses the
ping privilege level.

The GET form queries all registered agents. The POST form accepts an optional
body to filter to a specific set of hosts.

Optional request body (POST only):

```json
{ "hosts": ["web-01", "db-01"], "username": "alice", "token": "mytoken" }
```

If `hosts` is omitted or the body is absent, all agents in the registry are
queried.

Response:

```json
{
  "ok": true,
  "hosts": {
    "web-01": {
      "host": "web-01", "status": "ok", "version": "0.2.8",
      "tags": { "env": "production", "role": "web" },
      "scripts": [
        { "name": "deploy", "path": "/opt/ctrl-exec-scripts/deploy.sh", "executable": true }
      ]
    }
  }
}
```

`tags` is an object of key/value strings defined in the `[tags]` section of
the agent's `agent.conf`. An agent with no tags configured returns `"tags": {}`.

Results are keyed by the agent's **registry name** (canonical) for direct
lookup, and each agent is queried at its registry-resolved address and port
(see `lookup_by` / `port`). When the agent reports a different hostname for
itself, that value appears as a `reported_hostname` field on the entry; it is
omitted when it matches the registry name.

Discovery also refreshes each registered agent's cached `tags` in the registry
from this live response, so `ced list-agents --tags` can filter offline.

---

## HTTP status codes

```
200   Success
202   Async run accepted (POST /run with "async": true)
400   Bad request (missing body, invalid JSON, missing required field)
403   Auth denied
404   Unknown route or unknown/expired reqid (status endpoint)
409   Lock conflict
500   Server error
```

Auth error codes in the `code` field:

```
1   denied
2   bad credentials
3   insufficient privilege
4   lock conflict (409 only)
```

---

## Auth hook

If `auth_hook` is set in `ctrl-exec.conf`, it is called before every
request including `/run`, `/ping`, `/discovery`, and all informational
endpoints. The hook receives the full request context as JSON on stdin,
including `action`, `script`, `hosts`, `username`, `token`, and
`source_ip`. Exit codes follow the same convention as the CLI: 0 = authorised,
1 = denied, 2 = bad credentials, 3 = insufficient privilege.

If no hook is configured, behaviour is governed by `api_auth_default` in
`ctrl-exec.conf`. The default is `deny` - all requests return 403 until a
hook is configured. Set `api_auth_default = allow` only on isolated networks
where no credential checking is required.

Always use `ENVEXEC_ARGS_JSON` in hook scripts to inspect script arguments.
`ENVEXEC_ARGS` (space-joined) is deprecated and unreliable for arguments
containing spaces or newlines.

---

## OpenAPI spec

The static OpenAPI 3.1 spec is installed at
`/usr/local/lib/ctrl-exec/ctrl-exec/openapi.json` and served verbatim from
`GET /openapi.json`. The version field is stamped with the release version at
install time.

The spec describes all request and response schemas in full. It is suitable
for import into any OpenAPI-compatible tooling.


## Live spec generator

`GET /openapi-live.json` generates and serves a dynamic OpenAPI spec augmented
with live discovery data. It is intended for use with UI tools such as RapiDoc,
which load a spec URL and render an interactive interface.

### What it does

On each request:

1. Loads and parses the base spec from `openapi.json` on disk.
2. Pulls all registered hostnames from the local registry (no network call).
3. Runs `capabilities_all` against those hosts in parallel. Hosts that do not
   respond are silently omitted from enumeration.
4. Injects an `enum` array into the `hosts` field across the `PingRequest`,
   `RunRequest`, and `DiscoveryRequest` schemas.
5. Injects an `enum` array into the `script` field in `RunRequest` - all
   script names seen across reachable agents, deduplicated and sorted.
6. Stamps `info.version` with an epoch suffix in the form `0.2.8+1737123456`.
   Any existing epoch suffix is stripped first so repeated requests do not
   accumulate suffixes.
7. Encodes and serves the result in memory. No file is written to disk.

### Regeneration

The live spec is regenerated on each request. There is no caching, no file
watcher, and no scheduled job. A browser refresh picks up changes in host or
script availability.

### Using with RapiDoc

Point RapiDoc's `spec-url` at `/openapi-live.json`. Because the version stamp
changes on each generation, RapiDoc treats each response as a fresh spec.
The RapiDoc page itself is static; all dynamism is in the spec endpoint.

```html
<rapi-doc spec-url="/openapi-live.json"></rapi-doc>
```

### Scope

The live spec generator is a testing and validation aid for the current phase.
It will be superseded when a middleware layer wraps scripts, adds auth and
workflow, and exposes its own API. The generator should not grow beyond its
current scope.


## `Exec::API` module

Implemented in `lib/ctrl-exec/API.pm`. Public interface:

`run(%opts)`
: Required: `config`. Starts the server and blocks until SIGTERM or SIGINT.
  All other behaviour is internal.

`SSL_no_shutdown => 1` is used on connection close in both parent and child,
for the same reason as in the pairing server - see the note in
`Exec::Pairing` in DEVELOPER.md.
