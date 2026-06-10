---
title: API Reference
subtitle: HTTP API reference for ctrl-exec-api.
updated: 2026-06-10
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/API.md
current_page: /api
---

`ctrl-exec-api` listens on port 7445 (configurable via `api_port`). All request and response bodies are JSON with `Content-Type: application/json`. TLS is enabled when `api_cert` and `api_key` are set in `ctrl-exec.conf`.

The auth hook applies to all endpoints. With no hook configured, behaviour is governed by `api_auth_default` (default: `deny`). See [Auth Hooks](/auth).

# Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | API index |
| `GET` | `/health` | Liveness check |
| `POST` | `/ping` | Ping agents |
| `POST` | `/run` | Run a script |
| `GET` or `POST` | `/discovery` | List agents and their scripts |
| `GET` | `/status/{reqid}` | Retrieve a stored run result |
| `GET` | `/openapi.json` | Static OpenAPI spec |
| `GET` | `/openapi-live.json` | Live OpenAPI spec |

# GET /

Returns a JSON index of all endpoints, the API version, and spec URLs.

```json
{
  "name": "ctrl-exec-api",
  "version": "0.2.8",
  "spec": "/openapi.json",
  "live_spec": "/openapi-live.json",
  "endpoints": [
    { "method": "GET",  "path": "/health" },
    { "method": "POST", "path": "/ping" },
    { "method": "POST", "path": "/run" },
    { "method": "GET",  "path": "/discovery" },
    { "method": "POST", "path": "/discovery" },
    { "method": "GET",  "path": "/status/{reqid}" },
    { "method": "GET",  "path": "/openapi.json" },
    { "method": "GET",  "path": "/openapi-live.json" }
  ]
}
```

# GET /health

Liveness check. No auth required. Returns version.

```json
{ "ok": true, "version": "0.2.8" }
```

# POST /ping

Pings all specified hosts in parallel. Returns per-host status, RTT, certificate expiry, and version. Individual host failures are reported inline — the top-level `ok` is true if the request was processed, regardless of per-host results.

Request:

```json
{
  "hosts":    ["web-01", "web-02"],
  "username": "alice",
  "token":    "mytoken"
}
```

`hosts` is required. `username` and `token` are optional and forwarded to the auth hook.

Response:

```json
{
  "ok": true,
  "results": [
    {
      "host":    "web-01",
      "status":  "ok",
      "rtt":     "12ms",
      "expiry":  "Jan 15 12:00:00 2026 GMT",
      "version": "0.2.8"
    },
    {
      "host":   "web-02",
      "status": "error",
      "rtt":    "60001ms",
      "error":  "read timeout after 60s"
    }
  ]
}
```

# POST /run

Dispatches a script to all specified hosts in parallel. Individual host failures are reported inline.

Request:

```json
{
  "hosts":    ["db-01", "db-02"],
  "script":   "pg-backup",
  "args":     ["--database", "myapp"],
  "username": "alice",
  "token":    "mytoken"
}
```

`hosts` and `script` are required. `args`, `username`, and `token` are optional.

Response (success):

```json
{
  "ok":    true,
  "reqid": "a1b2c3d4",
  "results": [
    {
      "host":   "db-01",
      "exit":   0,
      "stdout": "Backup complete\n",
      "stderr": "",
      "rtt":    "4210ms",
      "reqid":  "a1b2c3d4"
    },
    {
      "host":  "db-02",
      "exit":  -1,
      "error": "read timeout after 60s",
      "rtt":   "60001ms"
    }
  ]
}
```

Exit code values:

| Value | Meaning |
| --- | --- |
| `0` | Script succeeded |
| positive | Script exited with failure |
| `-1` | ctrl-exec-side failure (connection error, timeout) |
| `126` | Exec failed or script killed by signal |

Response (lock conflict):

```json
{
  "ok":        false,
  "error":     "locked",
  "code":      4,
  "conflicts": ["db-01"]
}
```

The top-level `reqid` is the correlation ID for this dispatch. It appears in both ctrl-exec and agent log entries. Results are stored for 24 hours and retrievable via `GET /status/{reqid}`.

# GET /status/{reqid}

Returns the stored result for a completed run. Results are retained for 24 hours. Supports async polling: submit a run, record the top-level `reqid`, poll at a suitable interval.

Response (found):

```json
{
  "ok":        true,
  "reqid":     "a1b2c3d4",
  "script":    "pg-backup",
  "hosts":     ["db-01"],
  "completed": 1737123456,
  "results":   [...]
}
```

Response (not found): HTTP 404 with `{ "ok": false, "error": "not found" }`.

# GET /discovery or POST /discovery

Returns all registered agents and their current allowlisted scripts and tags. `GET` queries all registered agents. `POST` accepts an optional `hosts` array to filter the response. Results are keyed by the canonical registry name (the agent's reported hostname appears as `reported_hostname` when it differs), and each agent is queried at its registry-resolved address and port. Discovery also refreshes the registry's cached tags from this response, which is what `ced list-agents --tags` filters on offline.

Optional POST body:

```json
{
  "hosts":    ["web-01"],
  "username": "alice",
  "token":    "mytoken"
}
```

Response:

```json
{
  "ok": true,
  "hosts": {
    "web-01": {
      "host":    "web-01",
      "status":  "ok",
      "version": "0.2.8",
      "tags":    { "env": "production", "role": "web" },
      "scripts": [
        {
          "name":       "deploy",
          "path":       "/opt/ctrl-exec-scripts/deploy.sh",
          "executable": true
        }
      ]
    }
  }
}
```

# GET /openapi.json

Static OpenAPI 3.1 specification for all endpoints.

# GET /openapi-live.json

Dynamic OpenAPI spec augmented with live discovery data. On each request, queries all registered agents for their current script lists and injects `enum` arrays into the `hosts` and `script` fields. The version field is stamped with an epoch suffix so tools like RapiDoc treat each response as a fresh spec.

Use this endpoint to generate accurate client code or to drive tooling that needs an up-to-date view of the available operations across the fleet.

# HTTP Status Codes

| Code | Meaning |
| --- | --- |
| `200` | Success |
| `400` | Bad request — missing field or invalid JSON |
| `403` | Auth denied |
| `404` | Unknown route or unknown/expired reqid |
| `409` | Lock conflict |
| `500` | Server error |

When `auth_deny_generic` is enabled in `ctrl-exec.conf`, a denied request returns a generic `403` (`{"error":"forbidden"}`) with no `code` or reason; the codes below are returned only when it is off (the default).

Auth error codes in the `code` field:

| Code | Meaning |
| --- | --- |
| `1` | Denied (generic) |
| `2` | Bad credentials |
| `3` | Insufficient privilege |
| `4` | Lock conflict |
