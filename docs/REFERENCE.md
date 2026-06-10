---
title: ctrl-exec - Installation and Operations
subtitle: Platform requirements, setup, configuration, and operational reference
brand: odcc
---


This document is the authoritative reference for all `ctrl-exec` and
`ctrl-exec-agent` commands. It covers every mode, option, and environment
variable for both binaries.

For installation and initial setup, see INSTALL.md. For a hands-on
introduction to what the system can do, run the ctrl-exec-demonstrator
script on a paired agent - see INSTALL.md for instructions on enabling it.

## ctrl-exec

The `ctrl-exec` binary runs on the control host. It manages the CA,
handles agent pairing, and dispatches commands to paired agents.

### Synopsis

```bash
ctrl-exec <mode> [options] [args]
```

### Global options

These options apply to all modes.

`--config <path>`
: Path to `ctrl-exec.conf`. Default: `/etc/ctrl-exec/ctrl-exec.conf`.

`--port <n>`
: Override the default agent port (7443) for all hosts in this invocation.
  Individual hosts can also override their port with `<host>:<port>` syntax.

`--json`
: Output results as JSON. Applies to `run`, `ping`, and `list-agents`.

`--username <n>`
: Username to include in the request context. Defaults to `$USER`. This is an
  advisory field - it is forwarded to auth hooks and to the agent unchanged,
  but is not authenticated or verified by ctrl-exec. Its intended use is to
  carry an identity assertion that the auth hook can forward to an external
  authentication service alongside the token, allowing that service to verify
  whether the claimed identity is consistent with the token's authority. Do
  not use `username` alone as an access control basis. See
  SECURITY-OPERATIONS.md for the recommended pattern.

`--token <token>`
: Auth token to include in the request context. Defaults to the
  `$ENVEXEC_TOKEN` environment variable if set. Consumed by auth hooks
  on the agent side.

### Environment variables

`ENVEXEC_TOKEN`
: Default auth token. Equivalent to `--token`. Useful for scripted or
  automated invocations where passing a token on the command line is
  undesirable.

`USER`
: Default username. Overridden by `--username`.

---

### run

Run an allowlisted script on one or more agents in parallel.

```bash
ctrl-exec run <host>[:<port>] [<host>...] <script> [-- <arg>...]
```

The script name must match an entry in the agent's `scripts.conf` allowlist.
Everything after `--` is passed to the script as positional arguments.
Arguments are evaluated on the ctrl-exec host before being sent - use
`--` to pass static strings, not shell expressions intended to run on
the agent.

The ctrl-exec sends a JSON context object to the script via stdin on the
agent. This includes the script name, username, token, arguments, timestamp,
peer IP, and request ID. See INSTALL.md for the full context structure.

```bash
# Single host
ctrl-exec run web-01 deploy-app

# Multiple hosts in parallel
ctrl-exec run web-01 web-02 web-03 deploy-app

# Pass arguments to the script
ctrl-exec run db-01 backup-mysql -- --database myapp

# Custom port for one host
ctrl-exec run web-01:7450 deploy-app

# Identify the operator explicitly
ctrl-exec run web-01 deploy-app --username alice

# Pass an auth token
ctrl-exec run web-01 deploy-app --token mytoken
ENVEXEC_TOKEN=mytoken ctrl-exec run web-01 deploy-app

# JSON output
ctrl-exec run web-01 deploy-app --json
```

Output shows per-host status, exit code, round-trip time, stdout, and stderr.
Exit code is 0 if all hosts succeeded, 1 if any host failed or returned
a non-zero exit.

#### Dispatch host resolution

When a host argument matches a registered agent name, the connect address is
resolved from the registry according to that agent's `lookup_by` field
(set at pairing — see `approve --lookup-by`):

- `hostname` (default): connect to the agent's registered hostname.
- `ip`: connect to the IP recorded at pairing. Use this when the
  agent-reported hostname does not resolve from the dispatcher.

A host argument that is not a registered agent, or one given with an explicit
`:port`, is used verbatim (DNS resolution as before) — so ad-hoc and
non-default-port targets still work. mTLS is unaffected: the agent
certificate is validated against the CA, not matched to the connect address.
`list-agents` always shows the registered hostname; with `lookup_by = ip`,
`run`/`ping` output and logs show the IP actually connected to.

---

### ping

Test mTLS connectivity to one or more agents and report cert expiry and
agent version.

```bash
ctrl-exec ping <host>[:<port>] [<host>...]
```

```bash
# Single host
ctrl-exec ping web-01

# Multiple hosts in parallel
ctrl-exec ping web-01 web-02 web-03

# JSON output
ctrl-exec ping web-01 --json
```

Output columns: host, status (ok/error), round-trip time, cert expiry,
agent version.

---

### pairing-mode

Start the pairing listener on port 7444. Agents call `request-pairing`
to submit a CSR; this mode receives the request, displays it for operator
approval, and signs and returns the certificate on approval.

```bash
ctrl-exec pairing-mode
```

The prompt shows the requesting agent's hostname, IP, request ID, and a
6-digit confirmation code. The agent displays the same code at submission
time. Verify both match before approving.
Enter `a` to approve, `d` to deny, or `s` to skip and leave the request
pending. Press Ctrl-C to stop pairing mode.

Pairing mode processes one request at a time interactively. For
unattended approval workflows, use `list-requests` and `approve`.

---

### list-requests

List pending pairing requests that have not yet been approved or denied.

```bash
ctrl-exec list-requests
```

Output columns: request ID, hostname, IP, confirmation code, received timestamp.
Verify the confirmation code matches the 6-digit code displayed on the agent
before approving.

---

### approve

Approve a pending pairing request by ID. Signs the agent's CSR and
delivers the certificate on the agent's next poll.

```bash
ctrl-exec approve <reqid>
ctrl-exec approve <reqid> --lookup-by ip
```

The request ID is shown by `list-requests` and `pairing-mode`.

`--lookup-by <ip|hostname>`
: How dispatch resolves this agent's connect address (stored in the registry
  as `lookup_by`). `hostname` (default) connects to the agent's registered
  hostname; `ip` connects to the IP recorded at pairing. Use `ip` when the
  agent-reported hostname does not resolve from the dispatcher. This overrides
  any value the agent suggested with `request-pairing --lookup-by`. See
  *Dispatch host resolution* under `run`.

---

### deny

Deny a pending pairing request by ID. Removes the request without
signing.

```bash
ctrl-exec deny <reqid>
```

---

### list-agents

List all registered (paired) agents.

```bash
ctrl-exec list-agents
ctrl-exec list-agents --json
```

Output columns: hostname, IP address, lookup mode, paired timestamp, cert
expiry.

With `--json`, returns an array of objects with fields:

`hostname`
: Agent hostname as registered at pairing time.

`ip`
: IP address of the agent at last contact.

`lookup_by`
: How dispatch resolves this agent: `hostname` (default) or `ip`. See
  *Dispatch host resolution* under `run`.

`paired_at`
: ISO 8601 timestamp of when the agent was paired.

`cert_expiry`
: ISO 8601 timestamp of the agent certificate's notAfter date.

`serial`
: Truncated hex serial of the agent's current certificate.

---

### setup-ca

One-time initialisation of the ctrl-exec CA. Generates the CA key and
self-signed certificate used to sign all agent certificates. Run once
on the ctrl-exec host before any pairing.

```bash
ctrl-exec setup-ca
```

Writes to `/etc/ctrl-exec/`. Does not overwrite an existing CA.

---

### setup-ctrl-exec

Generate the ctrl-exec's own key and certificate, signed by the CA.
Run after `setup-ca`. If an existing cert is found and registered agents
exist, the command displays the agent count and requires confirmation before
proceeding - replacing the cert changes its serial and agents will need
re-pairing if they miss the rotation broadcast.

```bash
ctrl-exec setup-ctrl-exec
```

Writes to `/etc/ctrl-exec/`.

---

### rotate-cert

Rotate the ctrl-exec certificate immediately. Generates a new cert, marks
all registered agents as pending, broadcasts the new serial to all agents
in parallel, and reports per-agent results.

```bash
ctrl-exec rotate-cert
```

Agents that were unreachable during the broadcast are retried automatically
by the internal check loop. Agents that remain unreachable after
`cert_overlap_days` are marked `stale` and require re-pairing.

The `update-ctrl-exec-serial` script must be in the agent's `scripts.conf`
allowlist for the broadcast to succeed. See `scripts.conf.example`.

---

### serial-status

Show the current ctrl-exec serial, previous serial, rotation timestamps,
overlap expiry, and per-agent serial state.

```bash
ctrl-exec serial-status
ctrl-exec serial-status --json
```

Output columns: hostname, status (current/pending/stale/unknown), last
confirmed timestamp, serial (truncated).

Status values:

- `current` - agent has confirmed the current serial
- `pending` - broadcast attempted but not yet confirmed (agent may be offline)
- `stale` - overlap window expired without confirmation; re-pair required
- `unknown` - agent has never received a serial update

---

## ctrl-exec.conf

Configuration file for the ctrl-exec and ctrl-exec-api processes.
Default path: `/etc/ctrl-exec/ctrl-exec.conf`.

Key settings:

`cert`, `key`, `ca`
: Paths to the ctrl-exec's TLS certificate, private key, and CA
  certificate. Required for all mTLS operations.

`read_timeout`
: How long (in seconds) the ctrl-exec waits for a response from an agent
  before reporting a timeout error. Default: 60. The script continues
  running on the agent after a timeout - only the ctrl-exec's ability to
  receive the output is affected. Raise this value for scripts that are
  expected to take longer than 60 seconds.

  ```
  read_timeout = 120
  ```

`timeout`
: Deprecated alias for `read_timeout`. Accepted for backward compatibility.

`api_port`
: Port for the `ctrl-exec-api` HTTP server. Default: 7445.

`api_cert`, `api_key`
: TLS certificate and key for the API server. If both are present and
  readable, the API server uses TLS. If absent, plain HTTP is used.

`api_bind`
: Network address the API server binds to. Default: `127.0.0.1` (localhost
  only). Set to `0.0.0.0` to accept connections on all interfaces, or to a
  specific interface address. Only change this if external clients need direct
  access; prefer a reverse proxy for internet-facing deployments.

  ```
  api_bind = 0.0.0.0
  ```

`api_auth_default`
: Controls API behaviour when no `auth_hook` is configured. Accepts `deny`
  (default) or `allow`. With `deny`, all requests are rejected until a hook
  is configured. With `allow`, all requests are authorised without a hook -
  suitable only for isolated networks. When a hook is configured this setting
  has no effect.

  ```
  api_auth_default = allow
  ```

### Cert rotation settings

`cert_days`
: Lifetime of the ctrl-exec certificate in days. Default: 365. Applied when
  generating a new cert via `setup-ctrl-exec` or automatic rotation.

`cert_renewal_days`
: Begin renewal this many days before the ctrl-exec cert expires. Default: 90.
  With `cert_days = 365`, renewal begins at day 275 of the cert's life.

`cert_overlap_days`
: After rotation, continue retrying agents that missed the serial broadcast for
  this many days before marking them `stale` (requiring re-pair). Default: 30.
  Configurable to accommodate fleets with agents that are offline for extended
  periods.

  ```
  cert_overlap_days = 60
  ```

`cert_check_interval`
: Seconds between internal cert expiry checks. Default: 14400 (4 hours). Reduce
  for testing. The check is lightweight: read the cert, compare notAfter to now.

`auth_hook`
: Path to an executable called before every `run` and `ping` operation.
  Receives request context as JSON on stdin. See INSTALL.md for the full
  interface contract.

---

## agent.conf

Configuration file for the `ctrl-exec-agent` process.
Default path: `/etc/ctrl-exec-agent/agent.conf`.

Key settings:

`port`
: Port the agent listens on for mTLS connections from the ctrl-exec. Default: 7443.

`cert`, `key`, `ca`
: Paths to the agent's TLS certificate, private key, and CA certificate.

`revoked_serials`
: Path to a file listing revoked TLS certificate serial numbers, one per line.
  Connections presenting a revoked cert are rejected immediately after the mTLS
  handshake, before any request is processed. Reloaded on SIGHUP without restart.

  Accepted serial formats (all normalised to lowercase hex on load):

  - Plain hex: `deadbeef`
  - Colon-separated: `DE:AD:BE:EF` (as returned by some tools and `IO::Socket::SSL`)
  - `0x`-prefixed: `0xdeadbeef`
  - `serial=`-prefixed: `serial=DEADBEEF` (as output by `openssl x509 -serial`)
  - Decimal integer: `3735928559`

  Lines beginning with `#` are treated as comments.

  Default: `/etc/ctrl-exec-agent/revoked-serials`. A missing or empty file
  means no certs are revoked.

  ```
  revoked_serials = /etc/ctrl-exec-agent/revoked-serials
  ```

`dispatcher_serial_path`
: Path to the stored ctrl-exec cert serial file. Written automatically by
  `request-pairing` - do not edit manually. The `/capabilities` endpoint
  rejects peers whose cert serial does not match the stored value. Re-pair
  the agent to update after a ctrl-exec cert rotation.

  Default: `/etc/ctrl-exec-agent/ctrl-exec-serial`. Reloaded on SIGHUP.

`dispatcher_cn`
: Removed. Previously used to restrict `/capabilities` by cert CN. Replaced
  by serial tracking via `dispatcher_serial_path`.

`script_dirs`
: Colon-separated list of absolute directory paths. If set, any script in
  `scripts.conf` whose path does not fall under one of these directories is
  rejected at load time and re-validated at execution time.

  ```
  script_dirs = /opt/ctrl-exec-scripts:/usr/local/lib/ctrl-exec-scripts
  ```

`auth_hook`
: Path to an executable called before every `run` request on the agent,
  after allowlist validation. Enables independent downstream token validation
  separate from the ctrl-exec's own hook.

  The hook receives request context as a JSON object on stdin and as individual
  environment variables. Exit codes:

  - `0` - authorised, request proceeds
  - `1` - denied (generic refusal)
  - `2` - bad credentials (token not recognised or expired)
  - `3` - insufficient privilege (credentials valid but not permitted for this script)

  If no hook is configured, the request is authorised unconditionally - the agent
  relies on mTLS for identity; the hook is for additional policy enforcement only.

  See the [Auth hook (agent-side)] section under `ctrl-exec-agent` for context
  fields, environment variables, and differences from the ctrl-exec-side hook.

`pairing_port`
: Port the agent listens on during pairing. Default: 7444. Must match the
  `--port` value passed to `ctrl-exec-agent request-pairing` and the port
  used by `ctrl-exec pairing-mode`.

  ```
  pairing_port = 7444
  ```

`pairing_max_queue`
: Maximum number of pairing requests held in the queue at one time. When
  the limit is reached, incoming requests are rejected immediately with
  `ACTION=pair-reject REASON=queue-full`. Default: 10. Raise this value
  only on deployments where many agents are paired concurrently; the queue
  is normally short-lived as each request is approved or denied within
  seconds.

  ```
  pairing_max_queue = 10
  ```

`allowed_ips`
: Comma-separated list of IP addresses or CIDR prefixes (/8, /16, /24)
  permitted to connect to the agent's mTLS port. Connections from addresses
  not on the list are dropped immediately after the TCP accept, before the
  TLS handshake. If unset, all source addresses are accepted.

  ```
  allowed_ips = 192.168.1.0/24, 10.0.0.1
  ```

  Invalid entries are logged as `ACTION=config-warn` at load time and
  silently skipped.

### Rate limiting settings

The agent applies two independent rate limits per source IP. Both are
tracked in memory and reset on agent restart or SIGHUP.

The volume threshold blocks IPs that open an unusually high number of
connections in a short window — consistent with port scanning or connection
flooding. The probe threshold blocks IPs that repeatedly fail TLS
handshakes — consistent with certificate probing or brute-force attempts.

`rate_limit_volume`
: Volume threshold in the format `limit/window/block`. Blocks a source IP
  for `block` seconds when it opens more than `limit` connections within
  `window` seconds. Default: `10/60/300` (10 connections in 60 seconds
  triggers a 5-minute block).

  ```
  rate_limit_volume = 10/60/300
  ```

`rate_limit_probe`
: Probe threshold in the format `limit/window/block`. Blocks a source IP
  for `block` seconds when it produces more than `limit` TLS handshake
  failures within `window` seconds. Default: `3/600/3600` (3 failures in
  10 minutes triggers a 1-hour block).

  ```
  rate_limit_probe = 3/600/3600
  ```

`rate_limit_disable`
: Set to `1` to disable all rate limiting. Intended for use during the
  integration test suite, which opens many connections rapidly from
  localhost. Do not set in production.

  ```
  rate_limit_disable = 1
  ```

### Agent tags

Arbitrary key/value metadata attached to the agent and returned in the
`/capabilities` response. Used by the API and any tooling that queries
agent capabilities to filter or label agents by environment, role, or
location without requiring separate inventory.

Defined in a `[tags]` section in `agent.conf`:

```ini
[tags]
env = production
role = database
location = ams1
```

Tags are returned as a JSON object in the `tags` field of the
`/capabilities` response:

```json
{
  "status": "ok",
  "host": "db1.example.com",
  "version": "1.0.0",
  "scripts": [...],
  "tags": { "env": "production", "role": "database", "location": "ams1" }
}
```

Tag keys and values are arbitrary strings. No reserved keys. An agent
with no `[tags]` section returns `"tags": {}`.

---

## ctrl-exec-agent

The `ctrl-exec-agent` binary runs on each managed host. It serves the
mTLS listener, handles pairing, and executes allowlisted scripts on
request from the ctrl-exec.

### Synopsis

```bash
ctrl-exec-agent <mode> [options]
```

### Global options

`--config <path>`
: Path to `agent.conf`. Default: `/etc/ctrl-exec-agent/agent.conf`.

`--allowlist <path>`
: Path to `scripts.conf`. Default: `/etc/ctrl-exec-agent/scripts.conf`.

`--port <n>`
: Override the pairing port (default 7444). Applies to `request-pairing`
  only; the serve port is set in `agent.conf`.

---

### serve

Start the agent server. Listens on the port configured in `agent.conf`
(default 7443) for incoming mTLS connections from the ctrl-exec.

```bash
ctrl-exec-agent serve
```

Under normal operation this is started and managed by the init system
(systemd or procd). Run directly for debugging or on systems without
a supported init system.

The agent reloads `scripts.conf` and the revocation list on SIGHUP without
restarting:

```bash
# On systemd hosts (preferred)
systemctl reload ctrl-exec-agent

# On systems without systemd
kill -HUP $(pidof ctrl-exec-agent)
```

---

### request-pairing

Submit a pairing request to a ctrl-exec host. Generates a key and CSR
for this agent, connects to the ctrl-exec's pairing port (7444), and
waits for the operator to approve the request.

```bash
ctrl-exec-agent request-pairing --dispatcher <host>
ctrl-exec-agent request-pairing --dispatcher <host> --background [--timeout <n>]
```

`--ctrl-exec <host>`
: Hostname or IP of the ctrl-exec host. Required.

`--port <n>`
: Override the pairing port on the ctrl-exec (default 7444).

`--lookup-by <ip|hostname>`
: Suggest how the dispatcher should resolve this agent for dispatch
  (default: `hostname`). Sent with the pairing request; the operator's
  `approve --lookup-by` overrides it. See *Dispatch host resolution* under
  `ctrl-exec run`.

`--background`
: Non-interactive mode for orchestrated installations. Prints the request
  ID to stdout and exits immediately, leaving a background process to wait
  for approval and store the certificate on receipt. See
  [Orchestrated pairing](#orchestrated-pairing) below.

`--timeout <n>`
: How long (in seconds) the background process waits for approval before
  giving up. Default: 30. Maximum: 600. If the timeout expires the
  background process exits with code 2 and logs `ACTION=pair-timeout`.
  Only valid with `--background`.

The command blocks until the ctrl-exec approves or denies the request,
or until the connection times out. On approval, the signed certificate
and CA certificate are written to the config directory and the agent is
ready to serve.

If the connection fails with a configuration error, check that the
ctrl-exec host is reachable, that `pairing-mode` is active on the
ctrl-exec, and that the correct address was specified.

---

### Orchestrated pairing

For automated provisioning workflows where interactive approval is not
possible, `--background` separates the pairing request submission from the
approval wait. The foreground process exits as soon as the ctrl-exec
acknowledges the request, printing the request ID to stdout. A background
process holds the connection open and writes the certificate when approval
arrives.

The orchestrator's responsibility is to capture the request ID and call
`ctrl-exec approve` on the ctrl-exec host before the timeout expires.

#### Flow

On the agent host (as part of a provisioning script):

```bash
# Start pairing-mode on the ctrl-exec first, then:
REQID=$(ctrl-exec-agent request-pairing --dispatcher ctrl-exec.example.com \
    --background --timeout 60)
echo "Request ID: $REQID"
```

The command exits 0 immediately, printing the request ID. The background
process is now waiting for approval.

On the ctrl-exec host (or via the orchestrator calling it remotely):

```bash
ctrl-exec approve "$REQID"
```

The background process receives the certificate, writes it to
`/etc/ctrl-exec-agent/`, logs `ACTION=pair-complete`, and exits 0.

Confirm pairing succeeded on the agent host:

```bash
ctrl-exec-agent pairing-status
# Exits 0 if paired, 1 if not yet paired
```

#### Exit codes (background process)

`0`
: Approval received and certificates stored successfully.

`2`
: Timeout expired before approval arrived. Key and CSR have been
  cleaned up. Re-run `request-pairing` to try again.

`3`
: Request was explicitly denied by the operator.

#### Timing

The background process holds the connection open for up to `--timeout`
seconds (default 30, maximum 600). The ctrl-exec's own polling window is
600 seconds — approval must arrive within whichever is shorter. For
orchestrated workflows where the approval step may take time, increase
`--timeout` accordingly:

```bash
REQID=$(ctrl-exec-agent request-pairing --dispatcher ctrl-exec.example.com \
    --background --timeout 120)
```

#### Notes

The background process inherits the connection socket from the foreground
process — no reconnection occurs. The maximum `--timeout` of 600 seconds
is enforced because the ctrl-exec closes the connection after its own
600-second polling window, making longer waits unreliable.

The request ID printed to stdout is the same ID shown by
`ctrl-exec list-requests` on the ctrl-exec host. Both the confirmation
code and the request ID are available via `list-requests` for verification
before approving.

---

### pairing-status

Report whether the agent is paired and show the certificate expiry date.

```bash
ctrl-exec-agent pairing-status
```

Exits 0 if paired, 1 if not paired. Suitable for use in scripts and
health checks.

---

### Auth hook (agent-side)

When `auth_hook` is configured in `agent.conf`, the hook is executed after
every `run` request passes allowlist validation, before the script is
spawned. It provides an independent authorisation layer separate from the
ctrl-exec's own hook.

#### Context fields

The hook receives a JSON object on stdin:

```json
{
  "action":     "run",
  "script":     "backup-db",
  "args":       ["--full"],
  "username":   "alice",
  "token":      "eyJ...",
  "source_ip":  "10.0.0.5",
  "timestamp":  "2025-01-15T12:00:00Z"
}
```

`action` is always `"run"` on the agent side. The agent does not call the
hook for `ping` requests - those are handled before the hook path is reached.

#### Environment variables

The same context is available as environment variables:

`ENVEXEC_ACTION`
: Always `run` on the agent.

`ENVEXEC_SCRIPT`
: The script name from the allowlist.

`ENVEXEC_ARGS`
: Space-joined argument string. Deprecated - lossy if arguments contain
  spaces. Prefer `ENVEXEC_ARGS_JSON`.

`ENVEXEC_ARGS_JSON`
: JSON array of arguments. Reliable for all argument values.

`ENVEXEC_USERNAME`
: Username passed by the ctrl-exec in the request body.

`ENVEXEC_TOKEN`
: Token passed by the ctrl-exec in the request body.

`ENVEXEC_SOURCE_IP`
: IP address of the ctrl-exec connection.

`ENVEXEC_TIMESTAMP`
: ISO 8601 UTC timestamp when the hook was invoked.

#### Exit codes

`0`
: Authorised. Script execution proceeds.

`1`
: Denied - generic refusal. Logged as `reason=denied`.

`2`
: Bad credentials - token not recognised or expired. Logged as
  `reason=bad credentials`.

`3`
: Insufficient privilege - credentials valid but not permitted for this
  script or action. Logged as `reason=insufficient privilege`.

Any other non-zero exit code is treated as denied with reason `hook exited N`.

#### Differences from the ctrl-exec-side hook

The ctrl-exec-side hook (configured in `ctrl-exec.conf`) runs on the
control host before dispatch and covers both `run` and `ping` actions
across all target hosts. The agent-side hook runs on each managed host
independently, covering only `run` requests for that agent.

A request passes both hooks before any script is executed. The hooks are
independent - there is no shared state between them.

The agent hook does not receive a `hosts` field; the agent is unaware of
which other hosts are targeted in the same ctrl-exec invocation.

If no hook is configured on the agent, the request is authorised
unconditionally at the agent level. The agent relies on mTLS and the
allowlist as its primary access controls; the hook is for supplementary
policy enforcement such as token validation or time-of-day restrictions.

---

### self-check

Validate the local configuration, allowlist, and certificates without
making any network connections. Reports each check individually.

```bash
ctrl-exec-agent self-check
```

Checks performed:

- `agent.conf` parses without error and required keys are present
- `scripts.conf` allowlist loads and all listed scripts are executable
- Pairing certificates are present and not expired
- If `script_dirs` is configured, all scripts in `scripts.conf` fall under
  one of the permitted directories
- If `revoked_serials` is configured, the file is readable and all entries
  are valid serial formats

Exit code is 0 if all checks pass. Use this after installation or
configuration changes to confirm the agent will start cleanly.

---

### self-ping

Perform a live mTLS loopback test against the running agent. Connects to
`127.0.0.1:7443` using the agent's own certificate, verifies the port is
listening, completes the mTLS handshake, and sends a `/ping` request.

```bash
ctrl-exec-agent self-ping
```

The agent will reject the connection with a 403 serial mismatch — the
agent's cert is not a ctrl-exec cert and does not match the stored
ctrl-exec serial. This is the expected and correct result. `self-ping`
treats a 403 response as a pass: it confirms that the port is listening,
the TLS stack is functioning, and the agent is correctly enforcing serial
policy.

Typical output:

```
Checking config...
  Config OK (port 7443)
  Paired: yes (cert expires Jun 18 11:09:58 2028 GMT)
Connecting to 127.0.0.1:7443...
  Port 7443: listening
  mTLS handshake: OK
  Ping response: 403 serial mismatch (expected - agent is running and enforcing policy)
Self-ping complete.
```

Contrast with `self-check`: that mode validates configuration, allowlist,
and cert files locally with no network connection. `self-ping` requires
the agent to be running and paired and exercises the live network path.

Use `self-ping` after installation to confirm the agent is reachable and
policy enforcement is active before the ctrl-exec attempts its first
connection.

---

## ctrl-exec-api

The `ctrl-exec-api` binary exposes the ctrl-exec's run, ping, and
discovery operations as an HTTP REST API. It is installed as a systemd
service (`ctrl-exec-api.service`) and listens on `api_port` (default 7445).

Start manually for testing:

```bash
ctrl-exec-api --config /etc/ctrl-exec/ctrl-exec.conf
```

TLS is enabled if `api_cert` and `api_key` are set in `ctrl-exec.conf`
and the files exist. Plain HTTP is used otherwise.

Full endpoint documentation is in API.md. Summary:

`GET /`
: Returns a JSON index of all endpoints and spec URLs. Auth applies as for all endpoints.

`GET /health`
: Returns `{ ok: true, version: "..." }`. Use for liveness checks.

`POST /ping`
: Body: `{ hosts, username?, token? }`. Pings all specified hosts in parallel.

`POST /run`
: Body: `{ hosts, script, args?, username?, token? }`. Runs an allowlisted
  script on all specified hosts. Returns results including a top-level
  `reqid` for status polling and syslog correlation.

`GET /discovery` or `POST /discovery`
: Returns registered agents and their allowlisted scripts. Optional body:
  `{ hosts?, username?, token? }`.

`GET /status/{reqid}`
: Returns the stored result for a completed run. Results are retained for
  24 hours. Returns 404 if the reqid is unknown or has expired.

`GET /openapi.json`
: Serves the static OpenAPI 3.1 spec as installed.

`GET /openapi-live.json`
: Generates and serves a dynamic spec augmented with live host and script
  enumerations from the registry and a capabilities scan.

HTTP status codes: 200 success, 400 bad request, 403 auth denied, 404 not
found, 409 lock conflict, 500 server error.

---

## Syslog

Both binaries log structured key=value records to syslog under the
`daemon` facility. The ctrl-exec and ctrl-exec-api log under the tag
`ctrl-exec`; the agent logs under `ctrl-exec-agent`. Scripts themselves
may log under any tag they choose.

All log entries use the `ACTION=<name>` field to identify the event type.
The full action catalogue — fields, priorities, example lines, and
alerting guidance — is in LOGGING.md.

Key quick-reference patterns for common operations:

```
ACTION=run EXIT=<n> SCRIPT=<name> TARGET=<host:port> RTT=<ms> REQID=<id>   (ctrl-exec)
ACTION=run EXIT=<n> SCRIPT=<name> PEER=<ip> REQID=<id>                      (agent)
ACTION=ping STATUS=ok|error PEER=<ip> REQID=<id> RTT=<ms>
ACTION=revoked-cert PEER=<ip> SERIAL=<hex>
ACTION=serial-reject PEER=<ip> REQID=<id>
ACTION=rate-block PEER=<ip> REASON=volume|probe
ACTION=ip-block PEER=<ip>
```

To correlate a ctrl-exec log entry with agent log entries, filter both
sides by `REQID`:

```bash
grep 'REQID=a1b2c3d4' /var/log/syslog
```

See LOGGING.md for the complete action reference, field glossary, and
alert pattern tables.

---

## Managing long-running processes

When a script is expected to run longer than `read_timeout`, the ctrl-exec
will report a timeout and return a non-zero exit, but the script continues
running on the agent. There is no mechanism to cancel it remotely.

To run a long-lived process and retrieve its output later:

- Have the script start the process in the background (e.g. with `nohup` or
  `systemd-run`) and return immediately with a job identifier or PID written
  to a known path.
- Use a second allowlisted script to poll status or retrieve output by
  reading that path.
- Raise `read_timeout` in `ctrl-exec.conf` if the script must complete
  within a single ctrl-exec invocation and the runtime is known and bounded.

The agent logs `ACTION=run` only when the script process exits. If the
ctrl-exec times out before the script completes, no `ACTION=run` entry
appears in the agent's syslog until the script eventually exits. An operator
cannot determine from syslog alone that a script is currently running —
only that it was started (from the ctrl-exec-side `ACTION=run` entry) and
has not yet completed.

---

## Getting started with examples

The ctrl-exec-demonstrator script exercises all core ctrl-exec
capabilities from a single agent-side script: stdout and stderr capture,
exit code propagation, argument passing, JSON context logging, and
agent-side information. It is installed on every agent host by the
installer and is disabled in `scripts.conf` by default.

To enable it, uncomment the entry in `/etc/ctrl-exec-agent/scripts.conf`
on the agent host and reload the allowlist:

```bash
# On systemd hosts (preferred)
systemctl reload ctrl-exec-agent

# On systems without systemd
kill -HUP $(pidof ctrl-exec-agent)
```

Then run the script directly on the agent host to see all available
subcommands and the exact ctrl-exec invocations that exercise them:

```bash
/opt/ctrl-exec-scripts/ctrl-exec-demonstrator.sh
```
