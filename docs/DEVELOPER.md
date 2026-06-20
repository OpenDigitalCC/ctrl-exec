---
title: dispatcher and agent - Developer document
subtitle: Purpose, contents, protocol, logging, security model and extending
brand: opendigitalcc
---

# ctrl-exec - Developer Documentation

## Purpose and Design Criteria

ctrl-exec is a Perl machine-to-machine remote script execution system. It
allows a dispatcher host (the dispatcher) to run scripts on remote hosts (agents)
over mTLS-authenticated HTTPS, with no SSH involved.

The design criteria were:

no SSH
: The system must not rely on SSH. Agents expose a purpose-built HTTPS server
  with an explicit allowlist of callable scripts.

locked-down execution
: Agents execute only scripts named in a per-host allowlist. Script names are
  validated against an alphanumeric pattern before allowlist lookup. Scripts are
  executed via `fork`/`exec` with no shell, preventing injection via arguments.

mTLS trust
: All operational traffic uses mutual TLS. Both dispatcher and agent present
  certificates signed by a private CA. The CA is created once on the dispatcher
  host; the CA key never leaves that host.

pairing workflow
: The initial certificate exchange uses a separate TLS port (7444) where the
  agent connects to the dispatcher to submit a CSR. The dispatcher holds the
  connection open while waiting for operator approval. On approval the CSR is
  signed and the cert is delivered back over the open connection. Approved
  agents are recorded in a persistent registry.

automatic cert renewal
: Agent certs are renewed automatically by the dispatcher over the mTLS
  operational port (7443). Renewal is triggered when remaining cert validity
  drops below half the configured lifetime. No operator involvement required
  during normal operation.

argument support
: Scripts can receive arguments. Arguments are passed as a JSON array and
  forwarded to `exec` as a list, never interpolated into a shell command.

structured logging
: All actions are logged to syslog in a consistent `ACTION=value KEY=value`
  format with a request ID that correlates dispatcher and agent log lines for
  the same operation.

auth hook
: An optional external executable is called before every `run` and `ping`
  request, from both the CLI and the API. It receives request context as
  environment variables and JSON on stdin. Exit codes map to authorisation
  outcomes. No hook configured means unconditional pass. The hook is the
  intended policy engine for per-token, per-script, and per-argument access
  control; ctrl-exec deliberately does not implement config-based ACLs.

token forwarding pipeline
: Tokens and usernames are forwarded from the dispatcher through to the agent
  and into the script's stdin context. This supports multi-hop token validation:
  the dispatcher hook, the agent hook, and the script itself can all
  independently verify that the token is still valid and authorised for the
  stated purpose. Each hop trusts the CA for identity but verifies authority
  independently via its own token validation.

HTTP REST API
: An optional API server (`ctrl-exec-api`) exposes the same run, ping, and
  discovery operations as HTTP endpoints with JSON request and response bodies.
  Auth hook and lock checking apply identically to CLI and API.

Debian trixie system packages only
: No CPAN. All dependencies are available as `apt` packages on Debian trixie.
  The installer checks for missing packages and exits with the install command
  rather than attempting to install them automatically.

function-based design
: Each module exposes discrete, testable functions. Business logic is in the
  library modules; the `bin/` scripts handle argument parsing and output only.



## Ports

7443
: Operational mTLS port. The agent listens here for `run`, `ping`,
  `capabilities`, `renew`, and `renew-complete` requests. Both sides present
  certificates signed by the private CA.

7444
: Pairing port. Only open when the dispatcher is in `pairing-mode`. TLS server
  cert only (no client cert required) since the agent has no cert yet. Agents
  connect here to submit a CSR and wait for the signed cert.

7445
: API port. The `ctrl-exec-api` HTTP server listens here. Plain HTTP by
  default; TLS enabled if `api_cert` and `api_key` are set in
  `ctrl-exec.conf`. No mTLS - auth is delegated to the auth hook.


## Certificate Layout

dispatcher host (`/etc/ctrl-exec/`)

```
ca.key          CA private key (0600, root only, never leaves this host)
ca.crt          CA certificate (distributed to agents during pairing)
ca.serial       Serial counter for issued certs
dispatcher.key  the dispatcher's own private key (0600, owned by the ctrl-exec service user)
dispatcher.crt  the dispatcher's own cert, signed by CA
auth-hook       Auth hook executable (0755)
```

Agent host (`/etc/ctrl-exec-agent/`)

```
agent.key             Agent's private key (0640, root:ctrl-exec-agent)
agent.crt             Agent's cert, signed by dispatcher CA (0640, root:ctrl-exec-agent)
ca.crt                CA cert from ctrl-exec (0644)
agent.conf            Port, cert paths, optional script_dirs and tags
scripts.conf          Allowlist: name = /absolute/path
```

The trusted-dispatcher map (`ctrl-exec-dispatchers`) replaces the old single
`ctrl-exec-serial` file (0.9.0). Each line maps a trusted dispatcher's cert
serial to its `dispatcher_id`. `/run`, `/ping`, `/result`, and
`/capabilities` are accepted only when the connecting cert's serial is a key
in the map; the matched `dispatcher_id` drives permission and attribution.
Pairing appends a line (one agent can serve several distinct dispatchers, each
chaining to the shared CA root). The map now lives in the agent-writable state
directory (`/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`) rather than the
root-owned config dir, because the agent (a non-root service user) must rewrite
it in place during cert rotation. The path is configurable via
`trusted_dispatchers_path` (formerly `dispatcher_serial_path`) and is reloaded
on SIGHUP.

Runtime directories

```
/var/lib/ctrl-exec/pairing/    Pairing queue ({reqid}.json, .approved, .denied)
/var/lib/ctrl-exec/agents/     Agent registry ({hostname}.json, written at pairing)
/var/lib/ctrl-exec/locks/      flock files for host:script concurrency control
```

Agent host (`/var/lib/ctrl-exec-agent/`)

```
ctrl-exec-dispatchers               Trusted-dispatcher map: <hex-serial> <dispatcher-id>, one per line (agent-writable)
runs/<dispatcher-id>/<reqid>.json   Async result store, partitioned by owning dispatcher
```

The async result store is partitioned by owner. `GET /result/<reqid>` returns
a run only to the dispatcher that submitted it (owner-gate); a request from
any other trusted dispatcher gets 404.


## Module Reference

### `Exec::Log`

Structured syslog. Call `init()` once at startup, then `log_action()` for each
event. If `init()` has not been called, `log_action()` falls back to stderr,
allowing library functions to log without requiring a syslog context.

```perl
Exec::Log::init('ctrl-exec-agent');

Exec::Log::log_action('INFO', {
    ACTION => 'run',
    SCRIPT => 'backup',
    EXIT   => 0,
    PEER   => '10.0.1.5',
    REQID  => 'a3f9b2c1',
});
```

Output format: `ACTION=run EXIT=0 PEER=10.0.1.5 REQID=a3f9b2c1 SCRIPT=backup`

`ACTION` is always first. All other keys follow in alphabetical order. Values
containing spaces are quoted. Levels: `INFO`, `WARNING`, `ERR`.

Field ordering is enforced automatically by `log_action` - the caller passes
fields in any order and the output is always sorted. The `ACTION` key is
required; callers need not place it first in the hashref.

Functions:

`init($program_name)`
: Opens syslog with `LOG_DAEMON` facility. Sets the ident used in all
  subsequent log lines.

`log_action($level, \%fields)`
: Writes one structured syslog line. `ACTION` key is required.

`close_log()`
: Closes the syslog handle. Not usually needed explicitly.


### `Exec::CA`

CA management and CSR signing via `openssl` subprocesses. All crypto is
delegated to the system `openssl` binary - no Perl crypto modules used.

Functions:

`generate_ca(%opts)`
: Generates `ca.key` and `ca.crt` in `ca_dir` (default `/etc/ctrl-exec`).
  Dies if CA already exists unless `force => 1`. Sets `ca.key` to mode 0600.
  Options: `days` (default 3650), `bits` (default 4096), `cn`, `ca_dir`, `force`.

`sign_csr(%opts)`
: Accepts a CSR as a PEM string, writes it to a temp file, calls
  `openssl x509 -req` to sign it, returns the signed cert PEM. The `days`
  parameter controls cert lifetime and should be passed from `config->{cert_days}`
  (default 365). Options: `csr_pem` (required), `ca_dir`, `days`, `out_path`.

`read_ca_cert(%opts)`
: Returns the CA cert PEM from `ca_dir/ca.crt`. Used during pairing and renewal
  to send the CA cert to the agent alongside the signed agent cert.

`generate_dispatcher_cert(%opts)`
: Generates `dispatcher.key` (4096-bit RSA, 0600), `dispatcher.csr`, signs it
  with the CA, writes `dispatcher.crt` (825 days), removes the CSR.
  Guards: dies if CA does not exist, dies if `dispatcher.crt` already exists
  unless `force => 1`. Called by `bin/ced setup-ctrl-exec`.
  Options: `ca_dir`, `force`, `days`, `bits`, `cert`, `key`, and `key_owner` (a
  user name; if set, the new key is chowned to it - the dispatcher passes
  `ctrl-exec` so the unprivileged API can read its `0600` key).


### `Exec::Pairing`

dispatcher-side pairing server and approval queue. Handles the initial
certificate exchange from the dispatcher's perspective.

The pairing flow uses the filesystem as a message queue between the main
dispatcher process (which the operator interacts with via `approve`/`deny`)
and the forked child processes (which hold connections open to waiting agents).

File states in `/var/lib/ctrl-exec/pairing/`:

```
{reqid}.json      Pending request (CSR, hostname, IP, nonce, timestamp)
{reqid}.approved  Written by approve_request(); read by waiting child
{reqid}.denied    Written by deny_request(); read by waiting child
```

The child polls every 2 seconds for up to 10 minutes. On finding an `.approved`
or `.denied` file it sends the response and exits.

`approve_request` also calls `Exec::Registry::register_agent()` to write
a persistent record of the approved agent before cleaning up the pairing files.

Nonce
: Each pairing request carries a random nonce generated by the agent. The
  dispatcher stores it in the `.json` queue file and echoes it in the
  `.approved` response. The agent verifies the nonce matches before storing
  the delivered certs. This prevents misrouted or replayed approval responses.

Stale request expiry
: `_expire_stale_requests()` is called at entry to `run_pairing_mode()` and
  `list_requests()`. It deletes `.json` files older than 10 minutes with no
  corresponding `.approved` or `.denied` file, cleaning up requests abandoned
  due to agent-side failures (e.g. running without sudo).

Interactive mode
: When STDIN is a tty, `run_pairing_mode()` uses `IO::Select` to multiplex the
  server socket and STDIN. Incoming requests are displayed immediately and the
  operator is prompted. Commands: `a`/`d`/`s` for single request; `a1`/`d2`
  etc. for numbered selection when multiple are pending; `list`/`l` to
  redisplay; `quit`/`q` to exit. When STDIN is not a tty (service, pipe),
  behaviour is unchanged from the original blocking accept loop.

Functions:

`run_pairing_mode(%opts)`
: Starts a TLS server on port 7444. Accepts connections, forks a child per
  connection. Each child calls `_handle_pair_request()`. Blocks until SIGINT
  or SIGTERM. Interactive when STDIN is a tty. Options: `port`, `cert`, `key`,
  `ca_dir`, `log_fn`.

`list_requests(%opts)`
: Expires stale requests, then returns an arrayref of pending request hashrefs
  from `pairing_dir`, sorted by `received` timestamp. Each hashref has: `id`,
  `hostname`, `ip`, `csr`, `nonce`, `received`.

`approve_request(%opts)`
: Reads the `.json` file, signs the CSR with `Exec::CA::sign_csr()`,
  writes the signed cert, CA cert, and echoed nonce to `{reqid}.approved`, then
  calls `Exec::Registry::register_agent()`. The waiting child picks this
  up within 2 seconds and delivers it to the agent.
  Options: `reqid` (required), `ca_dir`, `pairing_dir`, `log_fn`.

`deny_request(%opts)`
: Writes `{reqid}.denied`. The waiting child delivers a denial response to
  the agent. Options: `reqid` (required), `pairing_dir`, `log_fn`.

Important SSL note - `SSL_no_shutdown => 1` on parent close
: When the parent process calls `$conn->close` after forking, `IO::Socket::SSL`
  by default sends a TLS close-notify to the remote end, which closes the
  child's connection too. Passing `SSL_no_shutdown => 1` releases the parent's
  file descriptor without sending close-notify, leaving the child's copy intact.
  This pattern is required anywhere a forked server hands off an SSL connection
  to a child.


### `Exec::Rotation`

dispatcher cert lifecycle management. Monitors the dispatcher's own cert
expiry, rotates it when approaching expiry, and broadcasts the new serial to
all registered agents.

Seamless rotation (add-then-remove)
: Dispatcher cert rotation updates each agent's trusted-dispatcher map
  (`/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`) automatically over the run
  channel — no re-pairing. The broadcast (`broadcast_serial` →
  built-in `/rotate-serial`) carries the **new** serial, and each agent **adds**
  it to the map under the dispatcher identity it derives from the caller's
  authenticated cert serial; the old
  serial is kept trusted through the overlap window so in-flight traffic on the
  previous cert continues to be accepted. After the overlap window the
  dispatcher broadcasts removal of the **old** serial via
  `retire_previous_serial`, so each agent ends up trusting only the current
  serial. The dispatcher-side registry status machinery below
  (current/pending/stale/confirmed) is unchanged; an agent that is offline for
  the whole broadcast and misses the update still needs re-pairing.

The module is used in two ways: `check_and_rotate` is called at startup and
by the background loop in `run_check_loop`; `rotate` is called directly by
`ced rotate-cert` for operator-initiated rotation.

Call sequence for automatic rotation:

```
run_check_loop
  └─ expire_stale_agents   (mark pending agents stale after overlap window)
  └─ check_and_rotate      (check expiry; calls _do_rotation if renewal due)
       └─ _do_rotation     (regenerate cert, write rotation.json, mark agents pending)
  └─ broadcast_serial      (POST /rotate-serial to all pending agents via Engine::rotate_all)
```

Call sequence for manual rotation (`ced rotate-cert`):

```
rotate
  └─ _do_rotation
broadcast_serial            (called separately by the CLI mode)
```

Rotation state (`/var/lib/ctrl-exec/rotation.json`):

```json
{
  "current_serial":  "0a1b2c3d",
  "previous_serial": "09abcdef",
  "rotated_at":      "2026-03-09T14:30:00Z",
  "overlap_expires": "2026-04-08T14:30:00Z"
}
```

The `overlap_expires` timestamp is `rotated_at + cert_overlap_days`. During
the overlap window, agents that have not yet confirmed the new serial are
`pending`. After the window expires, `expire_stale_agents` marks them `stale`.
The overlap protects `broadcast_serial` retry attempts only - it is not a
grace period for operational traffic.

Agent serial status values in the registry:

```
unknown    Paired before serial tracking was introduced
pending    Serial broadcast attempted but not yet confirmed
confirmed  Agent has acknowledged the current dispatcher serial
stale      Overlap window expired without confirmation
```

Functions:

`check_and_rotate(%opts)`
: Reads the dispatcher cert expiry. If remaining days is below
  `cert_renewal_days` (default 90), calls `_do_rotation`. Returns
  `{ rotated => 0 }`, `{ rotated => 1, serial => $hex, ... }`, or
  `{ rotated => 0, error => $str }` for non-fatal failures.
  Required: `config`.

`rotate(%opts)`
: Unconditional rotation. Thin wrapper around `_do_rotation`. Used by
  `ced rotate-cert`. Required: `config`.

`load_state(%opts)`
: Reads and parses `rotation.json`. Returns the state hashref or `undef` if
  the file does not exist or is corrupt. Logs `ERR` on corrupt file.
  Optional: `path` (default `/var/lib/ctrl-exec/rotation.json`).

`expire_stale_agents(%opts)`
: Reads rotation state. If `overlap_expires` is in the past, marks all
  `pending` agents as `stale` in the registry. No-op if no rotation state
  exists or overlap has not expired. Required: `config`.

`broadcast_serial(%opts)`
: Reads rotation state to find `current_serial`. Queries the registry for
  agents with status `pending` or `unknown`. POSTs to each agent's built-in
  `/rotate-serial` operation in parallel via `Exec::Engine::rotate_all`
  (`_rotate_one`) with `action => 'add'` and the new serial, so each agent
  **adds** the new serial to its trusted-dispatcher map under the dispatcher
  identity it derives from the caller's authenticated cert serial (the old
  serial stays trusted through the overlap window). On
  success for each agent, calls `Exec::Registry::update_agent_serial_status` to
  set status `confirmed`. Returns arrayref of
  `{ hostname, status => 'ok'|'failed', error? }`. Required: `config`.

`retire_previous_serial(%opts)`
: Run after the overlap window closes. Reads rotation state to find
  `previous_serial`, then POSTs to the built-in `/rotate-serial` operation
  (`Exec::Engine::rotate_all` with `action => 'remove'`) on the
  `confirmed` agents instructing each to **remove** that serial from its
  trusted-dispatcher map, leaving only the current serial trusted. Logs
  `serial-retire` per batch. Returns arrayref of
  `{ hostname, status => 'ok'|'failed', error? }`. Required: `config`.

`run_check_loop(%opts)`
: Infinite loop. Sleeps `cert_check_interval` seconds (default 4 hours),
  then calls `expire_stale_agents`, `check_and_rotate`, and if rotated calls
  `broadcast_serial`. On non-rotation checks, retries `broadcast_serial` for
  any still-pending agents. All steps are wrapped in `eval` - failures are
  logged at WARNING and the loop continues. Required: `config`.

Private functions:

`_do_rotation(%opts)`
: Core rotation logic. Reads the old cert serial, calls
  `Exec::CA::generate_dispatcher_cert(force => 1)` to replace the cert,
  reads the new serial, writes `rotation.json` with `overlap_expires` set to
  now + `cert_overlap_days`, then marks all registered agents as `pending` via
  `Exec::Registry::update_agent_serial_status`. Returns the result
  hashref passed back through `rotate` and `check_and_rotate`.

`_read_cert_serial($path)`
: Calls `openssl x509 -noout -serial` on the cert file. Returns lowercase hex.

`_cert_days_remaining($path)`
: Calls `openssl x509 -noout -enddate` and computes remaining days.
  Returns a number (may be negative for expired certs).


### `Exec::Registry`

Persistent store of all paired agents. Written by `Exec::Pairing::approve_request`
at pairing time and updated by `Exec::Engine::_renew_one` after cert
renewal. Read by `bin/ced list-agents` and by `Exec::API` for
the `/discovery` endpoint.

One JSON file per agent in `/var/lib/ctrl-exec/agents/{hostname}.json`.
Re-pairing the same hostname overwrites its registry entry. Files are written
atomically via temp file and rename.

Record format:

```json
{
  "hostname": "agent-host-01",
  "ip":       "192.0.2.10",
  "paired":   "2026-03-05T14:30:00Z",
  "expiry":   "Jun  7 16:28:00 2027 GMT",
  "reqid":    "1a15334d0001"
}
```

The `expiry` field is updated after each successful cert renewal. An agent
whose cert has expired and has not been renewed has been out of contact for
more than the full cert lifetime - this is intentional self-expiry for
decommissioned hosts.

Functions:

`register_agent(%opts)`
: Writes or overwrites the registry entry for `hostname`. Required: `hostname`,
  `ip`, `paired`, `expiry`, `reqid`. Optional: `registry_dir`.

`get_agent(%opts)`
: Returns the hashref for a single agent, or `undef` if not found.
  Required: `hostname`. Optional: `registry_dir`.

`list_agents(%opts)`
: Returns an arrayref of all agent hashrefs, sorted by hostname.

`list_hostnames(%opts)`
: Returns an arrayref of hostname strings only. Convenience wrapper for
  passing directly to Engine functions.

`remove_agent(%opts)`
: Deletes the registry entry for `hostname`. Returns the deleted record so the
  caller can log the cert expiry date in the warning message. Dies if the
  hostname is not in the registry. Required: `hostname`. Optional: `registry_dir`.
  Note: the agent's cert remains valid until its natural expiry date. No cert
  revocation mechanism exists - the agent should be decommissioned promptly
  after unpairing.


### `Exec::Engine`

Parallel dispatch, ping, capabilities query, and automatic cert renewal. Uses
fork-per-host with pipes to collect results. No threads.

Pattern: for each host, fork a child that performs the operation and writes a
JSON result to a pipe, then exits. The parent loops `waitpid -1, 0` collecting
children and reading their pipes as they finish.

Cert renewal is triggered automatically after every successful ping. If the
agent's cert expiry (returned in the ping response) is within half the
configured `cert_days`, the dispatcher initiates renewal over the same mTLS
connection. Renewal failure is logged at ERR level but does not affect the
ping result.

SSL configuration note
: Outbound connections use `IO::Socket::SSL::set_defaults` rather than
  `ssl_opts` on `LWP::UserAgent->new`. This is required because `LWP`'s
  `ssl_opts` mechanism does not reliably pass `SSL_cert_file` and
  `SSL_key_file` through to `IO::Socket::SSL` for client cert presentation
  in mTLS. `set_defaults` is the authoritative SSL configuration path for all
  outbound connections, including TLS version floor and cipher list. Any future
  SSL option changes for outbound connections must be made there, not in
  `ssl_opts`.

Functions:

`dispatch_all(%opts)`
: Required: `hosts` (arrayref), `script`, `config`. Optional: `args`, `reqid`,
  `port`, `username`, `token`. `username` and `token` are forwarded to the
  agent in the run request body and from there into the script's stdin context,
  enabling downstream token validation.
  Returns arrayref of `{ host, script, exit, stdout, stderr, reqid, rtt }`.

`ping_all(%opts)`
: Required: `hosts`, `config`. Optional: `reqid`, `port`. After collecting
  ping results, checks each successful response for renewal need and calls
  `_renew_one` if due.
  Returns arrayref of `{ host, status, version, expiry, rtt, reqid }`.

`capabilities_all(%opts)`
: Required: `hosts`, `config`. Optional: `port`.
  Queries each host's `/capabilities` endpoint. Returns arrayref of
  `{ host, status, version, tags, scripts => [{name, path, executable}, ...], rtt }`.

`parse_host($host_str, $default_port)`
: Parses `"hostname"` or `"hostname:port"`. Returns `($host, $port)`.

`gen_reqid()`
: Returns a 16-hex-character cryptographically random request ID. Generated
  by reading 8 bytes from `/dev/urandom` and unpacking as hex. IDs are
  opaque strings; no code assumes a fixed structure or derives meaning from
  their content.

Private functions (not part of public API but documented for extension):

`_renewal_due($expiry_str, $cert_days)`
: Returns true if the OpenSSL notAfter date string represents a cert whose
  remaining validity is less than half of `cert_days`. Returns false (safe
  default) if the date string cannot be parsed. Uses `Time::Piece` for parsing
  (core since Perl 5.10).

`_renew_one(%opts)`
: Performs the full renewal exchange for one agent: POST `/renew` to get CSR,
  sign via `Exec::CA::sign_csr`, POST `/renew-complete` to deliver cert,
  update registry. Dies on any failure so the caller can log at ERR.
  Required: `host`, `port`, `config`, `reqid`.

`_extract_expiry($cert_pem)`
: Extracts the notAfter date string from a PEM cert via `openssl x509 -noout
  -enddate`. Returns the date string or undef on failure.


### `Exec::Auth`

Auth hook runner. Called before every `run` and `ping` operation from both
the CLI and the API. Also called by the agent's `handle_run` when
`config->{auth_hook}` is set - the same module serves both dispatcher-side
and agent-side hook execution. If no hook is configured (dispatcher or agent),
all requests pass unconditionally.

The hook is an external executable called with request context as environment
variables and a JSON object on stdin. Its exit code determines the outcome.

The hook is the intended policy engine. ctrl-exec deliberately does not
implement config-based ACLs. Per-token script restrictions, per-host targeting
rules, argument validation, and user-based privilege separation are all
implemented in the hook.

Exit codes:

```
0   authorised
1   denied - generic
2   denied - bad credentials
3   denied - insufficient privilege
```

Environment variables passed to hook:

```
ENVEXEC_ACTION      run | ping
ENVEXEC_SCRIPT      script name (empty for ping)
ENVEXEC_HOSTS       comma-separated host list
ENVEXEC_ARGS        space-joined args (lossy if args contain spaces - see below)
ENVEXEC_ARGS_JSON   args as a JSON array string (reliable for all arg values)
ENVEXEC_USERNAME    username from request (may be empty)
ENVEXEC_TOKEN       token from request (may be empty)
ENVEXEC_SOURCE_IP   originating IP address
ENVEXEC_TIMESTAMP   ISO8601 UTC timestamp
```

On the agent side, the auth hook additionally receives the resolved
dispatcher identity:

```
ENVEXEC_DISPATCHER         dispatcher_id of the connecting dispatcher
ENVEXEC_DISPATCHER_SERIAL  the connecting cert serial (hex)
```

`ENVEXEC_ARGS` vs `ENVEXEC_ARGS_JSON`
: `ENVEXEC_ARGS` is kept for backwards compatibility but is ambiguous when
  arguments contain spaces - a hook reading it will silently miscalculate the
  argument count. `ENVEXEC_ARGS_JSON` contains the args as a proper JSON
  array and should be used for all argument inspection. Example hook pattern
  using JSON stdin (more complete than env vars alone):

```bash
#!/bin/bash
# Restrict the backup token to backup-* scripts only
if [[ "$ENVEXEC_TOKEN" == "backup-token" ]]; then
    if [[ "$ENVEXEC_SCRIPT" != backup-* ]]; then
        exit 3   # insufficient privilege
    fi
fi

# Read full args from JSON stdin for reliable argument inspection
ARGS=$(cat | python3 -c "import sys,json; print(json.load(sys.stdin)['args'])")

# Block dangerous argument patterns regardless of token
if echo "$ARGS" | grep -q '\-\-drop'; then
    exit 3
fi

exit 0
```

stdin: full request context as a JSON object. Fields: `action`, `script`,
`hosts` (array), `args` (array), `username`, `token`, `source_ip`, `timestamp`.

The hook must not produce output. Use syslog for audit logging in the hook.
stdout and stderr are redirected to `/dev/null` before exec.

SIGCHLD note
: `_run_hook` sets `local $SIG{CHLD} = 'DEFAULT'` before forking the hook
  process. This is required when running inside a forked server child (such as
  an API request handler) that has inherited a SIGCHLD reaper from the parent.
  Without it, the parent's reaper can collect the hook grandchild before
  `waitpid` in `_run_hook` can, causing `waitpid` to return -1 and `$?` to be
  -1, which decodes as exit code 255 via `($? >> 8) & 0xff`.

Functions:

`check(%opts)`
: Required: `action`, `config`. Optional: `script`, `hosts`, `args`, `username`,
  `token`, `source_ip`. Returns `{ ok => 1 }` or `{ ok => 0, reason => $str, code => $n }`.


### `Exec::Lock`

flock-based concurrency control. Prevents two concurrent requests from running
the same script on the same host simultaneously. Lock files live in
`/var/lib/ctrl-exec/locks/`.

The pattern is check-then-acquire in two separate calls:

- `check_available` is called in the parent process (or API handler) before
  forking. It tests all locks non-blocking and returns the conflict list immediately.
- `acquire` is called in the child process that will actually execute the script.
  It re-tests and acquires atomically within the child.

There is a small TOCTOU window between `check_available` and `acquire`. If
another request acquires the lock in that window, `acquire` detects it and
returns a conflict. The caller treats this as a lock error.

Locks are held for the duration of script execution. Releasing the filehandle
(by going out of scope or calling `release`) releases the flock automatically.

Test note
: Lock tests use an exec'd subprocess (`t/lock-holder.pl`) rather than a
  forked child. flock locks are per open-file-description; a forked child
  shares the parent's file table, so the parent's `check_available` sees its
  own child's lock as "already held by this process" and reports no conflict.
  An exec'd process has an independent file table and behaves as a true peer.

Functions:

`check_available(%opts)`
: Required: `hosts`, `script`. Optional: `lock_dir`.
  Returns `{ ok => 1 }` or `{ ok => 0, conflicts => \@pairs }`.

`acquire(%opts)`
: Required: `hosts`, `script`. Optional: `lock_dir`.
  Returns `{ ok => 1, handles => \@fh_list }` or `{ ok => 0, conflicts => \@pairs }`.
  On partial conflict, releases any locks already acquired before returning.

`release(%opts)`
: Required: `handles`. Optional: `hosts`, `script` (for logging).
  Closes all filehandles, releasing all flocks.


### `Exec::API`

HTTP API server. Listens on `api_port` (default 7445). TLS is enabled if
`api_cert` and `api_key` are present in config; plain HTTP otherwise.

Fork-per-request model: the parent accepts connections and forks a child per
request. The child handles the request and exits. The parent reaps children
with a SIGCHLD handler calling `waitpid(-1, WNOHANG)`.

`SSL_no_shutdown => 1` is used on both parent and child connection close, for
the same reason as in the pairing server - see the note in `Exec::Pairing`.

Endpoints:

`GET /health`
: No auth. Returns `{ ok: true, version: "0.12.1" }`. Use for liveness checks.

`POST /ping`
: Body: `{ hosts, username?, token? }`. Runs auth hook, then pings all hosts
  in parallel via `Engine::ping_all`. Returns `{ ok: true, results: [...] }`.

`POST /run`
: Body: `{ hosts, script, args?, username?, token? }`. Runs auth hook, checks
  locks via `Lock::check_available`, dispatches via `Engine::dispatch_all`.
  Returns `{ ok: true, results: [...] }` or on lock conflict:
  `{ ok: false, error: "locked", code: 4, conflicts: [...] }`.

`GET /discovery` or `POST /discovery`
: Optional body: `{ hosts?, username?, token? }`. If hosts omitted, uses
  `Registry::list_hostnames()` to query all registered agents. Auth uses ping
  privilege level. Returns `{ ok: true, hosts: { hostname: { scripts, tags, version, rtt, ... } } }`.

HTTP status codes:

```
200   Success
400   Bad request (missing body, invalid JSON, missing required fields)
403   Auth denied
404   Unknown route
409   Lock conflict
500   Server error
```

Functions:

`run(%opts)`
: Required: `config`. Starts the server and blocks until SIGTERM or SIGINT.


### `Exec::CertInfo`

Shared cert inspection and the single home for serial canonicalisation - the
trust key behind every dispatcher-trusted/serial-revoked decision. Exports
`serial_to_hex` (NOT in `@EXPORT_OK` - intentionally called by fully-qualified
name), `serial_from_path`, `expiry_from_path`, `expiry_from_pem`, `expiry_epoch`.


### `Exec::Digest`

SHA-256 helpers. `pairing_code` derives the short human-comparable pairing
confirmation code; `sha256_hex` returns the hex digest of a string.


### `Exec::Cmd`

`run_or_die(@cmd)` runs an external command (list form, no shell) and dies with
its captured stderr on a non-zero exit, redirecting fd 2 at the OS level so the
child's real error reaches the die text.


### `Exec::Random`

`hex_bytes($n)` returns `$n` cryptographically-unpredictable bytes as lowercase
hex. The one `/dev/urandom` reader; fails closed (croaks) on a short read, with
no `rand()` fallback. Used for nonces and reqids.


### `Exec::DispatcherConfig`

`load_config($path)` loads the dispatcher's flat `key = value` config (shared by
`ctrl-exec-dispatcher` and `ctrl-exec-api`). Dies unless `cert`, `key`, and `ca`
are present.


### `Exec::Pairing::Identity`

Source-IP identity diagnostics for pairing: forward-confirmed reverse DNS
(`reverse_lookup`) and the operator-facing `identity_lines` /
`identity_recommendation` derived from it. A self-contained leaf split out of
`Exec::Pairing`.


### `Exec::Http`

One place for the HTTP/1.0 JSON response framing shared by the three small
servers. `send_raw($conn, $code, $body)` writes an already-serialised body;
`send_json($conn, $code, $data)` encodes `$data` first.


### `Exec::FileUtil`

File IO helpers. `slurp`/`slurp_maybe` read a file (the latter tolerating
absence); `write_atomic` is the atomic writer (temp file + rename).


### `Exec::TLS`

`hardening()` returns the shared `IO::Socket::SSL` hardening options (TLS 1.2/1.3
only, AEAD ciphers) spliced into every ctrl-exec listener and client so the
policy cannot drift between endpoints.


### `Exec::RateLimit`

Connection and failure rate limiting. `parse_limit_spec` parses a limit string;
`check`, `record_connection`, and `record_failure` track and enforce per-source
limits.


### `Exec::RunStore`

The dispatcher's run store. Records sync (`record_sync`) and async
(`record_async`) runs keyed by reqid under `/var/lib/ctrl-exec/runs`, and
`load`/`aggregate`/`purge` for status retrieval and TTL expiry.


### `Exec::Agent::Config`

Config and allowlist loading for the agent. Both functions die on unrecoverable
errors (missing file, required key absent) and warn on recoverable issues
(malformed allowlist line, non-absolute path, path outside approved dirs).

Functions:

`load_config($path)`
: Parses `agent.conf`. Returns hashref. Required keys: `port`, `cert`, `key`,
  `ca`. Parses `script_dirs` from a colon-separated string into an arrayref.
  If absent or empty, the `script_dirs` key is not present in the returned
  hashref (no restriction). Validates `auth_hook` if present: the path must
  exist and be executable, otherwise dies. If absent or empty, the `auth_hook`
  key is not present in the returned hashref. Parses `[tags]` section into
  `$config->{tags}` hashref; other sections are silently ignored.

`load_allowlist($path, $script_dirs)`
: Parses `scripts.conf`. Returns hashref of `{ name => /absolute/path }`.
  If `$script_dirs` is provided (arrayref), rejects any path not under an
  approved directory with a warning. If undef, any absolute path is accepted.

`validate_script($name, $allowlist, $script_dirs)`
: Returns the script path if `$name` matches `/^[\w-]+$/` and exists in the
  allowlist, `undef` otherwise. Security gate called on every `run` request.
  If `$script_dirs` is provided, re-validates the path at execution time (not
  only at load time), guarding against allowlist modification between load and
  execution.

Config format (`agent.conf`):

```ini
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

# Optional: restrict scripts to approved directories
# script_dirs = /opt/ctrl-exec-scripts:/usr/local/lib/ctrl-exec-scripts

# Optional: agent-side auth hook for independent token validation
# auth_hook = /etc/ctrl-exec-agent/auth-hook

[tags]
env  = prod
role = db
site = london
```

Allowlist format (`scripts.conf`):

```ini
# name = /absolute/path/to/script
check-disk    = /opt/ctrl-exec-scripts/check-disk.sh
backup-mysql  = /opt/ctrl-exec-scripts/backup-mysql.sh
```


### `Exec::Agent::Runner`

Script execution. Forks a child, redirects stdin, stdout, and stderr to pipes,
calls `exec { $path } $path, @args` (no shell). The parent writes the request
context as JSON to the script's stdin pipe, then reads both output pipes to
completion and waits for the child.

Using `exec { $path } $path, @args` (the two-argument form with a block) means
the PATH is not searched, no shell is invoked, arguments are passed directly to
`execve()`, and shell metacharacters in arguments have no effect.

JSON stdin
: The full request context is serialised as a JSON object and piped to the
  script's stdin before closing the write end. The script may read and parse
  it or ignore it entirely. A script that does not want stdin should add
  `exec 0</dev/null` at the top of its body - this redirects stdin before the
  script's own read calls and discards the JSON cleanly without blocking.

Functions:

`run_script($script_path, $args_arrayref, $context)`
: Executes the script, returns `{ stdout => '', stderr => '', exit => N }`.
  `$context` is an optional hashref; if provided it is serialised as JSON and
  written to the script's stdin. If `undef`, stdin is closed immediately
  (empty). Exit code 126 if the process was killed by a signal or exec failed.
  Exit code -1 with an error in `stderr` if `fork` or `pipe` failed.

Context hashref fields:

```
script      Script name as requested
args        Arrayref of positional arguments
reqid       Request ID
peer_ip     dispatcher's IP address
username    Username from the dispatcher request (may be empty)
token       Auth token from the dispatcher request (may be empty)
timestamp   ISO 8601 UTC timestamp of the request
```


### `Exec::Agent::AgentPairing`

Agent-side pairing and cert renewal support. Generates key and CSR, connects
to the dispatcher pairing port, submits the CSR and waits (up to 11 minutes)
for the signed cert. Also handles cert-only renewal using the existing key,
and loading and resolving the trusted-dispatcher map.

Pairing delivers the dispatcher's serial and `dispatcher_id` and **appends**
them to the trusted-dispatcher map (it no longer replaces a single stored
serial). A second dispatcher paired to the same agent is added alongside the
first, each chaining to the shared CA root, which is how one agent comes to
serve several distinct dispatchers.

The 11-minute timeout on the socket is intentionally longer than the
dispatcher's 10-minute poll window, so the agent gets a proper denial response
rather than a socket timeout.

Nonce
: `submit_pairing_request` generates a 32-hex-character nonce via `_gen_nonce`
  and sends it in the pairing payload. `await_pairing_result` then verifies that
  the nonce in the approval response matches before returning the delivered
  certs. Mismatched nonce returns
  `{ ok => 0, error => 'nonce mismatch in pairing result' }`.

Functions:

`generate_key_and_csr(%opts)`
: Generates a 4096-bit RSA key and a CSR. Returns `{ key_pem, csr_pem }`.
  Options: `hostname` (required), `bits` (default 4096).

`generate_csr_only(%opts)`
: Generates a CSR from the existing agent key without creating a new key.
  Used for cert renewal - key continuity is preserved across renewals.
  Returns `{ csr_pem }`. Required: `hostname`, `key_path`. Dies if the key
  file does not exist.

Pairing is a two-phase API. `submit_pairing_request` opens the connection and
sends the request; `await_pairing_result` reads the (possibly long-delayed)
approval or denial on the still-open socket. They are split because the
dispatcher holds the connection open while an operator approves the request,
so the caller can do other work between the two calls.

`submit_pairing_request(%opts)`
: Connects to the dispatcher's pairing port over TLS, generates a nonce, and
  sends `{ hostname, csr, nonce, ... }`. Reads the immediate
  `{ status: pending, reqid }` acknowledgement and leaves the socket open.
  Returns `{ ok => 1, reqid, sock, nonce }` or `{ ok => 0, error }`.
  Options: `ctrl-exec` (required - the dispatcher host), `csr_pem` (required),
  `hostname` (required), `port` (default 7444), `ca_cert`, `lookup_by`,
  `agent_port`.

`await_pairing_result(%opts)`
: Reads the final approval/denial response on the socket returned by
  `submit_pairing_request`, verifies the nonce, and closes the socket. Returns
  `{ ok => 1, cert_pem, ca_pem, dispatcher_serial, dispatcher_id }` or
  `{ ok => 0, error }`. Options: `sock` (required), `nonce` (required).

`store_certs(%opts)`
: Writes `agent.crt` (0640), `agent.key` (0640), `ca.crt` (0644) to `cert_dir`.
  Uses atomic rename via temp file. Sets group ownership to `ctrl-exec-agent`
  if the group exists on the system.

`pairing_status(%opts)`
: Checks cert files, reads expiry via `openssl x509 -noout -enddate`.
  Returns `{ paired => 1, expiry }` or `{ paired => 0, reason }`.

`load_trusted_dispatchers(%opts)`
: Reads the trusted-dispatcher map file (one `<hex-serial> <dispatcher-id>`
  per line). Returns a hashref `{ '<hex-serial>' => '<dispatcher-id>', ... }`.
  Replaces the old `load_dispatcher_serial`, which returned a single hex
  string. Optional: `path` (default `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`).

`dispatcher_trusted($peer_serial, $trusted)`
: Resolves a connecting peer against the map. Returns the matched
  `dispatcher_id` if `$peer_serial` is a key in `$trusted`, otherwise `undef`.
  This is the per-request trust gate; callers refuse the request on `undef`.

HTTP response reading
: `submit_pairing_request` and `await_pairing_result` read headers
  line-by-line until the blank separator, extract `Content-Length`, then call
  `read()` for exactly that many bytes. Reading to EOF would block - the
  dispatcher child holds the connection open while polling and does not close
  it when sending the response.


### `Exec::Agent::Server`

The agent's HTTP request handlers, extracted from `bin/ctrl-exec-agent`. Owns
`handle_connection` and the per-endpoint handlers (`handle_run`, `handle_ping`,
`handle_capabilities`, `handle_rotate_serial`, `handle_renew`, `handle_result`,
...) plus their response helpers. The runtime version is threaded in from the
bin.


### `Exec::Agent::AsyncRunner`

Detached (setsid + double-fork) execution of allowlisted scripts with a
persisted run store under `/var/lib/ctrl-exec-agent/runs`. `submit` spawns and
records a job; `result`/`owned_by` read it back; `purge_expired` applies the
TTL. A second async run of the same script is refused via a per-script flock.


### `Exec::Agent::ExecClient`

Front-end -> executor client. `run(%opts)` hands an authorised run to the
privileged executor (`ctrl-exec-exec`) over its unix socket using the
length-prefixed wire framing and parses the captured result back.


### `Exec::Agent::Schema`

Agent side of the script-schema sidecar contract (`docs/SCHEMA-SIDECAR.md`).
`load_for_allowlist` reads the optional sidecar beside each allowlisted script,
derives a stable `schema_version`, and returns both for advertisement on
`/capabilities`. Core transports the body without interpreting it.


## `bin/ctrl-exec-dispatcher`

The dispatcher CLI. Argument parsing and output formatting only; all business
logic is in the library modules.

Modes:

`setup-ca`
: Calls `Exec::CA::generate_ca()`. One-time operation on the dispatcher
  host. Creates the CA key and cert in `/etc/ctrl-exec/`.

`setup-ctrl-exec`
: Calls `Exec::CA::generate_dispatcher_cert()`. Generates the
  dispatcher's own key and cert signed by the CA. Run after `setup-ca`.
  Replaces the four manual openssl commands previously required.

`pairing-mode`
: Calls `Exec::Pairing::run_pairing_mode()`. Blocks until interrupted.
  Interactive when run in a terminal (tty): displays incoming requests and
  prompts for approve/deny. Non-interactive when piped or run from a service.

`list-requests`
: Calls `Exec::Pairing::list_requests()` and prints a table.

`approve <reqid>` / `deny <reqid>`
: Calls `Exec::Pairing::approve_request()` or `deny_request()`.
  `approve` also triggers registry write via `Exec::Registry`.

`list-agents`
: Calls `Exec::Registry::list_agents()` and prints a table of all
  paired agents with hostname, IP, paired timestamp, and cert expiry.

`unpair <hostname>`
: Calls `Exec::Registry::remove_agent()`. Removes the agent from the
  registry and prints a warning that the cert remains valid until expiry.
  Logs `ACTION=unpair` with the cert expiry date.

`ping <host>...`
: Auth hook checked first, then `Engine::ping_all()`. Cert renewal triggered
  automatically for any host whose cert is past half-life.

`run <host>... <script> [-- <args>]`
: Auth hook checked, then `Lock::check_available`, then `Engine::dispatch_all`.

Auth options
: `--token` reads from the flag or `$ENVEXEC_TOKEN` env var (never appears
  in `ps` output when set via env). `--username` defaults to `$ENV{USER}`.
  Source IP is hardcoded to `127.0.0.1` for CLI calls.

Testability
: `main()` is called as `main() unless caller`. This means the file can be
  `do`'d by test files without triggering execution - the standard Perl idiom
  for making a script's functions testable without a separate library. The
  `ctrl-exec-cli.t` test relies on this to load `_parse_run_args` and
  `_format_*` functions without running the CLI.

Arg parsing for `run`
: `_parse_run_args()` splits `@ARGV` on `--`. Everything after `--` becomes
  script args; before `--`, the last element is the script name and the rest
  are hosts. `Getopt::Long` is configured with `:config pass_through` so that
  `--` is not consumed by the option parser.


## `bin/ctrl-exec-agent`

The agent daemon. Listens on port 7443 using `IO::Socket::SSL` directly.

`HTTP::Daemon::SSL` was originally used but removed: version 1.05_01 (the
current Debian trixie package) does not interoperate reliably with modern
`IO::Socket::SSL`. The agent reads raw HTTP/1.0 requests from the SSL socket.

Modes:

`serve` (default)
: Starts the `IO::Socket::SSL` server. Forks one child per connection. The
  child calls `handle_connection()` and exits. The parent closes its copy with
  `SSL_no_shutdown => 1` and reaps children with `waitpid -1, WNOHANG`.
  SIGHUP reloads both config and allowlist without restart; tag changes,
  `script_dirs` changes, and `auth_hook` changes take effect on reload.

`request-pairing`
: Performs a preflight writability check on `/etc/ctrl-exec-agent` before
  making any network connection. Dies immediately with "re-run with sudo" if
  the directory is not writable. On success: generates key and CSR, connects
  to the dispatcher pairing port, waits for approval, stores certs.

`pairing-status`
: Calls `Exec::Agent::AgentPairing::pairing_status()` and prints the result.

`self-check`
: Loads config, allowlist, and cert status without starting the server.
  Validates each allowlisted script is executable.

Accept loop skeleton

The accept loop is in `mode_serve`. Variable names, fork pattern, and SIGHUP
placement are shown below - this is the authoritative structure for any work
that needs to hook into the loop:

```perl
sub mode_serve {
    # Load initial state
    my $config    = Exec::Agent::Config::load_config($CONFIG_PATH);
    my $allowlist = Exec::Agent::Config::load_allowlist($ALLOWLIST_PATH);
    my $revoked   = Exec::Agent::AgentPairing::load_revoked_serials(...);
    # Trusted-dispatcher map: { '<hex-serial>' => '<dispatcher-id>', ... }
    my $trusted   = Exec::Agent::AgentPairing::load_trusted_dispatchers(
                        path => $config->{trusted_dispatchers_path});

    # SIGHUP handler is top-level in mode_serve (not local $SIG{HUP}).
    # It closes over $allowlist, $revoked, $trusted and reassigns them.
    # Changes take effect for the next accepted connection.
    $SIG{HUP} = sub {
        $allowlist = eval { ... };
        $revoked   = eval { ... };
        $trusted   = eval { ... };
    };

    my $server = IO::Socket::SSL->new(...)
        or die "Cannot start server: $IO::Socket::SSL::SSL_ERROR\n";

    while (my $conn = $server->accept) {
        my $peer        = $conn->peerhost // 'unknown';
        # Peer serial extracted HERE in the parent, before fork.
        # After the parent closes its copy of $conn the SSL object is
        # invalid in the child - _peer_serial must not be called in the child.
        my $peer_serial = _peer_serial($conn);

        my $pid = fork();
        if (!defined $pid) { ... next; }

        if ($pid == 0) {
            $server->close(SSL_no_shutdown => 1);
            handle_connection($conn, $peer, $allowlist, $config,
                              $revoked, $trusted, $peer_serial);
            $conn->close;
            exit 0;
        }
        # Parent releases fd without TLS shutdown so child owns it
        $conn->close(SSL_no_shutdown => 1);
        waitpid -1, WNOHANG();
    }
}
```

`$server->accept` on failure
: Returns `undef` and sets `$IO::Socket::SSL::SSL_ERROR`. The loop uses
  `while (my $conn = $server->accept)` - a failed handshake returns `undef`,
  the condition is false, and the loop continues. The error string is available
  as `$IO::Socket::SSL::SSL_ERROR` immediately after the failed accept, before
  the next iteration. Client cert failures (wrong CA, expired cert) manifest
  here as handshake errors, not inside `handle_connection`.

`handle_connection` signature
: `handle_connection($conn, $peer, $allowlist, $config, $revoked, $trusted, $peer_serial)`

  All variables come from `mode_serve`'s scope and are passed explicitly - there
  is no closure over them. `$peer_serial` is a plain lowercase hex string (or
  `''`) extracted before fork. `$revoked` is a hashref keyed by hex serial.
  `$trusted` is the trusted-dispatcher map: a hashref
  `{ '<hex-serial>' => '<dispatcher-id>', ... }` loaded from
  `ctrl-exec-dispatchers`. Resolve the connecting peer with
  `Exec::Agent::AgentPairing::dispatcher_trusted($peer_serial, $trusted)`,
  which returns the matched `dispatcher_id` or `undef`; an `undef` result
  means the serial is not a trusted dispatcher and the request is refused.
  The resolved `dispatcher_id` drives permission, attribution
  (`DISPATCHER=<id>` in logs, `ENVEXEC_DISPATCHER` /
  `ENVEXEC_DISPATCHER_SERIAL` to auth hooks), and result-store ownership.

Testability
: `bin/ctrl-exec-agent` calls `main()` unconditionally — it does not use
  the `main() unless caller` idiom used by `bin/ctrl-exec-dispatcher`. This is a
  deliberate design choice: functions defined in the binary (`_peer_serial`,
  `handle_connection`, `handle_capabilities`) are covered by integration
  tests, which exercise them through the full accept-loop path. Unit tests
  target `Exec::Agent::Config`, `Exec::Agent::Runner`, and other
  library modules directly. This boundary keeps integration test coverage
  where it is most meaningful for the binary's concurrent, socket-driven
  logic, and keeps unit test coverage targeted at the library modules where
  pure-function testing is practical.

`_peer_serial` helper
: Extracts the peer certificate serial from an accepted `IO::Socket::SSL`
  connection using `Net::SSLeay` directly. `IO::Socket::SSL`'s
  `peer_certificate('serialNumber')` is not a valid argument in the version
  shipped with Debian trixie - the Net::SSLeay approach is the only reliable
  method. Returns lowercase hex or `''` on failure.

```perl
sub _peer_serial {
    my ($conn) = @_;
    my $ssl  = eval { $conn->_get_ssl_object } or return '';
    my $cert = eval { Net::SSLeay::get_peer_certificate($ssl) } or return '';
    my $asn1 = eval { Net::SSLeay::X509_get_serialNumber($cert) } or return '';
    my $hex  = eval { Net::SSLeay::P_ASN1_INTEGER_get_hex($asn1) } // '';
    return lc $hex;
}
```

Endpoints handled in `handle_connection`:

Before any endpoint below runs, the connecting cert's serial is resolved
against the trusted-dispatcher map via `dispatcher_trusted`. `/run`, `/ping`,
`/result`, and `/capabilities` are accepted only if the serial is a key in
the map; the matched `dispatcher_id` is then used for permission, attribution
(`DISPATCHER=<id>` in agent logs, `ENVEXEC_DISPATCHER` /
`ENVEXEC_DISPATCHER_SERIAL` to the agent auth hook), and result-store
ownership.

`POST /run`
: Extracts `script`, `args`, `reqid`, `username`, and `token` from the request
  body. Validates the script name against the allowlist (and `script_dirs` if
  configured). If `config->{auth_hook}` is set, calls `Exec::Auth::check`
  with the full request context including `username` and `token` - this is the
  agent-side auth hook, independent of the dispatcher's own hook. On pass,
  builds a `$context` hashref (script, args, reqid, peer_ip, username, token,
  timestamp) and passes it to `Agent::Runner::run_script`. Returns
  `{ script, exit, stdout, stderr, reqid }`.

`POST /ping`
: Returns `{ status: "ok", host, version, expiry, reqid }`.

`GET /capabilities`
: Returns `{ status: "ok", host, version, tags, scripts: [{name, path, executable}, ...] }`.
  Iterates the loaded allowlist, checks `-x` on each path. Tags come from
  `$config->{tags}` (populated from `[tags]` section of `agent.conf`).

`POST /renew`
: ctrl-exec-initiated cert renewal request. Loads config to find the existing
  key path, calls `Exec::Agent::AgentPairing::generate_csr_only`, returns
  `{ status: "ok", csr: "<PEM>", reqid }`. Dies on config or CSR generation
  failure.

`POST /renew-complete`
: Receives `{ cert, ca, reqid }` from the dispatcher, calls `store_certs` with
  the new cert and the existing key. Logs `ACTION=renew-complete STATUS=cert-stored`.


## `bin/ctrl-exec-api`

Entry point for the HTTP API server. Loads config, calls `Exec::API::run`.
Installed as a systemd service (`ctrl-exec-api.service`).

The service runs as the unprivileged `ctrl-exec:ctrl-exec` service user (NOT
root) with `ProtectSystem=strict` and `ReadWritePaths=/var/lib/ctrl-exec`. That
user owns the dispatcher private key (`0600 ctrl-exec`), so the API can read it to
dispatch to agents over mTLS without being root; it is a member of the `ctrl-exec`
group for the runtime dirs (registry, runs, locks). It never needs the CA key -
cert renewal would need to sign, so `/ping` runs with `renew => 0` and renewal is
driven by `ced maintain` (root timer) instead. An RCE in this network-facing JSON
server is therefore not root and cannot sign certificates. The same `ctrl-exec`
group grants the **read-only** CLI commands (`list-agents`, `status`) without sudo
to users added to it; operations that use the dispatcher or CA key still require
sudo.


## Request/Response Wire Format

All JSON over HTTP/1.0.

Agent endpoints (dispatcher → agent, mTLS on port 7443):

Run request (`POST /run`):

```json
{
  "script":   "backup-mysql",
  "args":     ["--db", "myapp"],
  "reqid":    "a3f9b2c10001",
  "username": "alice",
  "token":    "tok123"
}
```

`username` and `token` are forwarded from the dispatcher request (CLI flag,
env var, or API body). The agent does not validate them directly - it passes
them to its own auth hook (if configured) and into the script's stdin context.

Run response:

```json
{ "script": "backup-mysql", "exit": 0, "stdout": "...", "stderr": "", "reqid": "a3f9b2c10001" }
```

Ping request (`POST /ping`):

```json
{ "reqid": "b7c3d1e40001" }
```

Ping response:

```json
{ "status": "ok", "host": "agent-host-02", "version": "0.12.1", "expiry": "Jun  7 16:28:00 2027 GMT", "reqid": "b7c3d1e40001" }
```

Capabilities response (`GET /capabilities`):

```json
{
  "status": "ok", "host": "agent-host-01", "version": "0.12.1",
  "tags": { "env": "prod", "role": "db" },
  "scripts": [
    { "name": "backup-mysql", "path": "/opt/ctrl-exec-scripts/backup-mysql.sh", "executable": true }
  ]
}
```

Cert renewal request (`POST /renew`, dispatcher → agent):

```json
{ "reqid": "c1d2e3f40001" }
```

Cert renewal response (agent → dispatcher):

```json
{ "status": "ok", "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "reqid": "c1d2e3f40001" }
```

Cert delivery (`POST /renew-complete`, dispatcher → agent):

```json
{ "status": "ok", "cert": "-----BEGIN CERTIFICATE-----\n...", "ca": "-----BEGIN CERTIFICATE-----\n...", "reqid": "c1d2e3f40001" }
```

Pairing request (agent → dispatcher, port 7444, `POST /pair`):

```json
{ "hostname": "agent-host-01", "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...", "nonce": "a3f4c2b1..." }
```

Pairing response:

```json
{ "status": "approved", "cert": "-----BEGIN CERTIFICATE-----\n...", "ca": "-----BEGIN CERTIFICATE-----\n...", "nonce": "a3f4c2b1..." }
```

API endpoints (caller → ctrl-exec-api, port 7445):

`POST /ping` request:

```json
{ "hosts": ["agent-host-01", "agent-host-02"], "username": "alice", "token": "..." }
```

`POST /run` request:

```json
{ "hosts": ["agent-host-01"], "script": "backup-mysql", "args": ["--db", "myapp"], "username": "alice", "token": "..." }
```

`GET /discovery` response:

```json
{
  "ok": true,
  "hosts": {
    "agent-host-01": {
      "status": "ok", "version": "0.12.1", "rtt": "68ms",
      "tags": { "env": "prod", "role": "db" },
      "scripts": [{ "name": "backup-mysql", "path": "/opt/scripts/backup-mysql.sh", "executable": true }]
    }
  }
}
```

Lock conflict response (409):

```json
{ "ok": false, "error": "locked", "code": 4, "conflicts": ["agent-host-01:backup-mysql"] }
```


## Syslog Format

All log lines follow `ACTION=value KEY=value KEY=value` with `ACTION` first
and all remaining keys in the order they are passed to `log_action`. Values
containing spaces are quoted.

The full action catalogue — every action, its fields, priorities, example
log lines, field glossary, and alert pattern reference — is in LOGGING.md.
Add new actions there when introducing new log calls.

Quick examples for orientation:

```
ctrl-exec[1234]: ACTION=dispatch HOSTS=agent-host-02 REQID=a3f9b2c10001 SCRIPT=backup-mysql
ctrl-exec[1234]: ACTION=run EXIT=0 REQID=a3f9b2c10001 RTT=87ms SCRIPT=backup-mysql TARGET=agent-host-02:7443
ctrl-exec[1234]: ACTION=pair-approve AGENT=agent-host-01 REQID=fa5e74630001
ctrl-exec-agent[5678]: ACTION=run EXIT=0 PEER=192.0.2.11 REQID=a3f9b2c10001 SCRIPT=backup-mysql
ctrl-exec-api[9012]: ACTION=api-request LEN=25 METHOD=POST PATH=/ping PEER=127.0.0.1
```

The `REQID` field appears in both dispatcher and agent log lines for the
same operation, enabling cross-host log correlation.


## Automatic Cert Renewal

Cert lifetime is configured in `ctrl-exec.conf` as `cert_days` (default 365).
Renewal is triggered by the dispatcher after every successful ping when the
agent's remaining cert validity drops below half the configured lifetime.

Renewal is driven hands-free by the dispatcher's `ctrl-exec-maintenance.timer`
(root, for CA-key access), which runs `ced maintain`: it pings every registered
agent and rotates the dispatcher's own cert. The trust boundary is drawn at the
private **key** - the agent transports and writes its own (public) certificate;
only signing (CA key) and the live-cert promotion stay privileged.

The renewal flow:

1. `ping_all` collects ping results. For each successful result, `_renewal_due`
   compares the returned expiry against `(cert_days / 2) * 86400`.
2. If renewal is due, `_renew_one` sends `POST /renew` to the agent. The agent
   generates a CSR from its existing key (`generate_csr_only`) and returns it.
   The key is never regenerated - key continuity is preserved across renewals.
3. The dispatcher signs the CSR via `Exec::CA::sign_csr` (binding the subject CN
   to the agent's registry identity via `expected_cn`), then sends
   `POST /renew-complete` with the new cert.
4. The agent **validates and stages** the cert itself (`stage_renewed_cert`):
   it verifies the cert against its CA and that the cert's public key matches its
   own key, then writes it atomically to a staging file in its writable state dir
   (`/var/lib/ctrl-exec-agent/agent.crt.staged`). The live cert is untouched and
   the running server keeps using it (still valid - renewal runs well before
   expiry). No privileged writer is needed: the cert is public material the agent
   owns.
5. The agent's `ctrl-exec-agent-renew.timer` notices a staged cert and restarts
   the service. The unit's `ExecStartPre=+ctrl-exec-agent promote-cert` runs as
   root before the server starts, re-validates the staged cert and atomically
   promotes it into the root-owned live cert path (`promote_staged_cert`), then
   the server comes up on the renewed cert. A staged cert that fails validation is
   dropped without touching the live cert, so a bad delivery can never wedge
   startup.
6. The dispatcher updates the registry expiry for the agent.

The validation at both stage and promote is a robustness gate, not a secret
boundary: a certificate is public, and a renewed one is useless unless CA-signed
for the agent's existing key (which the agent already holds), so a compromised
front-end gains nothing by writing one. The only secret - the private key - stays
root-owned and is never written by the agent. This is why renewal needs no
privileged cert installer: the boundary is the key, not the cert.

Renewal failure is logged at ERR level and does not affect the ping result.
The operator can investigate via syslog. A cert that fails renewal will
eventually expire; the next maintenance run retries it.

An agent that has been out of contact for the full cert lifetime self-expires,
which is correct behaviour for a decommissioned host that was never explicitly
unpaired.


## Security Model

allowlist validation
: `validate_script()` checks the name against `/^[\w-]+$/` before allowlist
  lookup. This prevents path traversal (no `/` or `..` can pass). The allowlist
  maps names to absolute paths; relative paths are rejected at load time.

script_dirs restriction
: If `script_dirs` is configured in `agent.conf`, `load_allowlist` rejects any
  path not under an approved directory at load time. `validate_script` also
  re-checks the resolved path at execution time, guarding against allowlist
  modifications between agent startup and execution. When not configured,
  behaviour is unchanged - any absolute path is permitted (opt-in hardening).

no shell execution
: `exec { $path } $path, @args` passes the argument list directly to the OS.
  Shell metacharacters in arguments have no effect.

mTLS on port 7443
: `SSL_verify_mode => SSL_VERIFY_PEER` on both sides means both dispatcher and
  agent must present a cert signed by the CA. An agent with no cert, or a cert
  signed by a different CA, cannot connect. CA trust alone is not sufficient
  for a dispatcher: above the mTLS layer, the agent additionally requires the
  connecting cert's serial to be a key in its trusted-dispatcher map
  (`ctrl-exec-dispatchers`) for `/run`, `/ping`, `/result`, and
  `/capabilities`. The matched `dispatcher_id` is the identity used for
  policy and attribution — policy keys on the id, not the serial.

pairing port security
: Port 7444 uses `SSL_VERIFY_NONE` for the client - the agent has no cert yet.
  This is a bootstrap problem: the first connection is unauthenticated.
  Mitigation: the operator reviews the hostname and IP before approving. The
  pairing port is only open when `pairing-mode` is running. Nonce verification
  prevents misrouted or replayed approvals.

pairing preflight check
: `request-pairing` verifies that `/etc/ctrl-exec-agent` is writable before
  making any network connection. This prevents a stale pairing request being
  left in the dispatcher queue when the agent cannot write the received certs.

cert renewal security
: Renewal uses the already-authenticated mTLS connection on port 7443. The
  dispatcher only initiates renewal for hosts in its registry. The agent only
  accepts renewal over the authenticated operational port - pairing mode does
  not need to be running.

unpairing
: `ced unpair <hostname>` removes the registry entry, ending the
  dispatcher's knowledge of the agent. The agent's cert remains technically
  valid until its natural expiry date. No CRL mechanism is implemented. The
  agent should be decommissioned promptly after unpairing.

API security
: Port 7445 has no mTLS. Auth is delegated entirely to the auth hook. The
  default hook authorises everything; operators must replace it with real
  token or credential checking for any internet-facing deployment.

auth hook token
: The token is passed to the hook via `ENVEXEC_TOKEN` env var and as a JSON
  field on stdin. It is never logged by the dispatcher. The CLI reads it from
  `--token` or `$ENVEXEC_TOKEN` env var; using the env var prevents the
  token appearing in `ps` output.

file permissions
: CA key: 0600 root. dispatcher key: 0600 ctrl-exec (the API service user; root
  also reads it). dispatcher cert: 0644 root. Agent cert/key: 0640
  root:ctrl-exec-agent. Scripts: 0750 root:ctrl-exec-agent. The
  `ctrl-exec-agent` system user has no login shell and no home directory.
  Runtime dirs: 0770 root:ctrl-exec; the shared agents/locks/runs dirs are setgid
  (2770) so files the root CLI and the unprivileged ctrl-exec API create both
  inherit the ctrl-exec group (lock files 0660 so either can flock them).

systemd hardening
: The agent unit sets `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`. The API unit sets the same and restricts
  writes to `/var/lib/ctrl-exec`.


## Known Issues and Bugs Fixed

SIGCHLD race in auth hook (fixed)
: The API server sets a SIGCHLD reaper that calls `waitpid(-1, WNOHANG)` in a
  loop to clean up request-handling children. Request handlers are themselves
  forked children. When `_run_hook` in `Auth.pm` forks the hook executable, the
  inherited reaper could collect the hook grandchild before `_run_hook`'s own
  `waitpid` could. `waitpid` on an already-reaped PID returns -1, `$?` stays
  -1, and `($? >> 8) & 0xff = 255`, appearing as a hook failure.
  Fixed by setting `local $SIG{CHLD} = 'DEFAULT'` before the fork in `_run_hook`.

`HTTP::Daemon::SSL` interoperability (fixed)
: Version 1.05_01 does not reliably interoperate with modern `IO::Socket::SSL`
  on Debian trixie. Replaced with direct `IO::Socket::SSL` and raw HTTP/1.0
  parsing in the agent.

`Getopt::Long` consuming `--` separator (fixed)
: `GetOptions` strips `--` from `@ARGV` by default, causing all args after `--`
  to be treated as hosts. Fixed with `:config pass_through`.

Interactive pairing prompt buffering (fixed)
: When STDIN is a tty, the pairing mode prompt was written to a buffered
  stdout and did not appear until Ctrl-C flushed the buffer. Fixed by setting
  `local $| = 1` (autoflush) at the start of `run_pairing_mode` when
  interactive mode is detected.

`handle_connection` missing `$config` argument (fixed)
: When agent-side auth hook support was added, `$config` was added to
  `handle_run`'s signature but `handle_connection` - which sits between
  `mode_serve` and `handle_run` - was not updated to receive and forward it.
  This caused a compile-time error (`Global symbol "$config" requires explicit
  package name`) when `ctrl-exec-agent request-pairing` was run. Fixed by
  passing `$config` at the `handle_connection` call site in `mode_serve` and
  adding it to `handle_connection`'s parameter list.

`_renewal_due`, `_renew_one`, `_extract_expiry` lost from `Engine.pm` (fixed)
: These private functions were inadvertently removed from `Engine.pm` during
  an edit session. Their absence caused `renewal.t` to fail with
  `Undefined subroutine &Exec::Engine::_renewal_due` and also silently
  disabled automatic cert renewal in `ping_all`. Restored in full.

`_renewal_due` test assertions inverted (fixed)
: `renewal.t` subtest `_renewal_due: respects cert_days configuration` used
  200 days remaining and asserted it was due with cert_days=365 (half-life
  182.5 days). Since 200 > 182.5, the cert is not yet past half-life and the
  assertion was wrong. Corrected: 200 days remaining is not due with
  cert_days=365 (200 > 182.5) and is due with cert_days=730 (200 < 365).

`RateLimit::check` stale key after expired block (fixed)
: When a block had expired, `check` deleted the entry and then re-initialised
  an empty `{ connections => [], failures => [] }` entry for the same IP before
  returning 0. This left a stale key in `%rate_state` with empty arrays rather
  than no key at all. On the next connection, `record_connection` would push
  into the pre-existing empty arrayref correctly, but the presence of the key
  meant that eviction would treat this IP as having a `blocked_until` of `undef`
  (sorting as 0) rather than as a genuinely new entry. Fixed by adding
  `return 0` immediately after `delete $state->{$peer}`, consistent with the
  spec's "delete the entire entry and continue" intent.


## Adding a New Script to an Agent

On the agent host:

```bash
# Place script in the managed directory
sudo cp my-script.sh /opt/ctrl-exec-scripts/
sudo chmod 750 /opt/ctrl-exec-scripts/my-script.sh
sudo chown root:ctrl-exec-agent /opt/ctrl-exec-scripts/my-script.sh

# Add to allowlist
echo "my-script = /opt/ctrl-exec-scripts/my-script.sh" \
    | sudo tee -a /etc/ctrl-exec-agent/scripts.conf

# Reload allowlist without restart
sudo systemctl kill --signal=HUP ctrl-exec-agent

# Verify discovery sees the new script
sudo ced ping agent-host-01
sudo ced run agent-host-01 my-script
```

Scripts receive positional arguments exactly as passed. They should exit 0 on
success, non-zero on failure. stdout and stderr are both captured and returned.

Scripts also receive the full request context (script, args, reqid, peer_ip,
username, token, timestamp) as a JSON object on stdin. Scripts that do not
need this should add `exec 0</dev/null` at the top to avoid blocking on an
unread stdin pipe.


## Extending the System

Adding a new agent endpoint
: Add a route check in `handle_connection()` in `bin/ctrl-exec-agent`.
  Add the handler following the `handle_run`/`handle_ping` pattern: decode
  body, do work, call `_send_json()`. Pass `$config` if agent configuration
  or tags are needed.

Adding a new API endpoint
: Add a route in `_handle_connection()` in `Exec::API`. Add a
  `_handle_*` function following the existing pattern: parse body, auth check,
  do work, call `_send_json()`.

Adding a new dispatcher CLI mode
: Add an entry to the `%dispatch` hash in `main()` in `bin/ctrl-exec-dispatcher`.
  Add a `mode_*` function. Keep network logic in Engine; keep output formatting
  in the inline `_format_*` helpers in `bin/ctrl-exec-dispatcher` (e.g.
  `_format_run_results`, `_format_ping_results`, `_format_status`); keep the
  mode function thin.

Adding a new library module
: Place in `lib/Exec/` or `lib/Exec/Agent/` (package `Exec::...`). Use `use strict;
  use warnings;`. All callers use `Module::function()` syntax - nothing exported
  by default. Private helpers prefixed `_`. Add a corresponding test in `t/`.

Adding agent tags
: Tags are free-form key-value pairs in the `[tags]` section of `agent.conf`.
  They appear in `/capabilities` responses and therefore in discovery output.
  The dispatcher does not interpret them. Tag-based filtering or routing belongs
  in the auth hook or in tooling that consumes the API.

Adding an agent-side auth hook
: Set `auth_hook` in `agent.conf` to an executable path. The agent calls
  `Exec::Auth::check` in `handle_run` after allowlist validation.
  The hook receives the same context as the dispatcher hook, including the
  forwarded `username` and `token`. This enables independent token validation
  on the agent - for example, verifying the token against a central validation
  service without trusting the dispatcher's prior check.

Changing cert lifetime
: Set `cert_days` in `ctrl-exec.conf`. All new certs (pairing and renewal)
  will use the new value. Existing certs are unaffected until their next
  renewal. Renewal is triggered at half the configured lifetime, so a change
  from 365 to 730 days will mean existing 365-day certs are renewed when they
  have approximately 182 days remaining, then the new 730-day cert begins its
  own half-life cycle.


## Dependencies

Agent role

```
Debian                   Alpine                   Module / binary
libio-socket-ssl-perl    perl-io-socket-ssl        IO::Socket::SSL
libjson-perl             perl-json                 JSON
openssl                  openssl                   (binary) key, CSR, cert ops
```

dispatcher role

```
Debian                   Alpine                   Module / binary
libwww-perl              perl-libwww               LWP::UserAgent
libio-socket-ssl-perl    perl-io-socket-ssl        IO::Socket::SSL
libjson-perl             perl-json                 JSON
openssl                  openssl                   (binary) CA and cert ops
```

Both roles also use core Perl modules (`Sys::Syslog`, `File::Temp`, `File::Path`,
`File::Basename`, `Getopt::Long`, `Sys::Hostname`, `POSIX`, `Time::HiRes`,
`Time::Piece`, `IO::Select`, `Fcntl`, `IPC::Open2`, `Carp`) which are in the
`perl` package on both Debian and Alpine and present on any standard installation.


## Releasing

### Version management

The version is stored in a single `VERSION` file in the repository root using
semver (`n.n.n`). It is the only authoritative source of the version.

Module files (`lib/`) carry no version strings. The three binaries
(`bin/ctrl-exec-dispatcher`, `bin/ctrl-exec-agent`, `bin/ctrl-exec-api`) carry the
sentinel value `UNINSTALLED` in their `our $VERSION` declaration in the source
tree. This value is replaced at two points:

- `make-release.sh` - stamps the release version into the staged copies of the
  binaries inside the tarball. The working tree is never modified.
- `install.sh` - stamps the version from the `VERSION` file into the installed
  binaries after copying them to `/usr/local/bin/`. If installed from a dev
  checkout without a release tarball, `UNINSTALLED` is preserved.

This means `ced --version`, agent ping responses, and API health checks
all report the version of the release that was installed, or `UNINSTALLED` if
run directly from the source tree.

### Version conventions

Patch (`0.1.x`)
: Auto-incremented by `make-release.sh` after each successful release. The
  `VERSION` file is updated and left uncommitted, ready for the release commit.

Minor (`0.x.0`)
: Manual bump in `VERSION` for significant feature additions. Edit the file
  before running `make-release.sh`.

Major (`x.0.0`)
: Manual bump in `VERSION` for breaking changes. Edit the file before running
  `make-release.sh`.

### Release process

```bash
# 1. Ensure working tree is clean - all work committed
git status

# 2. If bumping minor or major, edit VERSION manually first and commit it
#    For a patch release, VERSION is already at the right value from the
#    previous release's auto-bump

# 3. Run the release script
./make-release.sh
```

`make-release.sh` will:

- Validate `VERSION` is semver and the working tree is clean
- Stage all shipped files into a temp directory
- Stamp the version into the three staged binaries
- Generate `sbom.json` with SHA-256 hashes of all source components
- Create `ctrl-exec-<version>.tar.gz` and a `.sha256` checksum file
- Create an annotated git tag `v<version>`
- Auto-increment the patch version in `VERSION`

```bash
# 4. Review the SBOM, then commit sbom.json and the bumped VERSION together
git add sbom.json VERSION
git commit -m "release: <version>"

# 5. Push the tag
git push origin v<version>

# 6. Publish the tarball and checksum
```

The clean-tree check at step 3 is the guard against accidental double-releases:
`make-release.sh` blocks until `sbom.json` and the bumped `VERSION` are
committed, making it impossible to release the same version twice or skip a
version without a deliberate commit.

### What is shipped

The tarball contains:

```
bin/ctrl-exec-dispatcher
bin/ctrl-exec-agent
bin/ctrl-exec-api
lib/
etc/
t/
install.sh
VERSION
LICENCE
README.md
INSTALL.md
REFERENCE.md
API.md
DOCKER.md
SECURITY.md
DEVELOPER.md
BACKGROUND.md
sbom.json
```

Not shipped: `.git/`, `make-release.sh` (development tooling), editor and IDE
configuration files.

### SBOM

`sbom.json` is generated by `make-release.sh` in CycloneDX 1.6 JSON format.
It is committed to the repository as part of the release commit so it is
available alongside the source at the tagged version.

Source components (binaries and all `.pm` modules) are listed with SHA-256
hashes of the staged files (i.e. with the version already stamped). Runtime
dependencies are listed by name with `version: unknown` and external references
to the Debian and Alpine package trackers, reflecting that dependency versions
are resolved by the OS package manager at install time and are not fixed by the
distribution.
