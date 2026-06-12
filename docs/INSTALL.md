---
title: ctrl-exec - Installation and Operations
subtitle: Platform requirements, setup, configuration, and operational reference
brand: odcc
---

# ctrl-exec - Installation and Operations


## Platform Requirements

Supported platforms:

Debian / Ubuntu
: `apt` package manager, systemd for service management. All Perl dependencies
  available as system packages - no CPAN required.

Alpine Linux
: `apk` package manager. No systemd - services run directly or in Docker.
  See `DOCKER.md` for container deployment.

The installer detects the platform automatically and uses the correct package
names and commands. For RPM-based systems (RHEL, Rocky, Alma), install
dependencies manually and copy files according to the file layout in
`DEVELOPER.md`.


## Dependencies

Agent (`--agent`)

- Debian: `libio-socket-ssl-perl`, `libjson-perl`
- Alpine: `perl-io-socket-ssl`, `perl-json`

dispatcher (`--dispatcher`)

- Debian: `libwww-perl`, `libio-socket-ssl-perl`, `libjson-perl`
- Alpine: `perl-libwww`, `perl-io-socket-ssl`, `perl-json`

API (`--api`)
: No additional packages beyond the dispatcher role.

All roles require `openssl` (present on any standard installation) and `perl`.

The installer checks all dependencies before making any changes and prints the
correct install command if anything is missing.


## Installation

Install one of two ways: from the Debian/Ubuntu **packages** (recommended on
those platforms) or from the **source tarball** (any platform, including Alpine
and OpenWrt). Both produce the same binaries, the same `/etc`, `/var/lib`, and
group layout, and the same systemd units; they differ only in where the binaries
and examples live (`/usr` for packages, `/usr/local` for the tarball). The
*Initial Setup* steps that follow are identical for either.

### Debian/Ubuntu packages

Three packages are published per release:

- `ctrl-exec-common` — the shared Perl library. Required on **every** host.
- `ctrl-exec-dispatcher` — the `ced` CLI and the `ctrl-exec-api` server. Install
  on the **dispatcher** (control) host.
- `ctrl-exec-agent` — the `cea` agent service. Install on **each managed** host.

Download the release `.deb` files from the
[releases page](https://github.com/OpenDigitalCC/ctrl-exec/releases) (or build
them from a source checkout with `./make-release.sh`), then install `common`
plus the role for that host:

```bash
# dispatcher host
sudo apt install ./ctrl-exec-common_*.deb ./ctrl-exec-dispatcher_*.deb

# agent host
sudo apt install ./ctrl-exec-common_*.deb ./ctrl-exec-agent_*.deb
```

Use `apt install ./<file>.deb` rather than `dpkg -i`: apt resolves the runtime
dependencies (libwww-perl, libio-socket-ssl-perl, libjson-perl, openssl) from
your configured sources, whereas `dpkg -i` fails if they are not already
present. The packages seed example config into `/etc/ctrl-exec` and
`/etc/ctrl-exec-agent`, create the `ctrl-exec` group, and install the systemd
units **without enabling or starting them** — you start the agent only after
pairing (see *Initial Setup*).

### Source tarball (install.sh)

Works on Debian/Ubuntu, Alpine, and OpenWrt. Run as root; a role must be
specified:

```bash
sudo ./install.sh --agent        # on each remote host
sudo ./install.sh --dispatcher   # on the dispatcher host
sudo ./install.sh --api          # on the dispatcher host, after --dispatcher
sudo ./install.sh --uninstall    # remove files (preserves config and certs)
sudo ./install.sh --run-tests    # run test suite from source directory
```

`--run-tests` may be combined with a role flag to run tests after installation,
or used alone to test without installing. The installer checks all dependencies
before making any changes and prints the exact package command if any are
missing. (Unlike the packages, the dispatcher's API server is a separate
`--api` role here.)

### Installed paths

The tarball installs the binaries and library under `/usr/local`; the packages
install them under `/usr` (`/usr/bin`, `/usr/share/perl5/Exec`, examples in
`/usr/share/ctrl-exec/examples`). The config, state, and group paths are
identical.

```
/usr/local/bin/{ctrl-exec-dispatcher, ced, ctrl-exec-agent, ctrl-exec-api}
                                   the CLIs (packages: /usr/bin)
/usr/local/lib/ctrl-exec/          Perl library (packages: /usr/share/perl5/Exec)
/etc/ctrl-exec/                    dispatcher config, CA material, auth hook
/etc/ctrl-exec-agent/              agent config and certs
/opt/ctrl-exec-scripts/            managed scripts on agent hosts
/var/lib/ctrl-exec/pairing/        pending pairing requests
/var/lib/ctrl-exec/agents/         agent registry
/var/lib/ctrl-exec/locks/          concurrency lock files (transient)
ctrl-exec-agent.service            systemd unit (tarball: /etc/systemd/system;
ctrl-exec-api.service              packages: /usr/lib/systemd/system)
```

The tarball installer stamps the release version from the `VERSION` file into
the binaries at install time (the source files carry the sentinel `UNINSTALLED`
until then); `ced --version` then reports the installed release. Packages carry
their version in the `.deb` itself.

### ctrl-exec group

Both methods create a `ctrl-exec` system group. Add yourself to it for CLI
access without sudo:

```bash
sudo usermod -aG ctrl-exec $USER
# Log out and back in (or run `newgrp ctrl-exec`) for the group to take effect
```


## Running the Tests

Run from the project root before or after installing:

```bash
prove -Ilib t/
```

Or via the installer:

```bash
sudo ./install.sh --agent --run-tests
```

`t/lock.t` requires `t/lock-holder.pl` to be present alongside it.
`t/auth.t` and `t/pairing-ctrl-exec.t` require `libjson-perl` / `perl-json`
and are skipped automatically if not available.


## Initial Setup

### 1. dispatcher host - CA and certificates

Initialise the CA (once only - do not repeat on an existing installation):

```bash
sudo ced setup-ca
```

Generate the dispatcher's own certificate:

```bash
sudo ced setup-ctrl-exec
```

Both commands write to `/etc/ctrl-exec/`. The CA private key (`ca.key`) is
set 0600 and must not leave this host. Back it up to encrypted offline storage.

### 2. Configure the dispatcher

Edit `/etc/ctrl-exec/ctrl-exec.conf`:

```ini
port      = 7443
cert      = /etc/ctrl-exec/dispatcher.crt
key       = /etc/ctrl-exec/dispatcher.key
ca        = /etc/ctrl-exec/ca.crt
auth_hook = /etc/ctrl-exec/auth-hook

# Cert lifetime for new and renewed agent certs (days)
cert_days = 365
```

`auth_hook` is optional. Remove or comment it out to authorise all requests
unconditionally. Appropriate for isolated networks; not recommended for
production deployments accessible from outside.

### 3. Agent host - configure before pairing

Edit `/etc/ctrl-exec-agent/agent.conf`:

```ini
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

# Restrict scripts to approved directories (recommended)
script_dirs = /opt/ctrl-exec-scripts

# Optional: agent-side auth hook for independent token validation
# auth_hook = /etc/ctrl-exec-agent/auth-hook

# Optional tags - reported in discovery responses
[tags]
env  = prod
role = db
site = london
```

Edit the allowlist `/etc/ctrl-exec-agent/scripts.conf`:

```ini
# name = /absolute/path/to/script
backup-mysql  = /opt/ctrl-exec-scripts/backup-mysql.sh
check-disk    = /opt/ctrl-exec-scripts/check-disk.sh
```

Place scripts in the managed directory:

```bash
sudo cp your-script.sh /opt/ctrl-exec-scripts/
sudo chmod 750 /opt/ctrl-exec-scripts/your-script.sh
sudo chown root:ctrl-exec-agent /opt/ctrl-exec-scripts/your-script.sh
```

### 4. Pairing

On the dispatcher host, start pairing mode:

```bash
sudo ced pairing-mode
```

This blocks until interrupted. When run in a terminal it is interactive -
incoming requests are displayed immediately and you are prompted to approve
or deny.

On the agent host:

```bash
sudo ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>
```

The agent connects and waits. A prompt appears in the pairing mode terminal:

```
Pairing request from agent-host-01 (192.0.2.10) - ID: 00c9845e0001
  Received: 2026-03-05T18:38:09Z
Accept, Deny, or Skip? [a/d/s]:
```

Type `a` to approve. The agent stores its cert and exits. Press Ctrl-C to
stop pairing mode.

If multiple requests arrive simultaneously they are numbered:

```
1. agent-host-01 (192.0.2.10) - ID: 00c9845e0001 - 2026-03-05T18:38:09Z
2. prod-db-01  (192.0.2.12) - ID: 1a4f2e330001 - 2026-03-05T18:38:22Z
Command (a1/d1/a2/d2/list/quit):
```

Use `a1`, `d2` etc. to act individually, `list` to redisplay, `quit` to exit.

For non-interactive use (scripted or from a service), use separate commands
from another terminal while pairing mode runs:

```bash
ced list-requests
ced approve <reqid>
ced deny <reqid>
```

Confirm the agent is registered:

```bash
ced list-agents
```

### 5. Start the agent

On systemd platforms:

```bash
sudo systemctl enable ctrl-exec-agent
sudo systemctl start ctrl-exec-agent
sudo systemctl status ctrl-exec-agent
```

On Alpine or without systemd:

```bash
ctrl-exec-agent serve
```

### 6. Verify from the dispatcher

On the agent host, confirm the agent is listening and enforcing policy
correctly with a loopback test:

```bash
sudo ctrl-exec-agent self-ping
```

`self-ping` connects to `127.0.0.1:7443`, completes the mTLS handshake,
and sends a ping. The agent responds with 403 serial mismatch — the
correct behaviour, since the agent's own cert is not a dispatcher cert.
A successful `self-ping` confirms the port is listening, TLS is working,
and the agent is enforcing serial policy.

Then verify from the dispatcher host:

```bash
ced ping <agent-hostname>
```

Expected output:

```
HOST             STATUS    RTT    CERT EXPIRY                   VERSION
-----------------------------------------------------------------------
agent-hostname   ok        45ms   Jun  7 16:28:00 2027 GMT      0.1
```

### 7. Start the API server (optional)

On systemd platforms:

```bash
sudo systemctl enable ctrl-exec-api
sudo systemctl start ctrl-exec-api
```

On Alpine or without systemd:

```bash
ctrl-exec-api
```

Verify:

```bash
curl -s http://localhost:7445/health | python3 -m json.tool
```


## Network Topology and NAT

ctrl-exec opens connections in two directions, on two ports:

- **Pairing (once per agent):** the *agent* connects out to the dispatcher's
  pairing port (default 7444).
- **Dispatch and renewal (ongoing):** the *dispatcher* connects out to each
  agent's operational port (default 7443), for every `run`, `ping`, and
  automatic certificate renewal.

So the reachability requirement is asymmetric:

- the agent only needs to reach the dispatcher's pairing port **once**, at
  pairing time;
- the dispatcher must reach every agent's operational port **continuously**.

Because dispatch is dispatcher-initiated, **each agent must be inbound-reachable
on its operational port from the dispatcher**. A host the dispatcher cannot dial
cannot serve as an agent without a network relay (see *Both sides behind NAT*).

### How the agent's address is recorded

At pairing the agent reports its own source address, and the dispatcher records,
in priority order:

1. `approve --ip <addr>` — an explicit operator override (authoritative);
2. the address the **agent reported** for itself;
3. the source IP of the pairing connection (a last resort — unreliable behind a
   NAT, which rewrites it to the gateway).

`--lookup-by hostname` (the default) ignores the stored IP and resolves the
agent by name at dispatch time instead; `--lookup-by ip` dials the stored IP.
Correct a record after the fact with `ced edit-agent <name> --ip <addr>`.

### Dispatcher behind NAT, agents directly reachable

The common case — for example the dispatcher in a Docker container, agents on
the LAN.

- **Pairing:** publish the dispatcher's pairing port so agents can reach it
  (e.g. Docker `-p 7444:7444` on the host). Agents connect to the host's
  address.
- **Address:** the agent self-reports its real (pre-NAT) address, so it is
  registered correctly. (Recording the *connection* source IP here would store
  the NAT gateway address for every agent — which is what the self-report
  avoids.)
- **Dispatch:** works as long as the dispatcher's network can route to the
  agents. Docker masquerades container egress through the host, so LAN agents
  are reachable with no extra configuration.
- **Action:** usually none. Forward 7444 inbound to the dispatcher. If an
  agent's self-reported address is not the one to use, set it with
  `approve --ip` / `edit-agent --ip`, or use `--lookup-by hostname`.

### Agent behind NAT, dispatcher directly reachable

- **Pairing:** works unchanged — the agent dials out, which the NAT permits.
- **Address:** the agent self-reports its *private* address, which the
  dispatcher cannot reach, so it **must be overridden** with the agent's public
  address, and the agent's NAT must **forward the operational port** to it.
- **Action:**
  - On the agent's router, forward the operational port to the agent
    (`WAN:7443 -> agent:7443`, or a different external port).
  - Approve with the public address:
    `ced approve <reqid> --ip <public-ip>` — add
    `--agent-port <external-port>` if the forwarded external port is not 7443.
  - Or point a public DNS name at the agent's NAT and approve with
    `--lookup-by hostname`.

### Both sides behind NAT

Combine the two: the dispatcher's pairing port must be forwarded (for pairing)
and each agent's operational port must be forwarded (for dispatch). Register
each agent's public address with `approve --ip` (plus `--agent-port` if the
external port is remapped), or a public hostname with `--lookup-by hostname`.

If an agent sits behind a NAT you cannot configure for inbound forwarding (for
example carrier-grade NAT), the dispatcher cannot reach it. The clean solution
is to put the hosts on a routable overlay network — a WireGuard or VPN mesh, or
an SSH reverse tunnel that exposes the agent's port into the dispatcher's
network — and then pair and dispatch over the overlay addresses, where NAT no
longer applies.

### Reachability summary

| Who is NAT'd        | Forward inbound                         | Register agent IP as            |
|---------------------|-----------------------------------------|---------------------------------|
| Neither             | nothing                                 | agent self-report (automatic)   |
| Dispatcher only     | dispatcher pairing port (7444)          | agent self-report (automatic)   |
| Agent only          | agent operational port (7443)           | agent public IP (`--ip`)        |
| Both                | both of the above                       | agent public IP (`--ip`)        |

In every NAT case `--lookup-by hostname` with a public DNS name is an
alternative to a fixed `--ip`.


## CLI Reference

### Run

```bash
# Run a script on one host
ced run host-a backup-mysql

# With arguments (everything after -- is passed to the script)
ced run host-a logger -- -t my-tag "hello from ctrl-exec"

# Multiple hosts in parallel
ced run host-a host-b host-c check-disk

# Custom port on one host
ced run host-a:7450 host-b backup-mysql

# JSON output
ced run host-a backup-mysql --json

# With auth token (preferred: via environment, does not appear in ps)
ENVEXEC_TOKEN=mytoken ced run host-a backup-mysql
ced run host-a backup-mysql --token mytoken --username deploy
```

### Ping

```bash
ced ping host-a
ced ping host-a host-b host-c
ced ping host-a --json
```

### Agent management

```bash
ced list-agents                  # all paired agents with cert expiry
ced list-requests                # pending pairing requests
ced approve <reqid>              # approve a pairing request
ced deny <reqid>                 # deny a pairing request
ced unpair <hostname>            # remove agent from registry
```

`unpair` removes the registry entry. The agent cert remains valid until its
natural expiry - decommission the host promptly.


## API Reference

The API server listens on port 7445. All bodies are JSON with
`Content-Type: application/json`.

### Endpoints

`GET /health`
: Liveness check. No auth. Returns `{ "ok": true, "version": "0.1" }`.

`POST /ping`
: Body: `{ "hosts": [...], "username": "...", "token": "..." }`.
  Returns `{ "ok": true, "results": [...] }`.

`POST /run`
: Body: `{ "hosts": [...], "script": "...", "args": [...], "username": "...", "token": "..." }`.
  Returns `{ "ok": true, "results": [...] }`.

`GET /discovery` or `POST /discovery`
: Optional body: `{ "hosts": [...] }`. If hosts omitted, queries all registered
  agents. Returns `{ "ok": true, "hosts": { hostname: { scripts, tags, ... } } }`.

### HTTP status codes

```
200   Success
400   Bad request
403   Auth denied
404   Unknown endpoint, or unknown agent (host is not a registered agent)
409   Lock conflict (script already running on host)
500   Server error
```

### Examples

```bash
# Ping
curl -s -X POST http://localhost:7445/ping \
  -H 'Content-Type: application/json' \
  -d '{"hosts":["agent-host-01"]}' | python3 -m json.tool

# Run
curl -s -X POST http://localhost:7445/run \
  -H 'Content-Type: application/json' \
  -d '{"hosts":["agent-host-01"],"script":"backup-mysql","args":["--db","myapp"]}' \
  | python3 -m json.tool

# Discovery
curl -s http://localhost:7445/discovery | python3 -m json.tool
```

### API TLS

Add to `/etc/ctrl-exec/ctrl-exec.conf`:

```ini
api_cert = /etc/ctrl-exec/dispatcher.crt
api_key  = /etc/ctrl-exec/dispatcher.key
```

Restart the API service. Clients use `--cacert /etc/ctrl-exec/ca.crt` or a
certificate from a public CA if clients do not have the private CA cert.


## Auth Hook

The auth hook is called before every `run` and `ping` from both CLI and API.
It is the sole policy engine - ctrl-exec has no built-in ACLs.

The hook receives request context as environment variables and as a JSON object
on stdin. Tokens and usernames are forwarded through to agent hooks and to
scripts via JSON stdin, enabling token validation at every stage of an
execution pipeline.

### Environment variables

```
ENVEXEC_ACTION      run | ping
ENVEXEC_SCRIPT      script name (empty for ping)
ENVEXEC_HOSTS       comma-separated host list
ENVEXEC_ARGS        space-joined args (ambiguous if args contain spaces)
ENVEXEC_ARGS_JSON   args as a JSON array string (use this for arg inspection)
ENVEXEC_USERNAME    username from request (may be empty)
ENVEXEC_TOKEN       token from request (may be empty)
ENVEXEC_SOURCE_IP   127.0.0.1 for CLI, caller IP for API
ENVEXEC_TIMESTAMP   ISO 8601 UTC timestamp
```

### Exit codes

```
0   authorised
1   denied - generic
2   denied - bad credentials
3   denied - insufficient privilege
```

The hook must not produce output. Use syslog for audit logging.

### Examples

Static token check:

```bash
#!/bin/bash
[[ "$ENVEXEC_TOKEN" == "mysecrettoken" ]] || exit 2
exit 0
```

Per-token script restriction:

```bash
#!/bin/bash
case "$ENVEXEC_TOKEN" in
    backup-token)
        [[ "$ENVEXEC_SCRIPT" == backup-* ]] || exit 3
        exit 0 ;;
    ops-token)
        exit 0 ;;
    *)
        exit 2 ;;
esac
```

Argument count check using `ENVEXEC_ARGS_JSON`:

```bash
#!/bin/bash
ARG_COUNT=$(echo "$ENVEXEC_ARGS_JSON" \
    | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
[[ "$ARG_COUNT" -le 2 ]] || exit 3
exit 0
```

### Agent-side auth hook

Agents can also run an auth hook, configured via `auth_hook` in `agent.conf`.
This runs after allowlist validation and receives the same context including
token and username forwarded from the dispatcher. Useful for independent token
validation in zero-trust or multi-dispatcher deployments.


## Configuration Reference

### `/etc/ctrl-exec/ctrl-exec.conf`

```ini
port      = 7443                          # mTLS port agents connect to
cert      = /etc/ctrl-exec/dispatcher.crt
key       = /etc/ctrl-exec/dispatcher.key
ca        = /etc/ctrl-exec/ca.crt
auth_hook = /etc/ctrl-exec/auth-hook     # optional
api_port  = 7445                          # API server port
api_cert  = /etc/ctrl-exec/dispatcher.crt  # optional, enables TLS on API
api_key   = /etc/ctrl-exec/dispatcher.key  # optional
cert_days = 365                           # lifetime for new/renewed agent certs
```

### `/etc/ctrl-exec-agent/agent.conf`

```ini
port = 7443
cert = /etc/ctrl-exec-agent/agent.crt
key  = /etc/ctrl-exec-agent/agent.key
ca   = /etc/ctrl-exec-agent/ca.crt

# Colon-separated list of approved script directories (optional)
script_dirs = /opt/ctrl-exec-scripts

# Agent-side auth hook executable (optional)
# auth_hook = /etc/ctrl-exec-agent/auth-hook

# Pairing port (default: 7444)
# pairing_port = 7444

# Restrict connections to known dispatcher IPs (optional)
# allowed_ips = 192.168.1.10, 10.0.0.0/8

# Rate limiting (defaults shown - omit to use defaults)
# rate_limit_volume = 10/60/300
# rate_limit_probe  = 3/600/3600
# rate_limit_disable = 1   # disable for testing only

[tags]
env  = prod
role = db
site = london
```

### `/etc/ctrl-exec-agent/scripts.conf`

```ini
# name = /absolute/path/to/script
backup-mysql  = /opt/ctrl-exec-scripts/backup-mysql.sh
check-disk    = /opt/ctrl-exec-scripts/check-disk.sh
```


## Adding Scripts to an Agent

```bash
sudo cp check-disk.sh /opt/ctrl-exec-scripts/
sudo chmod 750 /opt/ctrl-exec-scripts/check-disk.sh
sudo chown root:ctrl-exec-agent /opt/ctrl-exec-scripts/check-disk.sh

echo "check-disk = /opt/ctrl-exec-scripts/check-disk.sh" \
    | sudo tee -a /etc/ctrl-exec-agent/scripts.conf

# Reload without restart
sudo systemctl kill --signal=HUP ctrl-exec-agent
```

Scripts receive positional arguments as passed. They should exit 0 on success,
non-zero on failure. stdout and stderr are both captured and returned.

Full request context (script name, args, reqid, peer IP, username, token,
timestamp) is also piped to the script as a JSON object on stdin. Scripts that
do not need it can redirect stdin: add `exec 0</dev/null` at the top of the
script.

### Script permissions and privilege

The agent process runs as root by default. Scripts that should not run as root
can drop privileges explicitly:

```bash
#!/bin/bash
exec sudo -u appuser /usr/local/bin/my-script.sh "$@"
```

Add a targeted sudoers rule:

```
ctrl-exec-agent ALL=(appuser) NOPASSWD: /usr/local/bin/my-script.sh
```

This hands privilege management to `sudo`, which has exactly that job.


## Automatic Cert Renewal

Renewal is triggered automatically after every successful ping when remaining
cert validity is less than half the configured `cert_days`. With the default
365 days, renewal begins at approximately 182 days remaining.

No operator action is needed during normal operation. To check cert status:

```bash
# On the agent host
sudo ctrl-exec-agent pairing-status

# From the dispatcher (CERT EXPIRY column)
ced ping host-a host-b
```

Renewal failure is logged at ERR level on the dispatcher and retried on the
next ping. A cert that fails repeatedly will eventually expire and require
re-pairing.

To change cert lifetime, update `cert_days` in `ctrl-exec.conf`. Existing
certs are unaffected until their next renewal.


## Dispatcher Redundancy

Two ctrl-exec installations can share a CA and manage the same agent fleet
independently. Each dispatcher signs certs and maintains its own registry.
Agents accept connections from any dispatcher that shares the CA.

On the primary dispatcher after `setup-ca` and `setup-ctrl-exec`:

```bash
# Transfer CA material to secondary over a secure channel
sudo scp /etc/ctrl-exec/ca.key root@secondary:/etc/ctrl-exec/ca.key
sudo scp /etc/ctrl-exec/ca.crt root@secondary:/etc/ctrl-exec/ca.crt
```

On the secondary:

```bash
sudo ced setup-ctrl-exec
```

Each dispatcher then pairs with agents independently. Agents must pair with
each dispatcher separately. This is active-active with independent registries -
registry synchronisation is an operational responsibility.


## Reloading and Restarting

Agent config and allowlist reload without downtime:

```bash
sudo systemctl kill --signal=HUP ctrl-exec-agent
# or on Alpine/non-systemd: kill -HUP <pid>
```

Reloads `agent.conf` and `scripts.conf` including `script_dirs`, `auth_hook`,
and `[tags]`. Changes take effect for subsequent requests.

Restart agent (drops in-flight connections):

```bash
sudo systemctl restart ctrl-exec-agent
```

Restart API server:

```bash
sudo systemctl restart ctrl-exec-api
```


## Troubleshooting

Agent unreachable after pairing
: Check the service is running: `systemctl status ctrl-exec-agent`.
  Check port 7443 is open: `ss -tlnp | grep 7443`.
  Verify cert: `sudo ctrl-exec-agent pairing-status`.
  Confirm the registered address is the one the dispatcher should dial
  (`ced list-agents`); if a NAT is involved, see *Network Topology and NAT*
  and correct it with `ced edit-agent <name> --ip <addr>`.

Connection refused
: The agent service is not running. `sudo systemctl start ctrl-exec-agent`.

SSL handshake failure
: Cert or CA mismatch. Re-pair the agent.

Script not found
: Check `scripts.conf` - path must be absolute and the file must be executable
  by the `ctrl-exec-agent` user. Check syslog for `ACTION=deny` lines.
  If `script_dirs` is set, confirm the path is under an approved directory.

Auth denied unexpectedly
: Confirm `auth_hook` is absent or commented out in `ctrl-exec.conf` if no
  hook is intended. Restart the API service after config changes.

Pairing request missing from `list-requests`
: Agent may have failed mid-pairing (run `sudo ctrl-exec-agent request-pairing`
  to retry). Stale requests older than 10 minutes are cleaned automatically.
  Check dispatcher syslog for `ACTION=pair-request`.

Cert renewal not occurring
: Renewal is triggered by ping. Check `CERT EXPIRY` in ping output.
  Check dispatcher syslog for `ACTION=renew` and `ERR` lines.

Connection blocked unexpectedly (`ACTION=rate-block` in syslog)
: The agent has rate-limited the source IP. The volume threshold (default: 10
  connections in 60 seconds) can be triggered by the integration test suite or
  rapid repeated pings. The block expires automatically (default: 5 minutes for
  volume, 1 hour for probe). To clear immediately, reload the agent:
  `sudo systemctl reload ctrl-exec-agent` (rate limit state is held in memory
  and reset on SIGHUP). To disable rate limiting during testing, set
  `rate_limit_disable = 1` in `agent.conf` and reload. Remove it before
  returning to production use.


## Uninstalling

```bash
sudo ./install.sh --uninstall
```

Config, certs, and the agent registry are preserved. To remove everything:

```bash
sudo rm -rf /etc/ctrl-exec-agent /etc/ctrl-exec
sudo rm -rf /var/lib/ctrl-exec /opt/ctrl-exec-scripts
# Debian
sudo userdel ctrl-exec-agent && sudo groupdel ctrl-exec
# Alpine
sudo deluser ctrl-exec-agent && sudo delgroup ctrl-exec
```
