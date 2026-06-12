---
title: ctrl-exec
subtitle: Perl machine-to-machine remote script execution over mTLS
brand: odcc
---

# ctrl-exec

A Perl machine-to-machine remote script execution system. The dispatcher host
runs scripts on remote agent hosts via HTTPS with mutual certificate
authentication. No SSH involved; agents expose only an explicit allowlist of
permitted scripts.

Designed for infrastructure automation pipelines where a dispatcher host needs
to trigger operations on a fleet of managed hosts with strong identity
guarantees and a minimal attack surface.


## How It Works

ctrl-exec has exactly two roles: a single **dispatcher host** that initiates
work, and one or more **agent hosts** that carry it out.

`ctrl-exec-dispatcher` (`ced`) - the dispatcher host
: The control host. A CLI tool plus an optional HTTP API (`ctrl-exec-api`).
  Connects to agents, sends signed requests, collects results. Manages the
  private CA, the agent registry, and the cert lifecycle. The API server
  exposes run, ping, discovery, and status endpoints with an OpenAPI spec
  (static and live-generated). There is one dispatcher host per deployment.

`ctrl-exec-agent` (`cea`) - an agent host
: A managed host. An mTLS HTTPS server on port 7443, one per host. Executes
  only scripts named in a per-host allowlist. No shell - arguments are passed
  directly to the OS. Reloads config on SIGHUP without dropping connections.

pairing
: One-time certificate exchange. The agent generates a key and CSR, connects
  to the dispatcher on port 7444, and waits for operator approval. The
  dispatcher signs the CSR with its private CA and returns the cert. After
  pairing, all traffic uses mTLS on port 7443.

auth hook
: An optional executable called before every `run` and `ping`. Receives full
  request context including token, username, script, args, and source IP.
  Tokens are forwarded through the pipeline so downstream components can
  independently verify authority. The hook is the policy engine - ctrl-exec
  has no built-in ACLs.

automatic cert renewal
: Certs are renewed automatically over the live mTLS connection when remaining
  validity drops below half the configured lifetime. No operator involvement
  during normal operation.


## Ecosystem

[ctrl-exec-plugins](https://github.com/OpenDigitalCC/ctrl-exec-plugins)
: A companion repository providing ready-built plugins across three
  categories: management interfaces for the HTTP API and CLI, agent scripts
  covering common infrastructure tasks, and auth hooks integrating ctrl-exec
  with external identity systems. Each plugin is self-contained.


## Documents

`INSTALL.md`
: Platform requirements, installer flags, initial setup, all configuration
  options, operational reference, troubleshooting.

`API.md`
: HTTP API reference. All endpoints, request and response schemas, error
  codes, OpenAPI spec endpoints, and the run result status store.

`DOCKER.md`
: Deploying dispatcher and agents in Alpine Docker containers, including
  entrypoint patterns, volume mounts, and the pairing workflow in Docker.

`SECURITY.md`
: Security model, trust boundaries, file permissions, and operational
  security guidance.

`DEVELOPER.md`
: Module reference, wire format, protocol details, and how to extend the
  system.


## Quick Start

Full detail is in `INSTALL.md`. The sequence below gets ctrl-exec running
between two hosts in about ten minutes.

### 1. dispatcher host

Install and initialise the CA and dispatcher identity:

```bash
sudo ./install.sh --dispatcher
sudo ced setup-ca
sudo ced setup-ctrl-exec
sudo usermod -aG ctrl-exec $USER
# Log out and back in for group membership to take effect
```

Configure the auth hook. The dispatcher requires an auth hook to authorise
`run` and `ping` requests. For an isolated network the simplest policy is
allow-all - replace with real logic when deploying to production:

```bash
sudo cp /usr/local/lib/ctrl-exec/auth-hook.example /etc/ctrl-exec/auth-hook
sudo chmod 755 /etc/ctrl-exec/auth-hook
```

Edit `/etc/ctrl-exec/auth-hook` and uncomment `exit 0` near the end of the
file (the "Allow everything" example). The last executable line must be
`exit 0`.

If you prefer not to use a hook, remove or comment out the `auth_hook` line
in `/etc/ctrl-exec/ctrl-exec.conf` and set:

```ini
api_auth_default = allow
```

### 2. Agent host

Install the agent:

```bash
sudo ./install.sh --agent
```

Edit `/etc/ctrl-exec-agent/scripts.conf` to add the scripts the agent is
permitted to run. `logger` is available on every platform and requires no
additional setup:

```ini
logger = /usr/bin/logger
```

Start the agent:

```bash
sudo systemctl enable ctrl-exec-agent
sudo systemctl start ctrl-exec-agent
```

Verify the agent configuration is valid before pairing:

```bash
sudo ctrl-exec-agent self-check
```

### 3. Pair the agent

On the dispatcher host, start pairing mode:

```bash
sudo ced pairing-mode
```

On the agent host, request pairing:

```bash
sudo ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>
```

A pairing code is displayed on both hosts. Confirm they match, then type `a`
in the pairing mode terminal to approve. The agent receives its signed cert
and is ready.

### 4. Verify

```bash
ced ping <agent-hostname>
ced run <agent-hostname> --script logger -- -t test "hello from ctrl-exec"
```

### Optional: API server

The API server exposes ctrl-exec over HTTP on `localhost:7445`. Install and
start it on the dispatcher host:

```bash
sudo ./install.sh --api
sudo systemctl enable ctrl-exec-api
sudo systemctl start ctrl-exec-api
curl -s http://localhost:7445/health
```

The API uses the same auth hook as the CLI. Ensure the hook is configured
before starting the API - the hook is read at startup and a stale process
will not pick up config changes without a restart.


## Platform Support

Debian / Ubuntu
: `apt` packages, systemd service management.

Alpine Linux
: `apk` packages, no systemd. Run binaries directly or use Docker - see
  `DOCKER.md`.

All dependencies are system packages on both platforms. No CPAN required.


## Licence

Released under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See `LICENCE` for the full text.

The AGPL extends the GPL copyleft requirement to cover network use: if you
run a modified version of ctrl-exec as a service, you must make the modified
source available to users of that service.
