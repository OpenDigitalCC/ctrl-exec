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
between two hosts in about ten minutes. **Run each numbered block on the host
named in its heading** - steps 1, 3 (approve), 4-stop and 5 are on the
dispatcher; steps 2, 3 (request) and 4-start are on the agent.

### 1. Dispatcher host - install and create the PKI

```bash
sudo ./install.sh --dispatcher
sudo ced setup-ca          # one-time: create the deployment CA
sudo ced setup-ctrl-exec   # create the dispatcher's own TLS certificate
```

Give your user CLI access without `sudo` (needed for `ced ping`/`run` in
step 5):

```bash
sudo usermod -aG ctrl-exec $USER
newgrp ctrl-exec           # apply the new group to this shell (or re-login)
```

> **Auth hook (optional).** With no auth hook configured, the dispatcher CLI
> allows every `run`/`ping` - fine for an isolated trial. To restrict who may
> run what, configure an auth hook later; see *Auth Hook* in `INSTALL.md`.

### 2. Agent host - install and configure

```bash
sudo ./install.sh --agent
```

Add the scripts the agent is allowed to run to
`/etc/ctrl-exec-agent/scripts.conf`. `logger` exists on every platform and
needs no extra setup:

```ini
logger = /usr/bin/logger
```

Check the configuration is valid (this does not need pairing):

```bash
sudo ctrl-exec-agent self-check
```

> **Do not start the agent service yet.** It has no certificate until it is
> paired (step 3) and would exit immediately. You start it in step 4.

### 3. Pair the agent

On the **dispatcher host**, open pairing mode (it auto-stops after 10 minutes):

```bash
sudo ced pairing-mode
```

On the **agent host**, request pairing - replace `<dispatcher-host>` with the
dispatcher's hostname or IP **as reachable from the agent**:

```bash
sudo ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>
```

Both hosts display the same 6-digit code. Confirm they match, then type `a`
and Enter in the pairing-mode terminal to approve. The agent stores its signed
certificate and is ready.

### 4. Agent host - start the service

Now that the agent is paired:

```bash
sudo systemctl enable --now ctrl-exec-agent
```

### 5. Dispatcher host - verify

```bash
ced ping <agent-hostname>
ced run <agent-hostname> logger -- -t test "hello from ctrl-exec"
```

`ced list-agents` shows every paired agent and the address dispatch will use.

### Optional: API server

The API server exposes the same operations over HTTP on `localhost:7445`.
Install and start it on the dispatcher host:

```bash
sudo ./install.sh --api
sudo systemctl enable --now ctrl-exec-api
curl -s http://localhost:7445/health
```

Unlike the CLI, the API denies requests by default. To allow them on a trusted
network, set `api_auth_default = allow` in `/etc/ctrl-exec/ctrl-exec.conf`; to
restrict them, configure an auth hook instead. Either is read at startup, so
restart the service after changing it.


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
