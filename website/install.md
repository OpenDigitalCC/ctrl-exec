---
title: Installation
subtitle: Full installation reference for ced and cea on all supported platforms.
updated: 2026-03-16
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/INSTALL.md
current_page: /install
---

# Dependencies

## Dispatcher host (`ced`)

Debian / Ubuntu:

```bash
sudo apt-get install libwww-perl libio-socket-ssl-perl libjson-perl openssl perl
```

Alpine:

```bash
sudo apk add perl-libwww perl-io-socket-ssl perl-json openssl perl
```

## Agent hosts (`cea`)

Debian / Ubuntu:

```bash
sudo apt-get install libio-socket-ssl-perl libjson-perl openssl perl
```

Alpine:

```bash
sudo apk add perl-io-socket-ssl perl-json openssl perl
```

## OpenWrt

```bash
opkg install perl perlbase-io perl-io-socket-ssl perl-json
```

The installer checks all dependencies before making any changes and prints the correct install command if anything is missing. (Debian/Ubuntu **packages** resolve these automatically — see the next section.)

# Installing from Packages

On Debian and Ubuntu, the `.deb` packages are the simplest route: `apt` resolves the runtime dependencies for you. Three packages are published per release:

- `ctrl-exec-common` — the shared Perl library, required on **every** host.
- `ctrl-exec-dispatcher` — the `ced` CLI and the `ctrl-exec-api` server, for the **dispatcher** host.
- `ctrl-exec-agent` — the `cea` service, for **each agent** host.

Download the release `.deb` files from the [releases page](https://github.com/OpenDigitalCC/ctrl-exec/releases), then install the shared library plus the role for that host:

```bash
# dispatcher host
sudo apt install ./ctrl-exec-common_*.deb ./ctrl-exec-dispatcher_*.deb

# agent host
sudo apt install ./ctrl-exec-common_*.deb ./ctrl-exec-agent_*.deb
```

Use `apt install ./<file>.deb`, not `dpkg -i`, so the Perl and OpenSSL dependencies are pulled in automatically. The packages seed example config into `/etc`, create the `ctrl-exec` group, and install the systemd units **without enabling or starting them** — you start the agent after pairing. The dispatcher package includes the API server, so no separate install is needed for it.

For Alpine, OpenWrt, or a source build, use the tarball installer below.

# Installing from Source

Clone the repository:

```bash
git clone https://github.com/OpenDigitalCC/ctrl-exec.git
cd ctrl-exec
```

Run the installer as root. Specify one or more roles:

```bash
sudo ./install.sh --dispatcher      # dispatcher host
sudo ./install.sh --agent          # agent host
sudo ./install.sh --api            # optional API server (dispatcher host)
```

Multiple roles can be combined:

```bash
sudo ./install.sh --dispatcher --api
```

The installer detects Debian/Ubuntu or Alpine automatically and installs to the paths below.

## Installed Paths

```
/usr/local/bin/ctrl-exec-dispatcher    ced binary
/usr/local/bin/ctrl-exec-agent         cea binary
/usr/local/bin/ctrl-exec-api           API server binary
/usr/local/lib/ctrl-exec/              Perl library modules
/etc/ctrl-exec-dispatcher/                        dispatcher config and CA material
/etc/ctrl-exec-agent/                  Agent config and certificates
/opt/ctrl-exec-scripts/                Managed scripts (agent hosts)
/var/lib/ctrl-exec/                    Runtime state: registry, locks, runs
```

Shortcut symlinks installed in `/usr/local/bin`:

```
ced  →  ctrl-exec-dispatcher
cea  →  ctrl-exec-agent
```

The above is the tarball layout. **Packages** install the binaries under `/usr/bin`, the library under `/usr/share/perl5/Exec`, and examples under `/usr/share/ctrl-exec/examples`; the `/etc`, `/var/lib`, and `/opt` paths are identical.

## Group Access

The installer creates a `ctrl-exec` system group. Add users who need CLI access:

```bash
sudo usermod -aG ctrl-exec $USER
newgrp ctrl-exec
```

# RPM-Based Systems

The installer supports Debian/Ubuntu and Alpine. For RHEL, Rocky, AlmaLinux, or Fedora, install dependencies manually:

```bash
sudo dnf install perl perl-libwww-perl perl-IO-Socket-SSL perl-JSON openssl
```

Then copy files according to the layout in `DEVELOPER.md`.

# Systemd Service Setup (Debian / Ubuntu)

The installer creates systemd unit files on systemd platforms.

## Agent service

```bash
sudo systemctl enable ctrl-exec-agent
sudo systemctl start ctrl-exec-agent
sudo systemctl status ctrl-exec-agent
```

Reload config and allowlist without downtime:

```bash
sudo systemctl kill --signal=HUP ctrl-exec-agent
```

View logs:

```bash
journalctl -u ctrl-exec-agent -f
```

## API server

```bash
sudo systemctl enable ctrl-exec-api
sudo systemctl start ctrl-exec-api
sudo systemctl status ctrl-exec-api
```

# OpenWrt / procd Service Setup

Install dependencies:

```bash
opkg install perl perlbase-io perl-io-socket-ssl perl-json
```

Run the installer:

```bash
sudo ./install.sh --agent
```

Manage the service:

```bash
/etc/init.d/ctrl-exec-agent enable
/etc/init.d/ctrl-exec-agent start
/etc/init.d/ctrl-exec-agent status
```

Reload config:

```bash
/etc/init.d/ctrl-exec-agent reload
```

View logs:

```bash
logread | grep ctrl-exec-agent | tail -20
```

::: textbox
OpenWrt is not affected by the `PrivateDevices`/`AF_UNIX` syslog constraint that applies to systemd units — procd does not implement `PrivateDevices`.
:::

# Docker

The dispatcher and `ctrl-exec-agent` run as Debian containers (`debian:trixie-slim`) built by installing the release `.deb` files. All persistent state is on bind mounts or named volumes; containers are stateless and can be rebuilt without losing pairing or configuration. The containers keep the packages' privilege split: a small root entrypoint does the work only root can do, then the service runs as an unprivileged user.

## Dispatcher container

The dispatcher entrypoint runs as root to fix mount ownership, create the CA on first start, and run certificate maintenance every four hours (the container's equivalent of the package's systemd timer). It then drops to the `ctrl-exec` user for the API with `setpriv`. In outline:

```bash
#!/bin/sh
set -eu
CONF_DIR=/etc/ctrl-exec-dispatcher
if [ ! -f "$CONF_DIR/ca.crt" ]; then
    ced setup-ca
    ced setup-ctrl-exec
fi
( sleep 300; while :; do ced maintain; sleep 14400; done ) &
exec setpriv --reuid=ctrl-exec --regid=ctrl-exec --init-groups /usr/bin/ctrl-exec-api
```

The complete entrypoint, Dockerfile and compose file are in the Docker deployment guide (`docs/DOCKER.md`). Two things in it are easy to miss:

- **Pin `dispatcher_id`.** It defaults to the hostname, which in a container is a random ID. Changing it after agents have paired invalidates every pairing, so set `DISPATCHER_ID` and `hostname:` in the compose file.
- **Pin the `ctrl-exec` UID in the image.** A fixed UID keeps bind-mount ownership predictable, including on hosts running Docker with `userns-remap`.

## Agent container

The agent uses a two-phase entrypoint: pair on first start, then serve as the unprivileged `ctrl-exec-agent` user. Set `DISPATCHER_HOST` to the hostname or address of the dispatcher container. The pairing request waits for approval on the dispatcher, 30 seconds by default.

```bash
#!/bin/sh
set -eu
CONF_DIR=/etc/ctrl-exec-agent
if [ -z "${DISPATCHER_HOST:-}" ]; then
    echo "ERROR: DISPATCHER_HOST not set" >&2; exit 1
fi
if [ ! -f "$CONF_DIR/agent.crt" ]; then
    ctrl-exec-agent request-pairing --dispatcher "$DISPATCHER_HOST"
fi
exec setpriv --reuid=ctrl-exec-agent --regid=ctrl-exec-agent --init-groups \
             ctrl-exec-agent serve
```

The privileged executor is a separate root service and is not part of the container, so per-script profiles are not enforced there. The guide gives the full entrypoint, which also turns `executor_socket` off in `agent.conf`.

## docker-compose

```yaml
services:
  dispatcher:
    build: ./dispatcher
    hostname: dispatcher
    restart: unless-stopped
    init: true
    read_only: true
    tmpfs: [/tmp, /run]
    cap_drop: [ALL]
    cap_add: [CHOWN, FOWNER, DAC_OVERRIDE, SETUID, SETGID]
    security_opt: [no-new-privileges:true]
    environment:
      DISPATCHER_ID: dispatcher
      API_BIND: 0.0.0.0
    ports:
      - "7445:7445"
    volumes:
      - ./dispatcher-data:/etc/ctrl-exec-dispatcher
      - ./dispatcher-registry:/var/lib/ctrl-exec
    networks:
      - ctrl-exec-net

  agent:
    build: ./agent
    hostname: agent
    restart: on-failure
    init: true
    read_only: true
    tmpfs: [/tmp, /run]
    cap_drop: [ALL]
    cap_add: [CHOWN, FOWNER, DAC_OVERRIDE, SETUID, SETGID]
    security_opt: [no-new-privileges:true]
    environment:
      DISPATCHER_HOST: dispatcher
    ports:
      - "7443:7443"
    volumes:
      - agent-data:/etc/ctrl-exec-agent
      - agent-state:/var/lib/ctrl-exec-agent
      - agent-scripts:/opt/ctrl-exec-scripts
    networks:
      - ctrl-exec-net

volumes:
  agent-data:
  agent-state:
  agent-scripts:

networks:
  ctrl-exec-net:
```

`DISPATCHER_HOST: dispatcher` uses Docker's internal DNS. No IP addresses required.

On first start, run `docker compose exec dispatcher ced pairing-mode`, start the agent container, and approve its pairing request on the dispatcher. The agent carries on to serving as soon as it is approved; no restart is needed.

## Upgrading a container to 0.13

The dispatcher's config directory is now `/etc/ctrl-exec-dispatcher` (it was `/etc/ctrl-exec`). A container image cannot migrate it for you: change the mount target in your compose file, edit the paths inside `ctrl-exec.conf` on the mount to match, and rebuild from the 0.13 packages. The old path stops working in 0.14. The deployment guide lists the steps.
