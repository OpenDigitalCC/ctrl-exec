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

The installer checks all dependencies before making any changes and prints the correct install command if anything is missing.

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
/etc/ctrl-exec/                        dispatcher config and CA material
/etc/ctrl-exec-agent/                  Agent config and certificates
/opt/ctrl-exec-scripts/                Managed scripts (agent hosts)
/var/lib/ctrl-exec/                    Runtime state: registry, locks, runs
```

Shortcut symlinks installed in `/usr/local/bin`:

```
ced  →  ctrl-exec-dispatcher
cea  →  ctrl-exec-agent
```

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

The dispatcher and `ctrl-exec-agent` run as Alpine Linux containers. All persistent state is on named volumes; containers are stateless and can be rebuilt without losing pairing or configuration.

## Dispatcher container

First-start initialisation entrypoint:

```bash
#!/bin/sh
set -e
CONF_DIR=/etc/ctrl-exec
if [ ! -f "$CONF_DIR/ca.crt" ]; then
    ced setup-ca
    ced setup-ctrl-exec
fi
exec ctrl-exec-api
```

## Agent container

The agent uses a two-phase entrypoint: pair on first start, serve on subsequent starts. Set `DISPATCHER_HOST` to the hostname or address of the dispatcher container.

```bash
#!/bin/sh
set -e
CONF_DIR=/etc/ctrl-exec-agent
if [ -z "$DISPATCHER_HOST" ]; then
    echo "ERROR: DISPATCHER_HOST not set" >&2; exit 1
fi
if [ ! -f "$CONF_DIR/agent.crt" ]; then
    ctrl-exec-agent request-pairing --dispatcher "$DISPATCHER_HOST"
    echo "Pairing request sent. Approve on the dispatcher, then restart this container."
    exit 0
fi
exec ctrl-exec-agent serve
```

## docker-compose

```yaml
services:
  ctrl-exec:
    build: .
    restart: unless-stopped
    ports:
      - "7445:7445"
    volumes:
      - ctrl-exec-data:/etc/ctrl-exec
      - ctrl-exec-registry:/var/lib/ctrl-exec
    networks:
      - ctrl-exec-net

  agent:
    build:
      context: .
      dockerfile: docker/Dockerfile.agent
    restart: on-failure
    environment:
      DISPATCHER_HOST: ctrl-exec
    ports:
      - "7443:7443"
    volumes:
      - agent-data:/etc/ctrl-exec-agent
      - agent-scripts:/opt/ctrl-exec-scripts
    networks:
      - ctrl-exec-net

volumes:
  ctrl-exec-data:
  ctrl-exec-registry:
  agent-data:
  agent-scripts:

networks:
  ctrl-exec-net:
```

`DISPATCHER_HOST: ctrl-exec` uses Docker's internal DNS. No IP addresses required.

On first start, approve the agent's pairing request on the dispatcher container, then restart the agent container to begin serving.
