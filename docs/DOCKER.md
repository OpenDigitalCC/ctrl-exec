---
title: ctrl-exec - Docker Deployment
subtitle: Running dispatcher and agent containers from the release packages
brand: odcc
---


This document covers deploying the ctrl-exec dispatcher and agent as Docker
containers built from the release Debian packages. The application has no
awareness of containers - the differences from a bare-metal installation are
in how services are started, how configuration is persisted, how the
privilege split of the packages is kept, and how pairing is performed between
containers.

The examples need ctrl-exec 0.13.0 or later: they use the dispatcher
configuration directory `/etc/ctrl-exec-dispatcher` and the entrypoints call
`ced`. If you run a container from an earlier release, read *Upgrading an
existing container deployment* first.

For bare-metal or VM installation see `INSTALL.md`.

## Overview

dispatcher container
: Runs `ctrl-exec-api` in the foreground as the unprivileged `ctrl-exec` user.
  Exposes port 7445 (API) and optionally 7444 (pairing, only while pairing
  mode is active). The CA, registry, and dispatcher cert are stored on
  bind mounts or volumes so they persist across container restarts and image
  rebuilds. A small root-owned entrypoint does the work only root can do: it
  fixes ownership, creates the CA on first start, and renews certificates.

agent container
: Runs `ctrl-exec-agent serve` as the unprivileged `ctrl-exec-agent` user and
  the privileged executor, `ctrl-exec-executor`, as root beside it, so
  per-script profiles are enforced as on a host. Exposes port 7443. Agent
  cert, config, and state are stored on named volumes. The container pairs
  with the dispatcher on first start and then serves normally on subsequent
  starts.

Volumes hold all state. Containers are otherwise stateless and can be rebuilt
from the image without loss of pairing or configuration.

The dispatcher and agent each have their own build directory, Dockerfile, and
entrypoint script. Keeping them separate means either can be built and deployed
independently. Both can be run together using the full-stack `compose.yml`.

Both images are built on `debian:trixie-slim` by installing the release `.deb`
files. The package dependency lists live in the packages, not in the
Dockerfiles, and `install.sh` is not involved. The deb files come from the
[releases page](https://github.com/OpenDigitalCC/ctrl-exec/releases) or from
`./make-release.sh` in a source checkout. The deployment directory looks like
this:

```
compose.yml
dispatcher/                      build context for the dispatcher image
    Dockerfile
    entrypoint.sh
    ctrl-exec-common_<version>_all.deb
    ctrl-exec-dispatcher_<version>_all.deb
agent/                           build context for the agent image
    Dockerfile
    entrypoint.sh
    ctrl-exec-common_<version>_all.deb
    ctrl-exec-agent_<version>_<arch>.deb
dispatcher-data/                 bind mount, created at first start
dispatcher-registry/             bind mount, created at first start
```

Keep the bind-mount directories outside the build contexts, as above. Once the
container has chowned them they are not readable by the user running
`docker compose build`, and a build context that contains them fails.

The agent package is architecture-specific (it carries the C executor), so
download the one that matches the platform the image runs on.


## Container privilege model

The packages split privilege on purpose, and the container keeps the split
rather than replacing it.

- `ctrl-exec-api` runs as the unprivileged `ctrl-exec` service user. It owns
  `dispatcher.key` (mode 0600) so it can make mTLS connections to agents, and it
  is in the `ctrl-exec` group for the runtime directories. A flaw in this
  network-facing process is not a root compromise, and it cannot read the CA key.
- The CA key (`ca.key`) stays `root:root` mode 0600. `setup-ca`, `pairing-mode`,
  `approve`, `rotate-cert` and `maintain` are root operations because they sign
  with it.
- `/etc/ctrl-exec-dispatcher` is mode 750 `root:ctrl-exec`. The four state
  directories under `/var/lib/ctrl-exec` (`pairing`, `agents`, `locks`, `runs`)
  are mode 2770 `root:ctrl-exec`, so files created by the root CLI and by the
  API both belong to the `ctrl-exec` group.
- The shipped `ctrl-exec-api.service` adds `NoNewPrivileges`, `ProtectSystem=strict`,
  `PrivateTmp`, `PrivateDevices` and `ReadWritePaths=/var/lib/ctrl-exec`. The
  container flags below are the equivalents.

A container has no systemd, so the dispatcher entrypoint starts as root, does the
root-only work, and then drops to `ctrl-exec` for the API:

1. fix ownership and modes on the mounted directories
2. seed `ctrl-exec.conf`, and run `ced setup-ca` and `ced setup-ctrl-exec`, on
   first start only
3. start the certificate-maintenance loop as root in the background (see
   *Certificate maintenance*)
4. `exec setpriv --reuid=ctrl-exec --regid=ctrl-exec --init-groups /usr/bin/ctrl-exec-api`

The compose file starts the container with `cap_drop: [ALL]` and adds back only
what the entrypoint needs:

`CHOWN`, `FOWNER`, `DAC_OVERRIDE`
: Fix ownership and modes on the mounts, and read and write the root-owned
  files on them.

`SETUID`, `SETGID`
: Let `setpriv` change to the `ctrl-exec` user and group.

These are capabilities of the container's user namespace. Under `userns-remap`
(see *Host and container hardening*) they confer no privilege on the host. The
API process itself ends up with an empty capability set, and
`no-new-privileges` is compatible with `setpriv` because it only stops a process
gaining privilege, not giving it up.

Do not add `--bounding-set=-all` to the `setpriv` line. Changing the bounding
set needs `CAP_SETPCAP`, which the container does not have, and `setpriv` fails
with "apply bounding set: Operation not permitted". It is not needed: after the
change of user the API holds no capabilities, and `no-new-privileges` stops it
regaining any.

Pairing and approval run as root with `docker compose exec dispatcher ced ...`,
so the operator commands in *Pairing Workflow in Docker* are the same as on a
bare-metal host. The difference is that the API process is not root while they
run. See also the Trust Model section of `SECURITY.md`.

The agent container keeps the agent package's split the same way: the agent
runs as `ctrl-exec-agent` with no capabilities, and the executor runs as root
and applies each script's profile. The executor needs more than the five
capabilities above; see *Executor capabilities* under *Agent Container*.


## Dispatcher Container

### Dockerfile

`dispatcher/Dockerfile`, with the two dispatcher-side debs and `entrypoint.sh`
beside it:

```dockerfile
FROM debian:trixie-slim

# Fixed UID/GID so bind-mount ownership is the same number on every host. The
# package postinst skips creating the user when the account already exists.
ARG CE_UID=10001
RUN groupadd --system --gid ${CE_UID} ctrl-exec \
 && useradd  --system --uid ${CE_UID} --gid ctrl-exec \
             --no-create-home --shell /usr/sbin/nologin ctrl-exec

# rsyslog, rsyslog-gnutls and ca-certificates are for optional remote syslog
# forwarding; they are inert unless SYSLOG_HOST is set at runtime.
COPY ctrl-exec-common_*.deb ctrl-exec-dispatcher_*.deb /tmp/
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        /tmp/ctrl-exec-common_*.deb /tmp/ctrl-exec-dispatcher_*.deb \
        rsyslog rsyslog-gnutls ca-certificates \
 && rm -f /etc/ctrl-exec-dispatcher/ctrl-exec.conf \
          /etc/ctrl-exec-dispatcher/auth-hook \
 && rm -rf /var/lib/apt/lists/* /tmp/*.deb

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 7444 7445
ENTRYPOINT ["/entrypoint.sh"]
```

The `ctrl-exec` user and group are created with a fixed UID and GID (10001)
before the package is installed. The package postinst skips creating the
account when it exists. A fixed number makes bind-mount ownership the same on
every host, which matters under `userns-remap` (see *Volumes and layout*). Change
`CE_UID` if 10001 clashes with something on your hosts.

The postinst also seeds `ctrl-exec.conf` and an example `auth-hook` into
`/etc/ctrl-exec-dispatcher`. The packaged `ctrl-exec.conf` has `auth_hook`
commented out, so it is fail-closed, and the example hook (which authorises
every request) is inactive until named. The Dockerfile still removes both so
that neither can end up on a volume (a named volume is filled from the image on
first use) and take the place of the config the entrypoint writes. See
*Auth hook*.

`rsyslog`, `rsyslog-gnutls` and `ca-certificates` are for optional remote syslog
forwarding (see *Remote syslog forwarding*); they are inert unless `SYSLOG_HOST`
is set at runtime.

### Entrypoint script

`dispatcher/entrypoint.sh`:

```bash
#!/bin/sh
# Runs as root for the work only root can do: fixing mount ownership, seeding
# the config and CA on first start, and the certificate-maintenance loop.
# It then drops to the ctrl-exec user for the API, so the network-facing
# process never holds the CA key.
set -eu

CONF_DIR=/etc/ctrl-exec-dispatcher
CONF="$CONF_DIR/ctrl-exec.conf"
STATE_DIR=/var/lib/ctrl-exec
MAINT_INTERVAL="${MAINT_INTERVAL:-14400}"    # seconds; the deb timer's 4h

log() { echo "[entrypoint] $*"; }

# A volume still mounted at the pre-0.13 path would be ignored, and a second
# CA created beside it. Stop before seeding anything. ced and ctrl-exec-api
# refuse the same thing themselves (exit 78); this check just stops early.
if [ -d /etc/ctrl-exec ] && [ ! -L /etc/ctrl-exec ]; then
    log "ERROR: /etc/ctrl-exec exists; mount the config at $CONF_DIR instead." >&2
    exit 78
fi

fix_perms() {
    chown root:ctrl-exec "$CONF_DIR" && chmod 750 "$CONF_DIR"
    for d in pairing agents locks runs; do
        mkdir -p "$STATE_DIR/$d"
        chown root:ctrl-exec "$STATE_DIR/$d" && chmod 2770 "$STATE_DIR/$d"
    done
}

# Seed ctrl-exec.conf from the environment on first start only. An existing
# file on the volume is never overwritten.
write_config() {
    [ -f "$CONF" ] && return 0
    log "seeding $CONF from the environment"
    cat > "$CONF" << EOC
# Seeded by the entrypoint on first start. Edit on the volume, then restart.
cert = $CONF_DIR/dispatcher.crt
key  = $CONF_DIR/dispatcher.key
ca   = $CONF_DIR/ca.crt

dispatcher_id    = ${DISPATCHER_ID:-dispatcher}
api_bind         = ${API_BIND:-127.0.0.1}
api_port         = ${API_PORT:-7445}
api_auth_default = ${API_AUTH_DEFAULT:-deny}
EOC
    [ -n "${READ_TIMEOUT:-}" ] && echo "read_timeout = $READ_TIMEOUT" >> "$CONF"
    # Reference the hook only if one is already present; see "Auth hook".
    [ -f "$CONF_DIR/auth-hook" ] && echo "auth_hook = $CONF_DIR/auth-hook" >> "$CONF"
    chown root:ctrl-exec "$CONF" && chmod 640 "$CONF"
}

init_ca() {
    [ -f "$CONF_DIR/ca.crt" ] && return 0
    log "first start: creating the CA and the dispatcher certificate"
    ced setup-ca
    ced setup-ctrl-exec
}

# The equivalent of the deb's ctrl-exec-maintenance.timer (OnBootSec=5min,
# OnUnitActiveSec=4h). Root only: renewal signs with the CA key.
maintenance_loop() {
    sleep 300
    while :; do
        ced maintain || log "maintain failed (exit $?)"
        sleep "$MAINT_INTERVAL"
    done
}

# Optional: forward the API's syslog to a remote TLS collector.
start_rsyslog() {
    [ -n "${SYSLOG_HOST:-}" ] || return 0
    SYSLOG_PORT="${SYSLOG_PORT:-6514}"
    log "forwarding daemon.* to $SYSLOG_HOST:$SYSLOG_PORT"
    cat > /run/rsyslog.conf << EOC
global(
    defaultNetstreamDriver="gtls"
    defaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
)
module(load="imuxsock")
daemon.* action(
    type="omfwd"
    target="$SYSLOG_HOST"
    port="$SYSLOG_PORT"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="$SYSLOG_HOST"
    template="RSYSLOG_SyslogProtocol23Format"
)
EOC
    # Background, before the drop, so /dev/log exists when the API opens syslog.
    rsyslogd -f /run/rsyslog.conf -i /run/rsyslogd.pid
}

fix_perms
write_config
init_ca
maintenance_loop &
start_rsyslog

# Copy the example hook for reference. It authorises everything, so it is
# never installed as the active hook.
if [ ! -f "$CONF_DIR/auth-hook.example" ]; then
    cp /usr/share/ctrl-exec/examples/auth-hook.example "$CONF_DIR/auth-hook.example"
fi

log "starting ctrl-exec-api as ctrl-exec"
exec setpriv --reuid=ctrl-exec --regid=ctrl-exec --init-groups \
             /usr/bin/ctrl-exec-api
```

Run the container with `init: true` (or `docker run --init`). The entrypoint
`exec`s the API, so the API replaces the shell, but the maintenance loop and
`rsyslogd` are other processes in the container, and Docker's init process reaps
them and passes `SIGTERM` on at shutdown.

Each first-start block is guarded: restarts are safe and any file already
present on the volume is never overwritten. Config generated on first start
persists on the data mount and is reused on subsequent starts.

The entrypoint stops with an error if `/etc/ctrl-exec` exists as a real
directory, which is what a mount left at the pre-0.13 path looks like (see
*Upgrading an existing container deployment*). The check is belt and braces:
`ced` and `ctrl-exec-api` refuse to run in that state anyway (exit 78), but the
entrypoint stops before it seeds a config or creates a CA.


## Dispatcher Configuration

The dispatcher is configured through environment variables in `compose.yml`.
On first start, the entrypoint generates `ctrl-exec.conf` from these values
and writes it to the data mount. On subsequent starts the existing config file
is used unchanged, so editing the compose file later has no effect on a setting
that is already in the file.

To reconfigure, either edit `ctrl-exec.conf` directly on the mount (it is
`./dispatcher-data/ctrl-exec.conf` in the layout above) and restart, or remove
it and let the entrypoint regenerate it from updated env vars on the next start.

`DISPATCHER_ID`
: The dispatcher's stable identity, written to `dispatcher_id` in
  `ctrl-exec.conf`. Default: `dispatcher`. See the warning below.

`API_BIND`
: Network address the API server binds to. Default: `127.0.0.1` (localhost
  only, not reachable from outside the container). Set to `0.0.0.0` to
  accept connections on all interfaces - required when accessing the API
  from the host, from other containers, or from external clients. The API is
  plain HTTP unless `api_cert` and `api_key` are set in `ctrl-exec.conf`, so
  publish its port only on a network you trust.

  ```yaml
  API_BIND: 0.0.0.0
  ```

`API_PORT`
: Port the API server listens on. Default: `7445`.

`API_AUTH_DEFAULT`
: What the API does with a request when **no `auth_hook` is configured**:
  `deny` rejects every request (default, recommended), `allow` permits every
  request (suitable for isolated networks or initial testing). When an
  `auth_hook` is configured this setting has no effect - the hook alone decides.
  See *Auth hook*.

  ```yaml
  API_AUTH_DEFAULT: allow
  ```

`READ_TIMEOUT`
: Maximum seconds to wait for a script to complete. Omit to use the
  dispatcher default (60 seconds).

  ```yaml
  READ_TIMEOUT: 120
  ```

`MAINT_INTERVAL`
: Seconds between certificate-maintenance runs. Default: `14400` (four hours),
  the same as the deb's timer. Read by the entrypoint at every start; it is
  not stored in `ctrl-exec.conf`. See *Certificate maintenance*.

`SYSLOG_HOST`
: Hostname of a remote TLS syslog collector. When set, the entrypoint starts
  rsyslog inside the container and forwards the dispatcher's logs to it (see
  *Remote syslog forwarding* below). Unset by default - the container logs
  only locally and rsyslog is not started.

  ```yaml
  SYSLOG_HOST: logs.example.com
  ```

`SYSLOG_PORT`
: Port of the remote syslog collector. Default: `6514` (the syslog-over-TLS
  port). Only used when `SYSLOG_HOST` is set.

  ```yaml
  SYSLOG_PORT: 6514
  ```

### dispatcher_id

Pin `dispatcher_id`, and do not change it after agents have paired. Every
agent records the dispatcher's identity at pairing, and a different value
invalidates all of those pairings - each agent must be paired again.

If `dispatcher_id` is not set in `ctrl-exec.conf`, ctrl-exec uses the host's
name. A container's hostname is its random container ID unless it is pinned, so
a compose file that sets neither would give the dispatcher a new identity every
time the container is recreated (`up --force-recreate`, or any image change).

The sample compose therefore sets both:

```yaml
hostname: dispatcher
environment:
  DISPATCHER_ID: dispatcher   # changing after pairing invalidates all pairings
```

The entrypoint writes `DISPATCHER_ID` into the seeded `ctrl-exec.conf`, so the
value is kept on the data mount and survives the compose file being edited
later. Use letters, digits, `.`, `-` and `_`, up to 64 characters, starting with
a letter or digit.

### Certificate maintenance

On a bare-metal host the `ctrl-exec-dispatcher` package installs a root systemd
timer, `ctrl-exec-maintenance.timer`, that runs `ced maintain` five minutes after
boot and every four hours after that. `maintain` pings every registered agent
(which triggers a renewal when an agent certificate is past half-life), rotates
and broadcasts the dispatcher's own certificate when it nears expiry, expires
agents long out of contact, and purges old run records.

A container has no timer, so the entrypoint runs the same command in a loop: a
five-minute initial delay, then every `MAINT_INTERVAL` seconds. `ced maintain`
signs with the CA key, so it is a root operation. That is why the loop belongs in
the root entrypoint and cannot be delegated to a scheduler container, a cron job
elsewhere, or anything else that only has API access: the API user cannot read
the CA key, by design, and there is no API call that renews certificates.

A failed pass is logged and the loop carries on. `maintain` runs every phase even
if one fails, so to see the result of a pass run it by hand:

```bash
docker compose exec dispatcher ced maintain
```

### Remote syslog forwarding

`ctrl-exec-api` logs via `Sys::Syslog` to the local syslog socket, `/dev/log`.
In a container with no syslog daemon those messages go nowhere. There are two
ways to collect them.

Share the host's socket
: Mount the host's `/dev/log` into the container
  (`- /dev/log:/dev/log` under `volumes`). The dispatcher's messages then go to
  whatever syslog or journal service the host runs, with no syslog software in
  the image. This is the simplest option when the host collects logs.

Forward from inside the container
: Setting `SYSLOG_HOST` makes the entrypoint run `rsyslog` inside the container to
  receive the local syslog and forward it to a remote collector over TLS. This
  works with `read_only: true` and the capability set above: the entrypoint
  writes the rsyslog config to `/run` (a tmpfs), `rsyslogd` creates `/dev/log` in
  the container's own `/dev`, and that socket is world-writable, so the API user
  can log to it after the drop to `ctrl-exec`.

How the in-container forwarder works:

- The entrypoint generates `/run/rsyslog.conf` from `SYSLOG_HOST` and
  `SYSLOG_PORT` on start, then launches `rsyslogd` in the background before the
  `exec` of `ctrl-exec-api`, so `/dev/log` exists when the API opens syslog.
- dispatcher logs on the **`daemon`** facility (`daemon.info`,
  `daemon.warning`, `daemon.err` - see `LOGGING.md`), so the forwarder
  selects `daemon.*`. Operations, security events, and `reqid` correlation
  fields all carry through unchanged in the structured `ACTION=...` lines.
- Transport is TCP with the GnuTLS netstream driver (`StreamDriverMode="1"`).
  The collector is expected to be server-authenticated only (rsyslog `anon`
  on the collector side); a certificate from a public CA validates against the
  system CA bundle (`ca-certificates`), so no custom CA or client certificate
  is required. `StreamDriverAuthMode="x509/name"` with the collector hostname
  as the permitted peer ensures the dispatcher only forwards to the genuine
  collector.

When `SYSLOG_HOST` is unset the block is skipped entirely: rsyslog is not
started and the container logs only locally.

```yaml
services:
  dispatcher:
    environment:
      SYSLOG_HOST: logs.example.com
      SYSLOG_PORT: 6514
```

#### Why in-container rsyslog rather than a direct connection

`Sys::Syslog` can connect directly to a remote server over TCP or UDP via
`setlogsock`, which would avoid running rsyslog at all. It is not used here
because it has **no native TLS**: a direct connection would send logs - which
include usernames, source IPs, script names, and arguments - in plaintext.

Running rsyslog inside the container also buys properties a direct
application connection would not have:

- TLS (the GnuTLS `gtls` driver) with server-certificate validation against
  the system CA bundle.
- A place to configure queueing, so logs can survive a briefly unreachable
  collector instead of being dropped by the application. The generated config
  uses rsyslog's defaults; add an action queue to it if you need more.
- Standard syslog framing (`RSYSLOG_SyslogProtocol23Format`) without the
  application needing to know anything about the transport.

If a TLS-capable direct path without rsyslog is wanted later, the usual
approach is `stunnel`: point `Sys::Syslog` at a local plaintext endpoint that
stunnel wraps in TLS to the collector. That trades one auxiliary process
(rsyslog) for another (stunnel) and loses the queueing, so rsyslog is
preferred unless a deployment specifically cannot run it. No code change is
needed for the stunnel path - it is purely a container/runtime arrangement.

### Auth hook

The auth hook controls who is permitted to run scripts and ping agents.

The setting `api_auth_default` applies **only when no `auth_hook` is configured**.
Once `ctrl-exec.conf` names a hook, the hook decides every request and
`api_auth_default` is ignored. The consequence to be careful of: the example
hook (`auth-hook.example`) ends with `exit 0`, so it authorises everything.
Naming it as `auth_hook` makes `api_auth_default` irrelevant: do not rely on
`deny` as a safety net with the example hook in place. The bare-metal package
seeds the example hook but leaves `auth_hook` commented out in `ctrl-exec.conf`,
so a fresh install denies API requests until the operator writes a hook and
enables it.

The container follows the same rule. The Dockerfile removes the packaged
config and hook, and the entrypoint writes `auth_hook` into `ctrl-exec.conf` only
if a hook file is already present on the data mount at first start. With no
hook, `api_auth_default` governs, and the default is `deny`: the API refuses
every request until you install a real hook.

On first start the entrypoint also copies the example hook to
`auth-hook.example` on the data mount, for reference. It is never the active hook.

Because `/etc/ctrl-exec-dispatcher` is itself the data mount, the hook lives on
it: put your hook at `./dispatcher-data/auth-hook`. No separate file mount is
needed. The API runs the hook as the `ctrl-exec` user, so it must be executable
by that user - mode 755, or 750 with group `ctrl-exec`.

The entrypoint adds `auth_hook =` to `ctrl-exec.conf` only if the hook is present
at **first start**. If you add the hook later, the config does not mention it
and `api_auth_default` carries on governing, so the hook is silently not used.
Add the line to `ctrl-exec.conf` by hand and restart:

```
auth_hook = /etc/ctrl-exec-dispatcher/auth-hook
```

For an unattended first start, create `./dispatcher-data/` and place the hook in
it before running `docker compose up` for the first time. (The ownership
settings in *Volumes and layout* apply to the directory either way; the
entrypoint fixes the directory, not the hook's contents.)

See `INSTALL.md` for the full auth hook interface and examples.


## Volumes and layout

The recommended layout keeps everything the deployment needs in one directory:
the compose file, the build contexts, and two bind mounts beside them.

```yaml
    volumes:
      - ./dispatcher-data:/etc/ctrl-exec-dispatcher       # config, CA, certs, auth-hook
      - ./dispatcher-registry:/var/lib/ctrl-exec          # paired-agent registry, runs, locks
```

The deployment is then a directory that can be backed up, or moved between
hosts, as one unit. The CA key is in `dispatcher-data`; treat the directory
accordingly (see *Encrypted Credentials*).

Named volumes work as well. Declare `dispatcher-data` and `dispatcher-registry`
under `volumes:` and mount them at the same two paths. Docker copies the image's
content into an empty named volume on first use and keeps the image's ownership,
which is why the Dockerfile removes the packaged config. The cost is that the
state is out of sight under Docker's own directory, and moving it between hosts
needs a copy step.

### Ownership

The entrypoint sets ownership and modes on the mounts at every start
(`root:ctrl-exec`, 750 on the config directory, 2770 on the four state
directories). On a plain Docker daemon that needs nothing from you.

On a daemon running `userns-remap`, container root is an unprivileged UID on the
host, so a bind-mounted directory must be owned by the *mapped* IDs before the
first start, or the entrypoint's `chown` is refused. Container UID `n` maps to
host UID `base + n`, where `base` is the first number in the remap user's line
in `/etc/subuid`. With the fixed `ctrl-exec` UID and GID of 10001 and a base of
100000, set once:

```bash
sudo chown 100000:110001 dispatcher-data dispatcher-registry
```

That is container `root:ctrl-exec`, and it is the reason the image fixes the
UID: a number assigned at build time by the package would differ between builds.
Named volumes are created with the right mapping by Docker and need nothing.

The agent uses named volumes in the sample compose. The agent's service user has
no fixed UID, which is the reason: a named volume carries the image's ownership
with it.


## Host and container hardening

For operators running the dispatcher on a shared Docker host. The sample
`compose.yml` applies the container flags; the daemon-level items are host
configuration.

`userns-remap`
: Recommended. Container root maps to an unprivileged host UID, so the namespaced
  capabilities in *Container privilege model* confer nothing on the host. Bind
  mounts must be owned by the mapped IDs (see *Ownership*).

Networking
: Use bridge networking. `network_mode: host` is refused by a daemon running
  `userns-remap` and is never needed: agents on other hosts connect to the
  dispatcher's published API port, and the dispatcher connects out to each agent
  on 7443. Publish 7444 only while pairing.

Container flags
: `read_only: true` with `tmpfs` on `/tmp` and `/run`; `cap_drop: [ALL]` with the
  five capabilities back; `security_opt: [no-new-privileges:true]`; and a limit
  on process count, memory and CPU (`pids_limit`, `mem_limit`, `cpus`). The
  numbers in the sample suit a small fleet - set your own. `init: true` goes with
  these flags, as described under the entrypoint. The agent container adds
  `SETPCAP` and `SYS_ADMIN` and `apparmor=unconfined` for the executor; see
  *Executor capabilities*.

Rootless Docker
: Not recommended. The settings above give the same practical isolation without
  the per-user systemd, lingering and `slirp4netns` machinery that rootless
  mode needs, which has proved fragile for a service that must stay up.

Anyone with access to the Docker socket on the dispatcher host can read the CA key
from the mount; see *Docker-Specific Security* in
`SECURITY-OPERATIONS.md`.


## compose.yml

The full stack - dispatcher and one agent - with the hardening above:

```yaml
# Hardening shared by both services. See "Host and container hardening".
x-hardened: &hardened
  restart: unless-stopped
  init: true
  read_only: true
  tmpfs: [/tmp, /run]
  cap_drop: [ALL]
  cap_add: [CHOWN, FOWNER, DAC_OVERRIDE, SETUID, SETGID]
  security_opt: [no-new-privileges:true]
  pids_limit: 200
  mem_limit: 256m
  cpus: "1.0"

# The agent container also runs the privileged executor, which needs three
# more settings. See "Executor capabilities".
x-hardened-agent: &hardened-agent
  <<: *hardened
  cap_add: [CHOWN, FOWNER, DAC_OVERRIDE, SETUID, SETGID, SETPCAP, SYS_ADMIN]
  security_opt: [no-new-privileges:true, apparmor=unconfined]

services:
  dispatcher:
    <<: *hardened
    build: ./dispatcher
    image: ctrl-exec-dispatcher:local
    hostname: dispatcher             # pin: see "dispatcher_id"
    environment:
      DISPATCHER_ID: dispatcher      # changing this after pairing invalidates all pairings
      API_BIND: 0.0.0.0
      API_AUTH_DEFAULT: deny
      # MAINT_INTERVAL: 14400
      # SYSLOG_HOST: logs.example.com
    ports:
      - "7445:7445"                  # API
      # - "7444:7444"                # pairing - publish only while pairing
    volumes:
      - ./dispatcher-data:/etc/ctrl-exec-dispatcher
      - ./dispatcher-registry:/var/lib/ctrl-exec
    networks: [ctrl-exec-net]

  agent:
    <<: *hardened-agent
    build: ./agent
    image: ctrl-exec-agent:local
    hostname: agent
    restart: on-failure
    environment:
      DISPATCHER_HOST: dispatcher    # Docker DNS resolves the service name
      # SYSLOG_HOST: logs.example.com
    ports:
      - "7443:7443"
    volumes:
      - agent-data:/etc/ctrl-exec-agent
      - agent-state:/var/lib/ctrl-exec-agent
      - agent-scripts:/opt/ctrl-exec-scripts
    networks: [ctrl-exec-net]

volumes:
  agent-data:
  agent-state:
  agent-scripts:

networks:
  ctrl-exec-net:
```

To run the dispatcher alone, delete the `agent` service and the three agent
volumes. To run an agent alone against a dispatcher elsewhere, delete the
`dispatcher` service and set `DISPATCHER_HOST` to the dispatcher's hostname or
address. The extension fields `x-hardened` and `x-hardened-agent` and the YAML
merge (`<<: *hardened`) are plain compose features; copy the settings inline if
you prefer. A merge replaces a list rather than adding to it, which is why
`x-hardened-agent` repeats the whole `cap_add` and `security_opt` lists.

Port 7444 is the pairing port. If agents are on the same Docker network and
pairing is done container-to-container, 7444 does not need to be published to
the host. Publish it only while pairing agents on external hosts, which means
editing the compose file and running `docker compose up -d dispatcher` to
recreate the container. Nothing is lost by that: the identity is pinned and the
state is on the mounts.

`DISPATCHER_HOST: dispatcher` uses Docker's internal DNS to resolve the
dispatcher service by name. No IP addresses required.

The scheduler that calls the API, `run-jobs`, is a separate container. It is
documented, with its own hardened compose service, in the `ctrl-exec-plugins`
repository, under `ce-api-plugins/ctrl-exec-cli/run-jobs`. It needs only API
access and holds no CA key; follow *Host and container hardening* above for the
flags it shares with the dispatcher.


## Agent Container

A containerised agent is useful for testing and proof-of-concept work.
In production, agents typically run directly on the VM or host they manage -
either installed from the packages (or `install.sh --agent`) on bare metal, or
added to an existing container that already runs the workload the agent needs to
reach. A standalone agent container makes most sense when the agent's scripts
make calls to other services in the same Docker network.

### Dockerfile

`agent/Dockerfile`, with the common and agent debs and `entrypoint.sh` beside it:

```dockerfile
FROM debian:trixie-slim

# The agent package is architecture-specific (it carries the C executor), so
# use the .deb that matches the image platform.
COPY ctrl-exec-common_*.deb ctrl-exec-agent_*.deb /tmp/
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        /tmp/ctrl-exec-common_*.deb /tmp/ctrl-exec-agent_*.deb \
        rsyslog rsyslog-gnutls ca-certificates \
 && rm -rf /var/lib/apt/lists/* /tmp/*.deb

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 7443
ENTRYPOINT ["/entrypoint.sh"]
```

The agent needs no fixed UID: nothing of the agent's is bind-mounted, and its state lives
on named volumes.

The Dockerfile and the entrypoint below are also in the source tree, under
`tools/agent-container/`, with the container test that exercises them
(`tools/agent-container/test.sh`).

### Entrypoint script

`agent/entrypoint.sh`:

```bash
#!/bin/bash
# Runs as root: pairs on first start (the certificates are written into a
# root-owned directory), starts the privileged executor as root, and runs the
# agent as the unprivileged ctrl-exec-agent user. It then stays as a small
# supervisor: a HUP is passed to the agent as a reload, a stop reaches both,
# and if either daemon exits the container exits.
set -eu

CONF_DIR=/etc/ctrl-exec-agent
CONF="$CONF_DIR/agent.conf"
RUN_DIR=/run/ctrl-exec-agent
SOCK="$RUN_DIR/exec.sock"
AGENT_USER=ctrl-exec-agent

log() { echo "[entrypoint] $*"; }

# DISPATCHER_HOST must be set in the container environment or compose file.
if [ -z "${DISPATCHER_HOST:-}" ]; then
    log "ERROR: DISPATCHER_HOST environment variable not set." >&2
    exit 1
fi

# First start: no cert means we have not paired yet. request-pairing blocks
# until the operator approves on the dispatcher (30 seconds by default), stores
# the certificates, and returns; a denial or timeout exits non-zero, and the
# restart policy then sends a fresh request.
if [ ! -f "$CONF_DIR/agent.crt" ]; then
    log "No cert found - requesting pairing with $DISPATCHER_HOST..."
    ctrl-exec-agent request-pairing --dispatcher "$DISPATCHER_HOST"
    log "Paired."
fi

# Optional: forward the agent's syslog to a remote TLS collector.
if [ -n "${SYSLOG_HOST:-}" ]; then
    SYSLOG_PORT="${SYSLOG_PORT:-6514}"
    log "forwarding daemon.* to $SYSLOG_HOST:$SYSLOG_PORT"
    cat > /run/rsyslog.conf << EOC
global(
    defaultNetstreamDriver="gtls"
    defaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
)
module(load="imuxsock")
daemon.* action(
    type="omfwd"
    target="$SYSLOG_HOST"
    port="$SYSLOG_PORT"
    protocol="tcp"
    StreamDriver="gtls"
    StreamDriverMode="1"
    StreamDriverAuthMode="x509/name"
    StreamDriverPermittedPeers="$SYSLOG_HOST"
    template="RSYSLOG_SyslogProtocol23Format"
)
EOC
    rsyslogd -f /run/rsyslog.conf -i /run/rsyslogd.pid
fi

# The privileged executor, as root, with the arguments of the package's
# ctrl-exec-executor.service. It makes the socket, owned by the agent user and
# mode 0600; the agent hands it every run.
mkdir -p "$RUN_DIR"
chmod 755 "$RUN_DIR"
log "Starting ctrl-exec-executor as root"
ctrl-exec-executor serve "$SOCK" "$CONF" "$CONF_DIR/scripts.conf" "$AGENT_USER" &
executor_pid=$!
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$SOCK" ]; then
    log "ERROR: ctrl-exec-executor did not create $SOCK." >&2
    exit 1
fi

# Adopt a renewed certificate staged while the agent was running (the deb's
# unit does this as ExecStartPre), then serve as the unprivileged user.
ctrl-exec-agent promote-cert || true
log "Starting ctrl-exec-agent serve as $AGENT_USER"
setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups \
        ctrl-exec-agent serve &
agent_pid=$!

# Signal the agent as its own user. Root here holds no CAP_KILL, and without it
# may not signal a process of another user; a process of the same user may.
signal_agent() {
    setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --clear-groups \
            sh -c 'kill -s "$1" "$2"' sh "$1" "$agent_pid" || true
}
stopping=
trap 'log "HUP: reloading the agent"; signal_agent HUP' HUP
trap 'stopping=1; signal_agent TERM; kill -TERM "$executor_pid" 2>/dev/null || true' TERM INT

# Wait for either daemon to exit. A trapped signal interrupts the wait; carry
# on while both are still running.
set +e
while :; do
    wait -n "$executor_pid" "$agent_pid"
    rc=$?
    [ -d "/proc/$agent_pid" ] && [ -d "/proc/$executor_pid" ] && continue
    break
done
if [ -z "$stopping" ]; then
    if [ -d "/proc/$agent_pid" ]; then
        log "ctrl-exec-executor exited ($rc); stopping the agent" >&2
        signal_agent TERM
    else
        log "ctrl-exec-agent exited ($rc); stopping the executor" >&2
        kill -TERM "$executor_pid" 2>/dev/null
    fi
fi
wait
[ -n "$stopping" ] && exit 0
exit "$rc"
```

The entrypoint does the work of the package's two systemd units, and stays
running as a small supervisor:

1. On first start (no `agent.crt`), it pairs as root, because the certificates
   are written into a root-owned directory. `request-pairing` blocks until the
   operator approves on the dispatcher, 30 seconds by default. If that time
   passes, or the request is denied, it exits non-zero and the restart policy
   (`on-failure`) starts the container again with a fresh request, so start
   `pairing-mode` first and approve promptly.
2. It starts `ctrl-exec-executor` as root, with the arguments of the package's
   `ctrl-exec-executor.service`. The executor makes its socket, owned by
   `ctrl-exec-agent` and mode 0600, and accepts connections only from that
   user.
3. It starts `ctrl-exec-agent serve` as `ctrl-exec-agent` with `setpriv`. The
   packaged `agent.conf` sets `executor_socket`, so the agent hands every run to
   the executor, which applies the script's profile.
4. It waits. A `HUP` is passed on to the agent as a reload (see *Reloading the
   agent*), `TERM` stops both daemons, and if either daemon exits the other is
   stopped and the container exits with that status, so the restart policy
   applies.

For automated or orchestrated deployments, `--background` mode can be used
instead. This prints the `reqid` to stdout and exits immediately, leaving a
background process to wait for approval (`--timeout`, up to 600 seconds):

```bash
ctrl-exec-agent request-pairing --dispatcher "$DISPATCHER_HOST" --background
```

The `reqid` can be captured by the orchestration layer and passed to
`ced approve <reqid>` on the dispatcher. See REFERENCE.md
`### Orchestrated pairing` for the full flow.

### Executor capabilities

The executor applies a profile to each run by creating a mount namespace for
it (the agent's control and state directories read-only; with `writable`, the
whole filesystem read-only except the listed paths), dropping the capability
bounding set to the profile's `caps`, and changing to the profile's `run_as`
user. Inside a container it can only do that with the capabilities and
security profile the container gives it. Docker's defaults are not enough: they
leave out `CAP_SYS_ADMIN`, and AppArmor's `docker-default` profile refuses
`mount`. So every agent container needs `cap_add: [SYS_ADMIN]` and
`security_opt: [apparmor=unconfined]` on a host that uses AppArmor. The sample
compose drops all capabilities and adds back the full list.

Measured on Docker with the default seccomp profile, the executor as root in
the container:

| Container setting | What the executor uses it for | Without it |
| --- | --- | --- |
| `SYS_ADMIN` | the per-run mount namespace, for every run; `writable` | every run fails: `cannot create the action's mount namespace` |
| `apparmor=unconfined` (AppArmor hosts) | the same, `mount` | every run fails: `cannot set up the action's mount namespace` |
| `SETPCAP` | dropping the bounding set, for every run | every run fails: `cannot drop CAP_... from the capability bounding set` |
| `SETUID` | `run_as` a non-root user; `setpriv` for the agent | those runs fail: `setuid: Operation not permitted`; the agent does not start |
| `SETGID` | every profile with `run_as`, `run_as = root` included | those runs fail: `setgroups: Operation not permitted`; the agent does not start |
| `CHOWN` | handing the socket to the agent user; `input=fields` files | every run fails: the agent reports permission denied on the socket |
| `FOWNER` | setting the socket's mode to 0600 | runs work, the socket keeps its default mode (only its owner can connect, and the executor checks the peer's user); `chmod: Operation not permitted` in the log |
| `DAC_OVERRIDE` | removing an `input=fields` run's directory afterwards | runs work, but the directory holding the run's input is left in `/run`; `could not remove input directory` in the log |
| each capability a profile lists in `caps` | giving it to the script | that profile's runs fail: `profile '<name>' keeps CAP_..., which the executor does not hold` |

What a container enforces, with the settings above:

- `run_as`, `caps`, `writable`, the read-only control and state directories,
  and `input=fields` work as on a host.
- A capability in a profile's `caps` must also be in the container's `cap_add`.
  The sample adds none beyond the executor's own, so add, for example, `KILL`
  for a profile with `caps = CAP_KILL`. A profile whose capability the container
  does not have fails every run, naming the capability; it never runs with less.
- `no_new_privileges = no` is not available: `no-new-privileges:true` on the
  container sets it for every process in it, the executor's actions included.
  A script that needs a setuid program such as `sudo` cannot run in the sample
  container. Remove `no-new-privileges:true` from the agent's `security_opt` if
  you need that; the executor still drops the bounding set to the profile's
  `caps`, so a root action regains nothing at exec.

None of these failures runs the script with less confinement than its profile
states: the executor stops before the script starts, exit status 126, and the
reason is in the run's error output.

Who holds the added capabilities: the executor, and the entrypoint's shell
(both root, neither on the network). The agent drops to `ctrl-exec-agent` with
an empty capability set, and a script holds only the capabilities its profile
lists. `CAP_SYS_ADMIN` and an unconfined AppArmor profile still widen what root
in the container can do, so run the agent container under `userns-remap` (see
*Host and container hardening*), where container root is an unprivileged user
on the host.

Asynchronous runs (`--async`) are not available while `executor_socket` is set,
on a host or in a container: the executor does not handle detached jobs.

### Agent state

The agent keeps three things that must survive the container being recreated:

`/etc/ctrl-exec-agent` (`agent-data`)
: Config, allowlist, and the agent certificate and key.

`/var/lib/ctrl-exec-agent` (`agent-state`)
: The trusted-dispatcher map, written at pairing, and the store for asynchronous
  results. If this is lost the agent no longer trusts its dispatcher and must be
  paired again, even though the certificate survived.

`/opt/ctrl-exec-scripts` (`agent-scripts`)
: The scripts the allowlist names.

### Remote syslog forwarding

The agent forwards logs the same way as the dispatcher: set `SYSLOG_HOST`
(and optionally `SYSLOG_PORT`, default `6514`) and the entrypoint runs rsyslog
to forward the agent's `daemon.*` syslog to the collector over TLS, skipping
the block entirely when unset. The host-socket option (`- /dev/log:/dev/log`)
works for the agent too. See *Remote syslog forwarding* under the dispatcher
above for how it works and the TLS/CA expectations.


## Networking

Container-to-container communication works reliably in two configurations:

- **Shared network** - both containers on the same Docker network. Use Docker DNS (service name) or container IP directly. This is the recommended approach for full-stack compose deployments.
- **Different hosts** - dispatcher and agent on separate machines, each with ports published to the host. The agent connects to the dispatcher's host IP and published port. This is the intended production pattern.

Same-host, different networks (container to host to container) is not reliable with default Docker networking. Docker's NAT and iptables rules do not consistently route traffic from one bridge network to a published port on another. If the dispatcher and agent must run on the same host in separate compose projects, either connect them to a shared network explicitly:

```bash
docker network connect <dispatcher-network> <agent-container>
```

Or set `DISPATCHER_HOST` to the dispatcher container's IP on the shared network rather than the host IP.

This limitation does not affect real deployments where the dispatcher and agents run on separate hosts.

The dispatcher connects out to each agent's port 7443, so every agent must be
reachable from the dispatcher container. The source address the dispatcher sees at
pairing is unreliable when Docker's NAT is in the way; see `approve` in
`REFERENCE.md` for `--ip` and `--lookup-by`.


## Pairing Workflow in Docker

Pairing between containers follows the same protocol as bare-metal but uses
`docker compose exec` instead of separate terminal sessions. The commands run as
root inside the container, which is what the CA key requires.

### Step 1 - Start the dispatcher

```bash
docker compose up -d dispatcher
```

Wait for the first-start initialisation to complete:

```bash
docker compose logs dispatcher
# CA created: ...
# dispatcher cert created: ...
# [entrypoint] starting ctrl-exec-api as ctrl-exec
```

### Step 2 - Start pairing mode on the dispatcher

```bash
docker compose exec dispatcher ced pairing-mode
```

This blocks, waiting for requests. Leave it running. If the agent is on another
host, 7444 must be published (see `compose.yml`).

### Step 3 - Start the agent container

In another terminal:

```bash
docker compose up agent
```

The entrypoint finds no cert and sends a pairing request, then waits for you:

```
[entrypoint] No cert found - requesting pairing with dispatcher...
```

### Step 4 - Approve the request

Back in the pairing mode terminal, the request appears:

```
Pairing request from agent (172.18.0.3) - ID: 00c9845e0001
  Received: 2026-03-06T12:00:00Z
Accept, Deny, or Skip? [a/d/s]:
```

Type `a` to approve, within the agent's 30 seconds.

Alternatively, run `pairing-mode` in the background
(`docker compose exec -d dispatcher ced pairing-mode`) and approve from any
terminal:

```bash
docker compose exec dispatcher ced list-requests
docker compose exec dispatcher ced approve <reqid>
```

On approval the agent stores its certificate and carries straight on to serving:

```
[entrypoint] Paired.
[entrypoint] Starting ctrl-exec-agent serve as ctrl-exec-agent
```

No restart is needed. After the first pairing the volume holds the certificate
and later starts go directly to serving.

Press Ctrl-C in the pairing mode terminal (or stop the background one) when the
agent is paired, and unpublish 7444 if you published it.

### Step 5 - Verify

```bash
docker compose exec dispatcher ced ping agent
docker compose exec dispatcher ced run agent check-disk
```

The name the dispatcher knows the agent by is the hostname it reported when it
paired; see *Multiple Agents*. `docker compose exec dispatcher ced list-agents`
shows it.


## Agent Scripts

Scripts run by the agent are stored in the `agent-scripts` volume. To add a
script to a running agent container:

```bash
# Copy script into the volume via the running container
docker compose cp check-disk.sh agent:/opt/ctrl-exec-scripts/
docker compose exec agent chown root:root /opt/ctrl-exec-scripts/check-disk.sh
docker compose exec agent chmod 755 /opt/ctrl-exec-scripts/check-disk.sh

# Add to allowlist
docker compose exec agent sh -c \
    'echo "check-disk = /opt/ctrl-exec-scripts/check-disk.sh" \
    >> /etc/ctrl-exec-agent/scripts.conf'

# Pick up the new allowlist
docker compose kill -s HUP agent
```

The executor runs the script as its profile's `run_as` user, so that user must
be able to read and execute it, and to reach it. A script with no `profile=`
uses `[profile default]`, which the packaged `agent.conf` sets to
`run_as = nobody`, and the packaged scripts directory is mode 750
`root:ctrl-exec-agent`, which `nobody` cannot enter. For scripts that run as
`nobody`, open the directory once:

```bash
docker compose exec agent chmod 755 /opt/ctrl-exec-scripts
```

Otherwise give the script a profile whose `run_as` user can reach it, for
example a group the user is in (see the run_as note in `agent.conf`). Either
way the script and every directory above it must be owned by root and not
writable by group or other, or the agent skips it and the executor refuses it
(see `INSTALL.md`). A run_as user that cannot execute the script gets the error
`'<path>' is not executable by the profile's run_as user`.

### Reloading the agent

Send the container a `HUP`:

```bash
docker compose kill -s HUP agent
```

The agent reloads `agent.conf`, the allowlist, schemas, the revocation list and
the trusted-dispatcher map, as `systemctl reload ctrl-exec-agent` does on a
host, without a restart. `docker kill -s HUP <container>` is the same thing, and
`docker compose exec agent sh -c 'kill -HUP 1'` works too.

The signal reaches Docker's init process (PID 1), which passes it to the
entrypoint, which sends it on to the agent. The entrypoint sends it as the
agent's own user: it runs as root without `CAP_KILL`, and without that
capability root may not signal a process of another user. The executor needs no
signal: it reads `scripts.conf` on every run and rereads `agent.conf` when the
file changes. Settings that need a restart are named in the agent's log when it
reloads, as on a host.

Alternatively, pre-populate scripts in the Dockerfile or bake them into the
image for immutable deployments. For mutable agent fleets, maintain scripts
on a separate volume that is populated by a provisioning step before the agent
starts.


## Encrypted Credentials

The dispatcher's data mount holds the CA key and dispatcher cert, and the agent's
volume holds the agent cert. For production deployments these should be
protected at rest.

### Docker secrets

Docker Swarm supports secrets natively. For standalone Docker, a common
pattern is to populate the config mount from a secrets manager at container
start via the entrypoint script, before `init_ca` runs:

```bash
#!/bin/sh
# Retrieve CA key from secrets manager before starting
if [ ! -f /etc/ctrl-exec-dispatcher/ca.key ]; then
    echo "[entrypoint] Fetching CA key from secrets manager..."
    # Example: AWS Secrets Manager
    aws secretsmanager get-secret-value \
        --secret-id ctrl-exec/ca-key \
        --query SecretString \
        --output text > /etc/ctrl-exec-dispatcher/ca.key
    chmod 600 /etc/ctrl-exec-dispatcher/ca.key
fi
```

The specific mechanism depends on the secrets manager available in the
deployment environment (Vault, AWS Secrets Manager, Azure Key Vault, etc.). The
CA key stays `root` mode 0600; do not give it to the `ctrl-exec` user.

### Encrypted volumes

LUKS-encrypted volumes or encrypted filesystem layers (dm-crypt) can protect
volume contents at rest. This is a host-level concern - the container has no
awareness of whether its volume is encrypted.

For cloud deployments, encrypted EBS volumes (AWS), managed disks (Azure), or
persistent disks (GCP) provide at-rest encryption with minimal operational
overhead. Enable encryption when creating the volume and the platform handles
key management.

### Minimum viable protection

At minimum, ensure:

- The host running the dispatcher container has restricted access
- The `dispatcher-data` directory is not world-readable
- The CA key is backed up to encrypted offline storage immediately after
  first-start initialisation

```bash
# Backup CA key after first start
docker compose exec -T dispatcher cat /etc/ctrl-exec-dispatcher/ca.key \
    | gpg --symmetric --cipher-algo AES256 \
    > ca.key.gpg
# Store ca.key.gpg in offline/offsite storage
```


## Multiple Agents

To run multiple agent containers, give each a unique name and its own volumes:

```yaml
services:
  agent-db:
    <<: *hardened-agent
    build: ./agent
    image: ctrl-exec-agent:local
    hostname: agent-db
    restart: on-failure
    environment:
      DISPATCHER_HOST: dispatcher
    volumes:
      - agent-db-data:/etc/ctrl-exec-agent
      - agent-db-state:/var/lib/ctrl-exec-agent
      - agent-db-scripts:/opt/ctrl-exec-scripts
    networks: [ctrl-exec-net]

  agent-web:
    <<: *hardened-agent
    build: ./agent
    image: ctrl-exec-agent:local
    hostname: agent-web
    restart: on-failure
    environment:
      DISPATCHER_HOST: dispatcher
    volumes:
      - agent-web-data:/etc/ctrl-exec-agent
      - agent-web-state:/var/lib/ctrl-exec-agent
      - agent-web-scripts:/opt/ctrl-exec-scripts
    networks: [ctrl-exec-net]
```

Each agent pairs independently and appears separately in `ced list-agents`.
The agent hostname in the registry is the hostname the agent reports in the
pairing request, which is its fully qualified name as the container resolves it,
so the `hostname:` setting above is the start of it, not always the whole name
(a search domain on the host can be appended). Check the name in
`ced list-agents`, or the request in `ced list-requests`, and use `ced approve
--lookup-by ip` or `ced edit-agent` if the dispatcher cannot resolve it (see
`REFERENCE.md`).


## Agent Tags

Tags let you label agents with arbitrary key/value metadata - for example,
environment, role, or location. They are returned in the `/capabilities`
response and propagate through API discovery, making it straightforward to
filter or identify agents without maintaining separate inventory.

For container deployments, add a `[tags]` section to `agent.conf` on the
config volume, or inject it via the entrypoint before starting the agent:

```bash
# In agent/entrypoint.sh, before the executor and the agent are started
grep -q '^\[tags\]' "$CONF" || cat >> "$CONF" <<EOF

[tags]
env  = ${AGENT_ENV:-production}
role = ${AGENT_ROLE:-agent}
EOF
```

The `grep` guard keeps the section from being appended again on every start.
Then pass values via container environment:

```yaml
agent-db:
  hostname: agent-db
  environment:
    DISPATCHER_HOST: dispatcher
    AGENT_ENV: production
    AGENT_ROLE: database
```

Tags appear in API discovery responses:

```json
{
  "agent-db": {
    "host": "agent-db",
    "status": "ok",
    "tags": { "env": "production", "role": "database" },
    "scripts": [...]
  }
}
```

An agent with no `[tags]` section returns `"tags": {}`. Tag values are
plain strings; no reserved keys.


## Rebuilding Images

Because all state is on the mounts and volumes, images can be rebuilt without
losing pairing or configuration:

```bash
docker compose build dispatcher
docker compose up -d dispatcher
# Mounts are reattached - CA and registry are intact
```

If the data mount is deleted (e.g. removing `dispatcher-data`, or
`docker compose down -v` with named volumes), the dispatcher loses its CA and
all agents must be re-paired. The CA backup covers this case.

To move to a new release, replace the `.deb` files in the build context and
rebuild. Config and certificates are not touched, because the entrypoint seeds
only what is missing.

### Upgrading an existing container deployment

Before 0.13 the dispatcher's config directory was `/etc/ctrl-exec`. From 0.13 it
is `/etc/ctrl-exec-dispatcher`, to match `/etc/ctrl-exec-agent`. A package
upgrade on a host moves the directory and rewrites the paths in `ctrl-exec.conf`,
but a container image has nothing to upgrade in place, so a deployment with a
volume mounted at `/etc/ctrl-exec` needs these steps once:

1. Change the mount target in `compose.yml` from `/etc/ctrl-exec` to
   `/etc/ctrl-exec-dispatcher`. The data on the host stays where it is.
2. Edit `ctrl-exec.conf` on that mount, changing each path that begins
   `/etc/ctrl-exec/` (`cert`, `key`, `ca`, and `auth_hook` if set) to begin
   `/etc/ctrl-exec-dispatcher/`. Keep a copy of the file first.
3. Rebuild the image from the 0.13 debs and recreate the container.

Do not leave the mount at the old path. An image built from the 0.13 package
always contains the new directory, so an entrypoint that creates the CA when
none is found would create a second one beside your mounted config and orphan
every pairing. The ctrl-exec code refuses this state itself: if `/etc/ctrl-exec`
exists and is not a symlink to `/etc/ctrl-exec-dispatcher`, `ced` and
`ctrl-exec-api` print both paths, log `ACTION=config-dir RESULT=refused` and
exit 78. The entrypoint in this document stops earlier, for the same reason.

The symlink that package upgrades leave at `/etc/ctrl-exec` is removed in 0.14.
Anything of yours that names `/etc/ctrl-exec` - a backup job, a `docker exec`
script, a monitoring check - must use `/etc/ctrl-exec-dispatcher` before then.

An agent container needs no such step: its directory, `/etc/ctrl-exec-agent`,
did not change. An agent image from an earlier release was built on Alpine from
the tarball; rebuild it on the new Dockerfile and keep the existing `agent-data`
volume. Add an `agent-state` volume at `/var/lib/ctrl-exec-agent`. The old layout
did not keep that directory on a volume, so the trusted-dispatcher map it holds
is missing from the new volume. If `ced ping` is refused after the move, remove
the agent with `ced unpair <hostname>` on the dispatcher, delete `agent.crt` and
`agent.key` from `agent-data`, and pair it again.
