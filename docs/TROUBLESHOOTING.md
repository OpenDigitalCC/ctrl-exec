---
title: ctrl-exec - Use Cases and Troubleshooting
subtitle: Operating profiles, privilege separation, upgrades and configuration
brand: odcc
---

# ctrl-exec - Use Cases and Troubleshooting

This guide covers the operational questions that arise once an agent is paired
and running - security profiles, privilege separation, package upgrades, and the
configuration-file pitfalls that are easy to hit the first time. It complements
the troubleshooting section in `INSTALL.md` (which covers pairing, TLS and rate
limiting) and the trust model in `SECURITY.md`.

Each entry states the question or symptom, the underlying cause, and what to do.
The material is drawn from real deployment experience: the things that were not
obvious until someone ran into them.


## Security profiles: the mental model

A profile is the security context a script runs under - which user, which Linux
capabilities, and (in future) which paths are writable. Profiles are the feature
most often misunderstood on first contact, because whether they apply at all
depends on one setting.

::: widebox
Profiles are enforced **only** by the root executor (`ctrl-exec-exec`). With
`executor_socket` unset, the agent runs scripts directly in its own process and
the `profile=` in `scripts.conf` is parsed but never applied.
:::

There are two execution paths, and which one is active is a property of the
agent, not of the individual script.

executor mode (`executor_socket` set)
: The unprivileged front-end hands each run to the root executor over a
  peer-credential-checked Unix socket. The executor re-derives the script path
  and profile from its **own** root-owned config, then applies the profile -
  mount namespace, read-only control and audit directories, capability drop,
  `setuid`, ambient capabilities, `no_new_privileges`. This is the path that
  makes per-script privilege possible.

direct mode (`executor_socket` unset)
: The agent executes the script itself, inside its own systemd sandbox. Every
  script runs under the same context - that of the `ctrl-exec-agent` service -
  regardless of any `profile=` you set. The annotation is inert.

So the answer to *"what profile runs when the executor is not enabled?"* is: none
in the per-script sense. Every script inherits the front-end service's sandbox,
which is configured once in the systemd unit, not per script.


### Profile questions that come up first

profiles are optional?
: Yes. A script with no `profile=` runs under the `default` profile (executor
  mode) or the service sandbox (direct mode). You only define profiles for
  scripts that need a context different from the default.

can a script have more than one profile?
: No. A script runs under exactly one profile - there is no stacking or
  inheritance. If a task needs several capabilities (for example both writing a
  file and signalling a service), list them all in one profile:
  `caps = CAP_CHOWN, CAP_KILL`.

is the executor required to activate profiles?
: Yes - this is the single most important point. Set `executor_socket` and run
  `ctrl-exec-exec.service`, or your `profile=` lines do nothing. The agent logs a
  startup warning if `scripts.conf` names profiles while `executor_socket` is
  unset.

can `--async` and the executor be used together?
: No. They are mutually exclusive. While `executor_socket` is set, detached
  (`--async`) runs are unavailable; leave `executor_socket` unset to use
  `--async`. Routing async jobs through the executor is a deferred item.

what if a script names a profile that is not defined?
: The agent refuses to start (fail-closed) and exits with a clear configuration
  error - see *Configuration pitfalls* below. Define the profile in `agent.conf`
  or correct the `profile=` in `scripts.conf`.


## Use case: deploy a certificate and restart a service

A common task is "drop a renewed certificate into place and bounce the service
that uses it". This needs elevated privilege, and it is the clearest example of
how to scope a profile.

The first instinct is one profile that can do everything:

```ini
[profile deploy-restart]
run_as = root
caps   = CAP_CHOWN, CAP_KILL
```

That works, but it grants both abilities to whichever script carries it. A
tighter design splits the task along its two dimensions - file deployment and
service control - so each script holds only what it needs.

```datatable
columns: Approach | Privilege held by each script | Blast radius if a script is subverted
widths: 4cm | X | X
bold: 1
tone: medium
---
One combined profile | Every script with this profile can both rewrite files (CAP_CHOWN) and signal processes (CAP_KILL). | Either ability is available wherever the profile is used - the scopes multiply.
Two narrow scripts | The deploy script holds only CAP_CHOWN; the restart script holds only CAP_KILL. | Each script is bounded to one ability. Compromise of one does not confer the other.
```

Splitting is the better default. It keeps each allowlist entry auditable on its
own terms and avoids "squaring the scope across dimensions" - a deploy script
should not also be able to kill processes just because a sibling task needed it.


### What `run_as = root` with capabilities actually grants

This catches people out: setting `run_as = root` does **not** give the script the
unrestricted power of root.

::: widebox
The executor drops the bounding set to exactly the profile's listed
capabilities, then sets the same set effective. A `run_as = root` script runs as
uid 0 but holds **only** the capabilities you listed - nothing more.
:::

The practical consequence concerns file writes. The capability that lets root
ignore file ownership and permission bits is `CAP_DAC_OVERRIDE`. If you do not
list it, your root script is still subject to normal filesystem permissions: it
can only write where uid 0 is allowed to write by ownership and mode.

So *"my script is `run_as = root` with `CAP_CHOWN` and `CAP_KILL` - can it write
to the target path and restart the service?"* depends on the target:

- It can `chown` files (`CAP_CHOWN`) and signal processes (`CAP_KILL`).
- It can **write** a file only if the path is writable by root under ordinary
  permissions. If the directory is owned by another user with a restrictive
  mode, the write fails - because `CAP_DAC_OVERRIDE` is not in the set.

If a script genuinely needs to write through restrictive ownership, add
`CAP_DAC_OVERRIDE` to that profile deliberately - and treat it as a meaningful
grant, because it removes filesystem permission as a guard rail.

the `writable` field - per-profile read-only filesystem
: When a profile sets `writable = /path:/path`, the executor makes the action's
  whole filesystem **read-only** except those paths (which are remounted
  read-write), plus a private `/tmp`. It is a per-script `ProtectSystem=strict`:
  the script may write only the declared paths, and writes elsewhere fail with
  `EROFS` - even when the profile runs as root, because the action holds no
  `CAP_SYS_ADMIN` to remount. The control/state dirs stay read-only regardless.
  This is enforced only through the executor (it needs the mount namespace), and
  requires a Linux kernel >= 5.12; on an older kernel a profile that declares
  `writable` fails closed (the action will not run). A profile with no `writable`
  is unaffected - write access then follows filesystem ownership and the
  capability set, as above.


## Configuration pitfalls

### Inline comments are not supported on value lines

Both config parsers - the Perl front-end and the C executor, kept in lockstep -
support whole-line comments only. A `#` after a value is **not** stripped; it
becomes part of the value.

```ini
# This is fine - a comment on its own line.
caps = CAP_CHOWN

# This is a trap - the comment becomes part of the value.
caps = CAP_CHOWN  # needed for the chown step
```

The second line parses the capability list as `CAP_CHOWN  # needed for the chown
step`, and validation rejects `#` as an invalid capability name. Put every
comment on its own line.

The agent now detects this specific mistake and adds a hint to the error rather
than just reporting an invalid capability, but the cleanest fix is to never
write the inline comment in the first place.


### A bad config no longer loops - it exits clearly

Earlier, a configuration error could make the agent die with a generic exception
and let systemd respawn it indefinitely, so the restart counter climbed into the
hundreds while the real cause scrolled off the top of the journal.

That no longer happens. A configuration error now prints a framed message naming
the specific problem and both config files, then exits `EX_CONFIG` (78). The unit
lists 78 in `RestartPreventExitStatus`, so systemd records one clean failure
instead of a respawn loop.

```bash
sudo systemctl status ctrl-exec-agent
sudo journalctl -u ctrl-exec-agent --since "5 minutes ago"
```

If the agent will not start, look for the framed `configuration error` block. It
tells you the offending file and the precise fault - an invalid capability, an
undefined profile, a malformed value - so you can fix the named file and start
again.


### Validate before you start

After editing `agent.conf` or `scripts.conf`, check the configuration before
(re)starting the service:

```bash
sudo ctrl-exec-agent self-check
```

This parses both files and reports any error without touching the running
service. It is the cheapest way to catch an inline comment or an undefined
profile before it becomes a failed start.


## Installing and upgrading

### Restart after an upgrade is automatic

Upgrading the agent package restarts the relevant services for you. Both the
front-end and the executor are restarted when they are running, because an
upgrade can change either the Perl front-end or the compiled executor binary, and
a stale executor must not keep serving after an upgrade.

```text
ctrl-exec: restarted ctrl-exec-exec to apply the upgrade.
ctrl-exec: restarted ctrl-exec-agent to apply the upgrade.
```

You should not need a manual `systemctl restart` after `apt install` of a newer
package. If you do, check that the services were actually running before the
upgrade - a service that was stopped is not started by the upgrade (see the next
entry).


### "Failed to stop ... Unit not loaded" during install

If you see a message like `Failed to stop ctrl-exec-exec.service: Unit
ctrl-exec-exec.service not loaded` during an install on a host where the agent
was not running, it is benign. The install still succeeds.

The agent package now reports the situation plainly instead:

```text
ctrl-exec: ctrl-exec-exec is not running - no restart needed.
```

There is nothing to fix. The message simply reflects that there was no running
service to restart.


### `Depends: libc6 (>= 2.38)` on an older stable release

If installing the agent `.deb` fails with a dependency on `libc6 (>= 2.38)` -
for example on Debian 12, which ships glibc 2.36 - you have an **old** package.
This was caused by the compiler redirecting a standard library call to a
C23 variant introduced in glibc 2.38, which raised the package's libc floor.

The current packages pin their floor at `libc6 (>= 2.34)`, well within reach of
current stable releases. Download a current release `.deb` from the releases
page and the dependency resolves.

```bash
dpkg-deb -f ctrl-exec-agent_*.deb Depends | tr ',' '\n' | grep libc6
```

The line should read `libc6 (>= 2.34)` or lower.


### The `-dbgsym` package

A `ctrl-exec-agent-dbgsym_*.deb` is a debug-symbols package - detached debugging
information for the compiled executor, used only when producing a backtrace from
a core dump. It is not needed for normal operation and you do not install it
alongside the agent.

Current releases suppress its generation entirely, so you should not see one in a
recent release set. If you have an old `dbgsym` file lying around, you can simply
ignore or delete it.


## Diagnosing an agent that will not start

When the agent enters `activating (auto-restart)` with status 255/EXCEPTION, or
sits in `failed`, work through the layers from configuration outward.

```datatable
columns: Symptom | Likely cause | What to check
widths: 5cm | X | X
bold: 1
tone: medium
---
Framed "configuration error", exit 78 | A fault in agent.conf or scripts.conf (inline comment, undefined profile, bad value). | Read the framed message - it names the file and the fault. Fix and run self-check.
255/EXCEPTION, restart counter climbing | On current releases this should be a config error caught as exit 78. If it is not, the start is failing after config load. | journalctl for the exception text; confirm cert, key and CA paths exist and are readable.
Port 7443 not listening | Service not running, or bound elsewhere. | systemctl status; the port setting in agent.conf; self-ping.
mTLS handshake error on self-ping | Cert/CA paths wrong or unreadable by the service. | self-ping output; cert file ownership and mode.
Profiles set but never applied | executor_socket unset, so the executor is not in the path. | Startup warning in the log; confirm executor_socket is set and ctrl-exec-exec.service is running.
```

The two first-line tools both run on the agent host with no dispatcher access:

```bash
sudo ctrl-exec-agent self-check    # parse and validate the configuration
sudo ctrl-exec-agent self-ping     # confirm the listener, TLS and serial policy
```

A `self-ping` that ends in `403 serial mismatch (expected)` is a **pass** - the
agent's own certificate is not a dispatcher certificate, and the agent correctly
rejects it. See `MANUAL-CHECKS.md` for the full reading of that output.

stale sandbox drop-in
: If `systemctl cat ctrl-exec-agent` shows a drop-in such as
  `50-ctrl-exec-sandbox.conf` left over from a pre-privilege-separation install,
  remove it and reload: `sudo rm /etc/systemd/system/ctrl-exec-agent.service.d/50-ctrl-exec-sandbox.conf`,
  then `sudo systemctl daemon-reload`. The shipped unit carries the correct
  hardening; a stale drop-in can mask or conflict with it.


## Certificate rotation with executor-mode agents

Rotating the dispatcher certificate does **not** require re-pairing executor-mode
agents, and it is not implemented as an allowlisted script. It is a built-in
front-end operation, which matters for two reasons.

First, an executor-mode agent keeps its trusted-dispatcher map read-only to
scripts - so rotation could not be a script even if you wanted it to be. The
front-end handles the `/rotate-serial` request directly.

Second, the new identity is derived from the **caller's** authenticated serial,
never from the request body, so a rotation cannot be used to assert an identity
the caller does not already hold.

::: widebox
Because each rotation requires the previous authority to grant the exchange,
trust chains unbroken back to the original, human-supervised pairing. Any number
of rotations is safe: every link is authorised by the link before it.
:::

The broadcast is add-then-remove with an overlap window, so a reachable agent is
never without a trusted serial during the change. Only an agent that is offline
for the whole broadcast needs re-pairing. The end-to-end check is in
`MANUAL-CHECKS.md` (*Cert Rotation Broadcast*); the security properties are in
`SECURITY-OPERATIONS.md` (*Cert-Rotation Security*).
