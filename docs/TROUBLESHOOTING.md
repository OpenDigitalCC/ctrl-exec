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

Start with doctor
: When something does not work and the symptom does not say why ("(no
  scripts)", "Connection refused", a refusal to start), run doctor on the host
  first. It lists every problem it finds, one line each with the command that
  fixes it, and logs each (`ACTION=doctor-finding`):

  ```bash
  sudo ctrl-exec-agent doctor          # on an agent
  sudo ctrl-exec-dispatcher doctor     # on a dispatcher
  ```

  `--fix` makes only the fixes that cannot lose data or widen access; `--json`
  is for automation. Package upgrades and `install.sh` run `doctor --brief`
  after an upgrade and print the result. See REFERENCE.md, *doctor*, for the
  checks.


## Security profiles: the mental model

A profile is the security context a script runs under - which user, which Linux
capabilities, and which paths are writable. Profiles are the feature
most often misunderstood on first contact, because whether they apply at all
depends on one setting.

::: widebox
Profiles are enforced **only** by the root executor (`ctrl-exec-executor`). With
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
: The `profile=` annotation on a script is optional; the `[profile default]`
  block in `agent.conf` is not. A script with no `profile=` resolves to the
  profile named `default`, and there is no built-in fallback: if `default` is
  not defined, the agent refuses to start (exit 78, see *Agent exits 78 with
  "script(s) reference an undefined profile"* below). This holds whether or
  not the executor is enabled. Define `[profile default]` once, as the baseline,
  and add further profiles only for scripts that need a different context
  (executor mode applies them; in direct mode the service sandbox is used).

can a script have more than one profile?
: No. A script runs under exactly one profile - there is no stacking or
  inheritance. If a task needs several capabilities (for example both writing a
  file and signalling a service), list them all in one profile:
  `caps = CAP_CHOWN, CAP_KILL`.

is the executor required to activate profiles?
: Yes - this is the single most important point. Set `executor_socket` and run
  `ctrl-exec-executor.service`, or your `profile=` lines do nothing. The agent logs a
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

a `run_as` user's home
: Under a profile with `run_as`, the executor sets `HOME`, `USER` and
  `LOGNAME` from that user's passwd entry (a numeric `run_as` with no passwd
  entry gets none of them). It does not create the home. A tool that writes
  there (docker's config folder, git, ssh's `known_hosts`) fails with an error
  such as `mkdir /home/<user>: permission denied` when the home does not exist:
  create it, owned by the user. Under a profile with `writable`, list the home
  in `writable` too, or the write fails with `EROFS`.


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
service. It is the cheapest way to catch an inline comment before it becomes a
failed start; an entry naming an undefined profile is listed as `SKIPPED`.

The running agent re-reads `agent.conf` and `scripts.conf` by itself at the
next connection after either changes on disk (`allowlist-reload
REASON=changed` in the agent log), and on `systemctl reload ctrl-exec-agent`
(SIGHUP), so a tightened `allowed_ips`, rate limit or `max_children` takes
effect without a restart. If the new `agent.conf` does not parse, the previous
configuration stays in force: look for `reload-fail` in the agent log. A
`scripts.conf` entry naming a profile `agent.conf` does not define skips only
that script. Only `port`, `cert`, `key` and `ca` need a restart; the log says
so (`reload-note`) and the running values are kept.

### "scripts.conf declares '<name>' input=fields, but the request carried no input"

Symptom
: A run of a script with no input fails with `executor: scripts.conf declares
  'agent-service-restart' input=fields, but the request carried no input; if
  scripts.conf changed, run 'systemctl reload ctrl-exec-agent'` (0.13.0 and
  0.13.1 said `takes input=fields but the agent sent no input (it is older
  than this executor)`).

Cause
: The executor reads `scripts.conf` for every run; the agent sent the request
  as for an `input=context` script, so it read the file differently. From
  0.13.2 the agent reloads an edited `scripts.conf` before the next request,
  so this is an agent older than 0.13.2 that has not been reloaded after an
  edit, or an agent older than 0.13.0.

Fix
: Check the line in `scripts.conf` (is `input=` meant to be on it?), then
  `systemctl reload ctrl-exec-agent`, or upgrade the agent.


### "script not permitted"

Symptom
: A run fails with `script not permitted: <reason>`, for example:

  ```
  error: script not permitted: '/srv/scripts/agent-cert-deploy.sh' is not under script_dirs (/opt/ctrl-exec-scripts)
  ```

Cause
: The agent refused the name. The text after the colon says which of these it
  was:

  | Reason | Fix |
  | --- | --- |
  | `not in scripts.conf` | The name is not listed. Add `<name> = /abs/path` to the agent's `scripts.conf`; the next request picks it up. Check the spelling of the name. |
  | `profile '<name>' is not defined in agent.conf` | The entry's `profile=` names no `[profile <name>]` block. Add the block to `agent.conf` or correct the name; the rest of `scripts.conf` is unaffected. |
  | `'<path>' is not under script_dirs (<dirs>)` | The most common one. `script_dirs` in `agent.conf` restricts scripts to those directories. Move the script into one, or add its directory to `script_dirs` (colon-separated), then reload. |
  | `'<path>' is not an absolute path` | Write the full path from `/` in `scripts.conf`. |
  | `its scripts.conf entry has more than one path` | One path per line; annotations such as `profile=` are `key=value`. |
  | `its input mode '<value>' is not one of context, raw, raw:<name>, fields` | `input=` takes `context`, `raw`, `raw:<field>` or `fields`. |
  | `its output mode '<value>' is not one of stored, confidential` | `output=` takes `stored` (the default) or `confidential`. |
  | `its scripts.conf entry has no script path` | The line has only `key=value` annotations; add the path. |
  | `its path is too long` / `its profile name is too long` | Shorten the path (under 4096 characters) or profile name (under 128). |
  | `'<path>' is group-writable` / `'<path>' is world-writable` | The script, or a directory on its path (the one named), can be written by others. `sudo chmod go-w '<path>'`. A script under `/tmp`, `/var/tmp` or another world-writable directory must be moved. |
  | `'<path>' is owned by uid N, not root` | The script, or the directory named, is not root's. `sudo chown root '<path>'` (keep the group, e.g. `root:ctrl-exec-agent`), or move the script under root-owned directories. A user's home directory never qualifies. |
  | `'<path>' is not a regular file` / `'<path>' is not a directory` | The path names a directory, device or fifo, or a file sits where a directory should be. Correct the path in `scripts.conf`. |
  | `'<path>' has too many levels of symbolic links` | A symlink loop on the path. |

  The ownership reasons (T-045) refuse a run only with `script_ownership =
  strict` in `agent.conf`; with `warn` (the default) the script runs and the
  reason is a warning (see "Script ownership warnings" below). They apply
  whatever the script's profile and `run_as`; see SECURITY.md, "Script
  ownership". With `strict` they are checked when `scripts.conf` is loaded and
  again before each run, so a `chmod` that makes a loaded script group-writable
  takes effect at once; a fix needs a reload.

Fix
: Run `sudo ctrl-exec-agent self-check` on the agent: it lists every skipped
  entry as `Script '<name>': SKIPPED - <reason>`. The agent also logs each one
  when it loads `scripts.conf` (`ACTION=allowlist-skip`). The reasons are
  recomputed on every reload, and an edit to the file is reloaded at the next
  request. A listed script that is not executable is not refused with this message; the agent
  does not check that when it loads `scripts.conf`.

### Script ownership warnings

Symptom
: `sudo ctrl-exec-agent self-check` shows a script with
  `[warning: '/srv/scripts' is group-writable]` (or `is owned by uid N, not
  root`, `is world-writable`), and the agent logs
  `ACTION=script-ownership REASON=... SCRIPT=...` at WARNING when it loads
  `scripts.conf`. The script runs.

Cause
: `script_ownership = warn` (the default): the script, or the directory named,
  breaks the ownership rule, so a user who can write it can change what runs.
  The script is not refused; the warning says what `strict` would refuse.

Fix
: Use the fixes in the table above (`chown root`, `chmod go-w`, or move the
  script under root-owned directories), reload, and check self-check again.
  `sudo ctrl-exec-agent doctor` lists each reason once, with the scripts it
  covers and the command for it; it never changes the permissions itself.
  When it shows no warnings, set `script_ownership = strict` in `agent.conf`
  and reload, so a later change to the layout is refused instead of warned
  about. To keep the current layout, leave `warn`, and accept that the group
  (or user) named can change what the profile runs.

### Exit 126 with "executor: script not permitted"

Symptom
: With the executor enabled and `script_ownership = strict`, a run returns
  exit 126 and stderr such as:

  ```
  executor: script not permitted: '/opt/ctrl-exec-scripts' is group-writable
  executor: script not permitted: '/opt/ctrl-exec-scripts/x.sh' is owned by uid 1000, not root
  executor: script not permitted: '/opt/ctrl-exec-scripts/x.sh' changed while it was being checked
  ```

Cause
: With `script_ownership = strict` the executor checks the ownership rule
  itself before every run (it is the authority, and it runs as root). The
  reasons are the ones in the table above.
  The front end normally refuses first with the same reason; the executor's
  message appears when the front end could not see the script (a directory the
  agent user cannot search, e.g. a `0700` script directory for a root profile)
  or the script changed in between. `changed while it was being checked` means
  the path named a different file at exec than the one just checked (it was
  replaced during the run request); retry, and find out what replaced it.

Fix
: As in the table above. To check one path the way the executor does:
  `sudo ctrl-exec-executor check-path /opt/ctrl-exec-scripts/x.sh` prints `OK` or
  `DENY <reason>`. If the layout cannot be fixed yet, `script_ownership = warn`
  (the default) runs the script and reports the reason instead.

### Agent exits 78 with "script(s) reference an undefined profile"

Symptom
: The agent will not start. The framed `configuration error` block (and
  `ctrl-exec-agent self-check`) reports a line such as:

  ```
  script(s) reference an undefined profile: check-disk -> default
  ```

  Each entry is `<script> -> <profile>`. Exit status is 78, so systemd does not
  restart-loop.

Cause
: Profiles are fail-closed. A script with no `profile=` in `scripts.conf` uses
  the profile named `default`, and `default` must be defined in `agent.conf`
  like any other; there is no implicit one. The same error appears when
  `profile=<name>` names a profile that has no `[profile <name>]` block (often a
  typo). Only the `profile=` annotation is optional, not `[profile default]`.

Fix
: Add the block to `agent.conf` (this is the restrictive baseline shipped in
  `etc/agent.conf.example`):

  ```ini
  [profile default]
  run_as            = nobody
  no_new_privileges = yes
  ```

  For a non-`default` entry, either define `[profile <name>]` or correct the
  `profile=` in `scripts.conf`. Then run `sudo ctrl-exec-agent self-check` and
  start the service.


## Installing and upgrading

### Restart after an upgrade is automatic

Upgrading the agent package restarts the relevant services for you. Both the
front-end and the executor are restarted when they are running, because an
upgrade can change either the Perl front-end or the compiled executor binary, and
a stale executor must not keep serving after an upgrade.

```text
ctrl-exec: restarted ctrl-exec-executor to apply the upgrade.
ctrl-exec: restarted ctrl-exec-agent to apply the upgrade.
```

After the restarts the upgrade runs `ctrl-exec-agent doctor --brief` (and
`ctrl-exec-dispatcher doctor --brief` for the dispatcher package) and prints
the result: one line when there is nothing to fix, otherwise each problem with
its fix. It only reports; it never fails the upgrade.

You should not need a manual `systemctl restart` after `apt install` of a newer
package. If you do, check that the services were actually running before the
upgrade - a service that was stopped is not started by the upgrade (see the next
entry).


### Upgrading to 0.13: the executor and the dispatcher config directory were renamed

0.13 renames two things so that every part of ctrl-exec is named
`ctrl-exec-<part>`. Upgrading with `install.sh` or the packages migrates an
existing install; no manual steps are needed.

- The executor `ctrl-exec-exec` is now `ctrl-exec-executor` (binary, and
  `ctrl-exec-executor.service`). The old unit is stopped and disabled, and its
  unit file and binary removed; the new unit is enabled and started if the old
  one was. `executor_socket` and the socket path in `agent.conf` are unchanged.
- The dispatcher's config directory `/etc/ctrl-exec/` is now
  `/etc/ctrl-exec-dispatcher/`, matching `/etc/ctrl-exec-agent/`. An existing
  directory is moved, the paths inside `ctrl-exec.conf` are updated (the old file
  is kept as `ctrl-exec.conf.pre-0.13`), and `/etc/ctrl-exec` is left as a symlink
  to the new directory. A config that cannot be moved (a container volume or
  other mount at `/etc/ctrl-exec`) is used in place and logged as
  `ACTION=config-dir RESULT=in-place`; see INSTALL.md, *Upgrading: the
  dispatcher config directory*.

If `ced` or `ctrl-exec-api` exits 78 with `refusing to start: the old config
directory /etc/ctrl-exec exists and is not a symlink to
/etc/ctrl-exec-dispatcher`, the host has a real `/etc/ctrl-exec` that is not
the old layout an upgrade moves (`ctrl-exec.conf` and `ca.key` there with the
new directory absent or without a CA, or `ctrl-exec.conf` there and no new
directory): both directories hold a CA, the old one has no CA while the new one
exists, or it is a symlink elsewhere. It is refused rather than guessed so that
the dispatcher never runs on the wrong config or creates a second CA. Keep the
directory whose CA your agents trust, merge it into
`/etc/ctrl-exec-dispatcher`, remove `/etc/ctrl-exec`, and change the paths
inside `ctrl-exec.conf` from `/etc/ctrl-exec/` to `/etc/ctrl-exec-dispatcher/`.
The refusal is logged as `ACTION=config-dir RESULT=refused`.
`ctrl-exec-dispatcher doctor` still runs on such a host and reports it, and
reports a config used in place with the command that moves it.


### "Failed to stop ... Unit not loaded" during install

If you see a message like `Failed to stop ctrl-exec-executor.service: Unit
ctrl-exec-executor.service not loaded` during an install on a host where the agent
was not running, it is benign. The install still succeeds.

The agent package now reports the situation plainly instead:

```text
ctrl-exec: ctrl-exec-executor is not running - no restart needed.
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
"... needs root - cannot read <file> (Permission denied)" from self-check, self-ping or pairing-status | The command was not run as root; the configuration and key files are root-only. | Re-run with sudo (for example, sudo ctrl-exec-agent self-check).
"ctrl-exec-agent is not running" from self-ping (or in self-check output) | Nothing is listening on the port in agent.conf. | Start the service as the message shows (systemctl start ctrl-exec-agent); if it will not stay up, systemctl status and journalctl -u ctrl-exec-agent.
Port 7443 not listening | Service not running, or bound elsewhere. | systemctl status; the port setting in agent.conf; self-ping.
mTLS handshake error on self-ping | Cert/CA paths wrong or unreadable by the service. | self-ping output; cert file ownership and mode.
Profiles set but never applied | executor_socket unset, so the executor is not in the path. | Startup warning in the log; confirm executor_socket is set and ctrl-exec-executor.service is running.
Every run fails with "ctrl-exec-executor is not available" | executor_socket is set but the executor is not running, or was never built (a tarball install on a host without gcc or the libcap headers). | self-check shows "Executor: NOT AVAILABLE". systemctl start ctrl-exec-executor.service; if the unit or /usr/local/sbin/ctrl-exec-executor does not exist, install gcc and libcap-dev and re-run install.sh --agent. To run without profiles instead, comment out executor_socket.
```

The first-line tools all run on the agent host with no dispatcher access:

```bash
sudo ctrl-exec-agent doctor        # every problem found, each with its fix
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


## ctrl-exec-maintenance.service shows as failed

`ced maintain` (run by `ctrl-exec-maintenance.timer`) runs the ping/renewal,
rotate, broadcast, expire, retire and purge phases independently, then exits 1 if any
of them failed. The unit therefore shows as failed in `systemctl --failed`
until the next successful run. It is not restarted in a loop; the timer simply
fires again at its next interval.

To see which phase failed, run it by hand or read the journal:

```bash
sudo ced maintain
journalctl -u ctrl-exec-maintenance.service
```

The output ends with `Maintenance FAILED in phase(s): ...`, and the cause is
logged at ERR (`ACTION=maintain PHASE=<phase>`). A failing `ping` or `rotate`
phase means certificate renewal is stalled - fix it before certs expire.

## A second dispatcher is refused: "predates 0.14"

An agent paired with two dispatchers whose CAs were both made before 0.14
holds two CAs named `ctrl-exec CA` in `ca.crt`. A dispatcher certificate
issued before 0.14 on an OpenSSL 1.1 host has no Authority Key Identifier, so
the agent can find its issuer only by name; it checks the certificate against
the first CA of that name and refuses it when the other one issued it. Every
request from that dispatcher fails at the TLS handshake. The refusal is
correct and stays: the dispatcher is not compatible until its certificate is
replaced. Upgrading it to 0.14 does not replace the certificate.

What each side shows:

Agent log
: `ACTION=tls-failure PEER=... REASON="... certificate verify failed - the
  dispatcher certificate (serial ...) predates 0.14: it has no Authority Key
  Identifier and its CA has the same name (CN=ctrl-exec CA) as another CA this
  agent trusts, so it is not compatible. ..."`. `ctrl-exec-agent doctor`
  notes the CAs with one name (`ca-same-name`).

Dispatcher (0.14 or later)
: the error for that agent (CLI and API result) ends with "this dispatcher's
  certificate predates 0.14 (it has no Authority Key Identifier): an agent
  that trusts another CA with the same name as this dispatcher's CA refuses
  it; run 'ctrl-exec-dispatcher rotate-cert', then pair that agent again".
  The dispatcher cannot see the agent's CAs, so it says this whenever its own
  certificate has no identifier and a connection fails as a refused handshake
  does. `ctrl-exec-dispatcher doctor` notes the certificate
  (`dispatcher-cert-no-aki`).

The fix, in this order:

1. On the refused dispatcher, upgrade to 0.14 or later.
2. On it, run `sudo ctrl-exec-dispatcher rotate-cert`. The new certificate
   carries the Authority Key Identifier, and the agent's handshake accepts it:
   the agent already trusts that dispatcher's CA. The rotation broadcast does
   not reach this agent, which refuses the old certificate, so the agent does
   not know the new serial yet and answers `forbidden: serial mismatch`.
3. Pair the agent with that dispatcher again: `sudo ctrl-exec-agent
   request-pairing --dispatcher <that-dispatcher>` on the agent, `approve` on
   the dispatcher. The agent keeps its certificate and records the new serial.

Before pairing an agent with a second dispatcher whose CA has the pre-0.14
name, do steps 1 and 2 on that dispatcher first; the pairing then records the
new certificate and nothing is refused. The other dispatcher (the first CA of
the name in `ca.crt`) is not affected either way, and its own pre-0.14
certificate goes on working; rotating it as well removes the dependence on the
order of the CAs in `ca.crt`.

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
never without a trusted serial during the change: the broadcast is sent with the
certificate the agent already trusts, and the new one is served only after it.
An agent offline during the broadcast is retried with the previous certificate;
only one offline for the whole overlap window needs re-pairing. The end-to-end check is in
`MANUAL-CHECKS.md` (*Cert Rotation Broadcast*); the security properties are in
`SECURITY-OPERATIONS.md` (*Cert-Rotation Security*).
