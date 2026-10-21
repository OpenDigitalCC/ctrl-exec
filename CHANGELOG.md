# Changelog

High-level release history for ctrl-exec. This is a summary extract — full
detail lives in the git log; each entry is anchored to the commit ref (or the
release commit) it lands at, not a date. Bullets mark what was **added**,
**changed**, or **removed** at the level of the area touched.

## 0.14.0 — (unreleased)

## 0.13.2 — scripts.conf edits work without a reload

Upgrading from 0.13.1: nothing to do. An edit to `scripts.conf` or
`agent.conf` now takes effect at the next request; `systemctl reload
ctrl-exec-agent` still works but is no longer needed after an edit.

- **Fixed** after `input=fields` was edited into `scripts.conf`, context scripts were refused by the executor as `takes input=fields but the agent sent no input (it is older than this executor)` until the agent was restarted: the executor reads `scripts.conf` and `agent.conf` for every run, the agent only at start-up and on SIGHUP. The agent now checks both files (inode, size, modification and change time) before handling each connection and, when either changed, reloads them exactly as SIGHUP does (`ACTION=allowlist-reload REASON=changed`, once per change), in the serve loop's parent so every later connection sees it. SIGHUP still reloads (`REASON=signal`). `port`, `cert`, `key` and `ca` still need a restart; a change to the revocation list or trusted-dispatcher map alone still needs SIGHUP. (T-059)
- **Changed** a `scripts.conf` entry naming a profile `agent.conf` does not define is skipped with the reason `profile '<name>' is not defined in agent.conf` (logged as `allowlist-skip`, refused as `script not permitted: <reason>`, listed by self-check as SKIPPED); it used to fail the whole start-up or reload, which on a reload kept the old allowlist while `systemctl reload` reported success. The rest of the file loads. (T-059)
- **Changed** non-breaking spaces pasted into `scripts.conf` or `agent.conf` (U+00A0, U+2000 to U+200A, U+202F, as a terminal or chat UI inserts them) read as ordinary spaces in the agent and the executor alike, so a pasted line works as typed; the agent logs `ACTION=config-nonascii-space FILE=...` once per load of a file that held any. Before, `profile=cert-deploy<NBSP>input=fields` was read as one undefined profile name. Parity fixtures in t/exec-conformance.t. (T-059)
- **Changed** the executor's refusal of a run with no input for a script it reads as `input=raw` or `fields` names the mismatch and the fix: `scripts.conf declares '<name>' input=<mode>, but the request carried no input; if scripts.conf changed, run 'systemctl reload ctrl-exec-agent'`. It no longer says the agent is older, which the request cannot show. (T-059)
- **Added** `tools/upgrade-rig` scenario s5: the reported sequence as root under systemd (a fields script run without and with input, then context scripts), pasted forms of the line, edits with no reload, an undefined profile, SIGHUP. (T-059)

## 0.13.1 — existing script layouts run again

Upgrading from 0.13.0: nothing to do. Scripts that 0.13.0 refused for their
ownership run again; `sudo ctrl-exec-agent self-check` shows a warning with
the reason next to each, and `script_ownership = strict` in `agent.conf`
restores the 0.13.0 behaviour once the layout is fixed.

- **Changed** the script ownership rule (T-045) no longer refuses scripts by default, because on upgrade it removed every script on hosts whose script directory or a parent is group-writable or user-owned (e.g. `/srv/scripts` `2775 root:dev`, a group-writable `/srv`), leaving the agent with no scripts. New `agent.conf` key `script_ownership = warn | strict` (default `warn`; any other value is a configuration error in both the agent and the executor). With `warn` a script that breaks the rule stays allowlisted and runs; the agent logs the reason once per `scripts.conf` load (`ACTION=script-ownership`, WARNING), `self-check` shows it next to the script (`[warning: '/srv/scripts' is group-writable]`) together with the mode, and nothing is added to the run's output. The executor still checks the rule before every run but in `warn` mode runs the script, binding the exec to the file the path names at that moment. `strict` keeps the 0.13.0 refusal in the agent and the executor. The agent and executor parse the key identically (t/exec-conformance.t); docs/SECURITY.md states the trade-off (`warn` lets anyone who can write the script or a directory on its path change what a profile runs) and recommends `strict` once self-check is clean. New t/exec-ownership-warn.t; t/agent-script-ownership.t and t/exec-ownership-root.t cover both modes. (T-054)
- **Added** `tools/upgrade-rig/`: installs the previous release on real-world layouts (scripts in a group-writable `/srv/scripts` owned by a user, the dispatcher's old config directory, a containerised dispatcher with a job parsing the CLI's output), upgrades to a given commit's debs and checks everything still lists and runs with no manual step. A required check before each release (docs/DEVELOPER.md). (T-057)

## 0.13.0 — confidential run input and output; executor hardening; API socket

Headlines: a script can receive secrets as named input fields that never
appear in arguments, environment, logs or stores (`input=`), and declare that
its output is returned but never stored (`output=confidential`); the API can
listen on a unix socket or with TLS; the executor checks script ownership,
hands the action only stdin, stdout and stderr, and runs in the agent
container; a fresh dispatcher install denies API requests until an auth hook
is enabled.

Upgrading from 0.12 - check these before or during the upgrade:

- The dispatcher's configuration lives in `/etc/ctrl-exec-dispatcher/`. The
  packages and `install.sh` move it; a container that mounts its own config
  must change the mount and the paths inside `ctrl-exec.conf`. A real
  `/etc/ctrl-exec` directory makes `ced` and `ctrl-exec-api` refuse to start
  (exit 78). (T-008, T-047)
- Allowlisted scripts must be root-owned and not group- or other-writable,
  down from `/`; a script that is not is refused with the reason. (T-045)
- A fresh install no longer enables the example auth hook (which allows
  everything). An existing `ctrl-exec.conf` is kept: if it names the seeded
  `auth-hook` that ends `exit 0`, the API is still allow-all - check it. (T-046)
- The API TLS settings are `api_tls_cert` / `api_tls_key`; the old
  `api_cert` / `api_key` stop the API from starting, naming the new key, and
  half a TLS pair is refused instead of serving plain HTTP. (T-013)
- The executor is now `ctrl-exec-executor` (was `ctrl-exec-exec`); upgrades
  switch over. An agent container needs `SYS_ADMIN`, `SETPCAP` and
  `apparmor=unconfined` for the executor (see docs/DOCKER.md). (T-008, T-048)
- Confidential input and output need 0.13 on both ends: upgrade agents first,
  then switch callers to `--input-fields` (the cert-deploy plugin: agents with
  `input=fields` and `output=confidential`, then the job). (T-013, T-053)

- **Fixed** docs/SECURITY.md claimed the agent enforces "schema validation (constrained arguments)" and that the surface is "argument-constrained"; core never validates argument values (the schema sidecar is advertised data only). SECURITY.md now says so everywhere and points to the auth hooks (dispatcher hook and the agent's `auth_hook`, both given `ENVEXEC_ARGS_JSON`) as the place to constrain arguments. (T-010)
- **Fixed** docs/TROUBLESHOOTING.md answered "profiles are optional?" with "Yes"; only the per-script `profile=` is optional, `[profile default]` in agent.conf is mandatory (an undefined profile exits 78). The answer is corrected and a troubleshooting entry added for "script(s) reference an undefined profile" with the `[profile default]` fix. (T-015)
- **Fixed** `self-check`, `self-ping`, `pairing-status` and `serve` reported a
  configuration error (or "not paired") when the real cause was a permission
  error on a root-only file because they were not run as root. They now say the
  command needs root, name the file and show the sudo form (`serve` exits 78
  with the permission error named); real configuration errors are unchanged.
  `pairing-status` and `self-check` now read the certificate directory beside
  `--config` rather than a fixed path. (T-006)
- **Fixed** `self-ping` failed obscurely, or with an unrelated "not paired"
  complaint, when the agent was not running. It now probes the configured port
  first (a plain loopback TCP connect, no root needed) and says "ctrl-exec-agent
  is not running" with the start command for the host's init system; `self-check`
  adds an informational running / not-running line. (T-007)
- **Fixed** the executor deadlocking on an action that writes more than a pipe
  buffer of output before reading its stdin, or never reads it: the handler
  wrote the whole stdin payload with a blocking write before draining stdout
  and stderr, so each side waited on its own write. stdin is now written
  non-blocking from the same `select` loop that drains the output, and closed
  once written or on EPIPE. (T-036)
- **Changed** the executor to give a `run_as` action `HOME`, `USER` and
  `LOGNAME` from the run_as user's passwd entry, so its tools (docker, git,
  ssh) find their home; before, the action got `PATH` alone and such tools
  failed or fell back. A numeric `run_as` with no passwd entry and a profile
  without `run_as` are unchanged; `PATH` stays fixed and nothing from the
  request or the executor's own environment is passed. The home is not
  created, and a `writable` profile must list it. (T-004)
- **Fixed** an agent without an executor could be killed by SIGPIPE when a script
  exited without reading its stdin: the Perl runner wrote the request context
  with no SIGPIPE guard (the same race T-034 fixed in the C executor), so the
  per-connection handler died and the run got no response. SIGPIPE is now
  ignored around the stdin write only, EPIPE is treated as "the script did not
  read its input", and the script always starts with SIGPIPE at its default even
  if the agent was started with it ignored. (T-038)
- **Changed (security)** the CA now issues a random serial for every certificate
  (CA, dispatcher, pairing and renewal): 16 bytes from `Exec::Random`, top bit
  clear, 32 lowercase hex digits, already in the canonical form the
  trusted-dispatcher map, revocation list and registry compare on. Serials were
  sequential from `01` and predictable, and the serial is the trust identity.
  Existing CA directories keep working; `ca.serial` is no longer read or
  advanced (it remains as the signing lock file) and certificates already
  issued keep their serials. (T-023)
- **Fixed** `/run` `args` are now type-checked: any element that is a reference or undef is rejected (agent: `exit -1` error before allowlist/auth/exec, the real boundary; dispatcher API: 400), so such values never reach the exec boundary. (T-024)
- **Fixed** lock files (dispatcher `locks/`, agent `.locks/`, registry lock) are opened with `O_NOFOLLOW`, so a symlink planted at a lock path is refused with a clear error instead of being followed and its target created or chmod-ed. (T-024)
- **Fixed** lock files no longer accumulate: idle files are swept opportunistically (`Exec::Lock::acquire`, and the agent's `AsyncRunner` purge). Release still does not unlink (that would let two processes lock different inodes of one lock); the sweep unlinks only while holding the flock, and lockers re-check the path after locking and retry on the fresh file. (T-024)
- **Changed** docs (and `etc/auth-hook.example`) now say `ENVEXEC_SOURCE_IP` is the reverse proxy's address, not the client's, when ctrl-exec sits behind one, so hooks must not use it for client identity there. (T-024)
- **Changed (security)** the pairing confirmation code is now bound to the
  dispatcher certificate the agent saw on the pairing connection: v2 =
  `SHA-256(CSR || SHA-256 fingerprint of that certificate's DER)`, same six
  digits. A man in the middle on port 7444 must show the agent its own
  certificate, so the two codes no longer match even when it relays the CSR
  unchanged (the old `SHA-256(CSR)` code matched). The agent prints the code
  once connected and states `code_version: 2` in its request; the dispatcher
  shows `v2` codes for those and the old code, marked `v1, pre-0.13 agent`, for
  agents that send no version, in the prompt, `list-requests` and `approve`.
  Upgrade dispatchers before agents: an older dispatcher shows a code a 0.13
  agent will not match (the agent warns). Existing pairings are untouched.
  (T-022)
- **Added (security)** the pairing listener refuses a CSR that is not exactly
  as openssl writes it, so text appended to a relayed CSR cannot be varied
  until the codes match. Agents send openssl's own output, so genuine requests
  are unaffected. (T-022)
- **Fixed** the Perl and C config parsers now agree on every case in a broadened conformance corpus (t/exec-conformance.t, which gates them in the normal suite): the executor takes the last valid duplicate script name as the front end does, honours `script_dirs` only at top level, treats `[PROFILE x]` case-insensitively, restricts everything for a `script_dirs` that yields no directory, rejects malformed lines, NUL bytes and the reserved top-level keys `profiles`/`tags`, and rejects over-long or over-numerous values instead of truncating them (the front end enforces the same limits). (T-031)
- **Added** a `status-read` audit log line for every `GET /status/{reqid}` (caller IP, reqid, recorded submitter, served / denied / not-found; never the token or output), so reads of a run's output are attributable. (T-030)
- **Added** `etc/auth-hook-args.example`, an opt-in agent `auth_hook` that validates a run's arguments against the script's schema sidecar (`argv` mapping; type, enum, pattern, bounds, and realpath-resolved `x-path-prefixes`), denying with exit 3 and a syslog line that names the argument and rule but never the value; shipped by `install.sh` and the Debian agent package, off unless `auth_hook` names it. Documented in `docs/SECURITY.md` and `docs/SCHEMA-SIDECAR.md`. (T-011)
- **Fixed** `ced maintain` reported success when a phase failed: it now exits 1
  and `--json` gives `"ok":0` with a `"failed"` array of phase names (the key is
  always present, empty when all passed); text output names the failed phases.
  Every phase still runs, so one failure does not stop the others. A systemd
  timer run now shows the unit as failed instead of hiding a stalled certificate
  renewal. (T-040)
- **Fixed** the agent not reloading `agent.conf` on SIGHUP: an operator who
  tightened `allowed_ips`, a rate limit, `max_children` or `auth_hook` and reloaded
  was not protected. SIGHUP now parses `agent.conf` into a new config
  (`Exec::Agent::Config::reload_plan`) and swaps it in with the allowlist only if it
  parses and every script's profile is still defined; otherwise the old config
  stays in force and `reload-fail` is logged. `port`, `cert`, `key` and `ca` keep
  their running value and log `reload-note` (restart needed). A `scripts.conf` that
  cannot be read no longer empties the allowlist: the previous one is kept. (T-021)
- **Fixed** the handshake-probe limit never blocking anyone: a TLS handshake failure
  was recorded under the peer name `unknown` (the listening socket has no peer), so
  the block applied to no real address. The listener now uses
  `SSL_startHandshake => 0`; the agent accepts the TCP connection, checks
  `allowed_ips` (before any TLS cost), then runs `accept_SSL` on it, so the failure
  is counted under the prober's address and the fourth connection from it gets the
  probe-block `429`. The trusted-dispatcher exemption, volume check, `max_children`
  and `accept_failure_action` retry/fatal handling are unchanged. The handshake runs
  in the accept-loop parent (it needs the peer serial and updates the rate state
  there) with a 5 s limit (`Exec::Agent::Server::HANDSHAKE_TIMEOUT`), SIGHUP held off
  across it; a silent client is dropped at the limit and counted as a failure, where
  the old handshake inside `accept()` could stall the loop indefinitely. A failed TCP
  accept is logged `accept-error` and no longer counted. (T-035)
- **Fixed** the agent's `429` reply being lost to a TCP reset: it answered and closed without
  reading the request, so a client that had already written its request could get a
  reset instead of the reply and report a connection error rather than "rate
  limited". After the reply the agent now sends `close_notify`, half-closes and drains
  what the client sent, then closes, bounded to 64 KiB and 1 s in total
  (`Exec::Agent::Server::drain_refused`), so a slow or silent client cannot hold the
  accept loop longer. (T-043)
- **Changed** the seven systemd units to one canonical set in `etc/systemd/`
  with `@BINDIR@` / `@SBINDIR@` placeholders, rendered by `etc/systemd/render-unit`
  (install.sh with `/usr/local/{bin,sbin}`, `debian/rules` with `/usr/{bin,sbin}`)
  in place of the hand-maintained `etc/` and `debian/` copies that had drifted
  (the stale `yourorg` URL lived in both). The executor unit's `ExecStart` is now
  `@SBINDIR@` (it was hard-coded in each copy). No hardening directive changed;
  `t/units-render.t` checks both renderings. (T-014)
- **Changed** the privileged executor `ctrl-exec-exec` to `ctrl-exec-executor`
  (ctrl-exec is the package, its parts are `ctrl-exec-<part>`): the source
  `src/ctrl-exec-executor.c`, the binary in `/usr/local/sbin` or `/usr/sbin`, the
  unit `ctrl-exec-executor.service`, and every reference to them (the process list
  no longer reads `ctrl-exec-exec`). The `executor_socket` key and the socket path
  `/run/ctrl-exec-agent/exec.sock` are unchanged, so no `agent.conf` edit is
  needed. Existing installs are switched over on upgrade (see the migration note
  below). (T-008)
- **Changed** the dispatcher's config directory from `/etc/ctrl-exec/` to
  `/etc/ctrl-exec-dispatcher/`, to match `/etc/ctrl-exec-agent/`: the defaults in
  `ctrl-exec-dispatcher`, `ctrl-exec-api`, the CA, pairing, rotation and engine
  code, `etc/ctrl-exec.conf.example`, the units and the packaging. (This bullet
  first described a fallback to the old directory and "new wins when both exist";
  both were replaced by a refusal, see T-047 below.) The `ctrl-exec` group and
  user, and `/var/lib/ctrl-exec/`, are unchanged. (T-008)
- **Changed** upgrades of existing installs, with no manual steps (`install.sh`
  and the `.deb` packages alike). Dispatcher: an existing `/etc/ctrl-exec/` is
  moved to `/etc/ctrl-exec-dispatcher/`, the paths inside `ctrl-exec.conf` are
  rewritten to match (the old file is kept as `ctrl-exec.conf.pre-0.13`), and
  `/etc/ctrl-exec` is left as a symlink to the new directory for this one
  release. **The symlink is removed in 0.14.** Agent: the old `ctrl-exec-exec`
  unit is stopped and disabled, and its unit file and `/usr/sbin` or
  `/usr/local/sbin` binary removed; `ctrl-exec-executor.service` is enabled and
  started if the old unit was. A fresh install gets only the new names.
  `install.sh --uninstall` now also stops and removes the executor. (T-008)
- **Changed** a refused run no longer answers a bare `script not permitted`. The
  agent now says why: `script not permitted: '<path>' is not under script_dirs
  (<dirs>)`, or the other skip reasons (relative path, two paths, over-long path
  or profile name, no path), and `script not permitted: not in scripts.conf` for
  a name that was never listed. The response shape (`exit` -1, `error`) is
  unchanged. Each skipped entry is logged once per load (`ACTION=allowlist-skip`),
  the reasons survive a SIGHUP reload, and `self-check` lists skipped entries
  with their reasons. The agent now applies `script_dirs` when it loads
  `scripts.conf` (as the docs always said), so a script outside the approved
  directories is no longer advertised by `/capabilities`. (T-044)
- **Fixed** `install.sh --dispatcher` / `--api` failing on a missing file: the
  0.13 config-directory rename pointed it at `etc/ctrl-exec-dispatcher.conf.example`;
  the example is still `etc/ctrl-exec.conf.example`. `t/install-sources.t` now
  checks that every file install.sh copies from the source tree exists.
- **Changed** (security) allowlisted scripts must now be root-owned, as
  `scripts.conf.example` always said: the script and every directory from `/`
  down to it must be owned by root and not group- or other-writable, and the
  script a regular file, whatever the profile's `run_as`. The root executor
  checks this before every run (walking the path with `O_NOFOLLOW` opens, then
  exec'ing by path only if it still names the file checked) and refuses with
  exit 126 and `executor: script not permitted: '<path>' is group-writable` (or
  world-writable, owned by uid N, not root, ...); the agent applies the same rule
  at load and before each run, so the reason appears as `script not permitted:
  <reason>` and in `self-check`, and direct mode (no executor) is covered too.
  New `ctrl-exec-executor check-path <path>`. Before, a user able to write a
  script or a directory on its path could change what root runs. **Upgrading:**
  a host with scripts that are not root-owned, are group-writable, or sit under
  `/tmp`, `/var/tmp` or a home directory will see them refused after the
  upgrade; run `sudo ctrl-exec-agent self-check` and fix them with `chown root`
  / `chmod go-w` (installed layout `root:ctrl-exec-agent 0750` passes). (T-045)
- **Added** bash completion for `ctrl-exec-dispatcher` (`ced`), `ctrl-exec-agent` (`cea`) and `ctrl-exec-api` (`etc/bash-completion/`): modes and options taken from each bin's dispatch and option tables, `--lookup-by` values, and registered host names (and local allowlist script names for `run`) when those files are readable without root. `install.sh` and both packages install them (with `ced`/`cea` as links) into the system bash-completion directory, and `t/completion-*.t` fails if a mode or option is added to a bin without completion. (T-009)
- **Fixed** a tarball install on a host without gcc or the libcap headers left
  a new `agent.conf` with `executor_socket` enabled and no executor: the agent
  started, then every run failed with a bare `executor unreachable: No such file
  or directory`, and the installer's only word was a mid-install warning. A new
  `agent.conf` now has `executor_socket` commented out (an existing one is never
  edited) and the end of the install states what is missing, the exact
  `apt-get`/`apk` command, that per-script profiles are not applied, and to
  re-run. With `executor_socket` set and the executor absent or refusing, a run
  now fails with `ctrl-exec-executor is not available (<cause>: <socket>)` and
  how to start it, logged as `ACTION=executor-unavailable`, and `self-check`
  reports `Executor: NOT AVAILABLE` and exits non-zero. (T-028)
- **Added** auth hooks receive `input_names` and `input_bytes` (env `ENVEXEC_INPUT_NAMES_JSON`, `ENVEXEC_INPUT_BYTES`) describing a run's confidential input, never its values, so policy can see what is sent without seeing it. (T-013)
- **Added** `POST /run` accepts `input`, an object of named string fields for confidential content, validated before any hook or dispatch (400 on a bad shape, more than 32 fields, or more than `max_input_bytes`, default 1 MiB) and forwarded unchanged to each agent in sync and async runs. The values reach only the agents: the dispatcher's auth hook gets names and total size, and no log line, run record or async record holds them. The API's body limit is now 1 MiB plus `max_input_bytes`. `input` is `writeOnly` in `openapi.json`. (T-013)
- **Added** agent-side confidential run input: a run request's `input` (named string fields) is validated and size-capped (`max_input_bytes`) before any hook or exec, and a script's `scripts.conf` entry chooses delivery with `input=context|raw|raw:<name>|fields` (stdin JSON gains `input`; stdin is one field; or 0600 files in a private 0700 directory at `$CTRL_EXEC_INPUT`, removed after the run, the context moving to `$CTRL_EXEC_CONTEXT` without the caller's token, since the environment reaches every program the script starts). Direct mode (no executor) delivers all three; input never reaches argv, hooks, logs or async records; `/capabilities` reports each script's mode; a bad `input=` value skips the script with a reason. With an executor configured, a run carrying input is refused (`input requires executor support; not yet available`) until the executor carries it. (T-013)
- **Changed** docs/DOCKER.md and the website Docker pages (docs): the container build is now `debian:trixie-slim` plus the release debs (the Alpine tarball build is gone), and keeps the packages' privilege split - root entrypoint, `setpriv` drop to `ctrl-exec`, `cap_drop: [ALL]` with five capabilities back, a fixed `ctrl-exec` UID, and a certificate-maintenance loop in place of the deb timer. New sections on pinning `dispatcher_id`, volume layout and `userns-remap` ownership, host hardening, and upgrading a container to the `/etc/ctrl-exec-dispatcher` config directory (the `/etc/ctrl-exec` fallback and symlink go in 0.14). Corrects `api_auth_default` (it applies only when no `auth_hook` is configured), the agent container (no executor in a container, an `agent-state` volume for the trusted-dispatcher map, serving as the unprivileged user, and no `kill -HUP 1`), and the pairing flow (the agent waits for approval and carries on to serve). (T-012)
- **Fixed** a fresh dispatcher install authorised every API request: the seeded `ctrl-exec.conf` named the seeded example `auth-hook` (which ends `exit 0`) as active, so `api_auth_default = deny` never applied. `etc/ctrl-exec.conf.example` now ships with `auth_hook` commented out (with how to enable it), so a new install denies API requests until the operator writes a hook or sets `api_auth_default` deliberately; the example hook is still seeded as a file to copy, but inactive. Upgrades never overwrite an existing `ctrl-exec.conf` (it is a conffile), so a host whose conf already names the seeded hook is unchanged: check `auth_hook` and replace the hook if you never edited it. `ced` (CLI) is unaffected. New `t/conf-example-auth.t`. docs/INSTALL.md, API.md, DOCKER.md, README and the website are corrected. (T-046)
- **Changed** a real `/etc/ctrl-exec` directory is now refused instead of silently handled. `Exec::DispatcherConfig::conf_dir()` no longer falls back to it when the new directory is missing, and no longer prefers the new directory when both exist (either let the dispatcher run on a seeded or empty config - an allow-all hook, or a second CA - while the real config sat at the old path, as in a container with the volume still mounted there). If `/etc/ctrl-exec` exists and is not the migration symlink to `/etc/ctrl-exec-dispatcher`, `ced` (every mode) and `ctrl-exec-api` print a message naming both paths and how to migrate (move the directory, fix the paths in `ctrl-exec.conf`; in a container change the mount) on stderr, log `ACTION=config-dir RESULT=refused`, and exit 78; `ctrl-exec-api.service` gains `RestartPreventExitStatus=78`. The symlink the installers leave is accepted, and a host with neither directory is a fresh install. The postinst and `install.sh` messages for "both exist" now say the dispatcher will refuse until the old one is merged and removed. The symlink is still removed in 0.14; the "old-path fallback until 0.14" described in the T-008 bullet and in the upgrading, Docker and troubleshooting docs no longer exists, and those docs are corrected. The Docker entrypoint check is kept as an early stop. `t/dispatcher-conf-dir.t` is rewritten. (T-047)
- **Fixed** the executor's `scripts.conf` parser now reads `input=` as the agent does: an invalid value (not `context`, `raw`, `raw:<name>` or `fields`) skips the script in both, where the executor used to run it. The last `profile=` on a line now wins in the executor as in the agent; an earlier over-long `profile=` made the executor skip a line the agent ran. Conformance fixtures cover both, and `ctrl-exec-executor resolve` reports the input mode. (T-013)
- **Added** confidential run input through the executor: all three `input=` modes now work with `executor_socket` set, and the agent's refusal (`input requires executor support; not yet available`) is gone. The agent sends a versioned frame (v2) carrying the input fields and the `CTRL_EXEC_CONTEXT` JSON (without the caller's token); the executor takes the mode from its own `scripts.conf`, bounds the input itself (32 fields, valid names, 4 MiB), feeds a `raw` field to stdin, and for `fields` creates `/run/ctrl-exec-agent/input/<reqid>.<random>` as root before the fork (0700, files 0600 via `openat` `O_EXCL|O_NOFOLLOW`, then `fchown` to `run_as`), readable read-only inside a `writable` profile, removed once the action is reaped however it ended and swept at start-up after a crash, without following links. Values never reach argv, other environment, logs or error replies. An executor older than the agent refuses a v2 frame without running it, reported as `ctrl-exec-executor does not support run input: it is older than this agent ...`; runs without input of `input=context` scripts keep the old frame and work with either. (T-013)
- **Fixed** an action run by the executor inherited the executor's connection to the agent (the socket came from `accept` without close-on-exec), so a script, as its `run_as` user, could write its own result frame to the agent - any exit status and output - or corrupt the real one. The connection is now accepted with `SOCK_CLOEXEC`, the listening socket and the config files are opened close-on-exec, and the action's process closes every fd from 3 up just before `execve` (`close_range`, with a `/proc/self/fd` fallback), so the action holds only stdin, stdout and stderr, in every input mode (`context`, `raw`, `fields`) and under `run_as`; an fd the executor inherited from whatever started it no longer reaches the action either. New `t/exec-fd.t` and `t/exec-fd-root.t`. (T-051)
- **Fixed** the executor ignored a failed drop of the capability bounding set. Without `CAP_SETPCAP` (a container started with `cap_drop: [ALL]`) the bounding set kept the container's capabilities, and a root profile with `no_new_privileges = no` regained them all at exec, `CAP_SYS_ADMIN` included, although it declared none. A capability that is in the bounding set and cannot be dropped now fails the run: `cannot drop CAP_... from the capability bounding set ... (the executor needs CAP_SETPCAP)`. On a host the executor is full root and nothing changes. Failures that already failed closed now say why: a profile `caps` entry the executor does not hold (`profile '<name>' keeps CAP_..., which the executor does not hold`), the per-run mount namespace (naming `CAP_SYS_ADMIN`, or a security profile that refuses `mount`), and `setgroups` before `run_as` (no message before). (T-048)
- **Changed** the agent container runs the executor: the entrypoint in docs/DOCKER.md starts `ctrl-exec-executor` as root and the agent as `ctrl-exec-agent`, leaves `executor_socket` on, and stays as a small supervisor, so per-script profiles are enforced in a container. A `HUP` (`docker compose kill -s HUP agent`, or `kill -HUP 1` inside) now reloads the agent: the entrypoint passes it on as the agent's own user, which needs no `CAP_KILL`, where Docker's init used to exit and restart the container. The agent service adds `SETPCAP`, `SYS_ADMIN` and `apparmor=unconfined`; a new *Executor capabilities* table says what each capability is for and what fails without it. The T-012 advice to run the agent on the host for profiles and to restart the container to reload is gone. The script-adding recipe now makes the script reachable by the default profile's `run_as = nobody`. The Dockerfile and entrypoint are also in `tools/agent-container/`, with `test.sh`, a container test (build from HEAD, pair, run_as, an unenforceable profile, reload, missing capabilities); `t/docker-agent-files.t` keeps the guide and the files identical. (T-048)
- **Added** the API can listen on a unix socket for same-host callers (`api_socket`, created mode 0660 in `api_socket_group`, default the API's own group), alone (`api_port = off`) or beside TCP, so file permissions decide who may call and confidential input need not cross TCP. Socket callers pass the same auth hook, recorded as `source_ip` `unix:<path>` with the caller's kernel-reported uid in `peer_uid` / `ENVEXEC_PEER_UID` (empty for TCP). A stale socket left by a crash is replaced; a live socket or a path that is not a socket (file, directory, symlink) stops start-up untouched; the file is removed on stop. The systemd unit now creates `/run/ctrl-exec-api` (`RuntimeDirectory`) for it; the socket stays off by default. (T-013)
- **Changed** the API refuses to start (exit 78) on a listener configuration it would otherwise guess at: no listener, `api_tls_cert` without `api_tls_key` or the reverse, a TLS file it cannot read or a certificate and key that do not load (previously it silently fell back to plain HTTP), `api_tls_cert`/`api_tls_key` with `api_port = off`, an `api_port` that is not a port number or `off`, or an unknown `api_socket_group`. The TLS handshake now runs in the per-request child, so a slow TLS client no longer stalls the accept loop, and the "listening on" lines are written at once rather than when stdout's buffer fills. Docs say confidential input should travel only over the socket or TLS, and that the API certificate is the operator's (one naming the API host, not `dispatcher.crt` or the ctrl-exec CA). (T-013)
- **Changed** the API TLS settings are renamed `api_tls_cert` / `api_tls_key`; the API refuses to start (exit 78) while the old `api_cert` / `api_key` are set, naming the new key, rather than accepting both. (T-013)
- **Fixed** an executor started with stdin, stdout or stderr closed let its next socket, pipe or directory take fd 0-2, where its error messages would go to that fd; it now fills a closed fd 0-2 with /dev/null before opening anything. (T-051)
- **Added** the unix-socket caller's uid is stored with the run (in its submitter record, only when the run came over the socket) and passed to the auth hook on a later `GET /status/{reqid}` as `owner_peer_uid` / `ENVEXEC_OWNER_PEER_UID` (null / empty for a TCP-started run or one recorded before this), beside the current caller's `peer_uid`, so a hook can allow "same uid as the starter". It is for hooks only: not returned in the status response, so the OpenAPI spec is unchanged. (T-052)
- **Added** the dispatcher's run store never writes the `stdout` or `stderr` of a per-host result marked `output_confidential`: a sync record keeps the exit status and metadata with the marker, and `aggregate` returns a freshly fetched confidential async result to its caller but stores it without the output. This is the dispatcher half of confidential output; agents mark results from the next change. Also, an agent's refusal of an async run (an error with no status) is logged by the dispatcher as `STATUS=error`, not `STATUS=accepted`; the run store and CLI already read it as an error. (T-053)
- **Added** `output=confidential` in the agent's `scripts.conf`: the script's stdout and stderr are returned to the caller in the synchronous response, marked `output_confidential: true`, and stored nowhere - the dispatcher's run store keeps the exit status and metadata only (`GET /status`, `ced status`), no log line carries the output, and an async run of the script is refused (an async result must be stored to be fetched later). `output=stored` is the default; any other value skips the entry (`its output mode '<value>' is not one of stored, confidential`) in both the agent and the executor, which parse it identically (t/exec-conformance.t). `/capabilities` lists each script's `output` mode. First use: cert-deploy's issuing script, whose output is the new private key. (T-053)
- **Changed** version skew for confidential output: the protection rests on the agent's declaration, since the dispatcher cannot tell that output is secret unless the result is marked. A result from an agent older than 0.13.0 carries no mark and is stored whole, as before; upgrade the agent and declare the script before relying on it. (T-053)
- **Fixed** (docs) the agent-script install recipe in INSTALL.md, DEVELOPER.md, the installer's next-steps hint, website/plugins.md and website/quickstart.md gave mode 750 `root:ctrl-exec-agent`, which the default profile's `run_as = nobody` cannot read, so the executor refused the run ("not executable by the profile's run_as user"). The recipe is now `install -o root -g root -m 755`, with the scripts directory opened to 755 (or a profile whose run_as user is in the group), matching DOCKER.md; SECURITY.md and REFERENCE.md say the same. New t/docs-script-install-recipe.t. (T-048)
- **Changed** the agent scripts directory and the demonstrator script are installed 755 `root:root` (install.sh and the deb postinst; was 750 `root:ctrl-exec-agent`), because the shipped default profile runs scripts as `run_as = nobody`, which could not enter the directory or read the script, so the executor refused them ("not executable by the profile's run_as user"). An upgrade (postinst, or re-running install.sh) opens a directory still at the old 750 `root:ctrl-exec-agent` and leaves any other mode alone; operator-added scripts are never touched. The install recipe in INSTALL.md, DEVELOPER.md, the installer hint, website/plugins.md and quickstart.md is now `install -o root -g root -m 755`, matching DOCKER.md. New t/install-scripts-dir.t and t/docs-script-install-recipe.t. (T-048)
- **Fixed** script output that is not valid UTF-8 made a direct-mode run fail while the agent encoded its reply, and output through the executor reached the caller encoded twice (`café` as `cafÃ©`); both paths now decode output as UTF-8 once and turn invalid bytes into U+FFFD.
- **Fixed** `ced pairing-mode` left its Ctrl-C handling in place after pairing stopped, so a second Ctrl-C while the dispatcher stopped its renewal check was ignored; the handling now ends with pairing mode.

## 0.12.4 — trusted dispatchers are no longer rate-limited; agent survives reload

- **Fixed (CRITICAL)** the recurring `exit -1 / "no response from child"` outage.
  The agent's per-IP volume limiter (default 10 connections / 60 s, then a 300 s
  block) counted the paired dispatcher's own connections - and every run, ping,
  result poll and discovery is a fresh mTLS connection - so roughly ten
  operations inside a minute from the one legitimate caller blocked it for five
  minutes, and the block was applied by closing the socket silently after the
  handshake. The accept loop now reads the peer certificate serial before the
  rate check and **exempts serials in the trusted-dispatcher map from the
  volume limit** (they are never counted). The probe limit (handshake failures),
  `max_children`, `allowed_ips` and the trusted-serial gate on every request are
  unchanged, so the limiter still guards against CA-signed-but-unpaired peers.
- **Changed** a volume/probe block to answer `HTTP/1.0 429 Too Many Requests`
  with `{status:"error", error:"rate limited", retry_after:<s>}` before closing,
  instead of a silent drop; the dispatcher maps a 429 to "agent rate-limited
  this dispatcher (HTTP 429) - ... pair it, or raise rate_limit_volume".
  `Exec::RateLimit::blocked_for` reports the remaining block time.
- **Fixed** the agent exiting its serve loop on *any* failed accept. The failure
  branch asked the listening socket for its `peerhost` (always `ENOTCONN`) before
  testing `$!`, so a stranger's bad TLS handshake, or the `EINTR` a SIGHUP reload
  produces (Perl installs handlers without `SA_RESTART`), was logged
  `accept-fatal` and stopped the agent - with no respawn under OpenRC, and
  `rc-service ctrl-exec-agent reload` / `rotate-serial` triggering it. errno is
  now captured first and classified by `Exec::Agent::Server::accept_failure_action`:
  `EINTR`/`EAGAIN`/`ECONNABORTED` retry, only `EBADF`/`EINVAL`/`ENOTSOCK` are fatal,
  everything else is a handshake failure. Twenty consecutive failures add a
  50 ms pause so a broken listener cannot spin.
- **Fixed** a per-connection memory leak in the agent parent: `peer_serial` never
  `X509_free`d the counted reference from `get_peer_certificate` (~230 MB RSS
  after two weeks of dashboard polling). Also stopped recording connection
  timestamps when `rate_limit_disable` is set (nothing pruned that list).
- **Changed** the dispatcher fan-out so a lost worker is self-describing:
  `no response from child` now carries why - `worker killed by signal N`,
  `worker exited N with no output`, `worker died: <message>`, `waitpid: <errno>`.
  The worker ignores SIGPIPE, resets the inherited INT/TERM handlers (which
  exited 0 silently) and runs under `eval`; the parent keeps each child's wait
  status and reports outstanding workers if `waitpid` fails instead of
  dropping them. Agent response bodies are decoded through `_json_hash`, so a
  non-object JSON body is `invalid JSON response` rather than a die in the worker.
- **Fixed** docs: the agent key is `rate_limit_disable` (TESTING.md said
  `disable_rate_limit`, which `Config.pm` never read); REFERENCE.md documents the
  trusted-dispatcher exemption and the 429 reply.
- **Added** tests: `t/agent-accept.t` (accept-failure classification and the
  `peerhost`-sets-errno trap), fan-out failure reasons, `blocked_for`, the 429
  phrase and transport mapping, and a non-object 200 body in `_dispatch_one`.
- **Fixed** `make-release.sh` shipping the previous release's `VERSION` in the
  tarball (`ctrl-exec-0.12.3.tar.gz` carried `VERSION` 0.12.2, so agents installed
  from it reported 0.12.2): the file was staged from the tree before the script
  advanced it. It is now stamped into the staged tree, and the script reads
  `VERSION` and `sbom.json` back out of the finished tarball (and `Version` from
  each `.deb`) before writing the `.sha256`, stopping before any commit, tag or
  push on a mismatch.
- **Fixed** the intermittent `exit -1` / `executor closed before responding` on
  runs through the executor (T-034; about 2-10% of runs, serialised or
  concurrent). The executor's per-connection handler writes the request context
  to the action's stdin after fork; when the action had already exited without
  reading stdin (any short script that ignores its context), that write hit a
  pipe with no reader and the default SIGPIPE killed the handler before it
  wrote a response. Whether the action won the race decided each run. The
  handler now ignores SIGPIPE, so the write fails with `EPIPE` and the run's
  real exit status and output are returned. The action is reset to the default
  SIGPIPE disposition before `execve`, so it starts with `SIG_DFL` whatever the
  executor was started with (under systemd's default `IgnoreSIGPIPE=yes`,
  actions previously inherited `SIG_IGN`). Nothing else at the privilege
  boundary changed: request parsing, re-derivation from root-owned config and
  the privilege-drop order are as before. Test: `t/exec-sigpipe.t`.
- **Changed** the dispatcher so a result with `exit -1` always names its cause
  in `error`. The agent reports its own failures (executor unreachable or
  closed, fork/pipe failure) in `stderr` only, so callers saw `exit -1` with an
  empty `error`. `_dispatch_one` and `_result_one` now copy the `stderr` text
  into `error` when the agent gave none; `stdout` and `stderr` are unchanged,
  and results with a script's own exit code are untouched. Tests in
  `t/engine.t`; API.md describes `exit -1`.

## 0.12.3 — fix agent crash on every connection (0.12.2 regression)

- **Fixed (CRITICAL)** the agent crashing its main process on every accepted
  connection. The 0.12.2 refactor that moved the request handlers into
  `Exec::Agent::Server` left the accept loop's pre-fork serial read calling
  `_peer_serial` unqualified, so it resolved to `main::_peer_serial` (undefined)
  and died with `Undefined subroutine &main::_peer_serial` the instant a
  connection arrived - taking down the listener and looping under systemd
  restart. The sub is now the public `Exec::Agent::Server::peer_serial` and the
  bin calls it through the package qualifier. Any agent on 0.12.2 was unable to
  serve a single request (run/ping/discovery all failed); 0.12.3 restores
  service. No config change required.
- **Added** a static regression guard (`t/agent-serve-symbols.t`) asserting the
  agent bin makes no unqualified call to any `Exec::Agent::Server` sub - the
  exact class of error `use strict` and `perl -c` cannot catch because an
  undefined-subroutine call only fails at runtime, on a live connection.

## 0.12.2 — security & correctness review hardening

- **Changed (BREAKING)** the security-profile model: there is no longer an
  implicit built-in `default` profile. Previously a script with no `profile=`
  annotation ran under a built-in default whose empty `run_as` meant it executed
  as **root** (capless) - the opposite of the "restrictive default" the docs
  described, so enabling the executor escalated unannotated scripts to root.
  Now every profile, including `default` (the name an unannotated script resolves
  to), must be defined in `agent.conf`; an undefined profile is refused
  (fail-closed) rather than run under an implicit context. The shipped
  `agent.conf.example` defines `[profile default]` as `run_as=nobody`, and the
  rule is uniform: nothing runs as root unless a profile sets `run_as=root`.
  UPGRADE: an existing `agent.conf` with unannotated scripts and no
  `[profile default]` will refuse to serve until that block is added (the error
  names exactly what to add) or those scripts are annotated.
- **Fixed** a trust-key divergence in cert-serial canonicalisation: the colon
  and plain-hex branches stripped leading zeros differently, so the same serial
  could canonicalise two ways and a revoked/trusted entry pasted from
  `openssl x509 -text` (colon form) could silently fail to match. One strip now,
  used at every read.
- **Fixed** reqid/nonce generation to route every value through the single
  `/dev/urandom` reader, dropping a non-cryptographic `rand()` fallback.
- **Changed** input hardening: `allowed_ips` octets are validated and
  canonicalised at config load (a zero-padded entry no longer fails open by never
  matching), and the unauthenticated pairing port caps the request body before
  reading it (memory-exhaustion DoS).
- **Changed** rate-limit eviction to an amortised single pass instead of an
  O(n log n) sort on every accept; rotation now batches its registry writes under
  one lock; and `list_hostnames` reads the registry from directory entries
  instead of decoding every record.
- **Added** behaviour tests for the root executor's privilege drop (cap masks,
  run_as, no_new_privileges, out-of-range run_as), the previously-untested shared
  utility modules, and made several masked/always-skipping tests able to fail.
- **Fixed** `make-release.sh` to tag the release commit rather than the prior
  HEAD (every tag had been one commit too early; `v0.12.0`/`v0.12.1` corrected).
- **Changed** documentation: removed references to a removed `Exec::Output`
  module and `request_pairing`, corrected install/source paths, completed the
  module reference, and documented `max_parallel`.

## 0.12.0 — unprivileged API, enforced writable profiles, hands-free certs, hardening

- **Changed** the HTTP API server to run as a dedicated unprivileged `ctrl-exec`
  service user instead of root. The dispatcher private key is now owned by that
  user (still `0600`, so the `ctrl-exec` group / operators still cannot read it -
  they continue to `sudo` for `run`/`ping`); the API reads its own key to dispatch
  and is in the `ctrl-exec` group for the runtime dirs. It never needs the CA key:
  `/ping` no longer triggers cert renewal (renewal would need to sign), so
  renewal is driven solely by `ced maintain` (root timer). An RCE in the
  network-facing JSON server is therefore not root and cannot sign certificates.
  The installer/postinst create the user and migrate the key ownership;
  `setup-ctrl-exec` and `rotate-cert` chown newly generated keys. The shared
  runtime dirs are setgid (`2770`) and lock files `0660` so the root CLI and the
  unprivileged API can share the registry, run records, and locks.
- **Changed** the bundled OpenAPI spec to match the code: added the `/`,
  `/openapi.json`, `/openapi-live.json` routes, `RunResponse.reqid`,
  `HostCapabilities.tags`/`reported_hostname`, 404s on `/run` and `/ping`, the
  `/status` `Authorization` header + owner-gating, and a polymorphic
  `StatusResponse.hosts`; refreshed the stale version examples.
- **Added** a concurrent-handler cap to both servers: the API (`api_max_children`,
  default 64) returns `503` above the cap, and the agent (`max_children`, default
  256) closes the connection above the cap on top of its per-IP rate limit -
  bounding an aggregate connection flood.
- **Changed** the agent renew timer to decide via `ctrl-exec-agent cert-staged`
  (which reads `cert_staging_path` from config) instead of a hard-coded path, so a
  staging-path override is honoured. Added `cert-promote`/`maintain` failure
  patterns to the LOGGING alert reference.
- **Fixed** the out-of-the-box auth default: the shipped dispatcher config
  activates `auth_hook`, but the example hook ended in `exit 1` (deny all), so a
  fresh install **denied** every `run`/`ping` - the quickstart could not work. The
  example now defaults to `exit 0` (allow), so ctrl-exec runs out of the box; the
  exposure is bounded (the API binds 127.0.0.1, agents are mTLS-gated), and the
  commented examples remain for production rules. README note corrected.
- **Added** per-profile read-only filesystem enforcement (the `writable` field is
  now enforced, no longer parsed-but-inert): when a profile sets `writable`, the
  executor makes the action's whole filesystem read-only except those paths (a
  per-script `ProtectSystem=strict`), with a private `/tmp`. Writes elsewhere fail
  with `EROFS` even when the profile runs as root. Opt-in; requires a Linux kernel
  >= 5.12 and fails closed on older kernels. Validated on-host.
- **Changed** the agent's ping response to report `staged` (a renewed cert is
  staged, awaiting restart), and the dispatcher to skip re-renewal while one is
  staged - the live expiry still reads old until restart, so this avoids
  re-signing/re-staging redundantly on every maintenance run.
- **Changed** the OpenWrt/procd init script to gate startup on pairing state (new
  `ctrl-exec-agent paired` check): an unpaired agent logs once and stays down
  instead of respawning forever (procd has no `RestartPreventExitStatus`).
  Documented a `cert-staged` cron snippet for hands-free renewal adoption there.
- **Changed** the three servers (API, agent, pairing) to share one `Exec::Http`
  response writer, removing the drifted hand-rolled status-phrase tables (413 and
  500 were inconsistent across them). No wire change beyond the phrase text.
- **Fixed** a registry lost-update: concurrent read-modify-write of an agent
  record (serial status, expiry, tags, and `edit_agent` - which a maintenance run
  or an operator edit can touch at once) could drop a change. A registry-wide lock
  now serialises all of those updates.
- **Changed** the agent accept loop to reap all finished children per accept
  (not one), so request handlers cannot accumulate as zombies under bursty load -
  matching the API and executor loops.
- **Changed** `GET /status/{reqid}` so it can be owner-gated. The API now records
  who submitted each run and runs a `status` auth-hook check that exposes the
  reqid and the submitter (`ENVEXEC_REQID`, `ENVEXEC_SUBMITTER[_IP]`); the caller
  authenticates with `Authorization: Bearer`, an unauthorised request gets `404`
  (no existence disclosure), and the submitter is stripped from responses. With
  no hook, the unguessable reqid remains the capability. Previously any caller
  holding a reqid could read any run's output and a hook could not gate it.
- **Added** hands-free agent-cert renewal, with the trust boundary drawn at the
  private key. The agent implements `POST /renew` (CSR from its existing key -
  key continuity preserved) and `POST /renew-complete`: it validates the signed
  cert (verifies against its CA and that the public key matches its own key) and
  stages it in its own writable state dir - the cert is public material the agent
  owns, so no privileged writer is involved. A renewed cert is promoted into the
  root-owned live path by a root `ExecStartPre` step at the next agent start, and
  adopted on restart. The dispatcher binds the signed CSR's CN to the agent's
  identity. Previously the dispatcher posted `/renew` but the agent had no
  handler, so renewal silently 404'd and certs never renewed.
- **Added** `ctrl-exec-maintenance.timer` (dispatcher, root) running `ced
  maintain` - pings all agents (triggering due renewals) and rotates the
  dispatcher's own cert - and `ctrl-exec-agent-renew.timer` (agent) that restarts
  the agent to adopt a staged cert. Both enabled on install, so cert lifecycle is
  hands-free with no operator action. `list-agents` now shows a DAYS LEFT column.
- **Changed** the default agent config to set `executor_socket` (run through the
  privileged executor, the recommended posture for per-script profiles); comment
  it out only where `--async` is needed.
- **Changed (behaviour)** the environment an allowlisted script runs in is now
  sanitised. The script no longer inherits the agent's full environment: the
  front-end keeps a small whitelist (`PATH` reset to a safe default, plus
  `HOME`/`LANG`/`TZ`/...), and the privileged executor passes a clean `PATH`
  only. This removes `LD_PRELOAD`/`LD_LIBRARY_PATH`/`BASH_ENV`/`IFS`/`PERL5LIB`
  as passthrough attack surface against shell/script interpreters. Request
  context still reaches scripts on stdin (JSON), never via the environment. A
  script that relied on an inherited variable must now be given it explicitly.
- **Added** request-size limits to the dispatcher HTTP API (`413` body /
  `431` headers), mirroring the agent, so an oversized `Content-Length` or a
  header flood cannot exhaust memory before the auth gate runs.
- **Added** CSR validation in the CA signer: reject keys under 2048-bit and weak
  (MD5/SHA-1) self-signatures, verify the CSR's self-signature, and optionally
  bind the subject CN to an expected identity. Closes the "sign any subject with
  any key" signing-oracle gap.
- **Added** `auth_hook_timeout` (default 10s): a hung auth hook is killed and
  the request fails closed instead of wedging the request handler indefinitely.
- **Changed** `/capabilities` to fail closed when no dispatcher is trusted (the
  trusted-dispatcher map is empty), matching `/run`, `/ping`, `/rotate-serial`
  and `/result`. An unpaired or map-less agent no longer discloses its allowlist.
- **Changed** the executor to reject an out-of-range numeric `run_as` (at config
  load and at apply time) instead of silently truncating it, which could land on
  uid 0 (root).
- **Changed** CA/dispatcher private-key generation to run under a tight umask so
  a key is never momentarily group/world-readable between creation and `chmod`.
- **Added** bounded fan-out concurrency to the dispatcher (`max_parallel`,
  default 64): a large fleet no longer forks one TLS client per host all at once,
  which could exhaust file descriptors before the host cap.
- **Changed** `bin/ctrl-exec-agent` into a modulino (`main() unless caller`) so
  its request handlers can be loaded and unit-tested directly.

- **Changed** agent startup so a configuration error (parse error, invalid
  capability, undefined profile, ...) prints one clear message naming the file
  and the problem, then exits `EX_CONFIG` (78). The unit lists 78 in
  `RestartPreventExitStatus`, so systemd reports a single failure instead of
  respawning into a restart loop that buries the real error ("restart counter is
  at 134"). Previously these died as a generic exception (255) and looped.
- **Changed** the "invalid capability" error to detect the common mistake of an
  inline `# ...` comment on a value line (the format supports whole-line comments
  only) and say so, instead of the bare "invalid capability '#'".
- **Added** `docs/TROUBLESHOOTING.md` - use cases and troubleshooting for a
  running agent: the profile mental model (executor required, one profile per
  script, executor/`--async` exclusivity), the deploy-and-restart use case,
  capability-bounded root (`run_as = root` grants only the listed caps, no
  implicit `CAP_DAC_OVERRIDE`), config-file pitfalls (inline comments, the
  exit-78 behaviour), upgrade/install messages (`libc6` floor, `-dbgsym`,
  automatic restart), diagnosing a failed start, and rotation under the executor.

## 0.11.1 — built-in cert rotation; clearer upgrades and profiles

- **Added** built-in cert rotation. The agent handles dispatcher-serial rotation
  as a first-class control-plane operation (`POST /rotate-serial`) in the
  front-end, replacing the `update-ctrl-exec-serial` script. This makes seamless
  rotation work under privilege separation (the executor keeps the trust map
  read-only for every action, so a script could not write it; the front-end can)
  - so rotation and the executor now coexist with no re-pairing. It is also more
  secure: the dispatcher identity is derived from the caller's authenticated
  serial, never sent in the request, so a dispatcher can only add/retire serials
  under its own identity. Gated by the trusted-dispatcher check + the auth hook
  (action `rotate`). Each new serial is authorised by the currently-trusted one,
  chaining back to the original human-supervised pairing.
- **Removed** the `update-ctrl-exec-serial` script and everything that shipped or
  referenced it (packaging, installer, allowlist example, SBOM, docs). Rotation
  needs no allowlist entry. If you had it in `scripts.conf`, the entry is now
  inert and can be deleted.
- **Changed** profile documentation and added a startup warning: profiles are
  enforced only by the executor; without `executor_socket` a `profile=` is parsed
  but not applied (scripts run as the unprivileged agent user). Documented that a
  script runs under exactly one profile, that `executor_socket` and `--async` are
  mutually exclusive, and pointed at `capabilities(7)`.
- **Fixed** a spurious `Failed to stop ctrl-exec-exec.service: Unit not loaded`
  warning on upgrade from a pre-privsep version (`--no-stop-on-upgrade` on the
  units; our postinst owns the restart). The install always succeeded; only the
  message was alarming.
- **Changed** the postinst upgrade restart to print an informative line per
  service - "restarted <svc> to apply the upgrade" or "<svc> is not running - no
  restart needed" - instead of being silent.

## 0.10.1 — packaging fixes for the compiled executor

- **Fixed** the agent `.deb` requiring `libc6 (>= 2.38)`, which blocked install on
  Debian 12 / Ubuntu 22.04 (glibc 2.36). The executor used `strtol`, which under
  `_GNU_SOURCE` redirects to the C23 `__isoc23_strtol` (a glibc-2.38 symbol);
  replaced it with a manual integer parse. The package's libc floor is now 2.34.
- **Removed** the automatic `-dbgsym` package (`dh_strip --no-automatic-dbgsym`):
  ctrl-exec does not distribute debug symbols. Also dropped the
  `ctrl-exec-agent-dbgsym` that the 0.10.0 release accidentally committed to
  `dist/`. Rebuild with `DEB_BUILD_OPTIONS=nostrip` if you need symbols.
- **Fixed** the upgrade restart not covering the executor: the agent postinst
  now restarts both `ctrl-exec-exec.service` and `ctrl-exec-agent.service` (each
  only if already running). Previously only the Perl front-end was restarted, so
  after an upgrade the **changed C executor** kept running its old code until a
  manual restart - the symptom under privilege separation.

## 0.10.0 — privilege separation and per-script profiles

- **Added** privilege separation. A new root, no-network executor
  (`ctrl-exec-exec`) runs allowlisted scripts; the unprivileged agent front-end
  hands it authorised requests over a peer-cred-checked unix socket. The
  executor re-derives the path and profile from its own root-owned config (it
  trusts nothing in the message) and applies the profile - mount namespace with
  the control/state dirs read-only, capability set, `run_as`, and
  `no_new_privileges` - before exec. Opt-in via `executor_socket` in agent.conf.
- **Added** per-script security profiles: `[profile <name>]` blocks in agent.conf
  (`run_as`, `caps`, `writable`, `no_new_privileges`) referenced from
  `scripts.conf` via `profile=<name>`. Unprofiled scripts use a restrictive
  default; an undefined profile is a fatal config error (fail-closed). A shared
  conformance test proves the C executor and the Perl front-end resolve the
  identical security decision for any config.
- **Removed** the interim filesystem sandbox (`sandbox`/`writable_paths`/
  `apply-config` and the `ProtectSystem=strict`-as-action-blocker default). It
  was a transitional mechanism; per-script profiles enforced by the executor
  replace it. Deployments that set `writable_paths`/`sandbox` should move the
  intent into a profile (those keys are now ignored).

## 0.9.3 — clearer dispatch errors

- **Changed** how the dispatcher reports a host it cannot reach: a raw LWP
  transport string (`500 Can't connect to host:7443 (Connection refused)`) is
  now translated into a status-like message — `host 'web01' did not resolve`,
  `… did not respond on port 7443 - connection refused (agent not running, or
  wrong port?)`, `… is unreachable`, `… connection timed out`, or `TLS handshake
  … failed`. Applies to run, ping, status, and capabilities. A genuine HTTP
  status (e.g. 403) is passed through unchanged, never mislabelled as a network
  fault.

## 0.9.1 — explicit serve mode

- **Changed** `ctrl-exec-agent` (`cea`) invoked with no mode: it now prints the
  usage summary and exits instead of defaulting to `serve`. A bare invocation
  previously launched the foreground server with no terminal output, which read
  as a hang. Start the server with an explicit `ctrl-exec-agent serve`; the
  systemd and procd units already do this, so service-managed agents are
  unaffected.
- **Added** a `--version` flag to `ctrl-exec-agent` (`cea`) and
  `ctrl-exec-dispatcher` (`ced`), printing the installed release version.
- **Fixed** `.deb` upgrades leaving old code running: the agent and dispatcher
  postinsts now restart `ctrl-exec-agent.service` / `ctrl-exec-api.service` on
  upgrade when already active, so the new code takes effect. Fresh installs are
  still left stopped (the agent cannot serve until paired), and a stopped or
  unconfigured service is not started.
- **Changed** the serve pre-flight to exit `78` (EX_CONFIG) instead of `1` when
  the agent is not paired, and added `RestartPreventExitStatus=78` to the unit.
  An enabled-but-unpaired agent now fails once with the "not paired" message
  instead of respawning every `RestartSec`. A genuine crash still restarts.
- **Changed** the agent to register its **fully-qualified** hostname at pairing
  (`Net::Domain::hostfqdn()`, falling back to the short name only when no domain
  is configured), instead of the bare short hostname. The short name does not
  resolve across subdomains, so a dispatcher on another network could not reach
  the agent by its registry name; the FQDN resolves consistently and survives a
  dispatcher move. Pairing now warns if no FQDN could be determined. Re-pair
  existing agents to update their registry key. The agent's self-reported host
  in run/capabilities responses is the FQDN too, for consistency.
- **Added** post-pairing enable/start instructions: a successful interactive
  pairing now prints the init-appropriate `enable`/`start` commands, since the
  agent is paired but not yet running.
- **Added** config-driven sandbox management for the agent. `agent.conf` now
  takes `sandbox = strict|moderate|off` (filesystem-protection level) and
  `writable_paths = …` (colon-separated dirs to open under the sandbox);
  `ctrl-exec-agent apply-config` renders these into a generated systemd drop-in
  (`…/50-ctrl-exec-sandbox.conf`) and reloads systemd, so writable-path policy is
  managed from `agent.conf` instead of hand-edited units (a restart applies it,
  since systemd builds the namespace before the agent starts). `serve` test-writes
  each `writable_paths` entry at startup and warns on any that are read-only,
  flagging an unapplied config. Default stays `strict`, matching the shipped unit.
- **Added** a `hint` field on run/result responses when a script's stderr shows
  "Read-only file system" (EROFS): it names the systemd sandbox as the cause -
  not permissions or a full disk - and points at `writable_paths`/`apply-config`
  and the new "Granting scripts a writable path" docs. The script's own stderr is
  left untouched.
- **Fixed** the dispatcher cert path being hardcoded as `dispatcher.crt` in the
  cert-lifecycle paths instead of honouring `ctrl-exec.conf` `cert`/`key` - the
  one place that names the cert the dispatcher actually presents. On a
  deployment whose cert is named otherwise (e.g. `ctrl-exec.crt`), `approve`
  read the serial from the absent `dispatcher.crt`, so the agent paired but
  trusted no serial and rejected every request as a "serial mismatch". The
  configured `cert`/`key` are now the single source of truth across `approve`
  (reads the serial there, and warns loudly if it cannot), `setup-ctrl-exec`
  (creates them there), and `rotate-cert` (re-keys them in place);
  `generate_dispatcher_cert` requires explicit paths with no hardcoded default.
  No migration code - existing deployments work as-is because every path now
  follows the config.
- **Fixed** a post-re-pair "serial mismatch": a running agent loads its
  trusted-dispatcher map once at startup (refreshed only on SIGHUP), so a
  re-pair that writes a new dispatcher serial to disk does not take effect until
  the agent is reloaded/restarted. The post-pairing message now detects an
  already-running agent and tells the operator to `systemctl restart
  ctrl-exec-agent` so the new certificate and serial are adopted.
- **Fixed** `serial_to_hex` not stripping an insignificant leading `00` byte in
  its plain-hex branch (the colon-separated branch already did). A dispatcher
  serial migrated from a pre-0.9.0 single-serial file as `00aabb...` never
  matched the live `aabb...` the agent reads from the cert, rejecting every
  request as a serial mismatch. All forms now canonicalise to minimal hex.
- **Added** pairing identity diagnostics on the dispatcher. When a request is
  queued the dispatcher now records a forward-confirmed reverse-DNS lookup of the
  agent's source IP (bounded by a short timeout). `list-requests` and the
  interactive approve prompt show the reported name, source IP, and reverse-DNS
  name, plus a recommendation (register the resolvable FQDN via `edit-agent
  --rename`, or fall back to `--lookup-by ip`) for when the reported short name
  will not resolve from the dispatcher - the common DHCP/network-managed-FQDN
  case. After approve, the dispatcher prints exactly what was registered (name,
  lookup_by, address) and the `edit-agent` command to change it without
  re-pairing (dispatch auth is CA-based, so no new certificate is needed).

## 0.9.0 — native multi-dispatcher and seamless rotation

Lands at the `release: 0.9.0` commit.

- **Added** native multi-dispatcher support: an agent serves more than one
  dispatcher. Trust is keyed on a per-dispatcher map (`<serial> <id>` entries)
  at `/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers`; pairing *appends* a
  dispatcher rather than replacing the previous one.
- **Added** a stable dispatcher identity (`dispatcher_id`, defaults to the
  dispatcher hostname), delivered at pairing and rotation; permission and
  attribution key on the identity, never the rotating serial.
- **Added** per-call attribution: a `DISPATCHER` field on agent
  run/ping/result/capabilities logs, and `ENVEXEC_DISPATCHER` /
  `ENVEXEC_DISPATCHER_SERIAL` in the agent auth-hook environment.
- **Added** an owner-partitioned async result store
  (`runs/<dispatcher-id>/<reqid>.json`) with an owner-gated `GET /result/<reqid>`
  — a run's output is returned only to the dispatcher that submitted it.
- **Changed** cert rotation to seamless add-then-remove against the trusted map
  (broadcast the new serial under the stable identity, keep the old through the
  overlap window, then retire it) — no re-pairing for reachable agents.
- **Changed** the trusted store from a single dispatcher serial in `/etc` to the
  agent-writable map in the state dir, so rotation can update trust in place;
  legacy single-serial installs are migrated automatically on upgrade.
- **Removed** the single-trusted-serial model (`ctrl-exec-serial`,
  `dispatcher_serial_path`, `load_dispatcher_serial`).
- **Fixed** packaging: the dispatcher `.deb` now ships
  `ctrl-exec-api.service` (the named systemd unit was previously dropped by
  `dh_installsystemd`).

## 0.8.x — MCP, async jobs, and the dispatcher/agent split

Release commits through `v0.8.14`.

- **Added** MCP integration: self-describing script schema sidecars in core and
  the `ctrl-exec-mcp` bridge plugin.
- **Added** asynchronous / long-running jobs — detached execution with a
  result store polled via `status` / `wait`.
- **Added** `.deb` packaging tracked in-repo with stale-version pruning.
- **Changed** naming throughout to the dispatcher/agent split: the control-host
  binary and package became `ctrl-exec-dispatcher`, cert files
  `dispatcher.{crt,key}`, cert CN `ctrl-exec-dispatcher`.
- **Changed** pairing/dispatch addressing: register the agent's real IP behind
  NAT, resolve every verb through one registry path, and fail loudly on unknown
  agents.
- **Added** pairing-mode session timeout and start/stop subcommands.

## 0.7.x and earlier

Release commits through `v0.7.7` and the `v0.1`–`v0.6` series. Foundational
work, summarised by theme (see the git log for per-tag detail):

- **Added** the core mTLS control plane: dispatcher CA, agent pairing with a
  6-digit confirmation code, and the allowlisted `/run` / `/ping` /
  `/capabilities` agent endpoints.
- **Added** the auth-hook trust model (default-deny), rate limiting, IP
  allowlisting, cert revocation, and the agent-side serial restriction on
  `/capabilities`.
- **Added** cert rotation with an overlap window, the agent registry, tag-based
  discovery, and the optional `ctrl-exec-api` HTTP API with an OpenAPI spec.
- **Added** the CycloneDX SBOM, the release tooling (`make-release.sh`), and
  brand repackaging.
