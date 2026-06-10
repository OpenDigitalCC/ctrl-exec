---
title: ctrl-exec - Testing Guide
subtitle: Running, understanding, and extending the test suite
brand: odcc
---

# ctrl-exec - Testing Guide

ctrl-exec has two levels of testing: unit tests that run entirely on the
control host without any network or agent involvement, and integration tests
that require at least one live paired agent.

Unit tests use `prove` and are safe to run at any time. Integration tests use
bash scripts and exercise real ctrl-exec-to-agent traffic over mTLS.

Manual checks that cannot be automated are documented separately in
`doc/MANUAL-CHECKS.md`.


## Unit Tests

Unit tests live in `t/` and test library modules directly. They require no
agents, no network, and no system services.

```bash
# Run all unit tests
prove -Ilib t/

# Run a single file
prove -Ilib t/rotation.t

# Verbose output
prove -Ilib -v t/auth.t
```

Each test file corresponds to one module:

| Test file | Module under test |
| --- | --- |
| `t/agent-config.t` | `Exec::Agent::Config` |
| `t/auth.t` | `Exec::Auth` |
| `t/auth-hook.t` | `Exec::Auth` (hook exit codes and env) |
| `t/lock.t` | `Exec::Lock` |
| `t/log.t` | `Exec::Log` |
| `t/output.t` | `Exec::Output` |
| `t/pairing-csr.t` | `Exec::Agent::AgentPairing` (key/CSR/nonce) |
| `t/pairing-ctrl-exec.t` | `Exec::Pairing` (queue/stale expiry) |
| `t/rate-limit.t` | `Exec::RateLimit` |
| `t/registry.t` | `Exec::Registry` |
| `t/registry-serial.t` | `Exec::Registry` (serial tracking fields) |
| `t/renewal.t` | `Exec::Engine` (cert renewal logic) |
| `t/rotation.t` | `Exec::Rotation` |
| `t/serial-normalisation.t` | `Exec::Agent::AgentPairing::serial_to_hex` |
| `t/update-ctrl-exec-serial.t` | `bin/update-ctrl-exec-serial` |

The `ctrl-exec-cli.t` and `engine.t` files cover CLI argument parsing and
dispatch logic respectively. `lock-holder.pl` is a test helper used by
`lock.t` to hold a lock in an independent process - it is not a test file.


## Integration Tests

Integration tests live in `t/integration/` and run real ctrl-exec commands
against live agents. They require a working ctrl-exec installation, at least
one paired agent, and the test scripts installed on each agent.

The tests are numbered and run in order. Each file is self-contained and can
also be run individually.


### Prerequisites

**1. Paired agents**

At least one agent must be registered and reachable. Two agents are needed for
parallel and multi-host tests; files that require two agents skip gracefully
when only one is available.

```bash
sudo ctrl-exec list-agents
sudo ctrl-exec ping <agent>
```

**2. Rate limiter raised**

The suite fires more than 10 connections to each agent, which exceeds the
default `volume_limit` and triggers a 5-minute block mid-suite. Before running,
disable rate limiting on every agent:

```bash
# On each agent host
echo "disable_rate_limit = 1" >> /etc/ctrl-exec-agent/agent.conf
systemctl reload ctrl-exec-agent   # or: /etc/init.d/ctrl-exec-agent reload
```

Remove the setting and reload when testing is complete. Rate-limit behaviour
itself is covered by `t/rate-limit.t` (unit) and `13-rate-limit-integration.sh`
(manual integration test, see below).

**3. Test scripts installed on each agent**

The integration tests call scripts by name via the ctrl-exec. These scripts
must exist in the agent's allowlist. Install them by running
`setup-agent-scripts.sh` on each agent host:

```bash
# Copy the script to the agent and run it as root
sudo bash t/integration/setup-agent-scripts.sh
```

This writes test scripts to `/opt/ctrl-exec-scripts/`, appends entries to
`/etc/ctrl-exec-agent/scripts.conf`, and sends SIGHUP to reload the allowlist.
It is safe to run multiple times.

Scripts installed:

| Name | Purpose |
| --- | --- |
| `env-dump` | Prints environment; confirms execution |
| `args-echo` | Echoes `argc` and each argument; used in argument tests |
| `exit-code` | Exits with the code passed as `$1`; used in exit code tests |
| `context-dump` | Reads stdin and echoes it; confirms JSON context forwarding |
| `big-output` | Produces N lines of output (default 500); used for output tests |
| `sleep-test` | Sleeps 30 seconds; used for lock tests |
| `lock-test` | Sleeps for `$1` seconds while holding a lock |
| `sleep-5` | Sleeps 5 seconds; completes within the default 10s timeout |
| `sleep-15` | Sleeps 15 seconds; triggers the 10s read timeout |
| `sleep-90` | Sleeps 90 seconds; completes within a 120s timeout |
| `daemonise-test` | Forks a background job and returns immediately |
| `allowlist-reload-check` | Added manually by test 09 to verify SIGHUP reload |
| `update-ctrl-exec-serial` | Serial update script; must be in allowlist for cert rotation |

The following are installed by `setup-agent-scripts.sh --install-auth-test` only,
and removed by `--remove-auth-test`.

| Name | Purpose |
| --- | --- |
| `auth-status-dump` | Outputs `/tmp/ctrl-exec-auth-test-status`; used by test 15 to retrieve hook-received context without SSH |

The accompanying hook (`/etc/ctrl-exec-agent/auth-context-check.sh`) is also
written by `--install-auth-test` and registered in `agent.conf` as `auth_hook`.
It records all `DISPATCHER_*` env vars to the status file on every call before
applying its known-value policy. `auth-status-dump` is always permitted through
so the test can retrieve results regardless of the policy outcome.

```bash
# Install
sudo bash t/integration/setup-agent-scripts.sh --install-auth-test

# Remove and restore agent.conf
sudo bash t/integration/setup-agent-scripts.sh --remove-auth-test
```


### Running the Suite

```bash
# Full suite
sudo bash t/integration/run-tests.sh

# Specific files only
sudo bash t/integration/run-tests.sh 01-security-boundary.sh 02-argument-integrity.sh

# Single file directly
sudo bash t/integration/01-security-boundary.sh
```

The runner discovers agents automatically via `ctrl-exec list-agents` and
pings each one before the suite begins. No agent names are hardcoded.

Output shows pass/fail/skip for each assertion within a file, followed by a
summary table at the end:

```
============================================================
Test file                         PASS  FAIL  SKIP  Status
--------------------------------  ----  ----  ----  ------
security-boundary                   19     0     0  PASS
argument-integrity                  43     0     0  PASS
...
Suite complete: 12 test files passed, 0 failed
============================================================
```

Exit code is 0 if all files passed, 1 if any failed.

The runner also monitors for rate-limit symptoms. If three or more consecutive
"no response from child" errors appear, a warning is printed identifying the
likely cause and the fix.


### Test Files

| File | What it covers |
| --- | --- |
| `01-security-boundary.sh` | Allowlist enforcement, script name validation, metacharacter rejection |
| `02-argument-integrity.sh` | Argument passing: spaces, quotes, metacharacters, path traversal, large arg lists |
| `03-partial-failure.sh` | Mixed success/failure across hosts, exit code propagation |
| `04-json-output.sh` | `--json` output structure for run, ping, and multi-host operations |
| `05-parallelism.sh` | Concurrent dispatch to multiple agents completes within expected time |
| `06-auth-context.sh` | Username, token, and reqid forwarded correctly to agent and script |
| `07-concurrency-lock.sh` | Lock conflicts detected and reported; second run completes after lock releases |
| `08-auth-hook.sh` | Auth hook called; exit codes respected (requires SSH to agent) |
| `09-allowlist-reload.sh` | New allowlist entry active after SIGHUP without restart (requires SSH) |
| `10-timeout-behaviour.sh` | Read timeout fires for slow scripts; long-running scripts complete within extended timeout |
| `11-api-status.sh` | API `/run`, `/ping`, `/status/{reqid}`, 404 on unknown reqid, multi-host result storage |
| `12-serial-check.sh` | Serial check on `/ping` and `/run`; 403 when serial file absent (requires SSH) |
| `15-agent-auth-context.sh` | Agent-side auth hook receives correct context fields (action, script, username, token, source IP); requires `--install-auth-test` setup — skips cleanly if not configured |

Files that require SSH to the agent host skip gracefully when SSH is not
available, reporting `SKIP` rather than `FAIL`. File 15 does not require SSH;
it uses a pre-installed hook and a dedicated allowlisted script to retrieve
results via dispatch.


### Environment Variables

`DISPATCHER`
: ctrl-exec binary name or path. Default: `ctrl-exec`. Override if the
  binary is not in PATH or you want to test a specific build.

`AGENT_SSH_USER`
: SSH username for tests that require remote access to agent hosts (files 08,
  09, 12). Default: `root`. Set to the appropriate user if root SSH is
  disabled.

`API_HOST`, `API_PORT`, `API_SCHEME`
: API server address for file 11. Defaults: `localhost`, `7445`, `http`.

`CURL_OPTS`
: Options passed to `curl` in API tests. Default: `-s -f`.


### Rate-Limit Integration Test (manual)

`13-rate-limit-integration.sh` is not included in the standard suite because
it deliberately triggers a 5-minute agent block. Run it separately after
restoring the default `volume_limit` on the agent (i.e. with
`disable_rate_limit` removed):

```bash
sudo bash t/integration/13-rate-limit-integration.sh
```

This verifies end-to-end rate-limit behaviour: block triggers at the threshold,
subsequent connections fail with the expected error, block expires and
connections recover.


## Install-Time Testing

The installer supports a `--run-tests` flag that runs the full unit test suite
against the installed files immediately after installation. This is the
recommended way to verify a new installation or upgrade.

```bash
sudo bash install.sh --ctrl-exec --run-tests
sudo bash install.sh --agent --run-tests
```

What `--run-tests` does:

- Checks that `prove` is available (from `libtest-simple-perl` on Debian)
- Runs `prove -Ilib t/` against the installed source tree
- Exits non-zero if any tests fail, causing the installer to report failure

The integration tests are not run by `--run-tests` because they require live
agents that are not available at install time. Run them separately once agents
are paired and test scripts are installed.

If `prove` is not installed, the installer prints the install command and
skips the tests rather than failing:

```
prove not found - install with: apt install libtest-simple-perl
Skipping unit tests.
```


## Test Library (`t/integration/lib.sh`)

All integration test files source `lib.sh`, which provides:

Agent discovery
: `discover_agents` queries `ctrl-exec list-agents`, pings each registered
  agent, and exports `AGENTS` (all reachable), `AGENT1` (first), `AGENT2`
  (second). Called once by the runner before any test files run; test files
  call it automatically when run standalone.

`require_agents <n>`
: Skips the entire test file if fewer than `n` agents are reachable. Place
  near the top of any file that needs a minimum agent count.

`assert_agents_reachable`
: Pings all `AGENTS` and stops if any have gone away since the suite started.
  Call this before each `describe` block in files that run multiple dispatches.
  In non-interactive mode (as in the runner), stops immediately on agent loss
  and prints a rate-limit diagnosis if the failure pattern matches.

`run_dispatcher <args...>`
: Wrapper around `sudo ctrl-exec`. Sets `OUT`, `ERR`, and `RC`. Increments
  per-agent and total connection counters. Calls `_check_rate_warning` after
  each invocation to detect rate-block patterns.

`describe <label>`, `pass <label>`, `fail <label> [detail]`, `skip <label> [reason]`
: Test output helpers. `fail` accepts an optional second argument for
  additional context printed below the failure line.

`summary`
: Prints the `Results: N passed, N failed, N skipped` line and returns 1 if
  any failures. Call once at the end of every test file.

Assertion helpers
: `assert_exit`, `assert_contains`, `assert_not_contains`, `assert_json_valid`,
  `assert_json_field`. See `lib.sh` for full signatures.

Connection tracking
: `_CONN_TOTAL` counts total `run_dispatcher` calls in the current process.
  Per-agent counts are stored in `_CONN_AGENT_<name>`. Used by `_check_rate_warning`
  to report the connection count at which rate-limit symptoms begin.


## Writing New Integration Tests

### Naming and placement

Name new files `NN-description.sh` where `NN` continues the existing sequence.
Place them in `t/integration/`. Add the filename to the `TESTS` array in
`run-tests.sh` to include it in the default suite run.

Tests that must be run manually (because they have destructive side-effects,
require special setup, or take a long time) should not be added to the `TESTS`
array. Document them in the file's header comment and in `MANUAL-CHECKS.md`.

### File structure

Every test file follows this structure:

```bash
#!/bin/bash
# NN-description.sh
#
# One-line summary of what this file tests.
#
# Requires: N reachable agent(s) minimum.
# Scripts needed: script-name-1, script-name-2.
# SSH required: yes/no (and why, if yes).

set -uo pipefail
source "${_LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}/lib.sh"

require_agents 1   # or 2 for multi-host tests

# ============================================================
assert_agents_reachable
describe "Short description of this group of assertions"
# ============================================================

run_dispatcher run "$AGENT1" script-name

assert_exit 0 "$RC" "clean exit"
assert_contains "$OUT" "expected output" "output contains expected string"

# ... more describe/assert blocks ...

summary
```

`set -uo pipefail` is required. `source lib.sh` must be the first non-comment
line after the set. `summary` must be the last line.

### Grouping assertions

Each `describe` block represents one logical scenario. Put an
`assert_agents_reachable` call before each block that dispatches to a live
agent - this ensures the test stops cleanly if the agent becomes unreachable
mid-suite rather than producing a cascade of confusing failures.

### SSH-gated blocks

Some tests require modifying agent-side state (config files, service reload)
and can only run if the test host can SSH to the agent. Use this pattern:

```bash
_SSH_USER="${AGENT_SSH_USER:-root}"
if ! ssh -o BatchMode=yes -o ConnectTimeout=3 \
        "${_SSH_USER}@${AGENT1}" true 2>/dev/null; then
    skip "Test description" \
        "cannot reach $AGENT1 via SSH as $_SSH_USER - set AGENT_SSH_USER or run locally"
    summary
    exit 0
fi

# SSH is available - proceed with the test
ssh "${_SSH_USER}@${AGENT1}" "sudo systemctl reload ctrl-exec-agent"
```

Always restore any state changed via SSH (config edits, service reloads) in a
trap or at the end of the block, so a test failure does not leave the agent in
a modified state.

### Counting connections

The rate limiter triggers at 10 connections per source IP within 60 seconds
(default). When writing a new test file, count the number of `run_dispatcher`
calls. If a single file sends more than 8-9 calls to the same agent, either
spread them across both agents using `"${AGENTS[@]}"`, or document that
`disable_rate_limit = 1` must be set before running the suite.

The connection counters in `lib.sh` will detect and warn about rate-block
symptoms automatically, but a well-designed test file should not rely on the
warning - it should stay within the threshold.

### Skipping vs failing

Use `skip` when a prerequisite is not available (fewer agents than needed, no
SSH access, API not running). Use `fail` when the system behaved unexpectedly.
A skipped test does not count as a failure and does not affect the file's exit
code. Excessive skips in the summary table indicate missing prerequisites, not
bugs.

### New scripts on agents

If a new test needs a script that does not already exist on agents, add it to
`setup-agent-scripts.sh`. Follow the existing pattern: write the script with
`cat > "$SCRIPT_DIR/name.sh" << 'EOF'`, set permissions with `chmod 0755`,
and add the allowlist entry with `append_if_missing`.

If the script is only needed for a specific optional test (one that modifies
`agent.conf` or installs a hook), add it under a named mode flag rather than
the default install path. See the `--install-auth-test` / `--remove-auth-test`
pattern for reference. The test file should detect whether the optional script
is present in the allowlist and skip cleanly if not, rather than failing.

Document the new script in the scripts table in this guide.


## Writing New Unit Tests

Unit tests use Perl's `Test::More`. Follow the existing files for structure.
The key conventions for this codebase:

Named parameters
: All public module functions use named parameters (`%opts` or `my (%opts) =
  @_`). Test calls must pass parameter names: `Registry::register_agent(hostname
  => 'host-01', ip => '10.0.0.1', ...)` not positional.

Private functions
: Private functions are prefixed `_` and are not part of the public API. Test
  them via the public interface where possible. Where the private function
  contains complex logic worth testing directly (as with `_serial_to_hex`),
  import it explicitly or call it as `Exec::Module::_function_name`.

Temporary directories
: Use `File::Temp::tempdir(CLEANUP => 1)` for tests that write files. Pass the
  temp dir as the relevant path parameter (e.g. `registry_dir => $tmpdir`).
  Never write to system paths in tests.

Test count declaration
: Declare the expected number of assertions with `use Test::More tests => N`
  or use `done_testing()` at the end. Undeclared counts make it harder to spot
  accidentally skipped assertions.

Reading source before writing tests
: Always read the current module source before writing tests for it. Verify
  parameter names, calling convention (named vs positional), and whether a
  function is public or private. The majority of test bugs in this codebase
  have been caused by assumptions about parameter names that did not match the
  actual module interface.
