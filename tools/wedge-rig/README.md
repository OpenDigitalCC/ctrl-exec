# wedge-rig: reproduction rig for the executor wedge (T-001 / R-007)

One Alpine 3.21 container holding `ctrl-exec-api`, `ctrl-exec-agent` and the
`ctrl-exec-exec` executor, as on the affected host (the api plays the
dispatcher role). Built from the **worktree source**: `up.sh` runs
`git archive HEAD` of the checkout and the Dockerfile runs the project's own
`install.sh --agent`, `--dispatcher`, `--api` (so the install path, file
layout and the compiled `ctrl-exec-exec` are what a real install produces;
commit your changes before `up.sh`, uncommitted edits are not in the image).

## What matches production, and what does not

- Alpine, three daemons in one container, executor enabled
  (`executor_socket`), a `run_as` profile (`rig`, run_as `ctrl-exec-agent`).
- `--ulimit nofile=1024:4096` on the container, inherited by all three daemons
  (override with `RIG_NOFILE`).
- Daemon users as installed: api as `ctrl-exec`, agent as `ctrl-exec-agent`,
  executor as root. syslog via busybox `syslogd`.
- Not OpenRC: the entrypoint starts the daemons directly (PID 1 is docker's
  `--init`, which reaps orphans). The limits, not the init system, are what
  matter here.
- Needs `--cap-add SYS_ADMIN --security-opt apparmor=unconfined` on the
  container: the executor creates a mount namespace per run (`unshare`,
  `mount`), which Docker's default profile forbids. This is container-scoped.
- Rate limiting is left at the agent defaults (10 connections / 60 s, 5 minute
  block), as on a stock host. Set `RIG_AGENT_EXTRA="rate_limit_disable = 1"` on
  `up.sh` to turn it off.
- Resource caps on the container: `--cpus=1 --memory=512m --pids-limit=2048`.
  The API is published on `127.0.0.1:17445` only.

## Commands

    ./up.sh                          # build and start; waits until paired and ready
    ./run.sh LABEL TOTAL CONC DELAY  # one measured burst (TOTAL 1..500, CONC 1..16)
    ./recover.sh LABEL [INT] [SETTLE]# poll with single runs until one succeeds
    ./down.sh [--image]              # remove the container (and the image)

    ./driver.pl --total 20 --conc 1 --delay 0 --out /path/runs.csv   # driver alone

`run.sh` starts the sampler inside the container, runs the driver, stops the
sampler, and copies everything to `out/LABEL/`. `out/` is gitignored; copy what
you want to keep.

## Output files (`out/LABEL/`)

`runs.csv`
: one row per run: `seq, epoch, time (UTC), dur_ms, http, exit, error, stdout`.
  The API returns HTTP 200 with the failure inside the result, so look at
  `exit` and `error`, not only `http`.

`samples.csv`
: one row per second from the in-container root sampler (`sampler.pl`).
  For each of `api`, `agent`, `exec` (master pid from `/run/rig/*.pid`):
  `_pid`, `_fds` (entries in `/proc/<pid>/fd`), `_kids` (direct children),
  `_desc` (all descendants), `_zomb` (zombie descendants), `_nofile` (soft
  limit). Then `all_procs`, `all_zomb` (container-wide), TCP socket counts by
  state from `ss -tan` (`ESTAB`, `TIME_WAIT`, `CLOSE_WAIT`, `FIN_WAIT`, `SYN`,
  `other_tcp`), and `exec_unix_conns` (non-listening unix sockets whose local
  address is the executor socket). Times are UTC, matching `runs.csv`.
  TCP counts include the docker-proxy leg from the host and the loopback legs
  inside the container.

`summary.txt`
: the driver's totals: ok, failed, first failure by start time, error strings.

`recovery.txt`
: from `recover.sh`: seconds from the start of polling to the first success.

`logs/`
: `syslog` (all daemon log lines for the burst, e.g. `rate-block`), and the
  daemons' stdout/stderr (`api.log`, `agent.log`, `exec.log`).

## Source files

`Dockerfile`, `entrypoint.sh` (config, CA, pairing, daemon start), `agent.conf`,
`scripts.conf`, `rig-hello.sh` (the allowlisted test script), `sampler.pl`,
`driver.pl`, `up.sh`, `down.sh`, `run.sh`, `recover.sh`.

## Attempt series

`series.sh PREFIX` runs the T-001 series on a default-config rig (bursts of 20,
50, 100, 200 serialised, then 40 each at concurrency 2, 4, 8, with idle
recovery between). `series-norate.sh PREFIX` runs the same sizes (plus 10) with
no recovery waits, for a rig started with
`RIG_AGENT_EXTRA="rate_limit_disable = 1" ./up.sh`. The default-config series
takes about 50 minutes because each wedge needs about 5 minutes idle to clear.
