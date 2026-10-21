# upgrade-rig: real estates upgraded from the last release (T-057)

Every other rig and test starts from a fresh, correct install, so none of the
0.13.0 upgrade failures showed before release. This rig installs the last
release's debs on the layouts real deployments use, upgrades them to the debs
under test with **no step in between** (the owner's ruling: real estates must
upgrade and run with no manual step; scripts run where they are), and checks
that the scripts still list and run.

Each scenario is a fresh set of containers. Hosts are Debian trixie with
systemd as PID 1, so the packages' maintainer scripts (unit migration,
`deb-systemd-invoke restart` on upgrade, daemon-reload) run exactly as on a
real host; the rig never restarts a service itself after an upgrade.

## Commands

    tools/upgrade-rig/run.sh                      # FROM 0.12.4, TO HEAD, all scenarios
    tools/upgrade-rig/run.sh --to 0.13.0          # the released 0.13.0 debs
    tools/upgrade-rig/run.sh --to claude/t-054-ownership-warn s1 s1b
    tools/upgrade-rig/run.sh --cli-to claude/t-058-cli-warnings-log s4
    tools/upgrade-rig/run.sh --cleanup            # remove everything, image included

Options:

`--from X`, `--to X`
: the deb sets. A release version (`0.12.4`) takes the debs committed in
  `dist/` at tag `v0.12.4`, byte for byte what was released. Anything else is
  a core commit-ish (branch, tag, sha), resolved in this checkout's repository;
  its debs are built once from that commit (`git archive` then
  `dpkg-buildpackage`, as `tools/agent-container/test.sh` does) and cached
  under `.build/debs/<sha>/`. Uncommitted edits are never in a build.
  Defaults: `--from 0.12.4`, `--to HEAD`.

`--cli-from R`, `--cli-to R`
: plugins commit-ishes for `ctrl-exec-cli`
  (`ce-api-plugins/ctrl-exec-cli/ctrl-exec-cli` in the plugins repository,
  `../plugins` beside core, or `PLUGINS_REPO`). `--cli-from` is the CLI baked
  into scenario 3's 0.12-era run-jobs image (default `v0.3.10`, the last
  plugins release before run input); `--cli-to` is used everywhere else
  (default `main`).

`--label L`
: name of the evidence directory, `out/L/` (default: the refs and a UTC time).

`--keep`
: leave the last scenario's containers up to inspect. The next run (or
  `--cleanup`) removes them.

Scenarios: `s1 s1b s2 s3 s4`, default all. Exit 0 only when every scenario
passed.

Needs docker (with compose), git and `dpkg-buildpackage` on the host; no root.
The first run builds the host image `ce-upgrade-rig:systemd` (network needed
for apt); it is kept and rebuilt only when `image/Dockerfile` changes.
Scenario 3 builds its dispatcher and run-jobs images from `debian:trixie-slim`
with apt each run (network needed) and removes them afterwards.

## Scenarios

| | Estate | Upgrade | Passes when |
|---|---|---|---|
| s1 | Agent, cloudient layout: scripts in `/srv/scripts` (2775 root:sysadmin), owned by `sysadmin`, one 775; profiles `cert-deploy` (run_as root, `CAP_CHOWN`, writable), `svc-restart` (run_as `ce-docker`), default (nobody); executor on. A dispatcher host beside it. | dispatcher, then agent: `dpkg -i` of the TO debs | units active; `self-check` lists all 3 scripts `[ok]`, none skipped; API discovery lists all 3 (no `(no scripts)`); each runs under its profile; no ownership warning text in run output |
| s1b | As s1, and `/srv` itself 2775 root:sysadmin | as s1 | as s1 |
| s2 | Dispatcher on the deb, config in `/etc/ctrl-exec` (0.12), token auth hook named in `ctrl-exec.conf`, API on all interfaces; stock agent stays on FROM | dispatcher only | `ctrl-exec-api` active and serving; `ced list-agents` and `ced run` work; the hook still allows the token and denies a wrong one; the maintenance unit runs |
| s3 | Cloudient-style dispatcher container: the 0.12-era compose layout (`estates/cloudient-dispatcher/`), data volume at `/etc/ctrl-exec`, the estate's entrypoint, run-jobs calling `http://dispatcher:7445` with a job that parses `ctrl-exec-cli ... 2>&1` as JSON; stock agent host on FROM | A: rebuild the dispatcher image with the TO debs, nothing else. B: the operator's documented compose change (`compose-0.13.yml`, `entrypoint-0.13.sh`) | `PASS` if A works; `OPERATOR-STEP` if only B works (A's failures are listed: what an operator meets without the change); `FAIL` otherwise |
| s4 | Dispatcher and agent hosts, FROM then TO; after the upgrade the agent adopts an `input=fields` script. A job pipes `--input-fields -` to `ctrl-exec-cli`, plain HTTP to `http://dispatcher:7445` (not loopback), captures `2>&1` and parses it with jq (the shape of `deploy-cert.sh`) | both hosts | the CLI exits 0, the captured output parses, result exit 0, the field reached the script, the value is not in the output. A control run of the same job on loopback must pass, so a failure is the plain-HTTP handling only |

Every scenario first checks that its estate works on FROM; if not it reports
`ERROR` (the estate, not the upgrade, is wrong). The estates are generic
stand-ins (no host names or real values) for the deployments recorded for
cloudient: the scripts only print who they run as and exercise their
profile.

## Evidence (`out/<label>/`)

`refs.txt` (what FROM, TO and the CLIs resolved to), `summary.txt` (the
table), and per scenario `<s>.log` (the ok / not ok lines) and
`<s>.evidence.txt` (maintainer-script output of each upgrade, self-check,
discovery and run output, journals or container logs). `out/` and `.build/`
are gitignored.

## Resources and what is left behind

Containers are limited: hosts `--cpus 0.5 --memory 384m --pids-limit 256`;
scenario 3's compose services keep the estate's own limits (dispatcher 1 CPU /
128 MB, run-jobs 0.25 CPU / 128 MB). One scenario runs at a time, at most three
containers. Hosts run in a private cgroup namespace with `SYS_ADMIN` and
AppArmor unconfined (what the executor needs anyway); the image's entrypoint
remounts the container's own cgroup subtree writable for systemd. No
`--privileged`, no host cgroup or `/dev/log` mount, no published ports.

Everything the rig creates is labelled `ce-upgrade-rig=1` and named
`ce-uprig-*`; it is all removed when `run.sh` exits (also on failure or
Ctrl-C), except the host image `ce-upgrade-rig:systemd` and the deb cache in
`.build/`. `run.sh --cleanup` removes the image too.

## Before a release cut

Run `tools/upgrade-rig/run.sh --from <last release>` on the release candidate
commit; every scenario must pass (docs/DEVELOPER.md, Release process).

## Files

`run.sh` (options, deb sets, image, scenario loop, summary), `lib.sh` (container,
install, pairing and assertion helpers), `image/Dockerfile` (the systemd host),
`scenarios/s*.sh`, `estates/` (the layouts: `cloudient-agent/`,
`cloudient-dispatcher/`, `jobs/`).
