#!/bin/bash
# Scenario 3: the cloudient-style dispatcher container. The estate's 0.12-era
# compose layout (estates/cloudient-dispatcher/compose-0.12.yml): the
# dispatcher image built from the release debs with the estate's own
# entrypoint, its data volume at /etc/ctrl-exec, and a run-jobs container that
# calls http://dispatcher:7445 with a job that parses `ctrl-exec-cli ... 2>&1`
# as JSON. A stock agent host (FROM) is paired with it.
#
# Phase A, the upgrade by swapping debs only: the dispatcher image is rebuilt
# with the TO debs, nothing else changes, and the stack is brought up again.
# Whatever fails here is listed: it is what an operator meets without the
# compose change.
# Phase B, the operator's documented 0.13 change (compose-0.13.yml and the 0.13
# entrypoint: data mounted at /etc/ctrl-exec-dispatcher, /etc/ctrl-exec/ paths
# in ctrl-exec.conf rewritten), on the same volumes.
#
# After a phase A that works, doctor (T-055) notes the config mounted in place
# with the remount as its fix, and phase B is run as that fix: doctor then has
# nothing to say about the directory.
#
# RESULT: PASS when phase A works (and phase B, doctor's fix, works too);
# OPERATOR-STEP when only phase B works; FAIL otherwise.
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` expands in the container
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")/..")
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

EST="$HERE/estates/cloudient-dispatcher"
STAGE="$HERE/.build/s3"
PROJ="$RIG_PREFIX-s3"
DISP="$PROJ-dispatcher-1"
JOBS="$PROJ-run-jobs-1"
AGENT="$PROJ-agent"
NET="$PROJ-net"
EV=${RIG_EVIDENCE:-/dev/null}
export CTRL_EXEC_TOKEN=$RIG_TOKEN
export RUNJOBS_IMAGE=$PROJ-run-jobs:from

compose() {   # compose <compose file> <args...>
    local f=$1
    shift
    docker compose -p "$PROJ" --project-directory "$STAGE" -f "$STAGE/$f" "$@"
}

rm -rf "$STAGE"
mkdir -p "$STAGE/dispatcher" "$STAGE/run-jobs/scripts"
cp "$EST/compose-0.12.yml" "$EST/compose-0.13.yml" "$STAGE/"
cp "$EST/dispatcher/Dockerfile" "$STAGE/dispatcher/"
cp "$EST/run-jobs/Dockerfile" "$STAGE/run-jobs/"
cp "$RIG_CLI_DIR/ctrl-exec-cli-from" "$STAGE/run-jobs/ctrl-exec-cli"
cp "$HERE/estates/jobs/plain-run-job.sh" "$STAGE/run-jobs/scripts/"
chmod -R a+rX "$STAGE"

# set_dispatcher <debs dir> <entrypoint file> <image tag>
set_dispatcher() {
    rm -f "$STAGE"/dispatcher/*.deb
    cp "$1"/ctrl-exec-common_*.deb "$1"/ctrl-exec-dispatcher_*.deb "$STAGE/dispatcher/"
    cp "$EST/dispatcher/$2" "$STAGE/dispatcher/entrypoint.sh"
    export DISPATCHER_IMAGE=$PROJ-dispatcher:$3
}

# api_up: until the API answers on the network from run-jobs (max 40 s)
api_up() {
    for _ in $(seq 1 40); do
        docker exec "$JOBS" perl -MHTTP::Tiny -e 'exit(HTTP::Tiny->new(timeout => 3)->get(q{http://dispatcher:7445/health})->{status} == 599 ? 1 : 0)' 2> /dev/null && return 0
        sleep 1
    done
    return 1
}

job() {   # job: run the plain-run job by hand in run-jobs, as the estate's docs do
    docker exec "$JOBS" /etc/run-jobs/scripts/plain-run-job.sh agent rig-hello upgrade-rig 2>&1 || true
}

# --- 0.12 estate ----------------------------------------------------------------
set_dispatcher "$RIG_DEBS_FROM" entrypoint-0.12.sh from
{ echo "== compose build (FROM)"; compose compose-0.12.yml build 2>&1; } >> "$EV" || die_setup "compose build (FROM) failed"
compose compose-0.12.yml create > /dev/null 2>&1 || die_setup "compose create failed"
# The operator's auth hook, in the data volume before first start (the
# entrypoint names it in the config it seeds).
docker run -i --rm --label "$RIG_LABEL" --entrypoint /bin/sh \
    --mount type=volume,src="$PROJ-dispatcher-data",dst=/d "$RIG_IMG" \
    -c 'cat > /d/auth-hook && chmod 755 /d/auth-hook' <<< "$AUTH_HOOK" \
    || die_setup "seeding the auth hook failed"
compose compose-0.12.yml up -d > /dev/null 2>&1 || die_setup "compose up (FROM) failed"
api_up || die_setup "FROM API not answering"

host_start "$AGENT" agent "$NET"
agent_install "$AGENT"
plain_layout "$AGENT"
pair "$DISP" "$AGENT" agent
note "FROM: dispatcher image $(docker exec "$DISP" dpkg-query -W -f '${Version}' ctrl-exec-dispatcher), agent $(pkg_version "$AGENT" agent)"
x "$DISP" 'grep -E "^[[:space:]]*(cert|key|ca|auth_hook)[[:space:]]*=" /etc/ctrl-exec/ctrl-exec.conf' | sed 's/^/#   /'
out=$(job)
{ echo "== job (FROM)"; echo "$out"; } >> "$EV"
check "FROM baseline: run-jobs job parses the CLI's 2>&1 output, result exit 0" "$out" '^result_exit=0$'
[ "$FAILED" = 0 ] || { echo "RESULT: ERROR (the estate does not work on FROM)"; exit 2; }

# --- phase A: swap the debs, nothing else -----------------------------------------
note "phase A: dispatcher image rebuilt with the TO debs; compose file, entrypoint and volumes unchanged"
set_dispatcher "$RIG_DEBS_TO" entrypoint-0.12.sh to
{ echo "== compose build (TO debs, 0.12 entrypoint)"; compose compose-0.12.yml build dispatcher 2>&1; } >> "$EV" || die_setup "compose build (TO) failed"
compose compose-0.12.yml up -d > /dev/null 2>&1 || nok "phase A: compose up exited non-zero"
A_FAIL=0
if api_up; then ok "phase A: the API answers on http://dispatcher:7445"; else echo "not ok - phase A: the API answers on http://dispatcher:7445"; A_FAIL=1; fi
sleep 3
state=$(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}} exit={{.State.ExitCode}}' "$DISP" 2>&1 || true)
note "phase A: dispatcher container: $state"
logs=$(docker logs --tail 15 "$DISP" 2>&1 || true)
{ echo "== phase A: dispatcher container $state"; echo "$logs"; } >> "$EV"
echo "$logs" | sort -u | sed 's/^/#   log: /' | head -12
if [[ $state != running\ restarts=0* ]]; then echo "not ok - phase A: the dispatcher container stays up"; A_FAIL=1; else ok "phase A: the dispatcher container stays up"; fi
out=$(job)
{ echo "== job (phase A)"; echo "$out"; } >> "$EV"
if grep -q '^result_exit=0$' <<< "$out"; then
    ok "phase A: run-jobs job parses the CLI's 2>&1 output, result exit 0"
else
    echo "not ok - phase A: run-jobs job parses the CLI's 2>&1 output, result exit 0"
    sed -n '1,2p;4,8p' <<< "$out" | sed 's/^/#   /'
    A_FAIL=1
fi
if [ "$A_FAIL" = 0 ]; then
    { echo "== dispatcher logs (phase A)"; docker logs "$DISP" 2>&1 | tail -40; } >> "$EV"
    # doctor (T-055): the volume mounted at the old path works in place; doctor
    # says so, as a note, with the fix - which phase B, run next, applies.
    out=$(x "$DISP" 'ctrl-exec-dispatcher doctor 2>&1; echo doctor-exit=$?' || true)
    { echo "== dispatcher doctor (phase A)"; echo "$out"; } >> "$EV"
    check "phase A doctor: the config mounted at /etc/ctrl-exec is a note, with the remount fix" "$out" \
        '^note +The dispatcher config is a mount at /etc/ctrl-exec and is used there; it works as it is\. Fix: mount the volume at /etc/ctrl-exec-dispatcher instead'
    check_not "phase A doctor: no problem" "$out" '^PROBLEM'
    check "phase A doctor: exit 0" "$out" 'doctor-exit=0'
fi

# --- phase B: the operator's documented compose change ---------------------------
# Needed when phase A failed; after a phase A that works, it is the fix doctor
# names for the config in place, and must work too.
note "phase B: compose-0.13.yml (data volume at /etc/ctrl-exec-dispatcher) and the 0.13 entrypoint (CONF_DIR, path rewrite)"
set_dispatcher "$RIG_DEBS_TO" entrypoint-0.13.sh to-compose-0.13
{ echo "== compose build (TO debs, 0.13 entrypoint)"; compose compose-0.13.yml build dispatcher 2>&1; } >> "$EV" || die_setup "compose build (phase B) failed"
compose compose-0.13.yml up -d > /dev/null 2>&1 || nok "phase B: compose up exited non-zero"
if api_up; then ok "phase B: the API answers on http://dispatcher:7445"; else nok "phase B: the API answers on http://dispatcher:7445"; fi
sleep 3
state=$(docker inspect -f '{{.State.Status}} restarts={{.RestartCount}}' "$DISP" 2>&1 || true)
check "phase B: the dispatcher container stays up" "$state" '^running restarts=0$'
out=$(job)
{ echo "== job (phase B)"; echo "$out"; } >> "$EV"
check "phase B: run-jobs job parses the CLI's 2>&1 output, result exit 0" "$out" '^result_exit=0$'
out=$(x "$DISP" 'ctrl-exec-dispatcher list-agents 2>&1; grep -E "^[[:space:]]*(cert|key|ca|auth_hook)[[:space:]]*=" /etc/ctrl-exec-dispatcher/ctrl-exec.conf' || true)
{ echo "== phase B: list-agents and config"; echo "$out"; } >> "$EV"
check "phase B: ced list-agents still lists the paired agent" "$out" '^agent '
check "phase B: config paths point at /etc/ctrl-exec-dispatcher" "$out" 'auth_hook = /etc/ctrl-exec-dispatcher/auth-hook'
out=$(x "$DISP" 'ctrl-exec-dispatcher doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== dispatcher doctor (phase B)"; echo "$out"; } >> "$EV"
check_not "phase B doctor: nothing about the config directory" "$out" '/etc/ctrl-exec '
check_not "phase B doctor: no problem" "$out" '^PROBLEM'
{ echo "== dispatcher logs"; docker logs "$DISP" 2>&1 | tail -40; } >> "$EV"

if [ "$FAILED" != 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
if [ "$A_FAIL" = 0 ]; then
    echo "RESULT: PASS"
    exit 0
fi
echo "RESULT: OPERATOR-STEP (swapping the debs alone fails; works after the compose change)"
exit 1
