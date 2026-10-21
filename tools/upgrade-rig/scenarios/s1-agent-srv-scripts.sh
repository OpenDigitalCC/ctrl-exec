#!/bin/bash
# Scenario 1 (and 1b): an agent with the cloudient script layout, upgraded
# from FROM to TO with no step between.
#
#   scripts in /srv/scripts, 2775 root:sysadmin, each script owned by sysadmin
#   (one of them 775); profiles cert-deploy (run_as root, CAP_CHOWN, writable),
#   svc-restart (run_as ce-docker) and default (run_as nobody); executor on.
#   1b (argument "srv-group-writable"): /srv itself 2775 root:sysadmin as well.
#
# A dispatcher host beside it (FROM debs, API behind a token hook) is paired
# with the agent, checked on FROM, then upgraded first (dispatchers before
# agents, as the upgrade notes say). After the agent's upgrade: the services
# are running, self-check lists every script, the API's discovery lists every
# script and each one runs under its profile, with no ownership warning text
# in the run output. doctor (T-055), run by the upgrade, reports the layout as a
# note (what strict would refuse), and its fixes, applied as it says, work.
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` expands in the container
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")/..")
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

variant=${1:-}
tag=s1
[ "$variant" = srv-group-writable ] && tag=s1b
NET="$RIG_PREFIX-$tag-net"
DISP="$RIG_PREFIX-$tag-dispatcher"
AGENT="$RIG_PREFIX-$tag-agent"
EV=${RIG_EVIDENCE:-/dev/null}
SCRIPTS="agent-cert-deploy agent-service-restart agent-cert-check"
OWNERSHIP_TEXT='owned by uid|not root|group-writable|world-writable|not permitted|allowlist-skip|ownership'

net_create "$NET"
host_start "$DISP" dispatcher "$NET"
host_start "$AGENT" agent "$NET"

# --- install FROM and lay out the estate ---------------------------------------
dispatcher_install "$DISP" > /dev/null
wait_api "$DISP" || die_setup "FROM API not answering"
agent_install "$AGENT"
tar -C "$HERE/estates/cloudient-agent" -c . | x "$AGENT" "mkdir -p /tmp/estate && tar -x -C /tmp/estate && bash /tmp/estate/layout.sh $variant" \
    || die_setup "estate layout failed"
pair "$DISP" "$AGENT" agent
note "FROM: dispatcher $(pkg_version "$DISP" dispatcher), agent $(pkg_version "$AGENT" agent)"
x "$AGENT" 'stat -c "%A %U:%G %n" /srv /srv/scripts /srv/scripts/*' | sed 's/^/#   /'

# --- the estate works on FROM (otherwise the scenario proves nothing) ---------
out=$(x "$AGENT" 'ctrl-exec-agent self-check 2>&1' || true)
{ echo "== agent self-check (FROM)"; echo "$out"; } >> "$EV"
check "FROM baseline: self-check allowlist holds all 3 scripts" "$out" 'Allowlist OK \(3 scripts\)'
for s in $SCRIPTS; do
    check "FROM baseline: self-check lists $s as ok" "$out" "Script '$s': /srv/scripts/$s.sh .*\\[ok\\]"
done
out=$(cli "$DISP" to discovery --scripts agent)
for s in $SCRIPTS; do
    check "FROM baseline: discovery lists $s" "$out" "^  $s "
done
out=$(cli "$DISP" to run agent --script agent-cert-deploy)
check "FROM baseline: agent-cert-deploy runs as root and chgrps in its writable dir" "$out" 'group=ce-docker'
out=$(cli "$DISP" to run agent --script agent-service-restart)
check "FROM baseline: agent-service-restart runs as ce-docker" "$out" 'user=ce-docker'
out=$(cli "$DISP" to run agent --script agent-cert-check)
check "FROM baseline: agent-cert-check runs as nobody" "$out" 'user=nobody'
[ "$FAILED" = 0 ] || { echo "RESULT: ERROR (the estate does not work on FROM)"; exit 2; }

# --- upgrade: debs only, nothing else ------------------------------------------
{ echo "== dispatcher dpkg -i (TO)"; install_debs "$DISP" to common dispatcher 2>&1; } >> "$EV" || nok "dispatcher dpkg -i of TO exited non-zero"
agent_up=$(install_debs "$AGENT" to common agent 2>&1) || nok "agent dpkg -i of TO exited non-zero"
{ echo "== agent dpkg -i (TO)"; echo "$agent_up"; } >> "$EV"
note "TO: dispatcher $(pkg_version "$DISP" dispatcher), agent $(pkg_version "$AGENT" agent)"
wait_api "$DISP" || true
wait_agent "$AGENT" || true

# --- after the upgrade ----------------------------------------------------------
states=$(unit_states "$AGENT" ctrl-exec-executor ctrl-exec-agent)
check "agent and executor units active after upgrade" "$states" '^ctrl-exec-executor=active ctrl-exec-agent=active$'
states=$(unit_states "$DISP" ctrl-exec-api)
check "dispatcher API unit active after upgrade" "$states" '^ctrl-exec-api=active$'

out=$(x "$AGENT" 'ctrl-exec-agent self-check 2>&1' || true)
{ echo "== agent self-check (TO)"; echo "$out"; } >> "$EV"
check "self-check: allowlist holds all 3 scripts" "$out" 'Allowlist OK \(3 scripts\)'
for s in $SCRIPTS; do
    check "self-check lists $s as ok" "$out" "Script '$s': /srv/scripts/$s.sh .*\\[ok\\]"
done
# A layout that breaks the ownership rule is reported (self-check shows a
# [warning: ...] per script, T-054), never skipped or refused.
check_not "self-check: no script skipped or refused" "$out" 'skipping|SKIPPED|refused|not permitted'

out=$(cli "$DISP" to discovery --scripts agent)
{ echo "== discovery --scripts (TO)"; echo "$out"; } >> "$EV"
check_not "discovery does not say (no scripts)" "$out" '\(no scripts\)'
for s in $SCRIPTS; do
    check "discovery lists $s" "$out" "^  $s "
done

out=$(cli "$DISP" to run agent --script agent-cert-deploy)
{ echo "== run agent-cert-deploy (TO)"; echo "$out"; } >> "$EV"
check "run agent-cert-deploy: runs as root" "$out" 'user=root'
check "run agent-cert-deploy: CAP_CHOWN and the writable dir work" "$out" 'group=ce-docker'
check_not "run agent-cert-deploy: no ownership warning text" "$out" "$OWNERSHIP_TEXT"

out=$(cli "$DISP" to run agent --script agent-service-restart)
{ echo "== run agent-service-restart (TO)"; echo "$out"; } >> "$EV"
check "run agent-service-restart: runs as ce-docker" "$out" 'user=ce-docker'
check_not "run agent-service-restart: no ownership warning text" "$out" "$OWNERSHIP_TEXT"

out=$(cli "$DISP" to run agent --script agent-cert-check -- -p 443)
{ echo "== run agent-cert-check (TO)"; echo "$out"; } >> "$EV"
check "run agent-cert-check: runs as nobody under the default profile" "$out" 'user=nobody args=-p 443'
check_not "run agent-cert-check: no ownership warning text" "$out" "$OWNERSHIP_TEXT"

# --- doctor (T-055) ---------------------------------------------------------------
# The upgrade printed doctor's report; the layout that breaks the ownership rule
# is a note saying what script_ownership = strict would do - never a problem, and
# the scripts run.
check "the upgrade ran doctor and printed its summary" "$agent_up" '^ctrl-exec-agent doctor: '
out=$(x "$AGENT" 'ctrl-exec-agent doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== agent doctor (TO)"; echo "$out"; } >> "$EV"
check "doctor: the group-writable directory is a note naming the 3 scripts and what strict would do" "$out" \
    "^note +'/srv(/scripts)?' is group-writable: 3 scripts run \(.*\) with a warning \(script_ownership = warn\); script_ownership = strict would refuse them\. Fix: sudo chmod g-w /srv"
check_not "doctor: no problem" "$out" '^PROBLEM'
check "doctor: exit 0" "$out" 'doctor-exit=0'

# doctor's fix works: apply each ownership fix as it says (the directory first,
# then what the next run names) until none is left; the scripts still run, with
# no warning left in self-check.
x "$AGENT" 'cat > /tmp/ownership-fixes.pl' <<'PL'
use JSON::PP;
local $/;
for my $f (@{ decode_json(<STDIN>)->{findings} }) {
    next unless $f->{check} eq 'script-ownership';
    print "$1\n" if $f->{fix} =~ /^sudo ((?:chmod [go]-w|chown root) [^\s,]+)/;
}
PL
for _ in 1 2 3 4 5 6; do
    fixes=$(x "$AGENT" 'ctrl-exec-agent doctor --json 2>/dev/null | perl /tmp/ownership-fixes.pl' || true)
    [ -n "$fixes" ] || break
    { echo "== applying doctor's fixes"; echo "$fixes"; } >> "$EV"
    while IFS= read -r cmd; do x "$AGENT" "$cmd" < /dev/null >> "$EV" 2>&1 || nok "doctor's fix failed: $cmd"; done <<< "$fixes"
done
out=$(x "$AGENT" 'ctrl-exec-agent doctor 2>&1; ctrl-exec-agent self-check 2>&1' || true)
{ echo "== agent doctor and self-check after its fixes"; echo "$out"; } >> "$EV"
check_not "after doctor's fixes: no ownership note left" "$out" 'script_ownership = strict would refuse'
check_not "after doctor's fixes: self-check shows no ownership warning" "$out" '\[warning: '
out=$(cli "$DISP" to run agent --script agent-cert-check -- after-fix)
{ echo "== run agent-cert-check after doctor's fixes"; echo "$out"; } >> "$EV"
check "after doctor's fixes: agent-cert-check still runs as nobody" "$out" 'user=nobody args=after-fix'

{ echo "== agent journal"; journal "$AGENT" 150; echo "== dispatcher journal"; journal "$DISP" 60; } >> "$EV"

if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$FAILED"
