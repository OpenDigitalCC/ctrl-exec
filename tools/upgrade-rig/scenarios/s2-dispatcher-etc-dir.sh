#!/bin/bash
# Scenario 2: a dispatcher on the deb, its configuration in /etc/ctrl-exec (the
# 0.12 location, as the FROM package's postinst made it) with a token auth hook
# named in ctrl-exec.conf, the API enabled under systemd. A stock agent host is
# paired and stays on FROM (dispatchers are upgraded first). Only the
# dispatcher is upgraded. After it: ced works, ctrl-exec-api is running and
# serves, the auth hook still decides (a good token runs, a bad one is denied),
# and the maintenance unit runs; doctor, which the upgrade runs, has nothing to
# report.
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` expands in the container
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")/..")
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

NET="$RIG_PREFIX-s2-net"
DISP="$RIG_PREFIX-s2-dispatcher"
AGENT="$RIG_PREFIX-s2-agent"
EV=${RIG_EVIDENCE:-/dev/null}

net_create "$NET"
host_start "$DISP" dispatcher "$NET"
host_start "$AGENT" agent "$NET"

confdir=$(dispatcher_install "$DISP" | tail -1)
wait_api "$DISP" || die_setup "FROM API not answering"
agent_install "$AGENT"
plain_layout "$AGENT"
pair "$DISP" "$AGENT" agent
note "FROM: dispatcher $(pkg_version "$DISP" dispatcher) with config in $confdir; agent $(pkg_version "$AGENT" agent)"
x "$DISP" "grep -E '^[[:space:]]*(cert|key|ca|auth_hook|api_bind)[[:space:]]*=' $confdir/ctrl-exec.conf" | sed 's/^/#   /'

# --- baseline on FROM --------------------------------------------------------
check "FROM baseline: config is in /etc/ctrl-exec" "$confdir" '^/etc/ctrl-exec$'
out=$(cli "$DISP" to run agent --script rig-hello)
check "FROM baseline: API run with the token" "$out" 'rig-hello user=nobody'
out=$(x "$DISP" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN 2>&1" || true)
check "FROM baseline: ced run with the token" "$out" 'rig-hello user=nobody'
[ "$FAILED" = 0 ] || { echo "RESULT: ERROR (the estate does not work on FROM)"; exit 2; }

# --- upgrade the dispatcher: debs only ------------------------------------------
disp_up=$(install_debs "$DISP" to common dispatcher 2>&1) || nok "dispatcher dpkg -i of TO exited non-zero"
{ echo "== dispatcher dpkg -i (TO)"; echo "$disp_up"; } >> "$EV"
note "TO: dispatcher $(pkg_version "$DISP" dispatcher); agent $(pkg_version "$AGENT" agent)"
wait_api "$DISP" || true

# --- after the upgrade ----------------------------------------------------------
out=$(unit_states "$DISP" ctrl-exec-api)
check "ctrl-exec-api active after upgrade" "$out" '^ctrl-exec-api=active$'
out=$(x "$DISP" 'ls -ld /etc/ctrl-exec /etc/ctrl-exec-dispatcher 2>&1; grep -E "^[[:space:]]*(cert|key|ca|auth_hook)[[:space:]]*=" /etc/ctrl-exec-dispatcher/ctrl-exec.conf 2>&1' || true)
{ echo "== config after upgrade"; echo "$out"; } >> "$EV"
while IFS= read -r line; do echo "#   $line"; done <<< "$out"

out=$(x "$DISP" 'ctrl-exec-dispatcher list-agents 2>&1; echo ced-exit=$?' || true)
check "ced list-agents works and lists the agent" "$out" '^agent '
check "ced list-agents exits 0" "$out" 'ced-exit=0'
out=$(x "$DISP" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN -- a1 2>&1; echo ced-exit=\$?" || true)
{ echo "== ced run (TO)"; echo "$out"; } >> "$EV"
check "ced run with the token runs the script" "$out" 'rig-hello user=nobody args=a1'

out=$(x "$DISP" 'perl -MHTTP::Tiny -e "my \$r = HTTP::Tiny->new->get(q{http://127.0.0.1:7445/health}); print \$r->{status}, q{ }, \$r->{content}"' || true)
{ echo "== GET /health (TO)"; echo "$out"; } >> "$EV"
# /health goes through the auth hook (0.12 and 0.13): a JSON 200 or 403 is the
# API serving; 599 is no connection.
check "API answers /health with JSON" "$out" '^(200|403) \{'
out=$(cli "$DISP" to run agent --script rig-hello -- a2)
{ echo "== API run with token (TO)"; echo "$out"; } >> "$EV"
check "API run with the token runs the script" "$out" 'rig-hello user=nobody args=a2'
out=$(x "$DISP" "CTRL_EXEC_TOKEN=wrong CTRL_EXEC_API_URL=http://127.0.0.1:7445 perl /rig-cli/ctrl-exec-cli-to run agent --script rig-hello 2>&1; echo cli-exit=\$?" || true)
{ echo "== API run with a wrong token (TO)"; echo "$out"; } >> "$EV"
check "API run with a wrong token is denied by the hook" "$out" 'bad credentials|denied|forbidden'
check_not "API run with a wrong token does not run the script" "$out" 'rig-hello user='

out=$(x "$DISP" 'systemctl start ctrl-exec-maintenance.service 2>&1; echo start-exit=$?; systemctl is-failed ctrl-exec-maintenance.service' || true)
{ echo "== maintenance unit (TO)"; echo "$out"; } >> "$EV"
check "the maintenance unit runs" "$out" 'start-exit=0'

# doctor (T-055): the upgrade ran it; the old /etc/ctrl-exec was moved, so it
# reports nothing about the config directory, and nothing to fix on this estate
# (the token hook is not the allow-all example).
check "the upgrade ran doctor and printed its summary" "$disp_up" '^ctrl-exec-dispatcher doctor: '
out=$(x "$DISP" 'ctrl-exec-dispatcher doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== dispatcher doctor (TO)"; echo "$out"; } >> "$EV"
check "doctor: no problems" "$out" '^ctrl-exec-dispatcher doctor: no problems'
check_not "doctor: nothing about the config directory (it was moved)" "$out" '/etc/ctrl-exec '
check "doctor: exit 0" "$out" 'doctor-exit=0'
out=$(x "$DISP" 'ctrl-exec-dispatcher doctor --json' || true)
check "doctor --json: one object with ok true" "$out" '^\{.*"ok":true.*"program":"ctrl-exec-dispatcher".*\}$'

{ echo "== dispatcher journal"; journal "$DISP" 120; } >> "$EV"

if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$FAILED"
