#!/bin/bash
# Scenario 6 (T-062): an agent paired with one dispatcher on FROM is upgraded,
# then paired with a second dispatcher that has its own CA, the way any agent
# is paired (request-pairing on the agent, approve on the dispatcher), with no
# key or CA file copied between the dispatchers. Passes when the agent keeps
# its certificate, both dispatchers run a script on it, the agent was not
# restarted for the second pairing, and the second dispatcher holds nothing of
# the first one's CA key.
#
# Then doctor (T-055): nothing to report with both; with A removed (T-064) it
# notes that no trusted dispatcher can renew the agent's certificate, and its
# fix - re-key with B - works; A's CA, left unused, goes with doctor --fix, and
# a second --fix changes nothing.
#
# Dispatcher A ("dispatcher") and the agent are installed on FROM and paired;
# A then the agent are upgraded to TO (dispatchers first). Dispatcher B
# ("dispatcher2") is a fresh TO install with its own CA.
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` expands in the container
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")/..")
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

NET="$RIG_PREFIX-s6-net"
DA="$RIG_PREFIX-s6-dispatcher"
DB="$RIG_PREFIX-s6-dispatcher2"
AGENT="$RIG_PREFIX-s6-agent"
EV=${RIG_EVIDENCE:-/dev/null}
MAP=/var/lib/ctrl-exec-agent/ctrl-exec-dispatchers

net_create "$NET"
host_start "$DA" dispatcher "$NET"
host_start "$AGENT" agent "$NET"

# --- FROM: one dispatcher, one agent --------------------------------------------
confa=$(dispatcher_install "$DA" | tail -1)
wait_api "$DA" || die_setup "FROM API not answering on dispatcher A"
agent_install "$AGENT"
plain_layout "$AGENT"
pair "$DA" "$AGENT" agent
note "FROM: dispatcher A $(pkg_version "$DA" dispatcher), agent $(pkg_version "$AGENT" agent)"

out=$(x "$DA" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN -- from 2>&1" || true)
check "FROM baseline: dispatcher A runs the script" "$out" 'rig-hello user=nobody args=from'
[ "$FAILED" = 0 ] || { echo "RESULT: ERROR (the estate does not work on FROM)"; exit 2; }

# --- upgrade A, then the agent: debs only -----------------------------------------
{ echo "== dispatcher A dpkg -i (TO)"; install_debs "$DA" to common dispatcher 2>&1; } >> "$EV" \
    || nok "dispatcher A dpkg -i of TO exited non-zero"
{ echo "== agent dpkg -i (TO)"; install_debs "$AGENT" to common agent 2>&1; } >> "$EV" \
    || nok "agent dpkg -i of TO exited non-zero"
wait_agent "$AGENT" || nok "agent listening after its upgrade"
note "TO: dispatcher A $(pkg_version "$DA" dispatcher), agent $(pkg_version "$AGENT" agent)"
out=$(x "$DA" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN -- upgraded 2>&1" || true)
check "after the upgrade, dispatcher A runs the script" "$out" 'rig-hello user=nobody args=upgraded'

# --- dispatcher B: TO, its own CA -------------------------------------------------
host_start "$DB" dispatcher2 "$NET"
confb=$(dispatcher_install "$DB" to | tail -1)
wait_api "$DB" || die_setup "dispatcher B API not answering"
subj_a=$(x "$DA" "openssl x509 -noout -subject -in $confa/ca.crt")
subj_b=$(x "$DB" "openssl x509 -noout -subject -in $confb/ca.crt")
{ echo "== CA subjects"; echo "A: $subj_a"; echo "B: $subj_b"; } >> "$EV"
note "A's CA: $subj_a; B's CA: $subj_b"
check "dispatcher B's new CA is named for it" "$subj_b" 'ctrl-exec CA dispatcher2 [0-9a-f]{8}'

crt_before=$(x "$AGENT" 'sha256sum /etc/ctrl-exec-agent/agent.crt /etc/ctrl-exec-agent/agent.key')
pid_before=$(x "$AGENT" 'systemctl show -p MainPID --value ctrl-exec-agent')

# --- pair the agent with B: the usual two steps -------------------------------------
x "$DB" 'ctrl-exec-dispatcher pairing-mode start --timeout 120 > /dev/null 2>&1' \
    || die_setup "pairing-mode start failed on dispatcher B"
out=$(x "$AGENT" "ctrl-exec-agent request-pairing --dispatcher dispatcher2 --background --timeout 120 2>&1" || true)
{ echo "== request-pairing with B"; echo "$out"; } >> "$EV"
paired=""
for _ in $(seq 1 40); do
    reqs=$(x "$DB" 'ctrl-exec-dispatcher list-requests 2>/dev/null' || true)
    [ -n "$reqs" ] && echo "$reqs" >> "$EV"
    # shellcheck disable=SC2013  # request ids are single words
    for id in $(awk '/^[0-9a-f]{8,}/ {print $1}' <<< "$reqs"); do
        x "$DB" "ctrl-exec-dispatcher approve $id" >> "$EV" 2>&1 || true
    done
    if x "$AGENT" "grep -q ' dispatcher2\$' $MAP" 2> /dev/null; then paired=1; break; fi
    sleep 1
done
x "$DB" 'ctrl-exec-dispatcher pairing-mode stop' > /dev/null 2>&1 || true
[ -n "$paired" ] || die_setup "the agent did not pair with dispatcher B"
sleep 1
check "list-requests on B showed the kept certificate and its CA" "$(cat "$EV")" 'Issued by: +SHA256:[0-9a-f]{64}'
name=$(x "$DB" 'ctrl-exec-dispatcher list-agents' | awk 'NR > 2 && ($1 == "agent" || index($1, "agent.") == 1) {print $1; exit}')
[ -n "$name" ] || die_setup "the agent is not in dispatcher B's registry"
if [ "$name" != agent ]; then
    x "$DB" "ctrl-exec-dispatcher edit-agent '$name' --rename agent" > /dev/null \
        || die_setup "rename of $name to agent on B failed"
fi

# --- after the second pairing -------------------------------------------------------
crt_after=$(x "$AGENT" 'sha256sum /etc/ctrl-exec-agent/agent.crt /etc/ctrl-exec-agent/agent.key')
if [ "$crt_before" = "$crt_after" ]; then ok "the agent kept its key and certificate"; else nok "the agent kept its key and certificate"; fi
out=$(x "$AGENT" "grep -c 'BEGIN CERTIFICATE' /etc/ctrl-exec-agent/ca.crt; cat $MAP")
{ echo "== agent bundle and map"; echo "$out"; } >> "$EV"
check "the agent's bundle holds both CAs" "$out" '^2$'
check "the agent trusts dispatcher A" "$out" ' dispatcher$'
check "the agent trusts dispatcher B" "$out" ' dispatcher2$'
out=$(x "$DB" 'ctrl-exec-dispatcher list-agents --json')
check "B's registry pins the agent's CA" "$out" '"agent_ca_fpr":"[0-9a-f]{64}"'

out=$(x "$DB" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN -- from-b 2>&1" || true)
{ echo "== ced run on B"; echo "$out"; } >> "$EV"
check "dispatcher B runs the script" "$out" 'rig-hello user=nobody args=from-b'
out=$(x "$DA" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN -- from-a 2>&1" || true)
{ echo "== ced run on A"; echo "$out"; } >> "$EV"
check "dispatcher A still runs the script" "$out" 'rig-hello user=nobody args=from-a'
pid_after=$(x "$AGENT" 'systemctl show -p MainPID --value ctrl-exec-agent')
if [ "$pid_before" = "$pid_after" ]; then ok "no agent restart for the second pairing"; else nok "no agent restart for the second pairing ($pid_before -> $pid_after)"; fi
out=$(journal "$AGENT" 300)
check "the agent reloaded its CA bundle" "$out" 'ACTION=ca-bundle-reload'

# B holds nothing of A's CA key: a line from the middle of it appears in no file
# under B's configuration or state.
keyline=$(x "$DA" "sed -n 6p $confa/ca.key")
[ ${#keyline} -gt 40 ] || die_setup "could not read a line of A's CA key"
out=$(x "$DB" "grep -rlF -- '$keyline' $confb /var/lib/ctrl-exec 2>/dev/null; echo grep-done" || true)
check_not "dispatcher B holds nothing of A's CA key" "$out" '^/'

# --- doctor (T-055) ------------------------------------------------------------------
# Two dispatchers, each with its own CA: nothing to report on the agent or on B.
out=$(x "$AGENT" 'ctrl-exec-agent doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== agent doctor, two dispatchers"; echo "$out"; } >> "$EV"
check_not "doctor: no problem with two dispatchers" "$out" '^PROBLEM'
check_not "doctor: trust state consistent (no CA missing or unused)" "$out" 'not in /etc/ctrl-exec-agent/ca.crt|is not used by any trusted dispatcher'
check "doctor: exit 0" "$out" 'doctor-exit=0'
out=$(x "$DB" 'ctrl-exec-dispatcher doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== dispatcher B doctor"; echo "$out"; } >> "$EV"
check "dispatcher B doctor: no problems (the pinned agent certificate has long to run)" "$out" 'ctrl-exec-dispatcher doctor: no problems'

# Dispatcher A, which issued the agent's certificate, is removed (T-064): no
# dispatcher can renew the certificate. doctor says so, with the re-key as fix.
x "$AGENT" 'ctrl-exec-agent remove-dispatcher dispatcher' >> "$EV" 2>&1 || nok "remove-dispatcher dispatcher (A) failed"
out=$(x "$AGENT" 'ctrl-exec-agent doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== agent doctor, A removed"; echo "$out"; } >> "$EV"
check "doctor: the certificate's issuer is no longer trusted - a note while it has more than 30 days" "$out" \
    "^note +This agent's certificate was issued by CA SHA256:[0-9a-f]{64}, which no trusted dispatcher uses .*expires on .* Fix: before then, re-key with a remaining dispatcher: sudo ctrl-exec-agent request-pairing --dispatcher <dispatcher-host> --rekey"
check "doctor: exit 0 (a note)" "$out" 'doctor-exit=0'

# doctor's fix: re-key with B (approve on B), restart the agent.
x "$DB" 'ctrl-exec-dispatcher pairing-mode start --timeout 120 > /dev/null 2>&1' \
    || die_setup "pairing-mode start failed on dispatcher B (re-key)"
crt_before=$(x "$AGENT" 'sha256sum /etc/ctrl-exec-agent/agent.crt')
out=$(x "$AGENT" "ctrl-exec-agent request-pairing --dispatcher dispatcher2 --rekey --background --timeout 120 2>&1" || true)
{ echo "== request-pairing --rekey with B"; echo "$out"; } >> "$EV"
rekeyed=""
for _ in $(seq 1 40); do
    reqs=$(x "$DB" 'ctrl-exec-dispatcher list-requests 2>/dev/null' || true)
    # shellcheck disable=SC2013  # request ids are single words
    for id in $(awk '/^[0-9a-f]{8,}/ {print $1}' <<< "$reqs"); do
        x "$DB" "ctrl-exec-dispatcher approve $id" >> "$EV" 2>&1 || true
    done
    if [ "$(x "$AGENT" 'sha256sum /etc/ctrl-exec-agent/agent.crt')" != "$crt_before" ]; then rekeyed=1; break; fi
    sleep 1
done
x "$DB" 'ctrl-exec-dispatcher pairing-mode stop' > /dev/null 2>&1 || true
[ -n "$rekeyed" ] || die_setup "the agent did not re-key with dispatcher B"
sleep 1
# B registered the re-keyed agent under its own name again: keep one entry, 'agent'.
name=$(x "$DB" 'ctrl-exec-dispatcher list-agents' | awk 'NR > 2 && $1 != "agent" && index($1, "agent.") == 1 {print $1; exit}')
if [ -n "$name" ]; then
    x "$DB" "ctrl-exec-dispatcher unpair agent > /dev/null && ctrl-exec-dispatcher edit-agent '$name' --rename agent > /dev/null" \
        || die_setup "re-registering the re-keyed agent as agent on B failed"
fi
x "$AGENT" 'systemctl restart ctrl-exec-agent' || nok "agent restart after the re-key"
wait_agent "$AGENT" || nok "agent listening after the re-key"

out=$(x "$AGENT" 'ctrl-exec-agent doctor 2>&1; echo doctor-exit=$?' || true)
{ echo "== agent doctor, after the re-key"; echo "$out"; } >> "$EV"
check_not "after the re-key: the issuer finding is gone" "$out" 'no trusted dispatcher uses'
check "after the re-key: A's CA, now unused, is a note --fix removes" "$out" \
    '^note +CA SHA256:[0-9a-f]{64} in /etc/ctrl-exec-agent/ca.crt is not used by any trusted dispatcher.* Fix: sudo ctrl-exec-agent doctor --fix'
out=$(x "$AGENT" 'ctrl-exec-agent doctor --fix 2>&1; echo doctor-exit=$?; grep -c "BEGIN CERTIFICATE" /etc/ctrl-exec-agent/ca.crt; sha256sum /etc/ctrl-exec-agent/ca.crt' || true)
{ echo "== agent doctor --fix"; echo "$out"; } >> "$EV"
check "doctor --fix: removed A's CA" "$out" '^fixed +CA SHA256:[0-9a-f]{64} in /etc/ctrl-exec-agent/ca.crt is not used'
check "doctor --fix: the bundle holds one CA (B's)" "$out" '^1$'
sum1=$(grep -E '^[0-9a-f]{64} ' <<< "$out" || true)
out=$(x "$AGENT" 'ctrl-exec-agent doctor --fix 2>&1; echo doctor-exit=$?; sha256sum /etc/ctrl-exec-agent/ca.crt' || true)
{ echo "== agent doctor --fix, again"; echo "$out"; } >> "$EV"
check_not "a second doctor --fix fixes nothing" "$out" '^fixed'
sum2=$(grep -E '^[0-9a-f]{64} ' <<< "$out" || true)
if [ -n "$sum1" ] && [ "$sum1" = "$sum2" ]; then ok "a second doctor --fix leaves ca.crt as it was"; else nok "a second doctor --fix leaves ca.crt as it was"; fi
check "doctor: exit 0 after the fixes" "$out" 'doctor-exit=0'
out=$(x "$DB" "ctrl-exec-dispatcher run agent rig-hello --token $RIG_TOKEN -- after-rekey 2>&1" || true)
{ echo "== ced run on B after the re-key"; echo "$out"; } >> "$EV"
check "dispatcher B runs the script after the re-key and --fix" "$out" 'rig-hello user=nobody args=after-rekey'

{ echo "== dispatcher B journal"; journal "$DB" 120; echo "== agent journal"; journal "$AGENT" 120; } >> "$EV"

if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$FAILED"
