#!/bin/bash
# Scenario 5 (T-059): scripts.conf edits on a running agent, on TO only (no
# upgrade). The field report (0.13.1): agent-cert-deploy was given input=fields
# in scripts.conf; after it ran (with no input, then with input fields) the
# context scripts agent-service-restart and agent-cert-check were refused by
# the executor as "takes input=fields but the agent sent no input" until the
# agent was restarted - the executor reads scripts.conf for every run, the
# agent only when it loaded it. From 0.13.2 the agent reloads an edited
# scripts.conf or agent.conf by itself. No phase here reloads the agent except
# E.
#
#   A  the field sequence, twice: every run works (nothing a fields run does
#      carries over to the next connection)
#   B  the deploy line as a paste from a terminal or chat leaves it (NBSPs
#      before input= or profile=, NBSPs as every separator, tabs, CRLF): it
#      runs as the plain line does; one config-nonascii-space notice
#   C  input=fields edited onto the context lines, a script added, one
#      removed: each is in effect at the next run, no mismatch refusal
#   D  a line naming an undefined profile skips only that script, with the
#      reason; self-check lists it as skipped
#   E  SIGHUP still reloads
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` expands in the container
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")/..")
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

NET="$RIG_PREFIX-s5-net"
DISP="$RIG_PREFIX-s5-dispatcher"
AGENT="$RIG_PREFIX-s5-agent"
EV=${RIG_EVIDENCE:-/dev/null}
CONF=/etc/ctrl-exec-agent/scripts.conf

net_create "$NET"
host_start "$DISP" dispatcher "$NET"
host_start "$AGENT" agent "$NET"

dispatcher_install "$DISP" to > /dev/null
wait_api "$DISP" || die_setup "API not answering"
agent_install "$AGENT" to
tar -C "$HERE/estates/cloudient-agent" -c . | x "$AGENT" "mkdir -p /tmp/estate && tar -x -C /tmp/estate && bash /tmp/estate/layout.sh" \
    || die_setup "estate layout failed"
# As on the reporting host: /srv/scripts root-owned; the deploy stand-in reads
# its fields when it has them (the real one takes --test without input).
x "$AGENT" 'set -e
    cat > /srv/scripts/agent-cert-deploy.sh << "EOS"
#!/bin/sh
set -e
echo "script=agent-cert-deploy user=$(id -un) args=$*"
if [ -n "${CTRL_EXEC_INPUT:-}" ]; then
    for f in cert key ca; do
        [ -f "$CTRL_EXEC_INPUT/$f" ] && echo "field $f bytes=$(wc -c < "$CTRL_EXEC_INPUT/$f")"
    done
fi
f=/srv/docker-vol/certs/rig-probe.key
echo probe > "$f"
chgrp ce-docker "$f"
echo "wrote $f group=$(stat -c %G "$f")"
EOS
    chown -R root:root /srv/scripts
    chmod 755 /srv/scripts /srv/scripts/*.sh
    printf "%s\n" "{\"cert\":\"rig-cert-value\",\"key\":\"rig-key-value\",\"ca\":\"rig-ca-value\"}" > /root/fields.json' \
    || die_setup "deploy stand-in failed"
docker cp "$AGENT:/root/fields.json" - | docker cp - "$DISP:/root/" \
    || die_setup "copying the fields file failed"
pair "$DISP" "$AGENT" agent
note "TO: dispatcher $(pkg_version "$DISP" dispatcher), agent $(pkg_version "$AGENT" agent)"

# write_conf <deploy line> [svc annotation] [check annotation] [extra line] [eol]
write_conf() {
    local eol=${5:-\\n}
    x "$AGENT" "printf '%s$eol%s$eol%s$eol%s$eol' \
        '$1' \
        'agent-service-restart = /srv/scripts/agent-service-restart.sh  profile=svc-restart${2:+ $2}' \
        'agent-cert-check      = /srv/scripts/agent-cert-check.sh${3:+ $3}' \
        '${4:-# end}' > $CONF"
}
DEPLOY='agent-cert-deploy     = /srv/scripts/agent-cert-deploy.sh      profile=cert-deploy input=fields'
reload() { x "$AGENT" 'systemctl reload ctrl-exec-agent.service'; sleep 2; }
# mark: a journal timestamp to read from; jsince <mark>: the agent's journal since
mark() { local t; t=$(x "$AGENT" 'date "+%Y-%m-%d %H:%M:%S"'); sleep 1; echo "$t"; }
jsince() { x "$AGENT" "journalctl --no-pager -u ctrl-exec-agent --since '$1'" || true; }
run_deploy_test()   { cli "$DISP" to run agent --script agent-cert-deploy -- --test /srv/docker-vol/certs example.test ce-docker; }
run_deploy_fields() { cli "$DISP" to run agent --script agent-cert-deploy --input-fields /root/fields.json; }
run_svc()   { cli "$DISP" to run agent --script agent-service-restart; }
run_check() { cli "$DISP" to run agent --script agent-cert-check; }

# --- A: the field sequence, scripts.conf unchanged between runs ---------------
write_conf "$DEPLOY"
for round in 1 2; do
    out=$(run_deploy_test)
    { echo "== A$round deploy --test, no input"; echo "$out"; } >> "$EV"
    check "A$round: agent-cert-deploy --test without input runs as root" "$out" 'script=agent-cert-deploy user=root args=--test'
    out=$(run_deploy_fields)
    { echo "== A$round deploy with fields"; echo "$out"; } >> "$EV"
    check "A$round: agent-cert-deploy with input gets its three fields" "$out" 'field ca bytes=12'
    check_not "A$round: the field values are not in the output" "$out" 'rig-(cert|key|ca)-value'
    out=$(run_svc)
    { echo "== A$round agent-service-restart"; echo "$out"; } >> "$EV"
    check "A$round: agent-service-restart (context) runs after the fields run" "$out" 'user=ce-docker'
    for i in 1 2 3; do
        out=$(run_check)
        { echo "== A$round agent-cert-check #$i"; echo "$out"; } >> "$EV"
        check "A$round: agent-cert-check (context) run $i after the fields run" "$out" 'script=agent-cert-check user=nobody'
    done
done
out=$(x "$AGENT" 'ls -A /run/ctrl-exec-agent/ 2>&1; find /run/ctrl-exec-agent -mindepth 2 2>/dev/null | head' || true)
{ echo "== executor runtime dir after A"; echo "$out"; } >> "$EV"

# --- B: the deploy line as a paste can leave it, no reload --------------------
# Non-breaking spaces read as spaces in both parsers (T-059): every form runs
# exactly as the plain line does, and the agent logs one notice per load.
NBSP=$'\xc2\xa0'
declare -A VARIANT=(
    [nbsp-before-input]="agent-cert-deploy = /srv/scripts/agent-cert-deploy.sh profile=cert-deploy${NBSP}input=fields"
    [nbsp-before-profile]="agent-cert-deploy = /srv/scripts/agent-cert-deploy.sh${NBSP}profile=cert-deploy input=fields"
    [nbsp-everywhere]="agent-cert-deploy${NBSP}=${NBSP}/srv/scripts/agent-cert-deploy.sh${NBSP}profile=cert-deploy${NBSP}input=fields${NBSP}"
    [tabs]=$'agent-cert-deploy\t=\t/srv/scripts/agent-cert-deploy.sh\tprofile=cert-deploy\tinput=fields'
)
for v in nbsp-before-input nbsp-before-profile nbsp-everywhere tabs crlf; do
    since=$(mark)
    if [ "$v" = crlf ]; then write_conf "$DEPLOY" '' '' '' '\r\n'; else write_conf "${VARIANT[$v]}"; fi
    out=$(run_deploy_fields)
    { echo "== B $v: deploy with fields"; x "$AGENT" "cat -A $CONF"; echo "$out"; } >> "$EV"
    check "B $v: agent-cert-deploy runs as root with its three fields" "$out" 'field ca bytes=12'
    out=$(run_svc)
    { echo "== B $v: agent-service-restart"; echo "$out"; } >> "$EV"
    check "B $v: agent-service-restart runs" "$out" 'user=ce-docker'
    out=$(run_check)
    { echo "== B $v: agent-cert-check"; echo "$out"; } >> "$EV"
    check "B $v: agent-cert-check runs" "$out" 'script=agent-cert-check user=nobody'
    jout=$(jsince "$since")
    { echo "== B $v: agent journal"; echo "$jout"; } >> "$EV"
    check "B $v: the edit was picked up with no reload" "$jout" 'ACTION=allowlist-reload REASON=changed'
    check_not "B $v: nothing failed or was skipped" "$jout" 'reload-fail|allowlist-skip'
    case "$v" in
        nbsp-*) check "B $v: one notice that the file held non-ASCII spaces" "$jout" "ACTION=config-nonascii-space FILE=$CONF LINES=1" ;;
    esac
done

# --- C: scripts.conf edited, no reload: the next run uses it -------------------
# In the field (0.13.1) this refused the context scripts as "takes
# input=fields but the agent sent no input" until the agent was restarted.
since=$(mark)
write_conf "$DEPLOY" input=fields input=fields
out=$(run_svc)
{ echo "== C agent-service-restart, input=fields edited in, no reload"; echo "$out"; } >> "$EV"
check "C: agent-service-restart runs with the edited mode" "$out" 'user=ce-docker'
check_not "C: no mismatch refusal" "$out" 'no input|scripts.conf declares'
out=$(run_check)
{ echo "== C agent-cert-check"; echo "$out"; } >> "$EV"
check "C: agent-cert-check runs with the edited mode" "$out" 'script=agent-cert-check user=nobody'
jout=$(jsince "$since")
check "C: the agent logged the reload" "$jout" 'ACTION=allowlist-reload REASON=changed'
# A script added, another removed, still no reload.
write_conf "$DEPLOY" '' '' 'agent-extra = /srv/scripts/agent-cert-check.sh'
out=$(cli "$DISP" to run agent --script agent-extra)
{ echo "== C agent-extra (added)"; echo "$out"; } >> "$EV"
check "C: an added script runs at once" "$out" 'script=agent-cert-check user=nobody'
x "$AGENT" "sed -i '/^agent-cert-check /d' $CONF"
out=$(run_check)
{ echo "== C agent-cert-check (removed)"; echo "$out"; } >> "$EV"
check "C: a removed script is refused at once" "$out" 'script not permitted: not in scripts.conf'

# --- D: an undefined profile skips only that entry -----------------------------
since=$(mark)
write_conf "$DEPLOY" input=fields '' 'typo = /srv/scripts/agent-cert-check.sh profile=nosuch'
out=$(cli "$DISP" to run agent --script typo)
{ echo "== D typo"; echo "$out"; } >> "$EV"
check "D: the entry is refused with the reason" "$out" "script not permitted: profile 'nosuch' is not defined in agent.conf"
out=$(run_svc)
{ echo "== D agent-service-restart"; echo "$out"; } >> "$EV"
check "D: the rest of scripts.conf loaded" "$out" 'user=ce-docker'
jout=$(jsince "$since")
{ echo "== D agent journal"; echo "$jout"; } >> "$EV"
check_not "D: the reload did not fail" "$jout" 'reload-fail'
check "D: the entry is logged as skipped" "$jout" "ACTION=allowlist-skip REASON=\"profile 'nosuch' is not defined in agent.conf\" SCRIPT=typo"
out=$(x "$AGENT" 'ctrl-exec-agent self-check 2>&1' || true)
{ echo "== D self-check"; echo "$out"; } >> "$EV"
check "D: self-check lists it as skipped" "$out" "Script 'typo': SKIPPED - profile 'nosuch' is not defined in agent.conf"

# --- E: SIGHUP still reloads -------------------------------------------------------
since=$(mark)
reload
out=$(run_svc)
check "E: runs after a SIGHUP reload" "$out" 'user=ce-docker'
check "E: the reload is logged as signalled" "$(jsince "$since")" 'ACTION=allowlist-reload REASON=signal'

{ echo "== agent journal"; journal "$AGENT" 200; } >> "$EV"

if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$FAILED"
