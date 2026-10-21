#!/bin/bash
# Scenario 4: a job sends confidential input (--input-fields) over plain HTTP
# to a dispatcher that is not on loopback, capturing the CLI's stdout and
# stderr together (2>&1) and parsing them as JSON - the shape of cert-deploy's
# deploy-cert.sh. Dispatcher and agent hosts are installed on FROM and upgraded
# to TO (debs only); input fields are a TO feature, so the agent's script with
# input=fields is added after the upgrade, as an operator adopting it would.
# The job runs on the agent host against http://dispatcher:7445 with the TO
# CLI. A control run of the same job against the dispatcher's own loopback
# shows that the input itself works, so a failure on the network URL is the
# CLI's plain-HTTP handling and nothing else.
# shellcheck disable=SC2016  # shell text for `docker exec bash -c` expands in the container
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")/..")
# shellcheck source-path=SCRIPTDIR/..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

NET="$RIG_PREFIX-s4-net"
DISP="$RIG_PREFIX-s4-dispatcher"
AGENT="$RIG_PREFIX-s4-agent"
EV=${RIG_EVIDENCE:-/dev/null}

net_create "$NET"
host_start "$DISP" dispatcher "$NET"
host_start "$AGENT" agent "$NET"

dispatcher_install "$DISP" > /dev/null
wait_api "$DISP" || die_setup "FROM API not answering"
agent_install "$AGENT"
plain_layout "$AGENT"
pair "$DISP" "$AGENT" agent
out=$(cli "$DISP" to run agent --script rig-hello)
check "FROM baseline: API run" "$out" 'rig-hello user=nobody'
[ "$FAILED" = 0 ] || { echo "RESULT: ERROR (the estate does not work on FROM)"; exit 2; }

{ echo "== dispatcher dpkg -i (TO)"; install_debs "$DISP" to common dispatcher 2>&1; } >> "$EV" || nok "dispatcher dpkg -i of TO exited non-zero"
{ echo "== agent dpkg -i (TO)"; install_debs "$AGENT" to common agent 2>&1; } >> "$EV" || nok "agent dpkg -i of TO exited non-zero"
note "TO: dispatcher $(pkg_version "$DISP" dispatcher), agent $(pkg_version "$AGENT" agent)"
wait_api "$DISP" || true
wait_agent "$AGENT" || true

# Adopt the TO feature: a script that takes its input as fields.
x "$AGENT" 'set -e
    cat > /opt/ctrl-exec-scripts/fields-probe.sh << "EOS"
#!/bin/sh
n=$(wc -c < "$CTRL_EXEC_INPUT/secret")
echo "fields-probe user=$(id -un) secret-bytes=$n"
EOS
    chown root:root /opt/ctrl-exec-scripts/fields-probe.sh
    chmod 755 /opt/ctrl-exec-scripts/fields-probe.sh
    echo "fields-probe = /opt/ctrl-exec-scripts/fields-probe.sh input=fields" >> /etc/ctrl-exec-agent/scripts.conf
    systemctl reload ctrl-exec-agent.service' || die_setup "adding the input=fields script failed"
sleep 2

docker cp "$HERE/estates/jobs/input-fields-job.sh" "$AGENT:/usr/local/bin/input-fields-job.sh" > /dev/null
docker cp "$HERE/estates/jobs/input-fields-job.sh" "$DISP:/usr/local/bin/input-fields-job.sh" > /dev/null

# Control: the same job on the dispatcher host, API on loopback (no warning).
out=$(x "$DISP" "CTRL_EXEC_TOKEN=$RIG_TOKEN CTRL_EXEC_API_URL=http://127.0.0.1:7445 input-fields-job.sh /rig-cli/ctrl-exec-cli-to agent fields-probe" || true)
{ echo "== control: job over loopback"; echo "$out"; } >> "$EV"
check "control (loopback): the input reaches the script" "$out" 'fields-probe user=nobody secret-bytes=17'
check "control (loopback): 2>&1 output parses, result exit 0" "$out" '^result_exit=0$'

# The case: plain HTTP to the dispatcher by name, from another host.
out=$(x "$AGENT" "CTRL_EXEC_TOKEN=$RIG_TOKEN CTRL_EXEC_API_URL=http://dispatcher:7445 input-fields-job.sh /rig-cli/ctrl-exec-cli-to agent fields-probe" || true)
{ echo "== job over plain HTTP to http://dispatcher:7445"; echo "$out"; } >> "$EV"
echo "$out" | sed -n '1,4p' | sed 's/^/#   /'
check "plain HTTP: the CLI exits 0" "$out" '^rc=0$'
check "plain HTTP: 2>&1 output parses as JSON, result exit 0" "$out" '^result_exit=0$'
check "plain HTTP: the input reaches the script" "$out" 'secret-bytes=17'
check_not "plain HTTP: the secret value is not in the output" "$out" 'rig-secret-value'

{ echo "== agent journal"; journal "$AGENT" 80; } >> "$EV"

if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$FAILED"
