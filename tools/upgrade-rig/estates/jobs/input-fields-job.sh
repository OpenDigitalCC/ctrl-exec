#!/bin/bash
# A job in the shape of cert-deploy's deploy-cert.sh run_on(): confidential
# input fields piped to ctrl-exec-cli, stdout and stderr captured together and
# parsed as JSON with jq. The API is wherever CTRL_EXEC_API_URL points.
#   input-fields-job.sh <cli> <agent> <script>
# Prints rc=, result_exit= and the captured output.
set -uo pipefail
cli=$1
host=$2
script=$3
FIELDS='{"secret":"rig-secret-value\n"}'
rc=0
RUN_OUT=$(printf '%s' "$FIELDS" \
    | perl "$cli" run "$host" --script "$script" --json --input-fields - 2>&1) || rc=$?
result_exit=$(printf '%s' "$RUN_OUT" | jq -r '.results[0].exit // -1' 2>/dev/null || echo "parse-error")
echo "rc=$rc"
echo "result_exit=$result_exit"
echo "--- captured output"
printf '%s\n' "$RUN_OUT"
