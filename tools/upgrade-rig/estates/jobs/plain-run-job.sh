#!/bin/bash
# A job in the shape of the 0.12-era deploy-cert.sh run_on(): a plain run,
# stdout and stderr captured together and parsed as JSON with jq.
#   plain-run-job.sh <agent> <script> [arg...]
# Uses ctrl-exec-cli from PATH and CTRL_EXEC_API_URL from the environment.
# Prints rc=, result_exit= and the captured output.
set -uo pipefail
host=$1
script=$2
shift 2
rc=0
RUN_OUT=$(ctrl-exec-cli run "$host" --script "$script" --json -- "$@" 2>&1) || rc=$?
result_exit=$(printf '%s' "$RUN_OUT" | jq -r '.results[0].exit // -1' 2>/dev/null || echo "parse-error")
echo "rc=$rc"
echo "result_exit=$result_exit"
echo "--- captured output"
printf '%s\n' "$RUN_OUT"
