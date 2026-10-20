#!/bin/bash
# Same bursts as series.sh but without the recovery waits: for a rig started with
# RIG_AGENT_EXTRA="rate_limit_disable = 1" (no agent rate limit), where failures
# are not expected to need minutes of idle to clear.
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")")
P="${1:?prefix}"
while read -r label total conc delay; do
    "$HERE/run.sh" "$P-$label" "$total" "$conc" "$delay"
    sleep 5
done <<LIST
t010-c1 10 1 0
t020-c1 20 1 0
t050-c1 50 1 0
t100-c1 100 1 0
t200-c1 200 1 0
t040-c2 40 2 0
t040-c4 40 4 0
t040-c8 40 8 0
LIST
