#!/bin/bash
# The T-001 attempt series against the running rig: serialised bursts of
# 10..200 then concurrency 2, 4, 8, each followed by idle recovery measurement
# and a settle so every burst starts with an empty rate window.
#   ./series.sh PREFIX
set -euo pipefail
HERE=$(readlink -f "$(dirname "$0")")
P="${1:?prefix}"
while read -r label total conc delay; do
    "$HERE/run.sh" "$P-$label" "$total" "$conc" "$delay"
    "$HERE/recover.sh" "$P-$label" 10 65
done <<LIST
t020-c1 20 1 0
t050-c1 50 1 0
t100-c1 100 1 0
t200-c1 200 1 0
t040-c2 40 2 0
t040-c4 40 4 0
t040-c8 40 8 0
LIST
