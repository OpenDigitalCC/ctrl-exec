#!/bin/sh
# Stand-in for the estate's agent-cert-check.sh (no profile=: the default
# profile, run_as nobody).
echo "script=agent-cert-check user=$(id -un) args=$*"
