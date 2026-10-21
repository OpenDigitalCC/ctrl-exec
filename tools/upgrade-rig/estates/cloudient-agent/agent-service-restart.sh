#!/bin/sh
# Stand-in for the estate's agent-service-restart.sh (profile svc-restart:
# run_as ce-docker, which needs its home for ~/.docker).
echo "script=agent-service-restart user=$(id -un) home=${HOME:-unset}"
