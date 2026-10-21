#!/bin/sh
# Stand-in for the estate's agent-cert-deploy.sh (profile cert-deploy: run_as
# root, CAP_CHOWN, writable certificate directory). Writes a file there and
# hands it to a group, which needs both the writable path and the capability.
set -e
echo "script=agent-cert-deploy user=$(id -un)"
f=/srv/docker-vol/certs/rig-probe.key
echo probe > "$f"
chgrp ce-docker "$f"
echo "wrote $f group=$(stat -c %G "$f")"
