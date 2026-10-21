#!/bin/bash
# Lay out the estate on the agent host, as the operator did on 0.12: a sysadmin
# account in a shared admin group, scripts in /srv/scripts (2775 root:sysadmin)
# owned by sysadmin, one of them group-writable (775), a service account
# ce-docker with a home. With "srv-group-writable", /srv itself is 2775
# root:sysadmin too (the 1b variant). Then the profiles and the allowlist.
# Runs as root inside the agent container, from a copy of this directory.
set -euo pipefail
variant=${1:-}
src=$(dirname "$(readlink -f "$0")")

groupadd --gid 1000 sysadmin
useradd --uid 1000 --gid sysadmin --create-home --shell /bin/bash sysadmin
useradd --system --create-home --home-dir /home/ce-docker --shell /usr/sbin/nologin ce-docker

if [ "$variant" = srv-group-writable ]; then
    chown root:sysadmin /srv
    chmod 2775 /srv
fi
mkdir -p /srv/scripts /srv/docker-vol/certs
chown root:sysadmin /srv/scripts
chmod 2775 /srv/scripts
for s in agent-cert-deploy agent-service-restart agent-cert-check; do
    install -o sysadmin -g sysadmin -m 755 "$src/$s.sh" "/srv/scripts/$s.sh"
done
chmod 775 /srv/scripts/agent-service-restart.sh

cat "$src/profiles.conf" >> /etc/ctrl-exec-agent/agent.conf
cp "$src/scripts.conf" /etc/ctrl-exec-agent/scripts.conf
rm -rf "$src"
