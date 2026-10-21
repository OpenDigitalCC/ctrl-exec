# Upgrade rig host image: Debian trixie with systemd as PID 1, so the packages'
# maintainer scripts (systemctl, deb-systemd-invoke, daemon-reload, restart on
# upgrade) run exactly as on a real host. Every dependency of the ctrl-exec
# packages is installed here, so `dpkg -i` of the debs needs no network.
# No ctrl-exec package is in the image: each scenario installs the FROM debs
# into a fresh container and upgrades it to the TO debs.
FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        perl libjson-perl libio-socket-ssl-perl libwww-perl \
        liblwp-protocol-https-perl openssl adduser libcap2 \
        ca-certificates jq procps iproute2 \
 && rm -rf /var/lib/apt/lists/* /usr/sbin/policy-rc.d \
 && systemctl mask getty@.service console-getty.service \
        systemd-logind.service systemd-timesyncd.service apt-daily.timer \
        apt-daily-upgrade.timer dpkg-db-backup.timer e2scrub_all.timer \
        fstrim.timer 2>/dev/null || true

# systemd needs a writable cgroup tree. The container runs in a private cgroup
# namespace, so this remounts only the container's own subtree.
RUN printf '#!/bin/sh\nmount -o remount,rw /sys/fs/cgroup\nexec /sbin/init\n' \
        > /usr/local/sbin/rig-init \
 && chmod 755 /usr/local/sbin/rig-init

ENV container=docker
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/rig-init"]
