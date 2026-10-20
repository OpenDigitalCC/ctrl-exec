---
title: Upgrading
subtitle: Upgrade instructions between versions, including breaking changes and migration steps.
updated: 2026-03-16
github_url: https://github.com/OpenDigitalCC/ctrl-exec/blob/main/docs/UPGRADING.md
current_page: /upgrading
---

# Upgrade Procedure

The general upgrade procedure for all versions:

1. Review the section below for your version boundary. Note any breaking changes or migration steps before proceeding.

2. Back up state directories:
   ```bash
   sudo cp -a /etc/ctrl-exec-dispatcher /etc/ctrl-exec-dispatcher.bak.$(date +%Y%m%d)
   sudo cp -a /var/lib/ctrl-exec /var/lib/ctrl-exec.bak.$(date +%Y%m%d)
   ```

3. Pull the new version:
   ```bash
   cd /path/to/ctrl-exec
   git pull
   ```

4. Run the installer for each role:
   ```bash
   sudo ./install.sh --dispatcher
   # on each agent host:
   sudo ./install.sh --agent
   ```

5. Restart services:
   ```bash
   sudo systemctl restart ctrl-exec-api
   sudo systemctl restart ctrl-exec-agent
   ```

6. Verify:
   ```bash
   ced --version
   ced ping <hostname>
   ```

# Version Notes

## Upgrading to 0.13

Two names changed so that every part of ctrl-exec is `ctrl-exec-<part>`. The installer and the packages migrate an existing install, so there is nothing to do by hand.

- The executor `ctrl-exec-exec` is now `ctrl-exec-executor` (binary and `ctrl-exec-executor.service`). The old unit is stopped and removed, and the new one is enabled and started if the old one was.
- The dispatcher's config directory `/etc/ctrl-exec/` is now `/etc/ctrl-exec-dispatcher/`, to match `/etc/ctrl-exec-agent/`. An existing directory is moved and the paths in `ctrl-exec.conf` are updated. `/etc/ctrl-exec` stays as a symlink for this release only; it is removed in 0.14, so change any script or backup job that names it.

Containers are the exception. An image cannot move a directory that is a mounted volume, and an image built from the 0.13 packages already contains the new directory, so the old-path fallback never applies inside it. For a dispatcher container, change the mount target from `/etc/ctrl-exec` to `/etc/ctrl-exec-dispatcher`, edit the paths in `ctrl-exec.conf` on the mount, and rebuild. Leaving the mount at the old path can make an entrypoint that creates the CA when none is found create a second one. The Docker deployment guide has the steps.

::: textbox
Other version-specific notes will be added here as releases are made. Check [CHANGELOG.md](/changelog) for a full history of changes.
:::
