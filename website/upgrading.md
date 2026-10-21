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
- The dispatcher's config directory `/etc/ctrl-exec/` is now `/etc/ctrl-exec-dispatcher/`, to match `/etc/ctrl-exec-agent/`. An existing directory is moved and the paths in `ctrl-exec.conf` are updated, and `/etc/ctrl-exec` is left as a symlink to the new directory.

From 0.14 an upgrade needs no manual step in any of the usual layouts. The real config is the directory holding `ctrl-exec.conf` and the CA key `ca.key`; the packages and the container image seed `/etc/ctrl-exec-dispatcher` with an example and no CA. The packages and `install.sh` move a real `/etc/ctrl-exec` when the new directory is absent or only that seeded example (the seeded one is kept as `/etc/ctrl-exec-dispatcher.seeded`). A config that cannot be moved, such as a container volume mounted at `/etc/ctrl-exec`, is used in place with its paths unchanged and logged as `ACTION=config-dir RESULT=in-place`, so a compose file from 0.12 works as it is; the mount can be moved to `/etc/ctrl-exec-dispatcher` at leisure (the Docker deployment guide has the steps). A host without a real `/etc/ctrl-exec` sees no change.

What is still refused is the state no tool can resolve for you: both directories holding a CA, an `/etc/ctrl-exec` with no CA, or a symlink there to another directory. `ced` and `ctrl-exec-api` then print both paths, log `ACTION=config-dir RESULT=refused` and exit 78 until you keep the directory whose CA your agents trust, merge it into `/etc/ctrl-exec-dispatcher` and remove the old one.

::: textbox
Other version-specific notes will be added here as releases are made. Check [CHANGELOG.md](/changelog) for a full history of changes.
:::
