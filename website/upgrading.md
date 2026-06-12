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
   sudo cp -a /etc/ctrl-exec /etc/ctrl-exec.bak.$(date +%Y%m%d)
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

::: textbox
Version-specific notes will be added here as releases are made. Check [CHANGELOG.md](/changelog) for a full history of changes.
:::
