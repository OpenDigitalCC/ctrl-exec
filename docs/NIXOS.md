---
title: ctrl-exec - NixOS
subtitle: Running the agent on NixOS with the flake and module
brand: odcc
---

# ctrl-exec on NixOS

`install.sh` does not apply to NixOS (it creates users, patches installed files
and builds the executor in place). The repository carries a Nix flake instead:
packages for the agent and the dispatcher, and a NixOS module for the agent.
The dispatcher is a package only; run `ced setup-ca` and the rest as described
in `INSTALL.md`.

The flake follows the `nixos-26.05` branch of nixpkgs (the revision is pinned in
`flake.lock`).

## Use

```nix
{
  inputs.ctrl-exec.url = "github:OpenDigitalCC/ctrl-exec";

  outputs = { nixpkgs, ctrl-exec, ... }: {
    nixosConfigurations.agent-01 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ctrl-exec.nixosModules.ctrl-exec-agent
        {
          services.ctrl-exec-agent = {
            enable = true;
            openFirewall = true;
            scripts.backup-db.source = ./backup-db.sh;
          };
        }
      ];
    };
  };
}
```

Without flakes: `imports = [ (import /path/to/ctrl-exec/nix).module ];`.
`nix build .#ctrl-exec-agent` and `.#ctrl-exec-dispatcher` build the packages.
`nix flake check` runs the VM test (`checks.<system>.agent`, needs KVM) and
`script-closure`, which builds a system and checks that a script given as a
path literal is in its closure.

## Pairing

Pairing is the same as on other platforms and is not declarative: the agent
writes its certificate, key and CA into `/etc/ctrl-exec-agent` itself. After
`nixos-rebuild switch`, on the host:

```bash
sudo ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>
```

approve it on the dispatcher, then `sudo systemctl start ctrl-exec-agent`. Until
the agent is paired its unit fails once with the "not paired" message and does
not restart in a loop.

Add `--name <agent-name>` to request-pairing to register under a name of your
choosing instead of the host's FQDN.

## Options

`services.ctrl-exec-agent.` followed by:

`enable`, `package`
: The service, and the package (default: built from this repository).

`port`, `openFirewall`
: Listen port (default 7443) and whether to open it in the firewall.

`scripts.<name>.source`, `scripts.<name>.options`
: The allowlist. See *Scripts* below. `options` are the `key=value` options of
  a `scripts.conf` entry (`profile`, `input`, `output`, `dispatchers`).

`profiles.<name>`
: `[profile <name>]` sections of `agent.conf`. `default` is defined for you
  (`run_as = nobody`) unless you set it.

`settings`, `extraConfig`, `tags`
: Other `agent.conf` keys (for example `script_ownership = "strict"`), verbatim
  top-level lines, and the `[tags]` section.

`scriptPath`
: See *Script PATH*.

`executor.enable`
: See *The executor*.

## Scripts: copied out of the Nix store

The agent and the executor refuse a script unless it, and every directory on
its resolved path, is owned by root and not group- or world-writable
(`SECURITY.md`, "Script ownership"). `/nix/store` is `root:nixbld` mode 1775,
so a script left in the store, or reached through `/run/current-system`, fails
that check. The trust walk is unchanged on NixOS; the module works with it.

Each entry in `scripts` is copied, at every activation (boot and
`nixos-rebuild switch`), to `/opt/ctrl-exec-scripts/<name>` as a regular
root-owned `0755` file, never a symlink, and `scripts.conf` points at that
copy. The copy satisfies `script_ownership = "strict"`. A script removed from
the configuration is removed from the directory (the module keeps a list of
what it installed in `/opt/ctrl-exec-scripts/.nix-managed` and touches nothing
else there). Names are limited to `[A-Za-z0-9_-]`.

A script can still use store programs: write `#!/nix/store/.../bash` lines (for
example with `pkgs.writeShellScript`) or absolute paths. Only the script file
itself must sit outside the store.

## Script PATH

The built-in PATH scripts run with is the FHS one (`/usr/local/sbin` ...
`/bin`), which holds almost nothing on NixOS. `scriptPath` (default
`/run/wrappers/bin:/run/current-system/sw/bin`) is written to `agent.conf` as
`script_path`. A script that starts with `#!/usr/bin/env perl` or calls bare
commands then finds them in the system profile. Add other directories to
`scriptPath` for packages that are not in `environment.systemPackages`.

## The executor

Off by default, as on other platforms. `executor.enable = true` runs
`ctrl-exec-executor.service` (root, not sandboxed, as in `etc/systemd/`) and
sets `executor_socket`. Profiles (`run_as`, capabilities, writable paths) are
applied only with it, and `--async` runs are refused while it is on.

## What the module sets up

- User and group `ctrl-exec-agent`; `nobody` for the default profile.
- `/etc/ctrl-exec-agent` (`0750 root:ctrl-exec-agent`) is created, not owned,
  by Nix: pairing and `promote-cert` write into it. Only `agent.conf` and
  `scripts.conf` are managed there, as real copies (`0640 root:ctrl-exec-agent`),
  not links into the store.
- `/var/lib/ctrl-exec-agent` (`0750`, agent user) and `/opt/ctrl-exec-scripts`
  (`0755 root:root`).
- `ctrl-exec-agent.service`, `ctrl-exec-executor.service` (when enabled),
  `ctrl-exec-agent-renew.service` and `.timer`, with every hardening setting of
  `etc/systemd/` and store paths in place of the FHS ones. A change to
  `agent.conf` restarts the agent; a change to the scripts only reloads it.
- The package wraps the programs so `openssl` and the non-core Perl modules
  (`JSON`, `IO::Socket::SSL`; the dispatcher adds `LWP`) are found without any
  system-wide install.
