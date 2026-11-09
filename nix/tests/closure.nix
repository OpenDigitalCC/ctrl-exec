# Check that a script given to services.ctrl-exec-agent.scripts.<name>.source
# as a path literal is part of the built system's closure, so a system built
# for another machine (a netboot or squashfs image) carries it.
#
# The VM test cannot show this: its machines mount the host's /nix/store,
# where the evaluated source tree exists anyway. Here the script is looked
# for by content (its sha256, which carries no store reference) among the
# files of the system's closure.
{ pkgs, lib, ... }:

let
  probe = ./closure-probe.sh;
  probeHash = builtins.hashFile "sha256" probe;

  system = import (pkgs.path + "/nixos/lib/eval-config.nix") {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      ../module.nix
      {
        boot.isContainer = true;
        system.stateVersion = lib.trivial.release;
        services.ctrl-exec-agent = {
          enable = true;
          package = (pkgs.callPackages ../package.nix { }).ctrl-exec-agent;
          scripts.probe.source = probe;
        };
      }
    ];
  };

  closure = pkgs.closureInfo { rootPaths = [ system.config.system.build.toplevel ]; };
in
pkgs.runCommand "ctrl-exec-agent-script-closure" { } ''
  while read -r p; do
    if [ -f "$p" ]; then
      case "$p" in *closure-probe.sh) echo "$p" ;; esac
    elif [ -d "$p" ]; then
      find "$p" -type f -name '*closure-probe.sh'
    fi
  done < ${closure}/store-paths > candidates
  found=
  while read -r f; do
    h=$(sha256sum "$f" | cut -d' ' -f1)
    if [ "$h" = "${probeHash}" ]; then found=$f; break; fi
  done < candidates
  if [ -z "$found" ]; then
    echo "scripts.probe.source is not in the system closure" >&2
    exit 1
  fi
  echo "found $found" > $out
''
