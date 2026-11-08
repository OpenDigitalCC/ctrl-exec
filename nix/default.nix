# Non-flake entry point:
#   nix-build nix -A ctrl-exec-agent            (or ctrl-exec-dispatcher)
#   nix-build nix -A tests.agent                (the NixOS VM test; needs KVM)
#   imports = [ (import /path/to/ctrl-exec/nix).module ];   (NixOS module)
{ pkgs ? import <nixpkgs> { } }:

(pkgs.callPackage ./package.nix { }) // {
  module = ./module.nix;
  tests.agent = pkgs.testers.runNixOSTest ./tests/agent.nix;
}
