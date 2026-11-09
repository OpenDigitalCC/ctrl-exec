{
  description = "ctrl-exec: remote script execution over mTLS - packages and NixOS module for the agent";

  # nixos-26.05 is the current stable branch (flake.lock pins the revision).
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs:
        let p = pkgs.callPackages ./nix/package.nix { };
        in p // { default = p.ctrl-exec-agent; });

      # The module's `package` option defaults to the package built from this
      # repository; `pkgs.ctrl-exec-agent` (below) is for people who want it
      # in pkgs, or to override it.
      nixosModules.ctrl-exec-agent = ./nix/module.nix;
      nixosModules.default = self.nixosModules.ctrl-exec-agent;

      overlays.default = final: _prev: final.callPackages ./nix/package.nix { };

      checks = forAllSystems (pkgs: {
        agent = pkgs.testers.runNixOSTest ./nix/tests/agent.nix;
        script-closure = import ./nix/tests/closure.nix { inherit pkgs; inherit (pkgs) lib; };
      });
    };
}
