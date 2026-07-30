# experiments/lldap-reconcile-harness.nix -- builds the REAL, Nix-generated
# nixiam-lldap-reconcile script (modules/lldap-reconcile.nix, unmodified) against a test
# nixiam.users declaration, pointed at whatever apiUrl/credentialFile the caller supplies.
#
# Exists so run-lldap-reconcile-proof.sh can execute the ACTUAL script this repo ships -- not a
# reimplementation of its logic -- against experiments/mock-lldap.py, and inspect what it
# actually did. `nix build --impure` this file with `--argstr apiUrl ... --argstr credentialFile
# ...` to get `result/bin/nixiam-lldap-reconcile`.
{ apiUrl, credentialFile }:
let
  flake = builtins.getFlake (toString ../.);
  system = "x86_64-linux";
  nixpkgs = flake.inputs.nixpkgs;
  pkgs = import nixpkgs { inherit system; };

  usersModule = flake.nixosModules.users;
  lldapReconcileModule = flake.nixosModules."lldap-reconcile";

  bareStubs = {
    fileSystems."/" = { device = "nodev"; fsType = "tmpfs"; };
    boot.loader.grub = { enable = true; devices = [ "nodev" ]; };
    networking.hostName = "example-node";
    system.stateVersion = "25.05";
  };

  # The scenario run-lldap-reconcile-proof.sh's own comment walks through end to end: alice is
  # wholly absent from the mock at the start (create user + group + membership); bob already
  # exists but is missing his declared group membership (create group + membership only); carol
  # is declared with enable = false and acknowledgeRemoval set, and already exists in the mock
  # (the one case this script is allowed to delete). "mallory", seeded directly into the mock and
  # never mentioned here at all, is this fixture's stand-in for undeclared drift.
  testUsers = {
    nixiam.users = {
      alice = {
        displayName = "Alice Example";
        email = "alice@example.com";
        groups = [ "admins" ];
      };
      bob = {
        displayName = "Bob Example";
        email = "bob@example.com";
        groups = [ "readers" ];
      };
      carol = {
        enable = false;
        acknowledgeRemoval = "experiment fixture -- proving the opt-in prune path";
        displayName = "Carol Example";
        email = "carol@example.com";
      };
    };

    nixiam.lldapReconcile = {
      enable = true;
      inherit apiUrl credentialFile;
      adminUsername = "admin";
    };
  };

  cfg = (import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    modules = [ usersModule lldapReconcileModule bareStubs testUsers ];
  }).config;

  execStart = cfg.systemd.services.nixiam-lldap-reconcile.serviceConfig.ExecStart;
in
pkgs.runCommand "nixiam-lldap-reconcile-harness" { } ''
  mkdir -p "$out/bin"
  ln -s ${execStart} "$out/bin/nixiam-lldap-reconcile"
''
