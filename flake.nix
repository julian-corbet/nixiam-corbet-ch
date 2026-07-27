{
  description = "Identity infrastructure for a self-hosted stack: an LDAP directory (lldap) and the OIDC/SSO provider (pocket-id) in front of it. Not a mail package -- mail, a git forge, a Kubernetes dashboard, and anything else that authenticates users are all just consumers of this repo, never the other way around.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
    in
    {
      # ---------------------------------------------------------------
      # Two independent services -- there is no shared "core" engine to
      # opt into here (unlike nixnet's core+providers shape). Import
      # either on its own, or both together for the common pairing (an
      # OIDC provider synced against this repo's own directory -- see
      # README for the one piece of that pairing that stays manual).
      #
      # Named after the actual upstream project behind each module, not
      # an abstract role -- see each module's own header comment for why
      # (a fake generic interface with exactly one implementation behind
      # it documents a boundary that doesn't exist).
      # ---------------------------------------------------------------
      nixosModules.lldap = ./modules/lldap.nix;
      nixosModules."pocket-id" = ./modules/pocket-id.nix;

      # ---------------------------------------------------------------
      # Both modules composed into one NixOS system, from examples/host.
      # They share the `nixid.*` namespace, so this is what
      # catches a collision between them — the failure mode a per-module
      # check cannot see by construction. It also exercises every
      # assertion either module makes, which is where the interesting
      # constraints live: a directory and the SSO provider in front of it
      # have to agree about the base DN and about which port the provider
      # binds against.
      #
      # This checks that the modules EVALUATE. It does not start lldap,
      # does not bind a port, and does not perform a login — see the
      # README for where that line sits.
      # ---------------------------------------------------------------
      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          host = lib.nixosSystem {
            inherit system;
            modules = lib.attrValues self.nixosModules
              ++ [ ./examples/host/configuration.nix ];
          };
        in
        {
          # The string context around the derivation path MUST be discarded. A
          # store path inside a string is tracked as a build dependency, so
          # keeping it would BUILD an entire NixOS system rather than evaluate
          # one — minutes and a multi-gigabyte download versus seconds.
          modules-evaluate =
            pkgs.writeText "nixid-host-drvpath"
              (builtins.unsafeDiscardStringContext host.config.system.build.toplevel.drvPath);
        });

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
