{
  description = "Two independent things sharing one flake, never one repo's worth of coupling: an identity-provider STACK (an LDAP directory via lldap, and the pocket-id OIDC/SSO provider in front of it) and a fleet-wide POSIX uid/gid REGISTRY (posix.nix) -- pure data, no daemon, importable on its own by the smallest host in a fleet. See README's \"Two scopes, one repo\" section for why the registry is not a separate repository, and checks/default.nix's `posix-purity` group for the mechanical proof that importing it alone never pulls in the stack.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
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
      # A third, structurally different module: pure data, no service.
      # The fleet-wide POSIX uid/gid registry (and its generated
      # Kubernetes securityContext twin) that a separate dataset-shape
      # repo consumes -- never the other way around, see the module's
      # own header for why that direction is load-bearing.
      #
      # This is a genuinely different KIND of "identity" than the two
      # modules above -- a host/container uid/gid, not a human's login
      # credential -- sharing this repo and the `nixid.*` prefix by
      # administrative convenience, not by any relationship between what
      # they do. Import this on its own (see
      # examples/registry-only-host) and nothing from lldap.nix or
      # pocket-id.nix is ever evaluated, built, or installed -- see
      # README's "Two scopes, one repo" for why that already-true
      # property is what makes cohabiting one repo acceptable, and
      # checks/default.nix's `posix-purity` group for where it is
      # mechanically enforced rather than merely argued.
      # ---------------------------------------------------------------
      nixosModules.posix = ./modules/posix.nix;

      checks = forAllSystems (system:
        import ./checks {
          pkgs = pkgsFor system;
          inherit lib nixpkgs system;
          nixidModules = self.nixosModules;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
