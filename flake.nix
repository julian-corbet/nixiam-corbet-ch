{
  description = "IAM infrastructure: an LDAP directory (lldap) and the pocket-id OIDC/SSO provider in front of it -- identity in the everyday sense, a human's login and the directory that remembers it -- plus the cross-host POSIX uid/gid registry (posix.nix) and the Kubernetes securityContext each entry implies -- identity in the completely different sense of what a host or container is allowed to touch. Successor to nixid, with the standalone nixposix registry folded back in as nixiam.posix.*: ACL, POSIX, and gid convergence all belong in the repo that already answers who a human is and how they prove it -- IAM, not merely \"id\". See README's \"Why posix folded back in\" for the full argument.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Used by `checks` only, for `posix.nix`'s own backend-parity proof (NixOS vs.
    # system-manager). The module itself takes no `pkgs` argument and never references this
    # input, so a consumer that imports only `nixosModules.lldap`/`."pocket-id"` pays no second
    # nixpkgs for it.
    system-manager.url = "github:numtide/system-manager";
    system-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, system-manager }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      # ---------------------------------------------------------------
      # Three independently toggleable pieces under one `nixiam.*` namespace -- IAM in full: WHO a
      # human is (lldap, the LDAP directory), how they PROVE it (pocket-id, the OIDC/SSO provider
      # in front of that directory), and WHAT a host/container identity is allowed to touch
      # (posix, the cross-host uid/gid registry + its derived Kubernetes securityContext). There
      # is no shared "core" engine to opt into (unlike nixnet's core+providers shape) -- import
      # any one on its own, lldap+pocket-id together for the common identity-provider pairing (see
      # README for the one piece of that pairing that stays manual), or posix alone on a host that
      # runs neither service at all.
      #
      # lldap and pocket-id are named after their actual upstream project, not an abstract role --
      # see each module's own header for why (a fake generic interface with exactly one
      # implementation behind it documents a boundary that doesn't exist). posix is pure data with
      # no upstream project behind it at all -- see its own header for why that boundary is
      # load-bearing, and why it costs nothing for even the smallest host to import.
      # ---------------------------------------------------------------
      nixosModules.lldap = ./modules/lldap.nix;
      nixosModules."pocket-id" = ./modules/pocket-id.nix;
      nixosModules.posix = ./modules/posix.nix;

      # posix.nix only -- see its own header for why it, alone of the three, ports cleanly to
      # every backend an operator manages: no `pkgs` argument, no `systemd.services`, nothing
      # NixOS-specific to be unavailable from. lldap/pocket-id stay NixOS-only (see README's "What
      # this deliberately does not do" for the specific system-manager barrier neither module has
      # been assessed against).
      systemManagerModules.posix = ./modules/posix.nix;
      systemManagerModules.default = self.systemManagerModules.posix;
      darwinModules.posix = ./modules/posix.nix;
      darwinModules.default = self.darwinModules.posix;

      checks = forAllSystems (system:
        import ./checks {
          pkgs = pkgsFor system;
          inherit lib nixpkgs system;
          nixiamModules = self.nixosModules;
          posixModule = self.nixosModules.posix;
          systemManagerLib = system-manager.lib;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
