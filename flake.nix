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
      # Six independently toggleable pieces under one `nixiam.*` namespace -- IAM in full: WHO a
      # human is (lldap, the LDAP directory; users, the declarative human-identity registry
      # projected into it), how they PROVE it (pocket-id, the OIDC/SSO provider in front of that
      # directory; vaultwarden, a password vault pocket-id can optionally front), WHAT a
      # host/container identity is allowed to touch (posix, the cross-host uid/gid registry + its
      # derived Kubernetes securityContext), and how a declared human actually LANDS in the running
      # directory (lldap-reconcile, the mechanism that reads `users` and converges it against
      # lldap's own GraphQL API). There is no shared "core" engine to opt into (unlike nixnet's
      # core+providers shape) -- import any one on its own, lldap+pocket-id together for the common
      # identity-provider pairing (see README for the one piece of that pairing that stays manual),
      # vaultwarden alongside pocket-id for SSO-fronted vault login (see vaultwarden.nix's own
      # header for why the master password stays regardless), users+lldap-reconcile together for
      # declarative human-identity provisioning, or posix alone on a host that runs no service at
      # all.
      #
      # lldap, pocket-id and vaultwarden are named after their actual upstream project, not an
      # abstract role -- see each module's own header for why (a fake generic interface with
      # exactly one implementation behind it documents a boundary that doesn't exist). posix and
      # users are pure data with no upstream project behind either -- see their own headers for why
      # that boundary is load-bearing, and why it costs nothing for even the smallest host to
      # import.
      # lldap-reconcile is the one piece here that is a mechanism rather than a table or a
      # service-in-itself: it acts on `users`, against a running lldap, and nothing else in this
      # repo may act on that table at all -- see modules/users.nix's own header for that split.
      # ---------------------------------------------------------------
      nixosModules.lldap = ./modules/lldap.nix;
      nixosModules."pocket-id" = ./modules/pocket-id.nix;
      nixosModules.posix = ./modules/posix.nix;
      # The guard that makes `posix` a contract instead of a suggestion: it compares the registry's
      # numbers against the accounts this host actually creates, and fails the build when they
      # disagree. NixOS-only on purpose (`config.users.users` exists nowhere else), which is why it
      # is a second file rather than a few lines inside the plane-agnostic posix.nix.
      #
      # Compose it wherever `posix` is composed. It is inert until a registry entry and a system
      # account of that name both exist, so adding it fleet-wide changes no evaluation -- and it is
      # what makes the FIRST registry entry safe to add, so it wants to be in place beforehand.
      nixosModules."posix-applied" = ./modules/posix-applied.nix;
      nixosModules.users = ./modules/users.nix;
      nixosModules."lldap-reconcile" = ./modules/lldap-reconcile.nix;
      # vaultwarden -- a self-hosted password vault, pocket-id's own SSO wired in as an OPTIONAL
      # front door (master password always stays as break-glass; see the module's own header for
      # why). NixOS-only, same as lldap/pocket-id (an actual service with a `pkgs` argument and a
      # systemd unit) -- unlike posix/users, which are pure data and reach system-manager/darwin too.
      nixosModules.vaultwarden = ./modules/vaultwarden.nix;

      # posix.nix only -- see its own header for why it ports cleanly to every backend an
      # operator manages: no `pkgs` argument, no `systemd.services`, nothing NixOS-specific to be
      # unavailable from. lldap/pocket-id stay NixOS-only (see README's "What this deliberately
      # does not do" for the specific system-manager barrier neither module has been assessed
      # against). `users.nix` is equally pure data but is NOT offered here -- its only current
      # consumer (`lldap-reconcile.nix`) is itself NixOS-only, so there is no real cross-backend
      # need for it yet; see `experiments/README.md` #016 for that left as an explicit, named
      # choice rather than a silent gap.
      systemManagerModules.posix = ./modules/posix.nix;
      systemManagerModules.default = self.systemManagerModules.posix;
      darwinModules.posix = ./modules/posix.nix;
      darwinModules.default = self.darwinModules.posix;
      systemManagerModules.packages = ./modules/packages.arch.nix;
      nixosModules.packages = ./modules/packages.nixos.nix;

      checks = forAllSystems (system:
        import ./checks {
          pkgs = pkgsFor system;
          inherit lib nixpkgs system;
          nixiamModules = self.nixosModules;
          posixModule = self.nixosModules.posix;
          usersModule = self.nixosModules.users;
          lldapReconcileModule = self.nixosModules."lldap-reconcile";
          systemManagerLib = system-manager.lib;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
