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

      formatter = forAllSystems (system: (import nixpkgs { inherit system; }).nixpkgs-fmt);
    };
}
