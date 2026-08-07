# Declarative package intent for nixiam consumers.
#
# Nixiam is currently a small IAM repo, but it still needs the same baseline tools
# everywhere its systems are managed from:
# - sudo (host maintenance and troubleshooting)
# - sops (secret lifecycle tooling)
# - age (crypto envelope/decryption workflows)
# - bitwarden (desktop GUI client for password-vault bootstrap and recovery paths)
# - bitwarden-cli (password-vault bootstrap and recovery paths)
# - rbw (Rust Bitwarden CLI client used by ops scripts)
#
# Keeping this as declarative package policy in this repo means all consumers can opt
# into the same floor without hand-maintaining identical host-local package lists.
{ config, lib, ... }:
let
  cfg = config.nixiam.packages;

  # nixpkgs renamed its `bitwarden` attribute to `bitwarden-desktop` (the bare name is now a
  # `throw`-aliased placeholder, not a working derivation) while the pacman package kept the name
  # `bitwarden`. The baseline below records the pacman/operator-facing name; this map corrects
  # only the NixOS-facing attribute for the one entry where the two diverge.
  nixosNameFor = name: { bitwarden = "bitwarden-desktop"; }.${name} or name;
in
{
  options.nixiam.packages = {
    # Baseline package names before backend mapping.
    baseline = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "age"
        "bitwarden"
        "bitwarden-cli"
        "rbw"
        "sops"
        "sudo"
      ];
      defaultText = lib.literalExpression ''
        [
          "age"
          "bitwarden"
          "bitwarden-cli"
          "rbw"
          "sops"
          "sudo"
        ]'';
      description = ''
        Baseline packages this module declares for all nixiam consumers, before a
        backend maps them to its concrete package source format.
      '';
    };

    # Platform-mapped outputs consumed by backends.
    archPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        Baseline pacman package names. This keeps the public face of the policy
        one list while each backend maps to its own package source.
      '';
    };

    aurPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        Baseline AUR package names. Left empty for this policy today because all
        declared baseline entries have an official pacman name.
      '';
    };

    nixosPackages = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      readOnly = true;
      description = ''
        NixOS package attribute names (as seen by nixpkgs). Equal to
        `nixiam.packages.baseline` except where a baseline entry's nixpkgs attribute
        diverges from its pacman name (see `nixosNameFor` above).
      '';
    };
  };

  config.nixiam.packages = {
    archPackages = lib.unique cfg.baseline;
    aurPackages = [ ];
    nixosPackages = lib.unique (map nixosNameFor cfg.baseline);
  };
}

