# NixOS backend for nixiam baseline packages.
#
# Unlike the Arch-backed system-manager plane, nixpkgs package installation is
# part of the same evaluation and can be done directly from this module.
{ config, lib, pkgs, ... }:
let
  cfg = config.nixiam.packages;

  evaluate = pkgName: builtins.tryEval (lib.getAttrFromPath (lib.splitString "." pkgName) pkgs);
  evals = map
    (pkgName: { inherit pkgName; result = evaluate pkgName; })
    cfg.nixosPackages;

  installable = map (entry: entry.result.value) (lib.filter (entry: entry.result.success) evals);
  unavailable = map (entry: entry.pkgName) (lib.filter (entry: !entry.result.success) evals);
in
{
  imports = [ ./packages.nix ];

  config = {
    environment.systemPackages = lib.unique installable;
    assertions = lib.optional (unavailable != [ ]) {
      assertion = false;
      message = ''
        nixiam: ${toString (builtins.length unavailable)} declared baseline package(s) do not resolve in this nixpkgs:
        ${lib.concatStringsSep ", " unavailable}
      '';
    };
  };
}
