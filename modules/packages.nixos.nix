# NixOS backend for nixiam baseline packages.
#
# Unlike the Arch-backed system-manager plane, nixpkgs package installation is
# part of the same evaluation and can be done directly from this module.
{ config, lib, pkgs, ... }:
let
  cfg = config.nixiam.packages;

  # Existence is TESTED, never caught. `lib.getAttrFromPath` reports a missing path with `abort`,
  # and `abort` is not catchable -- `builtins.tryEval (abort "x")` propagates the abort rather than
  # returning `{ success = false; }`, unlike `throw`. Wrapping it in `tryEval` therefore does not
  # degrade an unresolvable name into an assertion; it takes the WHOLE evaluation down, including
  # every unrelated check in the same run, with nixpkgs' message rather than this module's. So the
  # path is probed with `hasAttrByPath` first and only read once it is known to exist.
  resolves = pkgName: lib.hasAttrByPath (lib.splitString "." pkgName) pkgs;
  read = pkgName: lib.getAttrFromPath (lib.splitString "." pkgName) pkgs;

  installable = map read (lib.filter resolves cfg.nixosPackages);
  unavailable = lib.filter (pkgName: !resolves pkgName) cfg.nixosPackages;
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
