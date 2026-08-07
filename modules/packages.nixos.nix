# NixOS backend for nixiam baseline packages.
#
# Unlike the Arch-backed system-manager plane, nixpkgs package installation is
# part of the same evaluation and can be done directly from this module.
{ config, lib, pkgs, ... }:
let
  cfg = config.nixiam.packages;

  # A name is only resolvable if it is BOTH present and forceable, and the two are checked in that
  # order because they fail in incompatible ways.
  #
  # 1. ABSENT. `lib.getAttrFromPath` reports a missing path with `abort`, and `abort` is not
  #    catchable -- `builtins.tryEval (abort "x")` propagates the abort rather than returning
  #    `{ success = false; }`, unlike `throw`. Wrapping it in `tryEval` therefore does not degrade
  #    an unresolvable name into an assertion; it takes the WHOLE evaluation down, including every
  #    unrelated check in the same run, with nixpkgs' message rather than this module's. So the
  #    path is probed with `hasAttrByPath` first and only read once it is known to exist.
  #
  # 2. PRESENT BUT NOT FORCEABLE. Presence alone is not resolution, so `hasAttrByPath` cannot be
  #    the whole test. nixpkgs keeps a renamed package's old name as a `throw`-aliased placeholder
  #    (`bitwarden` is exactly that -- see packages.nix's `nixosNameFor`), and it refuses a package
  #    whose dependency carries `meta.knownVulnerabilities` at the point the derivation is
  #    instantiated, not on the attribute itself. `hasAttrByPath` answers `true` for both: the
  #    attribute genuinely exists, and only forcing it tells the two apart from a real package.
  #
  #    This distinction is not academic. Forcing to weak head normal form is not enough either --
  #    the value has to be taken all the way to a `drvPath`, which is what the insecure-dependency
  #    refusal actually guards. Without that, an uninstallable entry passes this filter, lands in
  #    `environment.systemPackages`, and surfaces only when a real host build forces the list,
  #    with nixpkgs' message instead of the assertion below naming the package.
  #
  #    Unlike the absent case, this one IS catchable: these are `throw`s, not `abort`s.
  forceable = value: (builtins.tryEval (builtins.seq value.drvPath true)).success;

  resolves = pkgName:
    lib.hasAttrByPath (lib.splitString "." pkgName) pkgs
    && forceable (lib.getAttrFromPath (lib.splitString "." pkgName) pkgs);

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

        Each is either absent under that attribute path, or present but refusing to be
        instantiated -- a `throw`-aliased name nixpkgs has since renamed, or a package held back
        by a dependency marked insecure. Check the name against this nixpkgs first; if it is
        correct and merely held back, the fix is to advance the nixpkgs this host evaluates
        against, not to permit the insecure dependency.
      '';
    };
  };
}
