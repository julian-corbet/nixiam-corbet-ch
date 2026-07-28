# checks/default.nix
#
# EVAL-TIME tests, plus one enforcement group that the rest of this repo relies on to keep an
# honest promise. No VM, no build beyond forcing evaluation: nothing here starts lldap, binds a
# port, or performs an OIDC round trip -- see the README's "Verifying" section for where that
# line sits.
#
# Two independent groups:
#
#   1. `modules-evaluate` -- the composition check this repo has had since its first `nix flake
#      check`: all three modules (lldap, pocket-id, posix) composed into one NixOS system from
#      examples/host/configuration.nix, forcing every assertion either module makes. Moved here,
#      unchanged in spirit, purely to match this family's own checks/default.nix convention (see
#      nixfs, nixboot, nixstorage) instead of living inline in flake.nix.
#
#   2. `posix-purity` -- the mechanical enforcement modules/posix.nix's own header argues for at
#      length but, before this file existed, nothing actually checked. That header states a
#      guarantee in the present tense ("no systemd.services, no environment.systemPackages, no
#      pkgs argument at all") that was true only because nobody had violated it yet. Four
#      independent proofs, because each one catches a different way the promise could quietly
#      stop holding, plus three meta-tests proving the proofs themselves have teeth (the same
#      "prove the failing direction too" discipline nixboot's own checks/default.nix applies to
#      its assertions):
#
#        a. SOURCE, function signature -- modules/posix.nix's own lambda never binds a `pkgs`
#           argument, checked via `builtins.functionArgs` rather than a text search: a module can
#           reference `pkgs` under a different bound name or smuggle it in through `...`, but it
#           cannot LEGALLY use it as `pkgs` inside its own body without that name appearing as a
#           formal argument first. `functionArgs` reports exactly the formal arguments actually
#           bound, which is the property that matters.
#
#        b. SOURCE, text scan -- the two literal option paths this module must never write
#           (`systemd.services`, `environment.systemPackages`) do not appear anywhere in its
#           CODE. Comment lines are stripped first: this module's own header spends its entire
#           opening argument discussing exactly those two option paths in prose, which would trip
#           a naive whole-file scan on every revision regardless of what the code does. What
#           survives the strip is only what actually evaluates.
#
#        c. EVAL, systemd.services -- `nixosModules.posix` composed ALONE (never alongside
#           lldap.nix/pocket-id.nix; see examples/registry-only-host/configuration.nix) produces
#           the exact same set of systemd unit names as the identical system with the module
#           absent entirely. This is the proof (a)/(b) cannot give: it is not enough that the
#           module's own text never writes `systemd.services` directly -- an indirect path (a
#           helper function reached through `config`, an import this module's own header says it
#           must never perform) would still show up here even if it dodged the text scan.
#
#        d. EVAL, environment.systemPackages -- the same comparison, for the other option this
#           module's header names by name.
#
#      The three meta-tests use a deliberately broken stand-in module (never modules/posix.nix
#      itself) that DOES bind `pkgs`, DOES add a systemd unit, and DOES add a package, then
#      confirm each of (a), (c) and (d) actually notices. Without these, a bug in the comparison
#      itself (e.g. accidentally diffing a fixture against itself) would pass silently forever --
#      the real module never trips it, and nothing would ever prove the check *could* trip.
#
{ pkgs, lib, nixpkgs, system, nixidModules }:

let
  # (b) scans CODE, not the module's own prose. modules/posix.nix's header comment spends its
  # entire first section discussing exactly the two option paths this scan looks for -- that is
  # the whole point of the header, and it would trip a naive whole-file scan on every single
  # revision regardless of what the code actually does. Comment lines (anything whose first
  # non-blank character is `#`, which is every comment in this file -- there are no block
  # comments in Nix) are stripped before scanning; what remains is only what the module actually
  # evaluates.
  isCommentLine = line: builtins.match "[ \t]*#.*" line != null;
  stripComments = src:
    lib.concatStringsSep "\n"
      (lib.filter (l: !(isCommentLine l)) (lib.splitString "\n" src));

  posixSrc = stripComments (builtins.readFile nixidModules.posix);

  evalNixos = extraConfig:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system;
      modules = [ extraConfig ];
    }).config;

  # Identical stub set to examples/registry-only-host/configuration.nix, minus the
  # `nixid.posix` declaration -- the control group (c)/(d) diff the registry-only example
  # against. Kept as a literal copy, not a derived "example minus nixid" transform, so this
  # file's own control group can never silently drift out of sync with what the example
  # actually stubs.
  bareStubs = {
    fileSystems."/" = { device = "nodev"; fsType = "tmpfs"; };
    boot.loader.grub = { enable = true; devices = [ "nodev" ]; };
    networking.hostName = "example-registry-only-node";
    system.stateVersion = "25.05";
  };

  sorted = lib.sort (a: b: a < b);
  serviceNames = cfg: sorted (lib.attrNames cfg.systemd.services);
  packageNames = cfg: sorted (map (p: p.name) cfg.environment.systemPackages);

  check = name: ok: detail: { inherit name ok detail; };

  # ── Fixtures for (c)/(d): the real registry, composed on its own ──────────────────────────
  cfg-bare = evalNixos bareStubs;

  cfg-posix-alone = evalNixos {
    imports = [ nixidModules.posix ../examples/registry-only-host/configuration.nix ];
  };

  # ── A deliberately broken stand-in for posix.nix, used ONLY to prove (a)/(c)/(d) actually
  # have teeth -- never composed alongside the real modules/posix.nix, and never shipped as a
  # module this repo exports.
  brokenPosixModule = { config, lib, pkgs, ... }: {
    options.nixid.posix.enable = lib.mkEnableOption "decoy, for the purity check's own meta-tests -- never a real nixid module";
    config = lib.mkIf config.nixid.posix.enable {
      systemd.services.nixid-posix-decoy-unit.script = "exit 0";
      environment.systemPackages = [ pkgs.hello ];
    };
  };

  cfg-broken-posix-alone = evalNixos (bareStubs // {
    imports = [ brokenPosixModule ];
    nixid.posix.enable = true;
  });

  results = [
    # --- a. no `pkgs` argument on the real module ---------------------------------------
    (check "posix-purity/no-pkgs-argument"
      (!(lib.functionArgs (import nixidModules.posix) ? pkgs))
      "modules/posix.nix's own module function now binds a `pkgs` argument -- its header's opening paragraph promises this never happens")

    # --- b. the two forbidden option paths never appear in the real module's source ------
    (check "posix-purity/source-never-mentions-systemd-services"
      (!(lib.hasInfix "systemd.services" posixSrc))
      "modules/posix.nix's source text now contains the literal string \"systemd.services\"")

    (check "posix-purity/source-never-mentions-environment-systemPackages"
      (!(lib.hasInfix "environment.systemPackages" posixSrc))
      "modules/posix.nix's source text now contains the literal string \"environment.systemPackages\"")

    # --- c./d. composing the real module alone changes nothing observable ----------------
    (check "posix-purity/alone-adds-no-new-systemd-units"
      (serviceNames cfg-posix-alone == serviceNames cfg-bare)
      "composing nixosModules.posix alone changed systemd.services vs. the identical system without it -- got: ${builtins.toJSON (serviceNames cfg-posix-alone)}, expected: ${builtins.toJSON (serviceNames cfg-bare)}")

    (check "posix-purity/alone-adds-no-new-packages"
      (packageNames cfg-posix-alone == packageNames cfg-bare)
      "composing nixosModules.posix alone changed environment.systemPackages vs. the identical system without it -- got: ${builtins.toJSON (packageNames cfg-posix-alone)}, expected: ${builtins.toJSON (packageNames cfg-bare)}")

    # --- meta-tests: prove (a)/(c)/(d) are not vacuously true -----------------------------
    (check "posix-purity/mechanism-catches-a-real-systemd-unit (meta-test)"
      (serviceNames cfg-broken-posix-alone != serviceNames cfg-bare)
      "a decoy module that DOES add a systemd unit was not caught by the systemd.services comparison -- the comparison itself, not posix.nix, is what's broken")

    (check "posix-purity/mechanism-catches-a-real-package (meta-test)"
      (packageNames cfg-broken-posix-alone != packageNames cfg-bare)
      "a decoy module that DOES add environment.systemPackages was not caught by the package-name comparison -- the comparison itself, not posix.nix, is what's broken")

    (check "posix-purity/functionArgs-mechanism-catches-a-pkgs-argument (meta-test)"
      (lib.functionArgs brokenPosixModule ? pkgs)
      "the decoy module (which binds `pkgs` in its own header) was not detected by functionArgs -- the mechanism itself is broken")
  ];

  failed = builtins.filter (r: !r.ok) results;
  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;

  posix-purity =
    if failed != [ ]
    then
      throw ''
        nixid posix-purity checks FAILED (${toString (builtins.length failed)}/${toString (builtins.length results)}):
        ${report}
      ''
    else
    # Depending on `passedCount` forces `results`, so the tests genuinely run under
    # `nix flake check` rather than merely being defined.
      pkgs.runCommand "nixid-posix-purity-tests"
        { passedCount = toString (builtins.length results); }
        ''
          echo "all $passedCount nixid posix-purity checks passed"
          touch $out
        '';

  # ── modules-evaluate: unchanged composition check, moved here from flake.nix ──────────────
  modules-evaluate =
    let
      host = (import (nixpkgs + "/nixos/lib/eval-config.nix") {
        inherit system;
        modules = lib.attrValues nixidModules ++ [ ../examples/host/configuration.nix ];
      }).config;
    in
    # The string context around the derivation path MUST be discarded. A store path inside a
      # string is tracked as a build dependency, so keeping it would BUILD an entire NixOS system
      # rather than evaluate one -- minutes and a multi-gigabyte download versus seconds.
    pkgs.writeText "nixid-host-drvpath"
      (builtins.unsafeDiscardStringContext host.system.build.toplevel.drvPath);
in
{
  inherit modules-evaluate posix-purity;
}
