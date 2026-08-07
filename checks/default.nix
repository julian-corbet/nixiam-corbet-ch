# checks/default.nix
#
# EVAL-TIME tests. No VM, no build beyond forcing evaluation: nothing here starts lldap, binds a
# port, performs an OIDC round trip, or runs any acting code at all -- posix.nix has none to run in
# the first place. Two independent groups, kept separate because they prove different things about
# different modules:
#
#   `modules-evaluate` -- every module this flake exports (lldap, pocket-id, posix) composed into
#   one NixOS system from examples/host/configuration.nix, forcing every assertion each one makes.
#   `nixiamModules` is `self.nixosModules` in full, so posix rides along too, composed but disabled
#   (examples/host declares no `nixiam.posix`), which is itself the running proof that an unused
#   registry costs the identity-provider stack nothing. examples/host is deliberately NOT where
#   posix gets exercised for real -- see `eval-tests` below for that.
#
#   `eval-tests` -- modules/posix.nix's own five check groups (`posix-purity`, `module`,
#   `podSecurity`, `backend-parity`, `example`). See each group's own comment below for what it
#   proves. `example` composes examples/posix-registry/configuration.nix (a separate directory from
#   THIS repo's own examples/host, the lldap+pocket-id fixture above) -- posix ALONE, deliberately
#   never alongside lldap/pocket-id: the purity proof needs to see posix's effect in isolation
#   against a bare system, and the backend-parity proof exercises system-manager, which
#   lldap/pocket-id have never been assessed against (see README's "What this deliberately does
#   not do").
#
#   Two more groups, `users-registry` and `lldap-reconcile`, prove modules/users.nix and
#   modules/lldap-reconcile.nix the same way: every assertion in both directions, plus the one
#   asymmetry that makes users.nix's own posixIdentity reference DIFFERENT from posix.nix's own
#   uid-collision assertions above -- it must additionally stay SILENT when nixiam.posix is not
#   imported into the composed system at all, proven by evaluating usersModule genuinely alone,
#   never alongside posixModule, for that one fixture. Nothing here starts lldap-reconcile's own
#   systemd unit or calls its script against anything -- that proof (idempotency; the
#   deletion-refusal behavior) is necessarily a runtime property of a shell script talking to a
#   real or mocked lldap, not something Nix evaluation alone can demonstrate; see
#   experiments/README.md for where that was actually exercised, against a local mock, never a
#   live lldap.
{ pkgs, lib, nixpkgs, system, nixiamModules, posixModule, usersModule, lldapReconcileModule, systemManagerLib }:

let
  # ══ modules-evaluate: every exported module, composed from examples/host ═══════════════════════
  modules-evaluate =
    let
      host = (import (nixpkgs + "/nixos/lib/eval-config.nix") {
        inherit system;
        modules = lib.attrValues nixiamModules ++ [ ../examples/host/configuration.nix ];
      }).config;
    in
    # The string context around the derivation path MUST be discarded. A store path inside a
      # string is tracked as a build dependency, so keeping it would BUILD an entire NixOS system
      # rather than evaluate one -- minutes and a multi-gigabyte download versus seconds.
    pkgs.writeText "nixiam-host-drvpath"
      (builtins.unsafeDiscardStringContext host.system.build.toplevel.drvPath);

  # ══ eval-tests: modules/posix.nix's own five check groups ══════════════════════════════════════

  check = name: ok: detail: { inherit name ok detail; };

  # ── Shared fixtures ═══════════════════════════════════════════════════════════════════════════

  # Stubs NixOS demands of any bootable system. Not a machine anyone would run -- it exists so a
  # module can type-check entirely on its own.
  bareStubs = {
    fileSystems."/" = { device = "nodev"; fsType = "tmpfs"; };
    boot.loader.grub = { enable = true; devices = [ "nodev" ]; };
    networking.hostName = "example-node";
    system.stateVersion = "25.05";
  };

  validRegistry = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      identities = {
        example-app = { uid = 3000; };
        example-linuxserver-app = { uid = 3001; variant = "puid"; };
      };
      groups.shared-readers.gid = 3100;
    };
  };

  domainUnset = {
    nixiam.posix = {
      enable = true;
      identities.example-app.uid = 3000;
    };
  };

  baselineWithMissingPackage = {
    nixiam.packages.baseline = [
      "age"
      "sops"
      "sudo"
      "bitwarden-cli"
      "rbw"
      "definitely-does-not-exist-in-nixpkgs"
    ];
  };

  uidCollision = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      identities = {
        a = { uid = 3000; };
        b = { uid = 3000; };
      };
    };
  };

  # b's EXPLICIT gid (3000) collides with a's UPG-resolved gid (a has no gid set, so it resolves
  # to a's own uid, 3000) -- the collision this fixture exercises only exists after UPG
  # resolution, never as two identical literal `gid` fields.
  gidCollision = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      identities = {
        a = { uid = 3000; };
        b = { uid = 3001; gid = 3000; };
      };
    };
  };

  encounteredGroup = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      groups.users = {
        gid = 100;
        encountered = "the distro-wide users group is fixed at gid 100";
      };
    };
  };

  chosenGroupOutsidePrivateBand = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      groups.users.gid = 100;
    };
  };

  encounteredGroupCollision = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      identities.example = {
        uid = 100;
        encountered = "an upstream image fixes this account at uid/gid 100";
      };
      groups.users = {
        gid = 100;
        encountered = "the distro-wide users group is fixed at gid 100";
      };
    };
  };

  encounteredAppliedGroup = lib.recursiveUpdate encounteredGroup {
    nixiam.posix.governs = [ "users" ];
    users.groups.users.gid = 100;
  };

  mismatchedEncounteredAppliedGroup = lib.recursiveUpdate encounteredGroup {
    nixiam.posix.governs = [ "users" ];
    users.groups.users.gid = 101;
  };

  # ── fixtures shared by the users-registry / lldap-reconcile groups below ─────────────────────

  validUsersWithPosix = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      identities.example-app.uid = 3000;
    };
    nixiam.users.alice = {
      posixIdentity = "example-app";
      displayName = "Alice Example";
      email = "alice@example.com";
      groups = [ "admins" ];
    };
  };

  danglingPosixIdentity = {
    nixiam.posix = {
      enable = true;
      domain = "example.com";
      identities.example-app.uid = 3000;
    };
    nixiam.users.alice = {
      posixIdentity = "no-such-identity";
      displayName = "Alice Example";
      email = "alice@example.com";
    };
  };

  # The identical unresolved reference as danglingPosixIdentity above, but composed WITHOUT
  # posixModule at all (see the users-registry group below) -- this is the fixture that must
  # build FINE, proving nixiam.users can be adopted before nixiam.posix is ever imported.
  unresolvedPosixIdentityNoPosixModule = {
    nixiam.users.alice = {
      posixIdentity = "no-such-identity";
      displayName = "Alice Example";
      email = "alice@example.com";
    };
  };

  contradictoryRemoval = {
    nixiam.users.alice = {
      enable = true;
      acknowledgeRemoval = "test fixture -- should never build";
      displayName = "Alice Example";
      email = "alice@example.com";
    };
  };

  lldapReconcileStorePath = {
    nixiam.lldapReconcile = {
      enable = true;
      credentialFile = "/nix/store/00000000000000000000000000000000-example/secret";
    };
  };

  lldapReconcileRuntimePath = {
    nixiam.lldapReconcile = {
      enable = true;
      credentialFile = "/run/secrets/example-lldap-reconcile-admin";
    };
  };

  # ══ Group 1: posix-purity ═════════════════════════════════════════════════════════════════════

  isCommentLine = line: builtins.match "[ \t]*#.*" line != null;
  stripComments = src:
    lib.concatStringsSep "\n"
      (lib.filter (l: !(isCommentLine l)) (lib.splitString "\n" src));

  posixSrc = stripComments (builtins.readFile posixModule);

  evalNixosModules = modules:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system modules;
    }).config;

  sorted = lib.sort (a: b: a < b);
  serviceNames = cfg: sorted (lib.attrNames cfg.systemd.services);
  packageNames = cfg: sorted (map (p: p.name) cfg.environment.systemPackages);

  cfg-bare = evalNixosModules [ bareStubs ];
  cfg-posix-alone = evalNixosModules [ posixModule ../examples/posix-registry/configuration.nix ];

  # A deliberately broken stand-in for posix.nix, used ONLY to prove (a)/(c)/(d) actually have
  # teeth -- never composed alongside the real modules/posix.nix, and never shipped as a module
  # this repo exports.
  brokenPosixModule = { config, lib, pkgs, ... }: {
    options.nixiamPosixDecoy.enable = lib.mkEnableOption "decoy, for the purity check's own meta-tests -- never a real nixiam.posix module";
    config = lib.mkIf config.nixiamPosixDecoy.enable {
      systemd.services.nixiam-posix-decoy-unit.script = "exit 0";
      environment.systemPackages = [ pkgs.hello ];
    };
  };

  cfg-broken-posix-alone = evalNixosModules [ bareStubs brokenPosixModule { nixiamPosixDecoy.enable = true; } ];

  purityResults = [
    (check "posix-purity/no-pkgs-argument"
      (!(lib.functionArgs (import posixModule) ? pkgs))
      "modules/posix.nix's own module function now binds a `pkgs` argument -- its header's opening paragraph promises this never happens")

    (check "posix-purity/source-never-mentions-systemd-services"
      (!(lib.hasInfix "systemd.services" posixSrc))
      "modules/posix.nix's source text now contains the literal string \"systemd.services\"")

    (check "posix-purity/source-never-mentions-environment-systemPackages"
      (!(lib.hasInfix "environment.systemPackages" posixSrc))
      "modules/posix.nix's source text now contains the literal string \"environment.systemPackages\"")

    (check "posix-purity/alone-adds-no-new-systemd-units"
      (serviceNames cfg-posix-alone == serviceNames cfg-bare)
      "composing nixosModules.posix alone changed systemd.services vs. the identical system without it -- got: ${builtins.toJSON (serviceNames cfg-posix-alone)}, expected: ${builtins.toJSON (serviceNames cfg-bare)}")

    (check "posix-purity/alone-adds-no-new-packages"
      (packageNames cfg-posix-alone == packageNames cfg-bare)
      "composing nixosModules.posix alone changed environment.systemPackages vs. the identical system without it -- got: ${builtins.toJSON (packageNames cfg-posix-alone)}, expected: ${builtins.toJSON (packageNames cfg-bare)}")

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

  # ══ Group 2: module assertions, through a real NixOS evaluation ══════════════════════════════

  # NixOS enforces assertions when `system.build.toplevel` is forced, not on a bare read of
  # `config.assertions` (a passive list).
  nixosBuildFails = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosModules [ posixModule bareStubs extraConfig ]).system.build.toplevel true)).success;

  nixosBuildFailsPackages = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosModules [ nixiamModules.packages bareStubs extraConfig ]).system.build.toplevel true)).success;

  nixosAppliedBuildFails = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosModules [ posixModule nixiamModules."posix-applied" bareStubs extraConfig ]).system.build.toplevel true)).success;

  encounteredGroupCfg = (evalNixosModules [ posixModule bareStubs encounteredGroup ]).nixiam.posix;

  moduleResults = [
    (check "module/disabled-registry-builds-fine"
      (!(nixosBuildFails { }))
      "a host that never enables nixiam.posix must never fail the build")

    (check "module/valid-enabled-registry-builds-fine"
      (!(nixosBuildFails validRegistry))
      "a valid, fully-populated registry must never fail the build")

    (check "module/missing-domain-fails-the-build"
      (nixosBuildFails domainUnset)
      "expected nixiam.posix.enable = true with domain unset to fail the build, but it succeeded")

    (check "module/uid-collision-fails-the-build"
      (nixosBuildFails uidCollision)
      "expected two identities sharing a uid to fail the build, but it succeeded")

    (check "module/gid-collision-fails-the-build"
      (nixosBuildFails gidCollision)
      "expected two identities resolving to the same gid after UPG resolution to fail the build, but it succeeded")

    (check "module/encountered-group-outside-private-band-builds"
      (!(nixosBuildFails encounteredGroup))
      "a reason-bearing externally fixed group must be allowed outside the private band")

    (check "module/chosen-group-outside-private-band-fails"
      (nixosBuildFails chosenGroupOutsidePrivateBand)
      "a group without an encountered reason must remain inside the private band")

    (check "module/encountered-group-still-participates-in-gid-collisions"
      (nixosBuildFails encounteredGroupCollision)
      "an encountered group must not bypass cross-table gid collision detection")

    (check "module/encountered-group-projects-through-allGroups"
      (encounteredGroupCfg.allGroups.users == 100)
      "allGroups must project a structured encountered group back to its numeric gid")

    (check "module/posix-applied-accepts-matching-encountered-group"
      (!(nixosAppliedBuildFails encounteredAppliedGroup))
      "posix-applied must compare the structured group's gid with the real host group")

    (check "module/posix-applied-rejects-mismatched-encountered-group"
      (nixosAppliedBuildFails mismatchedEncounteredAppliedGroup)
      "posix-applied must reject a host group whose gid differs from the structured registry entry")
  ];

  packageResults = [
    (check "packages/default-baseline-builds-on-nixos"
      (!(nixosBuildFailsPackages { }))
      "nixiam packages baseline must resolve on NixOS without failing the build")

    (check "packages/unresolvable-entry-fails-on-nixos"
      (nixosBuildFailsPackages baselineWithMissingPackage)
      "a baseline override that names a non-existent nixpkgs package must fail on NixOS")
  ];

  # ══ Group 3: podSecurity -- the generated product itself, not just its type ═════════════════

  podSecCfg = (evalNixosModules [ posixModule bareStubs validRegistry ]).nixiam.posix.podSecurity;

  podSecurityResults = [
    (check "podSecurity/native-pins-runAsUser-and-drops-all-capabilities"
      (podSecCfg.example-app.pod.runAsUser == 3000
        && podSecCfg.example-app.container.capabilities.drop == [ "ALL" ])
      "got: ${builtins.toJSON podSecCfg.example-app}")

    (check "podSecurity/puid-sets-env-and-never-pins-runAsUser"
      (!(podSecCfg.example-linuxserver-app.pod ? runAsUser)
        && podSecCfg.example-linuxserver-app.env.PUID == "3001"
        && podSecCfg.example-linuxserver-app.env.PGID == "3001")
      "got: ${builtins.toJSON podSecCfg.example-linuxserver-app}")
  ];

  # ══ Group 4: backend parity -- the same fixtures, system-manager's own eval instead ══════════

  # system-manager's makeSystemConfig gates its entire return value on assertions passing, so a
  # bare `.config` access already throws when one fails.
  evalSm = extraConfig:
    (systemManagerLib.makeSystemConfig {
      modules = [ posixModule extraConfig { nixpkgs.hostPlatform = system; } ];
    }).config;

  smBuildFails = extraConfig:
    !(builtins.tryEval (builtins.seq (evalSm extraConfig) true)).success;

  backendParityResults = [
    (check "backend-parity/valid-registry-builds-on-both"
      (!(nixosBuildFails validRegistry) && !(smBuildFails validRegistry))
      "a valid registry should never fail on either backend")

    (check "backend-parity/missing-domain-fails-on-both"
      (nixosBuildFails domainUnset && smBuildFails domainUnset)
      "a missing domain should fail identically on both backends")

    (check "backend-parity/uid-collision-fails-on-both"
      (nixosBuildFails uidCollision && smBuildFails uidCollision)
      "a uid collision should fail identically on both backends")

    (check "backend-parity/gid-collision-fails-on-both"
      (nixosBuildFails gidCollision && smBuildFails gidCollision)
      "a gid collision should fail identically on both backends")

    (check "backend-parity/encountered-group-builds-on-both"
      (!(nixosBuildFails encounteredGroup) && !(smBuildFails encounteredGroup))
      "a reason-bearing encountered group should build identically on both backends")

    (check "backend-parity/chosen-out-of-band-group-fails-on-both"
      (nixosBuildFails chosenGroupOutsidePrivateBand && smBuildFails chosenGroupOutsidePrivateBand)
      "a chosen out-of-band group should fail identically on both backends")
  ];

  # ══ Group 5: the shipped posix-registry example evaluates on its own ═══════════════════════

  examplePosixRegistry = lib.nixosSystem {
    inherit system;
    modules = [ posixModule ../examples/posix-registry/configuration.nix ];
  };

  exampleResults = [
    (check "example/posix-registry-evaluates"
      (builtins.tryEval (builtins.seq examplePosixRegistry.config.system.build.toplevel true)).success
      "the shipped example (examples/posix-registry) failed to evaluate -- it is meant to be internally consistent by construction")
  ];

  # ══ Group 6: users-registry -- modules/users.nix's own assertions, in both directions plus the
  # silent-when-unimported case ═══════════════════════════════════════════════════════════════
  #
  exampleUsersRegistry = lib.nixosSystem {
    inherit system;
    modules = [ posixModule usersModule ../examples/users-registry/configuration.nix ];
  };
  #
  # `nixosBuildFails` above always composes `[ posixModule bareStubs extraConfig ]` -- it does NOT
  # include `usersModule`, so it cannot be reused here as-is: a fixture setting `nixiam.users.*`
  # against a system that never imported `nixiam.nixosModules.users` fails for the WRONG reason
  # (an undeclared option), not the one this group means to test. Two more small helpers, each
  # composing the exact module list its own fixtures need.
  nixosBuildFailsUsersWithPosix = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosModules [ posixModule usersModule bareStubs extraConfig ]).system.build.toplevel true)).success;

  nixosBuildFailsUsersAlone = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosModules [ usersModule bareStubs extraConfig ]).system.build.toplevel true)).success;

  usersRegistryResults = [
    (check "users-registry/disabled-registry-builds-fine"
      (!(nixosBuildFailsUsersAlone { }))
      "a host that declares no nixiam.users at all must never fail the build")

    (check "users-registry/valid-posixIdentity-reference-builds-fine"
      (!(nixosBuildFailsUsersWithPosix validUsersWithPosix))
      "a user whose posixIdentity names a real nixiam.posix.identities entry must build fine")

    (check "users-registry/dangling-posixIdentity-fails-the-build"
      (nixosBuildFailsUsersWithPosix danglingPosixIdentity)
      "expected a user's posixIdentity naming an ABSENT nixiam.posix.identities entry (with nixiam.posix imported and populated) to fail the build, but it succeeded")

    (check "users-registry/unresolved-posixIdentity-is-silent-when-posix-module-is-not-imported"
      (!(nixosBuildFailsUsersAlone unresolvedPosixIdentityNoPosixModule))
      "the IDENTICAL unresolved posixIdentity reference as the dangling-reference fixture above, but composed WITHOUT nixiam.posix imported at all, must build fine -- this is what makes nixiam.users adoptable before nixiam.posix is, and it failed")

    (check "users-registry/contradictory-enable-and-acknowledgeRemoval-fails-the-build"
      (nixosBuildFailsUsersAlone contradictoryRemoval)
      "expected a user declaring BOTH enable = true and a set acknowledgeRemoval to fail the build (the two disagree about whether this person should exist), but it succeeded")

    (check "users-registry/example-evaluates"
      (builtins.tryEval (builtins.seq exampleUsersRegistry.config.system.build.toplevel true)).success
      "the shipped example (examples/users-registry) failed to evaluate -- it is meant to be internally consistent by construction")
  ];

  # ══ Group 7: lldap-reconcile -- the one assertion this module carries (credentialFile must
  # never resolve inside the Nix store), in both directions ══════════════════════════════════
  nixosBuildFailsLldapReconcileAlone = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixosModules [ lldapReconcileModule bareStubs extraConfig ]).system.build.toplevel true)).success;

  lldapReconcileResults = [
    (check "lldap-reconcile/disabled-builds-fine"
      (!(nixosBuildFailsLldapReconcileAlone { }))
      "a host that never enables nixiam.lldapReconcile must never fail the build")

    (check "lldap-reconcile/credentialFile-inside-nix-store-fails-the-build"
      (nixosBuildFailsLldapReconcileAlone lldapReconcileStorePath)
      "expected nixiam.lldapReconcile.credentialFile pointing inside /nix/store to fail the build, but it succeeded -- this is the one assertion standing between an admin credential and a world-readable location")

    (check "lldap-reconcile/credentialFile-outside-nix-store-builds-fine"
      (!(nixosBuildFailsLldapReconcileAlone lldapReconcileRuntimePath))
      "a credentialFile pointing at a plausible runtime secret path (outside /nix/store) must build fine")
  ];

  results =
    purityResults
    ++ moduleResults
    ++ packageResults
    ++ podSecurityResults
    ++ backendParityResults
    ++ exampleResults
    ++ usersRegistryResults
    ++ lldapReconcileResults;

  failed = builtins.filter (r: !r.ok) results;
  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;

  eval-tests =
    if failed != [ ]
    then
      throw ''
        nixiam eval-tests FAILED (${toString (builtins.length failed)}/${toString (builtins.length results)}):
        ${report}
      ''
    else
    # Depending on `passedCount` forces `results`, so the tests genuinely run under
    # `nix flake check` rather than merely being defined.
      pkgs.runCommand "nixiam-eval-tests"
        { passedCount = toString (builtins.length results); }
        ''
          echo "all $passedCount nixiam eval tests passed"
          touch $out
        '';
in
{
  inherit modules-evaluate eval-tests;
}
