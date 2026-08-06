# modules/posix-applied.nix — the registry is a CONTRACT, not a suggestion.
#
# `posix.nix` is deliberately pure data: it declares uid/gid numbers and never creates a
# `users.users` entry. Each service module applies its own identity (nixmail's stalwart module does
# `users.users.${cfg.user}.uid = cfg.uid`, defaulting from the registry; pocket-id, vaultwarden and
# several sibling repos do the same). That split is right, and this module does not change it.
#
# WHAT IT CLOSES. Nothing checked that the two halves AGREE. The registry could say 3050 while the
# host's actual account resolved to something else entirely, and every layer stayed quiet:
#
#   * a service module's uid is only a DEFAULT. Any host may override it with a literal, and
#     nothing compared that literal against the registry.
#   * a registry entry whose service module was never adopted leaves `users.users.<n>.uid = null`,
#     so NixOS auto-allocates from its own descending host-local range (995, 994, ...) -- a number
#     that is stable on THAT host and different on the next one.
#
# Either way the number the registry publishes is not the number the service runs as. That is not a
# cosmetic disagreement, because the registry is ACTED ON: nixstorage's reconciler chowns datasets
# to the registry's uid. A divergence therefore produces files owned by a uid nothing runs as --
# silently, and discovered when a service cannot read its own state.
#
# It also made ADOPTION the dangerous move. Declaring an identity for a service still auto-allocating
# its account made things strictly worse than not declaring it: the dataset moved to the declared
# number while the daemon kept the allocated one. A registry whose adoption is a footgun stays empty,
# which is exactly what happened.
#
# WHY THIS IS A SEPARATE FILE, and not a few lines added to posix.nix: `posix.nix` is exported as
# `nixosModules.posix`, `systemManagerModules.posix` AND `darwinModules.posix` from one source, and
# stays plane-agnostic precisely so a uid table means the same thing on every backend.
# `config.users.users` exists on NixOS only. Putting this check in that file would break the other
# two planes to serve one.
#
# INERT UNTIL IT ISN'T. Every check below fires only where BOTH halves exist -- a registry entry AND
# a system account of that name. A host that has adopted nothing sees nothing, so composing this
# fleet-wide costs nothing and changes no evaluation until an identity is genuinely declared. It is
# the guard that makes adopting the registry safe, so it belongs in place BEFORE the first entry
# lands, not after.
{ lib, config, ... }:
let
  # Read the registry defensively: this module may be composed on a host that never imported
  # posix.nix at all, and that is a legitimate configuration, not an error.
  identities = config.nixiam.posix.identities or { };
  groups = config.nixiam.posix.groups or { };

  users = config.users.users or { };
  sysGroups = config.users.groups or { };

  governs = config.nixiam.posix.governs;

  # NEVER INFER WHICH ACCOUNT A REGISTRY ENTRY GOVERNS. An earlier version of this file matched by
  # NAME -- if `identities.postgres` existed and `users.users.postgres` existed, it compared them.
  # That is wrong, and fatally so: nixpkgs' own `services.postgresql` creates `users.users.postgres`
  # with a fixed uid from `ids.nix` (71) that has nothing to do with a fleet identity of the same
  # name, so a host running native Postgres alongside a registry entry for, say, a Kubernetes chown
  # target failed to build. Same for grafana, which creates its own UPG group and would collide with
  # an unrelated cross-host `groups.grafana`. A shared string is not a shared identity.
  #
  # So the host says which names it governs, and nothing else is compared. Everything below is
  # scoped to that list.
  governed = lib.filter (n: identities ? ${n} && users ? ${n}) governs;
  governedGroups = lib.filter (n: groups ? ${n} && sysGroups ? ${n}) governs;

  mismatchedUids = lib.filterAttrs
    (name: ident: (users.${name}.uid or null) != ident.uid)
    (lib.getAttrs governed identities);

  mismatchedGids = lib.filterAttrs
    (name: group: (sysGroups.${name}.gid or null) != group.gid)
    (lib.getAttrs governedGroups groups);

  # Declared as governed but with nothing to govern -- almost always a typo in `governs`, or a
  # module that stopped creating the account. Loud, because a silent no-op here means the guard the
  # operator believes is running is not running.
  governedButAbsent = lib.filter
    (n: !((identities ? ${n} && users ? ${n}) || (groups ? ${n} && sysGroups ? ${n})))
    governs;

  # The discovery half: a registry name that matches a real account on this host but was never
  # declared governed. It may be the same identity (and should be declared) or a coincidence of
  # naming (and should be ignored) -- this module cannot tell, which is the whole reason it does
  # not guess. A warning, never an assertion.
  undeclaredCandidates = lib.filter
    (n: !(lib.elem n governs) && ((identities ? ${n} && users ? ${n}) || (groups ? ${n} && sysGroups ? ${n})))
    (lib.unique (lib.attrNames identities ++ lib.attrNames groups));

  describeUid = name: ident:
    let applied = users.${name}.uid or null;
    in "  ${name}: registry says ${toString ident.uid}, this host applies "
      + (if applied == null
    then "null (so NixOS auto-allocates a host-local number, which is the whole failure)"
    else toString applied);

  describeGid = name: group:
    let applied = sysGroups.${name}.gid or null;
    in "  ${name}: registry says ${toString group.gid}, this host applies "
      + (if applied == null then "null (auto-allocated, host-local)" else toString applied);
in
{
  options.nixiam.posix.governs = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    example = [ "stalwart-mail" "lldap" ];
    description = ''
      The registry names whose accounts THIS host actually applies -- and therefore the only ones
      whose numbers are checked against `users.users`/`users.groups` here.

      Explicit rather than inferred, because a name is not an identity. nixpkgs' own service
      modules create accounts named `postgres`, `grafana`, `matrix` with their own fixed uids from
      `ids.nix`, which have nothing to do with a fleet registry entry that happens to share the
      name. Matching on the string alone failed healthy hosts.

      Names here that the registry does not declare, or that this host does not create, are an
      error: a guard the operator believes is running, silently governing nothing, is worse than no
      guard. Registry names that DO match a local account but are not listed here produce a
      warning, not a failure -- this module cannot tell "same identity, not yet declared" from
      "unrelated service with the same name", so it says what it sees and leaves the call to you.
    '';
  };

  config.warnings =
    lib.optional (undeclaredCandidates != [ ]) ''
      nixiam.posix: ${toString (builtins.length undeclaredCandidates)} registry name(s) match an
      account on this host but are not listed in `nixiam.posix.governs`, so their numbers are NOT
      checked: ${lib.concatStringsSep ", " undeclaredCandidates}

      If these are the same identity, add them to `governs` and the uid/gid contract starts being
      enforced. If they are an unrelated service that merely shares a name (nixpkgs creates
      `postgres`, `grafana` and others with their own fixed numbers), ignore this -- or rename one
      side so the coincidence stops being confusing.
    '';

  config.assertions =
    lib.optional (governedButAbsent != [ ])
      {
        assertion = false;
        message = ''
          nixiam.posix.governs names ${lib.concatStringsSep ", " governedButAbsent}, but this host has
          no registry entry AND system account pair under those names.

          Listing a name here asserts "the account this host creates for this name IS the registry's
          identity". With nothing on one side of that pair there is nothing to check, and a guard that
          silently governs nothing is the failure mode this whole module exists to prevent -- so it
          says so instead of passing.

          Either the name is a typo, or the module that used to create that account no longer does.
        '';
      }
    ++
    lib.optional (mismatchedUids != { }) {
      assertion = false;
      message = ''
        nixiam.posix: the uid registry and this host's actual accounts disagree.

        ${lib.concatStringsSep "\n" (lib.mapAttrsToList describeUid mismatchedUids)}

        The registry is not advisory -- nixstorage's reconciler chowns datasets to the number it
        publishes. While these disagree, that path owns files as a uid no process here runs as, and
        the service cannot read its own state. Nothing else in the fleet reports this, which is why
        it is fatal rather than a warning.

        A `null` above means the service module was never pointed at the registry, so NixOS picked a
        host-local number instead. That is the common case on first adoption and is exactly what
        this check exists to catch BEFORE anything is chowned to the declared number.

        Fix by making the account use the registry's number -- for most services that means letting
        the module's uid default resolve rather than overriding it, i.e. compose nixiam's posix
        module on this host. If the LIVE number is the one that must be kept, change the registry
        instead, and remember that any already-chowned data has to move with it.
      '';
    }
    ++ lib.optional (mismatchedGids != { }) {
      assertion = false;
      message = ''
        nixiam.posix: the gid registry and this host's actual groups disagree.

        ${lib.concatStringsSep "\n" (lib.mapAttrsToList describeGid mismatchedGids)}

        This is the NFS AUTH_SYS failure posix.nix's own header describes, caught one layer earlier:
        AUTH_SYS puts the NUMBER on the wire with no name lookup, so a group name resolving to
        different gids on two hosts sharing an export silently grants different access on each.
      '';
    };
}
