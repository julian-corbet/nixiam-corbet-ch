# modules/users.nix
#
# THE HUMAN IDENTITY REGISTRY: one entry per real person, `nixiam.users.<name>`, declaring the
# three things about a human that are safe to put in a world-readable, deploy-time file --
# existence, which lldap groups they belong to, and (optionally) which entry in
# `nixiam.posix.identities` is THEIR uid/gid -- and nothing else. THIS MODULE IS PURE DATA, the
# same discipline `posix.nix` in this same repo holds itself to: no `pkgs` argument, no
# `systemd.services`, nothing that ever runs. The mechanism that actually reads this table and
# pushes it into a running lldap directory is a SEPARATE module, `modules/lldap-reconcile.nix` --
# see that file's own header for what it is and is not allowed to do, and see `posix.nix`'s own
# header for the general argument this repeats: a table and the mechanism that acts on it are two
# different things, and conflating them costs every future importer of the table whatever the
# mechanism needs, whether or not they have it.
#
# ── THE LINE THAT MAKES DECLARING THIS SAFE AT ALL ──────────────────────────────────────────────
#
# A human identity today has (at least) four independent places that each claim to know who they
# are: a POSIX uid/gid, an lldap directory entry, a network ACL group, and a local Unix account.
# None of the four asserts that it agrees with any of the others -- exactly the duplication this
# nix* family already removed once for a disk (`nixstorage.disks`) and once for an app/container
# identity (`nixiam.posix.identities`). This module is the same fix applied to a HUMAN, with one
# line drawn deliberately, because the failure mode on the wrong side of that line is worse than a
# drifted uid: lldap sits behind this fleet's SSO, so getting the CREDENTIAL half of this wrong
# does not just corrupt a file, it locks a real person out of everything at once, or leaks the one
# secret that unlocks every directory entry simultaneously.
#
#   CONFIGURATION -- declared here, safe to commit to a public repo, safe to hand to anyone who can
#   already read this file:
#     - that this name exists as a human identity at all
#     - which lldap groups they belong to (additive membership only -- see `lldap-reconcile.nix`
#       for exactly what "additive" is enforced to mean)
#     - which `nixiam.posix.identities.<name>` entry is their uid/gid, by NAME, never restated as
#       a raw number -- the identical by-name discipline `nixstorage.reconciler.nix`'s own
#       `leaves.<path>.identity` already applies to an app/container leaf
#     - a human-readable display name and a contact email
#
#   STATE -- never declared here, and never movable here no matter how it's stored or encrypted:
#     - password hashes, TOTP secrets, session tokens, last-login timestamps. lldap owns these
#       exclusively, permanently. This is not a policy this module chooses to hold to; it is a
#       structural property of the Nix store: the store is world-readable on every machine that
#       has ever built this configuration, so a secret placed in it is not "less safe", it is
#       PUBLISHED, to every local account on every one of those machines, forever (a store path is
#       never truly deleted while anything still references it).
#     - anything a human changes about their OWN account at runtime. A password reset must never
#       require a redeploy -- the same reason `lldap.nix`'s own `adminPasswordFile` in this repo is
#       read once, at lldap's first start, and never re-applied afterward (see that option's
#       description for the exact mechanism, `silenceForceUserPassResetWarning`).
#
# See `lldap-reconcile.nix`'s own header for the harder, load-bearing half of this split: what the
# mechanism that reads this table is, and is not, allowed to do to a directory entry it did not
# create.
{ config, lib, options, ... }:

with lib;

let
  cfg = config.nixiam.users;

  # ── nixiam.posix: read defensively, exactly nixstorage.reconciler.nix's own pattern ───────────
  # A host may import this module without ever importing nixiam.posix at all -- one that only
  # cares about lldap/SSO group membership and never touches a uid/gid, or one adopting this
  # registry before it has gotten around to wiring up the POSIX side. `options ? nixiam.posix.
  # identities` is how the module system lets this tell "not imported" apart from "imported,
  # empty" without forcing `config.nixiam.posix` itself -- which would fail to evaluate the moment
  # IT throws on ITS OWN unset `domain` (see posix.nix's own assertion), an unrelated failure this
  # module has no business surfacing just because it went looking.
  posixDeclared = options ? nixiam && (options.nixiam ? posix) && (options.nixiam.posix ? identities);
  posixIdentities = config.nixiam.posix.identities or { };

  availablePosixIdentities =
    if posixIdentities == { }
    then "(none declared)"
    else concatStringsSep ", " (attrNames posixIdentities);

  # ⚠ Deliberately DIFFERENT from nixstorage.reconciler.nix's own resolveLeafUid/resolveOwnerUid,
  # which throw regardless of whether nixiam.posix is imported (only the error TEXT changes). That
  # difference is correct there and would be wrong here: every one of nixstorage's identity
  # references is REQUIRED to resolve to a real number for the reconciler to act on at all -- there
  # is no legal "no identity" state for a leaf. `posixIdentity` below is `nullOr`, by design: most
  # declared humans are pure SSO/directory identities with no POSIX/local-account correspondence
  # whatsoever (someone who only ever authenticates to a web app fronted by pocket-id, never gets a
  # shell or a chowned dataset leaf). A host that imports `nixiam.users` alone, before it has
  # imported `nixiam.posix` at all, must be able to declare such a person -- or even a person who
  # will eventually get a posixIdentity once that side is wired up -- without a hard build failure
  # for a registry that genuinely is not there yet. Staying silent in that one case is what makes
  # incremental adoption of this repo's modules, one at a time, actually possible; see
  # checks/default.nix's own `users-registry` group for the fixture that proves this specific
  # asymmetry (composing `nixiam.nixosModules.users` WITHOUT `.posix` at all, with a
  # `posixIdentity` set, and asserting the build still succeeds).
  userSubmodule = types.submodule {
    options = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether `lldap-reconcile.nix`'s mechanism is allowed to CREATE this
          person's lldap account (if it does not already exist) and converge
          their declared `groups` membership going forward.

          Setting this to `false` does NOT remove an already-existing lldap
          account -- see `acknowledgeRemoval` below, the only option that
          does, and only when this is also `false`. What it means instead:
          stop asserting this person's existence and memberships from this
          point on. If lldap already has an account for this name, it is left
          exactly as it is and reported as drift (not currently declared) on
          every reconcile pass -- the identical treatment given to an account
          this registry never knew about at all; see this module's header for
          why that asymmetry (report, never delete) is the whole point.

          Without this flag, the only way to stop enforcing someone's
          declaration is to delete their entire block from this file --
          losing, in the same diff, the record of who they were, when they
          were declared, and any comment explaining why. With it, disabling
          someone is one boolean flip that survives in `git blame` next to a
          dated comment, while the reconciler simply stops touching them.
        '';
      };

      posixIdentity = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "someone";
        description = ''
          Name into `nixiam.posix.identities.<name>` -- never a raw uid/gid
          restated here (see that module's own header for the drift a second
          copy of the same number invites). `null` (the default): this human
          has no POSIX/local-account correspondence at all, the common case
          for a pure SSO/directory identity that never needs a uid.

          When set, it MUST name a real entry in `nixiam.posix.identities` --
          checked below, but ONLY when that registry is actually imported
          into this same host's configuration; see this file's own comment
          on `posixDeclared` above for exactly why an unimported registry
          makes this a silent no-op rather than a build failure, and why that
          is the opposite of `nixstorage.reconciler.nix`'s own choice for the
          same shape of reference on a DIFFERENT (required, not optional)
          field.
        '';
      };

      # ── person or mailbox: the same directory holds both, and they are not alike ──────────
      #
      # Derived from the live directory rather than guessed: of 18 entries, 11 belong to exactly
      # one group (`mail`) and nothing else. Those exist because the mail server authenticates
      # against this directory -- they are mailboxes, not people. Modelling them as people makes
      # two different assertions wrong at once: a mailbox legitimately has no SSO group membership,
      # while a person with none is usually a provisioning mistake worth noticing.
      #
      # It also separates the blast radii. Removing a person locks a human out of every service
      # behind SSO simultaneously. Removing a mailbox stops mail for one address. Both need the
      # explicit acknowledgement below, but a reviewer reading a diff should be able to see which
      # of the two they are approving without cross-referencing the group list.
      kind = mkOption {
        type = types.enum [ "person" "mailbox" ];
        default = "person";
        example = "mailbox";
        description = ''
          Whether this entry is a human who logs in, or an address the mail server authenticates.

          Defaults to `person`, deliberately the more cautious reading: an entry misdeclared as a
          person merely attracts a membership warning it did not need, whereas one misdeclared as a
          mailbox would suppress exactly the check that catches a human provisioned with no access
          at all.
        '';
      };

      groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "admins" ];
        description = ''
          lldap group membership, by display name, additive only.
          `lldap-reconcile.nix`'s mechanism CREATES a missing group (if no
          lldap group by this name exists yet) and CREATES a missing
          membership -- it never removes a membership that exists in lldap
          but is no longer listed here. Dropping a name from this list is
          reported as drift on the next reconcile pass, not enforced: the
          same "report, never delete" rule this whole registry exists to
          hold to, applied one level down from the account itself.

          An empty list (the default) is a legitimate declaration: this
          person exists and can authenticate, but belongs to no group beyond
          whatever lldap or an out-of-band admin action already granted them
          -- this registry never sees or touches memberships it was not told
          about, matching `lldap-reconcile.nix`'s own drift-reporting-only
          treatment of anything it does not manage.
        '';
      };

      displayName = mkOption {
        type = types.str;
        example = "Jane Doe";
        description = ''
          lldap `displayName` for this person -- shown in its own admin UI
          and, once wired up through pocket-id's own LDAP sync (see
          `pocket-id.nix`'s header for why that wiring is out-of-band), the
          name a relying-party OIDC client sees at login. No default:
          inventing one (the attribute name, title-cased, say) is exactly the
          kind of seed content this family avoids everywhere else -- a
          registry of real humans should never silently manufacture what one
          is called.
        '';
      };

      email = mkOption {
        type = types.str;
        example = "jane@example.org";
        description = ''
          lldap `email` for this person. No default, same reasoning as
          `displayName` -- and a wrong value here is worse than a missing
          one: it is where lldap sends password-reset mail and where
          pocket-id's own OIDC email claim comes from, so a silently invented
          default would misdirect account recovery for a real person rather
          than just looking wrong in a UI.
        '';
      };

      acknowledgeRemoval = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "Offboarded 2026-08-01; access already revoked upstream by IT.";
        description = ''
          A written reason to let `lldap-reconcile.nix`'s mechanism DELETE
          this person's lldap account -- and every group membership that
          comes with it -- the next time it runs, once `enable` above is
          `false`. No default, and a sentence rather than a boolean on
          purpose: mirrors `nixiac`'s own
          `acknowledgeWildcardActivation` for the identical reason. A boolean
          is invisible in a diff and in `git blame`; a sentence survives both
          and still reads to whoever inherits this file next, months later,
          wondering why an account is gone.

          lldap sits behind this fleet's SSO -- deleting a directory entry
          locks that human out of EVERY service behind it simultaneously,
          not just one, and there is no automatic undo once that mutation
          lands. This is the ONE supported path to that outcome, and it is
          deliberately opt-in PER PERSON: an entry with `enable = false` and
          this left `null` is reported as drift and left alone forever,
          never removed by anything in this repo. Setting this while `enable`
          is still `true` is a contradiction (asserted against below) --
          decide which one you mean.
        '';
      };
    };
  };

  # ── the assertion, proven in both directions plus the silent third case ────────────────────────
  # See checks/default.nix's `users-registry` group for all three states exercised: (1) a
  # posixIdentity naming a real nixiam.posix.identities entry builds fine; (2) one naming an
  # absent entry, WITH nixiam.posix imported and populated, fails the build; (3) the identical
  # unresolved reference, WITHOUT nixiam.posix imported at all, builds fine -- proving this repo's
  # modules can be adopted one at a time rather than all-or-nothing.
  danglingPosixIdentityAssertions = concatMap
    (name:
      let u = cfg.${name}; in
      optional
        (u.posixIdentity != null && posixDeclared && !(posixIdentities ? ${u.posixIdentity}))
        {
          assertion = false;
          message = ''
            nixiam.users."${name}".posixIdentity = "${u.posixIdentity}" was not found in
            nixiam.posix.identities. This is invisible at declaration time in exactly the way a
            typo'd name always is: nothing here restates a uid, so nothing catches a misspelling
            except this assertion -- and lldap-reconcile.nix's own generated model never even
            reaches the point of asking "what uid is this person" for an entry that fails here
            first.
            Declared identities: ${availablePosixIdentities}.
          '';
        })
    (attrNames cfg);

  contradictoryRemovalAssertions = concatMap
    (name:
      let u = cfg.${name}; in
      optional (u.enable && u.acknowledgeRemoval != null) {
        assertion = false;
        message = ''
          nixiam.users."${name}" sets acknowledgeRemoval but enable is still true. These two
          fields disagree about what should happen to this person's lldap account: enable = true
          asks the reconciler to keep ensuring they exist; acknowledgeRemoval asks it to delete
          them. Set enable = false to actually authorize the deletion acknowledgeRemoval
          describes, or clear acknowledgeRemoval if you meant to keep this person active.
        '';
      })
    (attrNames cfg);
in
{
  options.nixiam.users = mkOption {
    type = types.attrsOf userSubmodule;
    default = { };
    description = ''
      The human identity registry: one entry per real person, keyed by the
      lldap username they will be created under. Declares existence, lldap
      group membership, and (optionally, by NAME into
      `nixiam.posix.identities`) a POSIX uid/gid -- never a password, a
      session, or anything else lldap itself must remain the sole source of
      truth for; see this module's own header for exactly where that line
      falls and why.

      Pure data, same as `nixiam.posix.identities` in this repo: declaring an
      entry here does nothing on its own. It creates no local Unix account
      (there is no `users.users.<name>` here, deliberately -- that is a
      different, NixOS-specific concern this module does not touch), starts
      no service, and reaches no directory. `modules/lldap-reconcile.nix`,
      a separate module in this same repo, is the one thing allowed to read
      this table and act on it -- see its own header for what "act on it"
      is and is not permitted to mean.
    '';
  };

  config = mkIf (cfg != { }) {
    assertions = danglingPosixIdentityAssertions ++ contradictoryRemovalAssertions;
  };
}
