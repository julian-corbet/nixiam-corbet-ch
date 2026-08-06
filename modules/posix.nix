# modules/posix.nix
#
# The POSIX identity registry: a cross-host table of "this name is uid N,
# gid M, and behaves like THIS at startup" -- and, generated straight from
# that same table, the Kubernetes securityContext each identity implies.
# Nothing else in an operator's configuration (this repo's own sibling nix*
# repos included) should ever declare a raw uid/gid number a second time
# next to a dataset path or a pod spec; it declares a NAME here instead,
# and reads the number back through `config.nixiam.posix.identities.<name>`
# or `.podSecurity.<name>`.
#
# THIS MODULE IS PURE DATA. Read that literally: no `systemd.services`, no
# `environment.systemPackages`, no `pkgs` argument at all, not even a
# `users.users`/`users.groups` entry -- nothing this module declares ever
# runs, writes a file, or touches `/etc/passwd`. That is a deliberate
# boundary, not an oversight, for two reasons:
#
#   1. This is meant to be imported by EVERY host, including the
#      smallest one -- a single-purpose, memory-hardened VPS running at
#      ~1 GB of RAM with nothing to spare for a service it doesn't need.
#      Such a host may import this module purely so its own few identities
#      type-check against the same registry every other host uses,
#      without paying for (or even being able to run) whatever this same
#      repo's `lldap.nix`/`pocket-id.nix` need. A module that stays pure
#      data costs that host nothing to import.
#   2. The moment this module grows a systemd unit "just this once" (a
#      reconcile oneshot, a validation script, anything with an ExecStart),
#      the boundary that makes reason (1) true is gone, permanently -- every
#      future host that imports it for the data now also inherits whatever
#      that unit does, whether or not it has the storage the unit assumes.
#      If a future need genuinely wants automation over this data (walking
#      `identities` and calling `chown`, say), that automation belongs in
#      the module that already knows about paths and datasets -- never
#      here. Concretely: this registry answers "who"; a sibling module
#      elsewhere answers "where, and what shape" and is the one thing
#      allowed to consume this one, never the other way around. If this
#      module ever imports a path, a pool name, or a `pkgs.writeShellScript`,
#      that is this design failing, not a convenience.
#
# This is no longer just an argument in prose. checks/default.nix's `posix-purity` group fails
# `nix flake check` if this file's own function ever binds a `pkgs` argument, or if composing
# `nixosModules.posix` alone (see examples/posix-registry) ever changes `systemd.services` or
# `environment.systemPackages` relative to the identical system with this module absent entirely.
#
# This module used to live in its own repository, nixposix, split out of THIS repo (nixiam, at the
# time still named nixid) on the reasoning that a pure uid/gid table has nothing to do with
# lldap/pocket-id beyond sharing a repo and an option prefix. Folding it back in -- as
# `nixiam.posix` rather than a bare `nixposix.*` -- is nixiam's whole reason to exist under that
# name instead of staying nixid: identity, access, and credentials for a host or container
# (WHAT a workload is allowed to touch, this module's entire job) belong in the same repo as WHO a
# human is (lldap) and how they PROVE it (pocket-id) -- three answers to "who/what is this and what
# can it do", not one repo per upstream project that happens to touch identity. See this repo's
# README, "Why posix folded back in", for the full argument and the exact option-path change
# (`nixposix.<x>` -> `nixiam.posix.<x>`) every consumer that read it from the standalone nixposix
# repo needs to make -- including a warning that the cutover fails SILENTLY, not loudly.
#
# The purity check earns its keep here for a reason that has not changed across either home: this
# module is exported as `nixosModules`, `systemManagerModules`, AND `darwinModules` from the exact
# same file (see flake.nix), and a `pkgs` argument or a `systemd.services` write is exactly the
# kind of thing that evaluates fine on NixOS and then fails outright, or silently does nothing, the
# moment the same file is composed under system-manager or nix-darwin instead -- see nixhost's own
# `modules/nixhost.nix` header for a sibling repo that follows this exact "one file, every backend"
# shape and purity discipline for the identical reason.
#
# Two neither-here-nor-there notes on what a "pure data" identity registry
# deliberately does NOT need to provide, because both of this module's real
# consumers work directly off the plain integer, never off a resolved
# account name:
#
#   - No `users.users`/`users.groups` entries. A ZFS chown target and a
#     Kubernetes `runAsUser` both take a bare number; neither needs a
#     resolvable `/etc/passwd` line on THIS host to mean anything. (One
#     real container image is known to do its own `getpwuid()` lookup at
#     startup and crashes without a matching passwd entry -- but that
#     entry has to exist INSIDE that image's own filesystem, which is that
#     image's problem to solve in its own build, not something a host-side
#     identity registry can fix by declaring a user nothing on the host
#     ever reads.)
#   - No secrets, credentials, or passwords of any kind. This registry is
#     entirely public-shape numbers and booleans; if a future identity
#     genuinely needs a secret (an app that authenticates as itself
#     somewhere), that belongs in whatever module actually runs that app,
#     the same way this repo's own lldap module keeps its `jwtSecretFile`
#     on itself rather than here.
#
# ── `domain`, and the one failure it exists to prevent ──────────────────
#
# `domain` is the identity domain every host shares for anything that
# maps NAMES across a trust boundary rather than trusting numbers directly.
# Its first, and so far only, real consumer is NFSv4 idmapd's own
# `Domain=` setting (wired up by whatever module actually runs the NFS
# client/server -- this module only carries the value, it does not touch
# `services.nfs.idmapd` itself, for the same "no runtime component" reason
# as everything else here).
#
# The failure this one shared value exists to prevent is not hypothetical,
# and it is genuinely nasty to diagnose, because BASIC ownership keeps
# working the entire time it is broken. NFSv4 maps uids/gids to and from
# `name@domain` strings on the wire; if a client's idmapd `Domain=` does
# not match the server's, idmapd silently falls back to guessing the
# domain from the client's own DNS search domain instead -- and if that
# guess doesn't match either, every NFSv4 ACL-touching syscall starts
# paying a failed kernel upcall: `llistxattr` (reading the NFSv4 ACL
# attribute), `getfacl`, and the per-entry `stat`/`statx` a file manager or
# shell issues while just listing a directory. Measured cold, on a real
# host, against a single plain directory:
#
#     llistxattr   7.5 s
#     statx        1.6 s
#
# ...for ONE directory. Ordinary AUTH_SYS ownership checks (owner/group/
# other bits, the numeric uid/gid a `stat()` returns) are completely
# unaffected, because AUTH_SYS passes uids and gids over the wire as plain
# NUMBERS -- no name mapping, no idmapd involvement at all. That is exactly
# why this goes unnoticed for so long in practice: files still open, still
# read, still show the right owner; only the NFSv4-ACL-specific path is
# silently paying seconds per call, and nothing in the symptom points at
# "domain string mismatch" as the cause. One value, declared once here and
# referenced by every idmapd-touching module on every host that shares
# this directory's users, is what makes it structurally impossible for the
# two ends to drift apart by a typo.
{ config, lib, ... }:

with lib;

let
  cfg = config.nixiam.posix;

  # `null` gid resolves to the identity's own uid -- a User Private Group,
  # the common case and the only one that needs no explicit thought. See
  # `identities.<name>.gid`'s own description for the real failure mode
  # that makes the override exist at all.
  resolvedGid = ident: if ident.gid == null then ident.uid else ident.gid;

  identitySubmodule = types.submodule {
    options = {
      uid = mkOption {
        type = types.int;
        description = ''
          The one authoritative uid for this identity. Required, with no
          default: inventing a "next free number" automatically is exactly
          how two identities end up on the same uid without either
          declaration looking wrong on its own -- see the uid-uniqueness
          assertion below for the concrete failure this is designed to
          make impossible instead of merely unlikely.

          A convention that has worked in practice: leave uids below 1000
          alone (that range is not yours to hand out -- it is whatever a
          base image already baked in, encountered, not chosen), and hand
          out numbers for identities you DO control from a private block
          reserved for exactly this purpose (e.g. 3000 and up), one at a
          time, in the order identities are added -- never reused, even
          after an identity is retired.
        '';
      };

      encountered = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "grafana's own image runs as 472 and chowns nothing at startup";
        description = ''
          Set this ONLY for an identity whose number was ENCOUNTERED rather than CHOSEN -- fixed by
          something outside this registry, so it is not ours to move -- and say in one sentence
          WHERE it comes from. Presence of a reason exempts this identity from `identityRange`;
          absence means the band applies.

          Two kinds qualify. An upstream image or on-disk format that baked the number in; and a
          system-wide convention that owns a range outright -- an LXC/LXD idmap base at 100000,
          which is what `/etc/subuid` allocates and what a container's whole remapped block is
          anchored to. The band is for single-process service identities we hand out; neither of
          those is one, and widening the band to swallow them would be worse than exempting them:
          a range stretched to 165536 silently admits systemd's own DynamicUser allocations
          (61184-65519), which is exactly the host-allocated accident this check exists to reject.

          The distinction is the one the `uid` option above already draws. Real examples from a
          running fleet: a Postgres data directory at 26, an `www-data`-based image at 33, grafana
          at 472, the linuxserver.io family at 911. Those cannot be renumbered by declaring a
          different number here -- the image would start, chown nothing, and fail to read its own
          data.

          A free-form STRING rather than a boolean, deliberately. `encountered = true;` is a flag
          anyone can copy onto the next identity to silence the check; a sentence naming the image
          or format that fixed the number is a claim someone can go verify, and it is the only
          thing distinguishing "upstream forces this" from "I did not want to migrate today".
        '';
      };

      gid = mkOption {
        type = types.nullOr types.int;
        default = null;
        example = 3007;
        description = ''
          Primary gid for this identity, or `null` (the default) for a
          User Private Group -- gid numerically equal to `uid`. Leave this
          at `null` unless you have a concrete, verified reason not to:
          UPG is simpler to reason about and is what every generated
          `podSecurity` entry assumes unless this is set.

          The override exists because some container images do NOT bake a
          UPG layout: the process's own uid and its actual primary group
          number are two different values inside that specific image (a
          backend process and the reverse proxy in front of it sharing one
          group so the proxy can read the backend's generated output, say,
          while the backend's own uid belongs to a different group
          entirely). Get this wrong -- leave it at the UPG default when the
          image's real group differs -- and the failure is silent on BOTH
          ends: the backend still starts, still writes its own files
          successfully (it owns them by uid, not by this group), and the
          sibling process that was supposed to read them via group
          membership just... doesn't, with a permission failure that
          points at neither value directly, discovered only once someone
          notices the sibling's read count is short.
        '';
      };

      variant = mkOption {
        type = types.enum [ "native" "puid" ];
        default = "native";
        description = ''
          How this identity actually reaches its running uid, which is
          the one thing `podSecurity` below cannot infer from a bare
          number and genuinely needs to know:

          - `"native"` (default): the image's own entrypoint runs directly
            as the target non-root uid from the first instruction. The
            generated pod securityContext can and does pin `runAsUser`/
            `runAsGroup` directly -- Kubernetes itself refuses to start
            the container if the image tries to run as anything else.

          - `"puid"`: the linuxserver.io/s6-overlay family and anything
            built the same way -- the entrypoint starts AS ROOT, chowns
            its own config directory to match the identity, and only then
            drops privilege internally to the uid/gid it was told about
            via `PUID`/`PGID` environment variables. Setting `runAsUser`
            on a pod like this does not relax anything usefully -- the
            entrypoint's own root-required chown step is what fails
            instead, uselessly, in a different way. This variant tells
            `podSecurity` to supply `PUID`/`PGID` env vars instead, and to
            leave `runAsUser` unset entirely so the container is still
            allowed to start as root and perform its own drop. It also
            deliberately does NOT force `capabilities.drop = [ "ALL" ]`
            the way `"native"` does: an s6-style root-phase needs
            `CAP_CHOWN`/`CAP_SETUID`/`CAP_SETGID` to perform that drop at
            all, so stripping capabilities at the Kubernetes layer would
            break the exact mechanism this variant exists to support.
        '';
      };

      netBind = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Set when this identity needs to bind a privileged port (< 1024)
          while still running as a non-root uid -- its own resolver
          listening on 53, an ingress on 80/443 run without the ingress
          controller's usual root path, that kind of thing. Adds
          `CAP_NET_BIND_SERVICE` to the generated `"native"` securityContext
          instead of the much bigger hammer of just running as root; has
          no effect on a `"puid"` identity (see `variant` above for why
          that variant's container is never capability-stripped at all,
          which makes granting one specific capability back meaningless).
        '';
      };

      roRootfs = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Set `readOnlyRootFilesystem` on the generated `"native"`
          securityContext -- worth turning on for anything that has no
          business writing outside its declared data paths, since it turns
          a whole class of "wrote somewhere it shouldn't have" mistakes
          (a leaked temp file, a misconfigured cache path) into an
          immediate, visible failure instead of a silent write nobody
          notices until disk pressure or a security review finds it.
        '';
      };

      reconcile = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Whether an ownership-reconciling automation elsewhere
          (the sibling module that actually walks dataset paths and
          calls `chown`/`chmod` -- see this module's header for why that
          logic does not and must not live here) is allowed to bring this
          identity's on-disk data into line with its declared uid/gid.

          `false` means: this identity is still declared here, so
          everything else can still reference its uid/gid
          and every assertion in this module still checks it for
          collisions -- but no automation may act on it, because something
          ELSE already owns that data's ownership lifecycle. Concretely,
          two real shapes this covers: a database whose own
          migration/init tooling manages its data directory's ownership as
          part of its own startup sequence (a reconciler racing it would
          be fighting a well-behaved process, not fixing a broken one),
          and a data path that is genuinely somebody else's -- a separate,
          already-running system that happens to share this registry's
          numbering scheme but keeps its own automation in charge of
          applying it. Get this backwards (leave it `true` for a path a
          reconciler must not touch) and the very next reconcile pass
          chowns data out from under whatever legitimately owns it.
        '';
      };
    };
  };

  groupSubmodule = types.submodule {
    options = {
      gid = mkOption {
        type = types.int;
        description = ''
          The one authoritative gid for this shared group. Required, with
          no default, for the same reason identities require an explicit
          uid: allocation is a fleet decision and must never depend on a
          host's local creation order.
        '';
      };

      encountered = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "the distro-wide users group is fixed at gid 100";
        description = ''
          Set this only when the gid was encountered rather than chosen,
          and state where it comes from. Presence of the reason exempts
          this group from `identityRange`; absence means the private band
          applies. This is the group analogue of
          `identities.<name>.encountered`, and deliberately uses a reason
          string rather than a boolean so the exception remains auditable.
        '';
      };
    };
  };

  mkPodSecurityFor = ident:
    if ident.variant == "puid" then {
      # No `runAsUser`/`runAsGroup`, and no `capabilities.drop` -- see
      # `variant`'s own description for why forcing either would break the
      # root-phase chown-then-drop sequence this variant exists to allow.
      pod = { fsGroup = resolvedGid ident; };
      container = { allowPrivilegeEscalation = false; };
      env = {
        PUID = toString ident.uid;
        PGID = toString (resolvedGid ident);
      };
    } else {
      pod = {
        runAsNonRoot = true;
        runAsUser = ident.uid;
        runAsGroup = resolvedGid ident;
        fsGroup = resolvedGid ident;
        seccompProfile.type = "RuntimeDefault";
      };
      container = {
        allowPrivilegeEscalation = false;
        readOnlyRootFilesystem = ident.roRootfs;
        capabilities = { drop = [ "ALL" ]; }
          // optionalAttrs ident.netBind { add = [ "NET_BIND_SERVICE" ]; };
      };
      env = { };
    };

  # Group identity NAMES by a derived key (their uid, or their resolved
  # gid) and keep only the keys more than one name mapped to -- the shape
  # a collision message needs (WHICH identities collided), not just a
  # yes/no flag. `attrNames`/`attrValues` round-trip through `toString`
  # keys purely so two different-typed values can never accidentally
  # collide as Nix attrset keys; the numbers themselves are always real
  # ints going into every message below.
  duplicatesOf = keyFn:
    let
      grouped = foldl'
        (acc: name:
          let k = toString (keyFn cfg.identities.${name});
          in acc // { ${k} = (acc.${k} or [ ]) ++ [ name ]; })
        { }
        (attrNames cfg.identities);
    in
    filter (names: length names > 1) (attrValues grouped);

  uidCollisions = duplicatesOf (ident: ident.uid);

  # gid collisions are checked ACROSS ALL THREE TABLES, not within each. A gid is one number in one
  # kernel namespace: an identity's UPG gid colliding with a shared group, or a device group
  # colliding with either, grants exactly the same unintended access as two identities sharing one.
  # Checking each table against only itself would have left the two most likely collisions -- the
  # ones that cross a table boundary, where no single declaration looks wrong -- entirely unguarded,
  # and splitting `groups` in two made that gap wider rather than narrower.
  gidClaims =
    (mapAttrsToList (n: i: { gid = resolvedGid i; who = "identities.${n}"; }) cfg.identities)
    ++ (mapAttrsToList (n: g: { gid = g.gid; who = "groups.${n}"; }) cfg.groups)
    ++ (mapAttrsToList (n: g: { gid = g; who = "deviceGroups.${n}"; }) cfg.deviceGroups);

  gidCollisions =
    let
      grouped = foldl'
        (acc: c: let k = toString c.gid; in acc // { ${k} = (acc.${k} or [ ]) ++ [ c.who ]; })
        { }
        gidClaims;
    in
    filter (whos: length whos > 1) (attrValues grouped);
in
{
  options.nixiam.posix = {
    enable = mkEnableOption ''
      the cross-host POSIX identity registry -- pure data, no service, see
      this module's own header for why that boundary is load-bearing
    '';

    domain = mkOption {
      type = types.str;
      default = "";
      example = "example.org";
      description = ''
        The identity domain shared by every name-based (as opposed to
        plain-numeric) trust boundary across the hosts. See this module's
        header for the full NFSv4-idmapd failure this value exists to
        prevent by existing exactly once. Required (non-empty) whenever
        `enable` is true -- asserted below -- precisely because a silently
        empty or mismatched domain is the one failure mode here that does
        NOT show up as an obvious error at the point it goes wrong.
      '';
    };

    identities = mkOption {
      type = types.attrsOf identitySubmodule;
      default = { };
      description = ''
        The registry itself: one entry per app/service identity that
        needs a stable uid across every host, consumed by anything that
        needs to own filesystem paths as that uid (a dataset-shape module
        elsewhere) and by this module's own generated
        `podSecurity.<name>` (below) for anything that runs it as a
        Kubernetes pod. Declare an identity exactly once, here, and have
        every consumer reference `config.nixiam.posix.identities.<name>`
        (or the generated `podSecurity.<name>`) instead of repeating the
        literal uid -- that repetition, not this registry, is what lets a
        uid and the securityContext claiming to match it drift apart.
      '';
    };

    groups = mkOption {
      type = types.attrsOf groupSubmodule;
      default = { };
      example = { shared-readers.gid = 3100; };
      description = ''
        Cross-host GROUP number convergence, independent of the per-app
        `identities` above -- one structured entry per group that
        exist to be shared BETWEEN identities or hosts (a group several
        otherwise-unrelated services are members of so they can read a
        common tree), rather than one identity's own primary group.

        This matters for exactly the same wire-level reason `domain`
        matters above, but for a completely different protocol path:
        NFS's AUTH_SYS security flavor authenticates a request by sending
        the calling uid/gid as plain NUMBERS, with no name lookup and no
        idmapd involvement at all. If the SAME group name resolves to
        DIFFERENT gid numbers on two machines that share an NFS export,
        each machine's kernel still faithfully checks "does the caller's
        numeric gid match the file's numeric gid" -- and gets a different
        answer depending on which machine asked, silently granting access
        on one and denying it on the other, or worse, granting the WRONG
        access because gid 3100 happens to mean something else entirely
        on the machine that drifted. This has been observed across a
        real, small multi-machine deployment: a group left to auto-allocate
        independently on each host ended up numbered differently on each
        one, and reconverging it required an explicit rename pass on
        every machine that had drifted, after the mismatch was already
        causing wrong access. Declaring the number once, here, and having
        every host's own group definition reference
        `config.nixiam.posix.groups.<name>.gid` instead of a literal, is what
        makes that drift structurally impossible instead of something to
        remember to check.
      '';
    };

    deviceGroups = mkOption {
      type = types.attrsOf types.int;
      default = { };
      example = { video = 401; render = 402; input = 404; };
      description = ''
        Groups whose NAME is fixed by the platform -- the device, session and admin groups a distro
        and its udev rules already know about (`wheel`, `video`, `render`, `audio`, `input`, `kvm`,
        `seat`, `storage`, `tty`, ...). Split out of `groups` because the two tables need OPPOSITE
        number policies, not because they are conceptually different kinds of thing.

        A device group must sit LOW, below the floor a distro's dynamic allocator starts from
        (`SYS_GID_MIN`, 500 on Arch), so that `systemd-sysusers` can never allocate into the band
        and undo the convergence. A shared group in `groups` must sit HIGH, in the same
        deliberately-reserved band as `identities`, for the opposite reason: nothing else hands
        those numbers out.

        One table with one policy could only serve both by checking neither, which is what it did.
      '';
    };

    deviceGroupRange = mkOption {
      type = types.submodule {
        options = {
          lower = mkOption { type = types.ints.positive; default = 400; };
          upper = mkOption { type = types.ints.positive; default = 499; };
        };
      };
      default = { };
      description = ''
        The band `deviceGroups` numbers must fall inside. The upper bound matters more than the
        lower: it must stay below the lowest `SYS_GID_MIN` among the distros in the fleet (500 on
        Arch), because above that line a package install can dynamically allocate the same number
        for something else and the whole point of pinning is lost.
      '';
    };

    identityRange = mkOption {
      type = types.submodule {
        options = {
          lower = mkOption { type = types.ints.positive; default = 3000; };
          upper = mkOption { type = types.ints.positive; default = 3999; };
        };
      };
      default = { };
      description = ''
        The band `identities` uid/gid numbers must fall inside. Asserted, not advised.

        A cross-host registry only means anything if its numbers are ones no host will hand out on
        its own, and the ranges below it are exactly the ranges that get handed out:

        - Under 1000 is the system range. NixOS and every distro allocate here AUTOMATICALLY,
          descending from 999, whenever an account is created without an explicit number. Those
          allocations are recorded in host-local state, so the same service gets 995 on one machine
          and something else on the next -- which is the precise failure this registry exists to
          prevent. Adopting a number a host already auto-allocated (995, say) writes that accident
          into the fleet's shared vocabulary and guarantees a future collision, because the next
          host is free to give 995 to something else entirely.
        - 1000 upward is where human logins begin.

        So service identities get their own band, deliberately above both. The default matches the
        number `groups`' own documentation already uses in its example (3100).

        WIDEN IT IF YOU MUST, but do it here, visibly, once -- rather than by dropping an
        out-of-band number into `identities` and having nothing say so.

        `groups` IS checked against this same band -- it holds cross-host shared groups this fleet
        hands out, which is exactly what the band is for. Platform-named device groups live in
        `deviceGroups` instead, with their own low band, because they need the opposite policy.
      '';
    };

    # A single lookup surface over all three tables. The split above is about which NUMBER POLICY
    # applies, never about where a consumer has to look: a dataset can be owned by a device group
    # or a shared one, and a resolver that had to know which table a name lived in would be
    # answering a question about this module's internals rather than about the fleet.
    allGroups = mkOption {
      type = types.attrsOf types.int;
      readOnly = true;
      default = cfg.deviceGroups // mapAttrs (_: group: group.gid) cfg.groups;
      defaultText = "deviceGroups // mapAttrs (_: group: group.gid) groups";
      description = ''
        Every declared group name to its gid, `deviceGroups` and `groups` merged. Read-only, and
        the thing a consumer resolving a group NAME should read -- see `nixstorage`'s reconciler
        and `nixmail`'s stalwart module, both of which resolve a name they were given rather than
        choosing which table it ought to have come from.
      '';
    };

    podSecurity = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          pod = mkOption {
            type = types.attrs;
            description = "Fields that belong on the Pod's own `spec.securityContext`.";
          };
          container = mkOption {
            type = types.attrs;
            description = "Fields that belong on this container's `securityContext` specifically.";
          };
          env = mkOption {
            type = types.attrsOf types.str;
            description = ''
              Extra environment variables this identity's variant needs
              (`PUID`/`PGID` for `"puid"`; empty for `"native"`, which
              needs no environment-level help to reach its uid at all).
            '';
          };
        };
      });
      readOnly = true;
      default = mapAttrs (_: mkPodSecurityFor) cfg.identities;
      description = ''
        THE PRODUCT this module actually exists to generate: one
        Kubernetes securityContext per declared identity, split into
        `pod`/`container`/`env` to match how Kubernetes itself splits a
        securityContext across those three places. Read-only and entirely
        derived from `identities.<name>` -- there is no separate place to
        declare a pod's `runAsUser` by hand, and that absence is the whole
        point: a pod's securityContext is generated from the exact same
        declaration that determines the uid its data is actually chowned
        to elsewhere, so the two literally cannot say two different
        numbers. Consume it as
        `config.nixiam.posix.podSecurity.<name>.pod` /
        `.container` / `.env` from whatever module renders the actual
        Kubernetes manifest.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.domain != "";
        message = ''
          nixiam.posix.enable is true but nixiam.posix.domain is unset.
          See this module's header for the concrete NFSv4-idmapd failure
          (multi-second `llistxattr`/`statx` calls, on real hardware) an
          empty or mismatched domain silently causes -- set it to the
          same value every idmapd-touching host uses.
        '';
      }
    ]
    ++ map
      (names: {
        assertion = false;
        message = ''
          nixiam.posix.identities: uid ${toString cfg.identities.${elemAt names 0}.uid}
          is claimed by more than one identity: ${concatStringsSep ", " names}.
          Two identities sharing a uid is invisible at declaration time and
          stays invisible at runtime too -- both start, both write files,
          and each one can now silently read and overwrite the other's
          data, discovered (if ever) only when one of them behaves as if
          it has files it never wrote. Give every identity its own uid.
        '';
      })
      uidCollisions
    ++ map
      (names: {
        assertion = false;
        message = ''
          nixiam.posix: one gid is claimed by more than one declaration:
          ${concatStringsSep ", " names}

          Checked across `identities` (after UPG resolution -- an unset `gid` resolves to that
          identity's own `uid`), `groups`, and `deviceGroups`, because a gid is one number in one
          kernel namespace no matter which table declared it. Same failure as the uid collision
          above, one level removed: everything holding this gid can read anything group-readable
          belonging to anything else holding it.

          A collision that crosses two tables is the likely one, and the hard one to spot by eye:
          neither declaration looks wrong on its own, and they are usually in different files.

          Give each its own gid, or -- if two things genuinely must share one -- say so by pointing
          both at the same entry rather than by writing the number twice.
        '';
      })
      gidCollisions
    ++ map
      (name:
        let
          ident = cfg.identities.${name};
          r = cfg.identityRange;
          offenders =
            lib.optional (ident.uid < r.lower || ident.uid > r.upper) "uid ${toString ident.uid}"
              ++ lib.optional
              (resolvedGid ident < r.lower || resolvedGid ident > r.upper)
              "gid ${toString (resolvedGid ident)}";
        in
        {
          assertion = false;
          message = ''
            nixiam.posix.identities.${name}: ${concatStringsSep " and " offenders} falls outside
            nixiam.posix.identityRange (${toString r.lower}-${toString r.upper}).

            A number below 1000 is one the system allocates BY ITSELF, descending from 999, for any
            account created without an explicit uid -- and it records that choice in host-local
            state. Publishing such a number as a fleet-wide fact does not make it fleet-wide; it
            enshrines one machine's accident and leaves the next machine free to hand the same
            number to something else. A number at or above 1000 is in human-login territory.

            This most often means an identity was adopted by copying whatever the host had already
            auto-allocated. That is the one adoption route that cannot work: pick a number in the
            band, and migrate the data to it.

            If this identity genuinely must sit outside the band, widen `identityRange` -- once,
            visibly, with the reason -- rather than leaving the number unexplained here.
          '';
        })
      (lib.filter
        (name:
          let i = cfg.identities.${name}; r = cfg.identityRange; in
          # An identity whose number was ENCOUNTERED rather than chosen is exempt -- see the
            # `encountered` option. Postgres at 26 and grafana at 472 are not drift to be corrected;
            # they are facts about someone else's image, and a band assertion that cannot express
            # that would simply be widened until it asserted nothing.
          i.encountered == null
            && (i.uid < r.lower || i.uid > r.upper
            || resolvedGid i < r.lower || resolvedGid i > r.upper))
        (attrNames cfg.identities))

    # `groups` shares identities' band -- both are numbers this fleet hands out.
    ++ map
      (name: {
        assertion = false;
        message = ''
          nixiam.posix.groups.${name}.gid = ${toString cfg.groups.${name}.gid} falls outside
          nixiam.posix.identityRange (${toString cfg.identityRange.lower}-${toString cfg.identityRange.upper}).

          `groups` holds cross-host shared groups THIS fleet hands out, so it shares the band with
          `identities` for the same reason: nothing else allocates there.

          If this is a platform-named device group (`video`, `render`, `input`, `wheel`, ...) it is
          in the wrong table -- those go in `deviceGroups`, which has its own low band precisely
          because they must sit below a distro's dynamic-allocation floor.
        '';
      })
      (lib.filter
        (n:
          let g = cfg.groups.${n}; r = cfg.identityRange;
          in g.encountered == null && (g.gid < r.lower || g.gid > r.upper))
        (attrNames cfg.groups))

    # `deviceGroups` gets the OPPOSITE bound, and the upper one is the load-bearing half.
    ++ map
      (name: {
        assertion = false;
        message = ''
          nixiam.posix.deviceGroups.${name} = ${toString cfg.deviceGroups.${name}} falls outside
          nixiam.posix.deviceGroupRange (${toString cfg.deviceGroupRange.lower}-${toString cfg.deviceGroupRange.upper}).

          The upper bound is the one that matters: above a distro's `SYS_GID_MIN` (500 on Arch) a
          package install can dynamically allocate this same number for something else, and the
          pinning that this table exists to provide is silently undone on the next machine.

          If this is a shared group this fleet hands out rather than a platform-named device group,
          it belongs in `groups`, which uses the high band.
        '';
      })
      (lib.filter
        (n: let g = cfg.deviceGroups.${n}; r = cfg.deviceGroupRange; in g < r.lower || g > r.upper)
        (attrNames cfg.deviceGroups));
  };
}
