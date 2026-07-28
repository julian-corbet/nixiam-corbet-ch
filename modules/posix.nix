# modules/posix.nix
#
# The POSIX identity registry: a fleet-wide table of "this name is uid N,
# gid M, and behaves like THIS at startup" -- and, generated straight from
# that same table, the Kubernetes securityContext each identity implies.
# Nothing else in this repo (or its sibling nix* repos) should ever declare
# a raw uid/gid number a second time next to a dataset path or a pod spec;
# it declares a NAME here instead, and reads the number back through
# `config.nixid.posix.identities.<name>` or `.podSecurity.<name>`.
#
# THIS MODULE IS PURE DATA. Read that literally: no `systemd.services`, no
# `environment.systemPackages`, no `pkgs` argument at all, not even a
# `users.users`/`users.groups` entry -- nothing this module declares ever
# runs, writes a file, or touches `/etc/passwd`. That is a deliberate
# boundary, not an oversight, for two reasons:
#
#   1. This is meant to be imported by EVERY host in a fleet, including the
#      smallest one -- a single-purpose, memory-hardened VPS running at
#      ~1 GB of RAM with nothing to spare for a service it doesn't need.
#      Such a host may import this module purely so its own few identities
#      type-check against the same registry the rest of the fleet uses,
#      without paying for (or even being able to run) whatever the fuller
#      "SHAPE"/"DELIVERY" half of this design turns into elsewhere
#      (the sibling repo that actually walks datasets and calls chown).
#      A module that stays pure data costs that host nothing to import.
#   2. The moment this module grows a systemd unit "just this once" (a
#      reconcile oneshot, a validation script, anything with an ExecStart),
#      the boundary that makes reason (1) true is gone, permanently -- every
#      future host that imports it for the data now also inherits whatever
#      that unit does, whether or not it has the storage the unit assumes.
#      If a future need genuinely wants automation over this data (walking
#      `identities` and calling `chown`, say), that automation belongs in
#      the module that already knows about paths and datasets -- never
#      here. Concretely: nixid answers "who" (this module); the sibling
#      module answers "where, and what shape" and is the one thing allowed
#      to consume this one, never the other way around. If this module
#      ever imports a path, a pool name, or a `pkgs.writeShellScript`, that
#      is this design failing, not a convenience.
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
#     the same way `nixid.lldap`'s `jwtSecretFile` lives on the lldap
#     module rather than here.
#
# ── `domain`, and the one failure it exists to prevent ──────────────────
#
# `domain` is the identity domain shared by everything in the fleet that
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
  cfg = config.nixid.posix;

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
          Whether an ownership-reconciling automation elsewhere in the
          fleet (the sibling module that actually walks dataset paths and
          calls `chown`/`chmod` -- see this module's header for why that
          logic does not and must not live here) is allowed to bring this
          identity's on-disk data into line with its declared uid/gid.

          `false` means: this identity is still declared here, so
          everything else in the fleet can still reference its uid/gid
          and every assertion in this module still checks it for
          collisions -- but no automation may act on it, because something
          ELSE already owns that data's ownership lifecycle. Concretely,
          two real shapes this covers: a database whose own
          migration/init tooling manages its data directory's ownership as
          part of its own startup sequence (a reconciler racing it would
          be fighting a well-behaved process, not fixing a broken one),
          and a data path that is genuinely somebody else's -- a separate,
          already-running system that happens to share this fleet's
          numbering scheme but keeps its own automation in charge of
          applying it. Get this backwards (leave it `true` for a path a
          reconciler must not touch) and the very next reconcile pass
          chowns data out from under whatever legitimately owns it.
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
  gidCollisions = duplicatesOf resolvedGid;
in
{
  options.nixid.posix = {
    enable = mkEnableOption ''
      the fleet-wide POSIX identity registry -- pure data, no service, see
      this module's own header for why that boundary is load-bearing
    '';

    domain = mkOption {
      type = types.str;
      default = "";
      example = "example.org";
      description = ''
        The identity domain shared by every name-based (as opposed to
        plain-numeric) trust boundary in the fleet. See this module's
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
        needs a stable uid across the fleet, consumed by anything that
        needs to own filesystem paths as that uid (a dataset-shape module
        elsewhere) and by this module's own generated
        `podSecurity.<name>` (below) for anything that runs it as a
        Kubernetes pod. Declare an identity exactly once, here, and have
        every consumer reference `config.nixid.posix.identities.<name>`
        (or the generated `podSecurity.<name>`) instead of repeating the
        literal uid -- that repetition, not this registry, is what lets a
        uid and the securityContext claiming to match it drift apart.
      '';
    };

    groups = mkOption {
      type = types.attrsOf types.int;
      default = { };
      example = { shared-readers = 3100; };
      description = ''
        Fleet-wide GROUP number convergence, independent of the per-app
        `identities` above -- a plain name-to-gid table for groups that
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
        real, small multi-machine fleet: a group left to auto-allocate
        independently on each host ended up numbered differently on each
        one, and reconverging it required an explicit rename pass on
        every machine that had drifted, after the mismatch was already
        causing wrong access. Declaring the number once, here, and having
        every host's own group definition reference
        `config.nixid.posix.groups.<name>` instead of a literal, is what
        makes that drift structurally impossible instead of something to
        remember to check.
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
        `config.nixid.posix.podSecurity.<name>.pod` /
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
          nixid.posix.enable is true but nixid.posix.domain is unset.
          See this module's header for the concrete NFSv4-idmapd failure
          (multi-second `llistxattr`/`statx` calls, on real hardware) an
          empty or mismatched domain silently causes -- set it to the
          same value every idmapd-touching host in this fleet uses.
        '';
      }
    ]
    ++ map
      (names: {
        assertion = false;
        message = ''
          nixid.posix.identities: uid ${toString cfg.identities.${elemAt names 0}.uid}
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
          nixid.posix.identities: gid ${toString (resolvedGid cfg.identities.${elemAt names 0})}
          is claimed by more than one identity after UPG resolution
          (an unset `gid` resolves to that identity's own `uid`): ${concatStringsSep ", " names}.
          Same failure as the uid collision above, one level removed: any
          identity in the group can now read anything group-readable that
          belongs to any other member of it. Give every identity its own
          gid, or set `gid` explicitly on the ones that must genuinely
          share one.
        '';
      })
      gidCollisions;
  };
}
