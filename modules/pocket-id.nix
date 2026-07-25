# modules/pocket-id.nix
#
# The OIDC/SSO identity provider in front of this repo's LDAP directory --
# implemented today by pocket-id specifically (a small, self-contained Go/
# Svelte-based OIDC provider whose one built-in mechanism for sourcing
# users is an LDAP sync against a directory such as the one modules/
# lldap.nix runs). Named after the actual upstream project, matching this
# repo's convention (see lldap.nix's own header for the fuller rationale)
# rather than an abstract "oidc-provider" role.
#
# HONESTY NOTE, stated up front because it is the single most important
# thing to know about this module: pocket-id's LDAP-sync wiring -- which
# directory it binds to, the bind DN and bind password, the search base and
# filter, and the attribute mapping from directory entries onto pocket-id's
# own user fields -- is configured ENTIRELY out-of-band, through pocket-id's
# own admin UI/API, and stored ENCRYPTED inside pocket-id's own database.
# (`encryptionKeyFile` below is exactly that encryption key -- it protects
# the LDAP bind password and SMTP password rows alongside everything else
# pocket-id itself treats as a secret.) There is no environment variable,
# settings key, or config file pocket-id reads any of that from at start
# time, and consequently NO OPTION IN THIS MODULE configures it -- adding
# one would be decorative, describing a Nix-side value pocket-id itself
# never looks at. Wire the LDAP sync up by hand, once, through the running
# pocket-id instance's own setup flow, exactly the way you would on a
# system this module had no part in configuring at all.
#
# This is not a temporary gap waiting on more extraction work -- contrast
# lldap.nix's DIRECTORY-SCHEMA point (which group DNs and attribute names a
# consumer expects to find), which genuinely is Nix-declarable
# configuration and belongs in whatever module consumes the directory. This
# is a different, permanent boundary: what pocket-id itself exposes as
# start-time configuration versus what it treats as its own runtime state.
# This module is honest about that boundary rather than gesturing at an
# `ldapSync.*` option surface that would quietly do nothing.
#
# Everything this module DOES actually declare (`services.pocket-id.
# settings.APP_URL`/`TRUST_PROXY`/`PORT`/`HOST`, the `ENCRYPTION_KEY`
# credential, a pinned uid/gid) governs how the pocket-id PROCESS starts up
# -- not what it does once it is running.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.nixid.pocketId;
in
{
  options.services.nixid.pocketId = {
    enable = lib.mkEnableOption "pocket-id OIDC/SSO identity provider";

    package = lib.mkPackageOption pkgs "pocket-id" {
      extraDescription = ''
        See this module's `ExecStartPre` self-heal step (implementation,
        below `dataDir`) for a real pocket-id v1->v2 upgrade trap this
        module works around regardless of which package version you run:
        pocket-id v2 moved its SQLite database one directory level deeper
        than v1 did, and a v2 binary given a v1 layout silently creates a
        fresh, empty database rather than erroring -- every user
        disappearing from the login screen with no log line pointing at
        "wrong path".
      '';
    };

    publicUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://id.example.org";
      description = ''
        The externally-visible URL this identity provider is reached at --
        wired into `services.pocket-id.settings.APP_URL`, and the value
        pocket-id itself uses as its OIDC issuer identifier. No default:
        every relying-party OIDC client that trusts this instance has this
        exact URL baked into its own configuration, so a silently-wrong
        default here is worse than a required option that forces you to
        say it once, explicitly.
      '';
    };

    trustProxy = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Wired into `services.pocket-id.settings.TRUST_PROXY`. Defaults to
        `true` on the assumption that this instance sits behind a reverse
        proxy or tunnel terminating TLS (a self-hosted OIDC provider
        reachable over plain HTTP directly is rarely what you want -- see
        `httpHost`). Set `false` only for a bare loopback-only instance
        with genuinely nothing in front of it.
      '';
    };

    httpHost = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Address pocket-id's HTTP listener binds (wired into `services.
        pocket-id.settings.HOST` -- a freeform key pocket-id itself reads
        as an environment variable; the upstream NixOS module does not
        declare it as a typed option). Kept loopback-only by default, the
        same pattern as this repo's `lldap.nix` `httpHost`/`ldapHost`:
        front it with your own reverse proxy or tunnel for TLS and
        anything wider than this host.
      '';
    };

    httpPort = lib.mkOption {
      type = lib.types.port;
      default = 1411;
      description = ''
        Port pocket-id's HTTP listener binds, on `httpHost` (wired into
        `services.pocket-id.settings.PORT` -- see `httpHost` for why this
        is a freeform settings key rather than a typed upstream option).
        1411 mirrors pocket-id's own documented default in its upstream
        deployment examples; it is not a value specific to any particular
        deployment and is safe to change freely.
      '';
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/pocket-id";
      description = ''
        Directory pocket-id keeps its database and other state in --
        passed straight through to `services.pocket-id.dataDir` (upstream
        creates and owns it via `systemd.tmpfiles.rules`; unlike `lldap.
        nix` in this same repo, this module has no separate "is this a
        bind mount" flag, because upstream's own module already always
        goes through tmpfiles regardless).

        Also the path this module's own `ExecStartPre` legacy-database
        self-heal step reads and writes -- a real trap found running
        pocket-id in production: pocket-id v1 kept its SQLite database
        directly at `''${dataDir}/pocket-id.db`; v2 moved it one level
        deeper by default, to `''${dataDir}/data/pocket-id.db` (relative
        to its `WorkingDirectory`). A v2 binary started against a host
        that still only has the v1 file does NOT error or migrate it --
        it silently creates a brand-new, empty database at the v2 path
        instead, and every previously-registered user vanishes from the
        login screen with nothing in the journal pointing at "wrong
        path". This module's `ExecStartPre` moves a legacy v1 file into
        the v2 location, if-and-only-if the v2 file does not already
        exist, before pocket-id itself ever starts -- letting v2's own
        real migrations run against the actual pre-existing data on the
        very next start, instead of against an empty database it just
        created. Idempotent: after the first successful move, the legacy
        path is gone and every later start is a no-op.
      '';
    };

    encryptionKeyFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to a file containing pocket-id's `ENCRYPTION_KEY` -- wired in
        via `services.pocket-id.credentials.ENCRYPTION_KEY` (systemd
        `LoadCredential`, never written into the Nix store). This is the
        key pocket-id uses to encrypt every secret it itself stores at
        rest in its own database, including the LDAP bind password and
        any SMTP password entered through its admin UI (see this module's
        header for why that LDAP-sync configuration lives there and not
        in this module's option surface at all). No default -- provisioning
        a real secret here is entirely your responsibility. Losing this
        key after pocket-id has stored encrypted values against it makes
        those values permanently unrecoverable, the same failure shape as
        `lldap.nix`'s `keySeedEnvFile` in this same repo -- treat it with
        the same care.
      '';
    };

    uid = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = null;
      description = ''
        Fixed uid for the pocket-id system user, or `null` to let NixOS
        allocate one automatically. Note this is a DIFFERENT concern from
        `lldap.nix`'s own `uid` option in this repo: upstream `services.
        pocket-id` already creates a proper STATIC system user by default
        (`isSystemUser = true`, never `DynamicUser`), so this is not the
        DynamicUser ordering trap documented there.

        The failure this guards against instead: NixOS allocates an
        unpinned system user's concrete uid number from its own
        persistent allocation bookkeeping, which is stable across rebuilds
        of an EXISTING host (the allocation, once made, is remembered) but
        is not guaranteed to reproduce the same number on a genuinely
        fresh install of the identical configuration onto a new disk or
        image -- nothing seeds that allocation state before the first
        activation ever runs there. A `dataDir` that is itself persisted
        independently of the NixOS generation that first created it (a
        separate data disk, a restored snapshot, a dataset moved between
        hosts) can end up owned by a uid the newly (re)provisioned host
        never allocates to pocket-id, and the service fails to open its
        own already-existing database -- surfacing as a permission or
        "unable to open" error at the filesystem layer, not as anything
        that names "uid" directly. Pin a fixed number whenever `dataDir`
        outlives the host's own NixOS generation history; leave `null` for
        a fresh install with no prior data to inherit.
      '';
    };

    gid = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = null;
      description = ''
        Fixed gid for the pocket-id system group, or `null` to
        auto-allocate. See `uid` above for the failure this pins against.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.pocket-id = {
      enable = true;
      package = cfg.package;
      dataDir = cfg.dataDir;
      credentials = {
        ENCRYPTION_KEY = cfg.encryptionKeyFile;
      };
      settings = {
        APP_URL = cfg.publicUrl;
        TRUST_PROXY = cfg.trustProxy;
        PORT = cfg.httpPort;
        HOST = cfg.httpHost;
      };
    };

    # Pin uid/gid only when asked to -- see the options' own descriptions
    # for the cross-reimage stable-ownership failure this addresses.
    # Merges into upstream's own `users.users.pocket-id`/`users.groups.
    # pocket-id` definitions (created by `services.pocket-id` itself, see
    # its module) rather than replacing them -- the same `optionalAttrs`
    # pattern `lldap.nix` uses in this same repo for its own uid/gid.
    users.users.pocket-id = lib.optionalAttrs (cfg.uid != null) { uid = cfg.uid; };
    users.groups.pocket-id = lib.optionalAttrs (cfg.gid != null) { gid = cfg.gid; };

    # v1 -> v2 legacy database relocation -- see `dataDir`'s own
    # description for the full failure this self-heals. Runs before every
    # start; a no-op once the one-time move has already happened.
    systemd.services.pocket-id.serviceConfig.ExecStartPre = [
      "${pkgs.writeShellScript "nixid-pocket-id-relocate-legacy-db" ''
        set -eu
        legacy="${cfg.dataDir}/pocket-id.db"
        v2="${cfg.dataDir}/data/pocket-id.db"
        if [ -f "$legacy" ] && [ ! -f "$v2" ]; then
          mkdir -p "${cfg.dataDir}/data"
          mv "$legacy" "$v2"
          echo "nixid pocket-id: relocated legacy v1 database $legacy -> $v2"
        fi
      ''}"
    ];
  };
}
