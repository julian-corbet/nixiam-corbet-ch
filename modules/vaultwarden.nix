# modules/vaultwarden.nix
#
# A self-hosted, Bitwarden-compatible password vault (vaultwarden), with this
# repo's own pocket-id as an OPTIONAL OIDC/SSO front door in front of the
# master password rather than a replacement for it. Named after the actual
# upstream project, matching this repo's own convention (see lldap.nix's
# header for the fuller rationale) rather than an abstract "password-vault"
# role -- there is exactly one implementation behind this module, and a fake
# generic interface over it would document a boundary that doesn't exist.
#
# WHY THE MASTER PASSWORD STAYS, even with SSO on: pocket-id's own login can
# itself depend on a passkey or a saved credential -- and if that credential
# lives INSIDE this same vault, `sso.enable = true` alone would create a
# circular dependency the moment pocket-id is unreachable (can't unlock the
# vault to retrieve the passkey that unlocks pocket-id, can't reach pocket-id
# to unlock the vault). This module always leaves the master-password login
# path open as the break-glass, and only ever ADDS SSO alongside it
# (`sso.onlySso` stays an explicit opt-in, off by default, for exactly the
# deployment that has verified it has a different break-glass path).
#
# NON-GOAL, the same one lldap.nix states for itself: this module manages the
# vaultwarden SERVER (the process, its listeners, its systemd unit) and
# nothing about what's actually stored inside it. Vault items, organizations,
# collections and the JIT-provisioned user accounts themselves are live state
# in vaultwarden's own database -- this module never reads or writes any of
# it, and restores/migrations of that data are an operational concern for
# whoever runs the instance, not something Nix should assert into existence.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.nixiam.vaultwarden;
in
{
  options.nixiam.vaultwarden = {
    enable = mkEnableOption "vaultwarden, a self-hosted Bitwarden-compatible password vault";

    package = mkPackageOption pkgs "vaultwarden" { };

    publicUrl = mkOption {
      type = types.str;
      example = "https://vault.example.org";
      description = ''
        The externally-visible URL this instance is reached at -- wired into
        `services.vaultwarden.config.DOMAIN`. No default, the same reasoning
        this repo's own `pocket-id.nix` gives for its own `publicUrl`: every
        Bitwarden-compatible client (browser extension, mobile app, CLI)
        that has ever been pointed at this instance has this exact value
        baked into its own saved server setting, so a silently-wrong default
        here is worse than a required option.
      '';
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = ''
        Address vaultwarden's HTTP listener binds (`ROCKET_ADDRESS`). Kept
        loopback-only by default -- front it with your own reverse proxy or
        tunnel for TLS and anything wider than this host.
      '';
    };

    listenPort = mkOption {
      type = types.port;
      default = 8222;
      description = "Port vaultwarden's HTTP listener binds, on `listenAddress` (`ROCKET_PORT`).";
    };

    dbBackend = mkOption {
      type = types.enum [ "sqlite" "mysql" "postgresql" ];
      default = "sqlite";
      description = ''
        Wired into `services.vaultwarden.dbBackend`. `"sqlite"` needs no
        separate database server and is the right choice for a single-host
        deployment; the other two are upstream's own options for a
        deployment that already runs one.
      '';
    };

    environmentFile = mkOption {
      type = types.path;
      description = ''
        Path to a `KEY=VALUE` EnvironmentFile, wired into `services.
        vaultwarden.environmentFile` (read by systemd as root, before
        vaultwarden itself starts -- never written into the Nix store). No
        default: provisioning this file is entirely your responsibility, the
        same convention this repo's own `lldap.nix`/`pocket-id.nix` secret
        options follow. At minimum this needs `ADMIN_TOKEN` (vaultwarden's
        own admin-page credential); if `sso.enable` is true and the pocket-id
        client is registered as CONFIDENTIAL (as opposed to a public PKCE
        client, which needs no secret at all), it also needs
        `SSO_CLIENT_ID`/`SSO_CLIENT_SECRET`. Optional: `SMTP_*` keys if you
        want vaultwarden sending its own email notifications -- this module
        has no separate SMTP option surface, since every SMTP_* setting
        vaultwarden accepts is already free to set through this same file.
      '';
    };

    sso = {
      enable = mkEnableOption ''
        SSO login via this repo's own pocket-id, ALONGSIDE the master
        password (never instead of it, unless `onlySso` is also set -- see
        this module's own header for why the master password stays by
        default even with SSO on)
      '';

      authority = mkOption {
        type = types.str;
        example = "https://id.example.org";
        description = ''
          Pocket-id's OIDC issuer URL -- wired into `services.vaultwarden.
          config.SSO_AUTHORITY`. No default: required whenever `sso.enable`
          is true.
        '';
      };

      onlySso = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Wired into `services.vaultwarden.config.SSO_ONLY`. Keep `false`
          (the default) unless you have independently verified a working
          break-glass path for the case where pocket-id itself is
          unreachable -- see this module's own header for the exact
          circular-dependency failure that setting this to `true` without
          one recreates.
        '';
      };

      signupsMatchEmail = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Wired into `services.vaultwarden.config.SSO_SIGNUPS_MATCH_EMAIL`.
          Matches a JIT-provisioned SSO account to an existing local account
          by email claim, rather than always creating a new one.
        '';
      };
    };

    signupsAllowed = mkOption {
      type = types.bool;
      default = cfg.sso.enable;
      defaultText = literalExpression "config.nixiam.vaultwarden.sso.enable";
      description = ''
        Wired into `services.vaultwarden.config.SIGNUPS_ALLOWED`. Defaults
        to whatever `sso.enable` is, because JIT provisioning on first SSO
        login IS a signup from vaultwarden's own point of view -- leaving
        this at its upstream default (`true`, open signup) alongside SSO
        being off would let anyone reaching this instance create a local
        account with no invitation at all. Set explicitly to decouple the
        two, e.g. to allow invite-only local signups alongside SSO.
      '';
    };

    allowPasswordHints = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Wired into `services.vaultwarden.config.PASSWORD_HINTS_ALLOWED`
        (and `SHOW_PASSWORD_HINT`, which this module always sets to the same
        value -- the two only ever make sense together). Off by default: a
        password hint is, by design, a piece of information about the
        master password disclosed to anyone who asks for it by email
        address, which is rarely what a deployment with any other login
        path (SSO here, or simply "the operator already knows their users")
        actually wants.
      '';
    };

    webVaultEnabled = mkOption {
      type = types.bool;
      default = true;
      description = "Wired into `services.vaultwarden.config.WEB_VAULT_ENABLED`.";
    };

    ipHeader = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "CF-Connecting-IP";
      description = ''
        Wired into `services.vaultwarden.config.IP_HEADER` when set, else
        left at upstream's own default (`X-Real-IP`). Set this to whatever
        header your own reverse proxy or tunnel actually forwards the
        client's real address in -- e.g. `"CF-Connecting-IP"` in front of a
        Cloudflare Tunnel -- so rate-limiting and audit-log entries reflect
        the real caller instead of the proxy's own address. The mobile
        Bitwarden client in particular needs this to survive a tunnel that
        rewrites `X-Forwarded-For`.
      '';
    };

    uid = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = ''
        Fixed uid for the vaultwarden system user, or `null` to let NixOS
        allocate one automatically. See this repo's own `pocket-id.nix`
        `uid` option for the exact cross-reimage failure this pins against
        (a `dataDir` that outlives the host's own NixOS generation history
        can end up owned by a uid the generation never allocates, and the
        service fails to open its own already-existing database). Upstream
        `services.vaultwarden` already creates a proper static system user
        by default, so -- like `pocket-id.nix`'s own `uid` -- this is not
        the DynamicUser ordering trap `lldap.nix`'s `uid` documents.
      '';
    };

    gid = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = ''
        Fixed gid for the vaultwarden system group, or `null` to
        auto-allocate. See `uid` above for the failure this pins against.
      '';
    };
  };

  config = mkIf cfg.enable {
    services.vaultwarden = {
      enable = true;
      package = cfg.package;
      dbBackend = cfg.dbBackend;
      environmentFile = cfg.environmentFile;
      config = {
        DOMAIN = cfg.publicUrl;
        ROCKET_ADDRESS = cfg.listenAddress;
        ROCKET_PORT = cfg.listenPort;

        SSO_ENABLED = cfg.sso.enable;
        SSO_ONLY = cfg.sso.onlySso;
        SSO_AUTHORITY = mkIf cfg.sso.enable cfg.sso.authority;
        SSO_SIGNUPS_MATCH_EMAIL = cfg.sso.signupsMatchEmail;

        SIGNUPS_ALLOWED = cfg.signupsAllowed;

        SHOW_PASSWORD_HINT = cfg.allowPasswordHints;
        PASSWORD_HINTS_ALLOWED = cfg.allowPasswordHints;

        WEB_VAULT_ENABLED = cfg.webVaultEnabled;
      } // optionalAttrs (cfg.ipHeader != null) {
        IP_HEADER = cfg.ipHeader;
      };
    };

    # Pin uid/gid only when asked to -- merges into upstream's own
    # `users.users.vaultwarden`/`users.groups.vaultwarden` (created by
    # `services.vaultwarden` itself) rather than replacing them, the same
    # `optionalAttrs` pattern `lldap.nix`/`pocket-id.nix` use in this same
    # repo for their own uid/gid.
    users.users.vaultwarden = optionalAttrs (cfg.uid != null) { uid = cfg.uid; };
    users.groups.vaultwarden = optionalAttrs (cfg.gid != null) { gid = cfg.gid; };
  };
}
