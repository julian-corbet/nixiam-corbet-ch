# The smallest NixOS configuration that composes both nixid modules, used by the
# `modules-evaluate` check.
#
# This is not a machine anyone would run. Every domain is under example.com,
# every secret is a path that does not exist, and the root filesystem is tmpfs.
# It exists so the directory and the SSO provider in front of it can be
# type-checked together — they share the `nixid.*` namespace, and a
# collision between the two is exactly what a per-module check cannot see.
{ ... }:
{
  # The LDAP directory. Everything that authenticates users is a consumer of
  # this, never the other way around.
  #
  # Its three required values are all credential paths, and that is the point:
  # a directory holds the passwords for every service in front of it, so none of
  # them can be a value this module invents. Losing the key seed in particular
  # is not recoverable by resetting anything — it derives the encryption of
  # stored secrets.
  nixid.lldap = {
    enable = true;
    domain = "example.com";
    baseDn = "dc=example,dc=com";
    jwtSecretFile = "/run/secrets/example-lldap-jwt";
    adminPasswordFile = "/run/secrets/example-lldap-admin";
    keySeedEnvFile = "/run/secrets/example-lldap-key-seed";
  };

  # The OIDC/SSO provider in front of the directory.
  nixid.pocketId = {
    enable = true;

    # Load-bearing: OIDC redirect URIs and issuer discovery are built from it,
    # so a wrong value produces clients that complete a login and then get
    # redirected somewhere that does not exist.
    publicUrl = "https://id.example.com";

    # Protects the stored secret rows — including the LDAP bind password — and
    # is read by pocket-id itself rather than by any option here.
    encryptionKeyFile = "/run/secrets/example-pocketid-encryption-key";
  };

  # ── Stubs NixOS demands of any bootable system ───────────────────────────
  # tmpfs on / could never boot a real machine, which is the point: this exists
  # to type-check modules, not to describe hardware.
  fileSystems."/" = {
    device = "nodev";
    fsType = "tmpfs";
  };

  boot.loader.grub = {
    enable = true;
    devices = [ "nodev" ];
  };

  networking.hostName = "example-node";
  system.stateVersion = "25.05";
}
