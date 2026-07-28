# The smallest configuration that imports ONLY nixid's POSIX registry -- no LDAP directory, no
# OIDC/SSO provider, nothing that runs at all. This is the concrete proof of the claim
# modules/posix.nix's own header makes and checks/default.nix's `posix-purity` group enforces: a
# host can depend on this repo for nothing but the uid/gid table and pay zero systemd units, zero
# `environment.systemPackages` entries, and zero `pkgs` cost for the two services this same repo
# also ships. See README's "Two scopes, one repo" section for the full reasoning.
#
# Composed with ONLY `nixosModules.posix` (never `.lldap`/`."pocket-id"`) by
# checks/default.nix's `posix-purity` group. If this file ever grows an import of either service
# module, or anything that needs `pkgs`, that check starts failing by design.
{ ... }:
{
  nixid.posix = {
    enable = true;
    domain = "example.com";
    identities = {
      # One of each variant, so a reader sees both branches `podSecurity` can produce -- the
      # same reason examples/host/configuration.nix declares two identities, not one.
      example-app = {
        uid = 3000;
      };
      example-linuxserver-app = {
        uid = 3001;
        variant = "puid";
      };
    };

    # A shared-group entry too, independent of any one identity -- exercises the other half of
    # the registry this example would otherwise leave untouched.
    groups.shared-readers = 3100;
  };

  # ── Stubs NixOS demands of any bootable system ───────────────────────────
  # Same reasoning as examples/host/configuration.nix: this is not a machine anyone would run.
  # It exists so the registry module type-checks entirely on its own, with nothing else composed
  # in -- that absence is the whole point of this file.
  fileSystems."/" = {
    device = "nodev";
    fsType = "tmpfs";
  };

  boot.loader.grub = {
    enable = true;
    devices = [ "nodev" ];
  };

  networking.hostName = "example-registry-only-node";
  system.stateVersion = "25.05";
}
