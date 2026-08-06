# The smallest configuration that imports nixiam.posix ALONE -- no lldap, no pocket-id, nothing
# that runs at all. This is the concrete proof of the claim modules/posix.nix's own header makes
# and checks/default.nix's `posix-purity` group enforces: a host can depend on this repo for
# nothing but the uid/gid table and pay zero systemd units, zero `environment.systemPackages`
# entries, and zero `pkgs` cost.
#
# Composed with ONLY `nixosModules.posix` by both the `posix-purity` group's own alone-vs-bare
# comparison and its backend-parity check (NixOS vs. system-manager) -- deliberately never
# alongside ../host, whose lldap/pocket-id modules have not been assessed against system-manager
# at all (see README's "What this deliberately does not do"). If this file ever grows an import of
# anything that needs `pkgs`, `posix-purity` starts failing by design.
{ ... }:
{
  nixiam.posix = {
    enable = true;
    domain = "example.com";
    identities = {
      # One of each variant, so a reader sees both branches `podSecurity` can produce.
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
    groups.shared-readers.gid = 3100;
  };

  # ── Stubs NixOS demands of any bootable system ───────────────────────────
  # This is not a machine anyone would run. It exists so the registry module type-checks on its
  # own, with nothing else composed in -- that absence is the whole point of this file.
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
