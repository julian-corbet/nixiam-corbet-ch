# The smallest configuration that composes nixiam.users + nixiam.posix together -- the worked
# cross-reference `modules/users.nix`'s own header describes: a human resolving `posixIdentity`
# by name into an entry `nixiam.posix.identities` already declares, never restating the uid.
#
# Deliberately does NOT enable `nixiam.lldapReconcile` -- there is nothing here for it to talk to
# (no `nixiam.lldap` either), and the mechanism that reads `nixiam.users` is exercised separately,
# against a local mock, in ../../experiments (never against a real lldap, and never wired into
# `nix flake check` -- see this repo's own README for why `checks/` stays evaluation-only).
#
# Every name below is a placeholder: no real person, email, or group from any real deployment.
{ ... }:
{
  nixiam.posix = {
    enable = true;
    domain = "example.com";
    # The uid/gid a shell login for "alice" below would actually run as, on a host that also
    # gives her one -- declared once, here, and referenced by name, never repeated as a number.
    identities.alice-shell.uid = 3000;
  };

  nixiam.users = {
    # A human with BOTH a directory identity and a POSIX/local-account correspondence: she can
    # log in through SSO AND (on whatever host wires up a local account from this same name) get
    # a shell as uid 3000 -- one declaration, both consumers, structurally unable to disagree.
    alice = {
      posixIdentity = "alice-shell";
      displayName = "Alice Example";
      email = "alice@example.com";
      groups = [ "admins" ];
    };

    # A human with NO POSIX identity at all -- the common case: SSO-only access to whatever web
    # app pocket-id fronts, never a shell, never a chowned dataset leaf. posixIdentity's default
    # (null) is exactly this case, so it is simply omitted here.
    bob = {
      displayName = "Bob Example";
      email = "bob@example.com";
      groups = [ "readers" ];
    };

    # A departed identity, kept declared rather than deleted from this file, so the historical
    # record (who they were, and why they are no longer active) survives in git history next to
    # the flag that actually disables them. No acknowledgeRemoval here: this person's lldap
    # account, if it still exists, is reported as drift on every reconcile pass and left
    # completely alone -- see modules/lldap-reconcile.nix's own header for why that is the
    # default rather than an automatic cleanup.
    carol = {
      enable = false;
      displayName = "Carol Example";
      email = "carol@example.com";
    };
  };

  # ── Stubs NixOS demands of any bootable system ───────────────────────────
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
