# system-manager backend for nixiam baseline packages.
#
# On Arch/CachyOS the package backend runs through nixarch's reconcile machinery:
# publish pacman/AUR lists and let nixarch own the reconcile transaction.
{ config, ... }:
{
  imports = [ ./packages.nix ];

  config = {
    nixarch.packages.pacman = config.nixiam.packages.archPackages;
    nixarch.packages.aur = config.nixiam.packages.aurPackages;
  };
}
