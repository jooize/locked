{
  description = "locked -- three-tier BSD-flag protection for user-space trust surfaces";

  # No inputs: the module takes pkgs/lib from the consuming system.
  outputs = { self }: {
    darwinModules.default = import ./nix/module.nix;
  };
}
