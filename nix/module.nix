# Declarative locked install for nix-darwin.
#
# Declares everything `sudo locked setup` does imperatively: the binary in
# the system profile and a digest-pinned /etc/sudoers.d/locked entry. The
# sudoers digest and the installed binary derive from ONE string at eval time
# (scriptText below), so they can never disagree -- the drift window that
# manual setup closes by re-running is structurally absent here. The
# script itself detects the nix deployment and refuses its imperative
# setup path.
#
# Darwin-only on purpose: locked is built on BSD file flags and dscl;
# there is nothing portable to declare.
{ config, lib, pkgs, ... }:

let
  cfg = config.security.locked;

  srcText = builtins.readFile ../locked;

  # The compiled fd-window helper (mediated placement ops). Built from one
  # translation unit with the stdenv clang; -Werror because a warning in a
  # root-executing helper is a finding, not noise. Its store path is baked
  # into scriptText below, which does two jobs at once: the sudoers digest
  # of the script transitively commits to WHICH helper binary runs (the
  # path names the input-addressed build), and the string context makes the
  # helper part of the system closure with no systemPackages entry -- it
  # stays off PATH on purpose, it is locked's to invoke, not the user's.
  # Content trust at run time is the script's own ancestry/ownership walk,
  # the same check it applies to itself; a content hash cannot live here
  # because the binary's bytes only exist after the build.
  helper = pkgs.runCommandCC "locked-helper" { } ''
    mkdir -p $out/bin
    $CC -O2 -Wall -Wextra -Werror -framework Foundation \
      -o $out/bin/locked-helper ${../helper/locked-helper.m}
  '';

  # Anchor-line rewrites, failing the eval loudly if an anchor ever
  # changes shape in the script: INSTALL_TARGET's default becomes the
  # system-profile path (stable across generations, always resolving to
  # the current build), LOCKED_HELPER's default becomes the store path of
  # the helper built above, and LOCKED_GIT, the git that draws every diff,
  # becomes pkgs.git's store path. LOCKED_GIT
  # is a plain readonly assignment, not a `:=` default: root runs that git
  # on bytes the invoker wrote, so no environment may name another, and
  # like the helper's path it puts the git in the closure and under the
  # sudoers digest.
  #
  # Deliberate non-rewrites, unlike pinned's module: the shebang is
  # already `/bin/bash -p` in the repo (see the script's own header --
  # sudo passes the caller's PATH through, so `env bash` would let the
  # invoker pick root's interpreter, and -p keeps bash from reading
  # BASH_ENV, SHELLOPTS and exported functions before line one, with or
  # without sudo's env_reset), and PATH is NOT profile-prepended: every
  # probe in locked speaks BSD (stat -f, chflags, dscl), and a GNU
  # coreutils `stat` from the profile would shadow it with different
  # semantics. The OS-only PATH is correct here.
  #
  # Each anchor is a whole line, a line feed on both sides (line), so a
  # comment that quotes one -- `: "${VAR:=...}"` mid-sentence -- is never
  # rewritten, and a line that merely starts the same way never matches.
  line = l: "\n" + l + "\n";
  anchors = map (a: { from = line a.from; to = line a.to; }) [
    {
      from = '': "''${INSTALL_TARGET:=/usr/local/sbin/locked}"'';
      to = '': "''${INSTALL_TARGET:=${cfg.installPath}}"'';
    }
    {
      from = '': "''${LOCKED_HELPER:=/usr/local/sbin/locked-helper}"'';
      to = '': "''${LOCKED_HELPER:=${helper}/bin/locked-helper}"'';
    }
    {
      from = "readonly LOCKED_GIT=/Library/Developer/CommandLineTools/usr/bin/git";
      to = "readonly LOCKED_GIT=${pkgs.git}/bin/git";
    }
  ];
  scriptText =
    assert lib.assertMsg (lib.all (a: lib.hasInfix a.from srcText) anchors)
      "locked/nix: an anchor line was not found in ../locked; update module.nix";
    builtins.replaceStrings (map (a: a.from) anchors) (map (a: a.to) anchors) srcText;

  package = pkgs.writeScriptBin "locked" scriptText;

  digest = builtins.hashString "sha256" scriptText;

  # No NOPASSWD: sudo still authenticates; the Digest_Spec makes it hash
  # the resolved binary at invocation and refuse on mismatch. Darwin has
  # no visudo at build time in nixpkgs' sudo; the single generated line
  # below is shape-asserted via validUser instead (same stance as pinned).
  sudoersFile = pkgs.writeText "sudoers-locked"
    "${cfg.user} ALL=(root) sha256:${digest} ${cfg.installPath}\n";

  validUser = user: builtins.match "[A-Za-z_][A-Za-z0-9_-]*" user != null;

in
{
  options.security.locked = {
    enable = lib.mkEnableOption "locked, the BSD-flag trust-surface seal";

    user = lib.mkOption {
      type = lib.types.str;
      description = ''
        The human operator: granted sudo for the locked binary
        (digest-pinned, no NOPASSWD). Their pool is readable to them
        through an ACL entry the script itself gives.
      '';
    };

    installPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/current-system/sw/bin/locked";
      description = ''
        Path the sudoers entry names; it must be the path actually
        invoked under sudo. The default is the system-profile path, which
        is stable across generations and always resolves to the current
        build. (Manual, non-nix installs are unaffected: they use the
        script's own default, /usr/local/sbin/locked.)
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      default = package;
      defaultText = lib.literalMD "the script this module builds";
      description = ''
        The locked package this module builds and installs, exposed so a
        consumer can hand the SAME derivation to something that needs its
        own copy. Read-only on purpose: these are the bytes the sudoers
        Digest_Spec commits to.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = validUser cfg.user;
        message = "security.locked.user must match [A-Za-z_][A-Za-z0-9_-]* (it is spliced into sudoers)";
      }
      {
        assertion = pkgs.stdenv.hostPlatform.isDarwin;
        message = "security.locked is Darwin-only (BSD file flags)";
      }
    ];

    environment.systemPackages = [ package ];

    environment.etc."sudoers.d/locked".source = sudoersFile;
  };
}
