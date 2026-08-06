# Declarative locked install for nix-darwin.
#
# Declares everything `sudo locked setup` does imperatively: the binary in
# the system profile, the hidden lock account and group, a digest-pinned
# /etc/sudoers.d/locked entry, and the verify LaunchDaemon. The sudoers
# digest and the installed binary derive from ONE string at eval time
# (scriptText below), so they can never disagree -- the drift window that
# manual setup closes by re-running is structurally absent here. The
# script itself detects the nix deployment and refuses its imperative
# setup path.
#
# Darwin-only on purpose: locked is built on BSD file flags, dscl and
# launchd; there is nothing portable to declare.
{ config, lib, pkgs, ... }:

let
  cfg = config.security.locked;

  srcText = builtins.readFile ../locked;

  # Anchor-line rewrites, failing the eval loudly if any anchor ever
  # changes shape in the script:
  #
  #   - INSTALL_TARGET default becomes the system-profile path (stable
  #     across generations, always resolving to the current build).
  #   - The shebang becomes /bin/bash: `env bash` resolves the interpreter
  #     from the CALLER's environment before the script's own PATH pin
  #     runs, and /bin/bash is the exact interpreter the harness proves
  #     the script against.
  #
  # Unlike pinned's module, PATH is deliberately NOT rewritten to prepend
  # the system profile: every probe in locked speaks BSD (stat -f,
  # chflags, dscl), and a GNU coreutils `stat` from the profile would
  # shadow it with different semantics. The OS-only PATH is correct here.
  anchors = [
    {
      from = '': "''${INSTALL_TARGET:=/usr/local/sbin/locked}"'';
      to = '': "''${INSTALL_TARGET:=${cfg.installPath}}"'';
    }
    {
      from = "#!/usr/bin/env bash";
      to = "#!/bin/bash";
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

  # Same derivation as the script's lock_account_for().
  lockAccount = "_${cfg.user}-lock";
in
{
  options.security.locked = {
    enable = lib.mkEnableOption "locked, the BSD-flag trust-surface seal";

    user = lib.mkOption {
      type = lib.types.str;
      description = ''
        The human operator: granted sudo for the locked binary
        (digest-pinned, no NOPASSWD) and made a member of the lock group,
        which carries add-rights in placement-tier directories. The lock
        account and group are named _<user>-lock, matching the script's
        own derivation.
      '';
    };

    uid = lib.mkOption {
      type = lib.types.int;
      description = ''
        Uid for the lock account (also its gid unless gid is set).
        Darwin has no id allocator, so pick a free id in the hidden
        400-499 service range consciously; list what is taken with:

            dscl . -list /Users UniqueID | awk '$2 >= 400 && $2 < 500'
            dscl . -list /Groups PrimaryGroupID | awk '$2 >= 400 && $2 < 500'

        No default on purpose: a collision at activation is skipped with
        a warning by nix-darwin, which would leave the account missing
        while everything else deploys.
      '';
    };

    gid = lib.mkOption {
      type = lib.types.int;
      default = cfg.uid;
      defaultText = lib.literalExpression "config.security.locked.uid";
      description = "Gid for the lock group.";
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

    verifyInterval = lib.mkOption {
      type = lib.types.int;
      default = 900;
      description = "Seconds between verify daemon runs.";
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

    # Declarative replacement for setup's dscl block. home and shell are
    # left null: nix-darwin then creates the account with /var/empty and
    # /usr/bin/false, exactly the imperative values.
    users.knownUsers = [ lockAccount ];
    users.knownGroups = [ lockAccount ];
    users.users.${lockAccount} = {
      uid = cfg.uid;
      gid = cfg.gid;
      description = "Lock user for ${cfg.user}";
      # isHidden default true; uid < 500 hides it from loginwindow anyway.
    };
    users.groups.${lockAccount} = {
      gid = cfg.gid;
      description = "Lock group for ${cfg.user}";
      # Membership grants add-rights in placement-tier dirs (group-write
      # there); nix-darwin converges membership to exactly this list.
      members = [ cfg.user ];
    };

    # Declarative replacement for install_verify_timer. The daemon runs
    # the store path directly: launchd needs no digest gate (it is root
    # already), and the plist changing per build makes nix-darwin reload
    # it with each generation.
    launchd.daemons.locked-verify = {
      serviceConfig = {
        Label = "locked.verify";
        ProgramArguments = [ "${package}/bin/locked" "verify" "--quiet" ];
        StartInterval = cfg.verifyInterval;
        RunAtLoad = true;
        StandardErrorPath = "/var/log/locked-verify.log";
      };
    };
  };
}
