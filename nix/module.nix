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

  # One anchor-line rewrite, failing the eval loudly if the anchor ever
  # changes shape in the script: INSTALL_TARGET's default becomes the
  # system-profile path (stable across generations, always resolving to
  # the current build).
  #
  # Deliberate non-rewrites, unlike pinned's module: the shebang is
  # already /bin/bash in the repo (see the script's own header -- sudo
  # passes the caller's PATH through, so `env bash` would let the invoker
  # pick root's interpreter), and PATH is NOT profile-prepended: every
  # probe in locked speaks BSD (stat -f, chflags, dscl), and a GNU
  # coreutils `stat` from the profile would shadow it with different
  # semantics. The OS-only PATH is correct here.
  anchors = [
    {
      from = '': "''${INSTALL_TARGET:=/usr/local/sbin/locked}"'';
      to = '': "''${INSTALL_TARGET:=${cfg.installPath}}"'';
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

  # Account provisioning mirrors `setup` steps 2-4 (proven idempotent),
  # the same way pinned's module provisions its groups: Darwin has no id
  # allocator, so a declarative users.users entry would force a hand-
  # picked uid into the config. Instead scan the hidden 401-499 service
  # range for the first free id at activation time. The trade, accepted
  # knowingly: nix-darwin does not manage the account's lifecycle
  # (creation-if-absent only, no declarative deletion); nothing consumes
  # the id NUMBER -- sudoers, chown and the script all go by name.
  provisionAccounts = ''
    if ! /usr/bin/dscl . -read "/Groups/${lockAccount}" PrimaryGroupID >/dev/null 2>&1; then
      taken="$(/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk '{print $2}')"
      locked_gid=""
      for c in $(/usr/bin/seq 401 499); do
        if ! printf '%s\n' "$taken" | /usr/bin/grep -qx "$c"; then locked_gid="$c"; break; fi
      done
      if [ -z "$locked_gid" ]; then
        echo "locked: no free gid in 401-499; refusing to provision ${lockAccount}" >&2
        exit 1
      fi
      echo "creating group ${lockAccount} (gid $locked_gid, hidden range)..." >&2
      /usr/bin/dscl . -create "/Groups/${lockAccount}"
      /usr/bin/dscl . -create "/Groups/${lockAccount}" RealName "Lock group for ${cfg.user}"
      /usr/bin/dscl . -create "/Groups/${lockAccount}" PrimaryGroupID "$locked_gid"
    fi
    if ! /usr/bin/dscl . -read "/Users/${lockAccount}" UniqueID >/dev/null 2>&1; then
      locked_gid="$(/usr/bin/dscl . -read "/Groups/${lockAccount}" PrimaryGroupID | /usr/bin/awk '{print $2}')"
      taken="$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '{print $2}')"
      locked_uid=""
      for c in $(/usr/bin/seq 401 499); do
        if ! printf '%s\n' "$taken" | /usr/bin/grep -qx "$c"; then locked_uid="$c"; break; fi
      done
      if [ -z "$locked_uid" ]; then
        echo "locked: no free uid in 401-499; refusing to provision ${lockAccount}" >&2
        exit 1
      fi
      echo "creating user ${lockAccount} (uid $locked_uid, hidden range)..." >&2
      /usr/bin/dscl . -create "/Users/${lockAccount}"
      /usr/bin/dscl . -create "/Users/${lockAccount}" UniqueID "$locked_uid"
      /usr/bin/dscl . -create "/Users/${lockAccount}" PrimaryGroupID "$locked_gid"
      /usr/bin/dscl . -create "/Users/${lockAccount}" UserShell /usr/bin/false
      /usr/bin/dscl . -create "/Users/${lockAccount}" NFSHomeDirectory /var/empty
      /usr/bin/dscl . -create "/Users/${lockAccount}" RealName "Lock user for ${cfg.user}"
      /usr/bin/dscl . -create "/Users/${lockAccount}" IsHidden 1
      /usr/bin/dscacheutil -flushcache
    fi
    # Membership grants add-rights in placement-tier dirs; asserted on
    # every activation.
    /usr/sbin/dseditgroup -o edit -a "${cfg.user}" -t user "${lockAccount}" 2>/dev/null || true
  '';
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
      type = lib.types.nullOr lib.types.int;
      default = null;
      description = ''
        Uid for the lock account (also its gid unless gid is set),
        declared via users.knownUsers -- the preferred, declarative
        mode: the number lives in the config, and on-disk ownership of
        the snapshot tree survives any account recreation with its
        meaning intact. Pick a free id in the hidden 400-499 service
        range; list what is taken with:

            dscl . -list /Users UniqueID | awk '$2 >= 400 && $2 < 500'
            dscl . -list /Groups PrimaryGroupID | awk '$2 >= 400 && $2 < 500'

        For a config that must not carry a machine-specific number, set
        allocateId instead; one of the two is required. Deletion is a
        manual ceremony either way -- nix-darwin refuses to delete
        accounts with ids <= 501.
      '';
    };

    allocateId = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Opt out of declaring a number: provision the lock account
        imperatively at activation with the first free id in 401-499
        (setup's own allocation logic; idempotent). Nothing consumes the
        id number, so this is safe -- the trade is that the account
        lives outside nix-darwin's users.knownUsers registry.
      '';
    };

    gid = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = cfg.uid;
      defaultText = lib.literalExpression "config.security.locked.uid";
      description = "Gid for the lock group when uid is set.";
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

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [
        {
          assertion = validUser cfg.user;
          message = "security.locked.user must match [A-Za-z_][A-Za-z0-9_-]* (it is spliced into sudoers)";
        }
        {
          assertion = pkgs.stdenv.hostPlatform.isDarwin;
          message = "security.locked is Darwin-only (BSD file flags)";
        }
        {
          # Exactly one mode: declarative is the default expectation
          # (spirit of nix -- the config carries the number); imperative
          # allocation is the explicit opt-out, never a silent fallback.
          assertion = (cfg.uid != null) != cfg.allocateId;
          message = "security.locked: set uid (declarative, preferred) or allocateId = true (activation-time allocation) -- exactly one";
        }
      ];

      environment.systemPackages = [ package ];

      environment.etc."sudoers.d/locked".source = sudoersFile;
    }

    # Two provisioning modes, the assertion above enforcing a conscious
    # choice: declared number -> users.knownUsers, converged by
    # nix-darwin; allocateId -> imperative first-free allocation, same
    # as `setup` would do.
    (lib.mkIf (cfg.uid != null) {
      users.knownUsers = [ lockAccount ];
      users.knownGroups = [ lockAccount ];
      users.users.${lockAccount} = {
        uid = cfg.uid;
        gid = cfg.gid;
        description = "Lock user for ${cfg.user}";
        # home/shell left null: nix-darwin creates with /var/empty and
        # /usr/bin/false, exactly the imperative values.
      };
      users.groups.${lockAccount} = {
        gid = cfg.gid;
        description = "Lock group for ${cfg.user}";
        members = [ cfg.user ];
      };
    })
    (lib.mkIf cfg.allocateId {
      system.activationScripts.extraActivation.text = lib.mkAfter provisionAccounts;
    })

    {
      # Declarative replacement for install_verify_timer. The daemon runs
      # the store path directly: launchd needs no digest gate (it is root
      # already), and the plist changing per build makes nix-darwin
      # reload it with each generation. Label is set explicitly so the
      # plist keeps the documented path
      # /Library/LaunchDaemons/locked.verify.plist.
      launchd.daemons.locked-verify = {
        serviceConfig = {
          Label = "locked.verify";
          ProgramArguments = [ "${package}/bin/locked" "verify" "--quiet" ];
          StartInterval = cfg.verifyInterval;
          RunAtLoad = true;
          StandardErrorPath = "/var/log/locked-verify.log";
        };
      };
    }
  ]);
}
