# locked

Per-user file protection for macOS, v2: BSD-flag chains on top of the v1
ownership flip. A locked node can't be written, renamed, or deleted even by
a process with write permission on its parent, and the flag can't be
cleared by any process running as you (the node is owned by the lock
account, or carries a root-only system flag). Design: [DESIGN-v2.md](DESIGN-v2.md).
Every privileged action runs via `sudo`; whatever auth you've set up
(password, `pam_tid` for Touch ID, [`sudowhat`](https://github.com/jooize/sudowhat)
for trusted prompts) gates each operation. `locked` does not touch sudo's
auth chain.

Three tiers, named by what they protect:

- `content` (`uchg`, lock-account-owned) -- leaf files, or leaf dirs
  recursively. Edit cycle: unlock, edit, lock.
- `placement` (`uappnd`, lock-account-owned + group-write) -- shared parent
  dirs (`~/.config`, `~/Library`, ...): new entries fine, replacing or
  removing existing ones denied.
- `anchor` (`sappnd` or `schg`, ownership unchanged) -- nodes the OS
  identity-checks against your UID (`~`, `~/.ssh`): the system flag binds
  every user process while sshd's owner checks keep passing.

## Workflow
- `sudo locked lock <path>` -- adopt or relock. Derives and provisions the
  whole ancestor chain (placement for user-owned parents, anchor for `~`),
  stops only at a root-owned node, shows the snapshot diff, and asks
  before sealing (`--yes` for scripted runs, `--dry-run` to preview).
- `sudo locked edit <file>` -- sudoedit-style edit, the preferred flow:
  your editor runs as you on a user-owned temp copy, the candidate is
  staged out of reach, then diff + confirm installs and reseals. The
  file is never left unlocked and no chain release is needed.
- `sudo locked unlock <path>` -- release just that node (snapshot taken);
  `--chain` also drops the ancestors' flags when an edit needs a rename
  into a frozen parent (atomic-save editors).
- `sudo locked revert <file>` -- save current to `.attic`, restore
  snapshot, re-seal.
- `sudo locked status [<path>]` -- verify and print the full chain for each
  path. With no path, lists every node in your pool (tier, flag, and any
  drift) so you can see at a glance what is currently locked; reporting
  only, so it exits 0 even on drift and never touches the alert file.
- `sudo locked verify` -- re-check every locked node against its meta;
  exit 5 on drift; raises/clears the `locked--drift` statusline alert. A
  launchd timer (installed by setup) runs this every 15 minutes.
- `sudo locked setup` -- one-shot install + provision (see below).

Tests: `sudo /bin/bash tests/harness.bash` (scratch-dir only; stands in
`daemon` for the lock account, no global state touched).

## Nix install (nix-darwin module)

The flake exports `darwinModules.default` (Darwin-only on purpose: the
whole mechanism is BSD file flags). It declares everything `setup` does
imperatively -- binary in the system profile, hidden lock account and
group, verify LaunchDaemon -- and generates `/etc/sudoers.d/locked` at
build time from the same string the installed script is built from, so
the sudoers sha256 digest can never drift from the deployed bytes; a
rebuild moves both atomically with the generation.

```nix
# flake input (no inputs of its own), then:
imports = [ inputs.locked.darwinModules.default ];
security.locked = {
  enable = true;
  user = "jooize";
  uid = 403;   # declared id (users.knownUsers); pick a free one in 400-499
};
```

The id is declared in the config (spirit of nix; on-disk snapshot
ownership survives account recreation with its meaning intact). For a
config that must not carry a machine-specific number, set
`allocateIds = true` instead -- the account is then provisioned
imperatively at activation with the first free id in 401-499 (`setup`'s
own logic); exactly one of the two is required. Deletion is a manual
ceremony either way: nix-darwin refuses to delete accounts with ids
<= 501.

A nix-managed install refuses `setup` (the module owns provisioning) and
accepts `/nix/store` in the install-ancestry walk -- keyed to that
literal path, so `/usr/local`-shaped paths get no relaxation.

## One-shot install: `sudo ./locked setup`

From this folder, after cloning/copying:
```sh
sudo ./locked setup
```
Idempotent. Provisions everything in section "Prerequisites" below in one go:
- Creates `_<user>-lock` group and user (prefers UID/GID 401 in the 400-499 service lane, falling back to the next free; `IsHidden 1`; shell `/usr/bin/false`). 401 is the lock slot; 402 is reserved for the Claude trust group `_<user>-readonly`.
- Adds you to the lock group.
- Writes `/etc/sudoers.d/locked` with the matching sudoers entry; validates via `visudo -c` before installing.
- Self-installs the script to `/usr/local/sbin/locked` (root:wheel, mode 755), refusing if any ancestor up to `/` is user-writable.
- Installs and loads the verify LaunchDaemon (`/Library/LaunchDaemons/locked.verify.plist`, every 900 s).
- Flushes directory service cache so the new account is visible immediately.

Re-running setup is safe: each step is gated on existence/presence checks.

## Prerequisites (manual alternative to `setup`)

If you'd rather not run `sudo ./locked setup`, the same steps by hand. Replace `jooize` with your username throughout. Sudo auth is independent -- set up `pam_tid` (Touch ID), [`sudowhat`](https://github.com/jooize/sudowhat), or rely on password fallback separately; `locked` doesn't touch the sudo auth chain.

### 1. Install the binary

Verify `/usr/local/sbin` and every ancestor up to `/` are root-owned with no group/other write -- mode `755` or stricter. A user-writable ancestor lets a swapped binary inherit root after the next sudo approval.
```sh
for p in /usr/local/sbin /usr/local /usr; do
  stat -f '%Su:%Sg %OLp' "$p" 2>/dev/null
done
# Expect each line: owner "root" (any group) with mode 755 (or stricter: 750, 700, ...).
```
If any ancestor is user-owned -- common on Intel Macs where Homebrew once `chown`ed `/usr/local` -- repair before continuing: `sudo chown root:wheel <path> && sudo chmod 755 <path>`.

Then install:
```sh
sudo install -d -m 755 -o root -g wheel /usr/local/sbin
sudo install -m 755 -o root -g wheel ./locked /usr/local/sbin/locked
```

### 2. Lock account `_jooize-lock`

Pick an unused UID/GID < 500 (`dscl . -list /Users UniqueID` and `dscl . -list /Groups PrimaryGroupID` show the in-use set). 401 is the conventional lock slot here (400 collides with Apple's `com.apple.access_remote_ae`; 402 is reserved for `_jooize-readonly`).
```sh
GID_LOCK=401; UID_LOCK=401  # adjust on collision

sudo dscl . -create /Groups/_jooize-lock
sudo dscl . -create /Groups/_jooize-lock RealName "Lock group for jooize"
sudo dscl . -create /Groups/_jooize-lock PrimaryGroupID $GID_LOCK

sudo dscl . -create /Users/_jooize-lock
sudo dscl . -create /Users/_jooize-lock UniqueID $UID_LOCK
sudo dscl . -create /Users/_jooize-lock PrimaryGroupID $GID_LOCK
sudo dscl . -create /Users/_jooize-lock UserShell /usr/bin/false
sudo dscl . -create /Users/_jooize-lock NFSHomeDirectory /var/empty
sudo dscl . -create /Users/_jooize-lock RealName "Lock user for jooize"
sudo dscl . -create /Users/_jooize-lock IsHidden 1

sudo dseditgroup -o edit -a jooize -t user _jooize-lock
```

### 3. Sudoers entry (digest-pinned)

Compute the installed binary's sha256, stage the sudoers line to a tmp file, validate via `visudo -c`, then install. Skipping validation risks an unparseable `/etc/sudoers.d/locked` that locks you out of `sudo` until single-user recovery.
```sh
DIGEST=$(shasum -a 256 /usr/local/sbin/locked | awk '{print $1}')
TMP=$(mktemp)
printf 'jooize ALL=(root) sha256:%s /usr/local/sbin/locked\n' "$DIGEST" >"$TMP"
sudo visudo -c -f "$TMP" && \
  sudo install -m 440 -o root -g wheel "$TMP" /etc/sudoers.d/locked
rm -f "$TMP"
```
No `NOPASSWD` -- sudo prompts for your configured auth on each invocation. The `sha256:` pin means a swapped binary at the install path fails silently at the sudoers stage; sudo refuses without ever prompting.

### 4. Flush directory service cache

So `chown _jooize-lock` and group-membership checks take effect immediately instead of waiting for the cache TTL.
```sh
sudo dscacheutil -flushcache
```

### Verify

```sh
sudo /usr/local/sbin/locked unlock /nonexistent   # should print 'skip /nonexistent: does not exist'
```
Touch ID/password prompt names `/usr/local/sbin/locked unlock /nonexistent`; binary runs; logs `result=skip-noent` via `log show --predicate 'eventMessage CONTAINS "locked:"' --last 1m`.

## Initial setup of a file

`sudo locked lock <path>` adopts any file or dir you own -- no manual
chown. The first lock captures owner/group/mode as canonical, takes a
baseline snapshot, and provisions the ancestor chain.

## Snapshot layout
```
/var/db/locked-snapshots/             mode 700  root:wheel
└── jooize/                            mode 700  _jooize-lock
    ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.snap   mode 600  _jooize-lock
    ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.attic
    └── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.meta
```
- `.snap` -- pre-edit baseline, overwritten on each unlock (`.snapdir` for
  content-tier directories).
- `.attic` -- discarded post-edit content, overwritten on each revert.
- `.meta` -- captured identity plus lock state, one `key=value` per line:
  `owner`, `group`, `mode` (restore targets), `lockmode` (expected mode
  while locked), `tier`, `flag`, `flagsym` (exact post-seal flag word),
  `id` (dev.ino), `recursive`, `state` (`locked`/`unlocked`). `verify`
  compares reality against this.

## Mode and ownership preservation

The `owner`/`group`/`mode` restore targets are captured on the first `lock` of a file and carried unchanged through every later meta rewrite (v2 rewrites the file on each state transition to track flags and state, but the captured identity persists). On every subsequent `unlock`, `lock`, and `revert`, the script chmods/chowns the file back to the meta values. So:
- Accidental `chmod 666 ~/.ssh/authorized_keys` while unlocked -- next lock restores the captured mode.
- An attacker that gets a single chmod through (somehow) is undone the next cycle.
- To intentionally change the captured mode/owner, edit `.meta` directly: `sudo -u _jooize-lock vi /var/db/locked-snapshots/jooize/<encoded>.meta`. (Or delete the meta and re-lock to recapture.)

## Caveats
- First lock assumes file is currently owned by you. To bring a file owned by someone else into the pool: `sudo chown -h <you>:staff <file>` first, then `sudo locked lock <file>` captures meta and locks. Or hand-write the meta file before unlocking once.
- Other admins on the same machine can read snapshots via `sudo` (root reads all). Only encryption fixes that; not in scope here.
- `readlink -f` requires macOS 12+. On older macOS, replace with `realpath` or a Python one-liner.
- **Extended attributes and ACLs are not preserved across snapshot/restore.** `cp`/`install` don't carry xattrs by default; quarantine, code-signature, and custom-ACL metadata are lost on a `revert`. BSD flags ARE handled in v2 (meta records the exact word; revert re-seals). Designed for textual config files (authorized_keys, ssh config, settings.json), not binaries or files with critical attached metadata. **Future work** (deferred): round-trip xattrs via `xattr -p`/`-w`, ACLs via `/bin/chmod +a/-a` capture. Search for `TODO(xattrs)` in the script.
- Default install path is `/usr/local/sbin/locked`. **Why not `/usr/libexec/`** (the natural spot for system helpers): `/usr/libexec` is on the sealed system volume since macOS 11; even root can't write there without booting to recovery and tearing down SSV. **Why not `/usr/local/bin/`**: same writable space but with the legacy Intel-Homebrew "chown -R \$USER /usr/local" footgun more common there. **Why `/usr/local/sbin/`**: less commonly tampered, semantically right for "needs sudo" admin tools, and in PATH by default.
- Setup verifies the entire ancestry up to `/` is root-owned with no group/other write -- mode `755` or stricter -- and refuses to install otherwise. The same verification runs on **every** subsequent invocation -- if `/usr/local` ever gets chowned to a user after setup (e.g., a later Homebrew permission-fix recipe), the next `sudo locked ...` refuses with a clear error. This closes the "post-setup escalation" wedge: a swapped binary at a writable ancestor would otherwise inherit root after the next Touch ID approval.
- Override default install path via `INSTALL_TARGET=/path sudo -E ./locked setup`. If you go this route, you'll need to re-run setup any time you want to change the path -- the sudoers entry references the path, not a binary identity.

## Atomicity and TOCTOU

Snapshot/attic/restore writes go through `atomic_replace`:
1. Copy source into `/var/db/locked-snapshots/<user>/.staging/replace.XXXXXX` (lock-account-owned, mode 700 -- invisible to user UID).
2. `chown` and `chmod` the staged temp file.
3. Verify staging and destination are on the same filesystem (`stat -f '%d'`).
4. `mv -f` -- atomic same-filesystem rename.

This eliminates partial-write windows on the destination side and keeps the temp file out of user-visible space throughout preparation.

**Residual TOCTOU** (not fixable in pure bash, marked `TODO(toctou)` and `TODO(parent-swap)` in source):
- Source-side: an attacker who can write to the source's parent directory could swap the source file between `readlink -f` and `cp`'s `open(2)`. Closing this requires `O_NOFOLLOW` open + `fchmod`/`fchown` on a held fd -- needs a Swift/Python/C helper.
- Parent-dir swap: same threat applied to the destination's parent directory between path resolution and the final `mv`.

Both residuals exist in the original `install`-based implementation too -- `atomic_replace` doesn't make them worse, but doesn't close them either. They become real defenses only when the locked file's parent directory is itself protected (e.g., `~/.ssh/` chowned to the lock account, which requires a separate setup step).

## Audit log

Every action emits a unified-logging entry tagged `locked`. View recent activity:
```sh
log show --predicate 'eventMessage CONTAINS "locked: user="' --last 1h
```
Useful for spotting unexpected lock/unlock cycles. The log records `user=`, `action=`, `file=`, and `result=` (ok / skip-* / error) for each per-file operation.

## Removing a file from the lock pool
```sh
sudo locked unlock <file>
# (file is now owned by you, with restored meta mode)
# delete sidecar files:
sudo rm /var/db/locked-snapshots/jooize/<encoded>.{snap,attic,meta}
```
