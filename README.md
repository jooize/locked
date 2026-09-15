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
- `placement` (`uappnd`, lock-account-owned, group and mode unchanged,
  one ACL entry that lets you add) -- ancestor dirs *above* a locked
  leaf's own parent (`~/.config`, `~/Library`, ...), derived from the
  files you protect and never named: new entries fine, replacing or
  removing existing ones denied. What you create there is ordinary: your
  group, no ACL -- see
  [How you get into a placement directory](#how-you-get-into-a-placement-directory).
- `anchor` (`sappnd` or `schg`, ownership unchanged) -- nodes the OS
  identity-checks against your UID (`~`, `~/.ssh`): the system flag binds
  every user process while sshd's owner checks keep passing.

## Workflow
- `sudo locked lock <path>` -- protect a file, directory or symlink, or
  relock one. You name what to protect; locked derives the rest: the
  ancestor chain from the leaf's *grandparent* up (placement for user-owned
  dirs, anchor for `~`), stopping at a root-owned node, and any sealed
  directory no protected file needs any more, which it releases. The
  leaf's own parent is not sealed unless it is the anchor -- see [The pool
  is what you protect](#the-pool-is-what-you-protect). Nothing is touched
  until the whole ceremony is derived: the snapshot diff, then the plan --
  one line per node, root-most first -- then one question for all of it
  (`--yes` for scripted runs, `--dry-run` prints the plan and stops).
  Naming a symlink seals the link itself, not what it points at.
- `sudo locked unprotect <path>` -- stop protecting it for good: flag off,
  owner, group and mode back to what they were before the first lock, the
  record retired, and every directory no other protected file needs
  released in the same plan and under the same question.
- `sudo locked edit <file>` -- sudoedit-style edit, the preferred flow:
  your editor runs as you on a user-owned temp copy, the candidate is
  staged out of reach, then diff + confirm installs and reseals. The
  file is never left unlocked and no chain release is needed. With
  `--from <copy>` the proposed content comes from a file you prepared
  instead of from an editor -- see below.
- `sudo locked unlock <path>` -- release just that node (snapshot taken);
  `--chain` also drops the ancestors' flags when an edit needs a rename
  into a frozen parent (atomic-save editors).
- `sudo locked revert <file>` -- save current to `.attic`, restore
  snapshot, re-seal.
- `sudo locked rm|trash|mv` -- mediated placement: remove, trash, or
  rename something a sealed parent will not let go of. A compiled helper
  holds the parent by file descriptor, verifies its identity, lifts the
  flag, performs the one syscall, restores the flag, and diffs the
  parent's entries across the window -- anything but the expected change
  raises an alarm instead of being sealed over. `trash` calls the real
  macOS trash service as you (so the bin entry is yours and Put Back
  works), and suspends the record rather than retiring it: a Put Back of
  a previously sealed node is flagged by `verify` instead of silently
  coming back unprotected. `rm --recursive` takes a whole tree, sealed
  nodes included. Pool records follow every operation -- retired with
  provenance for a removal, re-keyed for a move -- so `verify` stays
  honest without training you to ignore it.
- `sudo locked rekey <old> <new>` -- record-only repair when something
  else already moved a pool node; refuses unless `<new>` is the very
  inode the record describes.
- `sudo locked tombstone <path>` -- assert a recorded path is gone for
  good (retired, provenance "assertion"). Refused while it still exists.
- `locked why <path>` -- what, if anything, stops this path from being
  changed, renamed, or removed: flags on it and every ancestor, who owns
  them, whether locked set them, and the command that goes through the
  constraint. No `sudo` needed.
- `locked status [<path>]` -- verify and print the full chain for each
  path. With no path, lists every node in your pool (tier, flag, and any
  drift) so you can see at a glance what is currently locked, then what
  the last `verify` run found and when; reporting only, so it exits 0
  even on drift and never writes the verify status.
  The one action that needs no `sudo`: it is read-only, and it shows your
  own pool only -- another user's pool is unreadable to you. One caveat,
  printed by the tool itself: without root the recursive interior of a
  content-tier directory may not be fully readable, so unprivileged
  status gives leaf checks only there; `sudo locked status` is the
  authoritative view.
- `sudo locked verify` -- re-check every locked node against its meta;
  exit 5 on drift. A launchd timer (installed by setup) runs this every
  15 minutes and records each result in `/var/db/locked/<user>/verify`
  (see [State layout](#state-layout)), where `locked status` and any
  other reader find it without `sudo`.
- `sudo locked setup` -- one-shot install + provision (see below).

Tests: `sudo /bin/bash tests/harness.bash` (scratch-dir only; stands in
`daemon` for the lock account, no global state touched).

### Proposed edits from a tool

A tool — Claude, a script, anything you would rather not hand the sealed
file to — writes the whole proposed file somewhere you own, say
`.tmp/settings.proposed.json`, and gives you one line to run:

```sh
sudo locked edit --from .tmp/settings.proposed.json ~/.config/agents/claude/settings/settings.json
```

locked copies the proposal into lock-account staging before it draws
anything on your screen, and the diff, the confirm and the install all
read that frozen copy. Whatever happens to the file under `.tmp` after
you have looked at the diff — a rewrite by the same tool, or by anything
else running as you — cannot change what installs.

## Nix install (nix-darwin module)

The flake exports `darwinModules.default` (Darwin-only on purpose: the
whole mechanism is BSD file flags). It declares everything `setup` does
imperatively -- binary in the system profile, hidden lock account and
group, verify LaunchDaemon -- and generates `/etc/sudoers.d/locked` at
build time from the same string the installed script is built from, so
the sudoers sha256 digest can never drift from the deployed bytes; a
rebuild moves both atomically with the generation. The module also
compiles the window helper (`helper/locked-helper.m`) and bakes its store
path into the script, so the digest transitively commits to which helper
binary runs; nothing extra to configure.

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
- Adds you to the lock group, which is what lets `locked status` read your pool without sudo.
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

Build and install the window helper alongside (needs the Xcode command
line tools; the mediated verbs and every snapshot copy go through it,
and `locked` verifies its ownership and ancestry on each use):
```sh
clang -O2 -Wall -Wextra -framework Foundation \
  -o /tmp/locked-helper helper/locked-helper.m
sudo install -m 755 -o root -g wheel /tmp/locked-helper /usr/local/sbin/locked-helper
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
baseline snapshot, and provisions the ancestor chain from the leaf's
grandparent up -- the leaf's own parent is deliberately left alone unless
it is the anchor, see below. It shows you the plan for the whole chain and
asks once, before it has touched anything.

A symlink is adopted as the link node itself: the link is what a process
running as you could re-point, so that is what gets sealed. Its target is
a separate node -- name it too if it should be sealed as well.

## The pool is what you protect

You name the files and directories to protect; every sealed directory
above them is derived, and released again once nothing needs it.

`lock ~/.claude/settings.json` seals the file and walks the chain from `~`
upward -- `~/.claude` itself is left exactly as it was: your ownership,
your group, your mode, no flag.

That is not a gap. A node is held in place by one of two things: its own
flag, or an append-only parent. The file holds itself (`uchg`). `~/.claude`
is held by `~`'s `sappnd`, which is what an anchor or placement seal on a
directory does for every entry in it. A seal on `~/.claude` would have
protected only the entries *inside* it that nothing else was protecting --
and it broke the software that owns the directory. Claude Code takes its
OAuth refresh lock with `mkdir ~/.claude/.oauth_refresh.lock` and releases
it with `rmdir`; `uappnd` refuses the `rmdir`, so the stale lock could
never be cleared and every token refresh failed. Temp+rename saves in the
same directory stranded a temp file each time.

**The anchor is exempt.** `~` and `~/.ssh` stay in the chain wherever they
sit, including as a leaf's own parent -- which every shell startup file
(`~/.zshrc`, `~/.bashrc`, ...) makes them. An anchor never changes
ownership, so it costs you nothing, and its `sappnd` is exactly what holds
`~/.claude` and `~/.config` in place.

What follows, all of it visible in the plan before the one question:

- A directory that is one file's parent can be another file's
  grandparent-or-higher. There it does real work, so it stays sealed.
- A sealed directory nothing needs any more -- its file was unprotected,
  removed, or moved elsewhere -- is released: flag off, owner, group and
  mode back to what they were, record retired. The plan row says why:
  `release  ~/.claude  (not needed: /Users/you keeps it in place)` or
  `(no protected file needs it)`. `lock`, `unprotect`, `rm` and the lock
  plan `mv` runs for a moved file all do this; `status` names any that are
  waiting.
- If any record in the pool cannot be read for this (written before
  0.13.0, say) or a file's chain cannot be worked out, nothing is released
  that run and a note says why.

The cost, stated: a non-root mount needs a user-owned mountpoint, so a
user-owned leaf parent can be shadowed by a mount. `~` can already be, for
the same reason -- the anchor tier never re-owns it -- so that class is a
mount-table question, not a tier question.

### What that does to a real pool

| Node | Sealed? | Why |
|---|---|---|
| `~` | anchor | every chain below it runs through it |
| `~/.zshrc` and the other startup files | content | you protect them |
| `~/.claude` | no | only `~/.claude/settings.json`'s parent |
| `~/.claude/settings.json` (a symlink) | content | you protect it |
| `~/.config`, `~/.config/agents`, `~/.config/agents/claude` | placement | the chain of `~/.config/agents/claude/settings/settings.json` |
| `~/.config/agents/claude/settings` | no | only that file's parent |
| `~/.config/ghostty` | content dir | you protect it |
| `~/Library` | placement | the chain of `~/Library/Application Support/com.mitchellh.ghostty` |
| `~/Library/Application Support` | no | only that directory's parent |
| `~/Library/LaunchAgents` | content dir | you protect it |

## State layout
```
/var/db/locked/                        mode 711  root:wheel
├── run.lock                           mode 600  root:wheel
└── jooize/                            mode 750  root:_jooize-lock
    ├── pool/                          mode 750  _jooize-lock:_jooize-lock
    │   ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.snap   mode 600
    │   ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.attic  mode 600
    │   └── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.meta   mode 640
    └── verify                         mode 640  root:_jooize-lock
```
The root dir is execute-only (711): you can reach the one dir whose name
you already know, but the user list is not enumerable. Your own dir and
pool are group-readable (750) by `_jooize-lock`, which you are a member
of, so `locked status` works without `sudo`; another user's belong to a
different lock group and the kernel refuses them. In the pool only `.meta`
follows -- it records identity and lock state, not content -- while
`.snap`, `.attic` and `.staging` keep their 600/700 shapes. Every root
invocation re-applies these modes.

`verify` is the result of the last verify run, one `key=value` per line:
`at` (UTC start time), `interval` (the timer's period in seconds; a result
older than three intervals is stale), `records`, `drifted` (the count),
then one `drift=<path>` line per drifted path, at most 20. Every byte of a
path outside printable ASCII, and the backslash, is written as `\xHH`, so
each line is printable ASCII and no file name can add a line of its own.
The file is replaced whole by a rename in a dir only root can write: a
reader always gets one run's complete answer, and nothing running as you
can change or remove it.

`run.lock` makes root runs take turns. Every root invocation (a
ceremony, the timer's verify, one you start) holds it until it exits, and
a run that finds it held prints whose it is and waits. So verify never
reads a ceremony halfway, two ceremonies never plan against one pool at
once, and runs finish in the order they started. The kernel drops the lock
when its holder exits, however it exits. A ceremony left open at its
editor or its `[y/N]` gate holds the lock too, so the timer's verify waits
for it; past three intervals the status reads as stale.

Up to 0.14.0 each pool sat at `/var/db/locked-snapshots/<user>`. The first
root invocation of 0.15.0 moves every pool into `<user>/pool` by rename and
removes the emptied old root; it refuses to merge a pool found at both.

- `.snap` -- pre-edit baseline, overwritten on each unlock (`.snapdir` for
  content-tier directories).
- `.attic` -- discarded post-edit content, overwritten on each revert.
- `.meta` -- captured identity plus lock state, one `key=value` per line:
  `owner`, `group`, `mode` (restore targets), `lockmode` (expected mode
  while locked), `tier`, `flag`, `flagsym` (exact post-seal flag word),
  `id` (volume uuid plus inode; records written before 0.6.0 carry
  `dev.ino` and are rewritten in place on the next root `status`, `lock`
  or `unlock`), `recursive`, `role` (`leaf` for a node you protect,
  `chain` for a directory sealed because one needs it), `state`
  (`locked`/`unlocked`/`retired`/`suspended`). `verify` compares reality
  against this. Retired and suspended records carry provenance -- `via`
  (`rm`, `trash-finalized`, `assertion` for a human tombstone, `unprotect`,
  or `unneeded` for a chain directory nothing needed any more), `by`,
  `at`, and for a suspension
  `bin`, the trash destination: `verify` flags the original path
  reappearing (a Put Back of a formerly sealed node) and finalizes the
  suspension to a retirement once the bin entry is gone.

## Mode and ownership preservation

The `owner`/`group`/`mode` restore targets are captured on the first `lock` of a node and carried unchanged through every later meta rewrite (v2 rewrites the file on each state transition to track flags and state, but the captured identity persists). What is done with them depends on the tier.

**content.** `unlock`, `lock` and `revert` chown and chmod the node back to the recorded values. So:
- Accidental `chmod 666 ~/.ssh/authorized_keys` while unlocked -- next lock restores the captured mode.
- An attacker that gets a single chmod through (somehow) is undone the next cycle.
- To intentionally change the captured mode/owner, edit `.meta` directly: `sudo -u _jooize-lock vi /var/db/locked/jooize/pool/<encoded>.meta`. (Or `unprotect` it and `lock` it again: a fresh seal recaptures them.)

**placement.** `unlock` clears `uappnd` and nothing else. The directory stays lock-account owned, with its ACL entry, for the whole window, on purpose: the owner has to be the lock account because `uappnd` is a user flag its owner could clear, and the entry is the one way you still reach into it. The entry only adds, so even with the flag off you cannot rename or remove what is in the directory -- `locked rm` and `locked mv` do that, as root. The recorded `owner`/`group`/`mode` are the pre-adoption identity, not a restore target for an unlock. The next `lock` of a file whose chain runs through it re-applies the flag, and refuses if the entry is gone. The one place that identity *is* restored is a release: once no protected file needs the directory it leaves the pool, so it goes all the way back -- flag off, the seal's entry off, owner, group and mode as they were.

**anchor.** Ownership never changes, in either direction -- that is the tier's whole point. Only the system flag goes on and off.

## How you get into a placement directory

A placement seal gives the directory to the lock account, because `uappnd` is a *user* flag and its owner can clear it -- leaving the directory yours would hand any process running as you the ability to unseal it. That leaves you outside a directory someone else owns, so the seal adds one ACL entry that lets you back in:

```
user:jooize allow list,add_file,search,add_subdirectory,readattr,readextattr,readsecurity
```

The rights are what the directory's owner bits gave you before the seal, minus anything that removes or renames an entry (`delete`, `delete_child`) or changes the directory itself (`writeattr`, `writeextattr`, `writesecurity`, `chown`). Only the owner or root can change an ACL, so you cannot strip or widen the entry, and it carries no inherit flags. The directory's group and mode stay what they were, and so do any ACL entries it already had: `~/Library` ships with Apple's `group:everyone deny delete`. The record keeps the entry, `verify` checks that it is there exactly, and a release takes off that entry and no other. `ls -le <dir>` shows it.

**What you create there is ordinary.** On macOS, as on every BSD, a new file or directory takes its group from the directory it is created in, and the directory's group is still yours (usually `staff`). Nothing inherits the entry.

**Why not a group.** Before 0.14.0 the way in was the lock group: the directory went to `_<user>-lock:_<user>-lock` with group `rwx`. By that same inheritance, everything created under a seal took the lock group, and so did everything created under that. On one Mac's `~/Library/Application Support`, the 88 entries from before the seal were `staff` and every entry after it `_jooize-lock`. A sweep reset them, and they came back. The ACL entry ends that by construction. What it costs: `ls -l` shows a `+` on the directory, and a tool that copies the directory together with its ACL copies the entry too.

**Two things that follow.** `locked trash` of an entry directly inside a placement directory is refused, because the trash service moves the entry as you and the entry does not let you remove anything; `locked rm` works, and so does `locked mv` to somewhere you can trash from. And `test -w` on the directory still says yes, so apps that check before writing see no difference.

A directory that already carries an ACL entry naming you is refused as a placement candidate: `chmod +a` would merge the seal's entry into yours, and no release could then tell them apart. Remove or reshape your entry first.

`locked` is Darwin-only; the ACL syntax above is macOS's.

## Caveats

This section collects the sharp edges of the how-to; what each verb does
and does not guarantee is written out in
[DESIGN-v2.md](DESIGN-v2.md#guarantees-and-limits-by-verb).

- A caller without a tty -- an editor's or an agent's embedded shell, a
  script -- cannot answer the confirm gate: `locked` refuses unless
  `--yes` is given, and `--yes` skips the gate, so the diff is approved
  unseen. Run `locked` from a real terminal when you want the gate.
- First lock assumes file is currently owned by you. To bring a file owned by someone else into the pool: `sudo chown -h <you>:staff <file>` first, then `sudo locked lock <file>` captures meta and locks. Or hand-write the meta file before unlocking once.
- Other admins on the same machine can read snapshots via `sudo` (root reads all). Only encryption fixes that; not in scope here.
- Records written before 0.6.0 identify their node by `dev.ino`. They still match (the inode is what proves the node), and the next root `status`, `lock` or `unlock` rewrites the field to the volume-uuid form with an `info` line. An unprivileged `status` says so and names the command that does it.
- `readlink -f` requires macOS 12+. On older macOS, replace with `realpath` or a Python one-liner.
- **Extended attributes and ACLs travel on file snapshots; directory trees still lose them.** File staging copies go through the helper with `COPYFILE_XATTR|COPYFILE_ACL`, so quarantine and custom-ACL metadata survive a snapshot/revert cycle. Content-tier *directories* (`.snapdir`) still copy with `cp -Rp`, which keeps the old limitation per file inside the tree -- search for `TODO(xattrs)` at `snapshot_tree`. BSD flags never travel by design (meta records the exact word; sealing re-applies it).
- **`locked trash` is gated by macOS privacy (TCC) through the app that invoked it.** The trash service checks the responsible app's Files-and-Folders grant even under `sudo`; from an unblessed automation context it fails cleanly (afpAccessDenied) with the window restored, from your own granted terminal it works. Nothing to configure in `locked` -- grant the terminal, or use `rm`.
- Default install path is `/usr/local/sbin/locked`. **Why not `/usr/libexec/`** (the natural spot for system helpers): `/usr/libexec` is on the sealed system volume since macOS 11; even root can't write there without booting to recovery and tearing down SSV. **Why not `/usr/local/bin/`**: same writable space but with the legacy Intel-Homebrew "chown -R \$USER /usr/local" footgun more common there. **Why `/usr/local/sbin/`**: less commonly tampered, semantically right for "needs sudo" admin tools, and in PATH by default.
- Setup verifies the entire ancestry up to `/` is root-owned with no group/other write -- mode `755` or stricter -- and refuses to install otherwise. The same verification runs on **every** subsequent invocation -- if `/usr/local` ever gets chowned to a user after setup (e.g., a later Homebrew permission-fix recipe), the next `sudo locked ...` refuses with a clear error. This closes the "post-setup escalation" wedge: a swapped binary at a writable ancestor would otherwise inherit root after the next Touch ID approval.
- Override default install path via `INSTALL_TARGET=/path sudo -E ./locked setup`. If you go this route, you'll need to re-run setup any time you want to change the path -- the sudoers entry references the path, not a binary identity.

## Atomicity and TOCTOU

Snapshot/attic/restore writes go through `atomic_replace`:
1. The helper copies the source into `/var/db/locked/<user>/pool/.staging/replace.XXXXXX` (lock-account-owned, mode 700 -- invisible to user UID) from a file descriptor it opened `O_NOFOLLOW` and identity-checked against the volume uuid and inode `locked` expected -- a source swapped between resolution and open is refused, not copied.
2. `chown` and `chmod` the staged temp file.
3. Verify staging and destination are on the same filesystem (`stat -f '%d'`).
4. `mv -f` -- atomic same-filesystem rename.

This eliminates partial-write windows on the destination side, closes the old source-side swap (`TODO(toctou)`, now retired for files), and keeps the temp file out of user-visible space throughout. The destination's parent is covered by the chain itself: every user-writable ancestor of a locked leaf is sealed, and the mediated window holds parents by fd, which is what retired `TODO(parent-swap)`.

**Honest residuals:**
- Directory-tree snapshots (`snapshot_tree`) still copy by path with `cp -Rp`; the per-file guarantees above do not apply inside a content-tier directory.
- Inside a mediated window there is a nanosecond gap between the helper's identity check of the named entry and the syscall on its name (macOS has no unlink-by-fd). The cross-window entry diff catches every shape that leaves the parent changed; a race that wins that gap *and* has somewhere unsealed to hide the original is the remaining theoretical escape.

## Audit log

Every action emits a unified-logging entry tagged `locked`. View recent activity:
```sh
log show --predicate 'eventMessage CONTAINS "locked: user="' --last 1h
```
Useful for spotting unexpected lock/unlock cycles. The log records `user=`, `action=`, `file=`, and `result=` (ok / skip-* / error) for each per-file operation.

## Removing a file from the lock pool

To delete the file itself, use the mediated verb -- it does the removal
through the window and retires the record in one step:
```sh
sudo locked rm <file>        # or: sudo locked trash <file>
```
To keep the file but stop protecting it:
```sh
sudo locked unprotect <file>
```
It goes back to the owner, group and mode it had before the first lock,
its record is retired, and directories nothing else needs are released
with it.
If something else already deleted the file and `verify` is flagging it:
`sudo locked tombstone <file>` records it as gone, with you as the
asserter.
