# locked

Per-user file protection for macOS: system-flag chains. A locked node
can't be written, renamed, or deleted, even by a process with write
permission on its parent, and no process running as you can clear the
flag: `schg` and `sappnd` are system flags, which only root sets or
clears. Nothing changes owner, group or mode, so every check the OS makes
against your account (sshd's owner checks on `~` and `~/.ssh`, say) keeps
passing. Design: [DESIGN-v2.md](DESIGN-v2.md).
Every privileged action runs via `sudo`; whatever auth you've set up
(password, `pam_tid` for Touch ID, [`sudowhat`](https://github.com/jooize/sudowhat)
for trusted prompts) gates each operation. `locked` does not touch sudo's
auth chain.

One sealing method, by what the node is:

- a file you name -- `schg`, sealed as a copy root made (see
  [Initial setup of a file](#initial-setup-of-a-file)). `--flag sappnd`
  makes it append-only instead (an SSH `known_hosts` file, say).
- a folder you name -- `schg` on the folder and every node in it, every
  file in it sealed as a copy. Edit cycle: `locked edit`, or unlock, edit,
  lock.
- a symlink you name -- `schg` on the link itself.
- `~` or `~/.ssh` named on its own -- `sappnd` (or `--flag schg`) on that
  folder alone.
- a chain folder -- `sappnd` on each folder *above* a locked node's own
  parent (`~/.config`, `~/Library`, ...), derived from the nodes you
  protect and never named: new entries fine, replacing or removing
  existing ones denied. `~` and `~/.ssh` are always in the chain.

## Workflow
- `sudo locked lock <path>` -- protect a file, directory or symlink, or
  relock one. You name what to protect; locked derives the rest: the
  ancestor chain from the leaf's *grandparent* up, stopping at a
  root-owned node, and any sealed directory no protected file needs any
  more, which it releases. The leaf's own parent is not sealed unless it
  is `~` or `~/.ssh` -- see [The pool is what you
  protect](#the-pool-is-what-you-protect). Nothing is touched until the
  whole ceremony is derived: the snapshot diff, then the plan -- one line
  per node, root-most first -- then one question for all of it (`--yes`
  for scripted runs, `--dry-run` prints the plan and stops). Naming a
  symlink seals the link itself, not what it points at; the plan says so
  when the target is yours and not protected, with the command that
  protects it.
- `sudo locked unprotect <path>` -- stop protecting it for good: flag
  off, the record retired, and every directory no other protected file
  needs released in the same plan and under the same question.
- `sudo locked edit <file>` -- sudoedit-style edit, the preferred flow:
  your editor runs as you on a user-owned temp copy, the candidate is
  staged out of reach, then diff + confirm installs and reseals. The
  file is never left unlocked and no chain release is needed. With
  `--from <copy>` the proposed content comes from a file you prepared
  instead of from an editor -- see below. Inside a folder locked as a
  whole, `edit` changes a file, or creates a new one, under the folder's
  own record, so the folder is never unlocked either. Naming a symlink
  edits the file it points at, as an editor would; the diff and the
  question show both the file and the link. After installing,
  `edit` checks the file against what you approved: the same bytes, the
  owner, mode and flag it set, and its folder's flags as they were. A
  mismatch can only come from root or a bug. It fails the edit, and it
  stays on the record as drift for `verify` and `status` until you edit
  that file again or seal the record afresh.
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
  path. With no path, lists every node in your pool (role, flag, and any
  drift) so you can see at a glance what is currently locked; reporting
  only, so it exits 0 even on drift. It needs no `sudo`: it is read-only,
  and it shows your own pool only -- another user's pool is unreadable to
  you. Without root it checks every node live except its content (the
  fingerprints are root's alone) and gives a folder sealed whole leaf
  checks only; it prints a note saying so. `sudo locked status` is the
  authoritative view.
- `sudo locked verify` -- re-check every locked node against its record:
  owner, group, mode, the exact flag word, identity, the volume its path
  resolves into, and the content of every sealed file against the
  fingerprint taken when it was sealed. Exit 5 on drift. It reports and
  exits; nothing runs it on a schedule and it keeps no result.
- `sudo locked setup` -- one-shot install (see below).

Tests: `sudo /bin/bash tests/harness.bash` (scratch-dir only; the
`daemon` account stands in for another user and for the old lock account
in the conversion section, no global state touched). Its sections run at
the same time, each in a scratch dir of its own; `--serial` runs them one
at a time, and section numbers run only those. The verbs run a copy of the
script whose git line names `--git PATH`, else the script's own git, else
the one git in `/nix/store`, and run it by its path, so every case starts
under its own `#!/bin/bash -p` as an install does. Its stdout is a TAP 14
stream, so `prove -v --exec 'sudo /bin/bash' tests/harness.bash` (TAP::Harness
3.50 or later) can check it. `bash tests/helper-gates.bash` runs the
helper's own cases without root.

### Proposed edits from a tool

A tool — Claude, a script, anything you would rather not hand the sealed
file to — writes the whole proposed file somewhere you own, say
`.tmp/settings.proposed.json`, and gives you one line to run:

```sh
sudo locked edit --from .tmp/settings.proposed.json ~/.config/agents/claude/settings/settings.json
```

locked copies the proposal into root's staging before it draws anything
on your screen, and the diff, the confirm and the install all read that
frozen copy. Whatever happens to the file under `.tmp` after you have
looked at the diff — a rewrite by the same tool, or by anything else
running as you — cannot change what installs.

## Nix install (nix-darwin module)

The flake exports `darwinModules.default` (Darwin-only on purpose: the
whole mechanism is BSD file flags). It declares everything `setup` does
imperatively -- the binary in the system profile and the sudoers entry --
and generates `/etc/sudoers.d/locked` at build time from the same string
the installed script is built from, so the sudoers sha256 digest can
never drift from the deployed bytes; a rebuild moves both atomically with
the generation. The module also compiles the window helper
(`helper/locked-helper.m`) and bakes its store path into the script, so
the digest transitively commits to which helper binary runs; nothing
extra to configure.

```nix
# flake input (no inputs of its own), then:
imports = [ inputs.locked.darwinModules.default ];
security.locked = {
  enable = true;
  user = "jooize";
};
```

No account, group or timer is declared: every sealed node stays yours,
and `verify` runs when you run it.

A nix-managed install refuses `setup` (the module owns provisioning) and
accepts `/nix/store` in the install-ancestry walk -- keyed to that
literal path, so `/usr/local`-shaped paths get no relaxation.

## One-shot install: `sudo ./locked setup`

From this folder, after cloning/copying:
```sh
sudo ./locked setup
```
Idempotent. Does the steps in section "Prerequisites" below in one go:
- Self-installs the script to `/usr/local/sbin/locked` (root:wheel, mode 755), refusing if any ancestor up to `/` is user-writable.
- Writes `/etc/sudoers.d/locked` with the matching sudoers entry; validates via `visudo -c` before installing.

Re-running setup is safe: each step is gated on existence/presence checks.
The window helper is built and installed by hand (step 1 below).

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
If any ancestor is user-owned -- common on Intel Macs where Homebrew once `chown`ed `/usr/local` -- repair before continuing: `sudo chown root:wheel PATH && sudo chmod 755 PATH`.

Then install:
```sh
sudo install -d -m 755 -o root -g wheel /usr/local/sbin
sudo install -m 755 -o root -g wheel ./locked /usr/local/sbin/locked
```

Always run it by its path, as above and as the sudoers entry names it.
Its first line is `#!/bin/bash -p`: privileged mode keeps bash from
sourcing the file `BASH_ENV` names, taking options from `SHELLOPTS` and
importing exported shell functions before the script's first line runs,
with or without sudo (`status` and `why` run without it). `bash locked`
reads no first line, so it runs without that protection.

Build and install the window helper alongside (needs the Xcode command
line tools; every seal, every mediated verb and every snapshot copy go
through it, and `locked` verifies its ownership and ancestry on each use):
```sh
clang -O2 -Wall -Wextra -framework Foundation \
  -o /tmp/locked-helper helper/locked-helper.m
sudo install -m 755 -o root -g wheel /tmp/locked-helper /usr/local/sbin/locked-helper
```

Every diff `locked` shows (relock, edit) is drawn by the command line
tools' git, `/Library/Developer/CommandLineTools/usr/bin/git`, and
`locked` checks it is root-owned along its whole path before each use.
That path is fixed in the script, so no environment can name another
git; with no git there, a verb that would show a diff refuses. Not
`/usr/bin/git`: that is a shim which picks the git it runs from
`DEVELOPER_DIR` and xcode-select state. Install the tools with:
```sh
xcode-select --install
```

### 2. Sudoers entry (digest-pinned)

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

### Verify

```sh
sudo /usr/local/sbin/locked unlock /nonexistent   # should print 'skipped, cannot resolve: /nonexistent'
```
Touch ID/password prompt names `/usr/local/sbin/locked unlock /nonexistent`; binary runs and refuses the path. Nothing is logged: a path that cannot be resolved stops before any action does. A path that resolves but has no record logs `result=skip-no-meta` (`log show --predicate 'eventMessage CONTAINS "locked:"' --last 1m`).

## Initial setup of a file

`sudo locked lock <path>` adopts any file or dir you own -- no manual
chown. The first lock records owner, group and mode, takes a baseline
snapshot, and seals the ancestor chain from the leaf's grandparent up --
the leaf's own parent is deliberately left alone unless it is `~` or
`~/.ssh`, see below. It shows you the plan for the whole chain and asks
once, before it has touched anything.

A file is sealed as a copy, never as the inode it was. The kernel checks
write permission when a file is opened, not on each write, so a process
that opened the file for writing before the seal would keep writing after
it. So root copies the file into its own staging (data, extended
attributes, ACL, owner, group, mode, times), swaps the copy in by one
rename, and flags it: nothing of yours ever had the sealed inode open.
Then it lists every process holding the sealed file open for writing,
which can only be one that opened it in the instant between the swap and
the flag, and names each one. What follows from the copy:

- The file gets a new inode. Its other hard links keep the old one and
  are no longer the same file; the plan notes a file with more than one
  name.
- A Finder alias or bookmark that tracks the file by its file id may
  lose it.
- The fingerprint of each file is taken from the copy before the swap, so
  a write in that instant shows as content drift on the next `verify`.

A symlink is adopted as the link node itself: the link is what a process
running as you could re-point, so that is what gets sealed. Its target is
a separate node -- name it too if it should be sealed as well. Under
`~/.ssh` a link is sealed like anywhere else: ssh and sshd resolve the
path before they check owners, so they never judge the link.

## The pool is what you protect

You name the files and directories to protect; every sealed directory
above them is derived, and released again once nothing needs it.

`lock ~/.claude/settings.json` seals the file and walks the chain from `~`
upward -- `~/.claude` itself is left exactly as it was: no flag.

That is not a gap. A node is held in place by one of two things: its own
flag, or an append-only parent. The file holds itself (`schg`). `~/.claude`
is held by `~`'s `sappnd`, which is what a chain seal on a directory does
for every entry in it. A seal on `~/.claude` would have protected only the
entries *inside* it that nothing else was protecting -- and it broke the
software that owns the directory. Claude Code takes its OAuth refresh lock
with `mkdir ~/.claude/.oauth_refresh.lock` and releases it with `rmdir`;
an append-only folder refuses the `rmdir`, so the stale lock could never
be cleared and every token refresh failed. Temp+rename saves in the same
directory stranded a temp file each time.

**`~` and `~/.ssh` are exempt.** They stay in the chain wherever they
sit, including as a leaf's own parent -- which every shell startup file
(`~/.zshrc`, `~/.bashrc`, ...) makes them. Their `sappnd` is exactly what
holds `~/.claude` and `~/.config` in place.

What follows, all of it visible in the plan before the one question:

- A directory that is one file's parent can be another file's
  grandparent-or-higher. There it does real work, so it stays sealed.
- A sealed directory nothing needs any more -- its file was unprotected,
  removed, or moved elsewhere -- is released: flag off, record retired.
  The plan row says why, in a word before the path:
  `release  unused  ~/.config/old`, or `release  kept    ~/.claude` with a
  line under it, `its parent keeps it in place: /Users/you`. `lock`,
  `unprotect`, `rm` and the lock plan `mv` runs for a moved file all do
  this; `status` names any that are waiting.
- If any record in the pool cannot be read for this (written before
  0.13.0, say) or a file's chain cannot be worked out, nothing is released
  that run and a note says why.

The cost, stated: a disk image can be attached over any folder you own,
whatever its flag, so any folder in a chain, a leaf's parent and `~`
itself can be shadowed by a mount. No flag refuses that. `verify` and
`status` compare the mount point each sealed path resolves into with the
one recorded at the seal and name a volume mounted over it.

### What that does to a real pool

| Node | Sealed? | Why |
|---|---|---|
| `~` | chain, `sappnd` | every chain below it runs through it |
| `~/.zshrc` and the other startup files | leaf, `schg` | you protect them |
| `~/.claude` | no | only `~/.claude/settings.json`'s parent |
| `~/.claude/settings.json` (a symlink) | leaf, `schg` on the link | you protect it |
| `~/.config`, `~/.config/agents`, `~/.config/agents/claude` | chain, `sappnd` | the chain of `~/.config/agents/claude/settings/settings.json` |
| `~/.config/agents/claude/settings` | no | only that file's parent |
| `~/.config/ghostty` | leaf folder, `schg` throughout | you protect it |
| `~/Library` | chain, `sappnd` | the chain of `~/Library/Application Support/com.mitchellh.ghostty` |
| `~/Library/Application Support` | no | only that directory's parent |
| `~/Library/LaunchAgents` | leaf folder, `schg` throughout | you protect it |

## State layout
```
/var/db/locked/                        mode 711  root:wheel
├── run.lock                           mode 600  root:wheel
└── jooize/                            mode 700  root:wheel  + read entry for jooize
    └── pool/                          mode 700  root:wheel  + read entry for jooize
        ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.meta   mode 600  + read entry for jooize
        ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.sum    mode 600
        ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.snap   mode 600
        ├── %2FUsers%2Fjooize%2F.ssh%2Fauthorized_keys.attic  mode 600
        └── .staging/                  mode 700
```
Everything is root's. The root dir is execute-only (711): you can reach
the one dir whose name you already know, but the user list is not
enumerable. Your own dir, your pool and each record carry one ACL entry
that lets you, and only you, list and read them:

```
user:jooize allow list,search,readattr,readextattr,readsecurity    (the two folders)
user:jooize allow read,readattr,readextattr,readsecurity           (each .meta)
```

So `locked status` works without `sudo`, and another user's pool is
refused by the kernel. Only `.meta` gets the entry -- it records identity
and lock state, not content -- while `.sum`, `.snap`, `.attic` and
`.staging` stay root's alone. A record is written to a temp file, given
its entry, then renamed into place, so it is never readable by anyone
else and never unreadable to you. `ls -le` shows the entries.

`run.lock` makes root runs take turns. Every root invocation (a ceremony,
a verify, a `sudo locked status`) holds it until it exits, and a run that
finds it held prints whose it is and waits. So verify never reads a
ceremony halfway, two ceremonies never plan against one pool at once, and
runs finish in the order they started. The kernel drops the lock when its
holder exits, however it exits. A ceremony left open at its editor or its
`[y/N]` gate holds the lock too, so a verify started meanwhile waits for
it.

Up to 0.16 sealed nodes and the pool belonged to a lock account
(`_<user>-lock`). The first root run of 0.17.0 converts every pool, see
[Upgrading from 0.16](#upgrading-from-016).

- `.snap` -- pre-edit baseline, overwritten on each unlock (`.snapdir` for
  folders sealed whole).
- `.attic` -- discarded post-edit content, overwritten on each revert.
- `.sum` -- the sha256 of a sealed file, or of every file in a sealed
  folder, taken by the helper while it held the bytes (the copy before the
  swap, or the staged file an edit installs). `verify` compares the
  content with it, as root.
- `.meta` -- captured identity plus lock state, one `key=value` per line:
  `owner`, `group`, `mode` (the node's own, which a seal never changes, so
  `verify` expects exactly them), `flag` (`schg` or `sappnd`), `flagsym`
  (exact post-seal flag word), `id` (volume uuid plus inode; records
  written before 0.6.0 carry `dev.ino` and are rewritten in place on the
  next root `status`, `lock` or `unlock`), `mount` (the mount point the
  path resolved into at the seal), `recursive`, `role` (`leaf` for a node
  you protect, `chain` for a directory sealed because one needs it),
  `state` (`locked`/`unlocked`/`retired`/`suspended`), and one `mismatch`
  line per file whose edit failed its install check (when, what differed,
  which file). `verify` compares reality against this. Retired and
  suspended records carry provenance -- `via` (`rm`, `trash-finalized`,
  `assertion` for a human tombstone, `unprotect`, or `unneeded` for a
  chain directory nothing needed any more), `by`, `at`, and for a
  suspension `bin`, the trash destination: `verify` flags the original
  path reappearing (a Put Back of a formerly sealed node) and finalizes
  the suspension to a retirement once the bin entry is gone.

## Owner, group and mode

A seal changes a node's flag word and nothing else, and so does an
unlock. `verify` expects the recorded owner, group and mode exactly, so a
`chmod` that somehow got through shows as drift, and `lock` refuses to
relock a drifted node until you have looked. To change a node's mode on
purpose: `sudo locked unlock` it, `chmod` it, `sudo locked lock` it
again. A seal records the node as it then is.

## Chain folders

A chain folder stays yours and takes `sappnd`, so you can add an entry to
it but not remove or rename one, and the folder itself cannot move. What
you create there is ordinary: your group, your mode. `test -w` still says
yes, so apps that check before writing see no difference.

To remove or rename something in a chain folder, use `sudo locked rm`,
`trash` or `mv`. An app that saves by writing a temp file and renaming it
over the original leaves its temp beside the target on every save in a
chain folder, since the rename is refused -- see
[DESIGN-v2.md](DESIGN-v2.md#an-atomic-save-writer-in-a-chain-folder-strands-a-temp-per-save).

## Upgrading from 0.16

0.16 gave a sealed file or folder to a lock account (`_<user>-lock`, with
`uchg`), gave a chain folder to it with `uappnd` and one ACL entry for
you, and kept your ownership only for `~` and `~/.ssh`. The first root
run of 0.17.0 (any `sudo locked` verb but `setup`) converts every pool
before the verb runs, record by record, leaves first: each node goes back to its recorded
owner, group and mode, the old flag and the chain folder's ACL entry come
off, and it takes the new seal, a file or folder by copy-and-swap. `~`,
`~/.ssh` and the files under it keep their node and flag. The content is
fingerprinted before and after; a difference is recorded as a
mismatch, which `verify` reports. A record that cannot be converted is
left exactly as it was and tried again on the next root run.

When the conversion says the account owns nothing locked made, delete it
and its group by hand (nix-darwin never deletes ids <= 501):

```sh
sudo dscl . -delete /Users/_jooize-lock
sudo dscl . -delete /Groups/_jooize-lock
```

## Caveats

This section collects the sharp edges of the how-to; what each verb does
and does not guarantee is written out in
[DESIGN-v2.md](DESIGN-v2.md#guarantees-and-limits-by-verb).

- A caller without a tty -- an editor's or an agent's embedded shell, a
  script -- cannot answer the confirm gate: `locked` refuses unless
  `--yes` is given, and `--yes` skips the gate, so the diff is approved
  unseen. Run `locked` from a real terminal when you want the gate.
- A first lock takes only what you own: a file, or a folder whose every node is yours, and refuses anything else before the question. To bring a file owned by someone else into the pool: `sudo chown -h YOU:staff FILE` first, then `sudo locked lock FILE`.
- **What the pool keeps, and who reads it.** A snapshot is a full copy of
  a sealed file or folder as it was before its last unlock or edit, the
  attic a full copy of what the last revert discarded, the fingerprint a
  sha256 of each sealed file. All three are root's alone, and they stay
  after `unprotect`, `rm` or `trash` retires the record, until a later
  lock or revert of the same path replaces them or you remove them as
  root. So a
  secret you once sealed and then deleted is still in the pool. Any admin
  on the Mac reads all of it through `sudo`; only encryption fixes that,
  and it is not in scope. A process running as you reads only your
  records, which hold no content and no fingerprint, so it cannot confirm
  a guess at a deleted short secret.
- **Hard links become copies.** Sealing a file, or a folder, replaces each
  file with a copy, so a hard link elsewhere keeps the old inode and stops
  being the same file. The plan says so before the question.
- **A writer the scan cannot see.** After every seal and install the
  helper names every process holding the sealed file open for writing.
  Two cases are invisible to it: a writable shared memory mapping whose
  descriptor was closed within the instant between the swap and the flag,
  and a descriptor in flight in a Unix-socket message. Either one could
  write the sealed file afterwards; `sudo locked verify` catches any write
  by its fingerprint.
- **A mount hides by path.** A disk image attached over a sealed folder or
  any folder above one (`~` included) shows its own content to every
  reader that resolves by path, and detaching it leaves nothing behind.
  `verify` and `status` name such a mount while it is there; a mount
  attached and detached between two looks is missed.
- **iCloud Drive keeps no BSD flag**, `schg` included
  ([eclecticlight 2026-06-02](https://eclecticlight.co/2026/06/02/bsd-flags-are-incompatible-with-icloud-drive/)),
  so a sealed path inside iCloud Drive does not stay sealed there.
- **Time Machine** restoring a `schg` file: unverified. Expect to relock
  a restored file.
- You can still add a user flag (`hidden`, `uchg`, ...) to a sealed node,
  though not remove its system flag. `verify` compares the whole flag word,
  so it reports the addition as drift.
- Records written before 0.6.0 identify their node by `dev.ino`. They still match (the inode is what proves the node), and the next root `status`, `lock` or `unlock` rewrites the field to the volume-uuid form with an `info` line. An unprivileged `status` says so and names the command that does it.
- `readlink -f` requires macOS 12+. On older macOS, replace with `realpath` or a Python one-liner.
- **Extended attributes and ACLs travel on snapshots, except a folder's own.** Every file copy goes through the helper with `COPYFILE_XATTR|COPYFILE_ACL`, files inside a folder sealed whole (`.snapdir`, the helper's `copy-tree`) included, so quarantine and custom-ACL metadata survive a snapshot/revert cycle. The folders in a tree snapshot are created fresh and carry neither. BSD flags never travel by design (meta records the exact word; sealing re-applies it).
- **`locked trash` is gated by macOS privacy (TCC) through the app that invoked it.** The trash service checks the responsible app's Files-and-Folders grant even under `sudo`; from an unblessed automation context it fails cleanly (afpAccessDenied) with the window restored, from your own granted terminal it works. Nothing to configure in `locked` -- grant the terminal, or use `rm`.
- Default install path is `/usr/local/sbin/locked`. **Why not `/usr/libexec/`** (the natural spot for system helpers): `/usr/libexec` is on the sealed system volume since macOS 11; even root can't write there without booting to recovery and tearing down SSV. **Why not `/usr/local/bin/`**: same writable space but with the legacy Intel-Homebrew "chown -R \$USER /usr/local" footgun more common there. **Why `/usr/local/sbin/`**: less commonly tampered, semantically right for "needs sudo" admin tools, and in PATH by default.
- Setup verifies the entire ancestry up to `/` is root-owned with no group/other write -- mode `755` or stricter -- and refuses to install otherwise. The same verification runs on **every** subsequent invocation -- if `/usr/local` ever gets chowned to a user after setup (e.g., a later Homebrew permission-fix recipe), the next `sudo locked ...` refuses with a clear error. This closes the "post-setup escalation" wedge: a swapped binary at a writable ancestor would otherwise inherit root after the next Touch ID approval.
- Override default install path via `INSTALL_TARGET=/path sudo -E ./locked setup`. If you go this route, you'll need to re-run setup any time you want to change the path -- the sudoers entry references the path, not a binary identity.

## Atomicity and TOCTOU

Every file root puts in your space goes through the helper, inside its
window on the held parent folder:
1. The source is copied into `/var/db/locked/<user>/pool/.staging`
   (root's, mode 700, out of your reach) from a file descriptor opened
   `O_NOFOLLOW`, after walking to it from `/` with no symlink allowed on
   the way but one only root controls (a root-owned link in root-owned
   folders no one else may write, as `/var` is), and identity-checked
   against the volume uuid and inode `locked` expected -- a source
   swapped between resolution and open is refused, not copied. The copy
   takes the node's owner, group and mode while still in staging.
2. The helper holds the destination's parent by descriptor, lifts its
   flag if it has one, and puts the staged file in place with one rename
   (`RENAME_SWAP` with the node it replaces, which must be the inode the
   record names, or an exclusive rename for a new file). Staging and
   destination must be on one volume, or the rename refuses.
3. It sets the flag on the new file through the descriptor it holds,
   restores the parent's flag, and diffs the parent's entries across the
   window (exit 6 on any change it did not make).
4. It lists every process holding the new file open for writing (exit 8,
   naming each).

This eliminates partial-write windows on the destination side, closes the
source-side swap, and keeps the staged file out of user-visible space
throughout. The destination's parent is covered by the chain itself:
every user-writable ancestor of a locked leaf is sealed, and the window
holds parents by fd. Snapshots and the attic are written inside the pool
by a rename from the same staging.

**Owner gate.** Every change root makes to a node in your space (its
flag, or the file an edit installs), and every read of one, goes through
the helper. That includes the chain directories above a protected file:
the chain is sealed leaf first, so a process running as you could swap one
between the plan and the seal. The helper opens each node `O_NOFOLLOW`
from its held parent and checks it on that descriptor: a directory, a
regular file or a symlink, owned by you. So root never does more to a file
than you could do yourself. A hard link to a root-owned file, placed in a
folder you lock, is still root's, so it is refused wherever it was linked.
A set-user-id or set-group-id file is refused too, by policy. A folder is
sealed top-down, each directory frozen before its entries are read, so
nothing placed during the run escapes the check. A refusal rolls back
every flag the run set; a file already swapped stays the copy (the same
bytes, owner, mode, times and attributes, a new inode).

**Reading as you.** The owner gate is the helper checking one fact. So
the helper also reads as you wherever you own the path: it walks from `/`
and opens each node under your identity, and the kernel checks every
folder on the way and the file's own permission bits exactly as it would
for you. A file of yours inside a folder you cannot enter is refused, not
read by root. locked's own state (snapshots and staging under
`/var/db/locked`) holds nothing of yours, so root reads it as root. Only
the walk and the opens change identity; root does the copying itself.

**Count guard.** A lock or unlock tells the helper how many nodes it will act on: one for a single node, or the whole tree for a folder, counted with `find`. The helper first counts the nodes it would reach, read-only, and refuses before any change when the numbers differ. While it changes nodes, it stops at the first one past the count, before changing it, and rolls back. So a walk that strays below a node it was not asked about touches nothing there.

**Honest residuals:**
- Between the swap and the flag there is an instant in which the new file
  is yours and unflagged, and a process running as you could open it for
  writing. The writer scan names such a process, and the fingerprint
  taken before the swap makes anything it writes show as drift. The scan's
  two blind spots are in the Caveats above.
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
sudo locked rm FILE        # or: sudo locked trash FILE
```
To keep the file but stop protecting it:
```sh
sudo locked unprotect FILE
```
Its flag comes off, its record is retired, and directories nothing else
needs are released with it. Its snapshot and fingerprint stay in the pool
(see Caveats).
If something else already deleted the file and `verify` is flagging it:
`sudo locked tombstone FILE` records it as gone, with you as the
asserter.
