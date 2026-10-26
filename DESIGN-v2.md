# locked v2 design -- system-flag chains

One sealing method since 0.17.0: every node keeps its owner, group, mode
and ACL, and a system flag holds it. Grounded in two probe rounds: the
2026-08-05 round (all primitives verified live on macOS 26.5.1, SIP
enabled, securelevel 0; system-flag probe 18/18) and the 2026-10-26 round
(37 cases on user-owned nodes, macOS 27.0.1, SIP on, securelevel 0).
Threat model unchanged: a tool running as the user -- terminal-app scope,
no TCC-protected dirs -- tampering with files between "I read it" and "I
sign/deploy it".

## Why flags: ownership alone does not protect the *name*

v1 protects file *content* (EACCES on write), but anyone with write
permission on the parent directory can `mv` the locked file aside and drop
a replacement. BSD flags close exactly that: a flagged node cannot be
renamed or deleted even by a user with parent write permission. A *system*
flag (`schg`, `sappnd`) is set and cleared by root only, so it binds every
process running as the user, the node's own owner included.

## The seal

| Node | Flag | How |
|---|---|---|
| a file you name | `schg` (`--flag sappnd` allowed: a TOFU `known_hosts`) | copy-and-swap: root's copy is swapped in, then flagged |
| a folder you name | `schg` on every node, top-down | each directory flagged before its entries are read; every file swapped |
| a symlink you name | `schg` on the link | no swap: a link has no write handle |
| `~` or `~/.ssh` named on its own | `sappnd` (default) or `schg` | that folder alone, no walk |
| a chain folder, `~` and `~/.ssh` included | `sappnd` | the folder only |

Nothing changes owner, group or mode, anywhere. The owner gate asks for
the invoker on every node, so root never does more to a node than the
invoker could. Every check the OS makes against the user's account (sshd
StrictModes, the ssh client's config-ownership checks, any owner == user
test) keeps passing, for `~` and `~/.ssh` and every other node alike.

Probed facts the seal rests on (2026-10-26, probe-result.txt in the work
item):

- `schg` on a user-owned file binds the owner: no write, remove, rename,
  chmod, ACL or xattr change, touch, hard link, atomic save, flag clear.
  `schg` or `sappnd` on a user-owned folder binds the same way for its
  entries. Control: `uchg` on the user's own file is cleared by its owner.
- The owner can still *add* a user flag (`hidden`, `uchg`, ...) to a
  `schg` node, and cannot zero the word. Harmless; verify compares the
  whole flag word, so an addition is drift.
- A descriptor opened for writing before `schg` still writes after it: the
  kernel checks the flag at open, not per write. That is why a file is
  sealed as a copy (below).
- A disk image attaches over a user-owned folder whatever its flag
  (plain, `sappnd`, `schg`), and over a folder in use. No flag refuses a
  mount; verify names one (below).
- Root clears and sets both flags live at securelevel 0. Older sources
  say `schg` clears only in single-user mode; at securelevel 0 it does not.
- Root cannot chown, chmod or rename a `schg` file. So a seal cannot flag
  a root-owned copy first and hand it over afterwards.
- `RENAME_SWAP` from root-only staging into a user folder works and leaves
  the old inode at the staging name. It is refused while the target or the
  staged file has `schg`, or the folder has `sappnd`, so the helper lifts
  those inside its window. `fchflags` on the held descriptor works after
  the swap.
- Flags do NOT inherit: contents of existing children stay writable --
  which is why a named folder is sealed **recursively**.
- `sappnd` dir = create-allowed / replace-denied; `sappnd` file =
  append-only. `schg` = total freeze.
- `st_dev` is not a volume key: APFS assigns it at mount, in mount order.
  It changed across a reboot on 2026-09-09, and `/` and `~` share one this
  boot (firmlinks) while their volume UUIDs differ. Identity is volume UUID
  plus inode; `getattrlist` with `ATTR_VOL_UUID` answers with the
  containing volume for any path or descriptor, and devfs answers with
  nothing, which is why the `st_dev` spelling survives as a fallback.

### Copy-and-swap

A file is never sealed as the inode it was. The helper copies it into
root's staging (data, xattrs, ACL, owner, group, mode, atime, mtime,
birthtime, the `nodump` and `hidden` flags), then, inside a window on the
held parent, swaps the copy in with `renameatx_np(RENAME_SWAP)` and checks
that the swapped-out inode is the one it opened and that the original's
size and mtime did not move during the copy; otherwise it swaps back and
refuses. Then it flags the copy through its held descriptor. The staged
original is unlinked at the end, whatever the outcome. A refused seal does
not swap back files already done: each stays the copy, the same bytes and
attributes on a new inode.

The fingerprint (sha256) of each file is printed from the copy before the
swap, and `install` prints the same for the staged file it installs. So
the baseline is what the helper held, never a later read, and a write that
races the swap-to-flag instant shows as content drift at the next verify
instead of becoming the baseline.

**Writer scan.** After every seal and install the helper walks every
process (libproc: `proc_listallpids`, `PROC_PIDLISTFDS`,
`PROC_PIDFDVNODEPATHINFO`), matches the sealed file's volume and inode,
and reports any descriptor opened for writing: a `writer` line with pid
and program, exit 8 (done, but a writer holds the new file). Two blind
spots, by construction: a writable shared mapping whose descriptor was
closed within the instant, and a descriptor in flight in a Unix-socket
message. Mapping detection was dropped on purpose: region data cannot tell
a shared writable mapping from a written private one. The fingerprint
catches any write either one makes.

What the swap costs: a new inode. A hard link elsewhere keeps the old one,
and the plan says so before the question.

### Why not a lock account any more

Up to 0.16 a sealed file or folder belonged to a lock account
(`_<user>-lock`) with the user flag `uchg`, and a chain folder too, with
`uappnd` and one add-only ACL entry for the user (before 0.14.0, group
`rwx` for a lock group, which leaked the group onto everything created
underneath). A user flag binds only on a node the user does not own, so
the account was what made the flag hold. Only `~` and `~/.ssh` kept the
user's ownership, with a system flag, because the OS checks their owner.

The 2026-10-26 study found that system flags on user-owned nodes give the
same binding, so every node can be sealed the way `~` already was. What
that removed: the account and its group, the provisioning, the ACL entry
machinery, the three tiers, and every owner hand-off in the helper. What
it cost, and how each is met:

- **Held write descriptors.** Under the account a first seal had the same
  gap (a chown revokes no open descriptor); under one method every install
  (edit, revert) would too. Copy-and-swap plus the writer scan closes it
  for both.
- **Mount-over.** Any folder the user owns takes a disk image over it. The
  account had closed that for chain folders, never for `~`, which shadows
  everything below it anyway. So one method adds mount points but no new
  reach; verify's mount check names a mount on any sealed path.
- **The install window.** Under the account the folder an edit installed
  into was closed to the user while its flag was off. Now the folder is
  the user's while the helper's window is open, so the helper diffs its
  entries across the window, as `rm` and `mv` always did.

0.17.0 converts every 0.16 pool once, at the first root run (below).

## Chain-walking

You name what to protect; `locked lock <leaf>` derives and seals the
**entire chain** for it in one ceremony:

1. The leaf's kind follows the node: a file, a symlink, `~` or `~/.ssh`
   on its own, or any other folder, sealed whole. There is no tier option;
   `--flag` picks `schg` or `sappnd` for a file, `~` or `~/.ssh`.
2. **The leaf's own parent is not sealed; the chain begins at the
   grandparent.** `~` and `~/.ssh` are the exception and stay in the chain
   wherever they sit, `$HOME` as a leaf's own parent included.
3. Every ancestor from there up that the invoker owns gets `sappnd`.
4. Ancestors already in the pool (record exists) are verified, not
   re-sealed. The walk stops at the first node the invoker does not own;
   that node must be root-owned with no group/other write (`/Users` on
   stock macOS) or the lock is refused.
5. **Nothing is touched until the whole ceremony is derived.** Every
   refusal is raised in that pass; then the diff witness, then the plan --
   one line per node, root-most first (`seal schg`, `seal sappnd`,
   `relock`, `reflag (old → new)`, and the ones that need nothing shown as
   `already locked`), and any directory the pool no longer needs as a
   `release` row with its reason on the line below it -- and then one
   `[y/N]` for the lot, under a `path:` row naming the leaf and a line
   saying what a yes does (`This seals 2 nodes and releases 1
   directory.`). The question holds no value and is one verb and its noun
   (`seal this path as listed?`, or `apply the plan for this path?` when
   the leaf's chain is already whole). Declining changes nothing at all.
   `--yes` answers that gate, `--dry-run` prints the plan and stops before
   it. Each seal used to ask for itself, which meant declining an ancestor
   left the leaf sealed under a parent nobody had protected. The only
   question left after the gate is the alarm a node raises when its
   identity changed during an unlock window: an anomaly, not a step in the
   plan.

A chain directory is never named. `lock` refuses a path whose record is a
chain node: protecting it as a folder would freeze everything inside it,
which is a different seal altogether.

### Why the leaf's parent is left out

A node is held in place by one of exactly two things: its own flag -- XNU
refuses `unlink` and `rename` of a vnode carrying `IMMUTABLE` or `APPEND`
-- or an append-only parent, since entries of such a directory cannot be
removed or renamed. The leaf holds itself (`schg`). The leaf's parent is
held by the *grandparent's* `sappnd`. Every ancestor above that needs its
own flag for its own entry, and that same flag pins the entry below it. So
a seal on the leaf's parent added nothing at all to the leaf's
protection. For the same reason the chain it leaves is the smallest one
that holds the path: drop any node from the grandparent up and that level
can be renamed away.

It did break the software that owns that directory. Claude Code takes an
OAuth refresh lock with `mkdir ~/.claude/.oauth_refresh.lock` and releases
it with `rmdir`; under an append-only flag the `rmdir` is refused, so the
stale lock could never be cleared, token refresh failed, and the user was
logged out at every expiry (observed 2026-09-15, the lock dir dated
minutes after the seal). Every temp+rename save in that directory
stranded its temp for the same reason.

**`~` and `~/.ssh` are exempt.** They stay in the chain wherever they
sit, including as a leaf's own parent, which every shell startup file
(`~/.zshrc`, `~/.bashrc`, ...) makes them. Under this very rule their
`sappnd` is what holds the leaf parents one level down -- `~/.claude`,
`~/.config` -- in place. Skipping them would take the load-bearing node
out of every chain below it.

Known cost, accepted: a disk image can be attached over any folder its
user owns, flag or no flag, so a chain folder or the leaf's parent can be
shadowed by a mount, as `~` itself always could. verify names a mount
over a sealed path; no flag can refuse one.

## The pool is what you asked to protect

Every record carries a `role`. A **leaf** is a node you named with `lock`:
that is the intent. A **chain** node is a directory sealed only because
some leaf needs it. The chain nodes a pool needs are exactly the union of
the chains of its live leaves (locked, unlocked, or suspended in the trash,
since Put Back can return them to the path their chain pins), and a chain
record outside that union protects nothing.

So every gated verb plans releases alongside its own work: `lock`,
`unprotect`, `rm` (in its existing question, applied once the removal has
happened), and the lock plan `mv` runs for each leaf it moved. A release
clears the flag through the helper and retires the record with
`via=unneeded`; nothing else about the folder was ever changed. Each
release row carries its reason as a word in the plan's qualifier column,
before the path:

- `kept` when the directory still holds a protected file -- without it,
  the row reads as if that file needed it -- with a dim line under the
  row naming what keeps it in place (`its parent keeps it in place:
  <dir above>`);
- `unused` otherwise.

Seals stay with the verb's own leaves. A pool-wide re-seal would close the
window an `unlock --chain` deliberately left open for another leaf.

**Fails closed.** A release is never planned on incomplete knowledge: a
live record with no role, or a live leaf whose chain cannot be derived
(its parent is gone, say), empties the plan and a note says which one.

`unprotect <leaf>` is the permanent counterpart of `lock`. `unlock` is the
edit window and keeps the record, the snapshot and the chain; `unprotect`
ends the protection -- flag off, the record retired with `via=unprotect`
-- and releases the chain nodes nothing else needs, under one question
(`stop protecting this path?`, under a `path:` row naming the leaf and the
line `This also releases 2 directories.`). Protecting that path again
later is a first seal: a retired record is history, so the record is
taken from the live node and the snapshot is taken fresh.

`trash`, `tombstone` and `rekey` plan no releases. A trashed leaf still
counts until verify finalizes it, and the other two are record repairs.
The directories they leave unneeded are released by the next gated plan;
until then the pool listing names them.

The 0.12.0 -> 0.13.0 cut added the field; the live pool was converted once
by hand. verify reports a live record without a role as drift.

#### The deployed pool under the rule

| Node | Role | Why |
|---|---|---|
| `~` | chain | in every chain below it |
| `~/.zshrc` and the other startup files | leaf | named |
| `~/.claude` | none | leaf parent of `~/.claude/settings.json`, nothing else's ancestor |
| `~/.claude/settings.json` (symlink) | leaf | named |
| `~/.config` | chain | grandparent chain of `~/.config/agents/claude/settings/settings.json` |
| `~/.config/agents`, `~/.config/agents/claude` | chain | same chain |
| `~/.config/agents/claude/settings` | none | leaf parent only |
| `~/.config/ghostty` | leaf | named |
| `~/Library` | chain | grandparent of `~/Library/Application Support/com.mitchellh.ghostty` |
| `~/Library/Application Support` | none | leaf parent only |
| `~/Library/LaunchAgents`, `~/Library/Application Support/com.mitchellh.ghostty` | leaf | named |

A **symlink argument names the link, not its target.** The parent is
canonicalized and the link's own name is kept, so the link node itself is
what gets sealed (`schg`, set with `lchflags`), since every OS identity
check resolves the path and judges the target (a link under `~/.ssh`
too). The link node is precisely what a same-UID process can re-point,
which is what sealing the target left open. The target takes its own
record if you name it too. A dangling link is sealed the same way: its
target may arrive later, and whether the link is worth sealing meanwhile
is your call, not the tool's -- the witness above the plan notes that the
target is missing.

`locked status <leaf>` verifies the FULL chain: per level owner, group,
mode, exact flag word vs the record, volume-uuid/inode identity and mount
point. `locked unlock` releases only the named node (`--chain`
additionally drops the flags on the chain's ancestors, for edits that need
a rename into a frozen parent -- atomic-save editors); the next `lock`
re-walks and re-seals the chain in reverse.

## Guarantees and limits by verb

What each verb promises, and where the promise stops. Every verb that
changes a sealed file shows a diff first and asks before it proceeds
(pinned-style "the diff matches what I intended"); `--yes` answers the
prompt for non-interactive use and `--dry-run` performs nothing, printing
the plan for `lock` and every mutation elsewhere.

### `edit`: the candidate is frozen before you see it

The editor runs as the invoker on a copy in a user-owned temp dir, so any
process running as the invoker can read or rewrite that copy while the
editor is open. That is the same exposure `sudoedit` has, and the reason
the copy is never the thing that installs. When the editor exits (with
`--from`, right away) the bytes are read as the invoker and written into
root's staging. **Everything after that reads the frozen bytes**: the
no-change check, the diff, the confirm gate, the install. Nothing that
happens to the copy or the proposal after the diff is on screen can change
what gets installed.

The candidate carries content and nothing else, because it was read with
`cat`. Extended attributes and ACLs are re-applied onto it from the
sealed file (`xattrs-from`), never taken from the copy, so quarantine and
ACL metadata survive an edit and the copy cannot smuggle any in.

The install is the helper's `install` verb: the staged file, given the
sealed file's owner, group and mode while still in staging, is swapped in
for the sealed node (which must be the recorded inode) inside a window on
the held parent, flagged through its descriptor, and followed by the entry
diff and the writer scan. Then `edit` checks the result against what was
approved: the fingerprint taken in staging, owner, mode, flag, and the
folder's flags as before. A difference fails the edit and stays on the
record as a `mismatch` line, which verify and status report as drift until
an edit of that file installs cleanly or the record is sealed afresh.

### `unlock` and relock are detection, not prevention

Between `unlock` and the next `lock` the file is writable by the invoker
and readable exactly as before. The relock diff (snapshot -> current)
shows what changed during the window; it does not stop it, and any reader
in that window sees the unlocked content. `edit` is the preferred path
because it has no window. `unlock` exists for what `edit` cannot serve:
tools that must rename into the directory (atomic-save editors, via
`--chain`), and edits inside a folder sealed whole.

### Any folder you own can be mounted over (measured 2026-09-12 and 2026-10-26)

A user can attach a disk image over a directory
(`hdiutil attach -mountpoint <dir>`) wherever the user owns that
directory, whatever its flag, and over a folder in use. Every sealed
folder is the user's, so every one of them, and `~` above them all, can
be mounted over. A mount there shadows the tree by path: a reader
resolving by path sees the image's content, and detaching afterwards
leaves nothing the seal can show. This is a by-path substitution no flag
closes.

What locked does: each record keeps the mount point its path resolved
into at the seal (`f_mntonname` of the volume holding a folder, or a
file's or link's folder, from the helper's `mount` verb), and verify and
status compare it. A different volume over the path, or over any folder
above it, is drift, named with the mount point. The kernel's mount table
cannot be faked by a process running as the user. What it misses: a mount
attached and detached between two looks. A root daemon watching for
mounts (kqueue `EVFILT_FS`, `VQ_MOUNT`) is an idea, not a decision.

### An atomic-save writer in a chain folder strands a temp per save

A chain seal puts `sappnd` on the directory, which lets a writer create a
new file but not rename over an existing one. A temp+rename writer
therefore leaves its temp beside the target on every save, named
something like `<file>.tmp.<pid>.<hex>`. Measured on Claude Code's
`.claude.json`: roughly 250 KB of strand per save, with the writer's
in-place fallback keeping the state itself correct. The directory's
`sappnd` refuses the unlink too, so the user cannot remove them. Cleanup
is one command, and it takes a glob because `rm`, `trash`, `lock` and
`unlock` all accept many paths in one batch:

```sh
sudo locked rm DIR/NAME.tmp.*
```

There is no automatic janitor, by design: a verb that deletes files it
was never handed is not something `locked` does.

The leaf-parent rule removes the common case: a sealed file's own
directory is not sealed, so an atomic-save writer beside it renames
normally and strands nothing. What remains is a chain directory -- one
that is a higher ancestor of some protected file -- with an atomic-save
writer of its own inside it.

### What the diff witness shows, and what it cannot

The diff is git's (`git diff --no-index`), started so that nothing it
reads can choose what it does: an empty environment, no global or system
config, attributes from the empty tree, `--no-ext-diff --no-textconv`, no
renames, no pager, and run from `/`, so no repository's config or
`.gitattributes` is found. Trusted binary != trusted output, so no git
driver and no textconv sits anywhere in the display path. The git is a
constant in the script, never read from the environment: the nix module
writes in `pkgs.git`'s store path, and a hand install uses the command
line tools' own binary (`/Library/Developer/CommandLineTools/usr/bin/git`,
not the `/usr/bin/git` shim, which picks the git it runs from
`DEVELOPER_DIR` and xcode-select state). Every diff first checks that git
is root-owned and unwritable by anyone else along its whole path, as the
window helper is checked.

Not `/usr/bin/diff`: it splits a line at a lone carriage return, so a
changed line could show as an unchanged half above a changed half, and
its `-r` follows symbolic links, which showed, to root, the content of
whatever a link inside a folder pointed at. git shows a link as its link
text.

`locked` rewrites git's headers to its own labels (`snapshot: <path>`,
`current: <path>`, and the path below a folder for each file in it), and
takes the output only when git's exit status, the output itself and
git's silence on stderr agree. Anything else refuses with none of the
output shown. A name holding a line feed refuses too, since a header
cannot show it on one line. git's own color is disabled and `locked`
paints the `+`, `-` and `@@` lines itself, so the only escape sequences
reaching the terminal are locked's own.

The diff then goes through the same renderer every path on screen goes
through (the untrusted-text rules), before it is drawn. Every code point
on the hidden list shows as `\u{HEX}` (uppercase, no leading zeros), in
reverse red on a tty: the C0 and C1 controls, DEL, the no-break and
other invisible spaces, the zero-width marks, joiners included, the bidi
marks, embeddings, overrides and isolates, U+FEFF, the variation
selectors and the tag characters (the full list is in the comment above
`UNTRUSTED_PL`). A byte that is not valid UTF-8 shows as `\xHH`, one per
byte, after every valid sequence is decoded. A literal backslash that
would begin an escape is escaped itself, so an escape on screen is always
one. Those two kept escapes take the line's own color, not the reserved
style. Newline and tab are layout and pass raw. Line endings are judged
per file of the diff: when a carriage return precedes every real newline
of a file's content lines, that file gets one header line, `CRLF line
endings`, after its `+++` line and before its first hunk, and each pair
draws as one break; any other carriage return is escaped where it is.
What git says when it fails is shown with every carriage return escaped.

One residual: homoglyphs are not distinguishable. A Cyrillic "а" is
drawn the way a Latin "a" is.

### Callers without a tty

The confirm gate refuses when stdin is not a tty unless `--yes` is given,
and `--yes` skips the gate outright. A caller with no tty -- an editor's
embedded shell prompt, an agent's tool shell, a script -- therefore
either fails closed or approves blind; there is no third behaviour. A
diff is only a witness while a human is reading it, so the mutating verbs
belong in a real terminal.

## Detection layer: `locked verify` and `locked status`

Flags deny with silent EPERM -- the process that was refused sees the
failure, the user does not. `locked verify` re-checks every locked chain
and exits nonzero on drift; it also catches a ceremony that forgot to
relock. Per node it compares, against the record: owner, group and mode
(a seal never changes them, so they must match exactly), the whole flag
word (a user flag added on top of the system one is drift), volume-uuid
and inode identity, the mount point, and, for a sealed file or folder,
the content against the fingerprints taken when it was sealed. A folder
sealed whole also gets a stray scan: any node in it not owned by the
recorded owner or without the seal's flag.

verify runs when someone runs it. Nothing schedules it, and it keeps no
result: the seals hold whether or not anyone looks, as every other setup
on the machine is trusted to. (0.15 and 0.16 ran it from a root
LaunchDaemon every 15 minutes and kept the last result in a status file
for other tools; 0.17.0 dropped both.)

The fingerprints are root's alone, so only root compares content.
`locked status` without sudo checks every other field live, leaves the
content out, gives a folder sealed whole leaf checks only (the stray
scan sees nothing inside a folder whose modes deny the caller), and says
so in a note. `sudo locked status` is the authoritative view.

Root runs take turns on one lock (`/var/db/locked/run.lock`, flock(2),
root 600). Without it a verify could read a record or node halfway through
a ceremony and report drift that is not there, and two ceremonies could
plan against one pool at once (one releasing a chain node the other's new
leaf needs). The lock is held from the root convergence to exit, gates
and the editor included, because a plan made under the lock has to be the
one applied; an open ceremony therefore makes a verify wait.

What this does not cover: drift is seen only when someone looks, and a
mount attached and detached between looks is never seen.
EndpointSecurity/eslogger EPERM-monitoring is explicitly later.

## State

`/var/db/locked` is root:wheel 711. Each user's dir and its `pool/` are
root:wheel 700 with one ACL entry for that user,
`user:<inv> allow list,search,readattr,readextattr,readsecurity`; each
record is root 600 with `user:<inv> allow read,readattr,readextattr,
readsecurity`, put on the temp file before its rename. Fingerprints
(`.sum`), snapshots, the attic and staging are root's with no entry. So
the user reads their own records without sudo, another user's are refused
by the kernel, and nothing running as any user can write any of it.

The fingerprints sit beside the record, not in it, because a record is
readable by anything running as its user: a stored sha256 there would let
such a process confirm a guess at a short secret in a file long deleted.
No keyed hash is used; root-only placement is the whole defense.

### One-shot conversion from 0.16

The first root run of 0.17.0 converts every pool still in the 0.16 shape
(a record carrying `tier=`), under the run lock and before any verb runs.
The per-user dir and pool become root:wheel with their read entries, and
0.16's verify status file is removed. Then each record, leaves first and
chain folders deepest first, through the helper on the node's own
descriptor: content fingerprinted while still sealed, the old flag
(`uchg`, `uappnd`) cleared, the chain folder's ACL entry removed, owner,
group and mode set back to the recorded ones, the new seal applied (a file
or folder by copy-and-swap), content fingerprinted again and compared; a
difference becomes a `mismatch` line. A record of 0.16's anchor tier
(`~`, `~/.ssh` and the files under it) keeps its node and its flag; a file
there gains a fingerprint, not a new inode. An unlocked record, retired
history and a node that is gone change on disk not at all; only the
record is rewritten. The record is rewritten without
`tier`, `lockmode` and `acl`. A record that fails stays exactly as it was,
is named, and is tried again on the next root run; until then only the
conversion rewrites it, and verify reports it as drift.

When none is left, the lock account owns nothing locked made, and the
user deletes the account and its group by hand (nix-darwin never deletes
ids <= 501). TODO 0.18.0: remove the conversion, with the helper's
`--chown`, `--mode` and `--acl-remove` on unseal that only it uses.

## Kept from v1

- Digest-pinned sudoers (`sha256:` Digest_Spec): binary integrity is
  enforced by sudo before our code runs; a swapped binary gets a silent
  refusal, not a Touch ID prompt.
- Snapshot / diff / revert flow and the `.snap`/`.attic`/`.meta` layout;
  the record gains `flag`, the exact post-seal flag word, the
  volume-uuid/inode identity and the mount point, and `.sum` sits beside
  it.
- Root-sudo invocation model for every mutating action. A no-root
  multiuser path is not needed: a system flag needs root to set, and the
  owner gate bounds root to what the invoker could do. `status` and `why`
  alone run unprivileged (read-only; the pool's own permissions gate what
  each user sees).
- Every file root puts in the user's space is installed inside the
  helper's window on the held parent: staged in root-only staging with
  its final owner and mode, swapped or renamed in, flagged through its
  descriptor, the parent's flag restored, its entries diffed, writers
  scanned.

## Caveats

- **Atomic-save editors** replace the file with a new inode via rename;
  under a flagged parent the rename is denied. Unlock prints a hint when
  the parent chain would deny it; `unlock --chain` is the escape and
  `locked edit` avoids the window entirely. In-place writers (`tee`,
  `vim` with `backupcopy=yes`, `>>`) are unaffected.
- **The rename hole partially reopens during a `--chain` window**: a
  released ancestor can be swapped by anything with write on its parent
  (rename checks parent write only). Locked leaves keep their own flags
  throughout, and re-seal refuses to bless a swapped chain folder, `~` or
  `~/.ssh` without a human at a tty (`--yes` deliberately does not satisfy
  that prompt); `verify` checks the identity against the record. Keep
  windows short; prefer `locked edit`.
- **Parent-swap above `~` is out of scope by construction**: the chain
  terminates at a root-owned dir, so there is no user-writable ancestor
  left to swap. What remains is the standing floor: pinned ceremonies
  never trust the terminal; terminal hardening protects orientation.
- `sappnd` on `~` does not stop *creates*: absent exec-class dotfiles must
  be created empty and locked first (ceremony pre-work).
- Flags are invisible to `ls` without `-lO`; `locked status` is the
  intended lens.
- iCloud Drive keeps no BSD flag, `schg` included
  ([eclecticlight 2026-06-02](https://eclecticlight.co/2026/06/02/bsd-flags-are-incompatible-with-icloud-drive/)).
  Finder's "Locked" checkbox is `uchg`
  ([eclecticlight 2026-05-30](https://eclecticlight.co/2026/05/30/protect-files-with-the-locked-or-immutable-flag/));
  what Get Info shows for `schg` is not checked. How Time Machine restores
  a `schg` file: not found, unverified.

## chflags invocation gotcha (probed)

`chflags -- <flagword> <path>`, never `chflags <flagword> -- <path>`: BSD
getopt stops at the flag word, so a later `--` becomes a filename and
poisons the exit code while the flag still gets applied.
