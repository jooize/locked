# locked v2 design -- three-tier BSD-flag chains

Supersedes the 2026-07-22 two-tier draft. Grounded in the 2026-08-05 probe
round (all primitives verified live on macOS 26.5.1, SIP enabled,
securelevel 0; system-flag probe 18/18). Threat model unchanged: a tool
running as the user -- terminal-app scope, no TCC-protected dirs --
tampering with files between "I read it" and "I sign/deploy it".

## Why flags: ownership alone does not protect the *name*

v1 protects file *content* (EACCES on write), but anyone with write
permission on the parent directory can `mv` the locked file aside and drop
a replacement. BSD flags close exactly that: a flagged node cannot be
renamed or deleted even by a user with parent write permission, and
`chflags` is owner-or-root only (kernel EPERM, probed), so a flag on a
node the user does not own binds every user-UID process.

## The three tiers (named by what they protect)

| Tier | Flag | Ownership | For | Effect |
|---|---|---|---|---|
| `content` | `uchg` | `_<user>-lock` | leaf files; leaf dirs (recursive) | total freeze: content, rename, delete. Edit = unlock, edit, lock. |
| `placement` | `uappnd` | `_<user>-lock`; group and mode unchanged; one add-only ACL entry for the user | ancestor dirs *above* a leaf's own parent (`~/.config`, `~/Library`, ...), derived from the leaves and never named | new entries allowed; rename/delete/replace of existing entries denied; dir itself immovable. Unlock only for uninstall/replace ceremonies. |
| `anchor` | `sappnd` (default) or `schg` | **unchanged** (stays the user) | nodes the OS identity-checks against the user's UID: `~`, `~/.ssh` and its files | system flags are root-only to set AND clear, so the flag binds all user processes while the user stays owner -- sshd StrictModes and every owner==user check keep passing. |

Probed facts the tiers rest on:

- `uappnd` dir: mkdir/create/mv-INTO allowed (append); rename/delete of
  existing entries denied; the dir itself immovable; subdir interiors
  unaffected.
- `uchg` dir: total entry freeze + node immovable. Flags do NOT inherit:
  contents of existing user-owned children stay writable -- which is why
  `content` on a directory is **recursive** (every node in the tree gets
  `uchg` and lock-account ownership).
- `chflags` is owner-or-root only. `sappnd`/`schg` require root even to
  set; the owner cannot clear or zero the flag word.
- `sappnd` dir = create-allowed / replace-denied; `sappnd` file =
  append-only. `schg` = total freeze.
- ACLs were evaluated and rejected for the anchor problem: the owner can
  always rewrite their own node's ACL, so self-deny entries are advisory.
  Flags are primary.
- On a node the user does NOT own, an ACL entry is binding: only the owner
  or root may change an ACL. A placement dir's add-only entry (probed
  2026-09-15, 41/0): adds work, new entries take the dir's group and no
  ACL, grandchildren too; rename/delete/replace stay denied under the flag,
  and a delete entry the user puts on their own file does not beat it; the
  user cannot strip the entry, add delete_child, clear the flag or chmod.
  With the flag off the entry alone still refuses a rename (no
  delete_child), though a delete entry on the user's own file then does
  delete it -- the flag stays the guard. `test -w` says yes.
  `chmod +a` merges a new allow entry into an existing one for the same
  principal, and `-a` removes rights from it (fails when none match).
- `st_dev` is not a volume key: APFS assigns it at mount, in mount order.
  It changed across a reboot on 2026-09-09, and `/` and `~` share one this
  boot (firmlinks) while their volume UUIDs differ. Identity is volume UUID
  plus inode; `getattrlist` with `ATTR_VOL_UUID` answers with the
  containing volume for any path or descriptor, and devfs answers with
  nothing, which is why the `st_dev` spelling survives as a fallback.

## Placement access: an ACL entry, not a group

The owner has to be the lock account (`uappnd` is a user flag its owner can
clear), which leaves the user outside the directory. The way back in is one
ACL entry naming the user: the rights the owner bits gave them, minus
delete, delete_child and every write over the directory's own metadata, no
inherit flags. Group and mode are left alone, and so are ACL entries already
there (`~/Library` carries Apple's `group:everyone deny delete`). The record
keeps the entry; verify checks it and the group; a release takes off that
entry only. A candidate that already has an entry naming the user is
refused, since `chmod +a` would merge the two.

Before 0.14.0 the way in was group `rwx` for the lock group. A new entry
takes its parent directory's group on macOS, as on every BSD, so everything
created under a seal took the lock group, and everything under that; a
sweep reset the strays and they came back. The README section "How you get
into a placement directory" has the user-facing account. The 0.13.0 ->
0.14.0 cut converted the live placement directories once, with a script
kept outside the tool; a placement record without the entry is drift, and
no lock plan reseals it.

## Chain-walking

You name what to protect; `locked lock <leaf>` derives and provisions the
**entire chain** for it in one ceremony:

1. The leaf's tier follows its path: `anchor` for `~` itself and anything
   under `~/.ssh` (the OS identity-checks those, so their owner must never
   change), `content` for everything else. There is no tier option.
2. **The leaf's own parent is not provisioned; the chain begins at the
   grandparent.** The anchor is the exception and stays in the chain
   wherever it sits, `$HOME` as a leaf's own parent included.
3. Every ancestor from there up that the invoker owns gets `placement` --
   except `$HOME` and `~/.ssh`, which get `anchor` (`sappnd`; ownership
   must not change).
4. Ancestors already in the pool (meta exists) are verified, not
   re-provisioned. The walk stops at the first node owned by neither the
   invoker nor the lock account; that node must be root-owned with no
   group/other write (`/Users` on stock macOS) or the lock is refused.
5. **Nothing is touched until the whole ceremony is derived.** Every
   refusal is raised in that pass; then the diff witness, then the plan --
   one line per node, root-most first, the ones that need nothing shown as
   `already locked`, and any directory the pool no longer needs as a
   `release` row with its reason -- and then one `[y/N]` for the lot. The
   question names what it covers (`Seal <leaf> as listed (2 seals, 1
   release)?`, or `Apply the plan for <leaf> (1 release)?` when the leaf's
   chain is already whole). Declining changes nothing at all. `--yes`
   answers that gate, `--dry-run` prints the plan and stops before it. Each
   seal used to ask for itself, which meant declining an ancestor left the
   leaf sealed under a parent nobody had protected. The only question left
   after the gate is the alarm a node raises when its identity changed
   during an unlock window: an anomaly, not a step in the plan.

A chain directory is never named. `lock` refuses a path whose record is a
placement chain node: protecting it as content would freeze everything
inside it, which is a different seal altogether.

### Why the leaf's parent is left out

A node is held in place by one of exactly two things: its own flag -- XNU
refuses `unlink` and `rename` of a vnode carrying `IMMUTABLE` or `APPEND`
-- or an append-only parent, since entries of such a directory cannot be
removed or renamed. The leaf holds itself (`uchg`, or the anchor's system
flag). The leaf's parent is held by the *grandparent's* `uappnd`. Every
ancestor above that needs its own flag for its own entry, and that same
flag pins the entry below it. So a placement seal on the leaf's parent
added nothing at all to the leaf's protection. For the same reason the
chain it leaves is the smallest one that holds the path: drop any node
from the grandparent up and that level can be renamed away.

It did break the software that owns that directory. Claude Code takes an
OAuth refresh lock with `mkdir ~/.claude/.oauth_refresh.lock` and releases
it with `rmdir`; under `uappnd` the `rmdir` is refused, so the stale lock
could never be cleared, token refresh failed, and the user was logged out
at every expiry (observed 2026-09-15, the lock dir dated minutes after the
seal). Every temp+rename save in that directory stranded its temp for the
same reason.

**The anchor is exempt.** `~` and `~/.ssh` stay in the chain wherever they
sit, including as a leaf's own parent, which every shell startup file
(`~/.zshrc`, `~/.bashrc`, ...) makes them. An anchor never changes
ownership, so it costs its owner nothing; and under this very rule its
`sappnd` is what holds the leaf parents one level down -- `~/.claude`,
`~/.config` -- in place. Skipping it would take the load-bearing node out
of every chain below it.

Known cost, accepted: a non-root mount needs a user-owned mountpoint, so a
user-owned leaf parent can be shadowed by a mount. `$HOME` -- anchor tier,
never re-owned -- already can, so that whole class is closed by a
mount-table check and not by this tier.

## The pool is what you asked to protect

Every record carries a `role`. A **leaf** is a node you named with `lock`:
that is the intent. A **chain** node is a directory sealed only because
some leaf needs it. The chain nodes a pool needs are exactly the union of
the chains of its live leaves (locked, unlocked, or suspended in the trash,
since Put Back can return them to the path their chain pins), and a chain
record outside that union protects nothing.

So every gated verb plans releases alongside its own work: `lock`, the new
`unprotect`, `rm` (in its existing question, applied once the removal has
happened), and the lock plan `mv` runs for each leaf it moved. A release
clears the flag, takes off the seal's ACL entry, and restores owner, group
*and* mode from the record, then retires the record with `via=unneeded`.
That is deliberately unlike `unlock` of a placement node, which keeps
lock-account ownership and the entry because the seal is coming back.
An anchor chain node loses only its flag. Each release row carries its
reason:

- `not needed: <dir above> keeps it in place` when the directory still
  holds a protected file -- without it, the row reads as if that file
  needed it;
- `no protected file needs it` otherwise.

Seals stay with the verb's own leaves. A pool-wide re-seal would close the
window an `unlock --chain` deliberately left open for another leaf.

**Fails closed.** A release is never planned on incomplete knowledge: a
live record with no role, or a live leaf whose chain cannot be derived
(its parent is gone, say), empties the plan and a note says which one.

`unprotect <leaf>` is the permanent counterpart of `lock`. `unlock` is the
edit window and keeps the record, the snapshot and the chain; `unprotect`
ends the protection -- flag off, the pre-lock identity back, the record
retired with `via=unprotect` -- and releases the chain nodes nothing else
needs, under one question (`Stop protecting <leaf> and release 2
directories?`). Protecting that path again later is a first seal: a retired
record is history, so the identity comes from the live node and the
snapshot is taken fresh.

`trash`, `tombstone` and `rekey` plan no releases. A trashed leaf still
counts until verify finalizes it, and the other two are record repairs.
The directories they leave unneeded are released by the next gated plan;
until then the pool listing names them.

The 0.12.0 -> 0.13.0 cut added the field; the live pool was converted once
by hand (content -> leaf, placement -> chain, anchor directory -> chain,
anchor file -> leaf). verify reports a live record without a role as drift.

#### The deployed pool under the rule (2026-09-15)

| Node | Role | Why |
|---|---|---|
| `~` | chain (anchor) | in every chain below it |
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
what gets sealed -- content tier, the only tier that applies to a link,
since every OS identity check resolves the path and judges the target (a
link under `~/.ssh` is therefore refused). The link node is precisely what a
same-UID process can re-point, which is what sealing the target left open.
The target keeps its own ownership and takes its own record if you name it
too. A dangling link is sealed the same way: its target may arrive later,
and whether the link is worth sealing meanwhile is your call, not the
tool's -- the witness above the plan notes that the target is missing.

`locked status <leaf>` verifies the FULL chain: per level owner, group,
mode, exact flag word vs meta, and volume-uuid/inode identity. `locked unlock`
releases only the named node (`--chain` additionally drops the flags on
the chain's ancestors, for edits that need a rename into a frozen parent
-- atomic-save editors); the next `lock` re-walks and re-seals the chain
in reverse.

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
root-held staging. **Everything after that reads
the frozen bytes**: the no-change check, the diff, the confirm gate, the
install. Nothing that happens to the copy or the proposal after the diff
is on screen can change what gets installed.

The candidate carries content and nothing else, because it was read with
`cat`. Extended attributes and ACLs are re-applied onto it from the
sealed file (`xattrs-from`), never taken from the copy, so quarantine and
ACL metadata survive an edit and the copy cannot smuggle any in.

### `unlock` and relock are detection, not prevention

Between `unlock` and the next `lock` the file is writable by the invoker
and readable exactly as before. The relock diff (snapshot -> current)
shows what changed during the window; it does not stop it, and any reader
in that window sees the unlocked content. `edit` is the preferred path
because it has no window. `unlock` exists for what `edit` cannot serve:
tools that must rename into the directory (atomic-save editors, via
`--chain`), and edits inside a content-tier directory tree.

### The anchor node stays mountable-over (measured 2026-09-12)

A user can attach a disk image over a directory
(`hdiutil attach -mountpoint <dir>`) only where the user owns that
directory. A placement-tier directory is owned by the lock account, so a
mount over it is refused with "Permission denied". The anchor tier leaves
ownership unchanged -- that is the tier's whole point, the node is the
user's home -- so **the anchor node itself can still be mounted over**. A
mount there shadows the entire tree by path: a reader resolving by path
sees the image's content, and detaching afterwards leaves nothing the
seal can show. This is a by-path substitution no flag closes. A
mount-table check is an idea, not a decision.

### Placement under an atomic-save writer strands a temp per save

A placement seal puts `uappnd` on the directory, which lets a writer
create a new file but not rename over the sealed one. A temp+rename
writer therefore leaves its temp beside the target on every save, named
something like `<file>.tmp.<pid>.<hex>`. Measured on Claude Code's
`.claude.json`: roughly 250 KB of strand per save, with the writer's
in-place fallback keeping the state itself correct. The directory's
`uappnd` refuses the unlink too, so the user cannot remove them. Cleanup
is one command, and it takes a glob because `rm`, `trash`, `lock` and
`unlock` all accept many paths in one batch:

```sh
sudo locked rm <dir>/<name>.tmp.*
```

(`trash` is refused here: the trash service moves an entry as you, and a
placement directory's ACL entry does not let you remove one.)

There is no automatic janitor, by design: a verb that deletes files it
was never handed is not something `locked` does.

The leaf-parent rule removes the common case: a sealed file's own
directory is no longer sealed, so an atomic-save writer beside it renames
normally and strands nothing. What remains is a chain directory -- one
that is a higher ancestor of some protected file -- with an atomic-save
writer of its own inside it.

### What the diff witness shows, and what it cannot

The diff is `/usr/bin/diff` on bytes under the pinned PATH --
trusted-binary != trusted-output, so no git driver and no textconv sits
anywhere in the display path. diff's own color is disabled and `locked`
paints the `+`, `-` and `@@` lines itself, so the only escape sequences
reaching the terminal are locked's own.

The diff then goes through locked's own encoder before it is drawn.
Rendered as `\x{HH}` / `\x{HHHH}` tokens, in reverse video on a tty: the
C0 controls except tab and newline, DEL, the C1 controls, the bidi
overrides and isolates (U+202A-U+202E, U+2066-U+2069), U+200B, U+200E,
U+200F and U+FEFF, and any byte that is not valid UTF-8. Tab, newline,
ZWNJ, ZWJ and every other valid UTF-8 sequence pass raw.

Two residuals. Homoglyphs are not distinguishable: a Cyrillic "а" is
drawn the way a Latin "a" is. And off a tty there is no reverse video, so
an encoded token is indistinguishable from a file that literally
contains the text `\x{1B}`.

### Callers without a tty

The confirm gate refuses when stdin is not a tty unless `--yes` is given,
and `--yes` skips the gate outright. A caller with no tty -- an editor's
embedded shell prompt, an agent's tool shell, a script -- therefore
either fails closed or approves blind; there is no third behaviour. A
diff is only a witness while a human is reading it, so the mutating verbs
belong in a real terminal.

## Detection layer: `locked verify` + the verify status

Flags deny with silent EPERM -- the attacker sees the failure, the user
does not. `locked verify` re-checks every locked chain (existence, owner,
group, mode, full flag word, recursive-tree spot checks) and exits
nonzero on drift; it also catches a ceremony that forgot to relock. A
root LaunchDaemon runs it on a timer, and each run records its result per
user in `/var/db/locked/<user>/verify`: when it ran, the timer's interval,
how many records it walked, how many drifted, and which (escaped to
printable ASCII, capped). locked names no consumer. `locked status` shows
it, and any other reader -- a statusline, a login check -- knows the path.

The status is root's alone. The per-user dir is root-owned 750 with the
lock group, so the user reads it through their membership and no process
running as the user can write, replace or remove anything in it; the file
is replaced whole by a rename from a temp in that dir, so a reader gets
one run's complete answer. The run's start time is in the file because a
timer can stop: a reader that finds the result older than a few intervals
reports it as stale rather than clean. (Until 0.15.0 the result was an
alert file written as the user under their home, which any process
running as the user could delete.)

What this does not cover: a reader sees drift only as of the last run, up
to one interval late, and while the machine sleeps nothing runs.
EndpointSecurity/eslogger EPERM-monitoring is explicitly later.

## Kept from v1

- Digest-pinned sudoers (`sha256:` Digest_Spec): binary integrity is
  enforced by sudo before our code runs; a swapped binary gets a silent
  refusal, not a Touch ID prompt.
- Snapshot / diff / revert flow and the `.snap`/`.attic`/`.meta` layout;
  meta gains `tier`, `flag`, the exact post-lock flag word, and the
  volume-uuid/inode identity.
  v1 metas are not migrated -- v1 was never provisioned.
- Root-sudo invocation model for every mutating action. The two-tier
  draft's no-root runas (`(_<user>-lock)`) multiuser path is deferred:
  the anchor tier needs root regardless, and one elevation path is
  simpler to audit. `status` alone runs unprivileged (read-only; the
  pool's own permissions gate what each user sees).
- `atomic_replace` staging (now flag-aware: clears/restores flags on dst
  and temporarily lifts `uappnd` on the destination parent around the
  rename, restoring it even on failure).

## Caveats

- **Atomic-save editors** replace the file with a new inode via rename;
  under a flagged parent the rename is denied. Unlock prints a hint when
  the parent chain would deny it; `unlock --chain` is the escape and
  `locked edit` avoids the window entirely. In-place writers (`tee`,
  `vim` with `backupcopy=yes`, `>>`) are unaffected.
- **The rename hole partially reopens during a `--chain` window**: a
  released ancestor can be swapped by anything with write on its parent
  (rename checks parent write only). Locked leaves keep their own flags
  throughout, and re-seal refuses to bless a swapped placement/anchor
  node without a human at a tty (`--yes` deliberately does not satisfy
  that prompt); `verify` checks the identity against meta. Keep windows
  short; prefer `locked edit`.
- **Parent-swap above the anchor is out of scope by construction**: the
  chain terminates at a root-owned dir, so there is no user-writable
  ancestor left to swap. What remains is the standing floor: pinned
  ceremonies never trust the terminal; terminal hardening protects
  orientation.
- `sappnd` on `~` does not stop *creates*: absent exec-class dotfiles must
  be created empty and content-locked first (ceremony pre-work).
- Flags are invisible to `ls` without `-lO`; `locked status` is the
  intended lens.

## chflags invocation gotcha (probed)

`chflags -- <flagword> <path>`, never `chflags <flagword> -- <path>`: BSD
getopt stops at the flag word, so a later `--` becomes a filename and
poisons the exit code while the flag still gets applied.
