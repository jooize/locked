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
| `placement` | `uappnd` | `_<user>-lock` + group-write; children inherit the lock group | shared parent dirs (`~/.config`, `~/Library`, ...) | new entries allowed; rename/delete/replace of existing entries denied; dir itself immovable. Unlock only for uninstall/replace ceremonies. |
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
- `st_dev` is not a volume key: APFS assigns it at mount, in mount order.
  It changed across a reboot on 2026-09-09, and `/` and `~` share one this
  boot (firmlinks) while their volume UUIDs differ. Identity is volume UUID
  plus inode; `getattrlist` with `ATTR_VOL_UUID` answers with the
  containing volume for any path or descriptor, and devfs answers with
  nothing, which is why the `st_dev` spelling survives as a fallback.

## Group inheritance

A new entry takes its parent directory's group on macOS, as on every BSD,
so everything created under a placement seal carries the lock group. That
is expected, not drift: the owner has to be the lock account (`uappnd` is
a user flag its owner can clear), which leaves group `rwx` as the user's
only way in. The mechanism, the rejected ACL alternative, and the access
consequences are written out in the README section of the same name. On
Linux the equivalent would need setgid on the directory or an explicit
`chgrp`; `locked` is Darwin-only and does not handle it.

## Chain-walking

`locked lock <leaf>` derives and provisions the **entire chain** in one
ceremony:

1. The leaf gets its requested tier (default: `content`).
2. Every ancestor owned by the invoker gets `placement` -- except `$HOME`
   itself, which gets `anchor` (`sappnd`; ownership must not change).
3. Ancestors already in the pool (meta exists) are verified, not
   re-provisioned. The walk stops at the first node owned by neither the
   invoker nor the lock account; that node must be root-owned with no
   group/other write (`/Users` on stock macOS) or the lock is refused.

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
prompt for non-interactive use and `--dry-run` prints every mutation and
performs none.

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
sudo locked trash <dir>/<name>.tmp.*
```

There is no automatic janitor, by design: a verb that deletes files it
was never handed is not something `locked` does.

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

## Detection layer: `locked verify` + alerts

Flags deny with silent EPERM -- the attacker sees the failure, the user
does not. `locked verify` re-checks every locked chain (existence, owner,
group, mode, full flag word, recursive-tree spot checks) and exits
nonzero on drift; it also catches a ceremony that forgot to relock. A
root LaunchDaemon runs it on a timer; failures raise
`~/.local/state/agents/claude/alerts/locked--drift` (one timestamped
ASCII line, statusline renders it as a red row), cleared on clean
re-verify. The alert file is staged in the root-owned snapshots dir and
renamed into place so a planted symlink is replaced, never followed.
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
