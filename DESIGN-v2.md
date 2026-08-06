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
| `placement` | `uappnd` | `_<user>-lock` + group-write | shared parent dirs (`~/.config`, `~/Library`, ...) | new entries allowed; rename/delete/replace of existing entries denied; dir itself immovable. Unlock only for uninstall/replace ceremonies. |
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
mode, exact flag word vs meta, and dev/ino identity. `locked unlock`
releases only the named node (`--chain` additionally drops the flags on
the chain's ancestors, for edits that need a rename into a frozen parent
-- atomic-save editors); the next `lock` re-walks and re-seals the chain
in reverse.

## Diff-witness on relock

`locked lock` shows the snapshot-vs-current diff and requires explicit
confirmation before sealing (pinned-style "the diff matches what I
intended"). Plain `/usr/bin/diff` on bytes under the pinned PATH --
trusted-binary != trusted-output: no git drivers/textconv anywhere in the
display path. `--yes` answers the prompt for non-interactive use;
`--dry-run` prints every mutation and performs none.

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
  meta gains `tier`, `flag`, the exact post-lock flag word, and dev/ino.
  v1 metas are not migrated -- v1 was never provisioned.
- Root-sudo invocation model. The two-tier draft's no-root runas
  (`(_<user>-lock)`) multiuser path is deferred: the anchor tier needs
  root regardless, and one elevation path is simpler to audit.
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
  that prompt); `verify` checks dev/ino against meta. Keep windows
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
