# locked v2 design -- BSD flags + no-root multiuser

Distilled from the 2026-07-22 trusted-chain discussion (threat model: a tool
running as the user -- terminal-app scope, no TCC-protected dirs -- tampering
with files between "I read it" and "I sign/deploy it").

## Why change: ownership flip alone does not protect the *name*

v1 protects file *content* (EACCES on write), but anyone with write permission
on the parent directory can still `mv` the locked file aside and drop a
replacement -- no ownership needed. This is the TODO(parent-swap) residual
seen from the other side.

BSD immutable flags close exactly that hole: a flagged file cannot be
modified, deleted, **or renamed**, even by a user with write permission on the
parent, regardless of who owns the file. Verified empirically 2026-07-22:
user-owned file + `schg` -> `mv` over it fails EPERM.

## Flag choice: uchg, owned by the lock account

- `schg` (system immutable): only root can set/clear.
- `uchg` (user immutable): the file's **owner** or root can clear.

v2 uses `uchg` with files owned by `_<user>-lock`:

- The attacker (runs as the user) is not the owner -> cannot clear the flag.
- The lock account can clear it -> unlock authority becomes "may act as
  `_<user>-lock`", NOT "is root".
- Sudoers grants each user only `( _<user>-lock )` -- e.g.
  `alice ALL=(_alice-lock) /usr/local/sbin/locked-helper` -- so on a
  multiuser machine every user gets lock/unlock over their own pool with
  **zero root grants** after initial provisioning. This is the elegant
  multiuser property v1's root-sudo model lacks.

## Mechanism: ownership stays fixed, group-write toggles

chown requires root, so a no-root design cannot flip ownership per cycle.
Instead ownership is permanent and the editability toggle is group-write +
flag, all doable by the owner:

- File: `_<user>-lock:_<user>-lock` forever; user is a member of the group.
- **lock**   = (as lock account) `chmod g-w` + `chflags uchg`
- **unlock** = (as lock account) `chflags nouchg` + `chmod g+w`
- Snapshot/diff/revert flow carries over from v1 unchanged in spirit.

Ordering constraint: immutable blocks chmod/chown too -- always clear the
flag first on unlock, set it last on lock.

Initial adoption of a file still needs one root chown (`chown _<user>-lock`).
That is setup-time, not per-cycle.

## Caveats (honest ones)

- **Atomic-save editors break the fast path.** Editors that write-then-rename
  (most GUI editors, vim with default backupcopy) replace the file with a new
  inode owned by the *user*, ejecting it from the pool. In-place writes
  (`>>`, `sed -i ''`? no -- also renames; `tee`, direct `open(O_WRONLY)`) are
  fine. `lock` must detect owner != lock account and fall back to a root
  re-adopt path (or refuse with a clear message). Document per-editor advice
  or keep the root fallback from v1.
- **Ancestor rename is NOT closed.** Flags protect the node, not the path:
  `schg dir/child` does not stop `mv dir dir2`. Pinning `~/.config/ghostty`
  still allows an attacker to rename `~/.config` wholesale and plant a copy
  (needs only write on $HOME). Freezing $HOME or ~/.config with flags is not
  viable (immutable dirs block all entry create/delete -> breaks everything).
  Countermeasure is a fail-closed check at point of use (e.g. root-owned
  trusted.fish verifying inode + `ls -lO` flags at session start), not
  prevention.
- **Flags don't survive v1's cp-based restore** -- fold flag capture/restore
  into the TODO(xattrs) helper work.
- `revert`/`atomic_replace` must clear the flag on dst before `mv -f`, re-set
  after.

## Relation to the trusted-chain stack

locked v2 pins the links of the read/sign chain that live in $HOME:
`~/.config/ghostty` (contains the `command` line launching
`fish --no-config --init-command 'source /etc/fish/trusted.fish'`) and any
other config the verification session depends on. Content of trust-critical
config should still live root-owned in the nix store /etc where possible;
locked covers what must remain in $HOME. Signing integrity itself comes from
sign-the-committed-SHA + deploy by `rev=$SHA` with signature verification
against a root-owned allowed-signers file -- locked hardens the display path,
it is not the root of trust.

## Migration sketch (v1 -> v2)

1. Add flag handling to lock/unlock/revert (order rules above).
2. Add `locked adopt <file>` (root): chown to lock account, set group, meta.
3. New sudoers shape: per-user `(_<user>-lock)` rule for the no-root fast
   path; keep a root rule only for `setup`/`adopt`/re-adopt.
4. Keep digest-pinned sudoers entries (v1's best idea) for both rules.
5. Update snapshot layout docs; no format change needed.
