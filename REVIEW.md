# Review status

External security review (2026-04-29). Findings tracked here.

## Findings

| Finding | Status |
|---|---|
| sudoers binds to path, not binary identity | **fixed** -- Digest_Spec sha256 pin in setup-written sudoers entry |
| Revert double-invocation destroys .attic | **fixed** -- `cmp -s` guard skips revert if file already matches snapshot |
| PATH not pinned | **fixed** -- `export PATH=/usr/bin:/bin:/usr/sbin:/sbin` at top of script |
| No audit log | **fixed** -- `log_action` -> `logger -t locked`; queryable via `log show` |
| Partial-failure across multiple files | **fixed** -- per-file `process_one` function; loop continues on failures |
| README "pam_tid_local" wording | **fixed** |
| INSTALL_TARGET / SNAPSHOTS_ROOT not overridable | **fixed** -- `: "${VAR:=default}"` pattern |
| .meta fallback on unlock may capture transient mode | **improved** -- clearer warning text instructing user to review and fix |
| Source-side TOCTOU (cp's open) | **deferred** -- `TODO(toctou)` in source; documented in README and `project_locked_residuals.md` memory |
| Parent-dir swap | **deferred** -- `TODO(parent-swap)`; same fix path as source-side TOCTOU |
| xattrs / ACLs / BSD flags not preserved | **deferred** -- `TODO(xattrs)`; documented in README and memory |
| Concurrency lock via `flock` | **skipped** -- reviewer's own call; unlikely to bite single human operator |
| UID/GID print order in do_setup | **skipped** -- trivial cosmetic |
| Paths with newlines | **skipped** -- out of scope per reviewer |
| chmod TOCTOU after readlink -f | **partially addressed** -- destination side closed by `atomic_replace`; source side same as TOCTOU above |

## Deferred work tracking

The three `TODO(...)` markers in `locked` source map to the deferred residuals:
- `TODO(toctou)` -- source-side file swap during cp's path resolution.
- `TODO(parent-swap)` -- destination parent renamed between path resolution and final mv.
- `TODO(xattrs)` -- extended attributes / ACLs / BSD flags lost on snapshot/restore.

All three close once a small Swift/Python helper using `O_NOFOLLOW` + `fchmod`/`fchown` exists. That helper is the same primitive needed by the trusted-prompt-sudo project (see `~/.claude/projects/.../memory/project_trusted_sudo_prompt.md`) -- build one, both tools benefit.

Cheaper interim mitigation: chown the parent dirs of protected files into the lock account too (e.g. `chown -h _<user>-lock:_<user>-lock ~/.ssh/`). Closes parent-swap on those specific dirs at the cost of more setup ceremony per protected dir.

## System-side application (user-run, not code)

Code is ready; these are the steps to actually apply on the machine:

1. `sudo ~/Projects/Claude/locked/locked setup`
2. Smoke-test unlock/lock/revert on a throwaway file.
3. Ensure `~/.claude/settings.json` (real file: `~/.config/agents/claude/settings/settings.json`) carries the hardening `permissions`/`sandbox` blocks — it is the source of truth; edit by hand (`sudoedit`) if needed. (The `settings-additions.json` snippet was retired 2026-06-05.)
4. `sudo locked lock` the user-global Claude Code config files (`~/.claude/settings.json`, `~/.claude/hooks/*.bash`, `~/.claude/CLAUDE.md`).
5. Drop `~/Projects/Claude/claude-code-hardening/claude.fish` into `~/.config/fish/functions/`.
6. Restart Claude Code so settings take effect.

## Other open work outside this review

- Fish install (`programs.fish.enable = true` in home-manager); point Ghostty at the fish path.
- Per-project lock of `<project>/.claude/settings.json` (closes the residual click-through risk on project-level settings) -- adds friction; decide whether the threat warrants it.
