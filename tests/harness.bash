#!/usr/bin/env bash
# locked v2 test harness: flag primitives + CLI end-to-end.
#
#   sudo /bin/bash tests/harness.bash
#
# Ports the 2026-08-05 probe round to repeatable assertions. Every denial
# assertion has a flag-vs-noflag control (clear the flag, re-run, expect
# success) so a failure can't be blamed on permissions or the sandbox.
#
# No global state is touched: the lock account is stood in by the existing
# `daemon` user (the account's identity is irrelevant to flag mechanics;
# what matters is that the invoker does not own the node), snapshots and
# fake home live in a scratch dir, and the cleanup trap clears all flags
# before removing it. Ancestry fixtures live in a second scratch under
# /var/db (the 1777 /private/tmp would itself fail the walk), and the
# window helper this harness builds lives in a third one there for the same
# reason; both are removed by the trap. Group-write add-rights on placement
# dirs depend on membership in the real _<user>-lock group and are exercised
# at ceremony time, not here.
#
# One thing this harness cannot keep entirely to itself: if the trash
# service is reachable from the terminal running it, the trash probe below
# and the trash success cases put entries in the invoker's real bin. Each
# one is taken back out again by the case that created it.

set -euo pipefail
IFS=$'\n\t'
shopt -s nullglob

[ "$(id -u)" -eq 0 ] || { echo "run via sudo: sudo /bin/bash tests/harness.bash" >&2; exit 1; }
INV="${SUDO_USER:-}"
[ -n "$INV" ] && [ "$INV" != "root" ] || { echo "needs SUDO_USER (invoke via sudo from your user)" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOCKED="$REPO/locked"
[ -x "$LOCKED" ] || { echo "locked binary not found at $LOCKED" >&2; exit 1; }

SCRATCH="$(mktemp -d /private/tmp/locked-harness.XXXXXX)"
chmod 755 "$SCRATCH"   # root-owned 755, no group/other write -> valid chain stop node

cleanup() {
  # Clear every flag we may have set (system flags need root; we are root),
  # then remove the scratch trees. No flags are ever set under ANC.
  chflags -R noschg,nosappnd,nouchg,nouappnd "$SCRATCH" 2>/dev/null || true
  rm -rf -- "$SCRATCH"
  if [ -n "${ANC:-}" ]; then rm -rf -- "$ANC"; fi
  if [ -n "${HELPERDIR:-}" ]; then rm -rf -- "$HELPERDIR"; fi
}
trap cleanup EXIT

# Environment for every locked invocation: scratch snapshots, daemon as the
# stand-in lock account, fake home, scratch alert dir. These seams only work
# because we execute the script directly as root -- sudo's env_reset strips
# them on real invocations.
LOCK_ACCT=daemon
FAKE_HOME="$SCRATCH/home"
ALERTS="$SCRATCH/alerts"
SNAPROOT="$SCRATCH/snapshots"

locked() {
  env SNAPSHOTS_ROOT="$SNAPROOT" \
      INSTALL_TARGET="$SCRATCH/not-installed" \
      LOCKED_HELPER="$HELPER" \
      LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
      LOCKED_USER_HOME="$FAKE_HOME" \
      LOCKED_ALERT_DIR="$ALERTS" \
      SUDO_USER="$INV" \
      /bin/bash "$LOCKED" "$@"
}

as_user() {
  sudo -u "$INV" "$@"
}

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }
ok() {   # ok <desc> <cmd...>: expect success; prints the output on failure
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    PASS=$((PASS + 1)); note "  ok    $desc"
  else
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (expected success)"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/        | /'
  fi
}
deny() { # deny <desc> <cmd...>: expect failure; prints the output on surprise
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (expected denial)"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/        | /'
  else
    PASS=$((PASS + 1)); note "  ok    $desc"
  fi
}
check() { # check <desc> <expected> <actual>
  local desc="$1" want="$2" got="$3"
  if [ "$want" = "$got" ]; then
    PASS=$((PASS + 1)); note "  ok    $desc"
  else
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (want '$want', got '$got')"
  fi
}
refuse() { # <desc> <needle> <cmd...>: expect failure WITH the named message,
           # so a denial can be attributed to the check under test.
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (expected refusal)"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/        | /'
  elif printf '%s\n' "$out" | grep -qF -e "$needle"; then
    PASS=$((PASS + 1)); note "  ok    $desc"
  else
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (refused, but not with '$needle')"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/        | /'
  fi
}

flags_of() {
  # Same normalization as locked: "-" (no flags) becomes "".
  local s
  s="$(stat -f '%Sf' "$1" | tr -d ' ')"
  [ "$s" = "-" ] && s=""
  printf '%s' "$s"
}
owner_of() { stat -f '%Su' "$1"; }
locked_notty() {
  # For prompts-must-fail-closed tests: run locked with stdin not a tty.
  locked "$@" </dev/null
}

install -d -o "$INV" -g staff "$FAKE_HOME"
install -d -o "$INV" -g staff "$ALERTS"
install -d -o "$INV" -g staff "$SCRATCH/raw"   # user-owned container for raw probes

# ---- 0. window helper ------------------------------------------------------
#
# atomic_replace routes EVERY staging copy through the compiled window
# helper, so lock, edit and revert all need one -- not just the placement
# verbs. Build the repo's source and install it where verify_helper's walk
# accepts it: root-owned, no group/other write, and a fully root-owned
# 755-or-stricter ancestry on both the textual and the resolved path. That
# rules out /private/tmp (1777), so the binary sits under /var/db beside the
# ancestry fixtures of section 3. LOCKED_HELPER is itself the seam, dead
# under sudo's env_reset like every other one.

note "== window helper: build and install =="
HELPERSRC="$REPO/helper/locked-helper.m"
[ -f "$HELPERSRC" ] || { echo "helper source not found at $HELPERSRC" >&2; exit 1; }
[ -x /usr/bin/clang ] || { echo "/usr/bin/clang is needed to build the window helper" >&2; exit 1; }
HELPERDIR="$(mktemp -d /private/var/db/locked-harness-helper.XXXXXX)"
chmod 755 "$HELPERDIR"
HELPER="$HELPERDIR/locked-helper"
/usr/bin/clang -O2 -Wall -Wextra -framework Foundation \
    -o "$SCRATCH/locked-helper.built" "$HELPERSRC" \
  || { echo "could not build $HELPERSRC" >&2; exit 1; }
install -o root -g wheel -m 755 "$SCRATCH/locked-helper.built" "$HELPER"
check "helper is root-owned"                  "root" "$(owner_of "$HELPER")"
check "helper is 755"                         "755" "$(stat -f '%OLp' "$HELPER")"
check "helper's dir is root-owned"            "root" "$(owner_of "$HELPERDIR")"
check "helper's dir is 755"                   "755" "$(stat -f '%OLp' "$HELPERDIR")"

# The `id` verb is the whole of the script's node_id(): it runs without
# root (unprivileged `status` needs it), reads nothing but attributes, and
# is what makes the record and the helper's own compare agree by
# construction.
note "== helper: the id verb =="
IDF="$SCRATCH/raw/idprobe.txt"
IDOUT="$SCRATCH/id-out.txt"
as_user /bin/sh -c "echo i > '$IDF'"
ok   "id succeeds on a scratch file"          "$HELPER" id "$IDF"
"$HELPER" id "$IDF" >"$IDOUT" 2>&1 || true
ok   "id prints <uuid>:<ino>" \
     grep -qE '^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}:[0-9]+$' "$IDOUT"
check "id reports the file's inode"           "$(stat -f '%i' "$IDF")" \
      "$(sed 's/.*://' "$IDOUT")"
ok   "id needs no root"                       as_user "$HELPER" id "$IDF"
check "unprivileged id agrees with root's"    "$("$HELPER" id "$IDF")" \
      "$(as_user "$HELPER" id "$IDF")"
# devfs reports no volume uuid; the st_dev fallback is what keeps the
# grammar total, and it must read the way stat(1) prints it.
"$HELPER" id /dev/null >"$IDOUT" 2>&1 || true
ok   "id falls back to <dev>:<ino> on devfs"  grep -qE '^[0-9]+:[0-9]+$' "$IDOUT"
check "the fallback agrees with stat"         "$(stat -f '%d.%i' /dev/null)" \
      "$(tr ':' '.' <"$IDOUT")"
deny "id fails on a path that is not there"   "$HELPER" id "$SCRATCH/raw/no-such-file"
refuse "id refuses a relative path"           "must be an absolute path" \
       "$HELPER" id idprobe.txt

# The trash service is TCC-gated by the responsible application: from a
# terminal that has not been granted access, trashItemAtURL: comes back
# afpAccessDenied and nothing locked does can change that. Probe once, so
# the success cases can skip with a reason instead of failing. Every
# bash-side trash refusal is tested either way.
note "== trash service: reachability probe =="
INV_UID="$(id -u "$INV")"
INV_GID="$(id -g "$INV")"
INV_HOME="$(dscl . -read "/Users/$INV" NFSHomeDirectory 2>/dev/null | awk '{print $2; exit}')"
TPROBE="$SCRATCH/trash-probe"
install -d -o "$INV" -g staff -m 755 "$TPROBE"
as_user /bin/sh -c "echo probe > '$TPROBE/locked-harness-trash-probe.txt'"
TRASH_SKIP=0
if TPOUT="$("$HELPER" trash --parent "$TPROBE" --parent-id - \
             --name locked-harness-trash-probe.txt --target-id - \
             --uid "$INV_UID" --gid "$INV_GID" --home "$INV_HOME" 2>/dev/null)"; then
  note "  note  trash service reachable; success cases will run"
  TPBIN="$(printf '%s\n' "$TPOUT" | awk -F'\t' '$1=="binurl"{print $2; exit}')"
  # Take the probe's own entry straight back out of the real bin.
  if [ -n "$TPBIN" ]; then as_user rm -rf -- "$TPBIN" || true; fi
else
  TRASH_SKIP=1
  note "  note  trash service refused this terminal (TCC); success cases skip"
fi

# ---- 1. raw flag primitives ------------------------------------------------

note "== raw primitives: uchg file =="
F="$SCRATCH/raw/uchg-file.txt"
as_user /bin/sh -c "echo original > '$F'"
chown "$LOCK_ACCT:$LOCK_ACCT" "$F"
chmod 666 "$F"
chflags -- uchg "$F"
deny "user append to uchg file"          as_user /bin/sh -c "echo x >> '$F'"
deny "user clear of non-owned uchg"      as_user chflags -- nouchg "$F"
deny "user rename of uchg file"          as_user mv -- "$F" "$F.moved"
chflags -- nouchg "$F"
ok   "control: append after nouchg"      as_user /bin/sh -c "echo x >> '$F'"
ok   "control: rename after nouchg"      as_user mv -- "$F" "$F.moved"

note "== raw primitives: uchg dir =="
D="$SCRATCH/raw/uchg-dir"
as_user mkdir -- "$D"
as_user /bin/sh -c "echo a > '$D/existing.txt'"
chown "$LOCK_ACCT:$LOCK_ACCT" "$D"
chmod 777 "$D"
chflags -- uchg "$D"
deny "entry create in uchg dir"          as_user /bin/sh -c "echo x > '$D/new.txt'"
deny "entry delete in uchg dir"          as_user rm -- "$D/existing.txt"
deny "rename of uchg dir itself"         as_user mv -- "$D" "$D.moved"
chflags -- nouchg "$D"
ok   "control: create after nouchg"      as_user /bin/sh -c "echo x > '$D/new.txt'"

note "== raw primitives: uappnd dir =="
A="$SCRATCH/raw/uappnd-dir"
as_user mkdir -- "$A"
as_user mkdir -- "$A/subdir"
as_user /bin/sh -c "echo a > '$A/existing.txt'"
as_user /bin/sh -c "echo m > '$SCRATCH/raw/movein.txt'"
chown "$LOCK_ACCT:$LOCK_ACCT" "$A"
chmod 777 "$A"
chflags -- uappnd "$A"
ok   "create new entry in uappnd dir"    as_user /bin/sh -c "echo x > '$A/new.txt'"
ok   "mkdir in uappnd dir"               as_user mkdir -- "$A/newdir"
ok   "mv-INTO uappnd dir"                as_user mv -- "$SCRATCH/raw/movein.txt" "$A/"
deny "rename existing entry"             as_user mv -- "$A/existing.txt" "$A/renamed.txt"
deny "delete existing entry"             as_user rm -- "$A/existing.txt"
deny "rename of uappnd dir itself"       as_user mv -- "$A" "$A.moved"
ok   "subdir interior unaffected"        as_user /bin/sh -c "echo x > '$A/subdir/inner.txt' && rm '$A/subdir/inner.txt'"
chflags -- nouappnd "$A"
ok   "control: rename after nouappnd"    as_user mv -- "$A/existing.txt" "$A/renamed.txt"
ok   "control: delete after nouappnd"    as_user rm -- "$A/new.txt"

note "== raw primitives: sappnd file (root-anchor, ownership stays user) =="
SF="$SCRATCH/raw/sappnd-file.txt"
as_user /bin/sh -c "echo start > '$SF'"
chflags -- sappnd "$SF"
check "sappnd set on user-owned file by root" "sappnd" "$(flags_of "$SF")"
deny "user truncate of sappnd file"      as_user /bin/sh -c "echo gone > '$SF'"
ok   "user append to sappnd file"        as_user /bin/sh -c "echo more >> '$SF'"
deny "user clear of sappnd (own file)"   as_user chflags -- nosappnd "$SF"
deny "user zero of flag word"            as_user chflags -- 0 "$SF"
chflags -- nosappnd "$SF"
ok   "control: truncate after nosappnd"  as_user /bin/sh -c "echo gone > '$SF'"

note "== raw primitives: schg file =="
SC="$SCRATCH/raw/schg-file.txt"
as_user /bin/sh -c "echo start > '$SC'"
chflags -- schg "$SC"
deny "user write to schg file"           as_user /bin/sh -c "echo x >> '$SC'"
deny "user rename of schg file"          as_user mv -- "$SC" "$SC.moved"
deny "user clear of schg (own file)"     as_user chflags -- noschg "$SC"
chflags -- noschg "$SC"
ok   "control: write after noschg"       as_user /bin/sh -c "echo x >> '$SC'"

# ---- 2. CLI end-to-end -----------------------------------------------------

note "== cli: no-arg status on an empty pool =="
# Runs before the first lock, so the pool genuinely has no metas yet.
POOL="$SCRATCH/pool.txt"
ok   "empty pool status succeeds"        locked status
locked status >"$POOL" 2>&1
ok   "empty pool listing says so"        grep -qF "pool for $INV is empty" "$POOL"

note "== cli: content-tier file lock provisions the chain =="
as_user mkdir -- "$FAKE_HOME/sub"
# 777 so the invoker keeps write on the placement parent via the OTHER bits:
# with the daemon stand-in the invoker is not in the lock group, and denial
# tests must be attributable to flags, not to ordinary permissions.
chmod 777 "$FAKE_HOME/sub"
CFG="$FAKE_HOME/sub/we ird %config.txt"   # space + percent stress the encoding
as_user /bin/sh -c "printf 'version 1\n' > '$CFG'"

ok   "lock --yes leaf"                   locked lock --yes "$CFG"
check "leaf owner is lock account"       "$LOCK_ACCT" "$(owner_of "$CFG")"
check "leaf flag uchg"                   "uchg" "$(flags_of "$CFG")"
check "parent owner is lock account"     "$LOCK_ACCT" "$(owner_of "$FAKE_HOME/sub")"
check "parent flag uappnd"               "uappnd" "$(flags_of "$FAKE_HOME/sub")"
check "home flag sappnd"                 "sappnd" "$(flags_of "$FAKE_HOME")"
check "home owner unchanged"             "$INV" "$(owner_of "$FAKE_HOME")"
deny "user write to locked leaf"         as_user /bin/sh -c "echo evil >> '$CFG'"
deny "user swap of locked leaf"          as_user mv -- "$CFG" "$CFG.bak"
ok   "status clean"                      locked status "$CFG"
ok   "verify clean"                      locked verify
ok   "lock is idempotent"                locked lock --yes "$CFG"

note "== cli: unlock, edit in place, diff-witness relock =="
ok   "unlock leaf"                       locked unlock "$CFG"
check "unlocked owner back to user"      "$INV" "$(owner_of "$CFG")"
check "unlocked flags empty"             "" "$(flags_of "$CFG")"
check "parent stays uappnd"              "uappnd" "$(flags_of "$FAKE_HOME/sub")"
ok   "user in-place edit while unlocked" as_user /bin/sh -c "printf 'version 2\n' > '$CFG'"
ok   "relock with --yes seals"           locked lock --yes "$CFG"
check "relocked flag uchg"               "uchg" "$(flags_of "$CFG")"
NT="$FAKE_HOME/notty.txt"
as_user /bin/sh -c "echo x > '$NT'"
deny "lock without --yes fails closed off-tty" locked_notty lock "$NT"
check "fail-closed lock left owner"      "$INV" "$(owner_of "$NT")"
ok   "verify clean after relock"         locked verify

note "== cli: revert restores unlock-time snapshot =="
ok   "unlock for revert round"           locked unlock "$CFG"
as_user /bin/sh -c "printf 'version 3\n' > '$CFG'"
RLF="$SCRATCH/relock-diff-header.out"
RLRC=0
locked lock --yes "$CFG" >"$RLF" 2>&1 || RLRC=$?
check "relock version 3"                 "0" "$RLRC"
ok   "relock names the snapshot side"    grep -qF -- "--- snapshot: $CFG" "$RLF"
ok   "relock names the current side"     grep -qF -- "+++ current: $CFG" "$RLF"
ok   "revert"                            locked revert "$CFG"
check "content back to unlock-time"      "version 2" "$(head -1 "$CFG")"
check "reverted file still uchg"         "uchg" "$(flags_of "$CFG")"
ok   "verify clean after revert"         locked verify

note "== cli: drift detection + alert + repair =="
chflags -- nouchg "$CFG"                 # simulate an attacker-with-root / forgotten relock
chown "$INV" "$CFG"
if locked verify >/dev/null 2>&1; then
  FAIL=$((FAIL + 1)); note "  FAIL  verify should exit nonzero on drift"
else
  rc=$?
  check "verify exit code 5 on drift"    "5" "$rc"
fi
ok   "alert file raised"                 test -s "$ALERTS/locked--drift"
check "alert file owned by user"         "$INV" "$(owner_of "$ALERTS/locked--drift")"
ok   "repair: unlock drifted node"       locked unlock "$CFG"
ok   "repair: relock"                    locked lock --yes "$CFG"
ok   "verify clean after repair"         locked verify
deny "alert cleared after clean verify"  test -e "$ALERTS/locked--drift"

note "== cli: content-tier directory (recursive) =="
CD="$FAKE_HOME/cfgdir"
as_user mkdir -p -- "$CD/nested"
as_user /bin/sh -c "echo a > '$CD/a.txt'; echo b > '$CD/nested/b.txt'"
ok   "lock --yes dir"                    locked lock --yes "$CD"
check "dir flag uchg"                    "uchg" "$(flags_of "$CD")"
check "nested file owner lock account"   "$LOCK_ACCT" "$(owner_of "$CD/nested/b.txt")"
check "nested file uchg"                 "uchg" "$(flags_of "$CD/nested/b.txt")"
deny "user write inside locked dir"      as_user /bin/sh -c "echo evil >> '$CD/a.txt'"
ok   "unlock dir"                        locked unlock "$CD"
check "dir owner back to user"           "$INV" "$(owner_of "$CD")"
check "nested owner back to user"        "$INV" "$(owner_of "$CD/nested/b.txt")"
ok   "relock dir"                        locked lock --yes "$CD"
ok   "verify clean with dir in pool"     locked verify

note "== cli: unlock --chain enables atomic-save, relock reseals =="
ok   "unlock --chain leaf"               locked unlock --chain "$CFG"
check "parent released"                  "" "$(flags_of "$FAKE_HOME/sub")"
check "home released"                    "" "$(flags_of "$FAKE_HOME")"
ok   "atomic-save style replace works"   as_user /bin/sh -c "printf 'version 4\n' > '$CFG.new' && mv -- '$CFG.new' '$CFG'"
ok   "relock reseals chain"              locked lock --yes "$CFG"
check "parent resealed uappnd"           "uappnd" "$(flags_of "$FAKE_HOME/sub")"
check "home resealed sappnd"             "sappnd" "$(flags_of "$FAKE_HOME")"
ok   "verify clean after chain reseal"   locked verify

note "== cli: locked edit -- sudoedit-style, no unlock window =="
ED="$SCRATCH/edscript"
cat >"$ED" <<'EOS'
#!/bin/sh
printf 'edited by script\n' > "$1"
EOS
chmod 755 "$ED"
ok   "edit installs via staging"         locked edit --yes --editor "$ED" "$CFG"
check "edited content installed"         "edited by script" "$(head -1 "$CFG")"
check "still locked after edit"          "uchg" "$(flags_of "$CFG")"
check "owner still lock account"         "$LOCK_ACCT" "$(owner_of "$CFG")"
ok   "verify clean after edit"           locked verify
ok   "revert undoes the edit"            locked revert "$CFG"
check "revert restored pre-edit"         "version 4" "$(head -1 "$CFG")"

note "== cli: locked edit --from -- a proposal instead of an editor =="
# A tool (or the user) writes the whole proposed file somewhere they own;
# locked freezes it into lock-account staging before drawing the diff.
PROPD="$SCRATCH/proposals"
install -d -o "$INV" -g staff -m 755 "$PROPD"
PROP="$PROPD/config.proposed.txt"
as_user /bin/sh -c "printf 'from a proposal\n' > '$PROP'"
EDF="$SCRATCH/edit-diff-header.out"
EDRC=0
locked edit --yes --from "$PROP" "$CFG" >"$EDF" 2>&1 || EDRC=$?
check "edit --from installs the proposal" "0" "$EDRC"
ok   "edit --from names current"          grep -qF -- "--- current: $CFG" "$EDF"
ok   "edit --from names proposed"         grep -qF -- "+++ proposed: $PROP" "$EDF"
check "proposed content installed"        "from a proposal" "$(head -1 "$CFG")"
check "still locked after edit --from"    "uchg" "$(flags_of "$CFG")"
check "owner still lock account"          "$LOCK_ACCT" "$(owner_of "$CFG")"
ok   "verify clean after edit --from"     locked verify
ok   "revert undoes the --from edit"      locked revert "$CFG"
check "revert restored the pre-edit file" "version 4" "$(head -1 "$CFG")"

refuse "a missing proposal is refused"    "--from: not a regular file" \
       locked edit --yes --from "$PROPD/nope" "$CFG"
check "the target is untouched"           "version 4" "$(head -1 "$CFG")"
check "the target is still sealed"        "uchg" "$(flags_of "$CFG")"
refuse "--from with --editor is refused"  "alternatives" \
       locked edit --yes --from "$PROP" --editor "$ED" "$CFG"
refuse "--from with two files is refused" "one proposed copy for one file" \
       locked edit --yes --from "$PROP" "$CFG" "$CFG"
refuse "--from on another verb is refused" "--from applies to edit only" \
       locked lock --yes --from "$PROP" "$CFG"

# A proposal identical to the sealed file is a no-op, exactly as an editor
# that changed nothing is.
PROPSAME="$PROPD/config.same.txt"
cat -- "$CFG" >"$PROPSAME"
chown "$INV" "$PROPSAME"
check "an unchanged proposal installs nothing" "no changes: $CFG" \
      "$(locked edit --yes --from "$PROPSAME" "$CFG")"
check "the unchanged target is still sealed"   "uchg" "$(flags_of "$CFG")"

# Off-tty the gate has nobody to ask, so it fails closed and names --yes --
# and the frozen copy must not be left behind in staging.
locked_notty() { locked "$@" </dev/null; }
refuse "no tty and no --yes is refused"   "--yes not given" \
       locked_notty edit --from "$PROP" "$CFG"
check "the declined target is unchanged"  "version 4" "$(head -1 "$CFG")"
check "the staging dir is left empty"     "0" \
      "$(ls -A "$SNAPROOT/$INV/.staging" | wc -l | tr -d ' ')"

# The freeze property itself: that a swap of the proposal between the diff
# and the install changes nothing. There is no pause in the flow a test can
# reach into without a test-only hook in locked, so it is asserted on the
# code instead -- the install reads $stage, and the proposal is never named
# again once it has been frozen.
EDITBODY="$SCRATCH/do_edit_one.body"
awk '/^do_edit_one\(\) \{/,/^\}$/' "$LOCKED" >"$EDITBODY"
ok   "the edit body was extracted"        test -s "$EDITBODY"
ok   "the diff reads the frozen copy"     \
     grep -qF -- '--label "$lhs" --label "$rhs" "$f" "$stage"' "$EDITBODY"
ok   "the install reads the frozen copy"  \
     grep -qF 'atomic_replace "$stage" "$f"' "$EDITBODY"
FREEZELN="$(grep -n 'show_diff' "$EDITBODY" | head -1 | cut -d: -f1)"
deny "the proposal is not named after the freeze" \
     /bin/sh -c "tail -n +$FREEZELN '$EDITBODY' | grep -q 'OPT_FROM'"

note "== cli: edit reads the candidate as the invoker, never as root =="
# Both candidate paths sit in the invoker's own space, so a same-UID
# process can replace either with a symlink. Read as root, the link would
# pull a root-only file's bytes into staging and, once approved, into a
# file the invoker can read.
ROOTONLY="$SCRATCH/rootonly"
printf 'secret\n' >"$ROOTONLY"
chmod 600 "$ROOTONLY"
as_user ln -s "$ROOTONLY" "$PROPD/link.proposed.txt"
refuse "a symlinked proposal is refused"  "cannot read as" \
       locked edit --yes --from "$PROPD/link.proposed.txt" "$CFG"
check "the target is unchanged"           "version 4" "$(head -1 "$CFG")"
check "the target is still sealed"        "uchg" "$(flags_of "$CFG")"
check "staging is left empty"             "0" \
      "$(ls -A "$SNAPROOT/$INV/.staging" | wc -l | tr -d ' ')"
deny "no root-only bytes reached the target" grep -qF secret "$CFG"

# The editor runs as the invoker, so it can leave a symlink behind just as
# readily as any other process running as them.
ED2="$SCRATCH/edscript-symlink"
cat >"$ED2" <<EOS
#!/bin/sh
rm -f -- "\$1"
ln -s '$ROOTONLY' "\$1"
EOS
chmod 755 "$ED2"
refuse "a symlink left by the editor is refused" "cannot read the edited copy" \
       locked edit --yes --editor "$ED2" "$CFG"
check "the target is unchanged"           "version 4" "$(head -1 "$CFG")"
check "the target is still sealed"        "uchg" "$(flags_of "$CFG")"
check "staging is left empty"             "0" \
      "$(ls -A "$SNAPROOT/$INV/.staging" | wc -l | tr -d ' ')"
deny "no root-only bytes reached the target" grep -qF secret "$CFG"

note "== cli: an edit carries the sealed file's xattrs, not the candidate's =="
# Keeping a sealed file's extended attributes is part of locked's job, and
# the candidate is read with cat, which carries bytes only. Its own fixture:
# xattrs cannot be set on a file that is already uchg.
XCFG="$FAKE_HOME/sub/xattr-edit.txt"
printf 'version 1\n' >"$XCFG"
chown "$INV" "$XCFG"
xattr -w house.test v1 "$XCFG"
ok   "lock the xattr edit fixture"         locked lock --yes "$XCFG"
XPROP="$PROPD/xattr.proposed.txt"
as_user /bin/sh -c "printf 'version 2\n' > '$XPROP'"
as_user xattr -w house.evil planted "$XPROP"
ok   "edit --from the xattr fixture"       locked edit --yes --from "$XPROP" "$XCFG"
check "the proposed content installed"     "version 2" "$(head -1 "$XCFG")"
check "the sealed file keeps its xattr"    "v1" "$(xattr -p house.test "$XCFG")"
deny "the candidate's xattr is not adopted" xattr -p house.evil "$XCFG"
check "the edited file is sealed again"    "uchg" "$(flags_of "$XCFG")"
ok   "verify clean after the xattr edit"   locked verify
ok   "revert the xattr fixture"            locked revert "$XCFG"
check "the reverted content"               "version 1" "$(head -1 "$XCFG")"
check "the reverted file keeps its xattr"  "v1" "$(xattr -p house.test "$XCFG")"

note "== cli: ~/.ssh class -- anchor only, ownership never changes =="
as_user mkdir -m 700 -- "$FAKE_HOME/.ssh"
SSHCFG="$FAKE_HOME/.ssh/config"
as_user /bin/sh -c "printf 'Host example\n' > '$SSHCFG'"
deny "content tier refused under ~/.ssh" locked lock --yes --tier content "$SSHCFG"
ok   "lock defaults to anchor"           locked lock --yes "$SSHCFG"
check "ssh config owner stays user"      "$INV" "$(owner_of "$SSHCFG")"
check "ssh config flag defaults schg"    "schg" "$(flags_of "$SSHCFG")"
check "ssh dir auto-anchored sappnd"     "sappnd" "$(flags_of "$FAKE_HOME/.ssh")"
check "ssh dir owner stays user"         "$INV" "$(owner_of "$FAKE_HOME/.ssh")"
deny "user write to schg ssh config"     as_user /bin/sh -c "echo evil >> '$SSHCFG'"
deny "user clear of schg (own file)"     as_user chflags -- noschg "$SSHCFG"
ok   "unlock ssh config"                 locked unlock "$SSHCFG"
check "unlocked owner stays user"        "$INV" "$(owner_of "$SSHCFG")"
ok   "in-place edit while unlocked"      as_user /bin/sh -c "printf 'Host edited\n' > '$SSHCFG'"
ok   "relock (diff-witness) seals"       locked lock --yes "$SSHCFG"
ok   "revert anchor file"                locked revert "$SSHCFG"
check "reverted content"                 "Host example" "$(head -1 "$SSHCFG")"
check "reverted owner stays user"        "$INV" "$(owner_of "$SSHCFG")"
check "reverted flag schg"               "schg" "$(flags_of "$SSHCFG")"
ok   "verify clean with ssh in pool"     locked verify

note "== cli: diff witness encodes controls and invisibles =="
# The diff is the trust decision, so the candidate must not be able to
# paint it: an escape sequence can scroll a removal out of sight or repaint
# it, and a bidi override can read as one thing and install as another.
# Each fixture below carries one class of byte and is driven through all
# three diff sites with the real verbs; the display is then read back, and
# the encoded token has to be in it while the raw byte must not be.
#
# Fixture bytes never reach a log line: every assertion here reports a
# count or a description, so this harness's own output stays printable
# whatever the fixtures hold.
#
# No fixture carries a NUL. diff does print one, but a NUL cannot survive a
# bash variable, and the encoder treats it as the C0 control that \x01
# already stands for here.
DWD="$FAKE_HOME/diffwitness"
install -d -o "$INV" -g staff -m 755 "$DWD"
DW="$SCRATCH/diff-witness.out"
DW_ESC="$(printf '\033')"
DW_C1="$(printf '\302[\200-\237]')"   # a c1 control still in its utf-8 form

DW_LBL=() DW_NDL=()
dw_want() { DW_LBL+=("$1"); DW_NDL+=("$2"); }

dw_site() { # <desc> <cmd...>: run one verb, then read its display back
  local desc="$1"; shift
  local rc=0 i=0
  "$@" >"$DW" 2>&1 || rc=$?
  check "$desc succeeded"                  "0" "$rc"
  while [ "$i" -lt "${#DW_NDL[@]}" ]; do
    ok   "$desc shows ${DW_LBL[$i]}"       grep -qF -- "${DW_NDL[$i]}" "$DW"
    i=$((i + 1))
  done
  check "$desc leaks no raw escape"        "0" \
        "$(LC_ALL=C grep -c -- "$DW_ESC" "$DW" || true)"
  check "$desc leaks no raw c1 byte"       "0" \
        "$(LC_ALL=C grep -c -- "$DW_C1" "$DW" || true)"
}

DWE="$DWD/edit-target.txt"
printf 'plain\n' >"$DWE"
chown "$INV:staff" "$DWE"
ok   "the edit target seals"              locked lock --yes "$DWE"

dw_case() { # <name> <printf escapes> <label> <needle>...: one class, three sites
  local name="$1" bytes="$2"; shift 2
  DW_LBL=() DW_NDL=()
  while [ "$#" -ge 2 ]; do dw_want "$1" "$2"; shift 2; done
  local rc f s p
  # Content relock: adopt plain, release (which is what snapshots), write
  # the fixture, reseal. The reseal is the site that draws the diff.
  f="$DWD/$name.txt"
  rc=0
  printf 'plain\n' >"$f"
  chown "$INV:staff" "$f"
  locked lock --yes "$f" >/dev/null 2>&1 || rc=1
  locked unlock "$f" >/dev/null 2>&1 || rc=1
  printf '%b' "$bytes" >"$f"
  check "content fixture ($name) was set up" "0" "$rc"
  dw_site "content relock ($name)"        locked lock --yes "$f"
  # Anchor relock: the same round under ~/.ssh, where the tier is forced.
  s="$FAKE_HOME/.ssh/$name.cfg"
  rc=0
  printf 'plain\n' >"$s"
  chown "$INV:staff" "$s"
  locked lock --yes "$s" >/dev/null 2>&1 || rc=1
  locked unlock "$s" >/dev/null 2>&1 || rc=1
  printf '%b' "$bytes" >"$s"
  check "anchor fixture ($name) was set up" "0" "$rc"
  dw_site "anchor relock ($name)"         locked lock --yes "$s"
  # Edit: the fixture arrives as a proposal for a sealed plain file, and
  # the revert hands that file back to the next class unchanged.
  p="$PROPD/$name.proposed"
  printf '%b' "$bytes" >"$p"
  chown "$INV:staff" "$p"
  dw_site "edit --from ($name)"           locked edit --yes --from "$p" "$DWE"
  rc=0
  locked revert "$DWE" >/dev/null 2>&1 || rc=1
  check "the edit target reverted ($name)" "0" "$rc"
}

# The keep-raw needles are built from escapes so this file stays ascii and
# the bytes are exactly the ones asserted: o with diaeresis, a rightwards
# arrow, a Persian word with a zero width non-joiner between its two parts,
# and a tab between two letters.
DW_OE="$(printf '%b' '\xc3\xb6')"
DW_ARROW="$(printf '%b' '\xe2\x86\x92')"
DW_FA="$(printf '%b' '\xd9\x86\xd9\x85\xdb\x8c\xe2\x80\x8c\xd8\xae\xd9\x88\xd8\xa7\xd9\x87\xd9\x85')"
DW_TAB="$(printf '%b' 'tab\there')"

dw_case esc  'esc \x1b[31mred\x1b[0m\n' \
        'the escape as a token'             '\x{1B}'
dw_case c0   'soh \x01 cr\x0d end\n' \
        'start of heading as a token'       '\x{01}' \
        'carriage return as a token'        '\x{0D}'
dw_case del  'del \x7f end\n' \
        'delete as a token'                 '\x{7F}'
dw_case c1   'c1 \xc2\x85 end\n' \
        'the c1 control as a token'         '\x{85}'
dw_case bidi 'bidi \xe2\x80\xae evil \xe2\x81\xa6 end\n' \
        'the bidi override as a token'      '\x{202E}' \
        'the bidi isolate as a token'       '\x{2066}'
dw_case zw   'zwsp \xe2\x80\x8b lrm \xe2\x80\x8e end\n' \
        'zero width space as a token'       '\x{200B}' \
        'the left-to-right mark as a token' '\x{200E}'
dw_case bom  '\xef\xbb\xbfbom on the first line\n' \
        'a leading byte order mark'         '\x{FEFF}'
dw_case bad  'bad \xc3 end\n' \
        'the invalid byte as a token'       '\x{C3}'
dw_case keep '\xc3\xb6 \xe2\x86\x92 \xd9\x86\xd9\x85\xdb\x8c\xe2\x80\x8c\xd8\xae\xd9\x88\xd8\xa7\xd9\x87\xd9\x85 tab\there\n' \
        'o with diaeresis byte-exact'       "$DW_OE" \
        'the arrow byte-exact'              "$DW_ARROW" \
        'the Persian word with its joiner'  "$DW_FA" \
        'the tab byte-exact'                "$DW_TAB"

ok   "verify clean after the witness round" locked verify

note "== diff witness: the filter is the only thing that emits an escape =="
# The painter runs only on a tty, which this harness is not, so it is
# exercised on the very source the script runs -- lifted out of locked by
# the quotes that delimit it, never a second copy of the program.
#
# The input is shaped like real unified output, because the file headers are
# recognized by where they sit: the pair at the top, then a hunk, then a
# removed line of SQL or Lua comment (-- not a header, which the diff shows
# as --- not a header) and an added line beginning ++. Those two are content
# and have to keep the colors of a removal and an addition -- painting a
# removal as a header would be the falsification this filter exists to stop.
DWFILT="$SCRATCH/diff-filter.pl"
sed -n "/^readonly DIFF_FILTER='\$/,/^'\$/p" "$LOCKED" | sed '1d;$d' >"$DWFILT"
ok   "the filter source was lifted out"    test -s "$DWFILT"
ok   "the filter source compiles"          /usr/bin/perl -c "$DWFILT"
DWPIN="$SCRATCH/painter.in"
DWPOUT="$SCRATCH/painter.out"
printf '%b' '--- a\n+++ b\n@@ -1 +1 @@\n+add \x1b[31m\n-del\n--- not a header\n+++ not a header\n' \
      >"$DWPIN"
/usr/bin/perl "$DWFILT" 1 <"$DWPIN" >"$DWPOUT" 2>&1 || true
check "an addition line opens green"       "1" \
      "$(grep -cF -- "${DW_ESC}[32m+add" "$DWPOUT" || true)"
check "the token wears reverse video"      "1" \
      "$(grep -cF -- "${DW_ESC}[7m\\x{1B}${DW_ESC}[27m" "$DWPOUT" || true)"
check "reverse video ends, the line color does not" "1" \
      "$(grep -cF -- "[31m${DW_ESC}[0m" "$DWPOUT" || true)"
check "a removal line opens red"           "1" \
      "$(grep -cF -- "${DW_ESC}[31m-del" "$DWPOUT" || true)"
check "a hunk header opens cyan"           "1" \
      "$(grep -cF -- "${DW_ESC}[36m@@" "$DWPOUT" || true)"
check "a file header goes magenta"         "1" \
      "$(grep -cF -- "${DW_ESC}[1;35m--- a" "$DWPOUT" || true)"
check "its mate goes magenta too"          "1" \
      "$(grep -cF -- "${DW_ESC}[1;35m+++ b" "$DWPOUT" || true)"
check "a removal that reads like a header opens red" "1" \
      "$(grep -cF -- "${DW_ESC}[31m--- not a header" "$DWPOUT" || true)"
check "an addition that reads like a header opens green" "1" \
      "$(grep -cF -- "${DW_ESC}[32m+++ not a header" "$DWPOUT" || true)"
check "and neither of them goes magenta"   "0" \
      "$(grep -cF -- "${DW_ESC}[1;35m--- not a header" "$DWPOUT" || true)"
/usr/bin/perl "$DWFILT" 0 <"$DWPIN" >"$DWPOUT" 2>&1 || true
check "color off emits no escape at all"   "0" \
      "$(LC_ALL=C grep -c -- "$DW_ESC" "$DWPOUT" || true)"
check "color off still encodes the token"  "1" \
      "$(grep -cF -- '\x{1B}' "$DWPOUT" || true)"

note "== cli: dry-run mutates nothing =="
DR="$FAKE_HOME/dryrun.txt"
as_user /bin/sh -c "echo dr > '$DR'"
ok   "lock --dry-run --yes"              locked lock --dry-run --yes "$DR"
check "dry-run left owner"               "$INV" "$(owner_of "$DR")"
check "dry-run left flags"               "" "$(flags_of "$DR")"
deny "dry-run wrote no meta or snapshot" \
     /bin/sh -c "ls '$SNAPROOT/$INV' | grep -q dryrun"

note "== cli: chain stop node whose group is not wheel =="
# The real ~ walk stops at /Users, which macOS ships root:admin 755. The
# stop-node check pins the owner and the mode, not the group name, so this
# shape must lock exactly like a root:wheel stop node does.
locked_home() { # <home> <args...>: locked with a different LOCKED_USER_HOME
  local h="$1"; shift
  env SNAPSHOTS_ROOT="$SNAPROOT" \
      INSTALL_TARGET="$SCRATCH/not-installed" \
      LOCKED_HELPER="$HELPER" \
      LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
      LOCKED_USER_HOME="$h" \
      LOCKED_ALERT_DIR="$ALERTS" \
      SUDO_USER="$INV" \
      /bin/bash "$LOCKED" "$@"
}
ADMSTOP="$SCRATCH/usersdir"
install -d -m 755 -o root -g admin "$ADMSTOP"
ADMHOME="$ADMSTOP/home"
install -d -o "$INV" -g staff "$ADMHOME"
ADMCFG="$ADMHOME/zshrc"
as_user /bin/sh -c "printf 'setopt nomatch\n' > '$ADMCFG'"
ok   "lock under a root:admin stop node"  locked_home "$ADMHOME" lock --yes "$ADMCFG"
check "leaf sealed uchg"                  "uchg" "$(flags_of "$ADMCFG")"
check "home anchored sappnd"              "sappnd" "$(flags_of "$ADMHOME")"
check "stop node left untouched"          "" "$(flags_of "$ADMSTOP")"
ok   "verify clean with admin stop node"  locked_home "$ADMHOME" verify

note "== cli: the interactive plan gate seals the whole chain (no --yes) =="
# One gate per leaf: the plan is derived and printed first, and the single
# [y/N] after it covers the leaf AND every ancestor in the list. A second
# prompt would leave this script waiting, so the case still guards the
# fd-3 chain feed -- the apply loop must never read the chain text as an
# answer -- and now also guards against a seal that asks again on its own.
if [ -x /usr/bin/expect ]; then
  TTYSTOP="$SCRATCH/ttyusers"
  install -d -m 755 -o root -g wheel "$TTYSTOP"
  TTYHOME="$TTYSTOP/home"
  install -d -o "$INV" -g staff "$TTYHOME"
  TTYCFG="$TTYHOME/zshenv"
  as_user /bin/sh -c "printf 'export EDITOR=vi\n' > '$TTYCFG'"
  TTYEXP="$SCRATCH/tty-lock.exp"
  cat >"$TTYEXP" <<EOF
set timeout 15
# The two keys inside [y/N] are painted bold blue, so SGR runs sit between
# the characters and the bracketed literal is no longer contiguous. Each
# run is optional, so this same pattern still matches the uncolored prompt
# (NO_COLOR, or a redirected stderr).
set ynp {\[(\x1b\[[0-9;]*m)*y(\x1b\[[0-9;]*m)*/(\x1b\[[0-9;]*m)*N(\x1b\[[0-9;]*m)*\]}
spawn env SNAPSHOTS_ROOT=$SNAPROOT INSTALL_TARGET=$SCRATCH/not-installed LOCKED_HELPER=$HELPER LOCKED_LOCK_ACCOUNT=$LOCK_ACCT LOCKED_USER_HOME=$TTYHOME LOCKED_ALERT_DIR=$ALERTS SUDO_USER=$INV /bin/bash $LOCKED lock $TTYCFG
expect {
  timeout { exit 1 }
  eof     { exit 1 }
  "plan for "
}
expect {
  timeout { exit 1 }
  eof     { exit 1 }
  "2 nodes to change"
}
expect {
  timeout { exit 1 }
  eof     { exit 1 }
  -re \$ynp
}
send "y\r"
expect {
  timeout { exit 1 }
  eof
}
catch wait result
exit [lindex \$result 3]
EOF
  ok   "interactive lock answers one gate for the chain" /usr/bin/expect -f "$TTYEXP"
  check "interactive leaf sealed uchg"         "uchg" "$(flags_of "$TTYCFG")"
  check "interactive home anchored sappnd"     "sappnd" "$(flags_of "$TTYHOME")"

  # A decline at the gate is a decline of the whole plan: the leaf is not
  # sealed, and the ancestor the plan listed as already locked stays as it
  # was. sappnd on the home lets a new entry be created under it, which is
  # what the placement/anchor tiers are for.
  TTYDEC="$TTYHOME/declined.txt"
  as_user /bin/sh -c "printf 'x\n' > '$TTYDEC'"
  TTYEXP2="$SCRATCH/tty-decline.exp"
  cat >"$TTYEXP2" <<EOF
set timeout 15
spawn env SNAPSHOTS_ROOT=$SNAPROOT INSTALL_TARGET=$SCRATCH/not-installed LOCKED_HELPER=$HELPER LOCKED_LOCK_ACCOUNT=$LOCK_ACCT LOCKED_USER_HOME=$TTYHOME LOCKED_ALERT_DIR=$ALERTS SUDO_USER=$INV /bin/bash $LOCKED lock $TTYDEC
expect {
  timeout { exit 1 }
  eof     { exit 1 }
  "1 node to change"
}
send "n\r"
expect {
  timeout { exit 1 }
  eof
}
catch wait result
exit [lindex \$result 3]
EOF
  TTYDRC=0
  /usr/bin/expect -f "$TTYEXP2" >/dev/null 2>&1 || TTYDRC=$?
  check "a typed decline exits 2"              "2" "$TTYDRC"
  check "the declined leaf keeps its owner"    "$INV" "$(owner_of "$TTYDEC")"
  check "the declined leaf carries no flag"    "" "$(flags_of "$TTYDEC")"
  check "the home anchor is still sealed"      "sappnd" "$(flags_of "$TTYHOME")"
else
  note "  skip  interactive plan gate (no expect on this machine)"
fi

note "== cli: no-arg status lists the populated pool =="
# Same fixtures as above, still in the pool: the content leaf, the home
# anchor, and the content dir (unlocked here only to render that state).
ok   "status lists the pool"             locked status
locked status >"$POOL" 2>&1
ok   "listing names the locked leaf"     grep -qF "✓  $CFG (content uchg)" "$POOL"
ok   "listing names the home anchor"     grep -qF "✓  $FAKE_HOME (anchor sappnd)" "$POOL"
ok   "unlock dir to expose its state"    locked unlock "$CD"
locked status >"$POOL" 2>&1
ok   "listing marks the unlocked node"   grep -qF "!  $CD (content, unlocked)" "$POOL"
ok   "relock dir after the listing"      locked lock --yes "$CD"

note "== cli: pool permissions =="
# Root re-applies these on every invocation (which is also how an older 700
# deployment migrates itself). They are what makes unprivileged status
# possible without exposing either the user list or any file content.
check "snapshots root is 711"            "711" "$(stat -f '%OLp' "$SNAPROOT")"
check "per-user pool dir is 750"         "750" "$(stat -f '%OLp' "$SNAPROOT/$INV")"
POOL_METAS=("$SNAPROOT/$INV"/*.meta)
POOL_SNAPS=("$SNAPROOT/$INV"/*.snap)
if [ "${#POOL_METAS[@]}" -gt 0 ] && [ "${#POOL_SNAPS[@]}" -gt 0 ]; then
  check "meta is group-readable 640"     "640" "$(stat -f '%OLp' "${POOL_METAS[0]}")"
  check "snapshot content stays 600"     "600" "$(stat -f '%OLp' "${POOL_SNAPS[0]}")"
else
  FAIL=$((FAIL + 1)); note "  FAIL  pool has no meta/snap to check modes on"
fi

note "== cli: unprivileged status =="
# The repo lives under the invoker's home, which no other account may
# traverse, so the lock account runs the same bytes from a root-owned,
# world-readable copy.
SCRIPT_COPY="$SCRATCH/locked-copy"
install -m 755 -o root -g wheel "$LOCKED" "$SCRIPT_COPY"

locked_as() { # <user> <args...>: run locked unprivileged AS <user>.
  # The seams ride the command line because sudo's env_reset drops inherited
  # variables (the alert writer hands its data across the same way).
  # SUDO_USER is deliberately not passed: sudo sets it to root here, and the
  # non-root branch must ignore it and derive the invoker from the real uid.
  local u="$1"; shift
  sudo -u "$u" /usr/bin/env \
      SNAPSHOTS_ROOT="$SNAPROOT" \
      INSTALL_TARGET="$SCRATCH/not-installed" \
      LOCKED_HELPER="$HELPER" \
      LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
      LOCKED_USER_HOME="$FAKE_HOME" \
      LOCKED_ALERT_DIR="$ALERTS" \
      /bin/bash "$SCRIPT_COPY" "$@"
}

MARKER="$SCRATCH/unpriv-marker"
: >"$MARKER"

# The invoker is not in the daemon group, so the pool dir the stand-in lock
# account owns is exactly the cross-user shape: reachable by name, entirely
# unreadable. Fail closed with one line, not a cascade of glob noise.
refuse "unprivileged status refuses an unreadable pool" "cannot read pool for $INV" \
       locked_as "$INV" status
refuse "same refusal for status with a path"            "cannot read pool for $INV" \
       locked_as "$INV" status "$CFG"

# As the lock account the derived pool is daemon's own, which does not
# exist -- so this drives the whole non-root branch (uid-derived invoker,
# provisioning skipped, nothing written) down to the empty-pool listing.
ok   "unprivileged status as the lock account"  locked_as "$LOCK_ACCT" status
locked_as "$LOCK_ACCT" status >"$POOL" 2>&1
ok   "it lists the lock account's OWN pool"     grep -qF "pool for $LOCK_ACCT is empty" "$POOL"

check "unprivileged status wrote nothing"       "" \
      "$(/usr/bin/find "$SNAPROOT" -newer "$MARKER" -print)"

# ---- 3. nix deploy guards --------------------------------------------------
#
# The store-ancestry acceptance and the setup refusal ride the same seams
# as everything above. Fixtures needing a STRICT root-owned chain live in
# ANC under /var/db (root:wheel 755 all the way up); /private/tmp's 1777
# would fail the walk on its own.

note "== nix deploy guards: install ancestry =="
ANC="$(mktemp -d /private/var/db/locked-harness-ancestry.XXXXXX)"
chmod 755 "$ANC"

locked_it() { # <install_target> <args...>: locked with a specific INSTALL_TARGET
  local it="$1"; shift
  env SNAPSHOTS_ROOT="$SNAPROOT" \
      INSTALL_TARGET="$it" \
      LOCKED_HELPER="$HELPER" \
      LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
      LOCKED_USER_HOME="$FAKE_HOME" \
      LOCKED_ALERT_DIR="$ALERTS" \
      SUDO_USER="$INV" \
      /bin/bash "$LOCKED" "$@"
}

# Accepted: strict root:wheel 755 chain (the /usr/local shape).
install -d -m 755 -o root -g wheel "$ANC/ok/sbin"
install -m 755 -o root -g wheel /dev/null "$ANC/ok/sbin/locked"
ok   "strict root-755 ancestry accepted"  locked_it "$ANC/ok/sbin/locked" verify --quiet

# Accepted: root owner, group admin, still no group write (the /Users shape).
# The group name is not part of the rule; the missing write bit is.
install -d -m 755 -o root -g admin "$ANC/adm/sbin"
install -m 755 -o root -g admin /dev/null "$ANC/adm/sbin/locked"
ok   "root:admin 755 ancestry accepted"   locked_it "$ANC/adm/sbin/locked" verify --quiet

# Refused: a non-root OWNER stays fatal however strict the mode is -- the
# widened group rule must not have loosened the owner check.
install -d -m 755 -o "$INV" -g staff "$ANC/uown"
install -d -m 755 -o root -g wheel "$ANC/uown/sbin"
install -m 755 -o root -g wheel /dev/null "$ANC/uown/sbin/locked"
refuse "non-root-owned ancestor refused" "expected root" \
       locked_it "$ANC/uown/sbin/locked" verify --quiet

# Refused: group-writable ancestor. Sticky must NOT rescue it outside the
# literal /nix/store -- the carve-out may never weaken /usr/local-shaped
# paths. (%OLp strips the sticky bit, so both report mode 775.)
install -d -m 775 -o root -g wheel "$ANC/gw"
install -d -m 755 -o root -g wheel "$ANC/gw/sbin"
install -m 755 -o root -g wheel /dev/null "$ANC/gw/sbin/locked"
refuse "group-writable ancestor refused" "mode 775" \
       locked_it "$ANC/gw/sbin/locked" verify --quiet
install -d -m 1775 -o root -g wheel "$ANC/sticky"
install -d -m 755 -o root -g wheel "$ANC/sticky/sbin"
install -m 755 -o root -g wheel /dev/null "$ANC/sticky/sbin/locked"
refuse "sticky+group-write refused outside /nix/store" "mode 775" \
       locked_it "$ANC/sticky/sbin/locked" verify --quiet

# The REAL chain is walked too: a root-owned symlink pointing into a
# user-writable directory must be refused, and the same link shape into
# the strict chain is the control.
install -d -m 777 -o root -g wheel "$ANC/userland"
install -m 755 -o root -g wheel /dev/null "$ANC/userland/locked"
install -d -m 755 -o root -g wheel "$ANC/links"
ln -s "$ANC/userland/locked" "$ANC/links/via-userland"
refuse "symlink into user-writable real chain refused" "mode 777" \
       locked_it "$ANC/links/via-userland" verify --quiet
ln -s "$ANC/ok/sbin/locked" "$ANC/links/via-ok"
ok   "control: symlink into root-755 real chain accepted" \
     locked_it "$ANC/links/via-ok" verify --quiet

# Symlink ANCESTORS are judged on owner alone: root-owned passes (the
# system-profile shape), user-owned is refused.
ln -s "$ANC/ok/sbin" "$ANC/links/root-sym"
ok   "control: root-owned symlink ancestor accepted" \
     locked_it "$ANC/links/root-sym/locked" verify --quiet
ln -s "$ANC/ok/sbin" "$ANC/links/user-sym"
chown -h "$INV" "$ANC/links/user-sym"
refuse "non-root symlink ancestor refused" "symlink owned by" \
       locked_it "$ANC/links/user-sym/locked" verify --quiet

# On a nix machine the deployed shape is live-testable: the profile path
# (symlink components down to a store path) and the resolved store path
# (/nix/store itself root-owned 1775) must both pass.
if [ -d /nix/store ] && [ -d /run/current-system/sw/bin ]; then
  PROFILE_BIN="$(/usr/bin/find /run/current-system/sw/bin/. -mindepth 1 -maxdepth 1 -print 2>/dev/null | /usr/bin/head -1)"
  if [ -n "$PROFILE_BIN" ]; then
    ok "system-profile install path accepted" locked_it "$PROFILE_BIN" verify --quiet
    ok "resolved store path accepted"         locked_it "$(readlink -f "$PROFILE_BIN")" verify --quiet
  fi
else
  note "  skip  nix store ancestry (no nix on this machine)"
fi

note "== nix deploy guards: setup refusal =="
# The INSTALL_TARGET prefix alone must trigger the refusal. The probe
# target is routed THROUGH an existing regular file where possible, so if
# the refusal ever regressed, setup's first step (install -d) dies on
# ENOTDIR before mutating anything -- and the wrong message fails the
# needle, catching the regression.
SETUP_IT=/run/current-system/nowhere/locked
if [ -e /run/current-system ]; then
  CS_FILE="$(/usr/bin/find /run/current-system/. -mindepth 1 -maxdepth 1 -type f -print 2>/dev/null | /usr/bin/head -1)"
  if [ -n "$CS_FILE" ]; then SETUP_IT="$CS_FILE/x/locked"; fi
fi
refuse "setup refused when nix-managed" "nix-managed" locked_it "$SETUP_IT" setup

# ---- 4. mediated placement verbs -------------------------------------------
#
# Deliberately last: this section leaves retired, suspended and re-keyed
# records in the pool, and section 3 walks the whole pool with `verify
# --quiet` on every one of its assertions.
#
# Fixtures live under MED, whose stop node is SCRATCH (root:wheel 755).
# Placement dirs are created 777 so the invoker keeps write through the
# OTHER bits: with the daemon stand-in they are not in the lock group, and
# do_trash_one's parent-writability pre-check must pass for the ordinary
# cases the way it does for a real placement dir's group write.

note "== mediated: fixtures =="
MED="$SCRATCH/med"
install -d -o "$INV" -g staff -m 777 "$MED"
OUTF="$SCRATCH/mediated-out.txt"

# Pool-file locations, mirroring locked's encode()/snap_paths().
enc_path() { printf '%s' "$1" | sed -e 's|%|%25|g' -e 's|/|%2F|g'; }
meta_path() { printf '%s' "$SNAPROOT/$INV/$(enc_path "$1").meta"; }
snap_path() { printf '%s' "$SNAPROOT/$INV/$(enc_path "$1").snap"; }
meta_get() { # <path> <field>: empty when there is no record
  local m
  m="$(meta_path "$1")"
  [ -f "$m" ] || return 0
  awk -F= -v f="$2" '$1==f{print substr($0, length(f)+2); exit}' "$m"
}
put_id() { # <path> <id>: rewrite just the id field of an existing record
  local m
  m="$(meta_path "$1")"
  sed "s|^id=.*|id=$2|" "$m" >"$m.tmp"
  mv -f "$m.tmp" "$m"
  chown "$LOCK_ACCT:$LOCK_ACCT" "$m"
  chmod 640 "$m"
}
id_form_of() { # <id> -> vol|dev, the same test the script makes
  case "${1%%.*}" in
    ????????-????-????-????-????????????) printf 'vol' ;;
    *)                                    printf 'dev' ;;
  esac
}
put_meta() { # <path> <key=value>...: craft a record write_meta would accept
  local m
  m="$(meta_path "$1")"
  shift
  printf '%s\n' "$@" >"$m"
  chown "$LOCK_ACCT:$LOCK_ACCT" "$m"
  chmod 640 "$m"
}

note "== mediated rm: plain entries under a sealed parent =="
RMD="$MED/rmarea"
install -d -o "$INV" -g staff -m 777 "$RMD"
as_user /bin/sh -c "echo v > '$RMD/victim.txt'"
as_user mkdir -- "$RMD/emptydir"
chflags -- uappnd "$RMD"
deny "raw delete blocked by the sealed parent" as_user rm -f -- "$RMD/victim.txt"
ok   "locked rm removes a plain file"          locked rm --yes "$RMD/victim.txt"
deny "the file is gone"                        test -e "$RMD/victim.txt"
check "parent flag restored after rm"          "uappnd" "$(flags_of "$RMD")"
ok   "locked rm removes an empty directory"    locked rm --yes "$RMD/emptydir"
deny "the empty directory is gone"             test -e "$RMD/emptydir"
# sappnd is the other sealed-parent shape (the anchor tier uses it on ~).
chflags -- nouappnd "$RMD"
as_user /bin/sh -c "echo v2 > '$RMD/victim2.txt'"
chflags -- sappnd "$RMD"
deny "raw delete blocked by an sappnd parent"  as_user rm -f -- "$RMD/victim2.txt"
ok   "locked rm works under sappnd too"        locked rm --yes "$RMD/victim2.txt"
check "sappnd restored after rm"               "sappnd" "$(flags_of "$RMD")"
chflags -- nosappnd "$RMD"

note "== batch grammar: [n/N] counters, summary tail, per-item failure =="
# terminal-output batch rules: a counter per item, one summary tail, and a
# failed (or declined) item affects only itself -- the rest still run.
as_user /bin/sh -c "echo b1 > '$RMD/b1.txt'; echo b3 > '$RMD/b3.txt'"
chflags -- uappnd "$RMD"
BRC=0
locked rm --yes "$RMD/b1.txt" "$RMD/missing.txt" "$RMD/b3.txt" >"$OUTF" 2>&1 || BRC=$?
check "mixed batch exits 3 (partial failure)"  "3" "$BRC"
deny "batch item 1 removed"                    test -e "$RMD/b1.txt"
deny "batch item 3 removed after the failure"  test -e "$RMD/b3.txt"
ok   "batch prints [1/3] counter"              grep -qF "[1/3] $RMD/b1.txt" "$OUTF"
ok   "batch prints [3/3] counter"              grep -qF "[3/3] $RMD/b3.txt" "$OUTF"
ok   "batch summary tail names the counts"     grep -qxF "2 removed, 0 declined, 1 failed" "$OUTF"
as_user /bin/sh -c "echo b4 > '$RMD/b4.txt'; echo b5 > '$RMD/b5.txt'"
BRC=0
locked rm --yes "$RMD/b4.txt" "$RMD/b5.txt" >"$OUTF" 2>&1 || BRC=$?
check "clean batch exits 0"                    "0" "$BRC"
ok   "clean batch summary"                     grep -qxF "2 removed, 0 declined, 0 failed" "$OUTF"
BRC=0
locked rm --yes "$RMD/single-missing.txt" >"$OUTF" 2>&1 || BRC=$?
check "single-path failure still exits 3"      "3" "$BRC"
deny "single-path invocation has no counter"   grep -q '^\[1/1\]' "$OUTF"
deny "single-path invocation has no summary"   grep -q 'declined, .* failed' "$OUTF"
chflags -- nouappnd "$RMD"

note "== mediated rm: --recursive =="
TREE="$RMD/tree"
as_user mkdir -p -- "$TREE/sub"
as_user /bin/sh -c "echo a > '$TREE/sub/a.txt'"
SURVIVOR="$MED/survivor.txt"
as_user /bin/sh -c "echo s > '$SURVIVOR'"
as_user ln -s -- "$SURVIVOR" "$TREE/link"
chflags -R -- uchg "$TREE/sub"
chflags -- uappnd "$RMD"
refuse "non-empty dir refused without --recursive" "sudo locked rm --recursive $TREE" \
       locked rm --yes "$TREE"
ok   "the tree survived the refusal"           test -d "$TREE"
ok   "rm --recursive takes the whole tree"     locked rm --yes --recursive "$TREE"
deny "the tree is gone"                        test -e "$TREE"
ok   "the symlink's target survived"           test -f "$SURVIVOR"
check "parent flag restored after recursive rm" "uappnd" "$(flags_of "$RMD")"
chflags -- nouappnd "$RMD"

note "== mediated rm: pool records =="
POOLF="$MED/pool-leaf.txt"
as_user /bin/sh -c "echo p > '$POOLF'"
ok   "lock a content leaf in the mediated area" locked lock --yes "$POOLF"
check "the mediated area became placement"     "uappnd" "$(flags_of "$MED")"
ok   "locked rm on a pool node"                locked rm --yes "$POOLF"
deny "the pool node is gone"                   test -e "$POOLF"
check "its record is retired"                  "retired" "$(meta_get "$POOLF" state)"
check "retired via rm"                         "rm" "$(meta_get "$POOLF" via)"
check "retired by the invoker"                 "$INV" "$(meta_get "$POOLF" by)"
ok   "the retirement carries a timestamp"      test -n "$(meta_get "$POOLF" at)"

# The subtree gate only gets a word in edgewise when the emptiness check
# above has nothing to say, so this fixture is emptied out on disk first --
# a directory whose records outlived its contents.
SUBT="$MED/subtree"
as_user mkdir -p -- "$SUBT/inner"
as_user /bin/sh -c "echo q > '$SUBT/inner/q.txt'"
ok   "lock a leaf deep in a subtree"           locked lock --yes "$SUBT/inner/q.txt"
chflags -- nouappnd "$SUBT/inner"
chflags -- nouchg "$SUBT/inner/q.txt"
rm -f -- "$SUBT/inner/q.txt"
chflags -- nouappnd "$SUBT"
rmdir -- "$SUBT/inner"
locked rm --yes "$SUBT" >"$OUTF" 2>&1 || true
ok   "rm refuses a subtree holding records"    grep -qF "locked records live under it" "$OUTF"
ok   "the refusal lists the records under it"  grep -qF "$SUBT/inner/q.txt" "$OUTF"
ok   "the refusal names --recursive"           grep -qF "sudo locked rm --recursive $SUBT" "$OUTF"
ok   "the subtree survived the refusal"        test -d "$SUBT"
ok   "rm --recursive retires the whole set"    locked rm --yes --recursive "$SUBT"
deny "the subtree is gone"                     test -e "$SUBT"
check "the leaf record is retired"             "retired" "$(meta_get "$SUBT/inner/q.txt" state)"
check "the inner record is retired"            "retired" "$(meta_get "$SUBT/inner" state)"
check "the subtree's own record is retired"    "retired" "$(meta_get "$SUBT" state)"

note "== mediated mv =="
# MVB is sealed the way a real placement dir is -- by adopting a leaf inside
# it -- because a directory that already wears uappnd cannot be adopted at
# all: the flag refuses the chown and chmod seal_placement performs. MVA
# never holds a pool node, so a bare chflags is the right shape for it.
MVA="$MED/mvsrc"
MVB="$MED/mvdst"
install -d -o "$INV" -g staff -m 777 "$MVA"
install -d -o "$INV" -g staff -m 777 "$MVB"
as_user /bin/sh -c "echo m > '$MVA/a.txt'"
RKF="$MVB/recorded.txt"
as_user /bin/sh -c "echo r > '$RKF'"
ok   "lock a node in the destination area"     locked lock --yes "$RKF"
check "the destination parent is sealed"       "uappnd" "$(flags_of "$MVB")"
chflags -- uappnd "$MVA"
deny "raw rename blocked by the sealed parent" as_user mv -- "$MVA/a.txt" "$MVA/b.txt"
ok   "locked mv renames inside one parent"     locked mv "$MVA/a.txt" "$MVA/b.txt"
ok   "the new name is there"                   test -f "$MVA/b.txt"
deny "the old name is gone"                    test -e "$MVA/a.txt"
check "source parent flag restored"            "uappnd" "$(flags_of "$MVA")"
ok   "locked mv across sealed parents"         locked mv "$MVA/b.txt" "$MVB/b.txt"
ok   "it landed in the destination parent"     test -f "$MVB/b.txt"
check "source parent still sealed"             "uappnd" "$(flags_of "$MVA")"
check "destination parent still sealed"        "uappnd" "$(flags_of "$MVB")"
as_user /bin/sh -c "echo z > '$MVB/taken.txt'"
refuse "mv never clobbers an existing dest"    "never clobbers" \
       locked mv "$MVB/b.txt" "$MVB/taken.txt"
ok   "both entries survived the refusal"       test -f "$MVB/b.txt"
refuse "mv refuses a missing destination parent" "cannot resolve $MED/no-such-dir" \
       locked mv "$MVB/b.txt" "$MED/no-such-dir/b.txt"
refuse "mv refuses a non-directory dest parent" "$MVB/taken.txt is not a directory" \
       locked mv "$MVB/b.txt" "$MVB/taken.txt/b.txt"
# Cross-device is live-testable without mounting anything: devfs is a second
# filesystem on every macOS, and the refusal lands before any window opens.
refuse "mv refuses a cross-device destination" "on different filesystems" \
       locked mv "$MVB/b.txt" "/dev/locked-harness-xdev"
deny "nothing was created on the other device" test -e "/dev/locked-harness-xdev"
ok   "the source survived the xdev refusal"    test -f "$MVB/b.txt"

RKID="$(meta_get "$RKF" id)"
ok   "locked mv re-keys the record"            locked mv "$RKF" "$MVB/renamed.txt"
deny "the old record key is gone"              test -e "$(meta_path "$RKF")"
ok   "the new record key exists"               test -f "$(meta_path "$MVB/renamed.txt")"
ok   "the snapshot moved with it"              test -f "$(snap_path "$MVB/renamed.txt")"
check "the recorded identity is unchanged"     "$RKID" "$(meta_get "$MVB/renamed.txt" id)"
check "the record is still locked"             "locked" "$(meta_get "$MVB/renamed.txt" state)"
check "the moved node is still sealed"         "uchg" "$(flags_of "$MVB/renamed.txt")"
ok   "verify clean after the move"             locked verify --quiet

note "== rekey: record-only repair =="
RKD="$MED/rekeyarea"
install -d -o "$INV" -g staff -m 777 "$RKD"
as_user /bin/sh -c "echo k > '$RKD/k.txt'"
as_user /bin/sh -c "echo o > '$RKD/other.txt'"
ok   "lock the node to be re-keyed"            locked lock --yes "$RKD/k.txt"
refuse "rekey refuses a node the record does not describe" \
       "not the one that record describes" \
       locked rekey "$RKD/k.txt" "$RKD/other.txt"
ok   "the record stayed where it was"          test -f "$(meta_path "$RKD/k.txt")"
# Move it by other means: exactly the situation rekey exists to repair.
chflags -- nouappnd "$RKD"
chflags -- nouchg "$RKD/k.txt"
mv -- "$RKD/k.txt" "$RKD/moved.txt"
chflags -- uchg "$RKD/moved.txt"
chflags -- uappnd "$RKD"
ok   "rekey accepts the very node the record describes" \
     locked rekey "$RKD/k.txt" "$RKD/moved.txt"
deny "the old key is gone"                     test -e "$(meta_path "$RKD/k.txt")"
check "the re-keyed record is still locked"    "locked" "$(meta_get "$RKD/moved.txt" state)"
ok   "verify clean after the re-key"           locked verify --quiet

# A pre-0.6.0 record still describes its node: the inode is what proves it,
# so the repair rekey exists for must not fail over the id's spelling.
put_id "$RKD/moved.txt" "999.$(stat -f '%i' "$RKD/moved.txt")"
chflags -- nouappnd "$RKD"
chflags -- nouchg "$RKD/moved.txt"
mv -- "$RKD/moved.txt" "$RKD/moved2.txt"
chflags -- uchg "$RKD/moved2.txt"
chflags -- uappnd "$RKD"
ok   "rekey accepts a legacy dev.ino record" \
     locked rekey "$RKD/moved.txt" "$RKD/moved2.txt"
ok   "verify clean after the legacy re-key"    locked verify --quiet

RKT="$MED/rekeytree"
RKT2="$MED/rekeytree2"
as_user mkdir -p -- "$RKT/in"
as_user /bin/sh -c "echo t > '$RKT/in/t.txt'"
ok   "lock a leaf under the tree to be moved"  locked lock --yes "$RKT/in/t.txt"
chflags -- nouappnd "$MED"
chflags -- nouappnd "$RKT"
mv -- "$RKT" "$RKT2"
chflags -- uappnd "$RKT2"
chflags -- uappnd "$MED"
refuse "rekey refuses a recorded subtree without --recursive" \
       "locked records live under it" \
       locked rekey "$RKT" "$RKT2"
ok   "rekey --recursive moves the whole set"   locked rekey --recursive "$RKT" "$RKT2"
deny "the old leaf key is gone"                test -e "$(meta_path "$RKT/in/t.txt")"
check "the moved leaf record is locked"        "locked" "$(meta_get "$RKT2/in/t.txt" state)"
check "the moved tree record is locked"        "locked" "$(meta_get "$RKT2" state)"
ok   "verify clean after the recursive re-key" locked verify --quiet

note "== tombstone: human assertion =="
TSF="$MED/tombstone.txt"
as_user /bin/sh -c "echo t > '$TSF'"
ok   "lock the node to be tombstoned"          locked lock --yes "$TSF"
refuse "tombstone refuses while the path exists" "present on disk" \
       locked tombstone --yes "$TSF"
check "the record is untouched"                "locked" "$(meta_get "$TSF" state)"
chflags -- nouappnd "$MED"
chflags -- nouchg "$TSF"
rm -f -- "$TSF"
chflags -- uappnd "$MED"
ok   "tombstone retires an absent record"      locked tombstone --yes "$TSF"
check "state is retired"                       "retired" "$(meta_get "$TSF" state)"
check "provenance is the assertion"            "assertion" "$(meta_get "$TSF" via)"
check "asserted by the invoker"                "$INV" "$(meta_get "$TSF" by)"
locked tombstone --yes "$TSF" >"$OUTF" 2>&1 || true
ok   "tombstone is idempotent"                 grep -qF "already retired: $TSF" "$OUTF"
check "still retired via assertion"            "assertion" "$(meta_get "$TSF" via)"

note "== helper exit codes: stand-in helpers =="
# The fakes live in the same root-owned dir as the real one, so they pass
# verify_helper and the only thing under test is how locked reads what a
# helper says. Each one is a shell script; locked execs it the same way.
mkfake() { # <name> <sh line>...: install a stand-in helper, print its path
  local name="$1" tmp
  shift
  tmp="$SCRATCH/fake-build"
  { echo '#!/bin/sh'; printf '%s\n' "$@"; } >"$tmp"
  install -m 755 -o root -g wheel "$tmp" "$HELPERDIR/$name"
  rm -f -- "$tmp"
  printf '%s' "$HELPERDIR/$name"
}
locked_fake() { # <helper> <args...>: locked with a stand-in LOCKED_HELPER
  local h="$1"; shift
  env SNAPSHOTS_ROOT="$SNAPROOT" \
      INSTALL_TARGET="$SCRATCH/not-installed" \
      LOCKED_HELPER="$h" \
      LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
      LOCKED_USER_HOME="$FAKE_HOME" \
      LOCKED_ALERT_DIR="$ALERTS" \
      SUDO_USER="$INV" \
      /bin/bash "$LOCKED" "$@"
}

FKD="$MED/fakearea"
install -d -o "$INV" -g staff -m 777 "$FKD"
as_user /bin/sh -c "echo f > '$FKD/t.txt'"
ok   "lock the stand-in helper's target"       locked lock --yes "$FKD/t.txt"

F2="$(mkfake exit2 'exit 2')"
refuse "exit 2 reads as an identity refusal"   "not the one recorded" \
       locked_fake "$F2" rm --yes "$FKD/t.txt"
check "exit 2 left the record alone"           "locked" "$(meta_get "$FKD/t.txt" state)"
ok   "exit 2 left the file alone"              test -f "$FKD/t.txt"

F3="$(mkfake exit3 'exit 3')"
refuse "exit 3 reads as a failed operation"    "the operation did not happen" \
       locked_fake "$F3" rm --yes "$FKD/t.txt"
check "exit 3 left the record alone"           "locked" "$(meta_get "$FKD/t.txt" state)"

F4="$(mkfake exit4 'exit 4')"
refuse "exit 4 reads as a malformed request"   "refused the request as malformed" \
       locked_fake "$F4" rm --yes "$FKD/t.txt"

F5="$(mkfake exit5 "printf 'window-open\t%s\n' '$FKD'" 'exit 5')"
locked_fake "$F5" rm --yes "$FKD/t.txt" >"$OUTF" 2>&1 || true
ok   "exit 5 raises the window-open alarm"     grep -qF "could not restore the flags it lifted" "$OUTF"
ok   "exit 5 names the window left open"       grep -qF "window left open on: $FKD" "$OUTF"
check "exit 5 left the record alone"           "locked" "$(meta_get "$FKD/t.txt" state)"
deny "no backstop alarm while the flags are intact" \
     grep -qF "came back with flags" "$OUTF"

F5B="$(mkfake exit5-clears \
  "chflags -- nouappnd '$FKD'" \
  "printf 'window-open\t%s\n' '$FKD'" \
  'exit 5')"
locked_fake "$F5B" rm --yes "$FKD/t.txt" >"$OUTF" 2>&1 || true
ok   "the backstop notices a cleared parent"   grep -qF "came back with flags 'none', expected 'uappnd'" "$OUTF"
ok   "the backstop re-seals from its captured word" \
     grep -qF "re-sealed by the backstop: $FKD (uappnd)" "$OUTF"
check "the parent really is sealed again"      "uappnd" "$(flags_of "$FKD")"
check "the record still says locked"           "locked" "$(meta_get "$FKD/t.txt" state)"

F6="$(mkfake exit6 \
  "chflags -- nouappnd '$FKD'" \
  "chflags -- nouchg '$FKD/t.txt'" \
  "rm -f -- '$FKD/t.txt'" \
  "chflags -- uappnd '$FKD'" \
  "printf 'anomaly\t+\tstranger.txt\t16777233:424242\n'" \
  'exit 6')"
if locked_fake "$F6" rm --yes "$FKD/t.txt" >"$OUTF" 2>&1; then rc6=0; else rc6=$?; fi
check "exit 6 exits 3 (partial failure)"       "3" "$rc6"
ok   "exit 6 prints the anomaly banner"        grep -qF "entries other than the target changed inside the window" "$OUTF"
ok   "exit 6 prints the anomaly line"          grep -qF "stranger.txt" "$OUTF"
check "exit 6 still updated the record"        "retired" "$(meta_get "$FKD/t.txt" state)"

note "== trash: refusals that never reach the helper =="
TRD="$MED/trasharea"
install -d -o "$INV" -g staff -m 777 "$TRD"
as_user /bin/sh -c "echo t > '$TRD/t.txt'"
# TRD stays unflagged until the lock below seals it: these first two
# refusals answer before any path is even looked at.
# An empty SUDO_USER is answered by the sudo guard, before do_trash_one's
# own no-invoker check ever runs; this is what the case actually produces.
refuse "trash without an invoking user"        "must be invoked via sudo" \
       env SNAPSHOTS_ROOT="$SNAPROOT" INSTALL_TARGET="$SCRATCH/not-installed" \
           LOCKED_HELPER="$HELPER" LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
           LOCKED_USER_HOME="$FAKE_HOME" LOCKED_ALERT_DIR="$ALERTS" SUDO_USER= \
           /bin/bash "$LOCKED" trash --yes "$TRD/t.txt"
refuse "trash refuses a root invoker"          "the invoker is root" \
       env SNAPSHOTS_ROOT="$SNAPROOT" INSTALL_TARGET="$SCRATCH/not-installed" \
           LOCKED_HELPER="$HELPER" LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
           LOCKED_USER_HOME="$FAKE_HOME" LOCKED_ALERT_DIR="$ALERTS" SUDO_USER=root \
           /bin/bash "$LOCKED" trash --yes "$TRD/t.txt"
ok   "the file survived both refusals"         test -f "$TRD/t.txt"
rmdir -- "$SNAPROOT/root" 2>/dev/null || true

NWD="$MED/nowrite"
install -d -o "$LOCK_ACCT" -g "$LOCK_ACCT" -m 700 "$NWD"
install -m 644 -o "$LOCK_ACCT" -g "$LOCK_ACCT" /dev/null "$NWD/x.txt"
locked trash --yes "$NWD/x.txt" >"$OUTF" 2>&1 || true
ok   "trash refuses a parent the invoker cannot write" \
     grep -qF "cannot write $NWD" "$OUTF"
ok   "the refusal points at rm instead"        grep -qF "sudo locked rm $NWD/x.txt" "$OUTF"
ok   "the file is still there"                 test -f "$NWD/x.txt"

# The trash verb has no emptiness rule, so the subtree gate is reachable
# here on an ordinary non-empty recorded directory.
TRSUB="$TRD/recorded"
as_user mkdir -p -- "$TRSUB/inner"
as_user /bin/sh -c "echo s > '$TRSUB/inner/s.txt'"
ok   "lock a leaf under the trash subtree"     locked lock --yes "$TRSUB/inner/s.txt"
locked trash --yes "$TRSUB" >"$OUTF" 2>&1 || true
ok   "trash refuses a subtree holding records" grep -qF "locked records live under it" "$OUTF"
ok   "the refusal lists the inner record"      grep -qF "$TRSUB/inner/s.txt" "$OUTF"
ok   "the refusal names --recursive"           grep -qF "sudo locked trash --recursive $TRSUB" "$OUTF"
ok   "the subtree survived the refusal"        test -f "$TRSUB/inner/s.txt"
ok   "clear the trash subtree fixture"         locked rm --yes --recursive "$TRSUB"

note "== trash: record side-effects (stand-in helpers) =="
TRB="$TRD/withbin.txt"
as_user /bin/sh -c "echo b > '$TRB'"
ok   "lock the bin-location fixture"           locked lock --yes "$TRB"
FBIN="$MED/fakebin"
install -d -o "$INV" -g staff -m 755 "$FBIN"
as_user /bin/sh -c "echo b > '$FBIN/withbin.txt'"
FTB="$(mkfake trash-bin \
  "chflags -- nouappnd '$TRD'" \
  "chflags -- nouchg '$TRB'" \
  "rm -f -- '$TRB'" \
  "chflags -- uappnd '$TRD'" \
  "printf 'binurl\t%s\n' '$FBIN/withbin.txt'" \
  'exit 0')"
ok   "a bin location suspends the record"      locked_fake "$FTB" trash --yes "$TRB"
check "the record is suspended"                "suspended" "$(meta_get "$TRB" state)"
check "it carries the bin location"            "$FBIN/withbin.txt" "$(meta_get "$TRB" bin)"
check "the suspension names the invoker"       "$INV" "$(meta_get "$TRB" by)"

TRN="$TRD/nobin.txt"
as_user /bin/sh -c "echo n > '$TRN'"
ok   "lock the missing-bin fixture"            locked lock --yes "$TRN"
FTN="$(mkfake trash-nobin \
  "chflags -- nouappnd '$TRD'" \
  "chflags -- nouchg '$TRN'" \
  "rm -f -- '$TRN'" \
  "chflags -- uappnd '$TRD'" \
  'exit 0')"
if locked_fake "$FTN" trash --yes "$TRN" >"$OUTF" 2>&1; then rcn=0; else rcn=$?; fi
check "a helper with no bin location exits 3"  "3" "$rcn"
ok   "it raises the no-bin alarm"              grep -qF "the helper reported no bin location" "$OUTF"
check "the record is suspended anyway"         "suspended" "$(meta_get "$TRN" state)"
check "and its bin field is empty"             "" "$(meta_get "$TRN" bin)"

note "== trash: the real service =="
if [ "$TRASH_SKIP" -eq 1 ]; then
  note "  skip  the trash service is TCC-gated by the responsible app and"
  note "        refused this terminal; re-run the harness from a terminal"
  note "        that has been granted access to see these"
else
  TRR="$TRD/real.txt"
  as_user /bin/sh -c "echo r > '$TRR'"
  locked trash --yes "$TRR" >"$OUTF" 2>&1 || true
  ok   "locked trash moves a plain file out"   grep -qF "trashed: $TRR" "$OUTF"
  deny "the file left the sealed parent"       test -e "$TRR"
  check "the parent flag is restored"          "uappnd" "$(flags_of "$TRD")"
  TRRBIN="$(awk '/^  bin: /{sub(/^  bin: /, ""); print; exit}' "$OUTF")"
  ok   "the bin entry exists"                  test -e "$TRRBIN"
  as_user rm -rf -- "$TRRBIN" || true

  TRP="$TRD/realpool.txt"
  as_user /bin/sh -c "echo rp > '$TRP'"
  ok   "lock the real-trash pool fixture"      locked lock --yes "$TRP"
  ok   "locked trash suspends a pool node"     locked trash --yes "$TRP"
  check "the record is suspended"              "suspended" "$(meta_get "$TRP" state)"
  ok   "the recorded bin entry exists"         test -e "$(meta_get "$TRP" bin)"
  as_user rm -rf -- "$(meta_get "$TRP" bin)" || true
  ok   "tombstone the emptied suspension"      locked tombstone --yes "$TRP"
  check "it is retired by assertion"           "assertion" "$(meta_get "$TRP" via)"
fi

note "== staging copies through the helper =="
XAF="$MED/xattr.txt"
as_user /bin/sh -c "printf 'v1\n' > '$XAF'"
as_user xattr -w com.locked.harness carried "$XAF"
ok   "lock the xattr fixture"                  locked lock --yes "$XAF"
XASNAP="$(snap_path "$XAF")"
check "the source xattr rode onto the snapshot" "carried" \
      "$(xattr -p com.locked.harness "$XASNAP" 2>/dev/null)"
check "the snapshot carries no flags"          "" "$(flags_of "$XASNAP")"
# The edit re-snapshots BEFORE it clears the flag, so this copy is taken
# from a still-uchg source: the staged result must not inherit it.
ok   "edit the sealed file through staging"    locked edit --yes --editor "$ED" "$XAF"
check "the edited file is sealed again"        "uchg" "$(flags_of "$XAF")"
check "the re-snapshot still has no flags"     "" "$(flags_of "$XASNAP")"
check "the re-snapshot still carries the xattr" "carried" \
      "$(xattr -p com.locked.harness "$XASNAP" 2>/dev/null)"
check "the staged content was installed"       "edited by script" "$(head -1 "$XAF")"

note "== verify: retired and suspended records =="
VD="$MED/states"
install -d -o "$INV" -g staff -m 755 "$VD"
install -d -o "$INV" -g staff -m 755 "$VD/bin"
# A retired record is not stat'ed at all, so a path that is BACK on disk
# and unsealed still says nothing -- that is the contract, not an oversight.
RETIRED="$VD/retired.txt"
as_user /bin/sh -c "echo r > '$RETIRED'"
put_meta "$RETIRED" \
  "owner=$INV" "group=staff" "mode=644" "lockmode=444" \
  "tier=content" "flag=uchg" "flagsym=uchg" "id=1.1" "recursive=0" \
  "state=retired" "via=rm" "by=$INV" "at=2026-08-25T00:00:00Z"
locked verify >"$OUTF" 2>&1 || true
deny "a retired record says nothing in verify" grep -qF "$RETIRED" "$OUTF"
ok   "verify is clean with a retired record"   locked verify --quiet

FINALIZE="$VD/finalize.txt"
put_meta "$FINALIZE" \
  "owner=$INV" "group=staff" "mode=644" "lockmode=444" \
  "tier=content" "flag=uchg" "flagsym=uchg" "id=1.2" "recursive=0" \
  "state=suspended" "by=$INV" "at=2026-08-25T00:00:00Z" "bin=$VD/bin/gone.txt"
locked verify >"$OUTF" 2>&1 || true
ok   "a vanished bin entry finalizes the suspension" \
     grep -qF "trashed item no longer in the bin; record retired" "$OUTF"
check "the finalized record is retired"        "retired" "$(meta_get "$FINALIZE" state)"
check "with trash-finalized provenance"        "trash-finalized" "$(meta_get "$FINALIZE" via)"
check "and the bin it came from is kept"       "$VD/bin/gone.txt" "$(meta_get "$FINALIZE" bin)"

STILL="$VD/still-binned.txt"
as_user /bin/sh -c "echo s > '$VD/bin/still-binned.txt'"
put_meta "$STILL" \
  "owner=$INV" "group=staff" "mode=644" "lockmode=444" \
  "tier=content" "flag=uchg" "flagsym=uchg" "id=1.3" "recursive=0" \
  "state=suspended" "by=$INV" "at=2026-08-25T00:00:00Z" \
  "bin=$VD/bin/still-binned.txt"
locked verify >"$OUTF" 2>&1 || true
deny "a suspension with its bin entry is quiet" grep -qF "$STILL" "$OUTF"
check "and it stays suspended"                 "suspended" "$(meta_get "$STILL" state)"

BACK="$VD/back.txt"
as_user /bin/sh -c "echo b > '$BACK'"
put_meta "$BACK" \
  "owner=$INV" "group=staff" "mode=644" "lockmode=444" \
  "tier=content" "flag=uchg" "flagsym=uchg" "id=1.4" "recursive=0" \
  "state=suspended" "by=$INV" "at=2026-08-25T00:00:00Z" "bin=$VD/bin/back.txt"
if locked verify >"$OUTF" 2>&1; then vrc=0; else vrc=$?; fi
check "a reappearance drifts"                  "5" "$vrc"
ok   "the drift says it came back from the trash" \
     grep -qF "back from the trash and unsealed" "$OUTF"
ok   "the drift names the bin it was in"       grep -qF "(bin was $VD/bin/back.txt)" "$OUTF"
ok   "the drift points at re-locking"          grep -qF "sudo locked lock $BACK" "$OUTF"

note "== status: retired and suspended rows =="
locked status >"$OUTF" 2>&1 || true
ok   "the pool listing marks a retired node"   grep -qF "~  $RETIRED (content, retired via rm" "$OUTF"
ok   "the pool listing marks a suspended node" grep -qF "~  $BACK (content, suspended" "$OUTF"
ok   "the suspended row carries its bin"       grep -qF "bin: $VD/bin/back.txt" "$OUTF"
locked status "$RETIRED" >"$OUTF" 2>&1 || true
ok   "per-path status renders the retired row" grep -qF "~  $RETIRED (content, retired via rm" "$OUTF"
locked status "$BACK" >"$OUTF" 2>&1 || true
ok   "per-path status renders the suspended row" grep -qF "~  $BACK (content, suspended" "$OUTF"
ok   "per-path status shows the bin line"      grep -qF "bin: $VD/bin/back.txt" "$OUTF"

note "== mediated: the pool is left consistent =="
# The reappearance fixture is deliberate drift, and the status rows above
# are its last consumer. Drop it HERE, not at the end of the file: every
# whole-pool verify a later section runs would otherwise inherit its
# drift, and what this harness leaves behind should be only what it meant
# to leave.
rm -f -- "$(meta_path "$BACK")"
ok   "verify clean once the drift fixture is gone" locked verify --quiet

note "== why: what is actually stopping this =="
WHYF="$MED/why-plain.txt"
as_user /bin/sh -c "echo w > '$WHYF'"
locked why "$WHYF" >"$OUTF" 2>&1 || true
ok   "why names the sealed ancestor"           grep -qF "note: $MED is flagged uappnd" "$OUTF"
ok   "why offers the mediated rm"              grep -qF "sudo locked rm $WHYF" "$OUTF"
ok   "why offers the mediated trash"           grep -qF "sudo locked trash $WHYF" "$OUTF"
ok   "why offers the mediated mv"              grep -qF "sudo locked mv $WHYF" "$OUTF"
locked why "$CFG" >"$OUTF" 2>&1 || true
ok   "why names an immutable pool leaf"        grep -qF "is immutable (uchg)" "$OUTF"
ok   "why offers edit on a pool leaf"          grep -qF "sudo locked edit $CFG" "$OUTF"
ok   "why offers unlock on a pool leaf"        grep -qF "sudo locked unlock $CFG" "$OUTF"
FGN="$MED/foreign.txt"
as_user /bin/sh -c "echo f > '$FGN'"
chflags -- uchg "$FGN"
locked why "$FGN" >"$OUTF" 2>&1 || true
ok   "why says locked did not set a foreign flag" \
     grep -qF "and locked has no record of" "$OUTF"
ok   "why offers chflags for a foreign flag"   grep -qF "sudo chflags nouchg $FGN" "$OUTF"
deny "why does not offer a locked verb for it" grep -qF "sudo locked unlock $FGN" "$OUTF"
chflags -- nouchg "$FGN"
UNB="$SCRATCH/raw/unblocked.txt"
as_user /bin/sh -c "echo u > '$UNB'"
locked why "$UNB" >"$OUTF" 2>&1 || true
ok   "why says nothing blocks an open path"    grep -qF "no file flag on this chain stops" "$OUTF"

note "== identity: a legacy dev.ino record is upgraded, not reported =="
# st_dev is not a volume key: APFS can hand the number to another volume at
# the next mount, which is what made a re-seal read as a swap on 2026-09-09.
# The inode is what proves the node, so a legacy record matches and gets
# rewritten; a legacy record with the WRONG inode is still a replacement.
IDL="$MED/identity-leaf.txt"
as_user /bin/sh -c "echo i > '$IDL'"
ok   "lock the identity fixture"               locked lock --yes "$IDL"
IDINO="$(stat -f '%i' "$IDL")"
check "the record is in volume form"           "vol" "$(id_form_of "$(meta_get "$IDL" id)")"
put_id "$IDL" "999.$IDINO"
locked status "$IDL" >"$OUTF" 2>&1 || true
ok   "status reports the upgrade"              grep -qF "identity record upgraded" "$OUTF"
deny "and does not call it drift"              grep -qF "DRIFT" "$OUTF"
check "the record is in volume form again"     "vol" "$(id_form_of "$(meta_get "$IDL" id)")"
check "and still names the same inode"         "$IDINO" "$(meta_get "$IDL" id | sed 's/.*\.//')"
ok   "verify is clean after the upgrade"       locked verify --quiet
put_id "$IDL" "999.$((IDINO + 1))"
if locked verify >"$OUTF" 2>&1; then vrc=0; else vrc=$?; fi
check "a legacy record with a wrong inode drifts" "5" "$vrc"
ok   "the drift names the identity"            grep -qF "(node replaced)" "$OUTF"
put_id "$IDL" "$("$HELPER" id "$IDL" | tr ':' '.')"
ok   "verify clean once the record is right again" locked verify --quiet

note "== lock: a relock keeps the tier the record names =="
PLD="$MED/placearea"
install -d -o "$INV" -g staff -m 750 "$PLD"
PLL="$PLD/leaf.txt"
as_user /bin/sh -c "echo p > '$PLL'"
ok   "lock a leaf provisions its parent"       locked lock --yes "$PLL"
check "the parent was adopted as placement"    "placement" "$(meta_get "$PLD" tier)"
ok   "unlock the placement dir"                locked unlock "$PLD"
check "the unlocked dir keeps the lock account" "$LOCK_ACCT" "$(owner_of "$PLD")"
check "and keeps its placement mode"           "770" "$(stat -f '%OLp' "$PLD")"
# An entry born under the seal carries the lock group by BSD inheritance,
# and a content-tier relock would refuse the tree for exactly that. This is
# the 2026-09-09 failure: unlock said placement, lock assumed content.
mkdir -p -- "$PLD/sub"
chgrp wheel "$PLD/sub"
locked lock --yes "$PLD" >"$OUTF" 2>&1 || true
ok   "the relock keeps the recorded tier"      grep -qF "relocked: $PLD (placement)" "$OUTF"
deny "and never mentions mixed ownership"      grep -qF "mixed ownership" "$OUTF"
deny "and never calls the placement mode drift" grep -qF "mode drifted" "$OUTF"
check "the relocked dir is uappnd again"       "uappnd" "$(flags_of "$PLD")"
refuse "a tier change on a recorded node is refused" "recorded as tier placement" \
       locked lock --yes --tier content "$PLD"
check "the refusal changed nothing"            "uappnd" "$(flags_of "$PLD")"
check "the recorded tier still stands"          "placement" "$(meta_get "$PLD" tier)"

note "== identity: a legacy record re-seals without an alarm =="
ok   "unlock for the legacy re-seal"           locked unlock "$PLD"
put_id "$PLD" "999.$(stat -f '%i' "$PLD")"
locked lock --yes "$PLD" >"$OUTF" 2>&1 || true
ok   "the re-seal says the record was upgraded" grep -qF "identity record upgraded" "$OUTF"
deny "and raises no REPLACED alarm"            grep -qF "REPLACED" "$OUTF"
check "the re-sealed record is in volume form" "vol" "$(id_form_of "$(meta_get "$PLD" id)")"
ok   "verify clean after the legacy re-seal"   locked verify --quiet

note "== helper: a volume-uuid mismatch refuses the window =="
IDW="$MED/idwindow"
install -d -o "$INV" -g staff -m 777 "$IDW"
as_user /bin/sh -c "echo v > '$IDW/victim.txt'"
chflags -- uappnd "$IDW"
refuse "rm refuses a parent whose volume uuid differs" "changed identity" \
       "$HELPER" rm --parent "$IDW" \
       --parent-id "00000000-0000-0000-0000-000000000000:$(stat -f '%i' "$IDW")" \
       --name victim.txt --target-id -
ok   "the entry is untouched"                  test -e "$IDW/victim.txt"
check "the parent is still sealed"             "uappnd" "$(flags_of "$IDW")"
ok   "the same call with the real id works"    "$HELPER" rm --parent "$IDW" \
       --parent-id "$("$HELPER" id "$IDW")" --name victim.txt --target-id -
deny "and the entry is gone"                   test -e "$IDW/victim.txt"
chflags -- nouappnd "$IDW"

note "== lock: a symlink argument is sealed as the node, not resolved =="
# The motivating shape: ~/.claude/settings.json is a link into a config
# repo. Resolving it sealed the TARGET and reported "already locked" for
# the link, leaving the link node user-owned -- so a same-UID process could
# repoint it and every reader would follow the new target instead.
LNKD="$MED/linkarea"
install -d -o "$INV" -g staff -m 777 "$LNKD"
LNKT="$LNKD/target.txt"
as_user /bin/sh -c "echo target > '$LNKT'"
LNKO="$LNKD/other.txt"
as_user /bin/sh -c "echo other > '$LNKO'"
LNK="$LNKD/link.txt"
as_user ln -s "$LNKT" "$LNK"
# The control for the denial below: unsealed, this is an ordinary swap.
ok   "the invoker can repoint it while unsealed" as_user ln -sfn "$LNKT" "$LNK"

ok   "lock --yes a link"                       locked lock --yes "$LNK"
check "the LINK node is sealed"                "$LOCK_ACCT uchg" "$(stat -f '%Su %Sf' "$LNK")"
check "the target keeps its owner"             "$INV" "$(owner_of "$LNKT")"
check "the target carries no flag"             "" "$(flags_of "$LNKT")"
deny "the target got no record of its own"     test -f "$(meta_path "$LNKT")"
check "the record names the content tier"      "content" "$(meta_get "$LNK" tier)"
check "and is not recursive"                   "0" "$(meta_get "$LNK" recursive)"
deny "no snapshot is taken for a link"         test -f "$(snap_path "$LNK")"
check "the parent got placement"               "uappnd" "$(flags_of "$LNKD")"
ok   "verify clean with a sealed link"         locked verify --quiet
# A link is one node everywhere: status reads the link's own record rather
# than resolving to a target that has none.
locked status "$LNK" >"$OUTF" 2>&1 || true
ok   "status reports the link's own record"    grep -qF "✓  $LNK (content uchg)" "$OUTF"
deny "and never resolves to the target"        grep -qF "$LNKT" "$OUTF"

# The point of the change: the link entry can no longer be re-pointed.
deny "the invoker cannot repoint the sealed link" as_user ln -sfn "$LNKO" "$LNK"
check "the link still names its target"        "$LNKT" "$(readlink "$LNK")"
check "and still resolves to the target"       "target" "$(head -1 "$LNK")"
# Attribution: with the parent's placement flag lifted, only the link
# node's own uchg is left to refuse -- which is what sealing the link
# rather than its target bought.
chflags -- nouappnd "$LNKD"
deny "the link's own uchg refuses the swap"    as_user ln -sfn "$LNKO" "$LNK"
chflags -- uappnd "$LNKD"

ok   "unlock the link"                         locked unlock "$LNK"
check "the unlocked link is back to the invoker" "$INV" "$(owner_of "$LNK")"
check "and carries no flag"                    "" "$(flags_of "$LNK")"
check "and still points where it did"          "$LNKT" "$(readlink "$LNK")"
# No re-point control here: unlock releases the named node only, and the
# parent's placement seal still refuses the unlink that ln -sfn needs.
ok   "relock the link"                         locked lock --yes "$LNK"
check "the relocked link is sealed again"      "$LOCK_ACCT uchg" "$(stat -f '%Su %Sf' "$LNK")"
ok   "verify clean after the round trip"       locked verify --quiet
refuse "edit refuses a symlink"                "no content to edit" \
       locked edit --yes --from "$LNKO" "$LNK"
check "the refused link is untouched"          "$LOCK_ACCT uchg" "$(stat -f '%Su %Sf' "$LNK")"
# Same one-node rule for revert: a link has no snapshot, and the file it
# points at is not what was named.
locked revert "$LNK" >"$OUTF" 2>&1 || true
ok   "revert on a link finds no snapshot"      grep -qF "no snapshot to revert from" "$OUTF"
check "the target content is untouched"        "target" "$(head -1 "$LNKT")"

# A dangling link is informed on, not refused: the target may arrive later
# (a volume mounted, a file a first run creates), so whether the link is
# worth sealing meanwhile is the operator's call. Same one-node rule as
# above -- the link seals, the absent target is only noted.
DNG="$LNKD/dangling.txt"
DNGT="$LNKD/nothing-here.txt"
as_user ln -s "$DNGT" "$DNG"
locked lock --yes "$DNG" >"$OUTF" 2>&1 || true
ok   "the witness says the target is missing"  grep -qF "target missing" "$OUTF"
check "the dangling LINK node is sealed"       "$LOCK_ACCT uchg" "$(stat -f '%Su %Sf' "$DNG")"
check "the record names the content tier"      "content" "$(meta_get "$DNG" tier)"
ok   "and the link got a record of its own"    test -f "$(meta_path "$DNG")"
deny "no snapshot is taken for a dangling link" test -f "$(snap_path "$DNG")"
deny "the missing target is still missing"     test -e "$DNGT"
deny "and the target got no record"            test -f "$(meta_path "$DNGT")"
ok   "verify clean with a sealed dangling link" locked verify --quiet
ok   "unlock the dangling link"                locked unlock "$DNG"
check "the unlocked dangling link is back to the invoker" "$INV" "$(owner_of "$DNG")"
check "and carries no flag"                    "" "$(flags_of "$DNG")"
check "and still points where it did"          "$DNGT" "$(readlink "$DNG")"

LNK2="$LNKD/link2.txt"
as_user ln -s "$LNKT" "$LNK2"
refuse "--tier placement on a link is refused" "does not apply to a link" \
       locked lock --yes --tier placement "$LNK2"
refuse "--tier anchor on a link is refused"    "does not apply to a link" \
       locked lock --yes --tier anchor "$LNK2"
check "the refused link keeps its owner"       "$INV" "$(owner_of "$LNK2")"
deny "and got no record"                       test -f "$(meta_path "$LNK2")"

note "== lock: the plan is derived first and gated once =="
# Every seal used to ask for itself, so declining an ancestor left the leaf
# ALREADY SEALED under a parent nobody had protected. The plan is derived
# before anything is touched, printed root-most first, and answered once.
# Its own stop node, so the chain is exactly leaf + one placement parent.
PLANSTOP="$SCRATCH/planstop"
install -d -m 755 -o root -g wheel "$PLANSTOP"
PLAND="$PLANSTOP/area"
install -d -o "$INV" -g staff -m 777 "$PLAND"
PLANF="$PLAND/leaf.txt"
as_user /bin/sh -c "echo plan > '$PLANF'"

# Off-tty the gate has nobody to ask and fails closed, which is a decline:
# the plan is printed, the exit is 2, and not one node has been touched.
PLANRC=0
locked_notty lock "$PLANF" >"$OUTF" 2>&1 || PLANRC=$?
check "an unanswerable gate declines"          "2" "$PLANRC"
ok   "the plan is printed before the gate"     grep -qF "plan for $PLANF (tier content)" "$OUTF"
ok   "the plan lists the leaf"                 grep -q "seal content  *$PLANF" "$OUTF"
ok   "the plan lists the parent"               grep -q "seal placement  *$PLAND" "$OUTF"
PLAN_P="$(grep -n "seal placement" "$OUTF" | head -1 | cut -d: -f1)"
PLAN_L="$(grep -n "seal content" "$OUTF" | head -1 | cut -d: -f1)"
ok   "the plan reads root-most first"          test "$PLAN_P" -lt "$PLAN_L"
check "the declined leaf keeps its owner"      "$INV" "$(owner_of "$PLANF")"
check "and carries no flag"                    "" "$(flags_of "$PLANF")"
deny "and got no record"                       test -f "$(meta_path "$PLANF")"
check "the parent was not touched either"      "" "$(flags_of "$PLAND")"
check "and the parent keeps its owner"         "$INV" "$(owner_of "$PLAND")"

ok   "seal the parent on its own"              locked lock --yes --tier placement "$PLAND"
locked_notty lock "$PLANF" >"$OUTF" 2>&1 || true
ok   "the plan shows the sealed ancestor"      grep -q "already locked  *$PLAND" "$OUTF"
ok   "and still offers the leaf"               grep -q "seal content  *$PLANF" "$OUTF"

locked lock --dry-run --yes "$PLANF" >"$OUTF" 2>&1 || true
ok   "dry run prints the plan"                 grep -qF "plan for $PLANF (tier content)" "$OUTF"
ok   "dry run says nothing changed"            grep -qF "dry run: nothing changed" "$OUTF"
check "dry run left the leaf's owner"          "$INV" "$(owner_of "$PLANF")"
check "dry run left no flag on it"             "" "$(flags_of "$PLANF")"
deny "dry run wrote no record"                 test -f "$(meta_path "$PLANF")"

ok   "the leaf seals after the previews"       locked lock --yes "$PLANF"
check "the leaf is sealed"                     "$LOCK_ACCT uchg" "$(stat -f '%Su %Sf' "$PLANF")"
locked lock --yes "$PLANF" >"$OUTF" 2>&1 || true
ok   "a whole chain asks nothing"              grep -qF "already locked: $PLANF" "$OUTF"
deny "and prints no plan"                      grep -qF "plan for" "$OUTF"
ok   "verify clean after the plan round"       locked verify --quiet

# ---- summary ---------------------------------------------------------------

echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "all assertions passed"
