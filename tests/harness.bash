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
# /var/db (the 1777 /private/tmp would itself fail the walk), also removed
# by the trap. Group-write add-rights on placement dirs depend on
# membership in the real _<user>-lock group and are exercised at ceremony
# time, not here.

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
chmod 755 "$SCRATCH"   # root:wheel 755 -> valid chain stop node

cleanup() {
  # Clear every flag we may have set (system flags need root; we are root),
  # then remove the scratch trees. No flags are ever set under ANC.
  chflags -R noschg,nosappnd,nouchg,nouappnd "$SCRATCH" 2>/dev/null || true
  rm -rf -- "$SCRATCH"
  if [ -n "${ANC:-}" ]; then rm -rf -- "$ANC"; fi
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
ok   "relock version 3"                  locked lock --yes "$CFG"
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

note "== cli: dry-run mutates nothing =="
DR="$FAKE_HOME/dryrun.txt"
as_user /bin/sh -c "echo dr > '$DR'"
ok   "lock --dry-run --yes"              locked lock --dry-run --yes "$DR"
check "dry-run left owner"               "$INV" "$(owner_of "$DR")"
check "dry-run left flags"               "" "$(flags_of "$DR")"
deny "dry-run wrote no meta or snapshot" \
     /bin/sh -c "ls '$SNAPROOT/$INV' | grep -q dryrun"

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
      LOCKED_LOCK_ACCOUNT="$LOCK_ACCT" \
      LOCKED_USER_HOME="$FAKE_HOME" \
      LOCKED_ALERT_DIR="$ALERTS" \
      SUDO_USER="$INV" \
      /bin/bash "$LOCKED" "$@"
}

refuse() { # <desc> <needle> <cmd...>: expect failure WITH the named message,
           # so a denial can be attributed to the guard under test.
  local desc="$1" needle="$2"; shift 2
  local out
  if out="$("$@" 2>&1)"; then
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (expected refusal)"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/        | /'
  elif printf '%s\n' "$out" | grep -qF "$needle"; then
    PASS=$((PASS + 1)); note "  ok    $desc"
  else
    FAIL=$((FAIL + 1)); note "  FAIL  $desc (refused, but not with '$needle')"
    [ -n "$out" ] && printf '%s\n' "$out" | sed 's/^/        | /'
  fi
}

# Accepted: strict root:wheel 755 chain (the /usr/local shape).
install -d -m 755 -o root -g wheel "$ANC/ok/sbin"
install -m 755 -o root -g wheel /dev/null "$ANC/ok/sbin/locked"
ok   "strict root-755 ancestry accepted"  locked_it "$ANC/ok/sbin/locked" verify --quiet

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

# ---- summary ---------------------------------------------------------------

echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "all assertions passed"
