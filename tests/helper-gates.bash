#!/usr/bin/env bash
# locked-helper gate tests that need no root:
#
#   bash tests/helper-gates.bash
#
# Builds the helper twice from the repo source, with the flags the nix
# module uses: the release build, and the test build (-DLOCKED_HELPER_TEST),
# which skips the helper's root gate and has the pause hook. Everything runs
# as whoever runs this, in a scratch dir of its own, so every chown the
# helper makes is a chown to that same account and the kernel grants the
# helper nothing the caller does not already have. What this covers is the
# helper's own decisions: the type gate, the owner gate, the identity pin,
# the canonical-path walk, a plant between plan and apply (held open by the
# pause hook), and the roll back of a refused seal. What only root can show
# -- a hard link to a root-owned file, a real change of owner -- is in the
# root harness (tests/harness.bash, section 9).
#
# stdout is TAP 14, like the root harness.

set -euo pipefail
IFS=$'\n\t'
shopt -s nullglob

REPO="$(cd "$(dirname "$0")/.." && pwd -P)"
SRC="$REPO/helper/locked-helper.m"

N=0
FAIL=0
echo "TAP version 14"
pass() { N=$((N + 1)); printf 'ok %d - %s\n' "$N" "$1"; }
fail() { N=$((N + 1)); FAIL=$((FAIL + 1)); printf 'not ok %d - %s\n' "$N" "$1"; }
skip() { N=$((N + 1)); printf 'ok %d - %s # skip %s\n' "$N" "$1" "$2"; }
detail() { printf '%s\n' "$1" | sed 's/^/#   | /'; }
note() { printf '# %s\n' "$1"; }

# expect <desc> <status> <needle|-> <cmd...>: the command exits <status>,
# and its stderr holds <needle> unless that is "-".
OUT=""
expect() {
  local desc="$1" want="$2" needle="$3" rc=0
  shift 3
  OUT="$("$@" 2>&1)" || rc=$?
  if [ "$rc" -ne "$want" ]; then
    fail "$desc"
    detail "exit $rc, want $want"
    detail "$OUT"
  elif [ "$needle" != "-" ] && ! printf '%s\n' "$OUT" | grep -qF -e "$needle"; then
    fail "$desc"
    detail "no '$needle' in:"
    detail "$OUT"
  else
    pass "$desc"
  fi
}
check() { # <desc> <want> <got>
  if [ "$2" = "$3" ]; then
    pass "$1"
  else
    fail "$1"
    detail "got:  '$3'"
    detail "want: '$2'"
  fi
}
flags_of() {
  local s
  s="$(/usr/bin/stat -f '%Sf' "$1")"
  s="${s// /}"
  [ "$s" = "-" ] && s=""
  printf '%s' "$s"
}
# Every flag word under a tree, one per node, symlinks included: empty
# output means nothing in it carries a flag.
flagged_under() {
  /usr/bin/find "$1" -flags +uchg -print 2>/dev/null || true
}

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/locked-helper-gates.XXXXXX")"
SCRATCH="$(cd "$SCRATCH" && pwd -P)"
# New nodes take their directory's group (BSD), and an ordinary user may
# not give one back to a group they are not in, so every chown here hands a
# node to the group it already has: a roll back can then always restore it.
MYGROUP="$(/usr/bin/stat -f '%Sg' "$SCRATCH")"
cleanup() {
  /usr/bin/chflags -R nouchg "$SCRATCH" 2>/dev/null || true
  /bin/rm -rf -- "$SCRATCH"
}
trap cleanup EXIT

ME="$(id -un)"
REL="$SCRATCH/locked-helper"
TST="$SCRATCH/locked-helper-test"
FLAGS=(-O2 -Wall -Wextra -Werror -framework Foundation)

note "build"
if /usr/bin/clang "${FLAGS[@]}" -o "$REL" "$SRC" 2>"$SCRATCH/cc.err"; then
  pass "release build compiles under -Werror"
else
  fail "release build compiles under -Werror"; detail "$(cat "$SCRATCH/cc.err")"
  echo "Bail out! no helper"; exit 1
fi
if /usr/bin/clang "${FLAGS[@]}" -DLOCKED_HELPER_TEST -o "$TST" "$SRC" 2>"$SCRATCH/cc.err"; then
  pass "test build compiles under -Werror"
else
  fail "test build compiles under -Werror"; detail "$(cat "$SCRATCH/cc.err")"
  echo "Bail out! no test helper"; exit 1
fi
check "the release build holds no test hook" "0" \
  "$(/usr/bin/strings "$REL" | grep -c LOCKED_HELPER_TEST || true)"
check "the test build does"                  "1" \
  "$(/usr/bin/strings "$TST" | grep -c LOCKED_HELPER_TEST_PAUSE || true)"
if [ "$(id -u)" -ne 0 ]; then
  expect "the release build refuses to seal without root" 4 "must run as root" \
    "$REL" seal --path "$SCRATCH" --id - --owner "$ME" --flag uchg
fi

seal() { "$TST" seal "$@"; }
unseal() { "$TST" unseal "$@"; }
OWN=(--owner "$ME" --chown "$ME:$MYGROUP")

# tree <dir>: a small tree of the caller's own, two levels deep.
tree() {
  /bin/mkdir -p "$1/a/b"
  printf 'one\n' >"$1/one.txt"
  printf 'two\n' >"$1/a/two.txt"
  printf 'three\n' >"$1/a/b/three.txt"
  /bin/ln -s one.txt "$1/link"
}

note "seal and unseal a tree"
T="$SCRATCH/t1"
tree "$T"
expect "seal --recursive succeeds" 0 - \
  seal --path "$T" --id - "${OWN[@]}" --mode 755 --flag uchg --recursive
check "every node carries uchg" "7" "$(flagged_under "$T" | wc -l | tr -d ' ')"
check "the link itself is flagged" "uchg" "$(flags_of "$T/link")"
check "and its target only as a node of the tree" "uchg" "$(flags_of "$T/one.txt")"
expect "unseal --recursive succeeds" 0 - \
  unseal --path "$T" --id - "${OWN[@]}" --mode 755 --flag uchg --recursive
check "no node carries uchg after unseal" "" "$(flagged_under "$T")"

note "the type gate"
T="$SCRATCH/t2"
tree "$T"
/usr/bin/mkfifo "$T/a/b/zz-fifo"
expect "a fifo deep in the tree is refused" 7 "a fifo is not a file, directory or symlink" \
  seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
check "the refusal rolled back every freeze" "" "$(flagged_under "$T")"
expect "a fifo named directly is refused" 7 "a fifo is not a file" \
  seal --path "$T/a/b/zz-fifo" --id - "${OWN[@]}" --flag uchg
/bin/mv -- "$T/a/b/zz-fifo" "$SCRATCH/fifo.away"

note "the owner gate"
expect "a tree the named owner does not own is refused" 7 "and not by root" \
  seal --path "$T" --id - --owner root --chown "$ME:$MYGROUP" --flag uchg --recursive
check "and nothing in it changed" "" "$(flagged_under "$T")"
expect "a list of owners passes when one matches" 0 - \
  seal --path "$T/one.txt" --id - --owner "root,$ME" --flag uchg
unseal --path "$T/one.txt" --id - --owner "$ME" --flag uchg
expect "unseal refuses a node not owned by its --owner" 7 "and not by root" \
  unseal --path "$T" --id - --owner root --chown "$ME:$MYGROUP" --flag uchg --recursive

note "the identity pin"
ID="$("$TST" id "$T/one.txt")"
expect "seal refuses a node that is not --id" 2 "changed identity" \
  seal --path "$T/one.txt" --id "${ID%:*}:1" "${OWN[@]}" --flag uchg
check "and leaves it unflagged" "" "$(flags_of "$T/one.txt")"
expect "seal takes the node --id names" 0 - \
  seal --path "$T/one.txt" --id "$ID" "${OWN[@]}" --flag uchg
unseal --path "$T/one.txt" --id "$ID" "${OWN[@]}" --flag uchg

note "the path walk"
/bin/ln -s "$T" "$SCRATCH/t2-link"
expect "a symlink on the path is refused" 7 "a symlink or not a directory" \
  seal --path "$SCRATCH/t2-link/one.txt" --id - "${OWN[@]}" --flag uchg
expect "a dot-dot component is refused" 7 "not canonical" \
  seal --path "$T/a/../one.txt" --id - "${OWN[@]}" --flag uchg
expect "a symlink as the node is sealed as itself" 0 - \
  seal --path "$SCRATCH/t2-link" --id - "${OWN[@]}" --flag uchg
check "the link carries the flag" "uchg" "$(flags_of "$SCRATCH/t2-link")"
check "its target does not" "" "$(flags_of "$T")"
unseal --path "$SCRATCH/t2-link" --id - "${OWN[@]}" --flag uchg
expect "--recursive without --chown is a usage error" 4 "--recursive needs --chown" \
  seal --path "$T" --id - --owner "$ME" --flag uchg --recursive
expect "--recursive with a flag other than uchg is a usage error" 4 "--recursive takes --flag uchg" \
  unseal --path "$T" --id - "${OWN[@]}" --flag uappnd --recursive
check "and nothing in the tree was frozen" "" "$(flagged_under "$T")"

note "set-user-id"
SU="$T/setuid-tool"
printf 'x\n' >"$SU"
/bin/chmod 4755 "$SU" 2>/dev/null || true
if [ "$(/usr/bin/stat -f '%OLp' "$SU")" = "4755" ]; then
  expect "a seal that gives a set-user-id file away is refused" 7 "set-user-id" \
    seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
  check "and nothing changed" "" "$(flagged_under "$T")"
else
  skip "a seal that gives a set-user-id file away is refused" "chmod 4755 not allowed here"
  skip "and nothing changed" "chmod 4755 not allowed here"
fi
/bin/rm -f -- "$SU"

note "a plant between plan and apply"
T="$SCRATCH/t3"
tree "$T"
FIFO="$SCRATCH/pause"
/usr/bin/mkfifo "$FIFO"
env LOCKED_HELPER_TEST_PAUSE="seal:$FIFO" "$TST" seal --path "$T" --id - \
  "${OWN[@]}" --flag uchg --recursive >"$SCRATCH/plant.out" 2>&1 &
PID=$!
# The helper is held at the fifo; the plan it was called on is already
# stale. Plant a node the gate must refuse, deep enough that the walk has
# frozen directories by the time it meets it, then let the helper go.
/usr/bin/mkfifo "$T/a/b/zz-planted"
printf 'g' >"$FIFO"
RC=0
wait "$PID" || RC=$?
check "the planted node is refused" "7" "$RC"
if grep -qF "a fifo is not a file" "$SCRATCH/plant.out"; then
  pass "named as the node that was planted"
else
  fail "named as the node that was planted"; detail "$(cat "$SCRATCH/plant.out")"
fi
check "the directories it froze were rolled back" "" "$(flagged_under "$T")"

note "copy-tree"
T="$SCRATCH/t4"
tree "$T"
expect "copy-tree copies the caller's tree" 0 - \
  "$TST" copy-tree --src "$T" --src-id - --owner "$ME" --dest "$SCRATCH/copy1" \
  --chown "$ME:$MYGROUP"
check "file content travels" "three" "$(cat "$SCRATCH/copy1/a/b/three.txt")"
check "a link travels as a link" "one.txt" "$(/usr/bin/readlink "$SCRATCH/copy1/link")"
expect "copy-tree refuses a tree its --owner does not own" 7 "and not by root" \
  "$TST" copy-tree --src "$T" --src-id - --owner root --dest "$SCRATCH/copy2" \
  --chown "$ME:$MYGROUP"
/usr/bin/mkfifo "$T/a/zz-fifo"
expect "copy-tree refuses a fifo" 7 "a fifo is not a file" \
  "$TST" copy-tree --src "$T" --src-id - --owner "$ME" --dest "$SCRATCH/copy3" \
  --chown "$ME:$MYGROUP"

note "copy and xattrs-from"
expect "copy refuses a source its --owner does not own" 7 "and not by root" \
  "$TST" copy --src "$T/one.txt" --src-id - --owner root --dest "$SCRATCH/copy4"
expect "copy takes a source its --owner owns" 0 - \
  "$TST" copy --src "$T/one.txt" --src-id - --owner "$ME" --dest "$SCRATCH/copy5"
expect "copy without --owner is a usage error" 4 "--owner is required" \
  "$TST" copy --src "$T/one.txt" --src-id - --dest "$SCRATCH/copy6"

echo "1..$N"
note "$((N - FAIL)) of $N passed"
[ "$FAIL" -eq 0 ]
