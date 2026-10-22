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

# count <dir>: the nodes of a tree, itself included, as locked's node_count
# counts them for --count.
count() { /usr/bin/find "$1" -print0 | LC_ALL=C /usr/bin/tr -cd '\0' | /usr/bin/wc -c | /usr/bin/tr -d ' '; }

# seal / unseal <args...>: the test helper's verb, with the --count the plan
# would pass when the args name none: the tree's count with --recursive,
# 1 without.
with_count() {
  local verb="$1" a prev="" path="" rec=0 has=0 n=1
  shift
  for a in "$@"; do
    case "$a" in --recursive) rec=1 ;; --count) has=1 ;; esac
    [ "$prev" = "--path" ] && path="$a"
    prev="$a"
  done
  if [ "$has" -eq 1 ]; then
    "$TST" "$verb" "$@"
    return
  fi
  [ "$rec" -eq 1 ] && n="$(count "$path")"
  "$TST" "$verb" "$@" --count "$n"
}
seal() { with_count seal "$@"; }
unseal() { with_count unseal "$@"; }
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

note "a single-node unseal of a directory"
# A chain anchor is one directory whose entries are not part of its seal:
# they may be anyone's, sealed or not. Its unseal touches the top alone.
/usr/bin/mkfifo "$T/a/zz-fifo"
seal --path "$T" --id - --owner "$ME" --flag uappnd
expect "an anchor-style unseal succeeds over entries the gate would refuse" 0 - \
  unseal --path "$T" --id - --owner "$ME" --flag uappnd
check "the flag is off the top" "" "$(flags_of "$T")"
check "and nothing below it was frozen" "" "$(flagged_under "$T")"
/bin/rm -f -- "$T/a/zz-fifo"

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

# paused <pause> <plant fn> <helper args...>: run the test helper held at
# the pause hook, run <plant fn> while it waits there, then let it go. RC is
# its exit, OUT what it printed. Opening the fifo's write end returns only
# once the helper holds the read end, so the plant lands at the pause.
paused() {
  local spec="$1" plant="$2" fifo="$SCRATCH/pause.$N" pid
  shift 2
  /usr/bin/mkfifo "$fifo"
  env LOCKED_HELPER_TEST_PAUSE="$spec:$fifo" "$TST" "$@" >"$SCRATCH/paused.out" 2>&1 &
  pid=$!
  exec 3>"$fifo"
  "$plant"
  printf 'g' >&3
  exec 3>&-
  RC=0
  wait "$pid" || RC=$?
  OUT="$(cat "$SCRATCH/paused.out")"
}
said() { # <desc> <needle>: the last paused run printed <needle>
  if printf '%s\n' "$OUT" | grep -qF -e "$2"; then
    pass "$1"
  else
    fail "$1"; detail "no '$2' in:"; detail "$OUT"
  fi
}

note "a plant between plan and apply"
# The helper is held before it opens anything; the plan it was called on
# is already stale. The count pass meets the plant first and refuses it
# before any change.
T="$SCRATCH/t3"
tree "$T"
plant_fifo() { /usr/bin/mkfifo "$T/a/b/zz-planted"; }
paused seal plant_fifo seal --path "$T" --id - "${OWN[@]}" --flag uchg \
  --recursive --count "$(count "$T")"
check "a planted fifo is refused" "7" "$RC"
said "named as the node that was planted" "a fifo is not a file"
check "and nothing was frozen" "" "$(flagged_under "$T")"
/bin/rm -f -- "$T/a/b/zz-planted"

note "the count guard"
plant_file() { printf 'new\n' >"$T/a/b/added.txt"; }
paused seal plant_file seal --path "$T" --id - "${OWN[@]}" --flag uchg \
  --recursive --count "$(count "$T")"
check "a node added before the count is refused" "7" "$RC"
said "with the plan's count and the tree's" "the plan names 7 nodes and the tree holds 8"
check "before anything was frozen" "" "$(flagged_under "$T")"
/bin/rm -f -- "$T/a/b/added.txt"
# After the count: the seal has frozen the folders above the plant by the
# time it reaches it, and stops at the first node past the plan.
paused seal-walk plant_file seal --path "$T" --id - "${OWN[@]}" --flag uchg \
  --recursive --count "$(count "$T")"
check "a node added after the count is refused" "7" "$RC"
said "at the first node past the plan" "the plan names 7 nodes and the walk reached more"
check "and every freeze was rolled back" "" "$(flagged_under "$T")"
/bin/rm -f -- "$T/a/b/added.txt"
paused seal-walk plant_fifo seal --path "$T" --id - "${OWN[@]}" --flag uchg \
  --recursive --count "$(count "$T")"
check "a fifo planted after the count is refused by the gate" "7" "$RC"
said "named as the node that was planted" "a fifo is not a file"
check "and the folders the seal froze were rolled back" "" "$(flagged_under "$T")"
/bin/rm -f -- "$T/a/b/zz-planted"
expect "a stale count refuses before any change" 7 "the plan names 6 nodes and the tree holds 7" \
  seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive --count 6
check "and nothing was frozen" "" "$(flagged_under "$T")"
expect "--count other than 1 without --recursive is a usage error" 4 \
  "--count must be 1 without --recursive" \
  seal --path "$T/one.txt" --id - "${OWN[@]}" --flag uchg --count 2
expect "a seal without --count is a usage error" 4 "--count is required" \
  "$TST" seal --path "$T/one.txt" --id - "${OWN[@]}" --flag uchg
expect "--count 0 is a usage error" 4 "--count must be a number of nodes" \
  seal --path "$T/one.txt" --id - "${OWN[@]}" --flag uchg --count 0
# The unseal: the tree is frozen, so the plant needs its folder thawed
# first, as only the owner the test runs as can. The first pass stops at
# the node past the plan, and the tree stays sealed as it was.
expect "seal the tree for the unseal cases" 0 - \
  seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
plant_sealed() {
  /usr/bin/chflags nouchg "$T/a/b"
  printf 'new\n' >"$T/a/b/added.txt"
  /usr/bin/chflags uchg "$T/a/b"
}
paused unseal-walk plant_sealed unseal --path "$T" --id - "${OWN[@]}" \
  --flag uchg --recursive --count 7
check "an unseal that reaches past the plan is refused" "7" "$RC"
said "at the first node past the plan" "the plan names 7 nodes and the walk reached more"
check "and the tree is still sealed" "7" "$(flagged_under "$T" | wc -l | tr -d ' ')"
/usr/bin/chflags nouchg "$T/a/b"
/bin/rm -f -- "$T/a/b/added.txt"
/usr/bin/chflags uchg "$T/a/b"
expect "the unseal with the tree's count succeeds" 0 - \
  unseal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
check "and nothing is left frozen" "" "$(flagged_under "$T")"

note "copy-tree"
T="$SCRATCH/t4"
tree "$T"
AS=(--as "$ME")
expect "copy-tree copies the caller's tree" 0 - \
  "$TST" copy-tree --src "$T" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy1" --chown "$ME:$MYGROUP"
check "file content travels" "three" "$(cat "$SCRATCH/copy1/a/b/three.txt")"
check "a link travels as a link" "one.txt" "$(/usr/bin/readlink "$SCRATCH/copy1/link")"
expect "copy-tree refuses a tree its --owner does not own" 7 "and not by root" \
  "$TST" copy-tree --src "$T" --src-id - --owner root "${AS[@]}" \
  --dest "$SCRATCH/copy2" --chown "$ME:$MYGROUP"
/bin/chmod 000 "$T/a/b"
expect "copy-tree refuses a folder --as cannot read" 7 "$ME may not open it" \
  "$TST" copy-tree --src "$T" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy7" --chown "$ME:$MYGROUP"
/bin/chmod 755 "$T/a/b"
/usr/bin/mkfifo "$T/a/zz-fifo"
expect "copy-tree refuses a fifo" 7 "a fifo is not a file" \
  "$TST" copy-tree --src "$T" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy3" --chown "$ME:$MYGROUP"

note "copy and xattrs-from"
expect "copy refuses a source its --owner does not own" 7 "and not by root" \
  "$TST" copy --src "$T/one.txt" --src-id - --owner root "${AS[@]}" \
  --dest "$SCRATCH/copy4"
expect "copy takes a source its --owner owns" 0 - \
  "$TST" copy --src "$T/one.txt" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy5"
expect "copy without --owner is a usage error" 4 "--owner is required" \
  "$TST" copy --src "$T/one.txt" --src-id - "${AS[@]}" --dest "$SCRATCH/copy6"
expect "copy without --as is a usage error" 4 "--as is required" \
  "$TST" copy --src "$T/one.txt" --src-id - --owner "$ME" --dest "$SCRATCH/copy8"
expect "copy refuses a source reached through a symlink" 7 "a symlink or not a directory" \
  "$TST" copy --src "$SCRATCH/t2-link/one.txt" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy9"
# --as is the caller here, so a folder they cannot enter is one the kernel
# closes to the read, not one the owner gate opens.
/bin/chmod 000 "$T/a"
expect "copy refuses a file inside a folder --as cannot enter" 7 \
  "$ME cannot enter a directory on the path" \
  "$TST" copy --src "$T/a/two.txt" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy10"
/bin/chmod 755 "$T/a"
/bin/chmod 000 "$T/one.txt"
expect "copy refuses a file --as may not read" 7 "$ME may not open it" \
  "$TST" copy --src "$T/one.txt" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy11"
expect "xattrs-from refuses it too" 7 "$ME may not open it" \
  "$TST" xattrs-from --src "$T/one.txt" --src-id - --owner "$ME" "${AS[@]}" \
  --dest "$SCRATCH/copy5"
/bin/chmod 644 "$T/one.txt"

echo "1..$N"
note "$((N - FAIL)) of $N passed"
[ "$FAIL" -eq 0 ]
