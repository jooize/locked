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
# helper nothing the caller does not already have. A user may not set a
# system flag, so the seals here use uchg where locked uses schg; the walk,
# the swap and the gates are the same code either way. What this covers is
# the helper's own decisions: the type gate, the owner gate, the identity
# pin, the canonical-path walk, copy-and-swap, install, the fingerprints,
# the open-writer check, a plant between plan and apply (held open by the
# pause hook), and the roll back of a refused seal. What only root can show
# -- a hard link to a root-owned file, schg itself -- is in the root
# harness (tests/harness.bash, section 9).
#
# The Bash sandbox refuses mkfifo; every case that needs a fifo (the fifo
# gates and the pause hook) then skips by name.
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
ino() { /usr/bin/stat -f '%i' "$1"; }
sha() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/locked-helper-gates.XXXXXX")"
SCRATCH="$(cd "$SCRATCH" && pwd -P)"
# New nodes take their directory's group (BSD), and an ordinary user may
# not give one back to a group they are not in, so every chown here hands a
# node to the group it already has: a roll back can then always restore it.
MYGROUP="$(/usr/bin/stat -f '%Sg' "$SCRATCH")"
# A second scratch dir under /private/tmp, for the walk through /tmp.
TMPLINKED=""
cleanup() {
  if [ -n "$TMPLINKED" ]; then
    /usr/bin/chflags -R nouchg "$TMPLINKED" 2>/dev/null || true
    /bin/rm -rf -- "$TMPLINKED"
  fi
  /usr/bin/chflags -R nouchg,nouappnd "$SCRATCH" 2>/dev/null || true
  # The ACL cases leave deny entries that refuse a removal.
  /bin/chmod -R -N "$SCRATCH" 2>/dev/null || true
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
# Can this process make a fifo here? The Bash sandbox says no.
FIFO_OK=0
if /usr/bin/mkfifo "$SCRATCH/fifo-probe" 2>/dev/null; then
  FIFO_OK=1
  /bin/mv -- "$SCRATCH/fifo-probe" "$SCRATCH/fifo-probe.away"
fi
# fifo_skip <desc>...: skip each case by name when no fifo can be made.
fifo_skip() { local d; for d in "$@"; do skip "$d" "mkfifo refused (sandbox)"; done; }

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
OWN=(--owner "$ME")

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
  seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
check "every node carries uchg" "7" "$(flagged_under "$T" | wc -l | tr -d ' ')"
check "the link itself is flagged" "uchg" "$(flags_of "$T/link")"
check "and its target only as a node of the tree" "uchg" "$(flags_of "$T/one.txt")"
expect "unseal --recursive succeeds" 0 - \
  unseal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
check "no node carries uchg after unseal" "" "$(flagged_under "$T")"

note "the type gate"
T="$SCRATCH/t2"
tree "$T"
if [ "$FIFO_OK" -eq 1 ]; then
  /usr/bin/mkfifo "$T/a/b/zz-fifo"
  expect "a fifo deep in the tree is refused" 7 "a fifo is not a file, directory or symlink" \
    seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
  check "the refusal rolled back every freeze" "" "$(flagged_under "$T")"
  expect "a fifo named directly is refused" 7 "a fifo is not a file" \
    seal --path "$T/a/b/zz-fifo" --id - "${OWN[@]}" --flag uchg
  /bin/mv -- "$T/a/b/zz-fifo" "$SCRATCH/fifo.away"
else
  fifo_skip "a fifo deep in the tree is refused" "the refusal rolled back every freeze" \
    "a fifo named directly is refused"
fi

note "the owner gate"
expect "a tree the named owner does not own is refused" 7 "and not by root" \
  seal --path "$T" --id - --owner root --flag uchg --recursive
check "and nothing in it changed" "" "$(flagged_under "$T")"
expect "a list of owners passes when one matches" 0 - \
  seal --path "$T/one.txt" --id - --owner "root,$ME" --flag uchg
unseal --path "$T/one.txt" --id - --owner "$ME" --flag uchg
expect "unseal refuses a node not owned by its --owner" 7 "and not by root" \
  unseal --path "$T" --id - --owner root --flag uchg --recursive

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
# A symlink only root controls is followed: /tmp is root's link in "/",
# which only root may change, so the walk puts private/tmp in its place.
# The caller's own link above is refused all the same.
TMPLINKED="$(/usr/bin/mktemp -d /private/tmp/locked-helper-gates.XXXXXX)"
printf 'x\n' >"$TMPLINKED/f.txt"
TL="/tmp/${TMPLINKED#/private/tmp/}"
expect "a path through root's /tmp link is followed" 0 - \
  seal --path "$TL/f.txt" --id - --owner "$ME" --flag uchg
check "and the node it reaches carries the flag" "uchg" "$(flags_of "$TMPLINKED/f.txt")"
expect "the unseal goes the same way" 0 - \
  unseal --path "$TL/f.txt" --id - --owner "$ME" --flag uchg
check "and the flag is off again" "" "$(flags_of "$TMPLINKED/f.txt")"
expect "copy reads through it too, as the caller" 0 - \
  "$TST" copy --src "$TL/f.txt" --src-id - --owner "$ME" --as "$ME" \
  --dest "$SCRATCH/copy-tmp"
check "the copy holds the bytes" "x" "$(cat "$SCRATCH/copy-tmp")"
# Below /private/tmp, which anyone may write, no link is followed, not even
# one that points back into the same folder.
/bin/ln -s "$TMPLINKED" "$TMPLINKED/self"
expect "a link below a folder others can write is refused" 7 "a symlink or not a directory" \
  seal --path "$TL/self/f.txt" --id - --owner "$ME" --flag uchg
expect "a dot-dot component is refused" 7 "not canonical" \
  seal --path "$T/a/../one.txt" --id - "${OWN[@]}" --flag uchg
expect "a symlink as the node is sealed as itself" 0 - \
  seal --path "$SCRATCH/t2-link" --id - "${OWN[@]}" --flag uchg
check "the link carries the flag" "uchg" "$(flags_of "$SCRATCH/t2-link")"
check "its target does not" "" "$(flags_of "$T")"
unseal --path "$SCRATCH/t2-link" --id - "${OWN[@]}" --flag uchg

note "usage"
expect "--recursive with an append flag is a usage error" 4 "--recursive takes --flag schg or uchg" \
  unseal --path "$T" --id - "${OWN[@]}" --flag uappnd --recursive
check "and nothing in the tree was frozen" "" "$(flagged_under "$T")"
expect "--chown on a seal is a usage error" 4 "--chown is for unseal" \
  seal --path "$T/one.txt" --id - "${OWN[@]}" --chown "$ME:$MYGROUP" --flag uchg
expect "--mode on a seal is a usage error" 4 "--mode is for unseal" \
  seal --path "$T/one.txt" --id - "${OWN[@]}" --mode 644 --flag uchg
expect "--swap without --stage is a usage error" 4 "--swap and --stage go together" \
  seal --path "$T/one.txt" --id - "${OWN[@]}" --flag uchg --swap
expect "--stage without --swap is one too" 4 "--swap and --stage go together" \
  seal --path "$T/one.txt" --id - "${OWN[@]}" --flag uchg --stage "$SCRATCH"
expect "--swap on an unseal is a usage error" 4 "--swap and --stage are for seal" \
  unseal --path "$T/one.txt" --id - "${OWN[@]}" --flag uchg --swap --stage "$SCRATCH"
expect "--acl-add is gone" 4 "unknown option --acl-add" \
  seal --path "$T" --id - "${OWN[@]}" --flag uappnd --acl-add "$ME:list"

note "a single-node unseal of a directory"
# A chain folder is one directory whose entries are not part of its seal:
# they may be anyone's, sealed or not. Its unseal touches the top alone.
if [ "$FIFO_OK" -eq 1 ]; then
  /usr/bin/mkfifo "$T/a/zz-fifo"
  seal --path "$T" --id - --owner "$ME" --flag uappnd
  expect "a chain-style unseal succeeds over entries the gate would refuse" 0 - \
    unseal --path "$T" --id - --owner "$ME" --flag uappnd
  check "the flag is off the top" "" "$(flags_of "$T")"
  check "and nothing below it was frozen" "" "$(flagged_under "$T")"
  /bin/mv -- "$T/a/zz-fifo" "$SCRATCH/fifo2.away"
else
  fifo_skip "a chain-style unseal succeeds over entries the gate would refuse" \
    "the flag is off the top" "and nothing below it was frozen"
fi

note "set-user-id"
SU="$T/setuid-tool"
printf 'x\n' >"$SU"
/bin/chmod 4755 "$SU" 2>/dev/null || true
if [ "$(/usr/bin/stat -f '%OLp' "$SU")" = "4755" ]; then
  expect "a seal of a tree holding a set-user-id file is refused" 7 "set-user-id" \
    seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
  check "and nothing changed" "" "$(flagged_under "$T")"
  expect "a set-user-id file named directly is refused too" 7 "set-user-id" \
    seal --path "$SU" --id - "${OWN[@]}" --flag uchg
else
  skip "a seal of a tree holding a set-user-id file is refused" "chmod 4755 not allowed here"
  skip "and nothing changed" "chmod 4755 not allowed here"
  skip "a set-user-id file named directly is refused too" "chmod 4755 not allowed here"
fi
/bin/mv -- "$SU" "$SCRATCH/setuid.away"

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
# away <path>: move a planted node out of the tree, into the scratch dir.
away() { /bin/mv -- "$1" "$SCRATCH/away.$N.$(basename "$1")"; }

T="$SCRATCH/t3"
tree "$T"
note "a plant between plan and apply"
plant_fifo() { /usr/bin/mkfifo "$T/a/b/zz-planted"; }
plant_file() { printf 'new\n' >"$T/a/b/added.txt"; }
if [ "$FIFO_OK" -eq 1 ]; then
  # The helper is held before it opens anything; the plan it was called on
  # is already stale. The count pass meets the plant first and refuses it
  # before any change.
  paused seal plant_fifo seal --path "$T" --id - "${OWN[@]}" --flag uchg \
    --recursive --count "$(count "$T")"
  check "a planted fifo is refused" "7" "$RC"
  said "named as the node that was planted" "a fifo is not a file"
  check "and nothing was frozen" "" "$(flagged_under "$T")"
  away "$T/a/b/zz-planted"

  note "the count guard"
  paused seal plant_file seal --path "$T" --id - "${OWN[@]}" --flag uchg \
    --recursive --count "$(count "$T")"
  check "a node added before the count is refused" "7" "$RC"
  said "with the plan's count and the tree's" "the plan names 7 nodes and the tree holds 8"
  check "before anything was frozen" "" "$(flagged_under "$T")"
  away "$T/a/b/added.txt"
  # After the count: the seal has frozen the folders above the plant by the
  # time it reaches it, and stops at the first node past the plan.
  paused seal-walk plant_file seal --path "$T" --id - "${OWN[@]}" --flag uchg \
    --recursive --count "$(count "$T")"
  check "a node added after the count is refused" "7" "$RC"
  said "at the first node past the plan" "the plan names 7 nodes and the walk reached more"
  check "and every freeze was rolled back" "" "$(flagged_under "$T")"
  away "$T/a/b/added.txt"
  paused seal-walk plant_fifo seal --path "$T" --id - "${OWN[@]}" --flag uchg \
    --recursive --count "$(count "$T")"
  check "a fifo planted after the count is refused by the gate" "7" "$RC"
  said "named as the node that was planted" "a fifo is not a file"
  check "and the folders the seal froze were rolled back" "" "$(flagged_under "$T")"
  away "$T/a/b/zz-planted"
else
  fifo_skip "a planted fifo is refused" "named as the node that was planted" \
    "and nothing was frozen" "a node added before the count is refused" \
    "with the plan's count and the tree's" "before anything was frozen" \
    "a node added after the count is refused" "at the first node past the plan" \
    "and every freeze was rolled back" \
    "a fifo planted after the count is refused by the gate" \
    "named as the node that was planted" \
    "and the folders the seal froze were rolled back"
fi
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
if [ "$FIFO_OK" -eq 1 ]; then
  # The unseal: the tree is frozen, so the plant needs its folder thawed
  # first, as only the owner the test runs as can (a system flag would bind
  # them too). The first pass stops at the node past the plan, and the tree
  # stays sealed as it was.
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
  away "$T/a/b/added.txt"
  /usr/bin/chflags uchg "$T/a/b"
  expect "the unseal with the tree's count succeeds" 0 - \
    unseal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
  check "and nothing is left frozen" "" "$(flagged_under "$T")"
else
  fifo_skip "an unseal that reaches past the plan is refused" \
    "at the first node past the plan" "and the tree is still sealed" \
    "the unseal with the tree's count succeeds" "and nothing is left frozen"
fi

note "copy-and-swap"
STG="$SCRATCH/stage"
/bin/mkdir -m 700 "$STG"
SW=(--swap --stage "$STG")
D="$SCRATCH/s1"
/bin/mkdir -m 755 "$D"
F="$D/conf"
printf 'line one\nline two\n' >"$F"
/bin/chmod 640 "$F"
/usr/bin/touch -t 202401021530.45 "$F"
/usr/bin/xattr -w org.example.kept yes "$F"
/usr/bin/chflags hidden "$F"
OLD_INO="$(ino "$F")"
OLD_MTIME="$(/usr/bin/stat -f '%m' "$F")"
WANT_SUM="$(sha "$F")"
expect "seal --swap seals a file" 0 - \
  seal --path "$F" --id "$("$TST" id "$F")" "${OWN[@]}" --flag uchg "${SW[@]}"
SUMS="$OUT"
check "the file at the name is a new inode" "1" "$([ "$(ino "$F")" != "$OLD_INO" ] && echo 1)"
check "with the same bytes" "$WANT_SUM" "$(sha "$F")"
check "the same mode" "640" "$(/usr/bin/stat -f '%OLp' "$F")"
check "the same modification time" "$OLD_MTIME" "$(/usr/bin/stat -f '%m' "$F")"
check "the same extended attribute" "yes" "$(/usr/bin/xattr -p org.example.kept "$F" 2>/dev/null)"
check "the kept flag and the seal's" "uchg,hidden" "$(flags_of "$F")"
check "the fingerprint line is the copy's, with its bytes" "sum"$'\t'"$WANT_SUM"$'\t'"."$'\t'"18" "$SUMS"
check "and staging is empty again" "" "$(/bin/ls -A "$STG")"
expect "digest prints the same line" 0 - \
  "$TST" digest --src "$F" --src-id - --owner "$ME" --as "$ME"
check "for the sealed file" "$SUMS" "$OUT"
expect "digest --length hashes the first bytes only" 0 - \
  "$TST" digest --src "$F" --src-id - --owner "$ME" --as "$ME" --length 9
check "  the first line's fingerprint, 9 bytes" \
  "sum"$'\t'"$(printf 'line one\n' | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"$'\t'"."$'\t'"9" "$OUT"
expect "digest --length past the end hashes what is there" 0 - \
  "$TST" digest --src "$F" --src-id - --owner "$ME" --as "$ME" --length 999
check "  the whole file, its own count" "$SUMS" "$OUT"
expect "digest --length takes only a count of bytes" 4 "--length must be a count of bytes" \
  "$TST" digest --src "$F" --src-id - --owner "$ME" --as "$ME" --length -1
expect "digest --length is refused with --recursive" 4 "--length applies to a file" \
  "$TST" digest --src "$D" --src-id - --owner "$ME" --as "$ME" --recursive --length 1
unseal --path "$F" --id - "${OWN[@]}" --flag uchg
/usr/bin/chflags nohidden "$F"
# A descriptor this shell holds open for writing points at the inode that
# goes out, so the sealed copy has no writer and the old file keeps the
# shell's writes.
exec 4>>"$F"
expect "a writer on the file being sealed does not reach the copy" 0 - \
  seal --path "$F" --id - "${OWN[@]}" --flag uchg "${SW[@]}"
printf 'late\n' >&4
exec 4>&-
check "and its write lands outside the sealed file" "$WANT_SUM" "$(sha "$F")"
unseal --path "$F" --id - "${OWN[@]}" --flag uchg
# Without --swap the inode stays, so a writer holding it is named.
exec 4>>"$F"
expect "a seal without --swap names a process holding the file for writing" 8 - \
  seal --path "$F" --id - "${OWN[@]}" --flag uchg
exec 4>&-
check "on a writer line with that process" "1" \
  "$(printf '%s\n' "$OUT" | grep -c "^writer"$'\t'"$$"$'\t' || true)"
check "and the seal is done" "uchg" "$(flags_of "$F")"
unseal --path "$F" --id - "${OWN[@]}" --flag uchg
# A sealed folder around the file: its flag comes off for the rename and
# goes back on.
/usr/bin/chflags uappnd "$D"
expect "a file in a sealed folder is swapped" 0 - \
  seal --path "$F" --id - "${OWN[@]}" --flag uchg "${SW[@]}"
check "the folder's flag is back" "uappnd" "$(flags_of "$D")"
unseal --path "$F" --id - "${OWN[@]}" --flag uchg
/usr/bin/chflags nouappnd "$D"
expect "a staging folder others may enter is refused" 7 "is not a folder only root may enter" \
  seal --path "$F" --id - "${OWN[@]}" --flag uchg --swap --stage "$D"
check "and the file is untouched" "" "$(flags_of "$F")"

T="$SCRATCH/t5"
tree "$T"
/bin/ln "$T/a/two.txt" "$T/a/b/two-again.txt"
TWO_INO="$(ino "$T/a/two.txt")"
expect "seal --recursive --swap seals a tree" 0 - \
  seal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive "${SW[@]}"
TSUMS="$OUT"
check "one fingerprint line per file name, in walk order" \
  "a/b/three.txt a/b/two-again.txt a/two.txt one.txt" \
  "$(printf '%s\n' "$TSUMS" | awk -F'\t' '$1=="sum"{printf "%s%s", s, $3; s=" "}')"
check "every node carries the flag" "8" "$(flagged_under "$T" | wc -l | tr -d ' ')"
check "the link was not swapped" "one.txt" "$(/usr/bin/readlink "$T/link")"
check "a hard link's two names are two files now" "1" \
  "$([ "$(ino "$T/a/two.txt")" != "$(ino "$T/a/b/two-again.txt")" ] &&
     [ "$(ino "$T/a/two.txt")" != "$TWO_INO" ] && echo 1)"
expect "digest --recursive prints the seal's lines" 0 - \
  "$TST" digest --src "$T" --src-id - --owner "$ME" --as "$ME" --recursive
check "line for line" "$TSUMS" "$OUT"
expect "the tree unseals" 0 - \
  unseal --path "$T" --id - "${OWN[@]}" --flag uchg --recursive
check "and nothing is left frozen" "" "$(flagged_under "$T")"
check "and staging is empty" "" "$(/bin/ls -A "$STG")"

note "install"
D="$SCRATCH/i1"
/bin/mkdir -m 755 "$D"
printf 'old\n' >"$D/f"
seal --path "$D/f" --id - "${OWN[@]}" --flag uchg
FID="$("$TST" id "$D/f")"
stage_file() { printf '%s' "$1" >"$STG/new"; /bin/chmod 600 "$STG/new"; }
stage_file $'new\n'
NEW_INO="$(ino "$STG/new")"
INS=(--parent "$D" --parent-id - --name f --chown "$ME:$MYGROUP" --mode 644 --flag uchg)
expect "install refuses a target that is not --target-id" 2 "changed identity" \
  "$TST" install --src "$STG/new" "${INS[@]}" --target-id "${FID%:*}:1" --owner "$ME"
check "and the sealed file is as it was" "old" "$(cat "$D/f")"
expect "install puts the staged file in place of the sealed one" 0 - \
  "$TST" install --src "$STG/new" "${INS[@]}" --target-id "$FID" --owner "$ME"
check "the file at the name is the staged inode" "$NEW_INO" "$(ino "$D/f")"
check "with its bytes" "new" "$(cat "$D/f")"
check "the mode asked for" "644" "$(/usr/bin/stat -f '%OLp' "$D/f")"
check "and the flag" "uchg" "$(flags_of "$D/f")"
check "the fingerprint line is the staged bytes'" "sum"$'\t'"$(sha "$D/f")"$'\t'"."$'\t'"$(/usr/bin/stat -f %z "$D/f")" "$OUT"
check "and staging is empty" "" "$(/bin/ls -A "$STG")"
stage_file $'brand new\n'
expect "install --new refuses a name that is taken" 7 "already at the new name" \
  "$TST" install --src "$STG/new" "${INS[@]}" --new
/usr/bin/chflags uappnd "$D"
expect "install --new puts a file at a free name in a sealed folder" 0 - \
  "$TST" install --src "$STG/new" --parent "$D" --parent-id - --name g \
  --chown "$ME:$MYGROUP" --mode 600 --flag uchg --new
check "with its bytes" "brand new" "$(cat "$D/g")"
check "the folder's flag is back" "uappnd" "$(flags_of "$D")"
check "and the new file's" "uchg" "$(flags_of "$D/g")"
/usr/bin/chflags nouappnd "$D"
stage_file x
expect "install with --new and --target-id is a usage error" 4 "--new names no target" \
  "$TST" install --src "$STG/new" "${INS[@]}" --new --target-id - --owner "$ME"
expect "install with a set-id mode is a usage error" 4 "no set-id bit" \
  "$TST" install --src "$STG/new" --parent "$D" --parent-id - --name h \
  --chown "$ME:$MYGROUP" --mode 4755 --flag uchg --new
expect "install from outside staging is refused" 7 "not in a folder only root may enter" \
  "$TST" install --src "$D/f" --parent "$D" --parent-id - --name h \
  --chown "$ME:$MYGROUP" --mode 644 --flag uchg --new

note "mount"
VOL="$(/bin/df -P "$SCRATCH" | /usr/bin/awk 'NR==2{print $NF}')"
expect "mount names the volume a folder is on" 0 - "$TST" mount "$SCRATCH"
check "as df does" "$VOL" "$OUT"
expect "and a file's, through its folder" 0 - "$TST" mount "$D/f"
check "the same volume" "$VOL" "$OUT"

note "the release of a 0.16 placement entry (one-shot conversion)"
# 0.16 and earlier gave a placement directory one ACL entry for the
# invoker; the conversion's unseal takes exactly that entry off. An ordinary
# user may change the ACL of a directory they own, so it all shows here.
acl_of() { /bin/ls -ledq -- "$1" | /usr/bin/sed -e 1d -e 's/^ *[0-9][0-9]*: //'; }
R=list,add_file,search,add_subdirectory,readattr,readextattr,readsecurity
ENT="user:$ME allow $R"
DENY="group:everyone deny delete"
PL=(--owner "$ME" --chown "$ME:$MYGROUP" --count 1)
P="$SCRATCH/p1"
/bin/mkdir -m 755 "$P"
/bin/chmod +a "$DENY" "$P"
/bin/chmod +a "$ENT" "$P"
/usr/bin/chflags uappnd "$P"
expect "unseal --acl-remove takes the entry off" 0 - \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --mode 755 --flag uappnd \
  --acl-remove "$ME:$R"
check "and only that entry" "$DENY" "$(acl_of "$P")"
check "with the flag off" "" "$(flags_of "$P")"
check "and no acl-absent line" "0" "$(printf '%s\n' "$OUT" | grep -c '^acl-absent' || true)"
expect "an unseal with no such entry succeeds" 0 - \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uappnd --acl-remove "$ME:$R"
check "and says so on an acl-absent line" "acl-absent"$'\t'"$P" \
  "$(printf '%s\n' "$OUT" | grep '^acl-absent' || true)"
/bin/chmod +a "$ENT,file_inherit" "$P"
expect "an entry with an inherit flag is not the seal's" 0 "acl-absent" \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uappnd --acl-remove "$ME:$R"
check "and is left in place" "$DENY"$'\n'"$ENT,file_inherit" "$(acl_of "$P")"
/bin/chmod -a "$ENT,file_inherit" "$P"
/bin/chmod +a "user:$ME allow list" "$P"
expect "nor is one with other rights" 0 "acl-absent" \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uappnd --acl-remove "$ME:$R"
check "which stays too" "$DENY"$'\n'"user:$ME allow list" "$(acl_of "$P")"
/bin/chmod -a "user:$ME allow list" "$P"
expect "a right that seal never granted is a usage error" 4 \
  "names a right a placement seal does not grant: 'delete_child'" \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uappnd --acl-remove "$ME:list,delete_child"
expect "--acl-remove without rights is a usage error" 4 "--acl-remove must be <user>:<right>" \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uappnd --acl-remove "$ME:"
expect "--acl-remove naming no account is a usage error" 4 "--acl-remove names no account" \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uappnd --acl-remove "no-such-user-zz:list"
expect "--acl-remove on a seal is a usage error" 4 "--acl-remove is for unseal" \
  "$TST" seal --path "$P" --id - --owner "$ME" --count 1 --flag uappnd --acl-remove "$ME:$R"
expect "--acl-remove with --recursive is a usage error" 4 "never --recursive" \
  "$TST" unseal --path "$P" --id - "${PL[@]}" --flag uchg --recursive --acl-remove "$ME:$R"
printf 'f\n' >"$P/f.txt"
expect "an entry on a file is refused" 7 "an ACL entry goes on a directory only" \
  "$TST" unseal --path "$P/f.txt" --id - "${PL[@]}" --flag uappnd --acl-remove "$ME:$R"
/bin/chmod -a "$DENY" "$P"

note "a directory swapped between plan and seal"
P="$SCRATCH/p4"
/bin/mkdir -m 755 "$P"
PID="$("$TST" id "$P")"
P3="$SCRATCH/p3"
/bin/mkdir -m 755 "$P3"
swap_dir() { /bin/mv -- "$P" "$P.away"; /bin/mkdir -m 755 "$P"; }
swap_link() { /bin/ln -s "$P3" "$P"; }
if [ "$FIFO_OK" -eq 1 ]; then
  paused seal swap_dir seal --path "$P" --id "$PID" --owner "$ME" --count 1 --flag uappnd
  check "a directory swapped in after the plan is refused" "2" "$RC"
  said "by the identity pin" "changed identity"
  check "and gets no flag" "" "$(flags_of "$P")"
  check "nor does the one the plan pinned" "" "$(flags_of "$P.away")"
  /bin/rmdir -- "$P"
  paused seal swap_link seal --path "$P" --id "$PID" --owner "$ME" --count 1 --flag uappnd
  check "a symlink swapped in after the plan is refused" "2" "$RC"
  check "and what it points at gets no flag" "" "$(flags_of "$P3")"
  away "$P"
else
  fifo_skip "a directory swapped in after the plan is refused" "by the identity pin" \
    "and gets no flag" "nor does the one the plan pinned" \
    "a symlink swapped in after the plan is refused" "and what it points at gets no flag"
fi

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
if [ "$FIFO_OK" -eq 1 ]; then
  /usr/bin/mkfifo "$T/a/zz-fifo"
  expect "copy-tree refuses a fifo" 7 "a fifo is not a file" \
    "$TST" copy-tree --src "$T" --src-id - --owner "$ME" "${AS[@]}" \
    --dest "$SCRATCH/copy3" --chown "$ME:$MYGROUP"
else
  fifo_skip "copy-tree refuses a fifo"
fi

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
