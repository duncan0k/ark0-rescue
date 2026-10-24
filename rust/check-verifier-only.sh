#!/usr/bin/env bash
# Builds the verifier-only static library (no `prover` feature) and checks
# with nm that it exports voleith_verify_s1 and holds no prover symbol.
#
# Every pattern has a positive control: it must match in a build with the
# prover, so that a pattern that can never match cannot pass. The controls
# are a staticlib with the prover, `test-trace` and `fault-injection`, built
# at opt-level 0 without LTO (so that nothing is inlined away), and, for the
# dudect module, which exists only under cfg(test), the library's unit-test
# binary. The verifier-only side is checked with LTO, without LTO, and at
# opt-level 0 without LTO, and its unit-test binary too.
#
# A failed or incomplete scan never counts as "no match":
# - nm must exit 0 with nothing on standard error, its listing must end
#   with a newline, and the number of complete symbol lines of `nm -a -C`
#   (address or blanks, type letter, a non-empty name) must equal the
#   number of .symtab entries that `readelf -sW` reports (the sum over all
#   members of an archive, less each table's null entry);
# - grep's status 1 is "no match", status 2 or more fails the check.
# A self-test runs these functions on a missing file, a directory, an
# empty file, and copies of a real listing cut after a type letter (with
# and without a newline), cut mid-line, cut in half, or with a message on
# nm's standard error, and each must fail.
# Usage: bash rust/check-verifier-only.sh   (from anywhere; needs nm, readelf)
set -euo pipefail
cd "$(dirname "$0")"
OUT=${CHECK_TARGET_DIR:-target/check-verifier-only}

# name|extended regex on `nm -a -C` output
PATTERNS=(
  'prove|voleith[0-9a-z_]*::proof::prove$'
  'prove_scrubbed|proof::prove_scrubbed'
  'prove_impl|proof::prove_impl'
  'scrub_stack|proof::scrub_stack'
  'prove_traced|proof::prove_traced'
  'ProverTrace|ProverTrace'
  'ProveError|ProveError'
  'vc::commit|vc::commit'
  'vc::Tree|vc::Tree'
  'CtMul|unihash::CtMul'
  'evaluate|Circuit>?::evaluate'
  'prover_terms|Circuit>?::prover_terms'
  's1_hmac|statements::s1_hmac'
  's1_secret_bits|statements::s1_secret_bits'
  'fault|voleith[0-9a-z_]*::fault::'
  'dudect|voleith[0-9a-z_]*::dudect::'
)

fail=0
SYMS=$OUT/symbols
mkdir -p "$SYMS"

# A complete symbol line of `nm -a`: an address or blanks, a type letter
# and a non-empty name (a line cut after the type letter is not one).
SYMLINE='^([0-9a-f]{8,16}| {8,16}) [A-Za-z?-] [^ ]'

# The number of lines of FILE matching the extended regex RE; status 2,
# with nothing printed, if grep could not read FILE (status 2 or more), so
# that a failed scan is never a count of 0.
count_re() { # file re
  local n rc
  n=$(grep -cE -- "$2" "$1" 2> /dev/null) && rc=0 || rc=$?
  if [ "$rc" -gt 1 ] || ! [[ "$n" =~ ^[0-9]+$ ]]; then
    return 2
  fi
  echo "$n"
}

# The .symtab entries of BINARY (an archive or an executable), less each
# table's null entry, from readelf; status 2 if readelf fails or finds none.
symtab_entries() { # binary
  local listing n
  listing=$(readelf -sW -- "$1" 2> /dev/null) || return 2
  n=$(awk '/^Symbol table .\.symtab. contains [0-9]+ entr/ {s += $5 - 1; t++}
    END {if (t) print s}' <<< "$listing") || return 2
  [[ "$n" =~ ^[0-9]+$ ]] || return 2
  echo "$n"
}

# Whether LISTING, nm's output for BINARY with nm's standard error in
# ERRFILE, is complete: nm wrote nothing to standard error, the listing
# ends with a newline, and its complete symbol lines are exactly the
# .symtab entries readelf reports. Prints the count; status 2 otherwise.
# Whether FILE ends with a newline: status 0 if so, 1 if not, 2 if it
# cannot be read (tail fails), so that a failed read is never "a newline".
# TAIL is the tail command; only the self-test sets it, to `false`.
TAIL=tail
ends_with_newline() { # file
  local last
  [ -f "$1" ] || return 2
  last=$("$TAIL" -c 1 -- "$1" 2> /dev/null) || return 2
  [ -z "$last" ] && [ -s "$1" ] && return 0
  return 1
}

check_listing() { # binary listing errfile
  local lines entries
  [ -s "$2" ] || return 2
  [ ! -s "$3" ] || return 2
  ends_with_newline "$2" || return 2
  lines=$(count_re "$2" "$SYMLINE") || return 2
  entries=$(symtab_entries "$1") || return 2
  [ "$lines" -eq "$entries" ] || return 2
  echo "$lines"
}

# Lists the symbols of BINARY into LISTING with `nm -a -C`; status 2 if nm
# fails or the listing is not complete (check_listing).
list_symbols() { # binary listing
  [ -f "$1" ] || return 2
  nm -a -C -- "$1" > "$2" 2> "$2.err" || return 2
  check_listing "$1" "$2" "$2.err"
}

# The self-test is called as `self_test || fail=1`, where bash does not
# apply `set -e`: every step below checks its own status, and every
# defective sample is checked to have the defect it is meant to have, so
# that a sample that failed to be made cannot pass as a caught defect.
st_fail() {
  echo "self-test: $*" >&2
  return 1
}

# The last complete symbol line of LISTING cut right after its type letter
# and the space after it (the name field removed), whatever the width of
# the address column (8 or 16 characters, or blanks); on standard output.
cut_after_type() { # listing
  local last line
  last=$(grep -nE -- "$SYMLINE" "$1" | tail -n 1) || return 1
  last=${last%%:*}
  [[ "$last" =~ ^[0-9]+$ ]] || return 1
  head -n "$((last - 1))" -- "$1" || return 1
  line=$(sed -n "${last}p" -- "$1") || return 1
  [[ "$line" =~ ^(([0-9a-f]{8}|[0-9a-f]{16}| {8}| {16})\ [A-Za-z?-]\ ) ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
  sed -n "$((last + 1)),\$p" -- "$1" || return 1
}

# For BINARY: its listing passes check_listing, and each defect, put into
# a copy and given to the same check_listing, fails. DIR holds the files.
defect_samples() { # binary dir
  local a=$1 d=$2 n total size
  mkdir -p "$d" || st_fail "cannot make $d" || return 1
  list_symbols "$a" "$d/full.txt" > /dev/null || st_fail "list_symbols failed on $a" || return 1
  : > "$d/noerr.txt" || return 1
  echo "nm: some warning" > "$d/err.txt" || return 1
  total=$(wc -l < "$d/full.txt") || return 1
  size=$(wc -c < "$d/full.txt") || return 1
  # The last symbol line cut after its type letter, with a newline and
  # without one; the cut line must then be exactly "<address> <type> ".
  cut_after_type "$d/full.txt" > "$d/cut-type.txt" || st_fail "cannot cut $d/full.txt" || return 1
  n=$(wc -l < "$d/cut-type.txt") || return 1
  [ "$n" -eq "$total" ] || st_fail "cut-type has another line count" || return 1
  n=$(grep -cE -- '^([0-9a-f]{8}|[0-9a-f]{16}| {8}| {16}) [A-Za-z?-] $' "$d/cut-type.txt") &&
    [ "$n" -eq 1 ] || st_fail "cut-type does not end a line after the type letter" || return 1
  { head -n "$((total - 1))" -- "$d/cut-type.txt" && tail -n 1 -- "$d/cut-type.txt" | tr -d '\n'; } \
    > "$d/cut-type-nonl.txt" || return 1
  # Cut in the middle of the last line, and in half at a line boundary.
  head -c "$((size - 5))" -- "$d/full.txt" > "$d/cut-mid.txt" || return 1
  head -n "$((total / 2))" -- "$d/full.txt" > "$d/cut-half.txt" || return 1
  local f
  for f in cut-type-nonl.txt cut-mid.txt; do
    n=0
    ends_with_newline "$d/$f" || n=$?
    [ "$n" -eq 1 ] || st_fail "$f should end without a newline" || return 1
  done
  n=0
  ends_with_newline "$d/cut-half.txt" || n=$?
  [ "$n" -eq 0 ] || st_fail "cut-half.txt should end with a newline" || return 1
  local case
  for case in "full.txt|err.txt" "cut-type.txt|noerr.txt" "cut-type-nonl.txt|noerr.txt" \
    "cut-mid.txt|noerr.txt" "cut-half.txt|noerr.txt" "noerr.txt|noerr.txt"; do
    if check_listing "$a" "$d/${case%%|*}" "$d/${case#*|}" > /dev/null; then
      st_fail "check_listing accepted $case for $a" || return 1
    fi
  done
  check_listing "$a" "$d/full.txt" "$d/noerr.txt" > /dev/null ||
    st_fail "check_listing refused the intact listing of $a" || return 1
}

self_test() {
  local d=$SYMS/self-test n rc total
  mkdir -p "$d/dir" || return 1
  : > "$d/empty.txt" || return 1
  printf 'x\n' > "$d/nl.txt" || return 1
  for bad in "$d/missing.txt" "$d/dir"; do
    if count_re "$bad" x > /dev/null; then
      st_fail "count_re read $bad" || return 1
    fi
    # A file that tail cannot read is not "a newline".
    rc=0
    ends_with_newline "$bad" || rc=$?
    [ "$rc" -eq 2 ] || st_fail "ends_with_newline gave $rc for $bad" || return 1
  done
  ends_with_newline "$d/nl.txt" || st_fail "ends_with_newline on a newline" || return 1
  # tail failing on a readable file (as root, no file is unreadable): the
  # same function with `false` as tail must report a failed read.
  rc=0
  TAIL=false ends_with_newline "$d/nl.txt" || rc=$?
  [ "$rc" -eq 2 ] || st_fail "ends_with_newline gave $rc when tail failed" || return 1
  n=$(count_re "$d/empty.txt" x) && [ "$n" -eq 0 ] || st_fail "count_re on an empty file" || return 1
  # The real archive's listing (16-character addresses) for every defect.
  defect_samples "$1" "$d/archive" || return 1
  # The cut after the type letter for both address widths, on committed
  # nm listings with 8- and 16-character address columns: the cut line
  # must end right after the type letter and no longer count as a symbol
  # line. (No assembler is needed, so this runs on any host.)
  local fx full cut
  for fx in nm-addr8.txt nm-addr16.txt; do
    fx=tests/fixtures/$fx
    total=$(wc -l < "$fx") || st_fail "cannot read $fx" || return 1
    full=$(count_re "$fx" "$SYMLINE") || st_fail "cannot scan $fx" || return 1
    [ "$full" -eq "$total" ] || st_fail "$fx has lines that are not symbol lines" || return 1
    cut_after_type "$fx" > "$d/cut-$(basename "$fx")" || st_fail "cannot cut $fx" || return 1
    n=$(wc -l < "$d/cut-$(basename "$fx")") || return 1
    [ "$n" -eq "$total" ] || st_fail "the cut of $fx has another line count" || return 1
    n=$(grep -cE -- '^([0-9a-f]{8}|[0-9a-f]{16}| {8}| {16}) [A-Za-z?-] $' "$d/cut-$(basename "$fx")") &&
      [ "$n" -eq 1 ] || st_fail "the cut of $fx does not end a line after the type letter" || return 1
    cut=$(count_re "$d/cut-$(basename "$fx")" "$SYMLINE") || return 1
    [ "$cut" -eq "$((full - 1))" ] || st_fail "the cut line of $fx is still counted" || return 1
  done
  for bad in "$d/missing.a" "$d/empty.txt"; do
    if list_symbols "$bad" "$d/x.txt" > /dev/null; then
      st_fail "list_symbols accepted $bad" || return 1
    fi
  done
  echo "self-test: an unreadable file, a cut or erroring listing (16- and 8-character addresses) and an empty binary are all caught"
}

lib() { # label lto opt-level codegen-units features...
  local label=$1 lto=$2 opt=$3 cgu=$4 n exported
  shift 4
  CARGO_PROFILE_RELEASE_LTO=$lto CARGO_PROFILE_RELEASE_OPT_LEVEL=$opt \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$cgu \
    cargo build --quiet --release --lib "$@" --target-dir "$OUT/$label"
  if ! n=$(list_symbols "$OUT/$label/release/libvoleith.a" "$SYMS/$label.txt"); then
    echo "$label: nm failed or its listing is incomplete" >&2
    fail=1
    return
  fi
  if ! exported=$(count_re "$SYMS/$label.txt" ' T voleith_verify_s1$'); then
    echo "$label: cannot scan the listing" >&2
    fail=1
    return
  fi
  echo "$label: $n symbols (= readelf), voleith_verify_s1 exported $exported time(s)"
  if [ "$exported" -lt 1 ]; then fail=1; fi
}

unit_tests() { # label features...
  local label=$1 exe n
  shift
  # The JSON reader prints exactly one path, the last test executable,
  # and fails (as does the pipeline, under pipefail) if there is none or
  # if the path holds a newline; no `tail` cuts a path apart.
  if ! exe=$(cargo test --quiet --release --lib --no-run "$@" --target-dir "$OUT/$label" \
    --message-format=json 2> /dev/null |
    python3 -I -c 'import json,sys
exes = [m["executable"] for m in map(json.loads, sys.stdin)
        if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]]
if not exes or "\n" in exes[-1]:
    sys.exit(1)
sys.stdout.write(exes[-1])'); then
    echo "$label: building the unit tests or finding their binary failed" >&2
    fail=1
    return
  fi
  if [ -z "$exe" ] || ! n=$(list_symbols "$exe" "$SYMS/$label.txt"); then
    echo "$label: no unit-test binary, or nm failed or its listing is incomplete" >&2
    fail=1
    return
  fi
  echo "$label: $(basename "$exe"), $n symbols (= readelf)"
}

# verifier-only-lto is the release profile as it stands (lto = true,
# codegen-units = 1): the archive that Bitcoin Core links. With 16
# codegen units, lto = true left the archive unmerged, so it was not that.
lib verifier-only-lto true 3 1 --no-default-features
self_test "$OUT/verifier-only-lto/release/libvoleith.a" || fail=1
lib verifier-only-nolto false 3 16 --no-default-features
lib verifier-only-O0 false 0 16 --no-default-features
unit_tests verifier-only-tests --no-default-features
lib control-O0 false 0 16 --features test-trace,fault-injection
unit_tests control-tests

LABELS=(verifier-only-lto verifier-only-nolto verifier-only-O0 verifier-only-tests)
for entry in "${PATTERNS[@]}"; do
  name=${entry%%|*}
  re=${entry#*|}
  line="$name:"
  for label in "${LABELS[@]}"; do
    if ! n=$(count_re "$SYMS/$label.txt" "$re"); then
      line="$line $label=SCAN-FAILED"
      fail=1
      continue
    fi
    line="$line $label=$n"
    if [ "$n" -ne 0 ]; then
      fail=1
      grep -m 5 -E -- "$re" "$SYMS/$label.txt" || true
    fi
  done
  c=0
  for label in control-O0 control-tests; do
    if ! k=$(count_re "$SYMS/$label.txt" "$re"); then
      line="$line $label=SCAN-FAILED"
      fail=1
      continue
    fi
    c=$((c + k))
  done
  line="$line control=$c"
  if [ "$c" -eq 0 ]; then
    line="$line (NO MATCH IN THE CONTROL)"
    fail=1
  fi
  echo "$line"
done
if [ "$fail" -ne 0 ]; then
  echo FAIL
  exit 1
fi
echo OK
