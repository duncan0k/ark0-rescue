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
# - nm must exit 0, and its listing must be complete: the number of symbol
#   lines of `nm -a -C` equals the number of .symtab entries that
#   `readelf -sW` reports (the sum over all members of an archive, less
#   each table's null entry), which a truncated listing cannot match;
# - grep's status 1 is "no match", status 2 or more fails the check.
# Before the builds, a self-test runs these functions on a missing file, a
# directory, an empty file and a truncated listing, and each must fail.
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

# A symbol line of `nm -a`: an address or blanks, a type letter, a name.
SYMLINE='^([0-9a-f]{8,16}| {8,16}) [A-Za-z?-] '

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
    END {if (t) print s}' <<< "$listing")
  [[ "$n" =~ ^[0-9]+$ ]] || return 2
  echo "$n"
}

# Lists the symbols of BINARY into LISTING with `nm -a -C`; status 2 if nm
# fails or the listing does not hold every .symtab entry.
list_symbols() { # binary listing
  local lines entries
  [ -f "$1" ] || return 2
  nm -a -C -- "$1" > "$2" 2> "$2.err" || return 2
  lines=$(count_re "$2" "$SYMLINE") || return 2
  entries=$(symtab_entries "$1") || return 2
  [ "$lines" -eq "$entries" ] || return 2
  echo "$lines"
}

self_test() {
  local d=$SYMS/self-test n
  mkdir -p "$d/dir"
  : > "$d/empty.txt"
  for bad in "$d/missing.txt" "$d/dir"; do
    if count_re "$bad" x > /dev/null; then
      echo "self-test: count_re read $bad" >&2
      return 1
    fi
  done
  n=$(count_re "$d/empty.txt" x) && [ "$n" -eq 0 ] || {
    echo "self-test: count_re on an empty file" >&2
    return 1
  }
  # A listing of a real archive passes, the same listing cut short does
  # not, and neither does a missing or empty binary.
  local a=$1
  list_symbols "$a" "$d/full.txt" > /dev/null || {
    echo "self-test: list_symbols failed on $a" >&2
    return 1
  }
  head -n "$(($(wc -l < "$d/full.txt") / 2))" "$d/full.txt" > "$d/cut.txt"
  local lines entries
  lines=$(count_re "$d/cut.txt" "$SYMLINE") && entries=$(symtab_entries "$a") || {
    echo "self-test: cannot count the cut listing" >&2
    return 1
  }
  if [ "$lines" -eq "$entries" ]; then
    echo "self-test: a listing cut in half looks complete" >&2
    return 1
  fi
  for bad in "$d/missing.a" "$d/empty.txt"; do
    if list_symbols "$bad" "$d/x.txt" > /dev/null; then
      echo "self-test: list_symbols accepted $bad" >&2
      return 1
    fi
  done
  echo "self-test: a missing file, a directory, an empty binary and a cut listing are all caught"
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
  exe=$(cargo test --quiet --release --lib --no-run "$@" --target-dir "$OUT/$label" \
    --message-format=json 2> /dev/null |
    python3 -I -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(m["executable"])' | tail -n 1)
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
