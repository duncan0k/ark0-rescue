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
# Usage: bash rust/check-verifier-only.sh   (from anywhere; needs nm)
set -euo pipefail
cd "$(dirname "$0")"
OUT=${CHECK_TARGET_DIR:-target/check-verifier-only}

# name|extended regex on `nm -C` output
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

lib() { # label lto opt-level features...
  local label=$1 lto=$2 opt=$3
  shift 3
  CARGO_PROFILE_RELEASE_LTO=$lto CARGO_PROFILE_RELEASE_OPT_LEVEL=$opt \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    cargo build --quiet --release --lib "$@" --target-dir "$OUT/$label"
  nm -C "$OUT/$label/release/libvoleith.a" 2>/dev/null > "$SYMS/$label.txt" || true
  local exported
  exported=$(grep -cE ' T voleith_verify_s1$' "$SYMS/$label.txt" || true)
  echo "$label: voleith_verify_s1 exported $exported time(s)"
  if [ "$exported" -lt 1 ]; then fail=1; fi
}

unit_tests() { # label features...
  local label=$1
  shift
  local exe
  exe=$(cargo test --quiet --release --lib --no-run "$@" --target-dir "$OUT/$label" \
    --message-format=json 2>/dev/null |
    python3 -I -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
        print(m["executable"])' | tail -n 1)
  nm -C "$exe" 2>/dev/null > "$SYMS/$label.txt" || true
  echo "$label: $(basename "$exe")"
}

lib verifier-only-lto true 3 --no-default-features
lib verifier-only-nolto false 3 --no-default-features
lib verifier-only-O0 false 0 --no-default-features
unit_tests verifier-only-tests --no-default-features
lib control-O0 false 0 --features test-trace,fault-injection
unit_tests control-tests

# An empty symbol list (a failed build or lookup) would pass every check.
for f in "$SYMS"/*.txt; do
  if [ "$(wc -l < "$f")" -lt 100 ]; then
    echo "$f: no symbols"
    fail=1
  fi
done

for entry in "${PATTERNS[@]}"; do
  name=${entry%%|*}
  re=${entry#*|}
  line="$name:"
  for label in verifier-only-lto verifier-only-nolto verifier-only-O0 verifier-only-tests; do
    n=$(grep -cE "$re" "$SYMS/$label.txt" || true)
    line="$line $label=$n"
    if [ "$n" -ne 0 ]; then
      fail=1
      grep -E "$re" "$SYMS/$label.txt" | head -5
    fi
  done
  c=$(cat "$SYMS/control-O0.txt" "$SYMS/control-tests.txt" | grep -cE "$re" || true)
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
