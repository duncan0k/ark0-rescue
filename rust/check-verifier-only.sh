#!/usr/bin/env bash
# Builds the verifier-only static library (no `prover` feature) and checks
# with nm that it exports voleith_verify_s1 and holds no prover symbol.
# The same scan of a default build (with the prover) must find prover
# symbols, so that a pattern that matches nothing cannot pass.
# Both builds are made without LTO as well: LTO internalizes and drops
# unreachable Rust code, which would hide prover code that is compiled in.
# Usage: bash rust/check-verifier-only.sh   (from anywhere; needs nm)
set -euo pipefail
cd "$(dirname "$0")"
OUT=${CHECK_TARGET_DIR:-target/check-verifier-only}

# Prover-only items: proof::{prove, prove_scrubbed, prove_impl,
# prove_traced, scrub_stack, ProverTrace, ProveError}, vc::{commit, Tree},
# unihash::CtMul, circuit::Circuit::{evaluate, prover_terms},
# statements::{s1_hmac, s1_secret_bits} and the dudect module.
PAT='voleith[0-9a-z_]*::(proof::(prove|prove_scrubbed|prove_impl|prove_traced|scrub_stack|ProverTrace|ProveError)|vc::(commit|Tree)|unihash::CtMul|circuit::Circuit>?::(evaluate|prover_terms)|statements::(s1_hmac|s1_secret_bits)|dudect)|ProverTrace|prove_impl|prove_scrubbed|scrub_stack|CtMul|prover_terms'

fail=0
scan() { # label features lto expect(none|some)
  local label=$1 feats=$2 lto=$3 expect=$4 dir=$OUT/$1
  CARGO_PROFILE_RELEASE_LTO=$lto cargo build --quiet --release --lib $feats --target-dir "$dir"
  local a=$dir/release/libvoleith.a
  local exported hits
  exported=$(nm -C "$a" 2>/dev/null | grep -cE ' T voleith_verify_s1$' || true)
  hits=$(nm -C "$a" 2>/dev/null | grep -cE "$PAT" || true)
  echo "$label: voleith_verify_s1 exported $exported time(s), prover symbols $hits"
  if [ "$exported" -lt 1 ]; then fail=1; fi
  if [ "$expect" = none ] && [ "$hits" -ne 0 ]; then
    nm -C "$a" 2>/dev/null | grep -E "$PAT" | sort -u | head -20
    fail=1
  fi
  if [ "$expect" = some ] && [ "$hits" -eq 0 ]; then
    echo "$label: the pattern found nothing in a build with the prover"
    fail=1
  fi
}

scan verifier-only-lto --no-default-features true none
scan verifier-only-nolto --no-default-features false none
scan default-lto "" true some
scan default-nolto "" false some
if [ "$fail" -ne 0 ]; then
  echo FAIL
  exit 1
fi
echo OK
