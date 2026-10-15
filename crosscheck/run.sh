#!/usr/bin/env bash
# Three-implementation cross-check (crosscheck/REPORT.md, step 3).
# Usage: bash crosscheck/run.sh [seed]   (from the repository root or anywhere)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SEED=${1:-20261015}
WORK=$HERE/work
GO_SRC=$WORK/go-src
mkdir -p "$WORK"

# 1. Cases and tests (y from Python's hmac module).
python3 -I "$HERE/gen.py" "$SEED" "$WORK"

# 2. Prove with the Rust prover of this branch, verify with the Rust verifier.
cargo build --release --manifest-path "$HERE/Cargo.toml"
BIN=$HERE/target/release/voleith-crosscheck
"$BIN" prove "$WORK/cases.tsv" "$WORK/proofs.txt"
"$BIN" verify "$WORK/cases.tsv" "$WORK/proofs.txt" "$WORK/tests.tsv" "$WORK/verdicts-rust.tsv"

# 3. The Python reference.
python3 -I "$HERE/verify_py.py" "$ROOT/python" "$WORK/cases.tsv" "$WORK/proofs.txt" \
  "$WORK/tests.tsv" "$WORK/verdicts-python.tsv" 4

# 4. The clean-room Go verifier in go/, copied to a scratch module so that
#    the driver does not add files to go/.
mkdir -p "$GO_SRC/go/cmd/xcverify"
cp -R "$ROOT/go/." "$GO_SRC/go/"
cp "$HERE/go/main.go" "$GO_SRC/go/cmd/xcverify/main.go"
(cd "$GO_SRC/go" && go build -o "$WORK/xcverify" ./cmd/xcverify)
"$WORK/xcverify" "$WORK/cases.tsv" "$WORK/proofs.txt" "$WORK/tests.tsv" "$WORK/verdicts-go.tsv"

# 5. Compare.
python3 -I "$HERE/compare.py" "$WORK" "$HERE/findings"
