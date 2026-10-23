#!/usr/bin/env bash
# The three verify commands agree: rust voleith-verify, python/tools/verify_cli.py
# and go/cmd/voleith-verify, on the 4 vector proofs, 20 differential cases
# and the usage errors of crosscheck/cli_agree.py.
# Usage: bash crosscheck/cli.sh   (from the repository root or anywhere)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
WORK=$HERE/work/cli
mkdir -p "$WORK"

cargo build --quiet --release --features cli --bin voleith-verify --manifest-path "$ROOT/rust/Cargo.toml"
(cd "$ROOT/go" && go build -o "$WORK/voleith-verify-go" ./cmd/voleith-verify)

python3 -I "$HERE/cli_agree.py" "$WORK" \
  "$ROOT/rust/target/release/voleith-verify" \
  "python3 -I $ROOT/python/tools/verify_cli.py" \
  "$WORK/voleith-verify-go"
