#!/usr/bin/env bash
# Runs the three targets in parallel on 4 cores for SECS seconds (default
# 11400 = 3h10m): verify_mutate on cores 0-1, verify_raw on 2, ffi on 3.
# Build first:
#   cargo +nightly fuzz build -O -a -s none verify_raw
#   cargo +nightly fuzz build -O -a -s none verify_mutate
#   cargo +nightly fuzz build -O -a -s address --target-dir target-asan ffi
#   cargo run --release --bin seed_corpus corpus
set -u
cd "$(dirname "$0")"
SECS=${1:-11400}
B=target/x86_64-unknown-linux-gnu/release
A=target-asan/x86_64-unknown-linux-gnu/release
export VOLEITH_SLOW_DIR=$PWD/slow
mkdir -p logs slow artifacts/verify_raw artifacts/verify_mutate artifacts/ffi
COMMON="-max_len=140000 -timeout=10 -print_final_stats=1 -max_total_time=$SECS"
run() { # core target binary logname extra...
  local core=$1 t=$2 bin=$3 log=$4; shift 4
  taskset -c "$core" "$bin" $COMMON -artifact_prefix=artifacts/$t/ "$@" corpus/$t > logs/$log.log 2>&1
  echo "$log exit $?" >> logs/exits.txt
}
: > logs/exits.txt
date -u +%FT%TZ > logs/start.txt
run 0 verify_mutate $B/verify_mutate verify_mutate-0 &
run 1 verify_mutate $B/verify_mutate verify_mutate-1 &
run 2 verify_raw $B/verify_raw verify_raw -use_value_profile=1 &
run 3 ffi $A/ffi ffi -use_value_profile=1 &
wait
date -u +%FT%TZ > logs/end.txt
