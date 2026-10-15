# Independent cross-check of the constant-time prover (branch `ct-prover`)

Date: 2026-10-15. Base: `origin/ct-prover` at `08bf7fa`. Machine: 4 vCPU
Intel Xeon @ 2.80 GHz (1 thread per core), with `pclmulqdq` in
`/proc/cpuinfo`; rustc 1.97.0 stable, nightly 1.101 (cargo-fuzz 0.13.2),
Go from `/usr/local/go`, Python 3. Nothing under `rust/src`, `python/`,
`vectors/` or `SPEC.md` was changed.

**Result: no finding.** I found no bug, no disagreement between the three
implementations, no crash, no timeout and no accepted modified proof. The
only fuzz signal was a set of "slow" inputs, and none of them reproduces
(§4.3).

## 1. Rerun of the existing checks

```
cd rust
cargo test --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

| Command | Result | Wall time (with build) |
|---|---|---|
| `cargo test --release` | 31 passed, 0 failed, 2 ignored (lib 21 + 2 ignored, cold_reject 1, differential 2, vectors 7, doctests 0) | 68.5 s |
| `cargo test` | same counts | 28.4 s |
| `cargo clippy --all-targets -- -D warnings` | clean (exit 0) | |
| `cargo fmt --check` | clean (exit 0) | |

The 31 passing tests match rust/CT-AUDIT.md. The 2 ignored tests are the
dudect timing tests in `src/dudect.rs`.

## 2. Portable path (no PCLMULQDQ)

I made a scratch copy (`git archive HEAD rust vectors` into `/tmp/portable`,
not committed) and edited only `src/gf128.rs`:

- `has_clmul()` returns `false`;
- `mul()` calls `mul_portable()` without trying `clmul::mul`.

As a result, the prover uses `mul_portable` everywhere. The verifier uses
its table fallback (`FixedMul` tables, `mul_vartime`) for public products
and `mul_portable` in `ZkHash::finish`, which is the configuration a CPU
without PCLMULQDQ gets.

| Check | Result |
|---|---|
| `cargo test --release` in the copy | **pass**: 31 passed, 2 ignored. Every KAT and differential proof is reproduced byte for byte (`vectors` 7 tests, 1.43 s; `differential` 2 tests, 8.37 s). Wall time 35.5 s, including the build. |
| The 100 step-3 cases re-proved with this build | `proofs.txt` SHA-256 `88fb63e6…679206c`, **identical** to the PCLMULQDQ build. 19.2 s for 100 proofs, against 4.6 s with PCLMULQDQ |
| The 800 step-3 tests verified with this build (table verifier) | verdicts **identical** to the PCLMULQDQ verifier; 36.2 s, against 25.4 s |

## 3. Three implementations

Harness: `crosscheck/` (cargo package `voleith-crosscheck` plus scripts).

```
bash crosscheck/run.sh 20261015
```

The script runs these stages:

1. **`gen.py`** writes 100 statements. Each has a printable-ASCII K of
   1–64 bytes, a suffix of 0–255, a random 32-byte x, and
   y = HMAC-SHA256(K, x ‖ u8(suffix)) computed with Python's `hmac` module.
   - Message lengths cycle through 0, 1, 96, a random length in [0, 4096]
     and 65,535 (20 cases each).
   - Each case gets a random 32-byte rho. The seed is 20261015.
2. **`src/main.rs prove`** proves every case with this branch's
   `voleith::prove`.
3. Every test is verified by:
   - `src/main.rs verify`, the Rust verifier (PCLMULQDQ path);
   - `verify_py.py`, the Python reference `python/voleith`, with 4 worker
     processes;
   - `go/main.go`, the clean-room Go verifier. Its `go/` directory is
     exported with `git archive origin/cleanroom/go-verifier go` into
     `/tmp/xc-go` (not merged), and the driver is copied in as
     `cmd/xcverify`.
4. **`compare.py`** expects acceptance for the valid proofs and rejection
   for every other test, with the same verdict from all three. It writes
   any mismatch to `crosscheck/findings/`.

There are 8 tests per case (800 in total):

- **The valid proof** (1 test).
- **5 single-bit proof flips** (5 tests). They walk the §10 layout
  round-robin over 182 fields, so 500 flips hit every field at least twice.
  The fields are:
  - version, statement id, `iv_pre`;
  - c_1 … c_23;
  - ũ, d, ã;
  - each co-path seed and each `com_{i,j*}` of the 24 openings;
  - `chall3`.

  Per region, the flips landed as follows: open 411, c 69, version 3,
  statement id 3, `iv_pre` 3, ũ 3, d 3, ã 3, `chall3` 2. The bit within
  each field is random.
- **1 message change** (1 test): a random bit flip, or an appended 0x00
  byte when the message is empty (20 cases).
- **1 statement change** (1 test), rotating through three kinds:
  - a bit of y (34 cases);
  - a different suffix (33 cases);
  - one character of K replaced by another printable character (33 cases).

| | Rust | Python | Go |
|---|---|---|---|
| prove 100 cases | 4.64 s | | |
| verify 800 tests | 25.4 s | 170.7 s (4 processes) | 34.2 s |

| Kind | Tests | Rust / Python / Go |
|---|---|---|
| valid | 100 | accept / accept / accept |
| proof bit flip | 500 | reject / reject / reject |
| message bit flip | 80 | reject / reject / reject |
| message append (empty message) | 20 | reject / reject / reject |
| statement: y bit | 34 | reject / reject / reject |
| statement: suffix | 33 | reject / reject / reject |
| statement: K character | 33 | reject / reject / reject |

**800 tests, 0 mismatches, no exception or panic in any implementation.**
`crosscheck/findings/` is therefore empty. The whole run took 4 min 4 s.

## 4. Fuzzing the new verifier

The harness is `origin/cloud/t1-fuzz:rust/fuzz`, copied to `crosscheck/fuzz/`.

- The only change is the dependency `voleith = { path = "../../rust" }`.
  `Cargo.lock` also picked up `zeroize 1.8.2` from this branch.
- The known-valid oracle loads `vectors/` (4 KATs and 100 differential
  proofs).

Every target therefore calls this branch's verifier, which uses the
PCLMULQDQ `gf128::mul` on this CPU (`ffi` goes through the C ABI).

```
cd crosscheck
cargo +nightly fuzz build -O -a -s none verify_raw
cargo +nightly fuzz build -O -a -s none verify_mutate
cargo +nightly fuzz build -O -a -s address --target-dir fuzz/target-asan ffi
cd fuzz
cargo run --release --bin seed_corpus corpus
bash run_campaign.sh 3600
```

The campaign script works as follows:

- **Cores:** `verify_mutate` runs on cores 0 and 1, `verify_raw` on core 2,
  and `ffi` (AddressSanitizer) on core 3.
- **Flags:** `-max_len=140000 -timeout=10`. `verify_raw` and `ffi` add
  `-use_value_profile=1`.
- **Duration:** 07:42:20Z to 08:42:22Z (3,601 s per target). All four
  workers exited with status 0.

### 4.1 Counts

| Target | Execs | Execs/s | Coverage (cov / ft) | Corpus | Peak RSS |
|---|---|---|---|---|---|
| verify_mutate (core 0) | 162,075 | 45 | 533 / 1,442 | 462 | 80 MB |
| verify_mutate (core 1) | 163,910 | 45 | 532 / 1,437 | 461 | 80 MB |
| verify_raw | 315,730 | 87 | 410 / 3,989 | 589 (30 MB) | 105 MB |
| ffi (ASan) | 329,819 | 91 | 1,519 / 9,801 | 1,263 | 411 MB |
| **total** | **971,534** | **≈ 270** | | | |

The valid-verify baselines measured by the harness at start-up (median of 9)
were 48.4 ms and 53.4 ms (`verify_mutate`) and 49.6 ms (`verify_raw`).

### 4.2 Crashes, timeouts and accepted modified proofs

None:

- `artifacts/` is empty for all three targets;
- no libFuzzer timeout, deadly signal, leak or AddressSanitizer report;
- no `CRITICAL` (an accepted non-known proof) and no oracle failure.

### 4.3 Slow inputs (over 2× a valid verify): not reproducible

During the campaign, the timing oracle saved 33 inputs, 17 from
`verify_mutate` and 16 from `verify_raw` according to the logs. The saved
files do not record their target, so every replay below also ran all 33
files through both targets. To be saved, an input had to take
more than 2× the baseline on its first run and also on the fastest of 3
immediate re-runs. Every reported time fell between 98.8 ms and 114.7 ms,
which is 2.0–2.4× the baseline.

Replayed on the idle machine with the same binaries and the same oracle
(input files passed explicitly, on core 0):

| Check | Result |
|---|---|
| 3 replay passes (inputs split by size) plus 2 passes of all 33 inputs through each target | 0 flagged slow |
| Per-input time, all 33 through `verify_mutate` | median 47 ms. The maximum in one pass was 302 ms: a spike started the oracle's re-timing, the 3 re-runs were fast, and nothing was flagged |
| Per-input time, all 33 through `verify_raw` | median 47 ms, max 85–93 ms |
| 8 back-to-back replays each of 4 flagged inputs (including `slow-95f3242b…`, which sets `chall3` = Δ = 0) | 47–74 ms, i.e. 0.95–1.5× |
| `timing` binary (release, uninstrumented), idle: valid KAT 0 | 34.0 ms |
| `timing` binary, the costliest invalid cases | `chall3`=0: 1.08×; `chall3`=ff…ff: 0.92×; with d=ff…ff: 0.90×; with a 65,535-byte message: 0.97× |

The flagged times are flat at about 100–115 ms and come from both targets.
They do not depend on the input, and every input runs at about 1× when
replayed. I attribute them to transient host or VM CPU contention that
lasted several hundred milliseconds, not to the verifier. For the record, a
`timing` run on core 0 with three fuzzers busy on the other cores did not
show a slowdown (31.5–34.8 ms), so the cause is outside the guest.

**No slow-input finding.** The inputs are kept locally, not committed.

## 5. Manual review notes (verifier side)

I read the diff `b32453d..08bf7fa` for the parts the verifier runs:

- `gf128.rs`;
- `clmul.rs`;
- `unihash.rs`;
- `circuit.rs::verifier_terms`;
- `proof.rs::verify_impl` and `verify_core`.

I found no defect. Specific points:

- **Reduction.** `reduce` is correct for any `hi` < 2^128. Folding `hi`
  gives `t_hi` of degree ≤ 6, so the second fold cannot overflow.
- **PCLMULQDQ path.** `clmul128_hw` computes the schoolbook product with
  the immediates 0x00, 0x11, 0x01 and 0x10. `mid` is placed at bit 64,
  which matches `clmul128_ct`.
- **Detection.** `clmul::available()` checks pclmulqdq and sse2 before the
  only unsafe call. `has_clmul()` and `clmul::mul` use the same predicate,
  so `FixedMul` / `mul_public` never mix the table and CLMUL paths
  inconsistently. Even if they did, the products would be identical
  (§2 shows the verdicts are identical).
- **Verifier changes.** The verifier-visible changes in `circuit.rs`
  (`gf128::mul` replaced by `mul_public`) and in `ZkHash::finish` (now
  always `gf128::mul`) compute the same field products. The step-3
  agreement with Python and Go, and the step-2 agreement of the table
  verifier, cover both paths on the same 800 inputs.

## 6. Reproducing and housekeeping

- **Committed:**
  - `crosscheck/{Cargo.toml,Cargo.lock,src/main.rs,gen.py,verify_py.py,compare.py,run.sh,go/main.go}`;
  - `crosscheck/fuzz/` (the t1 harness, rebased onto this crate);
  - this report.
- **Not committed (ignored):**
  - `crosscheck/work/` (cases, 26 MB of proofs, verdicts);
  - `crosscheck/target/`;
  - `crosscheck/fuzz/{target,target-asan,corpus,artifacts,logs,slow}`.
- **Scratch copies under `/tmp`:**
  - `/tmp/portable` (the forced-portable crate);
  - `/tmp/xc-go` (the Go verifier export);
  - `/tmp/t1` (the t1 harness export).
