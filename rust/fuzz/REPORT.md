# Fuzzing report: Rust verifier (SPEC.md v0.2 revision 1)

Base commit: `580fabe` (main). Date: 2026-10-15. Machine: 4 cores, Linux 6.18.
Tools: cargo-fuzz 0.13.2, libFuzzer via libfuzzer-sys 0.4, rustc nightly 1.101.0 (2026-10-14).

**Result: no crash, panic, timeout, memory error or accept of a modified proof
in 4.29 million executions over 3 h 15 min of wall time on 4 cores.** None of
the 21 inputs the timing oracle flagged during the campaign reproduces on an
idle core; the slowest one runs at 1.17x a valid verify (details below). No
verifier bug was found, and no verifier code was changed.

## 1. Test suite

`cd rust && cargo test --release`: **31 passed, 0 failed** (the 31 expected).

| test binary | passed |
|---|---|
| unit tests (`src/lib.rs`) | 21 |
| `tests/cold_reject.rs` | 1 |
| `tests/differential.rs` | 2 |
| `tests/vectors.rs` | 7 |
| doc tests | 0 |

## 2. Harness

All files are under `rust/fuzz/`:

| file | purpose |
|---|---|
| `src/lib.rs` | loads the 104 valid triples (4 KATs from `statement1-v0.2.json` and 100 from the differential set), the §10 section table (checked to be contiguous and 130,218 bytes long), an input reader and the timing oracle |
| `fuzz_targets/verify_raw.rs` | target a |
| `fuzz_targets/verify_mutate.rs` | target b |
| `fuzz_targets/ffi.rs` | target c |
| `src/bin/seed_corpus.rs` | writes the seed corpora |
| `src/bin/timing.rs` | median time of a valid verify and of the costliest invalid inputs |
| `run_campaign.sh` | runs the campaign on 4 cores |

**Accept oracle.** A `true` result (`1` from the FFI) is a CRITICAL finding
unless (public inputs, message, proof) is exactly one of the 104 known-valid
triples. `verify_mutate` also asserts that an unmodified base is accepted, so
the oracle cannot pass because verify always returns false.

**Timing oracle.** At startup each process takes the median of 9 valid
verifications as its baseline. A call over 2x the baseline is timed 3 more
times; if the fastest run is still over 2x, the input is written to `slow/`
and a `SLOW` line is logged. The run is not aborted.

**Panics.** libfuzzer-sys aborts on any panic, so a panic inside the C shim's
`catch_unwind` would also be reported. The verify targets are built with
`-a` (debug assertions and overflow checks on), so the verifier's
`debug_assert!`s are active.

### a. `verify_raw`

Input layout: `flags, statement id, u16 |pub|, u32 |msg| (mod 70,000), pub,
msg, proof = the rest`, passed to `voleith::verify`. Uniform random bytes stop
at steps 1–5, so three flag bits can steer inputs deeper:
- bit 0 pads or truncates the proof to 130,218 bytes;
- bit 1 forces the header to `02 01`;
- bit 2 forces the statement id to 1.

With these, the fuzzer reaches the padding checks (step 6) and full
verifications. The KATs are seeds both with and without the flags.

### b. `verify_mutate`

The input is a mutation program. Its first byte picks one of the 104 base
triples; then up to 16 operations follow:
- **Generic proof edits:** bit flip, byte replacement, chunk swap, truncation, extension (1–1,024 bytes) and splice of raw bytes.
- **Header:** a new value for byte 0 or byte 1.
- **Field boundaries:** a bit or byte edit at the first or last byte of any §10 field, or just outside it. The fields are version, statement id, `iv_pre`, each of `c_1…c_23`, `ũ`, `d`, `ã`, each of the 128 co-path seeds and 24 commitments of `open_0…open_23`, and `chall3`.
- **Whole-field rewrites:** fill a field with zeros, ones or a constant; copy a field from another valid proof; swap two fields of equal length.
- **Padding bits:** set them in a `c_i` or in `d`.
- **`chall3` (Δ):** set it to 0, to ff…ff or to another proof's value, or flip one bit.
- **Message:** the generic edits, or another vector's message.
- **Statement:** the generic edits on the encoding; field-level edits (suffix, a bit of y, a K byte to another printable byte, the length byte); or another vector's statement.

Because libFuzzer mutates and minimizes the program rather than a
130 kB blob, any finding would come out as a few bytes.

### c. `ffi`

The target calls `voleith_verify_s1` and is built with AddressSanitizer. Every
buffer is an exact-size heap allocation, so any read past a declared length
is reported. Each of `k`, `msg` and `proof` gets one of four modes:
1. an exact buffer of a fuzzed length, or of the expected length;
2. a null pointer with length 0, which the header allows;
3. a null pointer with an arbitrary nonzero length, which must return 0;
4. a 4-byte buffer with an out-of-range length (`k_len` ∉ 1..64,
   `msg_len` > 65,535, `proof_len` ≠ 130,218). This checks the header's claim
   that "lengths are checked before any pointer is read".

`y` is either a 32-byte buffer or null. A flag starts the call from a valid
vector's K, suffix, y, message and proof, with sparse XOR edits, so calls of
the right length reach the full verification.

## 3. Campaign

```
cargo +nightly fuzz build -O -a -s none verify_raw
cargo +nightly fuzz build -O -a -s none verify_mutate
cargo +nightly fuzz build -O -a -s address --target-dir target-asan ffi
cargo run --release --bin seed_corpus corpus
./run_campaign.sh 11400
```

The fuzzer options were `-max_len=140000` (above the 130,218-byte proof),
`-timeout=10` and `-print_final_stats=1`. `verify_raw` and `ffi` also used
`-use_value_profile=1`. Cores were assigned as follows: `verify_mutate` on
cores 0 and 1 (two processes, one shared corpus), `verify_raw` on core 2 and
`ffi` on core 3.

The campaign ran in two phases on the same corpora:
- **Phase 1:** 07:16:47–09:16:47 UTC (2 h 00 m). The session's background-job
  limit stopped it at exactly 2 h, so libFuzzer printed no final stats. Its
  counts below are from the last status line, so they slightly undercount.
- **Phase 2:** 09:16:58–10:31:59 UTC (1 h 15 m), `./run_campaign.sh 4500`.
  It ended normally.

**Total: 3 h 15 min of wall time on 4 cores (13 core-hours).**

| target | cores | execs phase 1 | execs phase 2 | **total execs** | execs/s per process | coverage at end (`cov` edges / `ft` features) | corpus |
|---|---|---|---|---|---|---|---|
| `verify_mutate` | 2 | 508,213 + 493,572 | 311,033 + 313,259 | **1,626,077** | 68–70 | 545 / 1,497 | 1,755 programs, 7.0 MB |
| `verify_raw` | 1 | 743,343 | 399,364 | **1,142,707** | 88–103 | 428 / 4,262 | 970 files, 41 MB |
| `ffi` (ASan) | 1 | 947,983 | 570,409 | **1,518,392** | 126–131 | 1,488 / 10,129 | 1,606 files, 6.5 MB |
| **all** | 4 | | | **4,287,176** | | | |

The coverage counts are libFuzzer's edge counters over the whole instrumented
binary, harness included. `ffi` counts more because ASan also instruments the
shim and the standard library.

Coverage flattened early:
- `verify_mutate`: 507 edges after 40 s, 536–545 from the first hour on.
- `verify_raw`: 409 after 40 s, 427–428 from about 1 h 30 m.
- `ffi`: 1,473 after 40 s, 1,483–1,488 from the first hour on.

Every check of verify's steps 1–6 and every block of steps 7–11 was reached.

`verify_mutate` mostly does full verifications. The rate is about 69/s per
core because each full verification takes 33–40 ms in the
debug-assertion build, with 4 busy cores. For comparison, the stable release
build verifies a valid proof in 27.9 ms on an idle core.

## 4. Findings

### Crashes, panics, memory errors: none

All four processes exited 0 in both phases. `artifacts/` is empty for all
three targets, and no log has a `panicked`, `ERROR` or ASan report. No ffi
input made ASan report a read before the length checks, including null
pointers with nonzero lengths and short buffers with out-of-range lengths.

### Accepts of modified inputs (CRITICAL): none

Neither verify target nor `ffi` ever returned true for a triple other than
the 104 known-valid ones. The sanity assertion that an unmodified base is
accepted never failed either.

### Timeouts (libFuzzer, 10 s): none

The slowest unit was under 1 s (`slowest_unit_time_sec: 0`).

### Timing (2x of a valid verify): no reproducible slow input

Under load, the in-process oracle flagged 21 inputs. All 21 flags came from
`verify_mutate-1` (8 in phase 1, 2 in phase 2) and `verify_raw` (1 in phase 1,
10 in phase 2), processes with a startup baseline of 32.9–35.5 ms. They measured 67–132 ms, against
the 2x limit of 66–71 ms. Process `verify_mutate-0`, whose startup baseline
was 39.9–41.6 ms, flagged nothing.

**Re-timing on an idle core.** Each of the 21 inputs was replayed 20 times
under both decoders (`verify_mutate` and `verify_raw`), with a warm-up input
first. The mean per call was 36.5–40.5 ms at most, against a 33.1–34.8 ms
baseline: a worst ratio of **1.17x**. No `SLOW` line was printed.

**Cause.** The flags are a measurement artifact, not a verifier finding. The
baselines were taken while the other three processes were still starting up
(the 19 MB JSON load), so the machine was quieter than during fuzzing. A busy
4-core machine slows a call to about 2x. The inputs are in the gitignored
`slow/` directory and are not committed as findings.

`src/bin/timing.rs` also measures the documented worst cases, in the stable
release build on an idle core, 31 runs each (median):

| input | median | ratio |
|---|---|---|
| valid proof (KAT 0) | 27.9 ms | 1.00 |
| `chall3` = ff…ff (all Δ bits set) | 29.0 ms | 1.04 |
| `chall3` = ff…ff and `d` = ff…ff | 28.1 ms | 1.01 |
| `chall3` = ff…ff, 65,535-byte message | 28.2 ms | 1.01 |
| `chall3` = 0 | 28.4 ms | 1.02 |
| bad public inputs (rejected at step 2) | 24 ns | ≈0 |
| padding bit of `d` set (rejected at step 6) | 62 ns | ≈0 |

This agrees with SPEC.md §11: the work after step 6 is bounded, with about 4%
variation from Δ.

### Harness issue found and fixed during setup (not a verifier bug)

The first `ffi` smoke run reported "accepted with a null pointer". The input
was KAT 2, whose message is empty, passed as `msg = NULL, msg_len = 0`. The
header allows that call and the verifier rightly accepts it. The oracle now
reads a null pointer with length 0 as the empty string.

### Observations (no change needed)

- `rust/include/voleith.h:20`: the header says "`y` must point to 32
  bytes". The shim also checks `y.is_null()` and returns 0
  (`rust/src/ffi.rs:54`). The fuzzer exercised both. The header could say
  that a null `y` returns 0, but this is optional.
- `rust/src/vc.rs:119-120` (called from `rust/src/proof.rs:196`) depends on
  `depth ∈ 1..=8` and `opening.len() == opening_len(depth)`. These are
  guarded only by `debug_assert!`, but they hold by construction because the
  layout is fixed (`params::SPLIT`). The debug-assertion builds never tripped
  them.

## 5. Reproducing a finding

There are none to reproduce, so `findings/` holds only a README. A future
finding replays with `cargo +nightly fuzz run <target> <file>`, or by running
the built binary on the file. A `verify_mutate` input is a short program
decoded by `fuzz_targets/verify_mutate.rs`, so it stays readable after
`cargo fuzz tmin`.
