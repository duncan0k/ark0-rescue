# Constant-time and zeroization audit of the Rust prover

Finding F7 of the 2026-10-14 internal review: the prover multiplied in
GF(2^128) with 64 KiB tables (and 16-entry windows) indexed by secret data,
and it did not zeroize secrets. This document records what was changed on
2026-10-15, what was checked, the timing-test results and
what remains open. It does not change the protocol, SPEC.md or the Python
reference. Every proof is byte-identical to before (all KAT and differential
vectors reproduce with the same fixed ρ).

**Status.** This is evidence from one audit on one machine, not a proof of
constant-time behaviour. An independent review should come before any real
seed is used. SPEC.md §13.3 and §14 item 2 still describe both provers as
test-only. They were deliberately left unchanged and should be revised by
the spec owner after that review.

## 1. GF(2^128) arithmetic

| Function | Used by | Constant time | How |
|---|---|---|---|
| `gf128::mul` | prover (all secret products), `ZkHash::finish`, verifier on CLMUL CPUs | yes | PCLMULQDQ if `is_x86_feature_detected!("pclmulqdq")`, else `mul_portable` |
| `gf128::mul_portable` | on CPUs without PCLMULQDQ: the prover, and the verifier's `ZkHash::finish` | yes | bit-serial: 3 × 64 iterations of shift, mask `0 - bit`, XOR (Karatsuba), shift-only reduction |
| `gf128::mul_x`, `reduce` | both | yes | fixed shifts; `mul_x` masks instead of multiplying |
| `gf128::mul_public`, `FixedMul` | verifier only | only on CLMUL CPUs | on CLMUL CPUs they are `gf128::mul`; otherwise the old 4-bit-window multiply and 64 KiB tables (public data only) |
| `unihash::CtMul` / `FixedMul` | `VoleHash<M>`, `ZkHash<M>` | — | the hashes are generic over the key multiplier: the prover instantiates `CtMul` explicitly (`proof.rs`, `VoleHash::<CtMul>` and `ZkHash::<CtMul>`), the verifier `FixedMul`. The type system does not enforce this: `FixedMul` also implements `KeyMul`, so swapping it in would still compile. That the prover reaches no table rests on the explicit instantiation and on the review of its call paths (§2) |

The only CPU-dependent choice is whether PCLMULQDQ is present. It depends on
the CPU, never on data. Both paths give identical products: unit tests compare
`mul`, `mul_portable`, `mul_public`, the table path and a bit-by-bit
reference on edge cases and 2,000 random pairs. A temporary build that forced
`mul_portable` everywhere produced the same proof hash
(`ad6beb93…ef00`).

**Generated code.** Checked in the release build on x86-64 (rustc 1.97.0):
- `clmul::mul_hw` is straight-line: four `pclmulqdq`, then shifts and XORs.
  It has no branch.
- The portable loop compiles to `bt` + `sbb` masks. Its only `cmov`/`jne`
  depend on the public loop counter (the u128 shift amount and the loop
  exit).

**Shared or separate for verify.** The task allowed one shared constant-time
implementation if it cost at most 10% on verify. On PCLMULQDQ hardware the
shared constant-time multiply is *faster* than the tables: it skips five
64 KiB table builds per call and is cheaper per product. So the verifier uses
it there (−12% verify time, §5). On CPUs without a carry-less instruction the
portable constant-time multiply is about 4× slower than the tables. Measured
with everything forced portable: prove 124.5 ms, verify 106.2 ms (median of
21), against 28/24 ms. So the verifier keeps its table fallback only there.
Its inputs are public. It does not run exactly as before there, though:
`ZkHash::finish` now uses the portable constant-time multiply (two products
per call), and the zeroization of shared types (SHA-256, Keccak, GGM expansion,
VOLE scratch) adds work. Measured in that configuration in §5. aarch64 PMULL is not implemented: an aarch64 prover
uses the portable path; an aarch64 verifier uses the tables, except in
`ZkHash::finish`, which uses the portable path. The crate checks
clean for aarch64 and i686.

## 2. Audit of the prover for secret-dependent branches and indexing

Secrets: witness x and its bits, every wire value and witness bit, ρ, rnd,
r, the tree roots, node and leaf seeds, the leaf expansions, u (including
u_i), v (columns and rows), the MACs, the QuickSilver terms and accumulators,
u*, v*.

Public: the statement, μ, iv_pre, iv, the challenges (and Δ, j*), every
proof field, all lengths, and the circuit (instruction list, wire kinds).

| Code | Finding | Action |
|---|---|---|
| `VoleHash::hash` on u and v columns | **was** a secret-indexed 64 KiB table (`FixedMul`) | now `CtMul` |
| `ZkHash::absorb` on QuickSilver terms | **was** a secret-indexed 64 KiB table | now `CtMul` |
| `Circuit::prover_terms` `mul(ma, mb)` | **was** secret-indexed 16-entry windows | now `gf128::mul` |
| `ZkHash::finish`, `mask_element` (`mul_x`) | windows / integer multiply by the top bit | `gf128::mul`; masked `mul_x` |
| `Circuit::evaluate` ASSERT check | **was** `if a&b != c { ok = false }`, a branch on secret wires | now `bad \|= (a&b)^c` |
| relation check `s1_hmac(..) != y` | **was** an early-exit `[u8; 32]` comparison | now `ct_eq` (OR of XORs). The verdict itself (RelationFails) is the intended output |
| `prover_terms` other ops | XOR/NOT on values; `AndSP` masks with a **public** bit; `Mul`/`Assert` mask with secret bits via `0 - bit` | no branch; wire indices come from the public instruction list |
| SHA-256 / HMAC (`sha256.rs`) | ARX only; `K256[t]` indexed by the round counter; branches on lengths only; the HMAC key is public | none needed |
| SHAKE256 (`sha3`/`keccak 0.1.6`, no `asm`) | Keccak-f is ARX with fixed round constants; buffering branches on lengths only | none needed |
| GGM `vc::commit` | loop over all nodes and leaves in fixed order | none needed |
| GGM `Tree::open(j*)` | indexes by j*, from the public challenge | fine (public) |
| `vole::expand_leaf`, `convert` | leaf index and climb depth come from the loop counter | none needed |
| `columns_to_rows`, `bits::load_bits`, `clear_padding` | indices and shifts from public positions only | none needed |
| `d` encoding loop | `w_bits.get(i)` bounds check on a public index; `bit << b` | none needed |
| `s1_secret_bits` | shifts only | rewritten to allocate once (see §3) |
| allocation sizes, loop counts, early returns | depend on the statement, lengths and witness *validity* only | fine |
| `Xof` tags, `trace` option, CPU feature check | not data | fine |

No integer division or modulo touches secrets. The only integer multiply on
a secret value (`mul_x`) was removed. Variable shift amounts all come from
loop counters.

**Not checked by this audit:** the compiler's output beyond the two GF
kernels above. The mask idioms (`0u128.wrapping_sub(bit) & x`) could in
principle become branches under another compiler or target. Also not
checked: microarchitectural effects below the instruction level (e.g.
operand-dependent power) and the C ABI, which exposes only the verifier.

## 3. Zeroization

Dependency: `zeroize = "=1.8.2"`, `default-features = false`,
`features = ["alloc"]`, with `Cargo.lock` committed. Why 1.8.2:
- it is over a year old (2025-09-29);
- its MSRV is 1.60, inside this crate's 1.85;
- it lies in `sha3`'s `^1.6` range, so one copy serves both;
- it pulls in no proc-macro (no `derive`).

1.9.1 was nine days old. 1.9.0 had introduced new `optimization_barrier`
code with an uninitialised-read bug that 1.9.1 fixed. A crate whose job is
correctness under adversarial conditions should take the mature line. The
`sha3` feature `zeroize` is enabled too, so the Keccak state is cleared when a
hasher or XOF reader is dropped.

Cleared when dropped (in `prove_impl` unless noted):

| Secret | Mechanism |
|---|---|
| witness bits, all wire values (`evaluate`), witness bit vector `w_bits` | `Zeroizing<Vec<u8>>` |
| rnd (r is a borrowed slice of it), tree roots | `Zeroizing` |
| GGM node seeds, leaf seeds, commitments | `impl Drop for vc::Tree`; `expand`/`leaf` clear their XOF output |
| u_i (all τ), u, v columns, VOLE rows | `Zeroizing<Vec<…>>` |
| leaf expansions in ConvertToVOLE | `impl Drop for vole::ConvertScratch` |
| wire bits and MACs in `prover_terms` | `Zeroizing<Vec<…>>` |
| ZKHash accumulators | `impl Drop for ZkAcc` (no longer `Copy`) |
| u*, v* | `Zeroizing<u128>` |
| copy of x in `s1_hmac`, HMAC inner hash | `Zeroizing` |
| SHA-256 chaining value, buffer, message schedule, block copy | `impl Drop for Sha256`, `w.zeroize()` in `compress` |
| Keccak state | `sha3` feature `zeroize` |
| `ProverTrace` (test-trace feature only) | `impl Drop` clears r and roots |

Every secret vector is allocated at its final size: `with_capacity` matches
the exact count, and `s1_secret_bits` no longer collects from an iterator
with an unknown size. So no reallocation leaves an unzeroized copy behind on
the heap.

Every prover entry point (`prove`, `prove_traced` and, with the
`bench-splits` feature, `bench::prove`) goes through one internal function,
`prove_scrubbed`. It calls `prove_impl` and then, on every return (`Ok` and
`Err`), `scrub_stack`, which overwrites 64 KiB of the stack below its own
frame with volatile writes. This covers the frames where seeds, hash states
and field elements were held. `prove_impl` is `#[inline(never)]`: inlined
into `prove_scrubbed`, its secrets would sit in the caller's own frame, which
the scrub (a callee) cannot reach.

**Residual (known gaps):**
- **The stack scrub is best effort.** Frame layout is the compiler's choice,
  and registers or vector registers can hold secrets until reused. Signal
  handlers and other threads are out of scope.
- **A panic skips the stack scrub.** A panic inside `prove_impl` unwinds past
  `scrub_stack` when the library is built with `panic = "unwind"` (the
  release profile, for the C ABI). Heap secrets are still cleared by their
  destructors during unwinding; the stack is not. The command-line tools
  are built with the `cli` profile (`panic = "abort"`, 2026-10-23): a panic
  there ends the process at once, before any further code runs.
- **Keccak permutation temporaries.** Since 2026-10-23, `src/sym.rs`
  implements the SHAKE256 sponge itself on `keccak::f1600`: input is XORed
  into the state and output read from it in place, the state is zeroized
  on drop, and the state lives on the heap, so moving an `Xof` (absorbing)
  or the `XofReader` that its `finalize` returns moves only a pointer. The
  two types make it impossible in any build to absorb after finalizing,
  finalize twice or read before finalizing (review round 2). This closes
  the earlier gap of `digest 0.10`'s block buffer and the XOF reader's
  output buffer, which had no zeroize support. What remains are the
  permutation's own locals inside `keccak::f1600` (stack and registers),
  which only the stack scrub covers.
- **Other stack and register copies.** Values returned or passed by value
  (e.g. a 16-byte seed read from a slice, the SHA-256 working variables
  `a..h`) can leave copies in stack slots and registers; the stack scrub
  covers the stack below `prove_scrubbed`, best effort. Since 2026-10-23
  SHA-256 compresses into its chaining value in place, finalizes by
  reference, and HMAC writes its inner digest into a zeroizing buffer; the
  GGM tree writes child and leaf seeds straight into their final slots;
  `Circuit::evaluate` returns zeroizing vectors allocated at their final
  size.
- **Caller-owned inputs.** `witness` and `rho` belong to the caller, who must
  clear them.
- **Paging and core dumps.** Swapped-out pages, core dumps and hibernation
  are outside what `zeroize` can address (use `mlock`/`madvise` in the
  caller).

## 4. Statistical timing tests (dudect)

`src/dudect.rs` holds the tests, `#[ignore]`d by default:

```
cargo test --release --lib dudect -- --ignored --nocapture --test-threads=1
```

How they work:
- **Classes.** Fixed versus random secret inputs, interleaved in random order.
- **Input generation.** As in dudect, the inputs for a whole chunk are
  generated before any of its measurements.
- **Statistic.** Welch's t on the raw timings and on timings cropped at the
  p99/95/90/75/50 percentiles. The maximum |t| is reported, with 4.5 as the
  threshold. Zero variance with different class means gives a signed
  infinite t (fully distinguishable), and fewer than 2 samples in a class
  gives NaN (undecidable); both fail the test. Before 2026-10-15 (review
  finding F2) both cases returned t = 0 and passed: 100 samples of 100 ns
  against 100 of 200 ns gave t = 0 raw and for every crop. A unit test now
  covers that sample. An undecidable crop does not overwrite the |t| of the
  other crops (review finding R1): a constant-time target fails if any crop
  is undecidable or any decidable |t| reaches 4.5, and a leak counts as
  detected (the positive control) if any decidable crop gives |t| > 4.5,
  infinities included. A regression test covers two leaky samples whose p50
  crop is undecidable.
- **GF measurements.** Each sample times 64 products.
- **prove() measurements.** Each sample is one call on the real statement
  (it cannot be made smaller): x and ρ fixed, or both random with matching
  public y.

Machine: Intel Xeon @ 2.80 GHz VM (pclmulqdq, avx2, avx512f), rustc 1.97.0,
release profile.

Final harness, n = 200,000 per GF row (20,000 for the control):

| Target | run 1 | run 2 | run 3 | median fixed / random (64 ops) |
|---|---|---|---|---|
| control: leaky by construction (must fail) | 1,923 | 1,538 | 1,657 | 116 / 560 ns |
| `gf128::mul` (PCLMULQDQ) | 1.90 | 2.38 | 1.42 | 548 / 548 ns |
| `gf128::mul_portable` | 1.39 | 1.76 | 1.66 | 19,484 / 19,484 ns |
| old `FixedMul` tables (now verifier only) | 1,303 | 1,282 | 1,266 | 711 / 787 ns |

Rerun once after the F2 fix (`cargo test --release --lib dudect_gf128 --
--ignored --nocapture --test-threads=1`, pinned with `taskset -c 1`,
n = 200,000, 20,000 for the control), on an Intel Xeon @ 2.10 GHz VM with
PCLMULQDQ: control 820.10 (must fail; 115 / 395 ns), `gf128::mul` **1.06**
(385 / 385 ns), `gf128::mul_portable` **1.03** (16,419 / 16,419 ns), old
`FixedMul` tables 383.03 (706 / 787 ns). Max |t| of the two constant-time
multiplications: 1.06.

Rerun after the R1 fix, same command and machine: control 889.36 (its p50
crop was undecidable, the very case R1 describes; before the fix that would
have failed the control), `gf128::mul` **2.77** (382 / 381 ns),
`gf128::mul_portable` **1.25** (16,444 / 16,445 ns), old `FixedMul` tables
323.52 (689 / 756 ns). No undecidable crop for the constant-time targets.

| Target | n | max \|t\| | median fixed / random |
|---|---|---|---|
| `prove()`, this branch | 1,000 | 2.14 | 27.92 / 27.94 ms |
| `prove()`, this branch | 3,000 | 1.83 | 28.05 / 28.06 ms |
| `prove()`, the old table prover (base `b32453d`) | 1,000 | 1.22 | 30.70 / 30.70 ms |
| `prove()`, the old table prover (base `b32453d`) | 3,000 | 1.69 | 30.67 / 30.67 ms |

How to read these results:
- **The GF tests have power.** The leaky control and the old tables are
  flagged in every run (control |t| 820–1,923, tables 323–1,303). The tables
  show a 10% timing difference between a fixed and a random operand, which
  confirms F7 was a real, measurable leak. Both constant-time
  multiplications stay at |t| ≤ 2.77 in every run of the final harness, well
  below 4.5.
- **The prove() test has almost no power.** The old prover, which certainly
  leaks through its tables, passes it as clearly as the new one. A ~30 ms
  call drowns a cache effect of a few nanoseconds per product in noise.
  Treat the prove() row as a smoke test for gross leaks (secret-dependent
  loop counts, early exits), not as evidence about cache timing. The
  evidence for prove() is the audit in §2 together with the GF tests.
- **An earlier harness version gave false alarms.** It generated
  random-class operands inside the measurement loop (outside the timed
  window). Six runs of it (one at n = 50,000, five at 200,000) gave max |t|
  of 3.00, 2.02, 5.39, 13.86, 3.29 and 7.93 for `mul`, and 1.92, 6.20, 4.29,
  6.91, 6.43 and 5.27 for `mul_portable`. The
  generated code has no data-dependent instruction, and the values dropped
  to 2.77 or less once both classes ran identical code between timer reads. So
  they are attributed to that artefact. They are recorded here because a
  timing test that only reports its passing runs is worth little.
- **What a pass means.** It means this machine, this build and this many
  samples showed no difference. It does not cover other CPUs or compilers,
  and it does not cover attackers with finer probes (cache-line monitoring,
  SMT co-residence, power).

## 5. Benchmarks

`cargo bench --bench prove_verify -- --runs 31` (new in this branch):
statement 0x01, 96-byte message, single thread, pinned to one core
(`taskset -c 1`). Base `b32453d` (this branch's first commit, which adds the
bench to unchanged code) and the final head, built separately, run
alternately in three rounds of 31 runs each:

| | before (median of each round) | after (median of each round) | delta |
|---|---|---|---|
| prove | 29.85 / 29.86 / 30.04 ms | 27.86 / 28.01 / 28.06 ms | **−6.4%** |
| verify | 27.40 / 27.28 / 27.32 ms | 24.12 / 24.08 / 24.12 ms | **−11.7%** |

Both binaries produce the same proof (130,218 bytes, sha256
`ad6beb9321612f18b3fd7164910be60692bab88c21c636aa42e346d729c7ef00`).
The cost of zeroization and the 64 KiB stack scrub was not measured
separately. The "after" numbers include it, and the CLMUL speedup more than
covers it.

**Without PCLMULQDQ.** Measured on 2026-10-15 in the real configuration of a
CPU without PCLMULQDQ: a scratch copy (not committed) with
`clmul::available()` forced to false, so that `has_clmul()` is false and
`gf128::mul` takes `mul_portable`. The verifier then uses its tables
everywhere except `ZkHash::finish`, which uses the portable constant-time
multiply. Same bench, `--runs 31`, `taskset -c 1`, on an Intel Xeon @
2.10 GHz VM that was noisier than the one above; eight alternating rounds
of the three binaries, the pre-change base being `b32453d` (the bench
commit), which uses tables everywhere:

| median of 31 runs, per round (ms) | median of the 8 rounds |
|---|---|
| verify, PCLMULQDQ (this branch): 23.42 / 21.58 / 21.67 / 25.43 / 22.18 / 21.46 / 23.73 / 27.67 | **22.8 ms** |
| verify, no PCLMULQDQ (this branch): 25.14 / 25.38 / 29.87 / 31.53 / 26.32 / 27.08 / 33.70 / 25.82 | **26.7 ms** |
| verify, base `b32453d` (tables): 25.96 / 26.44 / 25.92 / 27.14 / 29.13 / 26.02 / 26.04 / 26.09 | **26.1 ms** |
| prove, no PCLMULQDQ (this branch), rounds 1–3 and 6–8 | 100.1 / 102.0 / 121.9 / 109.9 / 132.5 / 105.7 ms |

All three binaries produced the same proof (sha256 `ad6beb93…ef00`).
Without PCLMULQDQ the verifier is therefore not unchanged: its median is
about 2% above the table-only base (26.7 against 26.1 ms) and 17% above the
PCLMULQDQ verifier, with a much wider spread between rounds (25.1–33.7 ms
against 25.9–29.1 ms). The 2% is within this VM's round-to-round noise, so
the cost of the portable `ZkHash::finish` and of zeroization is small but
was not resolved more precisely. The prover is about 4× slower there (§1).

## 6. Tests

- Before the review fixes: `cargo test`: 31 passed (21 unit, 1
  cold-reject, 2 differential, 7 vectors), plus 2 ignored timing tests. The same in `--release` and in the
  dev profile with debug assertions.
- `cargo clippy --all-targets` and `--all-targets --all-features` are clean.
  `cargo fmt --check` passes.
- After the review fixes F1–F4 (2026-10-15): `cargo test --release` and
  `cargo test` both pass 34 tests (24 unit, including the two new Welch's t
  tests and the R1 regression test, 1 cold-reject, 2 differential, 7
  vectors), plus 2 ignored timing
  tests. The KAT vectors and the 100 differential cases are reproduced
  byte for byte. `cargo clippy --all-targets --all-features -- -D warnings`
  is clean and `cargo fmt --check` passes. Under `cargo test --all-targets`
  the `prove_verify` bench only proves and verifies once (F4). The GF dudect
  test rerun after F2 gives max |t| 1.06, after R1 2.77 (§4).
- `cargo check --lib` passes for `aarch64-unknown-linux-gnu` and
  `i686-unknown-linux-gnu` (the portable path). They were not run: there is
  no cross toolchain here.
