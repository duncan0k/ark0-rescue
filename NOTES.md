# Notes on v0.1 (2026-10-14)

Companion to `SPEC.md`: measurements, what is missing, and questions for
reviewers.

## Measurements

Machine: Windows 11, AMD Family 25 Model 116 (Zen 4 laptop), Python 3.12.9,
one thread. Commands are at the end.

| What | Time |
|---|---|
| Build the statement 0x01 circuit (once per process) | 0.15 s |
| `prove` (median of 5; min–max) | **0.668 s** (0.650–0.677) |
| `verify` (median of 5; min–max) | **0.591 s** (0.579–0.603) |
| Full test suite (70 tests) | ~66 s |

- **Where Python spends its time.** Mostly GF(2^128) arithmetic: about 0.26 s
  in table multiplications (VOLEHash, ZKHash, `q·Δ`) and 0.22 s in the 42k
  general products of QuickSilver. SHAKE256 takes about 45 ms.
- **What a Rust verifier will spend its time on.** SHAKE256. The verifier
  expands 16 × 255 leaves of 5,307 bytes, 21.65 MB in total. With hashlib
  (OpenSSL), SHAKE256 runs at 560 MB/s here, so the expansion alone takes
  38.7 ms. The rest (8k short hashes, transposition, ~250k gate evaluations,
  ~210k carry-less products) should take well under 10 ms.
  - Estimate for a single-threaded Rust verifier: **45–80 ms (not measured)**.
  - R1 assumed AES-NI at 1–4 GB/s and estimated 6–22 ms.
  - **Early warning:** under M1's rule (weight ≥ 50 · t_rescue / t_Schnorr,
    with t_Schnorr ≈ 50 µs), 45–80 ms means about 45,000–80,000 units. The
    provisional 50,000 may not be enough. See Q5.
  - Measured since: about 113 ms, see "Rust verifier" below.

## Internal review

An AI reviewer (not an external cryptographer) re-implemented the circuit
builder, the prover and the verifier from SPEC.md alone. Its builder reproduced
both circuit digests and every gate count; its prover reproduced the four
vector proofs byte for byte; its verifier accepted them. It found no
high-severity issue. Its medium findings were test gaps, now closed:

- negative vectors and a unit test for the padding rule (a verifier that
  masked padding bits and hashed re-encoded values would have passed the old
  tests);
- a direct test that the VOLE consistency check is load-bearing (wrong
  corrections on rows that QuickSilver never reads).

The rest were wording, notation and stale section references.

## Sizes

| Quantity | Value |
|---|---|
| SHA-256 compression, all 768 inputs variable | **22,573 AND**, 111,607 XOR, 1,891 NOT (same AND count as the Bristol circuit) |
| Statement 0x01: AND of two secret wires | 41,815 |
| Statement 0x01: ASSERT (final-state checks) | 256 |
| Witness bits ℓ / constraints C | 42,071 / 42,071 (R1 estimate: 43,036) |
| Proof | **87,506 bytes** (R1 estimate: 89.2 kB) |

Of the 87,506 bytes, the 15 correction vectors take 79,605 (91%), `d` 5,259,
the tree openings 2,560 and the rest 82. Each witness bit costs 2 bytes
(τ = 16 bits).

The savings against R1's estimate come from folding constants and public
values (Ch and Maj with public inputs, the bit-0 carry of public addends) and
from the last four rounds of the outer compression, whose outputs are public
(`y − IV_out`) and are checked by `assert_add` without new witness bits.

## Rust verifier

Added 2026-10-14. `rust/` is a Cargo crate (library `voleith`, built as rlib
and staticlib) with the verifier, a prover and the C function
`voleith_verify_s1` (header `rust/include/voleith.h`). It was written from
SPEC.md with the Python package open for structure, so it checks the Python
code less independently than the internal review's re-implementation did.

- **Verifier.** SPEC §11 in order: statement id, canonical public inputs,
  message length, proof length, header and padding bits are checked before any
  parsing of proof contents or hashing. After those checks the work does not
  depend on the proof. Every buffer size is fixed by the statement: about
  6 MB per call (VOLE columns and rows 1.4 MB, wire keys 4.1 MB, five 64 KiB
  multiplication tables), plus about 8 MB for the circuit, built once per
  process (8–10 ms).
- **Prover.** Reproduces the Python proofs byte for byte from the same ρ (the
  4 vectors and the 100 differential cases). Like the reference it is not
  constant time and does not zeroize; it is for tests and tools.
- **Unsafe code.** The crate root has `#![deny(unsafe_code)]` and every module
  `#![forbid(unsafe_code)]`, except `src/ffi.rs`. That shim checks every length
  first (`k_len` 1–64, `msg_len` ≤ 65,535, `proof_len` = 87,506, `y` not
  null; a null pointer only with length 0), then makes slices, and runs the
  verifier under `catch_unwind` (release builds keep `panic = "unwind"`).
- **Portable arithmetic.** GF(2^128) products use a 4-bit-window carry-less
  multiply and 64 KiB tables for fixed multipliers; no CLMUL or AES
  instruction is used, so a generic x86-64 build is representative.
- **Dependencies.** Runtime: `sha3 =0.10.9` (RustCrypto, for SHAKE256), which
  brings `digest 0.10.7`, `block-buffer 0.10.4`, `crypto-common 0.1.7`,
  `generic-array 0.14.7`, `typenum 1.20.1`, `keccak 0.1.6`, `version_check
  0.9.5` (build only) and, on aarch64 only, `cpufeatures 0.2.17` and
  `libc 0.2.190`. SHA-256 and HMAC (for the HMAC midstates, the circuit digest
  and the prover's relation check) are implemented in the crate instead of
  adding `sha2`. Dev only: `serde_json =1.0.149` and `secp256k1 =0.31.1`
  (`secp256k1-sys 0.11.0` with libsecp256k1 v0.6.0, compiled by gcc 12.2 at
  `-O3` without the x86-64 assembly, `ECMULT_WINDOW_SIZE` 15). `Cargo.lock`
  holds `cc` at 1.4.7 because 1.8.0 was three days old.

### Tests

`cargo test`: 25 tests, all passing, in the generic and the x86-64-v3 build.

- 16 unit tests: field arithmetic, bit strings, SHA-256 and HMAC known
  answers, the transposition, ConvertToVOLE against its definition, GGM
  open/reconstruct, and the standalone compression circuit against native
  SHA-256 (22,573 AND, 111,607 XOR, 1,891 NOT).
- `tests/vectors.rs`: both circuit digests of SPEC §7.6 and every count in the
  vector file; the 4 valid vectors verify; every intermediate in the file
  matches, on the verifier side (μ, iv, the 16 tree hashes, hcom, chall1,
  h_V, chall2, b̃, chall3) and on the prover side (also r, the roots, ũ, ã);
  the prover reproduces the 4 proofs; the 44 negative vectors reject; the C
  function on null pointers and on bad lengths (`k_len` 0, 65 and 300,
  `msg_len` 65,536, short proofs).
- `tests/differential.rs`: `vectors/statement1-v0.1-differential.json`
  (13.3 MB), made by `python/tools/gen_differential.py` with master seed
  "voleith differential set v0.1 / 2026-10-14". It holds 100 random valid
  cases (K of 1–64 printable bytes, suffixes including 0 and 255, messages of
  0–299, 96 and 65,535 bytes) and 384 mutated ones: bit flips in every proof
  section (117), header bytes (8), padding bits (16), byte XORs (40), double
  flips (20), zeroed sections (7), truncations (16), extensions (7), wrong
  messages (20), wrong statements (22), malformed public inputs (20), proofs
  moved to another instance (14), sections swapped between proofs (11),
  random proof bodies (5) and random bit flips (60). The Python verifier
  accepts the 100 valid cases and rejects the 384 others; the Rust verifier
  returns the same verdict on all 484, and the Rust prover reproduces all 100
  proofs.
- C link check (not in the repository): a 30-line C program linked with
  `gcc -O2 smoke.c libvoleith.a -lpthread -ldl -lm` accepted vector 0 and
  rejected a flipped proof, a null `k` and a short proof. The archive also
  exports Rust standard-library symbols (2,214 global text symbols), so a
  binary should link only one Rust staticlib.

### Benchmarks

Machine: one pod on a shared single-node k3s host. AMD EPYC-Rome (Zen 2,
family 23 model 49), KVM guest with 12 vCPUs, TSC 1,996 MHz, 512 KB L2;
flags include AVX2, BMI1/BMI2, SHA-NI, AES and PCLMULQDQ, no AVX-512. Other
workloads kept the host's load average at 2.5–5 during the runs. rustc 1.98.1
(LLVM 22.1.8); release profile (opt-level 3, fat LTO, one codegen unit); no
`target-cpu`, i.e. generic x86-64; one thread. Each run is one process of
`cargo bench --bench verify`; no run overlapped minutes x4 or x5.

Generic x86-64 (the baseline):

| Run (UTC) | n | Verify median | Verify p99 | Worst rejection, median / p99 | Schnorr median (n = 20,000) | p99 / Schnorr | C |
|---|---|---|---|---|---|---|---|
| 15:56 | 300 | 112.7 ms | 180.7 ms | 119.3 / 166.1 ms | 40.46 µs | 4,466 | 279,102 |
| 16:16 | 300 | 112.8 ms | 145.8 ms | 113.7 / 144.9 ms | 42.22 µs | 3,453 | 215,823 |
| 16:20 | 300 | 114.8 ms | 149.9 ms | 122.7 / 188.5 ms | 42.58 µs | 3,521 | 220,065 |
| 16:06 (*) | 500 | 117.7 ms | 157.6 ms | 119.0 / 153.4 ms | 42.78 µs | 3,684 | 230,258 |

(*) Overlapped another workload's six-hourly job (16:07–16:09:48); listed,
not used. C = 1.25 × 50 × p99(verify) / median(Schnorr). The 15:56 run
predates the 65,535-byte-message case, so its worst rejection is over four
inputs; the crate code was the same in every run.

- **Rejections.** "Worst rejection" is the slowest of five invalid inputs
  that pass steps 1–6 and fail only at the final comparison: ã flipped,
  chall3 flipped, message flipped, a 65,535-byte message, and a random proof
  body with a valid header and zero padding. All cost the same as a valid
  proof (SPEC §11: the work does not depend on the proof); the p99
  differences are noise. Rejections at steps 4–6 take 0.04–0.08 µs.
- **Schnorr baseline.** libsecp256k1 BIP-340 verification in the same binary,
  40.5–42.6 µs, below the ≈ 50 µs assumed in M1's rule.
- **Where the time goes** (instrumented copy, 20 runs of 109–131 ms): leaf
  expansions (16 × 255 SHAKE256 outputs of 5,307 bytes, 21.65 MB) 86–105 ms,
  about 82%; GGM nodes, leaf hashes and tree hashes 8–10 ms; circuit keys and
  ZKHash 7 ms; ConvertToVOLE XORs 1.8 ms; VOLEHash and h_V 1.3 ms;
  transposition 1.2 ms.
- **Keccak speed here**, same output volume: SHAKE256 228–241 MB/s (OpenSSL
  reached 560 MB/s on the Zen 4 laptop above); for comparison only, SHAKE128
  284–296, TurboSHAKE256 387–501 and TurboSHAKE128 493–589 MB/s.

x86-64-v3 (comparison only, not the baseline): two runs at 15:59 and 16:18
gave verify medians of 94.8 and 91.0 ms, p99 158.5 and 112.8 ms, Schnorr
40.34 and 40.71 µs, and C = 245,521 and 173,184. The gain comes from Keccak
(SHAKE256 305–309 MB/s, likely from BMI1 `andn`).

### Does the proof pay for its verification?

No. The self-funded budget is the proof (87,506) plus the other witness bytes
plus 50, about 87,600. The measured C is 216,000–279,000, i.e. 2.5–3.2 times
that. Medians instead of p99 still give 1.25 × 50 × 2,670–2,790 ≈
167,000–174,000, about twice the budget. The p99 here includes interference
from other workloads; the median alone is already too high.

Implementation work is unlikely to close a factor of 2–3 with margin. Keccak
is about 90% of the time. The x86-64-v3 build is 1.2 times faster. A
multi-buffer AVX2 Keccak (four leaf expansions at once, dispatched at run
time) might make the Keccak part 2–3 times faster, but that is not measured,
and the weight must also hold on machines without AVX2.

**A protocol change looks necessary.** It is not made here; any of the
following needs a new version byte, new vectors and a re-check of the SPEC §13
bounds. The estimates come from a model fitted to the breakdown above: verify
≈ 10.4 ms + 2.1 µs per leaf + 22.6 µs per expanded leaf (SHAKE256); Schnorr
42.2 µs; p99 = 1.29–1.60 × median as measured; proof bytes = 2,082 + 5,339 τ
for λ = 128, k-split as in FAEST's mixed-depth trees.

| Option | Expanded leaves | Verify median (est.) | Proof bytes | C, median → p99 | Budget |
|---|---|---|---|---|---|
| v0.1 (τ 16, k 8) | 4,080 | 113 ms (measured) | 87,506 | 167k–174k → 216k–279k (measured) | 87.6k |
| TurboSHAKE128 for `exp`, `ggm`, `leaf`, `tree` | 4,080 | 54 ms | 87,506 | 80k → 103k–128k | 87.6k |
| τ 20 (8 trees of depth 7, 12 of depth 6) | 1,772 | 54 ms | 108,862 | 80k → 104k–129k | 109k |
| τ 22 (18 trees of depth 6, 4 of depth 5) | 1,258 | 42 ms | 119,540 | 62k → 79k–99k | 120k |
| τ 24 (8 of depth 6, 16 of depth 5) | 1,000 | 35 ms | 130,218 | 52k → 67k–83k | 130k |
| AES-128-CTR for `exp` (AES-NI, about 2 GB/s) | 4,080 | 32 ms | 87,506 | 47k → 60k–75k | 87.6k |

- **More, smaller trees** (τ ≈ 22, depths 6 and 5) is the smallest change
  that keeps SHAKE256 as the only primitive and leaves a margin. It costs 37%
  more proof bytes; the budget grows with them, while the PRG work falls by a
  factor of 3.2.
- **AES-128-CTR for the leaf expansions** (FAEST's own PRG) keeps the size,
  but brings AES back and is fast only with AES instructions.
- **TurboSHAKE128 alone** is not enough on this machine; together with τ ≈ 20
  it would be.
- Also possible outside SPEC.md: a consensus rule that charges rescue inputs
  extra weight or caps them per block (M4-R design).

### Spec

No ambiguity blocked the implementation. Two wording changes in SPEC.md, no
protocol change:

- §5.4: the last 128-bit block of x0 holds only ℓ + 128 − 128(n_v − 1) = 87
  bits for statement 0x01; the column bits that follow in the same bytes
  belong to x1 and must not enter that block. An implementation that reads
  the column 16 bytes at a time gets this wrong; the text now says so.
- §14 item 3: the "not measured" estimate is replaced by the measurement.

### Reproduce

Pod spec (image `rust:1.98.1-slim-bookworm`, pinned by its index digest; the
linux/amd64 manifest is
`sha256:dacc9e51f252243eb59d2fb4cb4ad8b0d3f607b6a82c398cf8a321e59ff778a7`).
It runs as a non-root user (uid 10001); the image's toolchain directories are
world-writable, so cargo and rustup work without root.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rescue-build
---
apiVersion: v1
kind: Pod
metadata:
  name: rust-build
  namespace: rescue-build
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  enableServiceLinks: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: rust
      image: docker.io/library/rust@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730
      command: ["sleep", "infinity"]
      workingDir: /work
      env:
        - name: HOME
          value: /work
        - name: CARGO_HOME
          value: /cargo-home
        - name: TMPDIR
          value: /tmp
      resources:
        requests:
          cpu: "2"
          memory: 2Gi
        limits:
          cpu: "4"
          memory: 6Gi
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: work
          mountPath: /work
        - name: cargo-home
          mountPath: /cargo-home
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: work
      emptyDir:
        sizeLimit: 8Gi
    - name: cargo-home
      emptyDir:
        sizeLimit: 4Gi
    - name: tmp
      emptyDir:
        sizeLimit: 2Gi
```

Commands (copy the source in as files, e.g. `git archive HEAD rust vectors`,
then `kubectl cp`):

```
# in the pod, in /work/rust
cargo test --locked
cargo bench --locked --bench verify -- [verify runs, default 300] [Schnorr runs, default 20000]
RUSTFLAGS="-C target-cpu=x86-64-v3" CARGO_TARGET_DIR=target-v3 cargo bench --locked --bench verify
# afterwards: delete the pod by name, then the namespace
kubectl -n rescue-build delete pod rust-build
kubectl delete namespace rescue-build
```

## Not done yet

- **Statement 2** (HKDF-SHA-512, desktop wallet). It needs SHA-512 gadgets, the
  degree-≤6 E3 encoding of R1 and a degree-d QuickSilver check, which v0.1
  does not have. R1 estimates the proof at about 296 kB.
- **Rust.** Verifier, prover and differential tests are done (see "Rust
  verifier"). Still open: fuzzing of the verifier, and a constant-time
  prover.
- **Core integration.** Annex TLV, rescue sighash with `key_version = 0x03`,
  the rescue token, validation weight and policy (M4-R design).
- **Review.** A written security note with the re-derived bounds, an
  internal design review, then the external cryptographer review that R1
  recommends before H4R.
- **Constant-time prover and zeroization.** The Python reference has neither.
- **Further tests from R1 §7.**
  - Toy-parameter statistics (λ = 16, τ = 1, k = 4, where a cheating prover
    should succeed about 2^−k of the time): this engine is not generic in λ.
    The closest test here: a wrong correction `c_4` passes exactly when
    `δ_4 = 0`, i.e. when the prover has guessed that tree's challenge.
  - Per-field transcript-dependency tests: the negative tests and vectors flip
    every proof section and statement field, but do not vary each hash input
    in isolation.
  - Bit flips across a larger sample of positions (the suite flips about 50
    fixed positions and 4 random ones; the differential set adds 262 seeded
    bit and byte flips across every section).
- **Performance.** Nothing is optimised beyond what the Python tests need. The
  Rust verifier is too slow for the validation weight; see "Rust verifier".

## Open questions for reviewers

1. **The security argument.** Does FAEST v1.1 Theorems 1–2 (with BBD+23
   Theorem 2 for the consistency check) carry over to this protocol (SPEC
   §13.2)? Specifically:
   - the VOLEHash replacement: two keyed polynomial hashes over GF(2^128)
     without constant term, with a 2λ-bit output. It is GF(2)-linear, and
     `ε_v ≤ (n_v/2^128)^2`. Is the SoftSpokenVOLE analysis happy with an
     F2-linear hash defined through GF(2^128) blocks?
   - ZKHash with a full-width `t`;
   - the generic degree-2 constraints in place of the AES constraints;
   - `ℓ`, `C ≈ 2^15.4`, beyond the `2^13` that FAEST's lemmas assume.
2. **Extraction.** Is straight-line extraction in the ROM (FAEST v1.1 Lemma 3)
   unaffected by the SHAKE256 GGM tree and the tweak encoding of SPEC §3.2?
3. **Non-malleability.** 4R-6 asks that a proof can neither be moved to
   another transaction nor mauled into another valid proof. SPEC §13.4 argues
   this informally, as FAEST v3 does. Is that enough for the signet, or do we
   need a proof, e.g. via unique responses and a Fiat–Shamir
   simulation-extractability result (ePrint 2024/1724)?
4. **QROM.** Accept "conjectured" (R1 option Q3), or fund a proof (R1 Q2,
   online extraction with compressed oracles)?
5. **PRG speed and validation weight.**
   - Options: keep SHAKE256 and accept 45–80 ms; move the leaf expansion to
     multi-lane Keccak (AVX2 4-way) or TurboSHAKE256; or use AES-128-CTR for
     the expansion only.
   - The task preferred stdlib primitives and no AES; whichever we pick
     changes the vectors and needs a version bump.
   - Measured on 2026-10-14: about 113 ms, so 45–80 ms was optimistic, and
     smaller trees (τ ≈ 22) are a further option. See "Rust verifier".
6. **Encoding.** Is the argument of SPEC §7.7 sufficient? In particular, the
   `assert_add` lemma, and the rule that public values only change
   coefficients, never the instruction list.
7. **Proof size.** 87.5 kB per rescue at τ = 16. Is that acceptable in the
   annex, or should v0.2 look at τ = 11 (about 61 kB, 9× more PRG work) or a
   FAEST v3-style BAVC?
8. **Statement registry.**
   - Is restricting `K` to 1–64 printable ASCII bytes right?
   - The empty-suffix ML-DSA variant needs an id (0x02 is reserved).
9. **Hedging.** `(r, iv_pre) = H(x ‖ μ ‖ ρ)` hashes the wallet seed directly.
   Should it use a derived key instead?
10. **Several statements per seed.** One seed underlies several statements
    (suffixes 0, 1, …, and the ML-DSA label). Zero knowledge says proofs for
    one do not help with another; worth a second look.
11. **Message limit.** Is 65,535 bytes the right cap for `m`? The rescue lane
    uses 96.

## Reproduce

```
python -I -m unittest discover -s python/tests -t python    # all tests
python -I python/tools/circuit_stats.py                     # gate counts, sizes, digests
python -I python/tools/bench.py 5                           # timings
python -I python/tools/gen_vectors.py                       # regenerate the vectors
python -I python/tools/gen_differential.py                  # regenerate the differential set (~1 min)
```

The Rust crate is in `rust/`; see "Rust verifier" for its tests, benchmark
and pod.

The package (`python/voleith`):

- `gf128`, `sym`, `bits`: field, tagged SHAKE256, bit strings;
- `vc`, `vole`, `unihash`: GGM trees, VOLE, hashes;
- `circuit`, `sha256_gadgets`, `sha256_ref`, `statements`: the constraint layer and statement 0x01;
- `proof`: prove and verify.
