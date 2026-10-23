# Notes on v0.2 (2026-10-14)

Companion to `SPEC.md`: measurements, what is missing, and questions for
reviewers. v0.2 replaced v0.1 on the same day: 24 GGM trees of mixed depth
instead of 16 trees of depth 8 (section "v0.2 tree split"). Two internal
reviews followed; their findings and SPEC v0.2 revision 1 are in section
"2026-10-14 internal reviews". Sections and numbers marked "v0.1,
superseded" are kept for the record only.

## Python measurements (v0.1, superseded)

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

## Internal review (of v0.1)

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
| Proof | **130,218 bytes** with 24 trees (v0.1, 16 trees: 87,506; R1 estimate: 89.2 kB) |

Of the 130,218 bytes, the 23 correction vectors take 122,061 (94%), `d` 5,259,
the tree openings 2,816 and the rest 82. Each witness bit costs 3 bytes
(τ = 24 bits; v0.1: 2 bytes).

The savings against R1's estimate come from folding constants and public
values (Ch and Maj with public inputs, the bit-0 carry of public addends) and
from the last four rounds of the outer compression, whose outputs are public
(`y − IV_out`) and are checked by `assert_add` without new witness bits.

## Rust verifier

Added 2026-10-14 for v0.1; the crate now implements v0.2 (section "v0.2 tree
split"). The design notes below still hold; the tests, benchmarks and the
validation-weight discussion in this section are v0.1's and superseded.

`rust/` is a Cargo crate (library `voleith`, built as rlib
and staticlib) with the verifier, a prover and the C function
`voleith_verify_s1` (header `rust/include/voleith.h`). It was written from
SPEC.md with the Python package open for structure, so it checks the Python
code less independently than the internal review's re-implementation did.

- **Verifier.** SPEC §11 in order: statement id, canonical public inputs,
  message length, proof length, header and padding bits are checked before any
  parsing of proof contents or hashing. After those checks the work is
  bounded but not constant: it varies with the bits of the public challenge
  `Δ` (a conditional XOR per set bit; SPEC §11, properties). Every buffer
  size is fixed by the statement: about 6 MB per call (VOLE columns and rows
  1.4 MB, wire keys 4.1 MB, and on CPUs without PCLMULQDQ five 64 KiB
  multiplication tables, which the fallback path alone allocates), plus
  about 8 MB for the circuit, built once per process (8–10 ms).
- **Prover.** Reproduces the Python proofs byte for byte from the same ρ (the
  4 vectors and the 100 differential cases). Since 2026-10-15
  (finding F7) its GF(2^128) arithmetic and control flow
  on secret data are constant time and it zeroizes its secrets; see
  `rust/CT-AUDIT.md` for what was checked, the dudect results and what
  remains. The Python reference is unchanged and still test-only.
- **Unsafe code.** The crate root has `#![deny(unsafe_code)]` and every module
  `#![forbid(unsafe_code)]`, except `src/ffi.rs` and `src/clmul.rs` (the
  PCLMULQDQ intrinsics, called only after run-time detection). The C shim checks every length
  first (`k_len` 1–64, `msg_len` ≤ 65,535, `proof_len` = the proof length,
  130,218 in v0.2, `y` not null; a null pointer only with length 0), then makes slices, and runs the
  verifier under `catch_unwind` (release builds keep `panic = "unwind"`).
- **Arithmetic.** GF(2^128) products use PCLMULQDQ when the CPU has it
  (run-time detection), otherwise a portable bit-serial constant-time multiply
  in the prover and in the verifier's `ZkHash::finish`, and, for the rest of
  the verifier's public data, a 4-bit-window multiply and 64 KiB tables for
  fixed multipliers. Without PCLMULQDQ the verifier is not exactly as fast as
  before the constant-time work: median 26.7 ms against 26.1 ms for the
  table-only base and 22.8 ms with PCLMULQDQ (`rust/CT-AUDIT.md` §5). No AES instruction is
  used.
- **Dependencies.** Runtime: `sha3 =0.10.9` (RustCrypto, for SHAKE256), which
  brings `digest 0.10.7`, `block-buffer 0.10.4`, `crypto-common 0.1.7`,
  `generic-array 0.14.7`, `typenum 1.20.1`, `keccak 0.1.6`, `version_check
  0.9.5` (build only) and, on aarch64 only, `cpufeatures 0.2.17` and
  `libc 0.2.190`. SHA-256 and HMAC (for the HMAC midstates, the circuit digest
  and the prover's relation check) are implemented in the crate instead of
  adding `sha2`. `zeroize =1.8.2` (no default features but `alloc`; also
  enabled in `sha3`) clears the prover's secrets; see `rust/CT-AUDIT.md`. Dev only: `serde_json =1.0.149` and `secp256k1 =0.31.1`
  (`secp256k1-sys 0.11.0` with libsecp256k1 v0.6.0, compiled by gcc 12.2 at
  `-O3` without the x86-64 assembly, `ECMULT_WINDOW_SIZE` 15). `Cargo.lock`
  holds `cc` at 1.4.7 because 1.8.0 was three days old.

### Tests (v0.1, superseded)

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

### Benchmarks (v0.1, superseded)

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

### Does the proof pay for its verification? (v0.1, superseded)

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

Outcome: v0.2 takes the first option, with `τ` chosen by measurement instead
of by this model (section "v0.2 tree split").

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
cargo bench --locked --features bench-splits --bench verify -- --taus 22,24 --runs 1000 --schnorr 20000
RUSTFLAGS="-C target-cpu=x86-64-v3" CARGO_TARGET_DIR=target-v3 cargo bench --locked --features bench-splits --bench verify
# afterwards: delete the pod by name, then the namespace
kubectl -n rescue-build delete pod rust-build
kubectl delete namespace rescue-build
```

The v0.1 benchmark above (`cargo bench --bench verify -- [verify runs]
[Schnorr runs]`) is the version at commit 962aeee.

## v0.2 tree split

**Decision rule** (coordinator, 2026-10-14): measure the candidate splits with
the v0.1 procedure, then pick the smallest `τ` whose measured
`C = 1.25 × 50 × p99(verify) / median(Schnorr)` is at most `budget / 1.5` in
every run, where `budget = proof bytes + 50`. Candidates: FAEST's split for
`τ = 22` (18 trees of depth 6, 4 of depth 5) and `τ = 24` (8 of depth 6, 16 of
depth 5); `τ = 26` or 32 only if neither qualifies.

**Implementation.** Python and Rust both take a `TreeSplit` (SPEC.md §2, §5.3).
`verify()`, `prove()` and `voleith_verify_s1` use only the frozen split. The
benchmark reaches other splits through `voleith::bench`, which exists only with
the cargo feature `bench-splits`; in Python, through the private
`_prove_impl(..., split=)` and `_verify_impl(..., split)`. The two
implementations produce the same proof for each candidate from the
benchmark's inputs (SHA-256 `fa208810…` for `τ = 22`, `66095300…` for
`τ = 24`, printed by every run), and each verifies it.

**Procedure.** The v0.1 pod spec and image (section "Rust verifier",
"Reproduce"), generic x86-64 release build, one thread. Per run: one proof per
split from the crate's prover; 1,000 verifications per split, the splits
interleaved; 20,000 libsecp256k1 BIP-340 verifications in the same binary, in
four blocks between the verifications; then 100 rejections per split of each
of two proofs that fail only at the final comparison. Three runs; none
overlapped minutes x4 or x5. Another workload's cross-compilation had loaded
the host (load average up to 29) until about 17:30; the runs started after it
had dropped to one core, at load averages of 1.3–2.7.

| Run (UTC) | τ | Proof bytes | Verify median | Verify p99 | Schnorr median | C | Budget | Margin (budget / C) | C ≤ budget / 1.5 |
|---|---|---|---|---|---|---|---|---|---|
| 17:30 | 22 | 119,540 | 41.06 ms | 57.81 ms | 41.58 µs | 86,898 | 119,590 | 1.38 | no |
| 17:30 | 24 | 130,218 | 33.92 ms | 50.24 ms | 41.58 µs | 75,524 | 130,268 | 1.72 | yes |
| 17:36 | 22 | 119,540 | 42.02 ms | 61.36 ms | 42.96 µs | 89,264 | 119,590 | 1.34 | no |
| 17:36 | 24 | 130,218 | 34.57 ms | 51.56 ms | 42.96 µs | 75,015 | 130,268 | 1.74 | yes |
| 17:38 | 22 | 119,540 | 48.41 ms | 63.49 ms | 44.38 µs | 89,397 | 119,590 | 1.34 | no |
| 17:38 | 24 | 130,218 | 37.89 ms | 57.36 ms | 44.38 µs | 80,765 | 130,268 | 1.61 | yes |

- `budget / 1.5` is 79,727 for `τ = 22` and 86,845 for `τ = 24`.
- Rejections at the final comparison cost the same as valid proofs: medians
  33.9–37.5 ms and p99 50.2–54.7 ms for `τ = 24` (43.9–46.3 and 59.8–60.6 ms for
  `τ = 22`).
- Proving with the Rust prover: 36–44 ms for `τ = 24`, 49–54 ms for `τ = 22`.
  SHAKE256 ran at 221–242 MB/s, as in the v0.1 runs.
- Against v0.1 (about 113 ms), verification is about three times faster: the
  verifier expands 1,000 leaves instead of 4,080 (5.3 MB of SHAKE256 output
  instead of 21.7 MB).

**Choice.** `τ = 22` misses the rule in all three runs (margins 1.34–1.38);
`τ = 24` meets it in all three (1.61–1.74), so `τ = 24` is the smallest
qualifying split, and `τ = 26` and 32 were not measured. It is frozen as the
only parameter set of SPEC v0.2: 8 trees of depth 6 and 16 of depth 5,
version byte `0x02`, proofs of 130,218 bytes.

**Tests for v0.2.**

- `vectors/statement1-v0.2.json`: the 4 fixed-rng vectors with their
  intermediates and 52 negative vectors (one per padding bit of the 23
  corrections and of `d`, the rest as in v0.1).
- `vectors/statement1-v0.2-differential.json` (19.5 MB, master seed
  "voleith differential set v0.2 / 2026-10-14"): 100 valid cases and 440
  mutated ones (166 section flips, 8 header bytes, 24 padding bits, 40 byte
  XORs, 20 double flips, 7 zeroed sections, 16 truncations, 7 extensions,
  20 wrong messages, 22 wrong statements, 20 malformed public inputs, 14 moved
  proofs, 11 swapped sections, 5 random bodies, 60 random flips).
- Python: 72 tests pass. It accepts the 100 valid cases and rejects all 440
  mutated ones.
- Rust: 27 tests pass (18 unit, 7 vector, 2 differential). Rust returns
  Python's verdict on all 4 + 52 + 540 cases and every intermediate matches;
  the Rust prover reproduces all 104 proofs byte for byte.
- The v0.1 vector files are removed; git history keeps them.

## 2026-10-14 internal reviews

Two AI models reviewed v0.2 at commit `0623179`. Neither is an external
cryptographer, and no external review has been done; the owner may arrange
one. Their full texts (in Chinese) are kept outside this repository.

| Reviewer | Verdict | In short |
|---|---|---|
| gpt-6-astra, effort xhigh | REVISE | Off-chain demos with test seeds may go on; before the consensus design, add the rescue-lane preconditions and fix the findings below. No reproducible forgery and no malleability of the proof encoding. It reran the 72 Python tests and read the Rust code without compiling it. |
| Fable 5.1, effort max | PROCEED | No construction defect that needs a new version byte. §13 has the right structure but gaps in its bookkeeping, and three properties of the rescue lane must become consensus rules. Close its High and Medium items before freezing v0.2 or activating it on signet. |

Revision 1 answers both without a protocol change: the version byte stays
`0x02`, every proof is the same, and both vector files regenerate byte for
byte from the revised Python code (SHA-256 `e4ae3f6d…` and `9ec6ff5f…`).

### Findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| astra: publishing `y = d` exposes the old Schnorr key on every other output, network or spend path of that key; the network id does not protect those | High (conditional) | SPEC §12.1 item 4 and §13.1. To be enforced and tested in the M4-R design; not verifiable in this repository. |
| Fable F1: three preconditions the proof cannot provide: `y` fixed by the spent output, a SIGHASH_ALL-type rescue sighash, and `y = d` burning the key | High | SPEC §12.1 items 1, 2 and 4, with item 3 (`m` exactly 96 bytes), mirrored in §13.1. |
| astra: `prove()` returned a `ProverTrace` holding `r` and the tree roots, with `Debug`; the reviewer recovered `x` from `r` and a vector proof | Medium | Fixed. `prove()` returns the proof only. `prove_traced()` exists only with the cargo feature `test-trace`, which only the tests enable, through a dev-dependency of the crate on itself; a plain library build has no features (checked in the rustc command line). `ProverTrace` has no `Debug`, `Clone` or `PartialEq`. Python's `prove()` already returned the proof only. |
| Fable F2: the "honest keys" assumption was misplaced; one-wayness and seed entropy unclear | Medium | SPEC §13.1. |
| Fable F3: §13.2 bookkeeping: no `Q_{2,3}·2^−128` term, an underived factor 3, partial guessing of `Δ` only asserted, the source of `C(τ,2)`, §13.6 on 128-bit outputs | Medium | SPEC §13.2 (new term, factor dropped, lemma sketch) and §13.6. The source of `C(τ,2)` is still to be checked. |
| Fable F4: strong unforgeability argued only informally | Medium | SPEC §13.4: lemma sketch; the owner can always change the `wtxid`. |
| Fable F5: the threat model is quantum, the claims are classical | Medium | SPEC §13.5 and §13.6. The risk decision itself belongs to the consensus design. |
| Fable F6 and astra: verification work depends on `Δ` (up to 1,324,702 bytes of XOR for `chall3 = ff…ff`), every well-formed proof costs a full verification, and the weight was calibrated on one machine | Medium (F6), Low | SPEC §11 and §12.1; measured below. Other hardware not measured; per-block or per-peer limits are M4-R policy. |
| Fable F7 and astra: both provers leak through cache timing and do not zeroize; the zero-knowledge wording was too strong; §14 named only the Python prover | Medium (deployment gate), Low | SPEC §13.3 and §14 item 2: zero knowledge stated conditionally, both provers test-only, demos with test seeds only. |
| astra: a cold `verify()` built the circuit before rejecting a malformed input (Python: 163 ms for an empty proof) | Low | Fixed in both languages: layouts from fixed sizes, the circuit only after step 6. Python, cold, empty proof: 157–159 ms before, 0.02 ms after. Tests: `rust/tests/cold_reject.rs`, `test_format_checks_do_not_build_the_circuit`. |
| astra: `voleith.h` still said 87,506 bytes and v0.1 | Low | Fixed: 130,218 bytes, v0.2, and that §12.1 is the caller's. |
| Fable F8: the second VOLEHash key is load-bearing | Low | SPEC §5.4. |
| Fable F9: tests should tamper with single QuickSilver terms, not only witness bits | Low | New tests: on the small gadget circuit, every `A0_t` and `A1_t`, in Python and Rust; end to end in Python, both terms of the first, a middle and the last constraint of statement 0x01. |
| Fable F10: stale `v0.1` in `sym.rs`; `verify_impl` parsed every statement as 0x01; no byte-order known answer | Low | Fixed: the comment; Rust parses public inputs by statement id, so an id without rules fails closed; a known answer in both languages (`X^127 · X` gives byte 0 = `0x87` and zeros, as SPEC §1.3 says). |
| Fable F11: say why `Δ = 0` is valid | Low | SPEC §11. |
| Fable F12: `rnd` hashes the seed directly | Low | No change; SPEC §15. |
| Fable F13: SHAKE128 or grinding would cut more work than `τ` | Low | No change (each needs a version bump); SPEC §15. |

On the open questions below, the reviews add: GF(2^128) blocks keep
VOLEHash GF(2)-linear and the full-width `t` is fine, but extraction and the
full CMA reduction still need a written argument (Q1–2); anti-replay, strong
unforgeability and simulation extractability must be defined separately in
the consensus design, with QROM as a conjecture (Q3–4); keep `τ = 24`, and
look at the corrections (94% of the proof) for size (Q5, Q7); the
`assert_add` argument holds (Q6); the ASCII restriction on `K` may stay, the
rescue layer should fix the wallet label and index encoding, and the empty
suffix needs its own statement id (Q8); a derived `rnd` key is not needed,
but several statements on one seed need a joint one-wayness assumption
(Q9–10); the library may keep 65,535 bytes if the rescue adapter requires 96
(Q11).

For the external review, Fable names three places: §5.4 with §13.2 (the
VOLEHash replacement and the SoftSpoken argument over 24 mixed-depth trees,
with the sub-cube lemma); §8 with §13.2 and §13.4 (transcript binding,
straight-line extraction, the `Q_{2,3}` term, strong unforgeability); and
§13.1, §13.5 and §13.6 (whether conjectured QROM security, Grover at category
1, a 256-bit one-way function and the seed-entropy precondition make an
acceptable, recorded decision). It suggests formal or exhaustive tools rather
than reading for §7.7.

### Benchmarks after revision 1

The pod, image and procedure of "v0.2 tree split" (generic x86-64 release
build, one thread), `τ = 24` only, `cargo bench --locked --features
bench-splits --bench verify -- --taus 24 --runs 1000 --schnorr 20000`. Each run
interleaves four inputs, 1,000 verifications each, with 20,000 libsecp256k1
BIP-340 verifications in the same binary: the valid proof with a 96-byte
message; the same proof with `chall3 = ff…ff` (well-formed, so verified in
full, with every bit of `Δ` set: the most conditional XOR); a valid proof
over a 65,535-byte message; and that proof with `chall3 = ff…ff`. Three runs;
none overlapped minutes x4 or x5 or another workload's six-hourly job
(04:07–04:09). Load average 1.7–2.7.

| Run (UTC) | Input | Median | p99 | C | Budget / C |
|---|---|---|---|---|---|
| 03:56 | valid, 96-byte message | 32.61 ms | 48.73 ms | 76,607 | 1.70 |
| 03:56 | `chall3 = ff…ff` | 32.81 ms | 47.99 ms | 75,449 | 1.73 |
| 03:56 | valid, 65,535-byte message | 32.93 ms | 49.10 ms | 77,189 | 1.69 |
| 03:56 | 65,535-byte message, `chall3 = ff…ff` | 33.01 ms | 48.84 ms | 76,789 | 1.70 |
| 03:58 | valid, 96-byte message | 33.57 ms | 53.11 ms | 82,106 | 1.59 |
| 03:58 | `chall3 = ff…ff` | 33.80 ms | 51.53 ms | 79,660 | 1.64 |
| 03:58 | valid, 65,535-byte message | 33.76 ms | 51.46 ms | 79,559 | 1.64 |
| 03:58 | 65,535-byte message, `chall3 = ff…ff` | 34.44 ms | 53.64 ms | 82,932 | 1.57 |
| 04:16 | valid, 96-byte message | 32.98 ms | 49.08 ms | 77,222 | 1.69 |
| 04:16 | `chall3 = ff…ff` | 32.82 ms | 48.04 ms | 75,577 | 1.72 |
| 04:16 | valid, 65,535-byte message | 32.94 ms | 50.73 ms | 79,816 | 1.63 |
| 04:16 | 65,535-byte message, `chall3 = ff…ff` | 33.01 ms | 47.62 ms | 74,912 | 1.74 |

- `C = 1.25 × 50 × p99 / median(Schnorr)`, budget 130,268 (proof bytes + 50).
  Schnorr medians: 39.76, 40.43 and 39.73 µs.
- Every input meets the v0.2 rule (`C ≤ budget / 1.5`) in every run; the
  lowest margin is 1.57. In each run the medians of the other three inputs
  are within −0.16 to +0.87 ms of the valid proof's: the extra XOR (at most
  1.3 MB) and hashing a 65,535-byte message into `μ` are lost in the noise.
- Rejections at the final comparison (ã or chall3 flipped, 100 each):
  medians 32.5–33.4 ms, p99 45.5–46.4 ms. Rust prover: 39–44 ms. SHAKE256:
  226–249 MB/s. The tree-split runs measured valid-proof medians of
  33.9–37.9 ms.

### Tests after revision 1

- Python: 76 tests pass (72 before). New: malformed inputs leave the
  circuit unbuilt; the GF(2^128) byte-order known answer; QuickSilver term
  tampering on the small circuit and end to end.
- Rust: 31 tests pass (27 before): 21 unit, 1 in `tests/cold_reject.rs`, 7
  vector and 2 differential tests. `cargo fmt --check` is clean, and clippy
  with `-D warnings` is clean for the library alone, for all targets and for
  all targets with `bench-splits`; each commit was checked separately.
- Rust returns Python's verdict on all 4 + 52 + 540 cases, every
  intermediate matches, and the Rust prover reproduces all 104 proofs byte
  for byte.
- The C link check of "Rust verifier" passes with the new header.

## Not done yet

- **Statement 2** (HKDF-SHA-512, desktop wallet). It needs SHA-512 gadgets, the
  degree-≤6 E3 encoding of R1 and a degree-d QuickSilver check, which v0.1
  does not have. R1 estimates the proof at about 296 kB.
- **Rust.** Verifier, prover and differential tests are done (see "Rust
  verifier"). The verifier was fuzzed, and the constant-time prover passed
  three rounds of AI code review and an independent cross-check (section
  "2026-10-15 work branches"). Still open: a human review of the
  constant-time prover before any real seed is used (`rust/CT-AUDIT.md`).
- **Core integration.** Annex TLV, rescue sighash with `key_version = 0x03`,
  the rescue token, validation weight and policy (M4-R design). The
  verifier-only static library is ready to link (section "2026-10-23 tools
  and verifier-only build").
- **Review.** Two internal reviews are done (section "2026-10-14 internal
  reviews"). Still open: a written security note with every bound derived,
  not sketched, and the external cryptographer review that R1 recommends
  before H4R.
- **Constant-time prover and zeroization.** The Rust prover has both
  (`rust/CT-AUDIT.md`); the Python reference has neither. SPEC §13.3 and §14
  item 2 still describe the Rust prover as test-only and are to be revised
  after review.
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

## 2026-10-15 work branches

Six cloud sessions on 2026-10-15 produced five branches. Their commits
were replayed under this repository's identity, with the same trees.
All five are merged into `main`; see "Integration (2026-10-15)".

| Branch | What | State |
|---|---|---|
| `cleanroom/go-verifier` | An independent verifier in Go, written from SPEC.md and the vectors only. Its base, `cleanroom/base`, holds nothing else. | done |
| `ct-prover` | Finding F7: constant-time GF(2^128) arithmetic in the Rust prover, zeroization and a dudect-style timing test (`rust/CT-AUDIT.md`). | done; three review rounds, the last SHIP |
| `crosscheck` | An independent check of `ct-prover`: rerun, the portable path, three implementations on 800 cases, 60 minutes of fuzzing the new verifier. | done, no finding |
| `spec-rev2` | SPEC.md v0.2 revision 2: wording only, resolves the 18 spec issues, adds per-gadget circuit digests. | done, reviewed |
| `fuzz` | cargo-fuzz targets for `verify`, for structured mutations of the valid proofs and for the C ABI (`rust/fuzz/REPORT.md`). | done, no finding |

### Clean-room Go verifier

- **Results.** Go 1.24, standard library only (`crypto/sha3`).
  - It verifies the 4 KATs with every intermediate equal, rejects all 52
    negatives and gives the expected verdict on all 540 differential cases.
  - It reproduces both circuit digests of §7.6 and every gate count.
  - An instrumented test shows that every rejection at steps 1–6 happens
    before any hash call.
  - Single-thread median verify time is about 27 ms on a 2.1 GHz Xeon.
    Valid proofs, `chall3 = ff…ff` and a 65,535-byte message are within
    0.25 ms of each other.
- **Spec issues.** `go/SPEC-ISSUES.md` lists 18 places where SPEC.md is
  ambiguous, underspecified or inconsistent. None disagrees with the vectors.
  For each one, the session implemented the other reading and ran it against
  the vectors and the digests. All 18 are wording or completeness issues, for
  a wording-only revision 2 (no protocol change, vectors unchanged).

| # | Severity | Section | Issue |
|---|---|---|---|
| 1 | High | §1.2, §5.1 | "The first ℓ̂ bits" of an `exp` output is defined through the padding rule, which rejects. Read literally, every valid proof fails: about half of the 1,000 expansions per proof have the padding bit set. |
| 2 | High | §7.4, §7.6 | The circuit is pinned by its digest only. Items 4–8 and 10 are guesses that only the digest confirms, and a mismatch cannot be localised. Needs a byte grammar, one emission-order rule and per-gadget test digests. |
| 3 | Medium | §11 | "Steps 1–5 before any hashing or parsing of proof contents" conflicts with step 5, which reads `π[0..2)`. It is not said when the SHA-256 work on `K` happens. Should read: steps 1–6 touch only lengths, the public-input encoding, `π[0..2)` and the padded bytes; no hash, PRG or circuit work before step 7. |
| 4 | Medium | §7.6 | Opcode width: one byte, then `u32le` operands. |
| 5 | Medium | §7.4 | `add_multi`: the accumulator is the first argument, `acc = add(acc, next)`. |
| 6 | Medium | §7.4 | Nested gadgets: arguments complete first; per-bit gadgets emit all of bit `i` before bit `i+1`; σ1 before σ0; the whole schedule before round 0. |
| 7 | Medium | §7.4, §7.2 | "Ch/Maj/Σ on public words fold away" contradicts "only constants fold". The PUB instructions are emitted; they only cost no MULs. |
| 8 | Medium | §7.4 | Standalone compression circuit: `P = 0` is not stated, and "big-endian words" has no meaning for a wire layout. |
| 9 | Medium | §11, §7.5 | The `verify` interface is not defined: statement id width, and the encoded public inputs as the input. |
| 10 | Low | §7.2 | "Return `NOT(w)`" means the builder's NOT instruction, not `XOR(w, 1)`. |
| 11 | Low | §3.2, §8, §11 | Three notations for the `ch3` input. |
| 12 | Low | §5.4, §6.3 | VH and ZKH use opposite Horner conventions; ZKH's `t` sum is only implied. |
| 13 | Low | §5.3 | The bit order of `Δ` and `δ_i` must be assembled from three sections. |
| 14 | Low | throughout | Symbols reused with other meanings (`s`, `t`, `T`, `S`, `w`, `c`, `C`, `r`, `Q`, `d`). |
| 15 | Low | §3.3 | "A `leaf` and an `exp` call differ only by tag" holds for the non-secret prefixes only. |
| 16 | Low | §11, §12.1 | The rescue-lane checks (`y` range, 96-byte `m`) could be put into `verify` by mistake. |
| 17 | Low | §11 | SPEC does not describe the differential file or its edit language. |
| 18 | Low | §1, §11, §14 | SPEC defers to code and to NOTES.md, which an independent implementer may not have. |

SPEC.md v0.2 revision 2 (branch `spec-rev2`) resolves all 18 issues in wording only; SPEC §16 lists where, and `vectors/gadgets-v0.2.json` adds per-gadget circuit digests (§7.6).

### Constant-time prover

What the branch changes (19 commits on `580fabe`, the review fixes
included):

- **Multiplication.** GF(2^128) products use PCLMULQDQ, detected at run
  time, and otherwise a bit-serial masked multiply.
- **Hashes.** The prover's universal hashes take a constant-time key
  multiplier. The prover names it explicitly; the type system does not
  enforce this (review finding F3), the review of the call paths does.
- **Branches.** Two branches on secret data are gone: the ASSERT check in
  circuit evaluation and the early-exit HMAC comparison.
- **Zeroization.** `zeroize =1.8.2` plus sha3's `zeroize` feature, and a
  64 KiB stack scrub after every prover entry point, on success and on
  error. `prove_impl` is never inlined, so its frames lie below the scrub.

Results and status:

- **Tests.** Every proof is byte-identical. 34 tests pass in release and
  dev, and clippy and fmt are clean. `python/`, `vectors/` and SPEC.md are
  untouched (checked here by diff). Branch `crosscheck` reran all of this
  independently (below).
- **Speed.** On PCLMULQDQ hardware the verifier uses the same constant-time
  multiply. Verify went from 27.3 to 24.1 ms (−11.7%) and prove from 29.9 to
  28.0 ms (−6.4%): medians of 3 × 31 alternating runs on a 2.8 GHz Xeon VM.
  Without PCLMULQDQ the prover takes about 125 ms. The verifier then keeps
  its tables, except for the two products in `ZkHash::finish`, and verifies
  in 26.7 ms against 26.1 ms for the old table-only code.
- **Timing tests.** In every run the leaky control (|t| 820–1,923) and the
  old tables (323–1,303) are flagged. Both constant-time multiplies stay at
  |t| ≤ 2.77 at n = 200,000. The prove()-level test cannot tell the old
  prover from the new one, so it is a smoke test only. False alarms from an
  earlier harness version are recorded in `rust/CT-AUDIT.md`.
- **Known gaps.**
  - The `digest 0.10` block buffer and the XOF output buffer cannot be
    zeroized; only the stack scrub covers them.
  - Registers.
  - The caller's `witness` and `rho`.
  - No aarch64 PMULL path: the portable path is used there.
- **Reviews.** Three rounds of gpt-6.1-sol max on the diff.
  - Round 1: NOT-YET. The bench entry point skipped the stack scrub
    (Medium), the Welch test passed a fully distinguishable sample (Low),
    plus a wording claim and the bench running under `--all-targets`.
  - Round 2: NOT-YET. Its Welch fix let an undecidable crop hide a
    detected leak, so the positive control could fail (Low). Two doc
    leftovers.
  - Round 3: SHIP.
  The original texts are archived outside this repository.

### Cross-check (branch `crosscheck`)

Another session reran the work on `ct-prover` before the review fixes, and
found nothing:

- **Rerun.** 31 tests pass in release and dev, clippy and fmt are clean.
- **Portable path.** With PCLMULQDQ switched off in a scratch copy, all
  tests pass and every proof is byte-identical.
- **Three implementations.** 100 new statements and proofs (messages of 0,
  1, 96, random and 65,535 bytes), each with 5 single-bit proof flips over
  all §10 fields, one message change and one statement change: 800 cases.
  The Rust, Python and Go verifiers agree on every case, accept every
  valid proof and reject every change.
- **Fuzzing the new verifier.** 60 minutes on 4 cores, 971,534 executions:
  no crash, no timeout, no AddressSanitizer report, no accepted modified
  proof. 33 inputs were flagged slow under load (2.0–2.4 times a valid
  verify) but ran at normal speed when replayed on an idle machine.

### SPEC revision 2 (branch `spec-rev2`)

Reviewed here against `python/voleith`:

- The two statement vector files are byte-identical, and only SPEC.md,
  NOTES.md and the new gadget tool, vectors and tests changed.
- The new statements match the reference: hash outputs are truncated without
  a padding check; the two Horner forms of VH and ZKH; the bit order of `Δ`;
  the emission order of `add` and `assert_add`; the public bits are computed
  only after step 6.
- One sentence was tightened here: steps 1–5 may run in any order, and
  step 6 needs the length that step 4 checked.
- Integration issue: `rust/tests/gadget_vectors.rs` includes `src/gf128.rs`
  and `src/circuit.rs` with `#[path]`. On `ct-prover`, gf128.rs also needs
  `clmul.rs`, so the merge has to adjust that test.

### Fuzzing (branch `fuzz`)

Three cargo-fuzz targets, run against `main` (`580fabe`):

- `verify_raw`: arbitrary bytes split into statement, message and proof;
- `verify_mutate`: structured edits of the valid proofs (bit flips, field
  boundaries of §10, header, lengths, message and statement);
- `ffi`: `voleith_verify_s1` under AddressSanitizer, with arbitrary lengths
  and null pointers.

Results:

- **Campaign.** 3 h 15 min on 4 cores, in two phases on the same corpora
  (the session's runner stopped the first at 2 h): 4.29 million
  executions. Coverage levelled off within about 1.5 hours.
- **Findings.** No crash, panic, timeout, memory error, or accepted
  modified proof.
- **Timing.** 21 inputs were flagged at more than twice a valid verify
  while all 4 cores were busy. On an idle core, none reproduces: the
  slowest runs at 1.17 times a valid verify. `Δ = ff…ff` costs 1.04 times
  and a 64 KiB message 1.01 times.
- **Harness.** An early `ffi` "accept" was the harness's mistake: a null
  message pointer with length 0 is the empty message, which the header
  allows. Fixed before the main run.
- **Optional notes.**
  - `rust/include/voleith.h` could say that a null `y` returns 0; the shim
    already checks it.
  - `vc.rs` relies on `debug_assert!` for the opening length, which holds
    by construction for the fixed layout.

The `crosscheck` branch ran the same harness for 60 minutes against the
constant-time verifier, with the same result.

## Integration (2026-10-15)

Merged into `main` on 2026-10-15, from `a405ac5`.

- **How the inputs went in.**
  - `ct-prover`, `spec-rev2`, `fuzz` and `crosscheck` are merged in that
    order (`--no-ff`). There was no conflict, NOTES.md included: every edit
    of both sides merged cleanly. `crosscheck` carries an earlier state of
    `ct-prover`, so `rust/src`, `Cargo.toml`, `Cargo.lock`, `CT-AUDIT.md`
    and `benches/` end up equal to `ct-prover`'s.
  - `cleanroom/go-verifier`: `go/` copied with
    `git archive origin/cleanroom/go-verifier go | tar -x` in one commit;
    its history is not merged and its files are unchanged.
- **Fixes, each its own commit.**
  - `rust/tests/gadget_vectors.rs` did not compile (`crate::clmul` missing
    from `gf128.rs`). The test now also includes `src/clmul.rs`, under the
    same cfg as lib.rs. Nothing under `rust/src` changed.
  - `crosscheck/fuzz/` removed: its targets, library and scripts were
    identical to `rust/fuzz/`; only the `voleith` path and the zeroize lock
    entries differed. `crosscheck/REPORT.md` now points at `rust/fuzz/`.
  - `crosscheck/run.sh` copies the tree's `go/` into
    `crosscheck/work/go-src/` (ignored) instead of exporting the branch to
    `/tmp/xc-go`; the driver comment in `crosscheck/go/main.go` says so.
  - `rust/fuzz/Cargo.lock` gains `zeroize 1.8.2`, which `cargo fuzz build`
    adds for the merged crate (the same lock as the removed copy).
- **New check.** `go/voleith/gadget_vectors_test.go` rebuilds all 20
  circuits of `vectors/gadgets-v0.2.json` with the clean-room builder
  (`circuit.go`, written from SPEC revision 1). All 20 match: digest,
  serialization length, the hex of the 18 entries that give it,
  instruction and output counts, and every gate count.

Checks (4 vCPUs, rustc 1.97.0, nightly 1.101.0, cargo-fuzz 0.13.2,
Go 1.24.7, Python 3.13.16):

| Check | Result |
|---|---|
| `python -I -m unittest discover -s python/tests -t python` | 81 tests OK (62 s) |
| `cargo test --release` | 40 passed, 2 ignored, 0 failed (lib 24 + 2 ignored, cold_reject 1, differential 2, gadget_vectors 6, vectors 7) |
| `cargo test` | the same 40 passed, 2 ignored |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo fmt --check` | clean |
| `go vet ./...` | clean |
| `go test ./...` | 17 tests pass (24 subtests, 20 of them gadget vectors), 1 skipped (`TestMedianVerifyTime`, benchmark only) |
| fuzz build (`verify_raw`, `verify_mutate` without sanitizer, `ffi` with AddressSanitizer) | all three build against the merged crate |
| fuzz run, `run_campaign.sh 120` (all three targets in parallel, 2 min each) | `verify_mutate` 6,680 + 6,669, `verify_raw` 41,580, `ffi` 17,752 executions; no crash, artifact or slow input |
| `bash crosscheck/run.sh` (takes a seed, not a case count: default 100 cases) | 800 tests, 0 mismatches between Rust, Python and Go (2 min 39 s) |
| SHA-256 of `vectors/statement1-v0.2.json` | `e4ae3f6d…8097d3`, as on `main` |
| SHA-256 of `vectors/statement1-v0.2-differential.json` | `9ec6ff5f…0a3535`, as on `main` |

No test failed. SPEC.md, `python/`, `vectors/` and `rust/src` are those of
the reviewed branches, and every proof is unchanged (the Rust vector and
differential tests reproduce the 4 vector and 100 differential proofs byte
for byte).

## 2026-10-23 tools and verifier-only build

Branch `cloud/c-r2-cli`, from `main` at `273f11b`. The protocol is
unchanged: SPEC.md and the three vector files have the SHA-256 they had
before (`c8b8773c…`, `e4ae3f6d…8097d3`, `9ec6ff5f…0a3535`,
`562954f8…484cae`), and the Rust tests still reproduce the 4 vector and
100 differential proofs byte for byte.

- **Verifier-only build.** A cargo feature `prover`, on by default, gates
  every prover-only item: `prove`, `prove_scrubbed`, `prove_impl`,
  `scrub_stack`, `ProveError`, `ProverTrace`, `vc::commit` and `vc::Tree`,
  `unihash::CtMul`, `Circuit::evaluate` and `prover_terms`,
  `s1_secret_bits`, `s1_hmac`, `S1_WITNESS_LEN`, the SHAKE tags `rnd` and
  `root`, and the dudect tests (`src/dudect.rs`). `prove_traced` needs
  `prover` and `test-trace`; `test-trace` stays a test-only feature,
  enabled by the self dev-dependency, which no longer turns on default
  features, so that `cargo test --no-default-features` tests the
  verifier-only library.
  - `cargo build --release --no-default-features --lib` gives a staticlib
    that exports `voleith_verify_s1`. `rust/check-verifier-only.sh` scans
    it with `nm -C`, with and without LTO, for the names above (and for
    `prove_impl`, `prove_scrubbed`, `scrub_stack`, `CtMul`,
    `prover_terms`, `ProverTrace` anywhere in a symbol): 0 hits in both
    verifier-only archives, 10 in both default ones (the positive
    control).
  - `cargo rustc --release --no-default-features --lib -- --print
    native-static-libs` on x86_64-unknown-linux-gnu:
    `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc`.
- **Command-line tools** (`rust/src/bin/`, feature `cli` = `prover` +
  `getrandom`; see `rust/README.md`). `voleith-prove` reads the seed from
  standard input only (64 hex digits, then nothing, `\n` or `\r\n`),
  through an unbuffered handle so that std's stdin buffer keeps no copy;
  computes y; draws rho with getrandom; proves; verifies; writes the proof
  to a new file; prints `y=<hex>`. Seed, hex digits, HMAC input and rho
  are in `Zeroizing` buffers inside `run()`, cleared before `main` exits
  on every path. `voleith-verify` prints `valid`/`invalid`, exit 0/1, 2
  for a usage error; a proof file of the wrong length is invalid.
  - **getrandom `=0.3.4`**, bin-only in effect: an optional dependency
    that only the `cli` feature enables and only `voleith-prove` calls. It
    was already in `Cargo.lock` (through the benchmark's secp256k1), is a
    year old, has MSRV 1.63, and is what most of the ecosystem runs (0.4
    is newer). On Linux it calls getrandom(2); on Windows `ProcessPrng`
    from bcryptprimitives.dll. Writing the OS calls by hand would need
    unsafe FFI in the tool for no gain.
  - `rust/tests/cli.rs`: round trip with the seed of the first proof
    vector (y must equal the vector's), all accepted stdin forms; 19
    malformed stdin inputs (bad hex, 63/65/66 digits, extra lines, a lone
    `\r`, spaces, NUL, 4 kB); 22 bad prove command lines (K empty, 65
    bytes, tab, DEL, non-ASCII, newline; suffix 256, -1, 01, empty, x;
    odd, non-hex and 65,536-byte messages; missing, repeated and unknown
    options); 17 bad verify command lines; an existing output file. No
    run prints 16 hex digits or 8 raw bytes of the seed to stdout or
    stderr, or writes them into the proof.
- **Python and Go verify commands.** `python/tools/verify_cli.py`
  (`python -I`) and `go/cmd/voleith-verify`, standard library only, with
  the Rust command's arguments, parsing rules and exit codes.
  `bash crosscheck/cli.sh` builds the Rust and Go commands and runs
  `crosscheck/cli_agree.py`: the 4 vector proofs, 20 differential cases
  (every tenth valid one; the first mutated case of ten kinds that a
  command line can express) and 34 usage and edge cases. All three give
  the expected exit code and output on all 58; with `/bin/true` as a
  command, all 58 are reported as mismatches.
- **Windows build.** `bash rust/build-windows.sh` cross-compiles both
  tools for `x86_64-pc-windows-gnu`, with Rust 1.97.0 pinned in
  `rust/windows/rust-toolchain.toml` (its own directory, so the crate's
  tests are not pinned) and Ubuntu 24.04's mingw-w64:
  `gcc-mingw-w64-x86-64` 13.2.0-6ubuntu1+26.1 (`-win32` and `-posix`
  variants the same), `binutils-mingw-w64-x86-64`
  2.41.90.20240122-1ubuntu1+11.4, `mingw-w64-x86-64-dev` 11.0.1-3build1.
  It builds twice from empty target directories with every local path
  remapped (checkout, target directory, CARGO_HOME, RUSTUP_HOME), `ld
  --no-insert-timestamp` and `-Cstrip=symbols`. Without the strip,
  `voleith-prove.exe` differed between builds: dlltool names the symbols
  of getrandom's raw-dylib import library after rustc's random temporary
  directory, which also put a local path in the binary. With it, the two
  builds are byte-identical, and a third from a checkout at another path
  gives the same hashes:

  | file | SHA-256 |
  |---|---|
  | `voleith-prove.exe` | `4918c38f12fbc8cd6864a41de0ee798044b7394e5079584c2f76bcebd54f5353` |
  | `voleith-verify.exe` | `f778aac193534eb632fd62aa1387242043319a519def11fd8b4bbc1027e9ff30` |

  Under wine 9.0 (Ubuntu's `wine64`, 9.0~repack-4build3): `voleith-prove.exe`
  with the first vector's seed (CRLF on stdin) printed the vector's y; its
  proof is `valid` for `voleith-verify.exe` and for the Rust, Python and
  Go commands on Linux, and `invalid` after one flipped bit; a bad seed,
  an extra line and suffix 300 exit 2. Not run on Windows itself. The
  binaries are not committed.
- **Still open before a real seed.** The human review of the constant-time
  prover (`rust/CT-AUDIT.md`, "Not done yet") applies to these tools too.

Checks (4 vCPUs, rustc 1.97.0, nightly 1.101.0, cargo-fuzz 0.13.2,
Go 1.24.7, Python 3.13.17):

| Check | Before (`273f11b`) | After |
|---|---|---|
| Python unittest | 81 OK | 81 OK |
| `cargo test --release` | 40 passed, 2 ignored | 40 passed, 2 ignored |
| `cargo test` | 40 passed, 2 ignored | 40 passed, 2 ignored |
| `cargo test --release --no-default-features` | — | 31 passed (lib 18, cold_reject 1, differential 1, gadget_vectors 6, vectors 5); the prover tests are compiled out |
| `cargo test --release --features cli` | — | 50 passed, 2 ignored (the 40, the bins' 3 + 3, cli 4) |
| clippy `-D warnings` | clean (`--all-features`) | clean: `--all-features`, `--no-default-features`, `--no-default-features --features test-trace` |
| `cargo fmt --check`, `go vet`, `gofmt -l` | clean | clean |
| `go test ./...` | 17 pass (24 subtests), 1 skip | 17 pass (24 subtests), 1 skip |
| fuzz, `run_campaign.sh 120` | `verify_mutate` 6,159 + 6,169, `verify_raw` 29,648, `ffi` 13,509; nothing found | 5,837 + 5,406, 14,274, 16,547; no crash or artifact; 10 inputs of 4–16 bytes flagged slow (71–82 ms against a 34.6 ms baseline), re-timed 20 times each on an idle core at about 33 ms a call with no `SLOW` line: the load artifact of `rust/fuzz/REPORT.md` |
| `bash crosscheck/run.sh` | 800 tests, 0 mismatches | 800 tests, 0 mismatches |
| `bash crosscheck/cli.sh` | — | 58 cases, 0 mismatches |
| `bash rust/check-verifier-only.sh` | — | OK |

### Review round 1 (2026-10-23)

A read-only review of `ff4ea00` and the design of how the operator uses
the tools. The operator restores the seed from an encrypted backup on
their own Windows machine and pipes it into `voleith-prove` once or twice.
That machine is the trust boundary (the backup's key is on its disk), so
swap there is not a concern. What must not leak is anything that leaves
the machine or that someone else sees: command lines, environment,
logs, crash reports and dumps, temporary files, and what the tool prints
or writes. SPEC.md, the vector files and every proof are unchanged (the
same SHA-256 as above; the Rust tests reproduce all proofs).

| Item | Change | Commit |
|---|---|---|
| 3 `--suffix` (Medium) | `--suffix 4294967296` overflowed (exit 101 with overflow checks). Length and digits are checked first; 2^32, 2^64, 400 digits and `000` are in the unit, CLI and agreement tests. | `60ea57f` |
| 1 Secret clearing (High) | SHAKE256 is a sponge of our own over `keccak::f1600` (`src/sym.rs`): it absorbs and squeezes in place, zeroizes its state and is never moved after absorbing. That closes the `digest 0.10` buffer gap of CT-AUDIT; a test compares it with `sha3` (now a dev-dependency); verify speed is unchanged (bench median 20.2–21.2 ms against 21.5 ms). SHA-256 compresses and finalizes in place; HMAC's inner digest is zeroizing; tree seeds and `rnd` are written into their final buffers; `evaluate` returns zeroizing vectors at final size; `read_seed` decodes into a caller-owned buffer. Profile `cli` (release + `panic = "abort"`) builds the tools; the library keeps unwind. The verifier-only library now depends on `keccak` and `zeroize` only. | `78f2a5f` |
| 2 Publishing (Medium) | Temporary file next to the output, write, `sync_all`, close, then a no-replace rename: `renameat2(RENAME_NOREPLACE)` (fallback link + unlink), link + unlink on other Unix, `MoveFileExW(MOVEFILE_WRITE_THROUGH)` without `MOVEFILE_REPLACE_EXISTING` on Windows; the directory is synced. On failure the temporary file is removed, or the error names it. | `2f0154e` |
| 5 Crash dumps | Before reading: Linux `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0`; Windows `SetErrorMode`, `WerAddExcludedApplication` (current user, persistent), an unhandled-exception filter and a panic hook that call `TerminateProcess` (abort's `__fastfail` would go to WER). Failure: exit 1, nothing read. Not covered (README): another `__fastfail` relies on the WER exclusion alone; LocalDumps were not checked on Windows; a same-user process can read memory while the tool runs. | `2f0154e` |
| 6 `--require-mlock` | Linux: `mlockall(MCL_CURRENT \| MCL_FUTURE)` before reading, after checking `RLIMIT_MEMLOCK` ≥ 128 MiB or root (peak RSS 17 MB); failure exits 1, nothing read (checked as `nobody` with `ulimit -l 1024`). Elsewhere a usage error. | `2f0154e` |
| 8 Tests (Low) | Feature `fault-injection` (`VOLEITH_FAULT`): random source, write, sync, naming and removal failures, a fixed ρ, a panic inside `prove`. `tests/cli.rs` scans stdout, stderr and every file of the working directory (TMPDIR inside it) for each 8-byte fragment of seed and ρ: raw, hex either case, decimal lists, u64 decimal, base64 (both alphabets, every alignment), with a positive-control test of the scanner. With `--profile cli` and `VOLEITH_TEST_EXPECT_ABORT=1` the panic must abort (SIGABRT). `check-verifier-only.sh` checks 16 patterns one by one, each with a positive control; this caught a test-binary lookup that had returned nothing, so those checks had passed vacuously. | `2f0154e`, `22a219a` |
| 4 Windows build (Medium) | cargo runs under `env -i` (`RUSTUP_TOOLCHAIN=1.97.0`, `LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH=0`, proxies and CA files only); refuses unless rustc is 1.97.0 at `2d8144b78` with the target, the four mingw-w64 packages have the recorded versions, and no `.cargo/config(.toml)` exists above the build directory or in CARGO_HOME; linker `x86_64-w64-mingw32-gcc-win32`. | `f720897` |
| 7 README | The seed is piped from the restore step (GnuPG example, `cmd.exe`); a file only for the public test seed of vector 0. "What stays private" says what is and is not cleared. | `4c20631` |

**Windows build** (Ubuntu 24.04; `gcc-mingw-w64-x86-64-win32` and
`gcc-mingw-w64-base` 13.2.0-6ubuntu1+26.1, `binutils-mingw-w64-x86-64`
2.41.90.20240122-1ubuntu1+11.4, `mingw-w64-x86-64-dev` 11.0.1-3build1;
rustup 1.97.0 with `x86_64-pc-windows-gnu`; profile `cli`). These replace
the hashes above:

| file | SHA-256 |
|---|---|
| `voleith-prove.exe` | `ca4eb060023d917d4d82008311097e200abbf87a8228e9120b71c58103a295c8` |
| `voleith-verify.exe` | `3abe78fb6d6497eac73bac56e829106bd422d658e73a62f324e4dcfc1f15f5e4` |

The two builds of each run were identical. Three runs gave these hashes:
one with `RUSTFLAGS`, `CARGO_PROFILE_CLI_OPT_LEVEL`, `CARGO_BUILD_JOBS`,
`RUSTUP_TOOLCHAIN=nightly`, `CC`, `LC_ALL` and `TZ` set in the calling
shell, one in a clean shell, and one from a checkout at another path. A
`.cargo/config.toml` above that checkout made the script refuse.

Under wine 9.0, the README's trial run (test seed from a CRLF file)
printed vector 0's y. The proof is `valid` for `voleith-verify.exe` and
for the Rust, Python and Go commands. An existing output file gives
exit 1 with nothing overwritten; `--suffix 4294967296`,
`--require-mlock` and a bad seed give exit 2. A fault-injection build's
panic ended with exit code 3 from `TerminateProcess`.
`WerAddExcludedApplication` returned success, but wine showed no registry
entry, so its effect is unverified. Nothing has been run on Windows
itself.

Checks (as before; `ff4ea00` → this round):

| Check | Before | After |
|---|---|---|
| Python unittest | 81 OK | 81 OK |
| `cargo test --release`, `cargo test` | 40 passed, 2 ignored | 41 passed, 2 ignored (lib 25: the sponge test) |
| `cargo test --release --no-default-features` | 31 passed | 32 passed |
| `cargo test --release --features cli` | 50 passed, 2 ignored | 55 passed, 2 ignored (bins 4 + 4, cli 6) |
| `cargo test --features fault-injection` | — | 56 passed, 2 ignored (cli 7) |
| `VOLEITH_TEST_EXPECT_ABORT=1 cargo test --profile cli --features fault-injection --test cli --bins` | — | 15 passed; the injected panic aborts |
| clippy `-D warnings` | clean (3 configurations) | clean: the 3, plus `x86_64-pc-windows-gnu` with `cli` and with `fault-injection` |
| `cargo fmt --check`, `go vet`, `gofmt -l` | clean | clean |
| `go test ./...` | 17 pass (24 subtests), 1 skip | 17 pass (24 subtests), 1 skip |
| fuzz, `run_campaign.sh 120` | 5,837 + 5,406, 14,274, 16,547 | 5,871 + 6,079, 12,328, 16,788; no crash or artifact; 1 input flagged slow (66.6 ms against 33.0 ms), no `SLOW` line when replayed 20 times on an idle core |
| `bash crosscheck/run.sh` | 800, 0 mismatches | 800, 0 mismatches |
| `bash crosscheck/cli.sh` | 58 cases, 0 mismatches | 62 cases, 0 mismatches |
| `bash rust/check-verifier-only.sh` | OK | OK, 16 patterns: 0 in 4 verifier-only builds, each ≥ 1 in its control |
| native-static-libs | `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc` | the same |

### Review round 2 (2026-10-23)

A read-only review of the round-1 fixes up to `63e2570`. It found the
sponge itself correct: rate 136, the 0x1f/0x80 padding, lane order,
little-endian bytes, and the fast and slow paths. The reviewer also
transcribed it to Python and matched hashlib on 9,430 cases. SPEC.md,
the vector files and every proof are unchanged.

| Item | Change | Commit |
|---|---|---|
| 1 Xof state (Medium) | Type states instead of `debug_assert!`: `Xof` absorbs, `finalize_xof(self)` consumes it and returns an `XofReader` that only reads; misuse no longer compiles in any build. The state is in a `Box`, so passing either type by value moves a pointer. Same bytes (vector and differential tests) and speed (verify median 20.4–20.8 ms). New test: many small reads, crossing the 136-byte boundary at every offset, equal one large read. | `94fc7b6` |
| 2 `prctl` (Medium) | Arguments passed as `libc::c_ulong`; a unit test reads back `PR_GET_DUMPABLE` = 0 and `RLIMIT_CORE` = 0/0. | `6838470` |
| 3 Fault injection (Medium) | A `fault-injection` build refuses to run (exit 1, message, nothing read) unless `VOLEITH_ALLOW_FAULT_INJECTION=tests`; tested without it and with four wrong values. `build-windows.sh` builds `--features cli` only and fails if a binary carries the refusal's marker string; the README says never `--all-features`. | `848d314` |
| 6 Windows fault test (Low) | The injected panic is asserted per platform: exit code 3 on Windows, SIGABRT elsewhere with the `cli` profile. The cli tests, run as a Windows program under wine, pass (8 of 8; the 65,535-byte message case uses 16,000 bytes on Windows, where a command line holds 32,767 characters). | `c230258` |
| 4 Windows build tools (Medium) | Tools by absolute path (linker, `-Cdlltool`, host linker); each, and a link's target, must belong to its package (`dpkg -S`); their SHA-256 below. With strace, the script fails if build 1 ran anything else; this found the host `/usr/bin/ld`, now listed. `check-windows-shadowing.sh` puts stand-ins (links to `/bin/false`) for `cc`, `ld` and `x86_64-w64-mingw32-{gcc,gcc-win32,as,dlltool,ld}` first on PATH in a fresh `/tmp` directory, builds, compares with a normal build (same files) and removes the directory. | `97ce9a0` |
| 5 Hibernation (Medium) | README: `--require-mlock` keeps pages out of swap, not out of a hibernation image; the claim holds only with hibernation off or its image encrypted. On Windows the tool's pages can reach `pagefile.sys` and `hiberfil.sys` (`powercfg /hibernate off`, BitLocker). | `6fa7940` |

The type states of item 1 allocate the sponge on the heap (a `Box`) for
every hash call, a few thousand per proof; verify time was unchanged by
it: `prove_verify` bench median 20.4 and 20.8 ms in two runs (31
iterations each), against 20.2–21.2 ms with the stack sponge of round 1
and 21.5 ms with `sha3` before.

**This sandbox.** During item 4, stand-ins for `cc`, `ld` and
`x86_64-w64-mingw32-{gcc,gcc-win32,as,dlltool,ld}` were written into
`/root/.cargo/bin`, and they are still there: removing them needed a
permission nobody could give, and nothing outside `/home/user` and `/tmp`
was touched after that. `cc` and `ld` are mode 644; the five mingw ones
are executable scripts that exit 99. Every result after that, all of the
results below included, was produced with
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.cargo/bin`
(plus `/usr/local/go/bin` at the end for Go). With that PATH,
`command -v` finds `/usr/bin` for all seven names and the rustup proxies
for `cargo` and `rustc`. A strace of a host build showed rustc running
`/usr/bin/cc`. The Windows build calls its tools by absolute path in an
`env -i` environment and its strace check passed.

**Windows build** (environment as in round 1; profile `cli`, `--features
cli`). The two builds were identical, and the shadowing check gave the
same files. These replace the earlier hashes:

| file | SHA-256 |
|---|---|
| `voleith-prove.exe` | `4828a2054e7f4f71fb262970c343b6ac2fe98b33adbea7fba2601242d5f8a546` |
| `voleith-verify.exe` | `d67ceec30efb33f2fcbdedaef1a2f5d09c642a7753205815197ee9173a1663f8` |

The tools that ran:

| tool | package and version | SHA-256 |
|---|---|---|
| `/usr/bin/x86_64-w64-mingw32-gcc-win32` | gcc-mingw-w64-x86-64-win32 13.2.0-6ubuntu1+26.1 | `260b0d734871a82030aaaa446338cd1dd1a48efeec119a110c0379b73a7ce972` |
| `/usr/lib/gcc/x86_64-w64-mingw32/13-win32/collect2` | gcc-mingw-w64-x86-64-win32 13.2.0-6ubuntu1+26.1 | `7fa510def1a3ac0f64c33096760c2db0eb5c13e8cf1461c95b1407a95a640e75` |
| `/usr/bin/x86_64-w64-mingw32-ld` | binutils-mingw-w64-x86-64 2.41.90.20240122-1ubuntu1+11.4 | `24ae8dc9ce6a34df398a7ddff2ba4a7d159eb18e4c60dd8f1c06687461ce1daa` |
| `/usr/bin/x86_64-w64-mingw32-dlltool` | binutils-mingw-w64-x86-64 2.41.90.20240122-1ubuntu1+11.4 | `d6cec3d94ef17b5136b92d6c19632c8490134e4eb8400ca34a5ef1ffc389e9e6` |
| `/usr/bin/x86_64-w64-mingw32-as` | binutils-mingw-w64-x86-64 2.41.90.20240122-1ubuntu1+11.4 | `3fb8bf11d2646c1bf07dbcdbe2909fbc4da79f92e4c0f732a5c7a9e415958276` |
| `/usr/bin/x86_64-linux-gnu-gcc-13` (host) | gcc-13-x86-64-linux-gnu 13.3.0-6ubuntu2~24.04.1 | `1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26` |
| `/usr/libexec/gcc/x86_64-linux-gnu/13/collect2` (host) | gcc-13-x86-64-linux-gnu 13.3.0-6ubuntu2~24.04.1 | `4d1f341ae5b763b513258ee2812422a45e063c30a2f1924a0cf63d3699f3a158` |
| `/usr/bin/ld` → `x86_64-linux-gnu-ld.bfd` (host) | binutils / binutils-x86-64-linux-gnu 2.42-4ubuntu2.10 | `e9ceb054c12207970f2726dfc07e9a66b411602748628baf27399f02a9bbb31b` |

Under wine 9.0, the README trial run printed vector 0's y. The Windows,
Rust, Python and Go verify commands all said `valid`, and no temporary
file was left behind.

Checks (`63e2570` → this round):

| Check | Before | After |
|---|---|---|
| Python unittest | 81 OK | 81 OK |
| `cargo test --release`, `cargo test` | 41 passed, 2 ignored | 42 passed, 2 ignored (lib 26: split reads) |
| `cargo test --release --no-default-features` | 32 passed | 33 passed |
| `cargo test --release --features cli` | 55 passed, 2 ignored | 58 passed, 2 ignored (bins 5 + 5: dumpable) |
| `cargo test --features fault-injection` | 56 passed, 2 ignored | 60 passed, 2 ignored (cli 8: refusal) |
| `VOLEITH_TEST_EXPECT_ABORT=1 cargo test --profile cli --features fault-injection --test cli --bins` | 15 passed | 18 passed; the panic aborts |
| the same for `x86_64-pc-windows-gnu` under wine, dev and cli profiles | — | 16 passed each (bins 4 + 4, cli 8); the panic exits 3 |
| clippy `-D warnings` (5 configurations, two of them Windows) | clean | clean |
| `cargo fmt --check`, `go vet`, `gofmt -l` | clean | clean |
| `go test ./...` | 17 pass, 1 skip | 17 pass, 1 skip |
| fuzz, `run_campaign.sh 120` | 5,871 + 6,079, 12,328, 16,788 | 5,740 + 5,646, 10,281, 15,958; no crash, artifact or slow input |
| `bash crosscheck/run.sh` | 800, 0 mismatches | 800, 0 mismatches |
| `bash crosscheck/cli.sh` | 62, 0 mismatches | 62, 0 mismatches |
| `bash rust/check-verifier-only.sh` | OK | OK (16 patterns, each with its control) |
| `bash rust/build-windows.sh`, `bash rust/check-windows-shadowing.sh` | — | identical builds; strace check passed; shadowing OK |
| native-static-libs | `-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc` | the same |

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
   - Settled in v0.2 by 24 smaller trees (section "v0.2 tree split"). The
     options considered before: keep SHAKE256 and accept 45–80 ms; move the
     leaf expansion to multi-lane Keccak (AVX2 4-way) or TurboSHAKE256; or use
     AES-128-CTR for the expansion only.
   - The task preferred stdlib primitives and no AES; whichever we pick
     changes the vectors and needs a version bump.
   - Measured on 2026-10-14: about 113 ms, so 45–80 ms was optimistic, and
     smaller trees (τ ≈ 22) are a further option. See "Rust verifier".
6. **Encoding.** Is the argument of SPEC §7.7 sufficient? In particular, the
   `assert_add` lemma, and the rule that public values only change
   coefficients, never the instruction list.
7. **Proof size.** 130.2 kB per rescue at τ = 24 (v0.1: 87.5 kB at τ = 16),
   chosen so that the proof pays for its validation weight. Is that acceptable
   in the annex, or should a later version look at a FAEST v3-style BAVC to
   save bytes at the same verification cost?
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
