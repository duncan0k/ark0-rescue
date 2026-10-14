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

## Not done yet

- **Statement 2** (HKDF-SHA-512, desktop wallet). It needs SHA-512 gadgets, the
  degree-≤6 E3 encoding of R1 and a degree-d QuickSilver check, which v0.1
  does not have. R1 estimates the proof at about 296 kB.
- **Rust.** The prover and verifier crates of R1 §6, differential tests
  against `vectors/statement1-v0.1.json`, and fuzzing of the verifier.
  - The Rust code should be written from SPEC.md, not translated from Python,
    so that the two implementations check each other.
  - The circuit digest (SPEC §7.6) lets the Rust circuit builder be checked
    before any proof is made.
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
    fixed positions and 4 random ones).
- **Performance.** Nothing is optimised beyond what the Python tests need.

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
```

The package (`python/voleith`):

- `gf128`, `sym`, `bits`: field, tagged SHAKE256, bit strings;
- `vc`, `vole`, `unihash`: GGM trees, VOLE, hashes;
- `circuit`, `sha256_gadgets`, `sha256_ref`, `statements`: the constraint layer and statement 0x01;
- `proof`: prove and verify.
