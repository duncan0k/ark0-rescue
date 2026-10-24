# VOLEitH rescue proofs: specification v0.2, revision 3

Status: **v0.2 is fixed**: version byte `0x02` is the version that the Ark-0
signet rescue lane (M4-R1) verifies. v0.2, revision 3 (2026-10-24); revisions
change wording only, and any change to the protocol takes a new version byte
(§16). Nothing here has had an external cryptographic review. v0.2 replaces v0.1,
which was never deployed: the construction is the same, but the 128
challenge bits are spread over 24 GGM trees of mixed depth (8 trees of depth
6, then 16 of depth 5) instead of 16 trees of depth 8, because verification
with 16 trees was too slow for the rescue lane's validation weight (NOTES.md,
"v0.2 tree split").

Revision 1 changes wording only. The version byte stays `0x02`; tags,
parameters, the proof format and both vector files are unchanged. It adds
the preconditions the consensus layer must enforce (§12.1), restates the
assumptions (§13.1), and adds argument sketches and missing terms to §13,
each marked as argued, not proven.

**Reviews.** Two internal reviews of v0.2 (commit `0623179`) by AI models,
not by external cryptographers, on 2026-10-14. gpt-6-astra (xhigh):
**REVISE**; it found no forgery and no malleability of the proof encoding,
and asked for the rescue-lane preconditions, a prover API that does not
return secrets, and smaller fixes. Fable 5.1 (max): **PROCEED**; it found no
construction defect, and asked for the same preconditions and for the
bookkeeping and lemmas of §13 before v0.2 is frozen. NOTES.md, "2026-10-14
internal reviews", lists every finding and what was done about it. No
external review has been done.

Revision 2 changes wording only. The version byte, tags, parameters, proof
format and both vector files of revision 1 are unchanged. It resolves 18
issues found by a clean-room implementation: a Go verifier written from
revision 1 and the vectors alone, which agrees with every vector
(`go/SPEC-ISSUES.md` on branch `cleanroom/go-verifier`). The vectors
contradicted none of the 18; each was an ambiguity, a gap or an internal
inconsistency of the text. Revision 2 adds a byte grammar and one emission
order for the circuit (§7.4, §7.6), per-gadget test circuits
(`vectors/gadgets-v0.2.json`), the verifier interface and what steps 1–6 may
read (§11), a symbol table (§1.1) and a description of the vector files
(Appendix A). §16 lists every change.

Revision 3 changes wording only, after a review of the final version (below).
The version byte, tags, parameters, proof format and all vector files are
unchanged. It describes the Rust prover as it now is (§13.3, §14), splits
§12.1 item 4 into what the node enforces and what wallets and operators must
do, tightens the bookkeeping of §13.1, §13.2, §13.4 and §13.5, and states that
`0x02` is fixed (§16).

**Review of the final version.** On 2026-10-24 the same two AI models, again
not external cryptographers, reviewed revision 2 with the Rust verifier and
the M4-R1 consensus rules. gpt-6-astra (xhigh): **NOT-YET**, on one point: the
consensus rules do not make a rescue depend on the freeze being in force,
which the M4-R1 design chose deliberately (§12.1 item 4). Fable 5.1 (max):
**SHIP**, on condition that the fixes to the text ship with the lane, which
runs only on a signet whose coins have no value and says it has had no
external review. Neither found a forgery, a malleability of the proof encoding
or a way around the consensus rules; astra's point is a rule it finds missing,
not a way around one. Fable 5.1 then checked revision 3 itself (SHIP); its
wording fixes are in this revision. NOTES.md, "2026-10-24 review of the final
version", lists every finding and what was done about it.

This document specifies a non-interactive zero-knowledge proof of knowledge,
used as a signature of knowledge on a public message, for the signet rescue
lane. It follows the FAEST v1.1 VOLE-in-the-head (VOLEitH) skeleton with the
AES-independent hardening of FAEST v3.0, replaces the AES relation by a generic
Boolean constraint layer, and defines one statement:

> **Statement 0x01.** The prover knows a 32-byte seed `x` such that
> `HMAC-SHA256(K, x ‖ suffix) = y`, for public `K`, `suffix` and `y`.

This text and the vector files of Appendix A define the protocol. An
implementation needs nothing else. The Python package in `python/voleith` is
the reference implementation. Where this text and the reference disagree,
that is a bug in one of them, and the vectors pin the intended behaviour.
References to `NOTES.md` (measurements, history) and to code are informative;
no conformance requirement depends on them.

Sources: the project's plan for this proof system (R1) and the rescue-lane
interface of its M4 design (requirements 4R-1 to 4R-9), neither of which is
published; §12 restates what this text needs from them. The rescue lane itself
is specified by the M4-R1 patches of bitcoin-p2mr-patches
(`doc/p2mr-rescue.md`). External references are listed in §17.

## Contents

1. Conventions
2. Parameters
3. Primitives and domain separation
4. All-but-one vector commitment
5. VOLE construction and consistency check
6. Constraint check (QuickSilver)
7. Constraint layer and circuits
8. Fiat–Shamir transcript
9. Prover
10. Proof format and size
11. Verifier
12. Use in the rescue lane
13. Security
14. Known limitations
15. Deviations from FAEST and from the R1 plan
16. Versioning
17. References

Appendix A. Vector files

## 1. Conventions

### 1.1 Notation

- `‖` is byte-string concatenation. `[a, b)` is the half-open integer range.
- `u8(v)`, `u16le(v)`, `u32le(v)`, `u64le(v)` encode an unsigned integer in 1, 2,
  4 or 8 bytes, little-endian.
- `⊕` is XOR of bit strings or addition in GF(2^128); `·` is multiplication in
  GF(2) or GF(2^128) as the context requires.
- `λ = 128`; `τ = 24` trees; tree `i` has depth `k_i` and `N_i = 2^{k_i}` leaves (§2).
- `ℓ` is the number of witness bits of a statement and `ℓ̂ = ℓ + 3λ` the VOLE
  length (§5).

Some letters have more than one meaning; the section in which a symbol
appears fixes its meaning:

| symbol | meanings |
|---|---|
| `s`, `t` | VH keys from `chall1` (§5.4); ZKH keys from `chall2` (§6.3). `t` is also the constraint index (§6.2, §7.2) and the schedule and round index of `compress` (§7.4) |
| `r` | root seed (§8); row index (§5.3). `r_i` are tree roots (§4.1), `r_{i,j}` leaf expansions (§5.1), `r0`, `r1` ZKH keys (§6.3) |
| `c` | `c_i` VOLE corrections (§5.3); third wire of a constraint `a·b = c` (§6.2); `c[i]` carries (§7.4); a state word of `compress` (§7.4) |
| `d` | masked witness (§6.1); GGM depth index (§4.3); a state word of `compress` (§7.4); Schnorr secret key (§12.1) |
| `w` | extended witness (§6.1, §7.2); a wire in `β_w`, `v_w`, `q_w` (§6.2); a word index (§7.4, §7.5) |
| `C` | number of constraints (§6.3, §7.2); `C(τ,2)` is a binomial coefficient (§5.4, §13.2) |
| `S` | number of secret inputs (§7.1); a set of trees (§13.2) |
| `P` | number of public inputs (§7.1); the x-only output key (§12.1); a number of machines (§13.6) |
| `Q` | verifier's VOLE columns `Q_j` (§5.3); random-oracle query counts (§13.2) |
| `K` | HMAC key (§7.5); `K_t` SHA-256 round constants (§7.4) |
| `m` | the message (§3.2, §8, §11); the index of a MUL in `w[S+m]` (§7.2) |
| `n` | a length in bits (§1.2); a GGM node index (§3.2, §4); a rotation (§7.4); the instruction count (§7.6); the secp256k1 group order (§12.1) |

### 1.2 Bit strings

A bit string `b[0..n)` is identified with the non-negative integer
`Σ b[i]·2^i`. Its byte encoding `enc_n(b)` has `⌈n/8⌉` bytes; bit `i` is bit
`i mod 8` (least significant first) of byte `⌊i/8⌋`. If `n` is not a multiple of
8, the unused high bits of the last byte are **padding bits and must be zero**;
a decoder of a proof field rejects any non-zero padding bit (§11 step 6).

Taking "the first `n` bits" of a hash output means reading it in this bit
order and discarding the bits at positions `≥ n`. No padding check applies
to a hash output.

### 1.3 The field GF(2^128)

`GF(2^128) = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)`. An element
`Σ_{i<128} a_i X^i` is the 128-bit string `a` (bit `i` = coefficient of `X^i`),
encoded in 16 bytes per §1.2 (byte 0 holds `X^0..X^7`). This is FAEST's
`P_128` with its little-endian `ToField` order [F30 §3], and GHASH's polynomial,
but **not** GHASH's reflected bit order.

Reduction: `X^128 ≡ X^7 + X^2 + X + 1`.

## 2. Parameters

| Symbol | Value | Meaning |
|---|---|---|
| version byte | `0x02` | protocol version v0.2 (§16) |
| `λ` | 128 | security parameter, field size, seed size in bits |
| `τ` | 24 | number of GGM trees (small VOLE instances) |
| `τ0`, `k0` | 8, 6 | the first `τ0` trees have depth `k0 = ⌈λ/τ⌉` |
| `τ1`, `k1` | 16, 5 | the other `τ1 = τ − τ0` trees have depth `k1 = ⌊λ/τ⌋`; `τ0 = λ mod τ` |
| `k_i`, `N_i` | | depth of tree `i` (`k0` if `i < τ0`, else `k1`) and its `N_i = 2^{k_i}` leaves; `Σ_i k_i = τ0·k0 + τ1·k1 = λ` |
| VOLE rows | `ℓ̂ = ℓ + 128 + 256` | witness rows, QuickSilver mask rows, consistency-hash mask rows |
| `ρ` | 32 bytes | hedging randomness per proof |
| grinding | none | |
| max message | 65,535 bytes | |

This is the only parameter set of v0.2. The split rule is FAEST v1.1's
(e.g. FAEST-128s: `τ = 11`, 7 trees of depth 12 and 4 of depth 11) applied to
`τ = 24`; `τ` was chosen by measured verification cost (NOTES.md, "v0.2 tree
split"). v0.1 used R1's `τ = 16`, `k = 8`; no grinding in either. For statement
0x01, `ℓ = 42,071` and `C = 42,071` constraints (§7.5).

## 3. Primitives and domain separation

### 3.1 Tagged SHAKE256

Every hash, PRG and random-oracle call is

```
SHAKE256[name](data, L) = SHAKE256( u8(|tag|) ‖ tag ‖ data , L bytes ),
tag = ASCII "VOLEitH-rescue/v0.2/" ‖ name
```

The tag contains the protocol version, so a new version changes every call.
Within one name, `data` is a concatenation of fields whose lengths are fixed by
the protocol and the statement id, or that carry an explicit length prefix, so
each input encoding is injective.

### 3.2 All calls

| name | input `data` | output | role (FAEST analogue) |
|---|---|---|---|
| `mu` | `u8(0x02) ‖ u8(sid) ‖ u16le(\|pub\|) ‖ pub ‖ u64le(\|m\|) ‖ m` | 32 | message/statement digest μ (`H_2^0`) |
| `rnd` | `u16le(\|x\|) ‖ x ‖ μ ‖ ρ` | 32 | root seed `r` (bytes 0–15) and `iv_pre` (16–31) (`H_3`) |
| `iv` | `iv_pre ‖ μ` | 16 | IV of this proof (v3 `H_4`) |
| `root` | `iv ‖ r` | `16τ` = 384 | tree roots `r_0..r_23`, 16 bytes each (PRG) |
| `ggm` | `iv ‖ u8(i) ‖ u16le(n) ‖ seed_n` | 32 | children of GGM node `n` of tree `i` (PRG) |
| `leaf` | `iv ‖ u8(i) ‖ u16le(N_i+j) ‖ seed_{N_i+j}` | 48 | `sd_{i,j}` (16) ‖ `com_{i,j}` (32) (`H_0`) |
| `exp` | `iv ‖ u8(i) ‖ u16le(N_i+j) ‖ sd_{i,j}` | `⌈ℓ̂/8⌉` | leaf expansion `r_{i,j}` (PRG) |
| `tree` | `iv ‖ u8(i) ‖ com_{i,0} ‖ … ‖ com_{i,N_i−1}` | 32 | tree commitment `h_i` (`H_1`) |
| `hcom` | `h_0 ‖ … ‖ h_23` | 32 | VOLE commitment `hcom` (`H_1`) |
| `ch1` | `μ ‖ hcom ‖ enc(c_1) ‖ … ‖ enc(c_23) ‖ iv_pre` | 32 | `chall1` (`H_2^1`) |
| `hv` | `Ṽ_0 ‖ … ‖ Ṽ_127` | 32 | `h_V` (`H_1`) |
| `ch2` | `chall1 ‖ ũ ‖ h_V ‖ enc(d)` | 64 | `chall2` (`H_2^2`) |
| `ch3` | `chall2 ‖ ã ‖ enc(b̃)` | 16 | `chall3` (`H_2^3`) |

`sid` is the statement id, `pub` the canonical public inputs, `m` the message,
`x` the witness. Seeds and IVs are 16 bytes. A field the proof carries
(`iv_pre`, `enc(c_i)`, `ũ`, `enc(d)`, `ã`) is hashed as its bytes in the
proof. `enc(b̃)` is the 16-byte encoding (§1.3) of the field element `b̃`.

### 3.3 Why SHAKE256 everywhere, and no AES

- FAEST uses AES-128-CTR as its PRG and SHAKE128 for λ = 128. This protocol
  is not byte-compatible with any FAEST version anyway (different relation,
  transcript and hashes), so nothing here requires AES for conformance.
- SHAKE256 is in the Python standard library and in RustCrypto (`sha3`), is
  naturally constant time, and needs no key schedule. One primitive, separated
  by tags, keeps the verifier small: no AES, no second field.
- The inputs carry the position, which gives the effect of FAEST v3's tweaked
  PRG: within a proof, no two `ggm`, `leaf` or `exp` calls with the same tag
  share the non-secret prefix `iv ‖ u8(i) ‖ u16le(n)` (a `leaf` and an `exp` call
  on the same leaf share this prefix but not the tag), the single `root` call has its own tag,
  and `iv` separates proofs. A seed guess therefore tests one target.
- **Cost.** The verifier expands `Σ_i (N_i − 1) = 1,000` leaves of
  `⌈ℓ̂/8⌉ = 5,307` bytes, about 5.3 MB of SHAKE256 output for statement 0x01
  (v0.1: 4,080 leaves, 21.7 MB). That still dominates verification (§14,
  NOTES.md). AES-NI would be several times faster.

## 4. All-but-one vector commitment

Each tree `i ∈ [0, τ)` is a GGM tree of depth `k_i` (§2) with `N_i = 2^{k_i}`
leaves and heap numbering: the root is node 1, the children of node `n` are `2n`
and `2n+1`, and leaf `j` is node `N_i + j`. Node indices are below `2^{k0+1}` and
fit the `u16le` fields.

### 4.1 Roots

`(r_0 ‖ … ‖ r_{τ−1}) = SHAKE256[root](iv ‖ r, 16τ)`.

### 4.2 Commit (prover)

```
seed_1 = r_i
for n = 1 .. N_i-1:                    (ascending)
    seed_{2n} ‖ seed_{2n+1} = SHAKE256[ggm](iv ‖ u8(i) ‖ u16le(n) ‖ seed_n, 32)
for j = 0 .. N_i-1:
    sd_{i,j} ‖ com_{i,j} = SHAKE256[leaf](iv ‖ u8(i) ‖ u16le(N_i+j) ‖ seed_{N_i+j}, 48)
h_i = SHAKE256[tree](iv ‖ u8(i) ‖ com_{i,0} ‖ … ‖ com_{i,N_i-1}, 32)
```

`sd_{i,j}` is 16 bytes, `com_{i,j}` 32 bytes. As in FAEST v1.1, each leaf key is
hashed into a seed and a commitment; the leaf commitments are **hash-based**,
not the PRG-based ones of FAEST v2/v3 (§15).

### 4.3 Open (prover)

For the hidden leaf `j*`, the path nodes are `p_d = (N_i + j*) >> (k_i − d)` for
depths `d = 1..k_i`, and the co-path nodes `s_d = p_d ⊕ 1`. The opening is

```
open_i = seed_{s_1} ‖ seed_{s_2} ‖ … ‖ seed_{s_{k_i}} ‖ com_{i,j*}      (k_i·16 + 32 bytes)
```

(co-path top-down, then the hidden leaf's commitment), as in FAEST v1.1 VC.Open:
128 bytes for depth 6, 112 for depth 5.

### 4.4 Reconstruct (verifier)

Given `open_i` and `j*`: set `seed_{s_d}` from the opening for `d = 1..k_i`; for
`n = 2..N_i-1` in ascending order, if `seed_n` is known, derive its children as in
§4.2. Every leaf except `j*` is now known. Compute `(sd_{i,j}, com_{i,j})` for
`j ≠ j*`, take `com_{i,j*}` from the opening, and recompute `h_i`. Path nodes and
the hidden leaf's seed are never known to the verifier.

## 5. VOLE construction and consistency check

### 5.1 Leaf expansion

`r_{i,j}` = the first `ℓ̂` bits (§1.2) of
`SHAKE256[exp](iv ‖ u8(i) ‖ u16le(N_i+j) ‖ sd_{i,j}, ⌈ℓ̂/8⌉)`.

### 5.2 ConvertToVOLE

Prover, for tree `i`, with `bit_b(j)` the bit `b` of the integer `j`:

```
u_i     = ⊕_{j ∈ [0,N_i)} r_{i,j}
v_{i,b} = ⊕_{j : bit_b(j) = 1} r_{i,j}               for b ∈ [0, k_i)
```

Verifier, knowing every `r_{i,j}` except `j* = δ_i` (§5.3):

```
q_{i,b} = ⊕_{j ≠ j*, bit_b(j ⊕ j*) = 1} r_{i,j}
```

Then `q_{i,b} = v_{i,b} ⊕ bit_b(δ_i)·u_i` [FAEST v1.1 Prop. 5]. Any algorithm
computing these sums (e.g. FAEST's divide-and-conquer) is conforming.

### 5.3 Corrections and the combined VOLE

`Δ ∈ GF(2^128)` is `chall3` (§8) read as a field element (§1.3); `Δ_j` denotes
its bit `j`, the coefficient of `X^j`, which is bit `j mod 8` of byte `⌊j/8⌋` of
`chall3`. **Challenge decoding** (FAEST's ChalDec): tree `i` uses the `k_i` bits of
`Δ` starting at

```
o_i = Σ_{i' < i} k_{i'} = k0·i                    if i < τ0
                        = k0·τ0 + k1·(i − τ0)     otherwise
```

and its index is `δ_i = Σ_{b < k_i} Δ_{o_i+b}·2^b`, so `bit_b(δ_i) = Δ_{o_i+b}` and
`Δ_{o_i}` is the least significant bit of `δ_i`. The
ranges `[o_i, o_i + k_i)` partition `[0, 128)`. The hidden leaf of tree `i` is
`j* = δ_i`. For `τ = 24`, tree `i < 8` uses bits `[6i, 6i + 6)` and tree `i ≥ 8`
uses bits `[48 + 5(i − 8), 53 + 5(i − 8))`.

```
u   = u_0
c_i = u_0 ⊕ u_i                              for i ∈ [1, τ)     (sent in the proof)
V_{o_i+b} = v_{i,b}                          (prover, column o_i+b, b < k_i)
Q_{o_i+b} = q_{i,b} ⊕ Δ_{o_i+b}·c_i  (i ≥ 1),  Q_b = q_{0,b}     (verifier)
```

For an honest prover `Q_j = V_j ⊕ Δ_j·u` for every column `j ∈ [0,128)`.

**Row view.** For a row `r ∈ [0, ℓ̂)`, `v[r] = Σ_j V_j[r]·X^j` and
`q[r] = Σ_j Q_j[r]·X^j` are field elements, and `q[r] = v[r] ⊕ u[r]·Δ`: a subfield
VOLE with `u[r] ∈ GF(2)`. Rows are allocated:

| rows | use |
|---|---|
| `[0, ℓ)` | witness masks |
| `[ℓ, ℓ+128)` | QuickSilver mask `u* = Σ_{i<128} u[ℓ+i]·X^i` (§6) |
| `[ℓ+128, ℓ+384)` | consistency-hash mask (§5.4) |

### 5.4 VOLE consistency check (VOLEHash)

Keys: `s = chall1[0..16)`, `t = chall1[16..32)` as field elements.

For a bit string `x` of length `ℓ̂`, let `x0 = x[0..ℓ+128)` and
`x1 = x[ℓ+128..ℓ̂)` (256 bits). Zero-pad `x0` to `n_v = ⌈(ℓ+128)/128⌉` blocks of 128
bits, `y_0 .. y_{n_v−1}` (block `j` = bits `[128j, 128j+128)` of the padded `x0`;
the last block holds the final `ℓ+128 − 128(n_v−1)` bits of `x0` and zeros, never
bits of `x1`), and define

```
P_s(x0) = Σ_{j<n_v} y_j · s^(n_v − j)        (Horner: h = 0; for each j: h = (h ⊕ y_j)·s)
VH(x)   = enc( P_s(x0) ⊕ x1[0..128) ) ‖ enc( P_t(x0) ⊕ x1[128..256) )        (32 bytes)
```

`VH` is GF(2)-linear in `x`. Every exponent is ≥ 1, so for `x0 ≠ 0` and any
target `v`, `P_s(x0) = v` holds for at most `n_v` values of `s`: each half is
`(n_v/2^128)`-almost uniform, the pair (independent keys) is
`ε_v = (n_v/2^128)^2`-almost uniform, and appending the identity on `x1` makes it
`ε_v`-almost universal and hiding on `x0` [FAEST v1.1 Prop. 1–2]. For statement
0x01, `n_v = 330` and `ε_v ≤ 2^−239.2`.

**Both keys are load-bearing** (argued in the 2026-10-14 internal review, not
proven). One polynomial hash alone gives `n_v/2^128 ≈ 2^−119.6`, and the
`C(τ,2) = 276` factor of §13.2 would leave `2^−111.5` per query, short of the
128-bit target; the second, independent key brings the term to `2^−231.1`. A
later version must not drop either half to save work. The argument uses
these properties of `VH`, all of which must be kept: it is GF(2)-linear; each
half is `(n_v/2^128)`-almost uniform on `x0` (every exponent is ≥ 1); the keys
`s` and `t` are independent; the 256 bits of `x1` are a one-time pad on the
output, so `ũ = VH(u)` hides `u`; and it is applied to all `ℓ̂` rows, mask rows
included.

Prover: `ũ = VH(u)`, `Ṽ_j = VH(V_j)` for each column, and
`h_V = SHAKE256[hv](Ṽ_0 ‖ … ‖ Ṽ_127, 32)`.

Verifier: `Ṽ'_j = VH(Q_j) ⊕ Δ_j·ũ` (byte-wise XOR of `ũ` when `Δ_j = 1`) and
`h_V = SHAKE256[hv](Ṽ'_0 ‖ … ‖ Ṽ'_127, 32)`. `VH` is applied to `Q` after the
`c_i` corrections and before the witness correction of §6.1. The check is
implicit: a wrong `h_V` changes `chall2` and hence the final comparison.

This replaces FAEST v1.1's VOLEHash (§15).

## 6. Constraint check (QuickSilver)

### 6.1 Witness commitment

The extended witness `w ∈ {0,1}^ℓ` (§7) is committed by `d = w ⊕ u[0..ℓ)`,
sent in the proof. The verifier corrects, column-wise, `Q_j ← Q_j ⊕ Δ_j·d` on
rows `[0, ℓ)`; afterwards, for `r < ℓ`, the verifier's key of witness bit `r` is
`q[r] = v[r] ⊕ w[r]·Δ` and the prover's tag is `v[r]`.

### 6.2 Constraint terms

Every wire `w` of the circuit (§7) carries, at the prover, a bit `β_w` and a
tag `v_w` (zero for constant and public wires) and, at the verifier, a key
`q_w = v_w ⊕ β_w·Δ` (for constant and public wires the verifier knows `β_w` and
uses `q_w = β_w·Δ`). For constraint number `t`, `a·b = c` over wires `a, b, c`:

```
prover:   A0_t = v_a·v_b
          A1_t = β_a·v_b ⊕ β_b·v_a ⊕ v_c
verifier: B_t  = q_a·q_b ⊕ q_c·Δ
```

If `β_a·β_b = β_c` then `B_t = A0_t ⊕ A1_t·Δ`; otherwise `B_t` has the extra term
`Δ^2`.

### 6.3 ZKHash and the response

Keys: `r0, r1, s, t` = bytes `[0,16)`, `[16,32)`, `[32,48)`, `[48,64)` of `chall2`.
For field elements `x_0..x_{C−1}` and a mask `z`:

```
ZKH(x; z) = r0·Σ_{i<C} s^(C−1−i)·x_i ⊕ r1·Σ_{i<C} t^(C−1−i)·x_i ⊕ z
            (Horner: h = h' = 0; for i = 0..C−1: h = h·s ⊕ x_i, h' = h'·t ⊕ x_i;
             then ZKH = r0·h ⊕ r1·h' ⊕ z)
```

ZKH's Horner step multiplies before it adds, so `x_{C−1}` has exponent 0. VH's
step (§5.4) adds before it multiplies, so every exponent is ≥ 1.

This is FAEST v1.1's ZKHash with `t` a full field element instead of a 64-bit
one: `ε_zk ≤ 2^−128 + ((C−1)/2^128)^2` [FAEST v1.1 Lemma 2 with Prop. 2–3]. For
`C = 42,071`, `ε_zk ≤ 2^−128·(1 + 2^−97)`.

QuickSilver masks: `u* = Σ_{i<128} u[ℓ+i]·X^i`, `v* = Σ_{i<128} X^i·v[ℓ+i]`,
`q* = Σ_{i<128} X^i·q[ℓ+i] = v* ⊕ u*·Δ`.

```
prover:   ã = ZKH(A1; u*),   b̃ = ZKH(A0; v*)                  (ã is sent, b̃ is not)
verifier: q̃ = ZKH(B; q*),    b̃ = q̃ ⊕ ã·Δ
```

The verifier's `b̃` equals the prover's iff the combined check holds; it enters
`chall3`, which the verifier recomputes and compares (§11).

## 7. Constraint layer and circuits

### 7.1 Wires and kinds

A circuit is a straight-line program over wires. Wire ids:

- `0` and `1` are the constants 0 and 1 (kind CONST);
- `2 .. 2+P−1` are the public input bits (kind PUB);
- `2+P .. 2+P+S−1` are the secret input bits (kind SEC);
- every emitted XOR, AND or NOT instruction creates the next wire id.

An output is SEC if any input is SEC, otherwise PUB. A SEC wire is an affine
function over GF(2) of the witness bits; its coefficients may depend on public
bits.

### 7.2 Instructions and folding rules

Instructions are XOR(a,b), AND(a,b), NOT(a) and ASSERT(a,b,c). A circuit is
produced by a builder that applies exactly these rules (constants are the wire
ids 0 and 1):

| call | rule |
|---|---|
| `XOR(a,b)` | both constant: return `a⊕b`. Exactly one constant `κ`, other wire `w`: return `w` if `κ = 0`, else return the result of the call `NOT(w)` below, which emits a NOT instruction (never `XOR(w,1)`). Otherwise emit `XOR(a,b)`. |
| `AND(a,b)` | both constant: return `a∧b`. Exactly one constant `κ`, other `w`: return `w` if `κ = 1`, else constant 0. Otherwise emit `AND(a,b)`. |
| `NOT(a)` | constant: return `1−a`. Otherwise emit `NOT(a)`. |
| `ASSERT(a,b,c)` | always emitted; no wire. |

Operands are recorded in the order of the call. Only the wire ids 0 and 1 are
folded; a call on PUB wires is emitted, although its value is public. So **the
instruction list depends only on the kinds of wires, never on public
values**; the witness layout and proof length are fixed per statement id.

- An emitted AND whose two inputs are SEC ("MUL") is the only non-linear gate:
  its output is the next witness bit and it carries the constraint
  `a·b = out`.
- ASSERT(a,b,c) carries the constraint `a·b = c`. A linear constraint
  `L = 0` is written ASSERT(L, 1, 0).
- Witness: `w[0..S)` are the secret inputs; `w[S+m]` is the output of the
  `m`-th MUL. `ℓ = S + #MUL`.
- Constraints, numbered `t = 0..C−1`, are the MULs and ASSERTs **in instruction
  order**. `C = #MUL + #ASSERT`.

All constraints have degree 2 (the E1 encoding of R1).

### 7.3 Evaluation

- Clear: XOR is `⊕`, AND is `∧`, NOT is `⊕1`; ASSERT checks `β_a·β_b = β_c`.
  The prover obtains `w` this way and must refuse if any ASSERT fails.
- Prover (tags): XOR adds bits and tags; NOT flips the bit; AND with a non-SEC
  input `p` gives `(p·β, p·v)`; a MUL takes its tag from the VOLE row; §6.2 gives
  the terms.
- Verifier (keys): XOR of two SEC wires adds keys; XOR of a SEC wire with a
  public bit `p` adds `p·Δ`; NOT of a SEC wire adds `Δ`; AND of a SEC wire with a
  public bit `p` multiplies the key by `p`; operations on non-SEC wires act on
  bits; a MUL with witness index `r` takes its key `q[r]` from the corrected VOLE.

### 7.4 SHA-256 gadgets

A word is a list of 32 wires, least significant bit first. `const_word`,
`rotr` and `shr` only select wires and emit nothing.

**Emission order.** Read the pseudo-code below as a sequential program; the
builder emits instructions in the order in which it makes the builder calls
of §7.2:

1. Statements and loops run in the order written, each loop over its range
   in ascending order.
2. A gadget defined per bit (`[i] = …`) is a loop over `i` from 0 to 31.
3. The arguments of a call are evaluated left to right, each completely,
   before the call itself.

A call that folds (§7.2) emits nothing. For example:

- The inner `xor_w` of `Σ0` emits all 32 XORs before the outer `xor_w`
  emits any.
- `Ch` makes the calls `XOR(f[i],g[i])`, `AND` and the outer `XOR` of bit
  `i` before any call of bit `i+1`.
- `add` makes, for bit `i`, the two XOR calls of `s[i]` and then the four
  calls of the next carry.
- `assert_add` makes the calls of all 32 `c[i]`, then `ASSERT(c[0], 1, 0)`,
  then three XOR calls and one ASSERT per bit.
- `compress` emits the whole message schedule before round 0, and within
  `W[t]` all of `σ1(W[t−2])` before `σ0(W[t−15])`.

```
const_word(v)[i] = wire (v >> i) & 1
rotr(w, n)[i]    = w[(i+n) mod 32]
shr(w, n)[i]     = w[i+n] if i+n < 32 else constant 0
xor_w(x, y)[i]   = XOR(x[i], y[i])
Σ0(a) = xor_w(xor_w(rotr(a,2),  rotr(a,13)), rotr(a,22))
Σ1(e) = xor_w(xor_w(rotr(e,6),  rotr(e,11)), rotr(e,25))
σ0(x) = xor_w(xor_w(rotr(x,7),  rotr(x,18)), shr(x,3))
σ1(x) = xor_w(xor_w(rotr(x,17), rotr(x,19)), shr(x,10))

Ch(e,f,g)[i]  = XOR(g[i], AND(e[i], XOR(f[i], g[i])))
Maj(x,y,z)[i] = XOR(AND(y[i], z[i]), AND(x[i], XOR(y[i], z[i])))
                    if x[i] is SEC and neither y[i] nor z[i] is SEC
              = XOR(AND(XOR(x[i], y[i]), XOR(x[i], z[i])), x[i])     otherwise

add(x, y):                      # ripple carry, one AND per carry bit
    c = constant 0
    for i in 0..31:
        s[i] = XOR(XOR(x[i], y[i]), c)
        if i < 31: c = XOR(AND(XOR(x[i], c), XOR(y[i], c)), c)
    return s

add_multi(words):
    order the words stably: those with no SEC wire first, then those with a SEC wire;
    drop words whose 32 wires are all constant 0;
    if none remain, return const_word(0)
    acc = the first remaining word                 # one word: returned, nothing emitted
    for each further remaining word v, in order: acc = add(acc, v)
    return acc

assert_add(x, y, z):            # x + y = z (mod 2^32), z without SEC wires
    for i in 0..31: c[i] = XOR(XOR(x[i], y[i]), z[i])
    ASSERT(c[0], 1, 0)
    for i in 0..30: ASSERT(XOR(x[i], c[i]), XOR(y[i], c[i]), XOR(c[i+1], c[i]))
```

The carry rule `c_{i+1} = ((x_i⊕c_i)∧(y_i⊕c_i)) ⊕ c_i = maj(x_i, y_i, c_i)` makes
an addition of two SEC words cost 31 MULs; a public addend saves the bit-0
carry (30 MULs), and a constant addend `κ` saves `1 + tz(κ)` carries. `assert_add`
uses the implied carries `c_i = x_i ⊕ y_i ⊕ z_i` and costs no witness bits
(§7.7).

```
compress(H, W, F = none):       # H: 8 words, W: 16 words, F: optional 8 non-SEC words
    for t in 16..63:
        W[t] = add_multi([σ1(W[t-2]), W[t-7], σ0(W[t-15]), W[t-16]])
    (a,b,c,d,e,f,g,h) = H
    for t in 0..63:
        s1 = Σ1(e);  ch = Ch(e,f,g)
        T1 = add_multi([h, s1, ch, const_word(K_t), W[t]])
        s0 = Σ0(a);  mj = Maj(a,b,c)
        T2 = add_multi([s0, mj])
        if F given and t ≥ 60:
            e' = F[4 + 63 − t];  a' = F[63 − t]
            assert_add(d, T1, e');  assert_add(T1, T2, a')
        else:
            e' = add_multi([d, T1]);  a' = add_multi([T1, T2])
        (h,g,f,e,d,c,b,a) = (g,f,e,e',c,b,a,a')
    if F given: return nothing
    return [add_multi([H[w], state[w]]) for w in 0..7]      # state = (a,b,c,d,e,f,g,h)
```

`K_t` are the FIPS 180-4 round constants. With `F` given, the circuit asserts
that the state after round 63, `(a_64, a_63, a_62, a_61, e_64, e_63, e_62, e_61)`,
equals `F`. From round 60 on, the asserted (public) words replace the computed
ones. `Σ0`, `Σ1`, `Ch` and `Maj` on public words then cost no MULs, but their
PUB instructions are emitted (§7.2).

**Standalone compression circuit** (for testing the generator): `P = 0`,
`S = 768`. Secret input `32j + i` (wire `2 + 32j + i`) is bit `i` of word `j`;
words 0–7 are the chaining value `H` and words 8–23 the block `W`. The circuit
is `compress(H, W)`, with 256 outputs: output `32w + i` is bit `i` of output
word `w`. A test that compares with native SHA-256 takes block word `j` as the
big-endian word of block bytes `[4j, 4j+4)` (FIPS 180-4). Counts:
**22,573 AND**, 111,607 XOR, 1,891 NOT. The AND count equals the Bristol Fashion
SHA-256 count that R1 verified.

### 7.5 Statement 0x01

**Public inputs (canonical encoding).**

```
pub = u8(|K|) ‖ K ‖ u8(suffix) ‖ y
```

with `1 ≤ |K| ≤ 64`, every byte of `K` in `0x20..0x7E` (printable ASCII), `y`
32 bytes; `|pub| = |K| + 34` exactly. Anything else is invalid.

**Witness.** `x`, 32 bytes. Witness bit `8n + b` is bit `b` of `x[n]`.

**Relation.** `HMAC-SHA256(K, x ‖ suffix) = y` (RFC 2104 with a key of at most
one block). Keys longer than 64 bytes are not supported.

**Public bits** (`P = 776`), computed natively by prover and verifier (by the
verifier only after step 6 of §11):

| bits | value |
|---|---|
| `[0, 256)` | `IV_in`: SHA-256 compression of `(K ‖ 0^{64−|K|}) ⊕ 0x36^64` from the standard IV; bit `32w + i` = bit `i` of word `w` |
| `[256, 512)` | `IV_out`: the same with `0x5c` |
| `[512, 768)` | `T`: `T_w = (y_w − IV_out_w) mod 2^32`, `y_w` the big-endian words of `y` |
| `[768, 776)` | `suffix`, bit `i` at `768 + i` |

**Circuit** (`P = 776`, `S = 256`):

```
X_j[i]  = secret bit 8·(4j + 3 − ⌊i/8⌋) + (i mod 8)          j ∈ [0,8)  (big-endian word j of x)
inner   = [X_0..X_7, W8, const_word(0) ×6, const_word(776)]
          W8[i] = constant 0 for i < 23, constant 1 for i = 23, suffix bit (i−24) for i ≥ 24
D       = compress(IV_in, inner)                               # inner digest, 8 SEC words
outer   = [D_0..D_7, const_word(0x80000000), const_word(0) ×6, const_word(768)]
compress(IV_out, outer, F = T)
```

The inner block is `x ‖ suffix ‖ 0x80 ‖ 0^22 ‖ be64(776)` and the outer block
`D ‖ 0x80 ‖ 0^23 ‖ be64(768)` (the 64-byte key block precedes each). Because
`y = IV_out + state` word-wise, `state = T`: the outer feed-forward and the last
four a/e additions cost no witness bits.

**How public inputs enter.** (1) `K` through the midstates `IV_in` and
`IV_out`, and `suffix` directly, all as PUB wires, i.e. as constants of the
affine forms; (2) `y` through `T` in the final `assert_add` constraints; (3) the
canonical encoding `pub` in `μ` (§8), on which every challenge depends. Public
values never change the instruction list (§7.2).

**Sizes** (pinned by the tests):

| quantity | value |
|---|---|
| MUL (AND of two secret wires) | 41,815 |
| other AND: secret × public (linear) / public × public | 255 / 830 |
| XOR / NOT | 211,450 / 3,857 |
| ASSERT | 256 |
| witness bits `ℓ = 256 + 41,815` | **42,071** |
| constraints `C = 41,815 + 256` | 42,071 |
| `ℓ̂ = ℓ + 384` | 42,455 |

### 7.6 Canonical serialization and digest

```
circuit = label ‖ u32le(P) ‖ u32le(S) ‖ u32le(n) ‖ instr_1 ‖ … ‖ instr_n
          ‖ u32le(n') ‖ u32le(o_1) ‖ … ‖ u32le(o_n')
label   = ASCII "VOLEitH-rescue circuit v0.1" ‖ 0x00        (28 bytes, no length prefix)
instr   = 0x01 ‖ u32le(a) ‖ u32le(b)                         XOR(a,b)       9 bytes
        | 0x02 ‖ u32le(a) ‖ u32le(b)                         AND(a,b)       9 bytes
        | 0x03 ‖ u32le(a)                                    NOT(a)         5 bytes
        | 0x04 ‖ u32le(a) ‖ u32le(b) ‖ u32le(c)              ASSERT(a,b,c) 13 bytes
```

- The opcode is one byte; each operand is a wire id in `u32le`.
- The instructions are the emitted ones, in emission order (§7.4), with
  operands in call order (§7.2). `n` counts them, ASSERTs included.
- A MUL is serialized as AND (`0x02`); kinds are not serialized.
- `o_1 … o_n'` are the output wire ids. A statement circuit has `n' = 0`.

SHA-256 of this byte string:

- statement 0x01 (no outputs):
  `5aadd73b39947a32f0eb217cf750ee280c3dadcd60b9ccccb09509892cf1435d`
- standalone compression circuit:
  `c0a978cb3bf40e83098fbf7b74226c557842bc09892598b66bdf3c7225c29114`

The label "circuit v0.1" is the version of the circuit layer, which v0.2 does
not change (§16).

An independent builder written from §7.2–§7.5 reproduced both digests and
every gate count (the clean-room verifier, §16).

**Per-gadget circuits.** `vectors/gadgets-v0.2.json` lists 20 small circuits
built from the gadgets of §7.4, so that a digest mismatch can be traced to
one gadget. Each entry gives `P`, `S`, the construction, the gate counts,
the serialization length and its SHA-256; entries of at most 2,048 bytes also
give the serialization in hex. Public word `Pj` is public inputs
`[32j, 32j+32)` and secret word `Sj` is secret inputs `[32j, 32j+32)`. The
outputs are the returned word's 32 wires, unless the entry says otherwise.
The circuits cover:

- `add` on SEC+SEC, SEC+PUB, PUB+SEC and SEC+constant;
- `add_multi` with SEC, PUB, zero and other constant words;
- `xor_w` with a constant (NOTs);
- `Ch` and `Maj` on SEC words, on mixed SEC and PUB words, and `Maj` with
  both forms in one word;
- `Σ0`, `Σ1`, `σ0`, `σ1` on a SEC word, and `Σ0` on a PUB word;
- `assert_add` with SEC+SEC=PUB and SEC+PUB=PUB;
- one full `compress` with a SEC chaining value and a PUB block.

`python/tools/gen_gadget_vectors.py` writes the file. The Python and Rust
tests rebuild every entry.

### 7.7 Encoding soundness

Claim: for every public `(K, suffix, y)`, the constraint system has a satisfying
witness iff some `x` satisfies the relation, and then the witness is
`(x, f(x))` for a fixed function `f`. Argument:

1. Every non-ASSERT instruction defines its output as a function of earlier
   wires; for a MUL the constraint `out = a·b` forces the witness bit to equal
   that function. So `w[S..ℓ)` is determined by `x`, and the computed wires are
   exactly the SHA-256 values.
2. `assert_add(x, y, z)` holds iff `x + y ≡ z (mod 2^32)`. (⇐) With the true carry
   sequence `κ`, `z_i = x_i ⊕ y_i ⊕ κ_i`, so `c_i = κ_i` and both constraint types
   hold. (⇒) `c_0 = 0` and `c_{i+1} = maj(x_i, y_i, c_i)` define the true carry
   sequence, so `z_i = x_i ⊕ y_i ⊕ κ_i` for all `i`.
3. Hence the asserts hold iff the state after round 63 of the outer compression
   equals `T`, i.e. iff `IV_out + state = y`, i.e. iff `HMAC(K, x ‖ suffix) = y`.

There are no selectors or branches, so the null-branch class of attacks
(ePrint 2026/2235, via R1 §1.4) has nothing to exploit.

Tests (`tests/test_gadgets.py`, `tests/test_statement1.py`):
- `add`: secret + secret and public + secret, all inputs, widths up to 6; the
  number of satisfying witness extensions is exactly 1 for widths up to 4;
  constant + secret checked for values and MUL counts at width 8.
- `assert_add`: holds iff the sum is right, all inputs, for (secret, secret,
  public) at widths 1, 2, 3, 5 and (secret, public, public) at widths 1, 3, 4.
- `add_multi`: one mixed configuration (order, dropped zero word).
- Ch and Maj: all 64 kind combinations of the three inputs, all values, exactly
  one satisfying witness, and the expected MUL count.
- Statement 0x01: single-bit mutations of the full witness (46 positions) are
  rejected; wrong `y`, `K`, `suffix` or `x` violate an ASSERT.

## 8. Fiat–Shamir transcript

All encodings are fixed; `enc` is §1.2 with the lengths `ℓ̂` (corrections) and
`ℓ` (`d`). The verifier hashes `enc(c_i)` and `enc(d)` exactly as they appear in
the proof, and must reject non-zero padding bits (§11 step 6) rather than mask
them: an implementation that masked the padding and then hashed re-encoded
values would accept several byte strings for one proof (malleable `wtxid`).

```
μ        = SHAKE256[mu](u8(0x02) ‖ u8(sid) ‖ u16le(|pub|) ‖ pub ‖ u64le(|m|) ‖ m, 32)
r‖iv_pre = SHAKE256[rnd](u16le(|x|) ‖ x ‖ μ ‖ ρ, 32)          (prover only)
iv       = SHAKE256[iv](iv_pre ‖ μ, 16)
hcom     = SHAKE256[hcom](h_0 ‖ … ‖ h_{τ−1}, 32)
chall1   = SHAKE256[ch1](μ ‖ hcom ‖ enc(c_1) ‖ … ‖ enc(c_{τ−1}) ‖ iv_pre, 32)
h_V      = SHAKE256[hv](Ṽ_0 ‖ … ‖ Ṽ_127, 32)
chall2   = SHAKE256[ch2](chall1 ‖ ũ ‖ h_V ‖ enc(d), 64)
chall3   = SHAKE256[ch3](chall2 ‖ ã ‖ enc(b̃), 16)
Δ        = chall3 as a field element; δ_i decoded from Δ (§5.3)
```

- Every challenge descends from μ, which binds the version byte, the statement
  id, the canonical public inputs and the message (length-prefixed). The tags
  bind the version label.
- `iv = H(iv_pre ‖ μ)` and `iv_pre ∈ chall1` are FAEST v3.0's fixes: the IV is
  bound to the message, and `iv_pre` (not `iv`) is hashed, which blocks
  malleability through IV collisions [FAEST v3.0 §1.1, Fig. 8.2].
- Hedging: `x` and μ enter `rnd`, so a failed `rng` degrades to deterministic
  proofs per `(x, μ)` rather than leaking `x`.

## 9. Prover

`prove(statement, x, m, rng)`, with `statement` as in §11, where `rng(n)`
returns `n` bytes and is called exactly once with `n = 32`:

1. Reject an unknown statement id, non-canonical public inputs, `m` not bytes
   or longer than 65,535 bytes, or `|x| ≠ 32`.
2. Refuse unless `HMAC-SHA256(K, x ‖ suffix) = y`; evaluate the circuit in the
   clear (§7.3) to get `w` and refuse if any ASSERT fails.
3. `μ`, `ρ = rng(32)`, `(r, iv_pre)`, `iv` (§8).
4. VOLE commitment: roots, `τ` trees (§4.2), leaf expansions (§5.1),
   `u_i, v_{i,b}` (§5.2), `u = u_0`, `c_i = u_0 ⊕ u_i`, columns `V`, `hcom`.
5. `chall1`; `ũ = VH(u)`; `h_V` over `VH(V_j)`; `d = w ⊕ u[0..ℓ)`; `chall2`.
6. Rows `v[r]` for `r < ℓ + 128`; terms `A0_t, A1_t` (§6.2); `u*`, `v*`;
   `ã = ZKH(A1; u*)`, `b̃ = ZKH(A0; v*)`; `chall3`.
7. `Δ = chall3`; for each tree, `open_i` at `j* = δ_i` (§4.3, §5.3).
8. Output the proof of §10.

The prover's secrets are `x`, `w`, `r`, all seeds, `u`, `V` and `ρ`.

## 10. Proof format and size

Fields in order (statement 0x01 offsets in bytes):

| offset | field | bytes | notes |
|---|---|---|---|
| 0 | version | 1 | `0x02` |
| 1 | statement id | 1 | `0x01` |
| 2 | `iv_pre` | 16 | |
| 18 | `enc(c_1) … enc(c_23)` | 23 × 5,307 | `⌈ℓ̂/8⌉` each; 1 padding bit each |
| 122,079 | `ũ` | 32 | |
| 122,111 | `enc(d)` | 5,259 | `⌈ℓ/8⌉`; 1 padding bit |
| 127,370 | `ã` | 16 | |
| 127,386 | `open_0 … open_23` | 8 × 128 + 16 × 112 | co-path seeds top-down (6 for trees 0–7, 5 after), then `com_{i,j*}` |
| 130,202 | `chall3` | 16 | |
| | **total** | **130,218** | |

General size formula (bytes):

```
|π| = 2 + λ/8 + (τ−1)·⌈(ℓ+3λ)/8⌉ + 2λ/8 + ⌈ℓ/8⌉ + λ/8 + Σ_i (k_i·λ/8 + 2λ/8) + λ/8
    = 2 + λ/8 + (τ−1)·⌈(ℓ+3λ)/8⌉ + 2λ/8 + ⌈ℓ/8⌉ + λ/8 + λ²/8 + τ·2λ/8 + λ/8
    = 2,130 + (τ−1)·⌈(ℓ+384)/8⌉ + ⌈ℓ/8⌉ + 32τ          (λ = 128; Σ_i k_i = λ)
```

The openings take `Σ_i (16·k_i + 32) = 2,048 + 32τ` bytes whatever the depths. For
statement 0x01 (`ℓ = 42,071`): `|π| = 2,082 + 5,339·τ`, i.e. `2,082 + 5,339·24 = 130,218`
bytes for `τ = 24` (v0.1, `τ = 16`: 87,506). Every
valid proof for a statement id has exactly this length; there is no other
encoding of the same proof.

`hcom`, `b̃` and the hidden seeds are not transmitted: the verifier recomputes
`hcom` and `b̃`, and the final `chall3` comparison covers both.

## 11. Verifier

`verify(statement, m, π) → bool`, where:

- `statement = (sid, pub)`: `sid` is the statement id, an integer, and `pub`
  is the byte string of public inputs in the encoding of §7.5, as received;
- `m` is the message and `π` the proof, both byte strings.

The verifier never takes parsed public inputs such as `(K, suffix, y)`: step 2
checks `pub`, and `μ` (§8) hashes `pub` as received. An `sid` outside
`[0, 255]` is not registered and fails step 1, so `u8(sid)` in `μ` is always
defined. An argument of the wrong type fails the step that checks it.

Return false at the first failed check:

1. `sid` is a registered id (only `0x01` in v0.2).
2. `pub` parses canonically (§7.5): first byte `L ∈ [1, 64]`, total length
   exactly `L + 34`, `K` bytes in `0x20..0x7E`.
3. `m` is a byte string of length ≤ 65,535.
4. `π` is a byte string of length exactly `|π|` for this statement id (130,218).
5. `π[0] = 0x02` and `π[1] = sid`.
6. Split `π` at the fixed offsets of §10. Decode each `enc(c_i)` and `enc(d)`;
   reject if any padding bit is non-zero. Steps 8–9 hash these bytes as
   received.
7. Compute `μ`, `iv`, `Δ = chall3`.
8. For each tree `i`: `j* = δ_i` (§5.3); reconstruct (§4.4) to get `h_i` and the
   seeds `sd_{i,j}`, `j ≠ j*`; expand them (§5.1); compute `q_{i,b}` (§5.2); form
   `Q` with the corrections (§5.3). Compute `hcom` and `chall1`.
9. `h_V` from `VH(Q_j) ⊕ Δ_j·ũ` (§5.4); `chall2`.
10. Correct `Q` with `d` (§6.1); compute rows `q[r]` for `r < ℓ + 128`; compute
    the public bits (§7.5); evaluate the circuit's keys (§7.3) to get `B_t`;
    `q*`; `q̃ = ZKH(B; q*)`; `b̃ = q̃ ⊕ ã·Δ`.
11. Recompute `chall3' = SHAKE256[ch3](chall2 ‖ ã ‖ enc(b̃), 16)` and return
    `chall3' == chall3`.

**Steps 1–6 depend only on `sid`, `pub`, the length of `m`, the length of
`π`, `π[0..2)` and the padding bits of each `enc(c_i)` and `enc(d)`.** No hash,
PRG, field or circuit work happens before all of steps 1–6 have passed. That
includes the native SHA-256 compressions of `K` and the subtraction that form
the public bits (§7.5). Step 10 lists them; an implementation may compute them
at any point after step 6.
Steps 1–5 may run in any order without changing the verdict; step 6 needs
the length that step 4 checked.

Every conforming verifier gives the expected verdict on every case of the two
proof vector files (Appendix A).

Properties:

- Steps 1–6 need only the fixed sizes of the statement id (§10), not its
  circuit. So a circuit that is built lazily is built after step 6, and a
  malformed input never pays for the build.
- The work after step 6 is bounded but not constant. Fixed work dominates it
  (about 5.3 MB of SHAKE256 output and the circuit's keys), and it varies
  with the bits of `Δ = chall3`: each set bit `Δ_j` adds a conditional XOR of
  `ũ` (step 9) and of `d` (step 10) and, outside tree 0, of a correction `c_i`
  (step 8). For `Δ = 2^128 − 1` (`chall3 = ff…ff`) that is 1,324,702 bytes of
  XOR. Measured, the median time of that input, of a valid proof over a
  65,535-byte message and of both together is within 0.9 ms (3%) of a valid
  proof's (NOTES.md, "2026-10-14 internal reviews").
- Every input that passes steps 1–6 costs a full verification before it can
  be rejected. Validation weight and relay policy must price a well-formed
  invalid proof like a valid one (§12.1).
- No step depends on secret data; there is no input on which the verifier
  must abort, loop or allocate a size taken from the proof. An implementation
  must treat any internal error as rejection.
- Every challenge value, including `Δ = 0`, is valid. With `Δ = 0` every key
  equals its tag (`Q = V`, `B_t = A0_t`), so a `b̃` computed from the tags
  passes for any `d`: the check then says nothing about the witness. This is
  not a hole. `Δ` is a random-oracle output, so a prover gets `Δ = 0` with
  probability `2^−128` per `ch3` query, and the `2^{1−λ}` term of §13.2 already
  counts every root of the final check, `Δ = 0` included. A special case that
  rejected `Δ = 0` would only reject honest proofs.

## 12. Use in the rescue lane

This section restates the rescue-lane interface (requirements 4R-1 to 4R-9 of
the M4 design) and lists what the consensus layer must enforce (§12.1). The
consensus rules themselves are those of the M4-R1 patches,
`doc/p2mr-rescue.md`.

- The proof is carried in the annex as one element, at most one proof per
  input (4R-3, 4R-9). Statement 0x01 proofs are 130,218 bytes (130,218 WU).
- `m = rescue sighash ‖ network id ‖ public-key commitment` (4R-6); the
  library treats `m` as opaque bytes. The rescue sighash
  (`key_version = 0x03`) omits `sha_annex`, so the proof never commits to
  itself; other signatures in the input commit to the full annex (4R-2, 4R-3).
- The statement id and public inputs come from the rescue token; the node
  checks the key relation natively (4R-7) and calls `verify(statement, m, π)`.
- 4R-6 requires that a proof can neither be moved to another transaction nor
  mauled into another valid proof. The first is a property of the sighash
  (§12.1 item 2); the second is argued in §13.4, not proven.

### 12.1 Preconditions the consensus layer must enforce

A valid proof shows only that its maker knew some `x` with
`HMAC-SHA256(K, x ‖ suffix) = y`, and binds that to `m`. None of the following
is a property of the proof system; if the rescue-lane rules miss one, coins
can be stolen however sound the proof is. They are hard requirements on the
M4-R design (from the 2026-10-14 internal reviews). The 2026-10-24 review
checked them against the M4-R1 rules: items 1–3 are consensus rules there,
and item 4 is partly relay policy and partly up to wallets and operators.
The node or the rescue adapter performs these checks, never
`verify`: `verify` performs exactly the checks of §11, so it accepts any
32-byte `y` and any `m` of up to 65,535 bytes.

1. **`y` is fixed by the spent output.** The node takes `y` from the rescue
   token and checks natively that `0 < y < n` (the secp256k1 group order) and
   that `x(y·G) = P`, the x-only key of the output being spent (4R-7). The
   spender has no other say in `y`: anyone can pick an `x` and compute a
   matching `y`.
2. **The rescue sighash is SIGHASH_ALL-type only.** It commits to every
   prevout (amounts and scripts), every input and output, and the index of
   the input being spent; ANYONECANPAY, NONE and SINGLE variants are invalid
   for rescue spends. The proof binds only `m`, so two transactions with the
   same `m` could swap proofs: that a proof cannot be moved to another
   transaction is the sighash's job.
3. **`m` is exactly 96 bytes**: rescue sighash (32) ‖ network id (32) ‖
   public-key commitment (32). The library accepts messages of up to 65,535
   bytes; the rescue adapter must accept only this form.
4. **Publishing `y = d` burns the key.** A rescue spend puts the Schnorr secret
   key `d` (`= y`) in the mempool and in a block, where classical observers
   see it too (a quantum attacker could derive `d` from `P` anyway). From then
   on, anyone can spend with `d` every output of `P` whose elliptic curve
   checks still work.
   - *The node's part (M4-R1).* The mempool takes a rescue spend only when
     the elliptic curve checks of leaf version `0xe0` are disabled for the
     next block and, over P2P, only from peers with `noban` permission
     (`sendrawtransaction` is not limited by this); a standard transaction
     holds at most three rescue inputs. The consensus rule itself does not
     depend on the freeze. In M4-R1 the freeze reaches the script interpreter
     as a restricting flag; a rescue conditioned on it would make that flag
     relax as well as restrict, against the rule that an added flag only ever
     makes fewer spends valid, and would make a rescue's validity depend on
     chain state beyond the block's height, the leaf and the transaction. Nor
     would such a rule help after a reorganization that undoes the freeze,
     when `d` is public and the checks work again. What it would prevent, a
     rescue that a block producer includes while the checks still work, is
     left to the operator: a block producer that includes a rescue
     transaction directly, outside the mempool, must check this itself, and
     on Ark-0 the lane is to open only once the freeze is in force (its height
     is not yet set). A rescue is safe only while no reorganization undoes the
     freeze; on a signet, only its block producer can make one.
   - *The wallet's and the operator's part, which the node cannot check.*
     Rescue all frozen outputs of a key together, in one transaction, so that
     none of them waits on the freeze rules alone while `d` is public. More
     than three need a transaction that a block producer includes directly,
     and a block holds about 30 rescue inputs (each carries about 130 kB of
     witness), so keep the outputs per key few. Before the first rescue, move
     by an ordinary spend every output that `P` can spend some other way (a
     leaf of version `0xc0`, a P2TR output with the same key, a legacy or
     witness v0 script): the freeze covers an output only where `P` is checked
     in a leaf of version `0xe0`, regardless of when the output was created.
     Never reuse `P` or `d` on other networks or protocols, and pay nothing
     more to `P` once it is burned.

Not preconditions of this specification, but for the same design:
validation weight and relay policy must price a well-formed invalid proof
like a valid one (§11), and slower validators need a safety factor or a
per-block or per-peer limit. M4-R1 charges 130,000 weight units per rescue
check, set from a single-check gate with a factor of 1.5 and a whole-block
gate (`doc/p2mr-rescue.md`).

## 13. Security

### 13.1 Model and assumptions

Revision 1 restates these assumptions after the 2026-10-14 internal
reviews; the restatement is argued, not proven.

- **Random oracles.** Every `SHAKE256[name]` is modelled as an independent
  random oracle (classical ROM). `rnd` may alternatively be modelled as a PRF
  keyed by `x` and `ρ`.
- **HMAC-SHA256 as a random function** (revision 3; a heuristic, used only for
  the multi-target accounting below). `K` is public and the secret `x` is in
  the message, so the PRF security of HMAC does not apply; the model is that
  of SHA-256's compression function as a random oracle, under which the
  values of one `x` for different `(K, suffix)` are independent. Knowledge
  soundness (§13.2) does not use it.
- **Knowledge soundness holds for every statement.** The extractor of §13.2
  works whatever `(K, suffix, y)` is and however it was chosen; a spender who
  picks `K` or `suffix` does not weaken it. (v0.2 assumed "honest keys" here
  and claimed nothing for adversarial statements; that assumption is needed
  only for the next item.)
- **Unforgeability reduces to a fixed-target preimage problem.** Making a
  valid proof without knowing a preimage reduces, through the extractor, to
  finding `x'` with `HMAC-SHA256(K, x' ‖ suffix) = y` for a `y` that the chain
  fixes (`x(y·G) = P` leaves only `d` and `n − d`; §12.1 item 1). The spender's
  choice of `(K, suffix)` changes the function, not the target. For `y` the
  HMAC output on a uniform 256-bit seed, that is a `2^256`-scale problem
  classically and `2^128` with Grover; with `N` target keys the loss is at most
  a factor `N`, irrelevant at 256 bits. The `N` targets may share a seed (one
  key per label and suffix): under the model above, the values for different
  `(K, suffix)` are independent, so the factor `N` covers that case too, and
  zero knowledge (§13.3) is what keeps a proof for one suffix from helping
  with another. The relation is length-preserving, so
  the extractor may return a different preimage; that suffices for the rescue
  lane, which needs knowledge of *a* preimage.
- **Seed entropy.** The above assumes a seed `x` with 256 bits of entropy.
  With `H(x)` bits, guessing `x` costs about `2^{H(x)}` classically and
  `2^{H(x)/2}` Grover iterations, so the lane's strength against a quantum
  attacker is about `min(2^64, 2^{H(x)/2})`, where `2^64` is Grover on `Δ` or on a
  hidden seed (§13.6). A wallet seed with less than 128 bits of entropy makes
  the lane weaker than the proof system.
- **External preconditions.** The consensus layer enforces §12.1 items 1–3
  and the node's part of item 4; wallets and operators do the rest of item 4.
  Without them nothing in §13 protects any coins.

### 13.2 Unforgeability (classical ROM, 128-bit target)

The target: no adversary that makes `Q` random-oracle queries produces a valid
proof for a fresh `(statement, m)` with probability much above `Q·2^−127`, apart
from inverting the one-way function.

By analogy with FAEST v1.1 Theorem 1 (EUF-KO) — straight-line extraction of the
leaf seeds from `leaf` queries, extraction of `w = d ⊕ u` from the queried
transcript, and round-by-round bad events — the bound becomes, with `Q_leaf`
queries to `leaf`, `Q_1` to `tree`/`hcom`/`hv` and `Q_{2,j}` to `ch_j`:

```
Adv_EUF-KO ≤ Q_H^2 / 2^257 + Q_H · T / 2^256           (collisions of 256-bit outputs; hits on fixed values)
           + Q_{2,1} · C(τ,2) · ε_v                     (VOLE consistency, ≤ 2^−231.1 per query)
           + Q_{2,2} · ε_zk                             (ZKHash, ≈ 2^−128 per query)
           + Q_{2,3} · 2^{1−λ}                           (QuickSilver final check, 2^−127 per query)
           + Q_{2,3} · 2^−λ                              (chall3 coincidence, 2^−128 per query)
           + Adv_OWF
```

with `Q_H = Q_leaf + Q_1 + Q_{2,1} + Q_{2,2}`, the queries to oracles whose
outputs have at least 256 bits.

- This is the form of the bound at the end of the proof of FAEST v1.1
  Theorem 1 (p. 71), which is sharper than the theorem statement's
  `Q_2·(ε_v + ε_zk + 2^−λ)`. Its terms are re-derived here, conservatively, for
  our hash families.
- **Revision 1** (2026-10-14 internal review; argued, not proven). The first
  term was `3·(Q_leaf + Q_1 + Q_2)^2/2^256`: the factor 3 had no derivation,
  and `Q_2` included `ch3`, whose 128-bit output has no useful collision. It
  became `Q_H^2/2^256`: at most `Q_H^2/2` pairs of outputs, each colliding with
  probability `2^−256`, with a factor 2 to spare for a query that hits a value
  fixed earlier in the transcript. The `chall3` term was new: the verifier
  compares `SHAKE256[ch3](chall2 ‖ ã ‖ enc(b̃'))` with the `chall3` in the
  proof, not `b̃'` with `b̃`, so a `ch3` query can also succeed when `b̃' ≠ b̃`
  and the 128-bit outputs coincide; revision 1 counted that as a fixed-point
  event, `2^−128` per query, dominated by the term above it.
- **Revision 3** (2026-10-24 review; argued, not proven). The pairs give
  `Q_H^2/2^257`, and a query that hits one of the `T` 256-bit values a proof
  fixes adds at most `Q_H·T/2^256`, with `T ≈ 1,050` (1,024 leaf commitments,
  24 `h_i`, `hcom` and `h_V`). Revision 1's `Q_H^2/2^256` covers both once
  `Q_H ≥ 2T`; below that the hit term is under `2^−234` anyway. Counted more
  precisely, the `chall3` event needs no term per query: a `ch3` query whose
  output closes the loop, with `Δ` taken from that same output, is the
  final-check event of the term above it, and what is left is the verifier's
  own fresh query matching `chall3`, `2^−λ` once per verification. The bound
  keeps the larger, conservative `Q_{2,3}·2^−λ`.
- The `C(τ,2)·ε_v` term is FAEST's Claim 1 (from BBD+23 Theorem 2, SoftSpokenVOLE
  with the repetition code over the τ trees). With `τ = 24`, `C(τ,2) = 276`
  (v0.1: 120), and `ε_v ≤ (330/2^128)^2` keeps the term at `2^−231.1` per query
  (v0.1: `2^−232.3`); FAEST v1.1 needed `B = 16` extra hash bits for the same factor.
  The exact source and form of the `C(τ,2)` factor in FAEST still need
  checking; the lemma sketch below derives it on its own terms, as a union
  bound over the pairs of trees whose `e_i` could collide under `VH`. At
  `ε_v ≈ 2^−239` any factor polynomial in `τ` is irrelevant.
- **What else depends on τ or the depths** (re-checked for v0.2):
  - The final-check term `2^{1−λ}`, the challenge space and brute force on `Δ`
    (§13.6) depend on `Σ_i k_i = λ = 128` only, which mixed depths keep.
  - A cheating prover can send inconsistent corrections for a set `S` of trees
    and hope the challenge hides them; that needs the `Σ_{i∈S} k_i` bits of `Δ`
    of those trees, and the other bits still bind the final check, so the total
    stays at the `2^{1−λ}` level. Smaller trees make one tree's bits easier to
    guess (`2^−5` instead of `2^−8`) without changing the total. This is the
    SoftSpokenVOLE argument behind FAEST v1.1 Theorem 1, whose parameter sets
    already mix depths (FAEST-128s: depths 12 and 11). The lemma sketch below
    makes it explicit for depths 6 and 5; an external reviewer should still
    confirm it.
  - The leaf-commitment and extraction terms count random-oracle queries, not
    leaves; a tree has fewer leaves (`N_i ≤ 64`) but every leaf is still bound
    by a 256-bit commitment.
  - Zero knowledge (§13.3) needs one hidden leaf per tree, unchanged.
- EUF-CMA follows FAEST v1.1 Theorem 2: signing queries are simulated by
  programming `ch1`, `ch2`, `ch3`; the added terms are PRG/PRF advantages of the
  tagged SHAKE256 calls and programming collisions bounded by the min-entropy of
  `hcom` (256 bits) and `iv_pre` (128 bits). These terms are named here, not
  derived, except the one from `iv_pre`'s 128 bits: with `q_s` proofs made by
  honest provers, every proof made counted (retries included), it is at most
  about `q_s·Q·2^−128`, a factor `q_s/2` above the EUF-KO target of `Q·2^−127`
  (the price of `λ = 128`). The rescue lane makes few proofs, about one per
  rescued output; up to `q_s = 2^12` the term is at most `Q·2^−116`.

**Lemma sketch: guessing part of `Δ`** (2026-10-14 internal review; argued,
not proven). Fix everything the prover commits to before `chall1`, let `u_i` be
tree `i`'s VOLE input as determined by its committed leaves, and let
`e_i = u_i ⊕ c_i ⊕ u_0` (`e_0 = 0`; an honest prover has every `e_i = 0`). For every
column `j` of tree `i`, `Q_j = V_j ⊕ Δ_j·(u_0 ⊕ e_i)`, so the verifier's
consistency values are `Ṽ'_j = VH(V_j) ⊕ Δ_j·(VH(u_0) ⊕ VH(e_i) ⊕ ũ)`. Suppose `VH`
has no collision on the `e_i`, which fails with probability at most
`C(τ,2)·ε_v`. Then the trees with `VH(e_i) = ũ ⊕ VH(u_0)` share one value `e*`,
and each column `j` of the other trees (the set `G`) pins `Δ_j` to the one
value `g_j` that matches the committed `h_V`: the consistency check passes
only on the affine sub-cube `{Δ : Δ_j = g_j for j ∈ G}`. On that sub-cube,
`Q = V' ⊕ Δ·u'` for every column, with `u' = u_0 ⊕ e*` (the `u` the extractor
uses) and `V'` known to the prover. The final check is then a polynomial of
degree at most 2 in `Δ`, fixed before `Δ` is drawn, with at most two roots in
the whole field, so it passes with probability at most `2·2^−128 = 2^{1−λ}`,
whatever `|G|` and whatever the depths (5 or 6). A bad leaf (a commitment
whose `leaf` query the extractor never saw) is usable only as the hidden
leaf, which pins that tree's `k_i` bits of `Δ`; the same argument covers it.

**This is a re-instantiation by analogy, not a proof.** The things that differ
from FAEST v1.1 and must be re-checked by a reviewer: the hash families of
§5.4 and §6.3, the degree-2 generic constraint layer (FAEST proves AES S-box
constraints of the same degree), `ℓ ≈ 2^15.4` and `C ≈ 2^15.4` instead of
`≤ 2^13`, the transcript of §8, and the multi-user setting (many statements;
the reduction to one-wayness loses at most the number of target statements, or
uses a multi-instance OWF assumption).

### 13.3 Zero knowledge (argued, not proven)

By analogy with FAEST v1.1 Theorem 2's games G6–G9, the interactive protocol
is honest-verifier zero knowledge and proofs can be simulated in the ROM: `u`
and the `c_i` are pseudorandom given the openings (one hidden leaf per tree;
Lemma 5, modelling `ggm`, `leaf` and `exp` as PRGs), `ũ` is masked by the 256
hash-mask rows, `ã` by `u*`, and `d` by `u[0..ℓ)`; `b̃` is determined by the
rest. If this argument holds, an honestly generated proof reveals nothing
about `x` beyond the statement.

That is a property of the protocol, not of any code here. The two provers in
this repository differ (revision 3; revision 2 still called both test code):

- **The Python reference prover is test code.** It is not constant time (it
  indexes 64 KiB GF(2^128) tables, and 16-entry windows of the carry-less
  multiply, with secret values such as VOLE tags and ZKHash accumulators), and
  it does not zeroize secrets. Use it with test seeds only.
- **The Rust prover is written to be constant time and to clear its
  secrets**, as `rust/CT-AUDIT.md` claims and documents: constant-time
  GF(2^128) products, no branch or table index on secret data, zeroization of
  the secret buffers it allocates (the circuit's wire values included), and a
  best-effort stack scrub after each call. The audit's evidence is a code
  review and statistical timing tests on one machine; the gaps it states are
  registers, the path of a panic, the Keccak permutation's own temporaries
  and buffers that belong to the caller. No external review has checked it.

So the Rust prover may be used with test seeds and with seeds used on this
signet alone, never on another network or protocol (§12.1 item 4). A seed
that protects anything of value elsewhere needs a prover whose constant-time
claims have been reviewed (§14).

### 13.4 Strong unforgeability and non-malleability (argued, not proven)

Given a valid proof, producing a *different* valid proof for the same
`(statement, m)` without `x` should require a hash collision or second
preimage:

- the length is fixed, the header is checked and every padding bit must be zero;
- `iv_pre` and every `c_i` enter `chall1`; `ũ` and `d` enter `chall2`; `ã`
  enters `chall3`; `chall3` is compared;
- every opening byte determines leaf seeds or `com_{i,j*}`, hence `h_i`, `hcom`
  and `chall1`;
- `iv_pre` itself (not only `iv`) is hashed (FAEST v3.0's strong-unforgeability
  fix).

**Lemma sketch** (2026-10-14 internal review; argued, not proven). Let
`π ≠ π'` both be valid for the same `(sid, pub, m)`. If the inputs of `ch1`,
`ch2` and `ch3` are the same for both, then `iv_pre`, the `c_i`, `ũ`, `d`, `ã`,
`chall3` and `hcom` are equal, and openings that differ while giving the same
`h_i` need a 256-bit collision of `tree`, `leaf` or `ggm`; so `π' = π`.
Otherwise `π'` uses a fresh random-oracle input in some round, every later
challenge is fresh, and the simulation and straight-line extraction of FAEST
v1.1 Theorem 2 apply to `π'`. A `π'` that reuses some of `π`'s trees is
covered by the sub-cube lemma of §13.2: a reused tree pins its `k_i` bits of
`Δ'` to the bits `δ_i` of `π`'s `Δ` (otherwise `π`'s opening bytes rebuild a
different `h_i` under the new hidden leaf), and on that sub-cube the final
check is still a polynomial of degree at most 2 fixed before `Δ'` is drawn,
so it passes with probability at most `2^{1−λ}` per `ch3` query. (Revision 2
argued from `Δ' ≠ Δ` alone, which misses a partial reuse: one tree's hidden
leaf stays the same with probability `2^−k_i`, not `2^−128`.) Hence
`Adv_SUF-CMA ≤ Adv_EUF-CMA` plus collision terms of 256-bit outputs. Making this a proof needs a Fiat–Shamir simulation-extractability
result (NOTES.md, question 3); §12 does not rely on it as proven.

Moving a proof to another message or statement changes μ, hence every
challenge; moving it to another transaction with the same `m` is prevented by
the sighash (§12.1 item 2), not by the proof. The owner of `x` can always make
a different valid proof with a new `ρ`, so the `wtxid` of a rescue spend is
malleable by its owner; that is inherent to any randomised proof or
signature, and the consensus design must accept it. FAEST v3.0 likewise
claims only *conjectured* strong unforgeability; we claim no more.
Simulation extractability in the sense of 4R-6 is a reviewer question (§14,
NOTES.md).

### 13.5 QROM

**Only conjectured.** FAEST v1.1 §10.1.3 gives a non-tight QROM argument that
rests on a conjecture about extracting hash-based VOLE commitments in the QROM
(its Conjecture 1). FAEST v3.0's QROM proof does not transfer: it uses PRG-based
leaf commitments and switches the public key to one without a preimage, which
needs a one-way function with domain smaller than codomain. Statement 0x01 is
length-preserving (about `1/e` of outputs have no preimage only heuristically)
and statement 2 always has preimages (R1 §5.2). We claim no QROM bound.
FAEST v3.0's classical proof takes the same key-switching route, which is why
§13.2 follows v1.1's extraction-based proof instead.

**The threat model is quantum, the claims are classical** (2026-10-14
internal review). The rescue lane exists because of quantum attackers, but
§13.2–§13.4 are classical-ROM arguments. Against a quantum attacker only the
best known attacks can be stated: Grover search for a `ch3` output that
decodes to a root of the degree-2 final check at its own input (at most two
such `Δ` per input, so about `2^63.5` iterations, each one `ch3` evaluation and
one evaluation of that polynomial, once `chall2` and `ã` are fixed) or for any
hidden seed (128 per proof, each with its own
tweak, about `2^64`), and `2^128` Grover iterations against the one-way
function. The loss of a three-round Fiat–Shamir transform in the QROM is not
known. The consensus design must record, as an explicit risk decision, that
it accepts NIST category 1 strength against known quantum attacks, QROM
security as a conjecture, and the seed-entropy precondition of §13.1. A
larger margin needs a larger `λ`, which the proof size does not allow; that
trade-off belongs in the same record.

### 13.6 Generic attacks

- Seeds, `r`, `iv_pre`, `iv` and `Δ` are 128 bits: brute force costs `2^128`
  classically and about `2^64` Grover iterations (the FAEST-128 / NIST
  category 1 level). Grover's iterations are sequential: spread over `P`
  machines, each still runs about `2^64/√P` of them. NIST's category
  definitions take this depth limit into account (MAXDEPTH); `2^64` is an
  operation count, not a time estimate.
- Each `ggm`, `leaf` and `exp` call is separated by `iv` (fresh per proof) and
  the tree and node index, so one seed guess tests one target: no multi-target
  speed-up within or across proofs (FAEST v1.1 §10.2.2 and v3.0 tweaks).
- Commitments and digests are 256 bits (collisions `2^128`). Two outputs have
  128 bits. A collision of `iv` between two proofs (expected after about `2^64`
  proofs) is harmless for binding, because `chall1` hashes `iv_pre`, not `iv`,
  and it gives at most a two-target seed guess on those two proofs. Collisions
  of `chall3` are not useful; what counts is a `ch3` output that coincides
  with the `chall3` in a proof while `b̃' ≠ b̃`, the `Q_{2,3}·2^−λ` term of §13.2
  (counted more precisely there).
- Grinding challenges is the `Q_{2,3}·(2^{1−λ} + 2^−λ)` part of §13.2.

## 14. Known limitations

1. No formal security proof (§13.2); QROM security conjectured (§13.5); strong
   unforgeability and simulation extractability argued only (§13.4). The
   lemma sketches of revision 1 come from an internal review.
2. Only the Rust prover is written to be constant time and to zeroize its
   secrets, and those claims (`rust/CT-AUDIT.md`) have had no external
   review; the Python reference indexes lookup tables with secret values and
   keeps secrets in ordinary memory (§13.3). The Python prover is for the
   specification, tests and demonstrations with test seeds; the Rust prover
   also for seeds used on this signet alone. Proving with a seed that is
   worth something elsewhere requires a prover whose constant-time claims
   have been reviewed.
3. Verification cost is dominated by ~5.3 MB of SHAKE256 output (§3.3). The
   Rust verifier takes 33–38 ms single-threaded on a Zen 2 server (median;
   NOTES.md, "v0.2 tree split" and "2026-10-14 internal reviews"), against
   R1's estimate of 6–22 ms with AES-NI. With 24 trees the proof pays for its
   validation weight with a margin of 1.57–1.74 in every measured run,
   including the most expensive invalid input and the longest message (§11);
   with v0.1's 16 trees (about 113 ms) it did not. Only one machine was
   measured.
4. One parameter set; no BAVC, `T_open` or grinding (FAEST v2/v3 savings of a
   few hundred bytes deferred).
5. Degree-2 QuickSilver only; statement 2 (HKDF-SHA-512) needs the degree-≤6
   encoding of R1 (E3) and a degree-`d` check, not specified here.
6. Statement 0x01 only: `K` must be 1–64 printable ASCII bytes and the suffix
   exactly one byte; the empty-suffix (ML-DSA) variant has no id yet.
7. The relation proves knowledge of a preimage, not that it is the wallet's
   original seed (by design).

## 15. Deviations from FAEST and from the R1 plan

From FAEST v1.1 [F11] (the skeleton) and FAEST v3.0 [F30] (the hardening):

| # | Here | FAEST | Why |
|---|---|---|---|
| D1 | SHAKE256 for every PRG and hash, prefix tags with the version | AES-CTR PRG; SHAKE128 (λ = 128) with a trailing domain byte | task constraint (stdlib, no AES); §3.3 |
| D2 | Tweaks as explicit `u8(tree) ‖ u16le(node)` fields | v3: 32-bit tweak added to the AES-CTR IV | same effect with SHAKE |
| D3 | VOLEHash: two polynomial hashes over GF(2^128) without constant term, 2λ-bit output, `ℓ̂ = ℓ + 3λ` | v1.1: λ+B bits with a GF(2^64) part and a 2×2 matrix, `ℓ̂ = ℓ + 2λ + B`; v3: a 4-output KOS-style hash | v1.1's Lemma 1 is stated for `ℓ̂ ≤ 2^13` (ours is 42,455); one field only; `ε_v ≈ 2^−239`; costs 224 bytes per proof |
| D4 | ZKHash with full-width `t` | v1.1: `t` restricted to 64 bits | one field; bound valid for any `C < 2^64` |
| D5 | Generic degree-2 constraints from a Boolean circuit | AES S-box inverse constraints (v1, degree 2; v3, degree 7) | different relation |
| D6 | τ separate trees, hash-based leaf commitments, no grinding | v1.1 same; v2/v3 one BAVC tree, PRG-based leaf commitments, `T_open`, grinding | R1 decision (extractability in the ROM, simplicity) |
| D7 | `μ` binds version byte, statement id, canonical public inputs and length-prefixed message | `μ = H(pk ‖ msg)` | multiple statements, versions |
| D8 | `iv = H(iv_pre ‖ μ)`, `iv_pre` in `chall1` and in the proof | v3.0 identical; v1.1 used `iv` directly | adopted from v3 |
| D9 | `rnd` input `x ‖ μ ‖ ρ` with 32-byte `ρ` | `sk ‖ μ ‖ ρ`, λ-bit `ρ` | witness is the HMAC seed |
| D10 | Proof header (version, statement id); bit strings with checked zero padding; field order with `iv_pre` first | no header; all lengths multiples of 8; `iv` last | canonical encoding for consensus |
| D11 | Tree commitment hash includes `iv` and the tree index | `H_1(com_0..com_{N−1})` | uniform tweak convention; harmless |
| D12 | `τ = 24` trees, `k0`/`k1` split as in FAEST (8 trees of depth 6, then 16 of depth 5) | FAEST-128f: `τ = 16`, `k = 8`; FAEST-128s: `τ = 11`, depths 12 and 11 | more, smaller trees than any FAEST set: fewer leaf expansions for a faster verifier, at the cost of proof size |

From R1, the plan for this proof system:

| # | Change | Reason |
|---|---|---|
| R-a | SHAKE256 instead of v3's tweaked AES-CTR PRG and SHAKE128 hashes | task constraint; costs verify time (§14 item 3) |
| R-b | VOLEHash and ZKHash variants D3, D4 | R1 kept v1.1's hashes and flagged the `ℓ̂ ≤ 2^13` bound as unchecked; these variants make the bound immediate |
| R-c | `K` is a public input (1–64 printable ASCII bytes), not fixed per statement id | task definition of statement 1 |
| R-d | Free additions for the last four outer rounds and constant/public folding (§7.4): `ℓ = 42,071` instead of the estimated 43,036; proof 87,506 B instead of 89.2 kB | R1 §3.3 suggested public-output folding |
| R-e | No `param_id` field: the version byte fixes the parameters | one parameter set per version |
| R-f | v0.2: `τ = 24` mixed-depth trees (8 trees of depth 6, then 16 of depth 5) instead of R1's `τ = 16`, `k = 8` | verification cost: 1,000 instead of 4,080 leaf expansions; the proof grows from 87,506 to 130,218 bytes and still pays for its validation weight (NOTES.md) |

Considered in the 2026-10-14 internal reviews and left unchanged in v0.2;
either change would need a new version:

- **`rnd` hashes the wallet seed directly** (D9). That is fine in the ROM; if
  the rng fails, proofs become deterministic per `(x, μ)`, which is benign.
  Deriving a key `k_x` from `x` once and hashing `k_x` instead would be hygiene
  only.
- **Faster levers than `τ`.** Soundness does not depend on `τ` (`Σ k_i = 128`),
  and FAEST's balanced split minimises `Σ_i 2^{k_i}` for a given `τ`. Two other
  levers would cut verification work without growing the proof: SHAKE128
  for `exp`, `ggm` and `leaf` (FAEST's choice at λ = 128; about 24% faster
  than SHAKE256 on the benchmark machine, NOTES.md), and FAEST v3-style
  `w`-bit grinding, which lowers `Σ k_i` to `128 − w` (fewer leaf expansions;
  the prover pays about `2^w` extra attempts).

## 16. Versioning

- The version byte (`0x02`) and the label `v0.2` in every tag identify this
  specification. Any change to a primitive, tag, transcript field, parameter,
  hash family, proof layout or the circuit-building rules of §7 requires a new
  version byte and label.
- Statement ids are allocated per version: `0x01` is defined above; `0x02`
  (empty-suffix HMAC, ML-DSA) and `0x03`/`0x04` (statement 2) are reserved per
  the R spike numbering. A statement's definition includes its circuit digest
  (§7.6) and proof length.
- History: v0.1 (`0x01`, 2026-10-14) used `τ = 16` trees of depth 8 and was never
  deployed; v0.2 (`0x02`) changes only the tree split, hence the version byte,
  the tag label, the roots, the openings, the challenge decoding and the proof
  length. v0.1's vectors are in git history only.
- The circuit layer (§7) is unchanged; its serialization label (§7.6) names the
  circuit layer's own version and stays "circuit v0.1", so the digests are the same.
- Revision 1 of v0.2 (2026-10-14) changes wording only, after two internal
  reviews: §5.4 (both keys load-bearing), §11 (verification work), §12.1
  (consensus preconditions), §13 (assumptions, missing terms, lemma
  sketches, the quantum risk decision), §14 and §15. The version byte, the
  tags, the parameters, the proof format and the vectors are unchanged.
- Revision 2 of v0.2 (2026-10-15) changes wording only, after a clean-room
  implementation. A Go verifier written from revision 1 and the vectors
  alone agrees with every vector and reproduces both circuit digests. Its
  author listed 18 issues in the text (`go/SPEC-ISSUES.md`, branch
  `cleanroom/go-verifier`); the vectors contradicted none of them. Revision 2
  states what the vectors and the reference already fixed: §1 (normative
  sources, symbol table), §1.2 (the first `n` bits of a hash output are
  masked, not checked), §3.2–§3.3 and §8 (one notation for hash inputs),
  §5.3 (bit order of `Δ` and `δ_i`), §6.3 (the two Horner forms), §7.2 (only
  ids 0 and 1 fold; NOT is emitted), §7.4 (one emission-order rule,
  `add_multi`'s fold, PUB instructions emitted, the standalone circuit's
  inputs), §7.6 (byte grammar, per-gadget circuits), §11 (the interface,
  what steps 1–6 read), §12.1 (consensus checks are not in `verify`) and
  Appendix A (vector files). Two symbols were renamed: the hash tag (§3.1)
  and `compress`'s asserted state `F` (§7.4). The version byte, the tags,
  the parameters, the proof format and both vector files of revision 1 are
  unchanged; `vectors/gadgets-v0.2.json` is new.
- Revision 3 of v0.2 (2026-10-24) changes wording only, after the review of
  the final version (NOTES.md, "2026-10-24 review of the final version"): the
  status and sources at the top; §12 and §12.1 (item 4 split into the node's
  part and the part of wallets and operators); §13.1 (targets that share a
  seed, under a heuristic model of HMAC-SHA256); §13.2 (the collision term,
  the `chall3` term, the `iv_pre` term, the
  source of `C(τ,2)`); §13.3 and §14 item 2 (the Rust prover as it now is);
  §13.4 (proofs that reuse some trees); §13.5 (the cost of a Grover iteration);
  §15 and §17 (the internal sources described, not named by file); and this
  section. The version byte, the tags, the parameters, the proof format and
  every vector file are unchanged.
- v0.2 is fixed: `0x02`, as revisions 2 and later specify it, is what the
  Ark-0 signet rescue lane (M4-R1) verifies. Later revisions change wording
  only. Any change to the protocol, including a future frozen version
  published with new vectors, takes a new version byte and label.

## 17. References

- [F11] FAEST team. *FAEST Algorithm Specifications, Version 1.1.*
  https://faest.info/faest-spec-v1.1.pdf — §3.3 primitives, §4.2 universal
  hashing (Fig. 4.4, Lemmas 1–2, Prop. 1–4), §5 VOLEitH (Figs. 5.1–5.5, Prop. 5),
  §8 signing and verification (Figs. 8.2–8.3), §10.1 security (Lemmas 3–5,
  Theorems 1–3, Conjecture 1), §10.2.2.
- [F30] FAEST team. *FAEST Algorithm Specifications, Version 3.0* (2026-09-01).
  https://faest.info/faest-spec-v3.0.pdf — §1.1 changelog, §3 primitives
  (Fig. 3.6 tweakable PRG, `H_4`), §8 (Figs. 8.2–8.3), §10.4.
- [BBD+23] C. Baum, L. Braun, C. Delpech de Saint Guilhem, M. Klooß, E. Orsini,
  L. Roy, P. Scholl. *Publicly Verifiable Zero-Knowledge and Post-Quantum
  Signatures From VOLE-in-the-Head.* CRYPTO 2023. https://eprint.iacr.org/2023/996
- [Roy22] L. Roy. *SoftSpokenOT: Quieter OT Extension from Small-Field Silent VOLE
  in the Minicrypt Model.* CRYPTO 2022. https://eprint.iacr.org/2022/192
- [QS] K. Yang, P. Sarkar, C. Weng, X. Wang. *QuickSilver: Efficient and
  Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any
  Field.* CCS 2021. https://eprint.iacr.org/2021/076
- [GGM] O. Goldreich, S. Goldwasser, S. Micali. *How to Construct Random
  Functions.* J. ACM 33(4), 1986.
- [NB] *Practical Null-Branch Witness Attacks on In-the-Head Signatures.*
  ePrint 2026/2235 (cited from R1 §1.4; not re-read).
- [FIPS 180-4] SHA-256. [FIPS 202] SHAKE256. [RFC 2104] HMAC.
- Internal, not published: the plan for this proof system (R1), the spike
  on rescue proof systems before it (R), and the rescue-lane interface and
  owner decisions of the M4 design.

## Appendix A. Vector files

Three files in `vectors/` pin the behaviour. Byte strings are hex unless
noted. The `spec` field names the version; a revision that changes wording
only keeps a file unchanged (§16).

**`statement1-v0.2.json`: known answers.**

- The header gives the parameters, `proof_len` and the statement 0x01
  circuit: its digest (§7.6) and gate counts (§7.5).
- `vectors`: 4 valid proofs. Each gives the statement (`statement_id`,
  `public_inputs`, and `K_ascii`, `suffix`, `y` for reading), `witness_x`,
  `message`, `rho` (the one `rng(32)` output, §9), `proof` and
  `intermediates` (`mu` … `chall3`, for localising a mismatch).
- `negative_vectors`: 52 cases. Each applies one edit, `proof_edit`, to the
  proof of `vectors[base_vector]`, and verifies the result against its own
  `statement_id`, `public_inputs` and `message`. The expected verdict is
  false. The cases cover every header byte, every padding bit, each proof
  section, length ±1, the empty proof, malformed public inputs, and a wrong
  `m`, `y`, `K`, `suffix` or statement id.

**`statement1-v0.2-differential.json`: verdicts.** `format` is
`voleith-differential-1`.

- `valid`: 100 proofs with `expected` true. They have the fields of a known
  answer except `proof_len` and `intermediates`, and carry the proof as base64 in
  `proof_b64`.
- `mutated`: 440 cases with `expected` false. Each applies the list
  `proof_edits`, in order, to the decoded proof of `valid[base]`, and
  verifies the result against its own `statement_id` (0, 1, 2 or 255),
  `public_inputs` and `message`. A `message` of null means `message_zeros`
  zero bytes. `kind` groups the cases; `counts` gives the number per kind.
- `master_seed` and `stream_note` say how the generator derived each case;
  a verifier does not need them.

**Edit language.** An edit is a JSON object; offsets and lengths count bytes
of the proof:

| `op` | fields | effect |
|---|---|---|
| `none` | | no change; the case changes the statement or the message (known-answer file only) |
| `xor` | `offset`, `mask` | XOR the byte at `offset` with the one-byte `mask` |
| `set` | `offset`, `data` | overwrite `\|data\|` bytes from `offset`, inside the proof |
| `truncate` | `length` | keep the first `length` bytes |
| `append` | `data` | append `data` |
| `prepend` | `data` | insert `data` before byte 0 |

**`gadgets-v0.2.json`: per-gadget circuits.** §7.6 describes it.
