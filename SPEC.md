# VOLEitH rescue proofs: specification v0.1

Status: **draft for review, not frozen** (2026-10-14). Nothing here has had an
external cryptographic review.

This document specifies a non-interactive zero-knowledge proof of knowledge,
used as a signature of knowledge on a public message, for the signet rescue
lane. It follows the FAEST v1.1 VOLE-in-the-head (VOLEitH) skeleton with the
AES-independent hardening of FAEST v3.0, replaces the AES relation by a generic
Boolean constraint layer, and defines one statement:

> **Statement 0x01.** The prover knows a 32-byte seed `x` such that
> `HMAC-SHA256(K, x ‖ suffix) = y`, for public `K`, `suffix` and `y`.

The Python package in `python/voleith` is the executable form of this
specification. Where this text and the code disagree, that is a bug in one of
them; `vectors/statement1-v0.1.json` pins the intended behaviour.

Sources: the approved plan `R1-voleith-plan.md`, the rescue-lane interface in
`m4-design-2026-10-14.md` §11 and the owner decisions in `m4-plan-2026-10-14.md`
§9 (all in the scopeScan repository, `docs/quantum-program/`). External
references are listed in §17.

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

## 1. Conventions

### 1.1 Notation

- `‖` is byte-string concatenation. `[a, b)` is the half-open integer range.
- `u8(v)`, `u16le(v)`, `u32le(v)`, `u64le(v)` encode an unsigned integer in 1, 2,
  4 or 8 bytes, little-endian.
- `⊕` is XOR of bit strings or addition in GF(2^128); `·` is multiplication in
  GF(2) or GF(2^128) as the context requires.
- `λ = 128`, `τ = 16`, `k = 8`, `N = 2^k = 256` (§2).
- `ℓ` is the number of witness bits of a statement and `ℓ̂ = ℓ + 3λ` the VOLE
  length (§5).

### 1.2 Bit strings

A bit string `b[0..n)` is identified with the non-negative integer
`Σ b[i]·2^i`. Its byte encoding `enc_n(b)` has `⌈n/8⌉` bytes; bit `i` is bit
`i mod 8` (least significant first) of byte `⌊i/8⌋`. If `n` is not a multiple of
8, the unused high bits of the last byte are **padding bits and must be zero**;
a decoder rejects any non-zero padding bit.

Taking "the first `n` bits" of a byte string means decoding it with this rule
and discarding bits at positions `≥ n`.

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
| version byte | `0x01` | protocol version v0.1 (§16) |
| `λ` | 128 | security parameter, field size, seed size in bits |
| `τ` | 16 | number of GGM trees (small VOLE instances) |
| `k` | 8 | tree depth; `τ·k = λ` |
| `N` | 256 | leaves per tree |
| VOLE rows | `ℓ̂ = ℓ + 128 + 256` | witness rows, QuickSilver mask rows, consistency-hash mask rows |
| `ρ` | 32 bytes | hedging randomness per proof |
| grinding | none | |
| max message | 65,535 bytes | |

The parameters follow R1 (τ = 16, k = 8, no grinding). For statement 0x01,
`ℓ = 42,071` and `C = 42,071` constraints (§7.5).

## 3. Primitives and domain separation

### 3.1 Tagged SHAKE256

Every hash, PRG and random-oracle call is

```
SHAKE256[name](data, L) = SHAKE256( u8(|T|) ‖ T ‖ data , L bytes ),
T = ASCII "VOLEitH-rescue/v0.1/" ‖ name
```

The tag `T` contains the protocol version, so a new version changes every call.
Within one name, `data` is a concatenation of fields whose lengths are fixed by
the protocol and the statement id, or that carry an explicit length prefix, so
each input encoding is injective.

### 3.2 All calls

| name | input `data` | output | role (FAEST analogue) |
|---|---|---|---|
| `mu` | `u8(0x01) ‖ u8(sid) ‖ u16le(\|pub\|) ‖ pub ‖ u64le(\|m\|) ‖ m` | 32 | message/statement digest μ (`H_2^0`) |
| `rnd` | `u16le(\|x\|) ‖ x ‖ μ ‖ ρ` | 32 | root seed `r` (bytes 0–15) and `iv_pre` (16–31) (`H_3`) |
| `iv` | `iv_pre ‖ μ` | 16 | IV of this proof (v3 `H_4`) |
| `root` | `iv ‖ r` | 256 | tree roots `r_0..r_15`, 16 bytes each (PRG) |
| `ggm` | `iv ‖ u8(i) ‖ u16le(n) ‖ seed_n` | 32 | children of GGM node `n` of tree `i` (PRG) |
| `leaf` | `iv ‖ u8(i) ‖ u16le(N+j) ‖ seed_{N+j}` | 48 | `sd_{i,j}` (16) ‖ `com_{i,j}` (32) (`H_0`) |
| `exp` | `iv ‖ u8(i) ‖ u16le(N+j) ‖ sd_{i,j}` | `⌈ℓ̂/8⌉` | leaf expansion `r_{i,j}` (PRG) |
| `tree` | `iv ‖ u8(i) ‖ com_{i,0} ‖ … ‖ com_{i,255}` | 32 | tree commitment `h_i` (`H_1`) |
| `hcom` | `h_0 ‖ … ‖ h_15` | 32 | VOLE commitment `hcom` (`H_1`) |
| `ch1` | `μ ‖ hcom ‖ enc(c_1) ‖ … ‖ enc(c_15) ‖ iv_pre` | 32 | `chall1` (`H_2^1`) |
| `hv` | `Ṽ_0 ‖ … ‖ Ṽ_127` | 32 | `h_V` (`H_1`) |
| `ch2` | `chall1 ‖ ũ ‖ h_V ‖ enc(d)` | 64 | `chall2` (`H_2^2`) |
| `ch3` | `chall2 ‖ ã ‖ b̃` | 16 | `chall3` (`H_2^3`) |

`sid` is the statement id, `pub` the canonical public inputs, `m` the message,
`x` the witness. Seeds and IVs are 16 bytes.

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
  on the same leaf differ only by tag), the single `root` call has its own tag,
  and `iv` separates proofs. A seed guess therefore tests one target.
- **Cost.** The verifier expands `16 × 255` leaves of `⌈ℓ̂/8⌉ = 5,307` bytes,
  about 21.7 MB of SHAKE256 output for statement 0x01. That dominates
  verification (§14, NOTES.md). AES-NI would be several times faster.

## 4. All-but-one vector commitment

Each tree `i ∈ [0, 16)` is a GGM tree of depth `k = 8` with heap numbering:
the root is node 1, the children of node `n` are `2n` and `2n+1`, and leaf `j`
is node `N + j`.

### 4.1 Roots

`(r_0 ‖ … ‖ r_15) = SHAKE256[root](iv ‖ r, 256)`.

### 4.2 Commit (prover)

```
seed_1 = r_i
for n = 1 .. N-1:                      (ascending)
    seed_{2n} ‖ seed_{2n+1} = SHAKE256[ggm](iv ‖ u8(i) ‖ u16le(n) ‖ seed_n, 32)
for j = 0 .. N-1:
    sd_{i,j} ‖ com_{i,j} = SHAKE256[leaf](iv ‖ u8(i) ‖ u16le(N+j) ‖ seed_{N+j}, 48)
h_i = SHAKE256[tree](iv ‖ u8(i) ‖ com_{i,0} ‖ … ‖ com_{i,N-1}, 32)
```

`sd_{i,j}` is 16 bytes, `com_{i,j}` 32 bytes. As in FAEST v1.1, each leaf key is
hashed into a seed and a commitment; the leaf commitments are **hash-based**,
not the PRG-based ones of FAEST v2/v3 (§15).

### 4.3 Open (prover)

For the hidden leaf `j*`, the path nodes are `p_d = (N + j*) >> (k − d)` for
depths `d = 1..k`, and the co-path nodes `s_d = p_d ⊕ 1`. The opening is

```
open_i = seed_{s_1} ‖ seed_{s_2} ‖ … ‖ seed_{s_k} ‖ com_{i,j*}      (k·16 + 32 = 160 bytes)
```

(co-path top-down, then the hidden leaf's commitment), as in FAEST v1.1 VC.Open.

### 4.4 Reconstruct (verifier)

Given `open_i` and `j*`: set `seed_{s_d}` from the opening for `d = 1..k`; for
`n = 2..N-1` in ascending order, if `seed_n` is known, derive its children as in
§4.2. Every leaf except `j*` is now known. Compute `(sd_{i,j}, com_{i,j})` for
`j ≠ j*`, take `com_{i,j*}` from the opening, and recompute `h_i`. Path nodes and
the hidden leaf's seed are never known to the verifier.

## 5. VOLE construction and consistency check

### 5.1 Leaf expansion

`r_{i,j}` = the first `ℓ̂` bits (§1.2) of
`SHAKE256[exp](iv ‖ u8(i) ‖ u16le(N+j) ‖ sd_{i,j}, ⌈ℓ̂/8⌉)`.

### 5.2 ConvertToVOLE

Prover, for tree `i`, with `bit_b(j)` the bit `b` of the integer `j`:

```
u_i     = ⊕_{j ∈ [0,N)} r_{i,j}
v_{i,b} = ⊕_{j : bit_b(j) = 1} r_{i,j}               for b ∈ [0, k)
```

Verifier, knowing every `r_{i,j}` except `j* = δ_i` (§5.3):

```
q_{i,b} = ⊕_{j ≠ j*, bit_b(j ⊕ j*) = 1} r_{i,j}
```

Then `q_{i,b} = v_{i,b} ⊕ bit_b(δ_i)·u_i` [FAEST v1.1 Prop. 5]. Any algorithm
computing these sums (e.g. FAEST's divide-and-conquer) is conforming.

### 5.3 Corrections and the combined VOLE

`Δ ∈ GF(2^128)` is `chall3` (§8) read as a field element; `Δ_j` denotes its
bit `j`. Tree `i` uses bits `[8i, 8i+8)`: its index `δ_i = Σ_b Δ_{8i+b}·2^b` is
simply byte `i` of `chall3`, so `bit_b(δ_i) = Δ_{8i+b}`. The hidden leaf of tree
`i` is `j* = δ_i`.

```
u   = u_0
c_i = u_0 ⊕ u_i                              for i ∈ [1, 16)    (sent in the proof)
V_{8i+b} = v_{i,b}                           (prover, column 8i+b)
Q_{8i+b} = q_{i,b} ⊕ Δ_{8i+b}·c_i  (i ≥ 1),  Q_b = q_{0,b}       (verifier)
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
            (Horner: h = 0; for each i: h = h·s ⊕ x_i)
```

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
| `XOR(a,b)` | both constant: return `a⊕b`. Exactly one constant `κ`, other wire `w`: return `w` if `κ = 0`, else `NOT(w)`. Otherwise emit `XOR(a,b)`. |
| `AND(a,b)` | both constant: return `a∧b`. Exactly one constant `κ`, other `w`: return `w` if `κ = 1`, else constant 0. Otherwise emit `AND(a,b)`. |
| `NOT(a)` | constant: return `1−a`. Otherwise emit `NOT(a)`. |
| `ASSERT(a,b,c)` | always emitted; no wire. |

Operands are recorded in the order of the call. Only constant wires are folded,
so **the instruction list depends only on the kinds of wires, never on public
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

A word is a list of 32 wires, least significant bit first. Word gadgets emit
their instructions bit by bit in ascending bit order; nested calls evaluate
their arguments left to right.

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
    if none remain, return const_word(0); otherwise fold left with add.

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
compress(H, W, S = none):       # H: 8 words, W: 16 words, S: optional 8 non-SEC words
    for t in 16..63:
        W[t] = add_multi([σ1(W[t-2]), W[t-7], σ0(W[t-15]), W[t-16]])
    (a,b,c,d,e,f,g,h) = H
    for t in 0..63:
        s1 = Σ1(e);  ch = Ch(e,f,g)
        T1 = add_multi([h, s1, ch, const_word(K_t), W[t]])
        s0 = Σ0(a);  mj = Maj(a,b,c)
        T2 = add_multi([s0, mj])
        if S given and t ≥ 60:
            e' = S[4 + 63 − t];  a' = S[63 − t]
            assert_add(d, T1, e');  assert_add(T1, T2, a')
        else:
            e' = add_multi([d, T1]);  a' = add_multi([T1, T2])
        (h,g,f,e,d,c,b,a) = (g,f,e,e',c,b,a,a')
    if S given: return nothing
    return [add_multi([H[w], state[w]]) for w in 0..7]      # state = (a,b,c,d,e,f,g,h)
```

`K_t` are the FIPS 180-4 round constants. With `S` given, the circuit asserts
that the state after round 63, `(a_64, a_63, a_62, a_61, e_64, e_63, e_62, e_61)`,
equals `S`; from round 60 on, the asserted (public) words replace the computed
ones, and Ch/Maj/Σ on public words fold away.

**Standalone compression circuit** (for testing the generator): 768 secret
inputs (chaining value words 0–7, then block words 0–15, bit `i` of word `j` at
input `32j + i`, big-endian words), `compress(H, W)`, and 256 outputs: bit `i` of
output word `w` is output `32w + i`. Counts:
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

**Public bits** (`P = 776`), computed natively by prover and verifier:

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
compress(IV_out, outer, S = T)
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
"VOLEitH-rescue circuit v0.1" ‖ 0x00 ‖ u32le(P) ‖ u32le(S) ‖ u32le(#instructions)
  ‖ for each instruction: opcode ‖ operands, each u32le
        (XOR = 0x01 a b; AND = 0x02 a b, including MULs; NOT = 0x03 a; ASSERT = 0x04 a b c)
  ‖ u32le(#outputs) ‖ outputs, each u32le
```

SHA-256 of this byte string:

- statement 0x01 (no outputs):
  `5aadd73b39947a32f0eb217cf750ee280c3dadcd60b9ccccb09509892cf1435d`
- standalone compression circuit:
  `c0a978cb3bf40e83098fbf7b74226c557842bc09892598b66bdf3c7225c29114`

An independent implementation that follows §7.2–§7.5 reproduces these digests.

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
μ        = SHAKE256[mu](u8(0x01) ‖ u8(sid) ‖ u16le(|pub|) ‖ pub ‖ u64le(|m|) ‖ m, 32)
r‖iv_pre = SHAKE256[rnd](u16le(|x|) ‖ x ‖ μ ‖ ρ, 32)          (prover only)
iv       = SHAKE256[iv](iv_pre ‖ μ, 16)
hcom     = SHAKE256[hcom](h_0 ‖ … ‖ h_15, 32)
chall1   = SHAKE256[ch1](μ ‖ hcom ‖ enc(c_1) ‖ … ‖ enc(c_15) ‖ iv_pre, 32)
h_V      = SHAKE256[hv](Ṽ_0 ‖ … ‖ Ṽ_127, 32)
chall2   = SHAKE256[ch2](chall1 ‖ ũ ‖ h_V ‖ enc(d), 64)
chall3   = SHAKE256[ch3](chall2 ‖ enc(ã) ‖ enc(b̃), 16)
Δ        = chall3 as a field element; δ_i = chall3[i]
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

`prove(statement, x, m, rng)`, where `rng(n)` returns `n` bytes and is called
exactly once with `n = 32`:

1. Reject an unknown statement id, non-canonical public inputs, `m` not bytes
   or longer than 65,535 bytes, or `|x| ≠ 32`.
2. Refuse unless `HMAC-SHA256(K, x ‖ suffix) = y`; evaluate the circuit in the
   clear (§7.3) to get `w` and refuse if any ASSERT fails.
3. `μ`, `ρ = rng(32)`, `(r, iv_pre)`, `iv` (§8).
4. VOLE commitment: roots, 16 trees (§4.2), leaf expansions (§5.1),
   `u_i, v_{i,b}` (§5.2), `u = u_0`, `c_i = u_0 ⊕ u_i`, columns `V`, `hcom`.
5. `chall1`; `ũ = VH(u)`; `h_V` over `VH(V_j)`; `d = w ⊕ u[0..ℓ)`; `chall2`.
6. Rows `v[r]` for `r < ℓ + 128`; terms `A0_t, A1_t` (§6.2); `u*`, `v*`;
   `ã = ZKH(A1; u*)`, `b̃ = ZKH(A0; v*)`; `chall3`.
7. `Δ = chall3`; for each tree, `open_i` at `j* = chall3[i]` (§4.3).
8. Output the proof of §10.

The prover's secrets are `x`, `w`, `r`, all seeds, `u`, `V` and `ρ`.

## 10. Proof format and size

Fields in order (statement 0x01 offsets in bytes):

| offset | field | bytes | notes |
|---|---|---|---|
| 0 | version | 1 | `0x01` |
| 1 | statement id | 1 | `0x01` |
| 2 | `iv_pre` | 16 | |
| 18 | `enc(c_1) … enc(c_15)` | 15 × 5,307 | `⌈ℓ̂/8⌉` each; 1 padding bit each |
| 79,623 | `ũ` | 32 | |
| 79,655 | `enc(d)` | 5,259 | `⌈ℓ/8⌉`; 1 padding bit |
| 84,914 | `ã` | 16 | |
| 84,930 | `open_0 … open_15` | 16 × 160 | 8 co-path seeds top-down, then `com_{i,j*}` |
| 87,490 | `chall3` | 16 | |
| | **total** | **87,506** | |

General size formula (bytes):

```
|π| = 2 + λ/8 + (τ−1)·⌈(ℓ+3λ)/8⌉ + 2λ/8 + ⌈ℓ/8⌉ + λ/8 + τ·(k·λ/8 + 2λ/8) + λ/8
    = 2,642 + 15·⌈(ℓ+384)/8⌉ + ⌈ℓ/8⌉            (λ = 128, τ = 16, k = 8)
```

For statement 0x01 (`ℓ = 42,071`): `2,642 + 15·5,307 + 5,259 = 87,506` bytes. Every
valid proof for a statement id has exactly this length; there is no other
encoding of the same proof.

`hcom`, `b̃` and the hidden seeds are not transmitted: the verifier recomputes
`hcom` and `b̃`, and the final `chall3` comparison covers both.

## 11. Verifier

`verify(statement, m, π) → bool`. Return false at the first failed check.
**Steps 1–5 happen before any hashing or parsing of proof contents.**

1. The statement id is a registered id (only `0x01` in v0.1); otherwise false.
2. The public inputs parse canonically (§7.5): first byte `L ∈ [1, 64]`, total
   length exactly `L + 34`, `K` bytes in `0x20..0x7E`.
3. `m` is a byte string of length ≤ 65,535.
4. `π` is a byte string of length exactly `|π|` for this statement id (87,506).
5. `π[0] = 0x01` and `π[1] =` the statement id.
6. Split `π` at the fixed offsets of §10. Decode each `enc(c_i)` and `enc(d)`;
   reject if any padding bit is non-zero. Steps 8–9 hash these bytes as
   received.
7. Compute `μ`, `iv`, `Δ = chall3`.
8. For each tree `i`: `j* = chall3[i]`; reconstruct (§4.4) to get `h_i` and the
   seeds `sd_{i,j}`, `j ≠ j*`; expand them (§5.1); compute `q_{i,b}` (§5.2); form
   `Q` with the corrections (§5.3). Compute `hcom` and `chall1`.
9. `h_V` from `VH(Q_j) ⊕ Δ_j·ũ` (§5.4); `chall2`.
10. Correct `Q` with `d` (§6.1); compute rows `q[r]` for `r < ℓ + 128`; evaluate
    the circuit's keys (§7.3) to get `B_t`; `q*`; `q̃ = ZKH(B; q*)`;
    `b̃ = q̃ ⊕ ã·Δ`.
11. Recompute `chall3' = SHAKE256[ch3](chall2 ‖ ã ‖ enc(b̃), 16)` and return
    `chall3' == chall3`.

`vectors/statement1-v0.1.json` holds 4 valid vectors and 44 negative vectors
(edits of a valid proof, statement or message: every header byte, every padding
bit, each proof section, length ±1, wrong `m`, `y`, `K`, `suffix` and statement
id) that every conforming verifier must reject.

Properties: the work is the same for every input that passes steps 1–6; no
step depends on secret data; there is no input on which the verifier must
abort, loop or allocate a size taken from the proof. An implementation must
treat any internal error as rejection. Every challenge value, including
`Δ = 0`, is valid.

## 12. Use in the rescue lane

This section restates the interface of `m4-design-2026-10-14.md` §11; the
consensus details belong to the M4-R design.

- The proof is carried in the annex as one element, at most one proof per
  input (4R-3, 4R-9). Statement 0x01 proofs are 87,506 bytes (87,506 WU).
- `m = rescue sighash ‖ network id ‖ public key` (or the public-key
  commitment of 4R-6); this specification treats `m` as opaque bytes. The rescue sighash
  (`key_version = 0x03`) omits `sha_annex`, so the proof never commits to
  itself; other signatures in the input commit to the full annex (4R-2, 4R-3).
- The statement id and public inputs come from the rescue token; the node
  checks the key relation natively (4R-7) and calls `verify(statement, m, π)`.
- 4R-6 requires that a proof cannot be moved to another transaction or mauled
  into another valid proof: §13.4.

## 13. Security

### 13.1 Model and assumptions

- **Random oracles.** Every `SHAKE256[name]` is modelled as an independent
  random oracle (classical ROM). `rnd` may alternatively be modelled as a PRF
  keyed by `x` and `ρ`.
- **One-wayness.** For uniform `x ∈ {0,1}^256`, given `(K, suffix)` and
  `y = HMAC-SHA256(K, x ‖ suffix)`, finding any `x'` with the same output is hard.
  The relation is length-preserving, so the extractor may return a different
  preimage; that suffices for the rescue lane, which needs knowledge of *a*
  preimage.
- **Honest keys.** Statements are derived from honestly generated seeds;
  security for adversarially chosen statements is not claimed.

### 13.2 Unforgeability (classical ROM, 128-bit target)

The target: no adversary that makes `Q` random-oracle queries produces a valid
proof for a fresh `(statement, m)` with probability much above `Q·2^−127`, apart
from inverting the one-way function.

By analogy with FAEST v1.1 Theorem 1 (EUF-KO) — straight-line extraction of the
leaf seeds from `leaf` queries, extraction of `w = d ⊕ u` from the queried
transcript, and round-by-round bad events — the bound becomes, with `Q_leaf`
queries to `leaf`, `Q_1` to `tree`/`hcom`/`hv` and `Q_{2,j}` to `ch_j`:

```
Adv_EUF-KO ≤ 3·(Q_leaf + Q_1 + Q_2)^2 / 2^256          (collisions/preimages of 256-bit outputs)
           + Q_{2,1} · C(τ,2) · ε_v                     (VOLE consistency, ≤ 2^−232.3 per query)
           + Q_{2,2} · ε_zk                             (ZKHash, ≈ 2^−128 per query)
           + Q_{2,3} · 2^{1−λ}                           (QuickSilver final check, 2^−127 per query)
           + Adv_OWF
```

- This is the form of the bound at the end of the proof of FAEST v1.1
  Theorem 1 (p. 71), which is sharper than the theorem statement's
  `Q_2·(ε_v + ε_zk + 2^−λ)`. Its terms are re-derived here, conservatively, for
  our hash families.
- The `C(τ,2)·ε_v` term is FAEST's Claim 1 (from BBD+23 Theorem 2, SoftSpokenVOLE
  with the repetition code over the τ trees). Our `ε_v ≤ (330/2^128)^2` makes it
  negligible; FAEST v1.1 needed `B = 16` extra hash bits for the same factor.
- EUF-CMA follows FAEST v1.1 Theorem 2: signing queries are simulated by
  programming `ch1`, `ch2`, `ch3`; the added terms are PRG/PRF advantages of the
  tagged SHAKE256 calls and programming collisions bounded by the min-entropy of
  `hcom` (256 bits) and `iv_pre` (128 bits).

**This is a re-instantiation by analogy, not a proof.** The things that differ
from FAEST v1.1 and must be re-checked by a reviewer: the hash families of
§5.4 and §6.3, the degree-2 generic constraint layer (FAEST proves AES S-box
constraints of the same degree), `ℓ ≈ 2^15.4` and `C ≈ 2^15.4` instead of
`≤ 2^13`, the transcript of §8, and the multi-user setting (many statements;
the reduction to one-wayness loses at most the number of target statements, or
uses a multi-instance OWF assumption).

### 13.3 Zero knowledge

Honest-verifier zero knowledge of the interactive protocol and simulation in
the ROM follow FAEST v1.1 Theorem 2's games G6–G9: `u` and the `c_i` are
pseudorandom given the openings (one hidden leaf per tree; Lemma 5, modelling
`ggm`, `leaf` and `exp` as PRGs), `ũ` is masked by the 256 hash-mask rows, `ã`
by `u*`, and `d` by `u[0..ℓ)`. `b̃` is determined by the rest. A proof reveals
nothing about `x` beyond the statement.

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

Moving a proof to another message or statement changes μ, hence every
challenge. FAEST v3.0 likewise claims only *conjectured* strong unforgeability;
we claim no more. Simulation extractability in the sense of 4R-6 is a
reviewer question (§14, NOTES.md).

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

### 13.6 Generic attacks

- Seeds, `r`, `iv_pre`, `iv` and `Δ` are 128 bits: brute force costs `2^128`
  classically and about `2^64` Grover iterations (the FAEST-128 / NIST
  category 1 level).
- Each `ggm`, `leaf` and `exp` call is separated by `iv` (fresh per proof) and
  the tree and node index, so one seed guess tests one target: no multi-target
  speed-up within or across proofs (FAEST v1.1 §10.2.2 and v3.0 tweaks).
- Commitments and digests are 256 bits (collisions `2^128`).
- Grinding challenges is the `Q·2^−127` term of §13.2.

## 14. Known limitations

1. No formal security proof (§13.2); QROM security conjectured (§13.5); strong
   unforgeability and simulation extractability argued only (§13.4).
2. The Python reference is not constant time and keeps secrets in ordinary
   memory. It is for specification and testing, not for proving with real
   seeds on shared machines. A production prover must be constant time.
3. Verification cost is dominated by ~21.7 MB of SHAKE256 output (§3.3): the
   leaf expansions alone take 38.7 ms with OpenSSL's SHAKE256 on the test
   machine (NOTES.md). The Rust verifier takes about 113 ms single-threaded on
   a Zen 2 server (median; NOTES.md, "Rust verifier"), against R1's estimate
   of 6–22 ms with AES-NI; at that speed the proof does not pay for its own
   validation weight (NOTES.md).
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

From R1 (`R1-voleith-plan.md`):

| # | Change | Reason |
|---|---|---|
| R-a | SHAKE256 instead of v3's tweaked AES-CTR PRG and SHAKE128 hashes | task constraint; costs verify time (§14 item 3) |
| R-b | VOLEHash and ZKHash variants D3, D4 | R1 kept v1.1's hashes and flagged the `ℓ̂ ≤ 2^13` bound as unchecked; these variants make the bound immediate |
| R-c | `K` is a public input (1–64 printable ASCII bytes), not fixed per statement id | task definition of statement 1 |
| R-d | Free additions for the last four outer rounds and constant/public folding (§7.4): `ℓ = 42,071` instead of the estimated 43,036; proof 87,506 B instead of 89.2 kB | R1 §3.3 suggested public-output folding |
| R-e | No `param_id` field: the version byte fixes the parameters | one parameter set in v0.1 |

## 16. Versioning

- The version byte (`0x01`) and the label `v0.1` in every tag identify this
  specification. Any change to a primitive, tag, transcript field, parameter,
  hash family, proof layout or the circuit-building rules of §7 requires a new
  version byte and label.
- Statement ids are allocated per version: `0x01` is defined above; `0x02`
  (empty-suffix HMAC, ML-DSA) and `0x03`/`0x04` (statement 2) are reserved per
  the R spike numbering. A statement's definition includes its circuit digest
  (§7.6) and proof length.
- v0.1 is a review draft. After review, a frozen version is published with
  new vectors; v0.1 vectors stay as historical test data.

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
- Internal: `R1-voleith-plan.md`, `R-rescue-proof-system.md`,
  `m4-design-2026-10-14.md` §11, `m4-plan-2026-10-14.md` §9.
