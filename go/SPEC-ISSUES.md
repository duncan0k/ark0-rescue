# SPEC.md v0.2 rev. 1: issues found while writing an independent Go verifier

Scope: `SPEC.md` (v0.2, revision 1) and `vectors/` on `cleanroom/base`
(commit `b4b199d`). These were the only sources. No other branch, no Python or
Rust code and no `NOTES.md` were read. The verifier is in `voleith/`.

**Overall result.** The verifier follows SPEC §11 and checks every vector:

- 4/4 KATs verify, with every intermediate equal;
- 52/52 KAT negatives are rejected;
- all 540 differential cases give the expected verdict (100 accepted, 440 rejected);
- both circuit digests of §7.6 are reproduced.

No verdict or intermediate value in either vector file contradicts the
reading below. Every issue is therefore an ambiguity, an underspecification,
an internal inconsistency or a wording error. None is a disagreement with the
vectors. Several ambiguities could be settled only because the vectors happen
to pin them.

**How "resolved by the vectors" was established.** For each ambiguity, the
alternative reading was implemented in a scratch copy and run against the
vectors:

- for the verifier: the KAT intermediates (`mu` … `chall3`);
- for the circuit builder: the two SHA-256 digests of §7.6.

An issue is marked *resolved* only when the alternative fails. Each issue
lists its probe results.

Severity: **High**: a reasonable reading produces a non-conforming verifier.
**Medium**: needs a guess that the vectors happen to pin. **Low**: wording,
notation or documentation.

## Summary

| # | Sev. | Section | Issue | Resolved by vectors? |
|---|---|---|---|---|
| 1 | High | §1.2, §5.1 | "first ℓ̂ bits" of the `exp` output is defined through a decoding rule that *rejects* non-zero padding | Yes (the rejecting reading fails every valid proof) |
| 2 | High | §7.4, §7.6 | The circuit is pinned by a digest only; several construction details are not stated anywhere | Yes, by the two digests (8 probes) |
| 3 | Medium | §11 | "Steps 1–5 happen before any hashing or parsing of proof contents" contradicts step 5, and the vectors cannot test it | No (verdict-only vectors); checked by instrumentation |
| 4 | Medium | §7.6 | Opcode width in the serialization (`opcode ‖ operands, each u32le`) | Yes (digest) |
| 5 | Medium | §7.4 | `add_multi` "fold left with add": argument order of `add` | Yes (digest) |
| 6 | Medium | §7.4 | Order of emission for nested word gadgets ("bit by bit" vs argument evaluation) | Yes (digest) |
| 7 | Medium | §7.4 | "Ch/Maj/Σ on public words fold away" contradicts §7.2 (only constants fold) | Yes (counts and digest) |
| 8 | Medium | §7.4 | Standalone compression circuit: `P` not stated; "big-endian words" undefined for wires | Yes (digest) |
| 9 | Medium | §11, §7.5 | The `verify` API is not defined ("statement" type, id width, where public bits are computed) | Partly (JSON layout) |
| 10 | Low | §7.2 | "return … `NOT(w)`": an emitted NOT, not `XOR(w,1)` | Yes (digest) |
| 11 | Low | §3.2, §8, §11 | Three different notations for the `ch3` input | Yes (KAT `chall3`) |
| 12 | Low | §5.4, §6.3 | VH and ZKH use opposite Horner conventions; ZKH's `t` Horner is only implied | Yes (KAT `h_v`, `b_tilde`) |
| 13 | Low | §5.3, §1.2–1.3 | Bit order of `Δ` and `δ_i` must be assembled from three sections | Yes (KAT `tree_hashes`) |
| 14 | Low | throughout | Symbols reused with different meanings | n/a |
| 15 | Low | §3.3 | "a `leaf` and an `exp` call on the same leaf differ only by tag" is inaccurate | n/a (no behavioural effect) |
| 16 | Low | §11, §12.1 | Library and consensus checks can be confused (`y` range, 96-byte `m`) | Yes (valid vectors with other `m` lengths) |
| 17 | Low | §11, vectors | The differential vector file and its edit language are not described in SPEC | n/a (inferred from the JSON notes) |
| 18 | Low | §1, §11, §14 | Normative references unavailable to an independent implementer (`python/voleith`, `NOTES.md`) | n/a |

Most important: #1, #2 and #3.

---

## 1. "First ℓ̂ bits" vs. the padding-rejection rule (High)

> §1.2: "If `n` is not a multiple of 8, the unused high bits of the last byte
> are **padding bits and must be zero**; a decoder rejects any non-zero padding
> bit. Taking "the first `n` bits" of a byte string means decoding it with this
> rule and discarding bits at positions `≥ n`."
>
> §5.1: "`r_{i,j}` = the first `ℓ̂` bits (§1.2) of
> `SHAKE256[exp](iv ‖ u8(i) ‖ u16le(N_i+j) ‖ sd_{i,j}, ⌈ℓ̂/8⌉)`."

**Problem.** "Decoding it with this rule" includes the rule's rejection
clause. Read literally, a verifier must reject when the PRG output's top bit
is set. That bit is uniformly random: `ℓ̂ = 42,455 ≡ 7 (mod 8)`, so bit 7 of
byte 5,306 is padding. The two halves of the sentence contradict each other:
"decode with this rule" (reject) and "discard bits ≥ n" (mask).

**Assumed.** Mask: the bits at positions `≥ ℓ̂` are dropped, never checked.
The padding rule applies only to proof fields (`enc(c_i)`, `enc(d)`), as §8
and §11 step 6 say.

**Vectors.** Resolved. Instrumented over the four KAT proofs, 484, 493, 514
and 516 of the 1,000 leaf expansions per proof have the padding bit set. The
rejecting reading would reject every valid vector. Masking and ignoring the
bit give the same result, because no step uses rows `≥ ℓ̂`. Probe: removing
the mask still passes every KAT.

**Suggested fix.** "Taking the first `n` bits of a hash output means reading
it in the bit order of §1.2 and discarding bits at positions `≥ n`; no
padding check applies."

## 2. The circuit is specified by its digest, not by its text (High)

> §7.6: "An independent implementation that follows §7.2–§7.5 reproduces
> these digests."

**Problem.** The claim holds only if the implementer guesses the same way
on #4, #5, #6, #7, #8 and #10. Each of those choices changes the instruction
list. A wrong guess shows up only as a 32-byte digest mismatch over about
1.3 MB of serialization, with nothing to say which gadget is wrong. Every
verifier must rebuild this circuit exactly, because constraint numbering
(§7.2) fixes the ZKHash order. So a builder that differs in any detail
rejects every valid proof.

**Assumed.** The choices listed in #4–#10. With them, both digests and every
gate count match on the first build: `5aadd73b…435d` for statement 0x01 and
`c0a978cb…9114` for the standalone circuit. The counts are XOR 211,450,
AND 42,900 (41,815 / 255 / 830), NOT 3,857 and ASSERT 256 for statement 0x01,
and 22,573 / 111,607 / 1,891 for the standalone circuit.

**Vectors.** Resolved, by the two digests only. Probe results, each an
alternative reading of the text:

| alternative reading | statement 0x01 digest | compression digest |
|---|---|---|
| opcode as `u32le` (#4) | fails | fails |
| fold as `add(next, acc)` (#5) | fails | fails |
| no stable SEC/non-SEC ordering in `add_multi` | fails | fails |
| Σ/σ: inner and outer `xor_w` interleaved per bit (#6) | fails | fails |
| `Ch` emitted word-at-a-time (all XORs, then ANDs, then XORs) (#6) | fails | fails |
| σ0 before σ1 in the message schedule (#6) | fails | fails |
| message schedule computed lazily inside the rounds (#6) | fails | fails |
| `AND(t, e[i])` instead of `AND(e[i], t)` in `Ch` | fails | fails |
| `Maj` always the second form | fails | passes (no PUB wires) |
| `Maj` always the first form | fails | fails |
| XOR with constant 1 emits `XOR(w,1)` instead of `NOT(w)` (#10) | fails | fails |
| no `0x00` after the label | fails | fails |
| `assert_add` without `ASSERT(c[0], 1, 0)` | fails | passes (no asserts) |

**Suggested fix.** Give a byte grammar for §7.6 and state the evaluation
order as one rule (#6). Publish per-gadget digests or small test circuits
(`add`, `Ch`, `Maj`, `assert_add` on fixed kinds), so a mismatch can be
localised.

## 3. "Steps 1–5 before any hashing or parsing of proof contents" (Medium)

> §11: "Return false at the first failed check. **Steps 1–5 happen before any
> hashing or parsing of proof contents.**" … "5. `π[0] = 0x02` and
> `π[1] =` the statement id." … "6. Split `π` at the fixed offsets of §10."
>
> §11, properties: "An implementation that builds a statement's circuit lazily
> must do so after step 6".

**Problems.**

1. Step 5 itself reads proof contents (`π[0]`, `π[1]`). The rule must mean
   "nothing except the two header bytes", but it does not say so.
2. The bold sentence covers steps 1–5. Yet step 6, the padding checks, also
   needs no hashing, and the properties paragraph treats 1–6 as the
   "format" group ("Steps 1–6 need only the fixed sizes …"). It is
   unclear whether hashing may begin before step 6. The step order implies
   it may not.
3. Statement 0x01 needs two SHA-256 compressions of `K` (`IV_in`, `IV_out`,
   §7.5) and one subtraction to form `T`. That is hashing of public inputs.
   §7.5 says only "computed natively by prover and verifier", and §11 never
   says when. Computing them during step 2, an easy shortcut, would break
   the "no hashing before step 5" rule.
4. The order among steps 1–5 matters only for cost, and the vectors give
   only a verdict. No vector can detect a verifier that hashes or builds the
   circuit first, or that checks the steps in another order.

**Assumed.** Steps 1–6 run in order and touch only lengths, the public-input
bytes, `π[0]`, `π[1]` and the padding bytes. The public bits are computed in
step 10, and the circuit is built (once, `sync.Once`) after step 6.

**Vectors.** Not resolvable from verdicts. Checked by instrumentation instead.
The test build records the rejecting step and whether any hash was called.
Every rejection at steps 1–6 happens with no hash call. Histograms:

- KAT negatives: step 1: 1, step 2: 2, step 4: 3, step 5: 3, step 6: 24,
  step 11: 19.
- Differential rejections: step 1: 6, step 2: 20, step 3: 1, step 4: 22,
  step 5: 10, step 6: 24, step 11: 357.

Every observed step matches the expected one for the vector's kind.

**Suggested fix.** "Steps 1–6 read only lengths, the public-input encoding,
`π[0..2)` and the last byte of each padded field; no hash, PRG or circuit
work happens before step 7, including the public bits of §7.5."

## 4. Opcode width in the circuit serialization (Medium)

> §7.6: "`‖ for each instruction: opcode ‖ operands, each u32le`
> `(XOR = 0x01 a b; AND = 0x02 a b, including MULs; NOT = 0x03 a; ASSERT = 0x04 a b c)`"

**Problem.** "Each u32le" can attach to the operands only, or to the opcode
and the operands. The two-digit hex opcodes suggest one byte but do not say
so.

**Assumed.** One byte for the opcode, then `u32le` operands: 1 for NOT,
2 for XOR/AND, 3 for ASSERT. The label is raw ASCII with no length prefix,
then one `0x00`.

**Vectors.** Resolved by both digests. A `u32le` opcode, or no `0x00`, fails
both.

## 5. `add_multi`: "fold left with add" (Medium)

> §7.4: "`order the words stably: those with no SEC wire first, then those with
> a SEC wire; drop words whose 32 wires are all constant 0; if none remain,
> return const_word(0); otherwise fold left with add.`"

**Problem.** `add(x, y)` is not symmetric in the instructions it emits: the
`XOR`/`AND` operand order changes. "Fold left" fixes the order of the words,
but not whether the accumulator is the first or second argument of `add`.

**Assumed.** `acc = add(acc, next)`. A single remaining word is returned
unchanged, with no instruction.

**Vectors.** Resolved. `add(next, acc)` fails both digests.

## 6. Order of emission for nested and per-bit gadgets (Medium)

> §7.4: "Word gadgets emit their instructions bit by bit in ascending bit order;
> nested calls evaluate their arguments left to right."

**Problem.** The two rules conflict for nested word gadgets.

- `Σ0(a) = xor_w(xor_w(rotr(a,2), rotr(a,13)), rotr(a,22))` can be emitted:
  - bit by bit, interleaving the inner and outer `xor_w` per bit; or
  - argument first, completing the inner 32-bit word before the outer.
- `Ch`/`Maj` are defined per bit (`Ch(e,f,g)[i] = …`). Whether bit `i`'s three
  instructions come before bit `i+1`'s depends on reading "bit by bit" as
  "per output bit, all its instructions".
- In `compress`, the order of `σ1(W[t−2])` and `σ0(W[t−15])` follows only
  from "left to right". So does the fact that the whole message schedule
  (`t = 16..63`) is emitted before round 0.

**Assumed.**

- Argument evaluation first: an inner `xor_w` completes before the outer one
  starts.
- Per-bit gadgets (`Ch`, `Maj`, `add`, `assert_add`) emit all instructions
  of bit `i`, in left-to-right nesting order, before bit `i+1`.
- σ1 before σ0.
- The schedule is emitted in full before the rounds, as the pseudo-code
  reads.

**Vectors.** Resolved. Each of the alternatives (interleaved Σ, word-at-a-time
`Ch`, σ0 first, lazy schedule) fails both digests.

## 7. "Ch/Maj/Σ on public words fold away" (Medium; inconsistent with §7.2)

> §7.4: "from round 60 on, the asserted (public) words replace the computed
> ones, and Ch/Maj/Σ on public words fold away."
>
> §7.2: "Only constant wires are folded, so **the instruction list depends
> only on the kinds of wires, never on public values**".

**Problem.** Under §7.2, `Σ`, `Ch` and `Maj` on PUB words do not fold. They
emit PUB-kind `XOR`/`AND`/`NOT` instructions, which appear in the
serialization and the digest and are evaluated on bits by the verifier
(§7.3). An implementer who takes "fold away" literally and emits nothing for
PUB-only operations gets a different circuit. The two sentences contradict
each other.

**Assumed.** §7.2: only wire ids 0 and 1 fold. "Fold away" is read as "costs
no MULs".

**Vectors.** Resolved. The JSON `gate_counts.AND = 42,900` and §7.5's
"public × public 830" count these PUB×PUB ANDs, and the digest matches only
when they are emitted.

## 8. Standalone compression circuit: `P` and "big-endian words" (Medium)

> §7.4: "**Standalone compression circuit** (for testing the generator): 768
> secret inputs (chaining value words 0–7, then block words 0–15, bit `i` of
> word `j` at input `32j + i`, big-endian words), `compress(H, W)`, and 256
> outputs".

**Problem.** The serialization starts with `u32le(P)`, but `P` is not given
(no public inputs is implied, not stated). "Big-endian words" has no meaning
for a wire layout that is already fully specified as `32j + i`. It can only
describe how a test harness packs bytes into inputs.

**Assumed.** `P = 0`, `S = 768`, secret wire `2 + 32j + i`. Outputs are
listed as wire ids, `32w + i`.

**Vectors.** Resolved by the digest `c0a978cb…9114` (`P` is serialized, so
any other `P` changes it).

## 9. The `verify` interface is not defined (Medium)

> §11: "`verify(statement, m, π) → bool`." §12: "The statement id and public
> inputs come from the rescue token; … calls `verify(statement, m, π)`."

**Problem.** "statement" is never defined as a value. It could be the id
alone, `(id, pub)`, or parsed `(K, suffix, y)`. If it is the parsed form,
step 2's canonical-encoding check has nothing to check, yet `μ` hashes the
encoding `pub`. The id's width is also unstated: `u8(sid)` in `μ`, but the
JSON carries an integer, so a caller-supplied id outside `[0, 255]` has no
defined meaning.

**Assumed.**
`Verify(Statement{ID byte; Public []byte}, m, proof []byte) bool`. `Public`
is the canonical encoding `u8(|K|) ‖ K ‖ u8(suffix) ‖ y`. It is validated
by step 2 and hashed as received in `μ`.

**Vectors.** Partly resolved. Both files give `statement_id` (0, 1, 2 or 255
only) and `public_inputs` as the raw encoding, and the malformed-encoding
vectors (`K length byte 0`, `65 with 65 bytes of K`, `byte 0x1f/0x7f/0x80/0x00`,
trailing/missing byte, empty) only make sense if the encoding is the input.

## 10. "return `NOT(w)`" in the XOR folding rule (Low)

> §7.2: "Exactly one constant `κ`, other wire `w`: return `w` if `κ = 0`, else
> `NOT(w)`."

**Problem.** `NOT(w)` could mean the builder call (emits a NOT instruction)
or the Boolean value (emit `XOR(w, 1)` unfolded, or a NOT of the constant).
In context it is the builder call.

**Assumed.** The builder's `NOT`, which emits `NOT(w)`.

**Vectors.** Resolved. Emitting `XOR(w,1)` instead fails both digests.

## 11. Three notations for the `ch3` input (Low)

> §3.2: "`ch3` | `chall2 ‖ ã ‖ b̃`" — §8: "`chall3 = SHAKE256[ch3](chall2 ‖ enc(ã)
> ‖ enc(b̃), 16)`" — §11 step 11: "`SHAKE256[ch3](chall2 ‖ ã ‖ enc(b̃), 16)`".

**Problem.** The same input is written three ways. Under §1.3 all three give
the same 48 bytes, but the mixed `ã ‖ enc(b̃)` in §11 invites the question of
whether `ã` is hashed as received and `b̃` re-encoded. The same mix appears
in §3.2's `ch1` (`enc(c_i)`) against `ch2` (`enc(d)`, raw `ũ`).

**Assumed.** `chall2 ‖ (16 proof bytes of ã) ‖ (16-byte encoding of b̃)`.

**Vectors.** Resolved. KAT `b_tilde` and `chall3` match.

## 12. VH and ZKH use opposite Horner conventions (Low)

> §5.4: "`P_s(x0) = Σ_{j<n_v} y_j · s^(n_v − j)` (Horner: `h = 0`; for each `j`:
> `h = (h ⊕ y_j)·s`)" — §6.3: "`ZKH(x; z) = r0·Σ_{i<C} s^(C−1−i)·x_i ⊕ r1·Σ_{i<C}
> t^(C−1−i)·x_i ⊕ z` (Horner: `h = 0`; for each `i`: `h = h·s ⊕ x_i`)".

**Problem.** Both are stated correctly, but they differ: VH has no constant
term (exponents ≥ 1), and ZKH does (exponents ≥ 0). They also share key
names `s`, `t` (#14). The ZKH Horner line names only `s`, so the `t` sum is
implied. Swapping the two conventions is an easy slip that the text does not
warn about. Note that §5.4 calls "every exponent ≥ 1" load-bearing.

**Assumed.** As written. VH: `h = (h ⊕ y)·s`. ZKH: `h = h·s ⊕ B_t` and
`h' = h'·t ⊕ B_t`, then `r0·h ⊕ r1·h' ⊕ q*`.

**Vectors.** Resolved. VH with `h = h·s ⊕ y` changes `h_v`. ZKH with
`h = (h ⊕ B)·s`, or with `r0`/`r1` swapped, changes `b_tilde`.

## 13. Bit order of `Δ` and `δ_i` (Low)

> §5.3: "`Δ ∈ GF(2^128)` is `chall3` (§8) read as a field element; `Δ_j` denotes its
> bit `j`." … "`δ_i = Σ_{b < k_i} Δ_{o_i+b}·2^b`".

**Problem.** That `Δ_j` is bit `j mod 8` of byte `⌊j/8⌋` of `chall3` follows
only by combining §1.2 (bit order), §1.3 (field encoding) and §5.3. Nowhere
is it stated in one place. The same holds for which proof bit selects which
leaf.

**Assumed.** Least-significant-bit-first throughout. `δ_i` takes `Δ_{o_i}` as
its least significant bit.

**Vectors.** Resolved. Most-significant-bit-first `δ_i` changes
`tree_hashes`, `hcom` and everything after.

## 14. Symbols reused with different meanings (Low)

Not ambiguous in context, but error-prone for an implementer:

- `s`, `t`: the VH keys from `chall1` (§5.4); the ZKH keys from `chall2`
  (§6.3); `t` is also the constraint index (§6.2) and the round index (§7.4).
- `T`: the hash tag (§3.1) and the public words `T_w` (§7.5).
- `S`: the number of secret inputs (§7.1) and the asserted state argument of
  `compress` (§7.4).
- `w`: a wire (§6.2), the witness (§6.1, §7.2) and a word index (§7.4–7.5).
- `c`: `c_i` are the VOLE corrections (§5.3), `c[i]` the carries (§7.4), and
  `c` the third wire of `a·b = c` (§6.2).
- `C`: the number of constraints, and `C(τ,2)`.
- `r`: the root seed (§8), the row index (§5.3), and `r_{i,j}` the leaf
  expansions.
- `Q`: the verifier's columns (§5.3) and the random-oracle query count (§13.2).
- `d`: the masked witness (§6.1), the tree depth index (§4.3) and the Schnorr
  key (§12.1).

## 15. "A `leaf` and an `exp` call on the same leaf differ only by tag" (Low)

> §3.3: "no two `ggm`, `leaf` or `exp` calls with the same tag share the non-secret
> prefix `iv ‖ u8(i) ‖ u16le(n)` (a `leaf` and an `exp` call on the same leaf
> differ only by tag)".

**Problem.** The two calls also differ in their last field: `leaf` hashes
`seed_{N_i+j}` and `exp` hashes `sd_{i,j}`. The parenthesis means "their
non-secret prefixes differ only by tag", but it reads as if the whole inputs
did.

**Assumed.** As §3.2's table says. **Vectors.** No behavioural effect; the
table is confirmed by KAT `tree_hashes`.

## 16. Library checks vs. rescue-lane checks (Low)

> §12.1: "checks natively that `0 < y < n` … `m` is exactly 96 bytes … The library
> accepts messages of up to 65,535 bytes; the rescue adapter must accept only
> this form."

**Problem.** §12.1 lists checks that are easy to put into `verify` by
mistake. Doing so would make the verifier non-conforming for the library
interface. §11 is clear, but §12.1 does not say outright that `verify` must
not perform them.

**Assumed.** `Verify` checks only §11, so any 32-byte `y` and any
`|m| ≤ 65,535`.

**Vectors.** Resolved. Valid vectors have messages of 0, 1, 96 and 65,535
bytes. The 65,536-byte message (`mut-307`) is rejected at step 3.

## 17. The differential vector file is not described by SPEC (Low)

> §11: "`vectors/statement1-v0.2.json` holds 4 valid vectors and 52 negative
> vectors … that every conforming verifier must reject."

**Problem.** SPEC never mentions `vectors/statement1-v0.2-differential.json`.
Its semantics exist only in the file's own notes:

- the edit language `xor` / `set` / `truncate` / `append` / `prepend`,
  applied in order;
- `message: null` plus `message_zeros`;
- `base` as an index into `valid`;
- base64 proofs, unlike the hex of the KAT file.

The KAT file's `op: "none"` is not described anywhere. Both files say
`"spec": "SPEC.md v0.2"` with no revision; that is consistent with revision
1's "both vector files are unchanged".

**Assumed.** The notes in the JSON. **Vectors.** Every count in SPEC §11 (4
valid, 52 negatives, and the listed categories) and in the differential
header (100 valid, 440 mutated, 0 accepted by Python) matches what the files
contain and what this verifier returns.

## 18. Normative references unavailable to an implementer (Low)

> §1: "The Python package in `python/voleith` is the executable form of this
> specification. Where this text and the code disagree, that is a bug in one of
> them; `vectors/statement1-v0.2.json` pins the intended behaviour."

**Problem.** An independent implementation has the text and the vectors only.
The text defers to code it does not ship, and its performance claims (§11,
§14) rest on `NOTES.md`, which is not included. Where the text is ambiguous
(#1–#10), the only arbiters are the vectors and two digests. The differential
file is not even named as normative (#17).

**Assumed.** SPEC plus vectors as the sole authority. **Vectors.** n/a.
For reference, this implementation measures a single-thread median of about
27 ms on one 2.1 GHz Xeon core (see `BENCHMARK.md`). The valid,
`chall3 = ff…ff` and 65,535-byte-message cases are within 0.25 ms of each
other, which is consistent with §11's "within 0.9 ms (3%)".

---

## Claims checked and found consistent

These were recomputed or checked by tests, and are listed so a reviewer
knows they were looked at:

- §2: `τ0 = λ mod τ = 8`, `k0 = ⌈128/24⌉ = 6`, `k1 = 5`, `Σ k_i = 128`.
- §3.3: `Σ (N_i − 1) = 1,000` and `⌈ℓ̂/8⌉ = 5,307`.
- §5.4: `n_v = 330` and `ε_v ≤ 2^−239.2`.
- §7.4–§7.5: the gate counts and both circuit digests.
- §7.4: the `add` cost claims (31 MULs for SEC+SEC, 30 for SEC+PUB, `30 − tz(κ)`
  for a constant addend; `TestAddCosts`).
- §10: every offset, the total 130,218, `|π| = 2,082 + 5,339·τ`, and v0.1's
  87,506.
- §11: "1,324,702 bytes of XOR" for `Δ = 2^128 − 1`:
  `128·32 + 128·5,259 + 122·5,307`.
- The 24 padding bits rejected at step 6, and `Δ = 0` handled without a
  special case.
- §7.5: the relation (`HMAC-SHA256(K, x ‖ suffix) = y`) for every KAT, and the
  clear evaluation of the circuit on the KAT witness (all ASSERTs hold;
  flipping one bit of `y` violates at least one).
