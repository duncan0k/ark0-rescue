# voleith: independent Go verifier for SPEC.md v0.2 rev. 1

This is a clean-room verifier written from `../SPEC.md` and `../vectors/` only.
It implements SPEC §11 and has no prover. It has no dependencies outside the
standard library: SHAKE256 comes from Go 1.24's `crypto/sha3`.

```go
ok := voleith.Verify(voleith.Statement{ID: 0x01, Public: pub}, m, proof)
```

`Public` is the canonical encoding `u8(|K|) ‖ K ‖ u8(suffix) ‖ y` (§7.5).
Steps 1–6 of §11 (statement id, public-input encoding, message length,
proof length, header, padding bits) run before any hashing. The circuit is
built once, lazily, after step 6.

| file | content |
|---|---|
| `voleith/verify.go` | §11 verifier, VOLE reconstruction, VOLEHash, ZKHash |
| `voleith/circuit.go` | §7 circuit builder (statement 0x01 and the standalone compression circuit), serialization and digest |
| `voleith/field.go`, `voleith/hash.go` | GF(2^128) arithmetic, tagged SHAKE256, native SHA-256 compression |
| `voleith/*_test.go` | the tests and the benchmark |
| `SPEC-ISSUES.md` | ambiguities and inconsistencies found in SPEC.md |
| `BENCHMARK.md` | median single-thread verify time |

Tests:

```
cd go
go test ./voleith          # all vectors, including the differential set (~25 s)
go test -short ./voleith   # without the differential set
```

The tests check:

- the 4 KATs, with every intermediate (`mu`, `iv`, `tree_hashes`, `hcom`,
  `chall1`, `h_v`, `chall2`, `b_tilde`, `chall3`, plus `r`, `iv_pre` and
  `roots` recomputed from the JSON's secrets, and the openings checked
  against fully expanded trees);
- the 52 KAT negatives;
- the 100 valid and 440 mutated differential cases;
- the step of §11 at which each negative is rejected, and that steps 1–6
  reject before any hashing;
- both circuit digests and the gate counts;
- the field arithmetic, against a naive reference.
