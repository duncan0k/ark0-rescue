# ark0-rescue

Proofs of seed knowledge for the rescue lane of the Ark-0 test signet: their specification and three
implementations. A proof shows, in zero knowledge, that the prover knows a seed `x` with
`HMAC-SHA256(K, x || suffix) = y` (statement `0x01`). It is a VOLE-in-the-head proof of 130,218 bytes.

From height 51000 the nodes of Ark-0 accept such a proof, in a P2MR leaf of version `0xe0`, in place of an
elliptic curve signature that the network's tripwire has disabled, with `y` the secret key of the key the
leaf checks. That is the M4-R series of
[bitcoin-p2mr-patches](https://github.com/duncan0k/bitcoin-p2mr-patches), which vendors the Rust crate of
this repository and specifies the rule in `doc/p2mr-rescue.md`. Ark-0 is a test network for trying things
out, and it may be reset at any time. Nothing here is part of a Bitcoin proposal.

| Path | What it is |
|---|---|
| `SPEC.md` | the specification, v0.2 revision 3; the version byte `0x02` is fixed |
| `NOTES.md` | measurements, design choices, and every review with what was done about it |
| `python/` | the reference implementation, prover and verifier |
| `rust/` | the crate `voleith`: verifier, constant-time prover and C ABI (`rust/README.md`) |
| `go/` | a verifier written from the specification and the vectors alone, with Go's standard library only |
| `vectors/` | test vectors of statement `0x01` and of the circuit gadgets |
| `crosscheck/` | runs the three verifiers on the same proofs and compares their verdicts, with its report |

**Status.** The proof system has had no external cryptographic review. Its security rests on an argument
in the classical random oracle model with a 128-bit target; against quantum attackers it is conjectured,
not proven (`SPEC.md`, sections 13 and 14). Two reviews by AI models of the final version found no forgery,
no malleability of the proof encoding and no way around the consensus rules (`NOTES.md`, "2026-10-24
review of the final version"). The Python prover is for the specification, tests and demonstrations with
test seeds; the Rust prover also for seeds used on Ark-0 alone (`SPEC.md`, section 14).

## License

MIT, see [`LICENSE`](LICENSE).
