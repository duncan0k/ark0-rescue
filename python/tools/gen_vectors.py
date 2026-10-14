"""Generate vectors/statement1-v0.1.json (fixed-rng known-answer vectors).

Usage: python -I python/tools/gen_vectors.py [output path]

Each vector fixes the prover randomness rho, so the proof bytes are fully
determined by (statement, witness, message, rho). The intermediates are for
localising mismatches in an independent implementation.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import voleith  # noqa: E402
from voleith import proof as P  # noqa: E402
from voleith import statements as st  # noqa: E402
from voleith import params  # noqa: E402

TRACE_KEYS = ("mu", "r", "iv_pre", "iv", "roots", "tree_hashes", "hcom", "chall1",
              "u_tilde", "h_v", "chall2", "a_tilde", "b_tilde", "chall3")


def sha(s):
    return hashlib.sha256(s).digest()


def synthetic_message(i):
    # Synthetic stand-ins for rescue sighash || network id || public key.
    return sha(b"vector %d sighash" % i) + sha(b"vector network id") + sha(b"vector %d pubkey" % i)


CASES = [
    # (description, K, suffix, seed label, message, rho label)
    ("web wallet v1 derivation, suffix 0", b"ark0-wallet v1 schnorr", 0, b"seed 0",
     synthetic_message(0), b"rho 0"),
    ("web wallet v1 derivation, suffix 1", b"ark0-wallet v1 schnorr", 1, b"seed 1",
     synthetic_message(1), b"rho 1"),
    ("web wallet v1 derivation, suffix 255, empty message", b"ark0-wallet v1 schnorr", 255,
     b"seed 2", b"", b"rho 2"),
    ("other key label, one-byte message", b"VOLEitH test label ~ 0123456789", 7, b"seed 3",
     b"\x00", b"rho 3"),
]


def make_vector(desc, key, suffix, seed_label, message, rho_label):
    x = sha(b"voleith vector " + seed_label)
    rho = hashlib.shake_256(b"voleith vector " + rho_label).digest(params.RHO_BYTES)
    stmt = voleith.statement1_for_seed(key, suffix, x)
    proof, trace = P._prove_impl(stmt, x, message, lambda n: rho, enforce_relation=True,
                                 trace=True)
    if not voleith.verify(stmt, message, proof):
        raise SystemExit("generated proof does not verify")
    _, _, y = st.s1_parse_public(stmt.public_inputs)
    return {
        "description": desc,
        "statement_id": stmt.statement_id,
        "K_ascii": key.decode("ascii"),
        "suffix": suffix,
        "y": y.hex(),
        "public_inputs": stmt.public_inputs.hex(),
        "witness_x": x.hex(),
        "message": message.hex(),
        "rho": rho.hex(),
        "proof_len": len(proof),
        "proof_sha256": hashlib.sha256(proof).hexdigest(),
        "intermediates": {k: trace[k].hex() for k in TRACE_KEYS},
        "proof": proof.hex(),
    }


def negative_vectors(base, lay):
    """Must-reject cases derived from vector `base` (SPEC §11)."""
    pub0 = bytes.fromhex(base["public_inputs"])
    msg0 = bytes.fromhex(base["message"])
    key, suffix, y = st.s1_parse_public(pub0)
    out = []

    def add(desc, edit, pub=pub0, msg=msg0, sid=st.STATEMENT1_ID):
        out.append({"description": desc, "base_vector": 0, "statement_id": sid,
                    "public_inputs": pub.hex(), "message": msg.hex(),
                    "proof_edit": edit, "expected": False})

    def xor(offset, mask):
        return {"op": "xor", "offset": offset, "mask": "%02x" % mask}

    none = {"op": "none"}
    tau = lay.split.tau
    depths = lay.split.depths
    v = params.VERSION
    add("version byte 0x%02x -> 0x%02x" % (v, v ^ 0x01), xor(0, 0x01))
    add("version byte 0x%02x -> 0x%02x" % (v, v ^ 0x03), xor(0, 0x03))
    add("statement id byte 0x01 -> 0x03", xor(1, 0x02))
    add("iv_pre bit flip", xor(lay.off_iv_pre + 5, 0x01))
    for i in range(tau - 1):
        add("padding bit of c_%d set" % (i + 1), xor(lay.off_c + (i + 1) * lay.c_bytes - 1, 0x80))
    add("c_1 first byte bit flip", xor(lay.off_c, 0x01))
    add("c_%d last data bit flip" % (tau - 1), xor(lay.off_c + (tau - 1) * lay.c_bytes - 1, 0x01))
    add("u_tilde first byte bit flip", xor(lay.off_u_tilde, 0x01))
    add("u_tilde last byte bit flip", xor(lay.off_u_tilde + 31, 0x80))
    add("d first byte bit flip", xor(lay.off_d, 0x01))
    add("d last data bit flip", xor(lay.off_d + lay.d_bytes - 1, 0x01))
    add("padding bit of d set", xor(lay.off_d + lay.d_bytes - 1, 0x80))
    add("a_tilde bit flip", xor(lay.off_a_tilde + 3, 0x01))
    add("tree 0 co-path seed at depth 1", xor(lay.open_offsets[0], 0x01))
    add("tree 7 co-path seed at depth %d" % depths[7],
        xor(lay.open_offsets[7] + (depths[7] - 1) * 16 + 3, 0x01))
    add("tree %d hidden-leaf commitment" % (tau - 1),
        xor(lay.open_offsets[tau - 1] + depths[tau - 1] * 16 + 31, 0x01))
    add("chall3 first byte bit flip", xor(lay.off_chall3, 0x01))
    add("chall3 last byte bit flip", xor(lay.off_chall3 + 15, 0x80))
    add("proof truncated by one byte", {"op": "truncate", "length": lay.total - 1})
    add("empty proof", {"op": "truncate", "length": 0})
    add("proof with one extra byte", {"op": "append", "data": "00"})
    add("message with an extra byte", none, msg=msg0 + b"\x00")
    add("empty message", none, msg=b"")
    add("message bit flip", none, msg=bytes([msg0[0] ^ 1]) + msg0[1:])
    add("y bit flip", none, pub=st.s1_encode_public(key, suffix, bytes([y[0] ^ 1]) + y[1:]))
    add("other K", none, pub=st.s1_encode_public(b"ark0-wallet v1 mldsa44", suffix, y))
    add("suffix + 1", none, pub=st.s1_encode_public(key, suffix ^ 1, y))
    add("statement id 0x02 (unregistered)", none, sid=2)
    add("public inputs with a trailing byte", none, pub=pub0 + b"\x00")
    add("K length byte 0", none, pub=b"\x00" + pub0[1:])
    return out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        HERE, "..", "..", "vectors", "statement1-v0.1.json")
    circ = st.REGISTRY[st.STATEMENT1_ID].circuit()
    lay = P.layout(st.STATEMENT1_ID)
    doc = {
        "spec": "SPEC.md v0.1",
        "protocol_version_byte": params.VERSION,
        "params": {"lambda": params.LAMBDA, "tau": params.SPLIT.tau, "k": params.SPLIT.k0,
                   "rho_bytes": params.RHO_BYTES},
        "statement_id": st.STATEMENT1_ID,
        "circuit": {
            "sha256_of_serialization": circ.digest(),
            "n_public": circ.n_public,
            "n_secret_inputs": circ.n_secret,
            "n_witness": circ.n_witness,
            "n_constraints": circ.n_constraints,
            "n_and_secret_secret": circ.n_mul,
            "n_assert": circ.n_assert,
            "gate_counts": circ.counts(),
        },
        "proof_len": lay.total,
        "rng_note": "the prover calls rng(32) exactly once; rho is that output",
        "vectors": [make_vector(*c) for c in CASES],
    }
    doc["negative_note"] = ("each negative vector applies proof_edit to the proof of "
                            "vectors[base_vector] and verifies it against the given "
                            "statement id, public inputs and message; verify must return false")
    doc["negative_vectors"] = negative_vectors(doc["vectors"][0], lay)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote", os.path.normpath(out))


if __name__ == "__main__":
    main()
