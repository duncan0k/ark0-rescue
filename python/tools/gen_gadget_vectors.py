"""Generate vectors/gadgets-v0.2.json (per-gadget circuit digests, SPEC.md §7.6).

Usage: python -I python/tools/gen_gadget_vectors.py [output path]

Each entry is a small circuit built with the gadgets of SPEC.md §7.4 and
serialized with the grammar of §7.6. A builder that disagrees with the
statement 0x01 digest can build these circuits one at a time and find the
first gadget whose digest differs.

Inputs are grouped into words: public word Pj is public input bits
[32j, 32j+32) and secret word Sj is secret input bits [32j, 32j+32), least
significant bit first. Unless an entry says otherwise, the outputs are the
32 wires of the returned word, bit 0 first.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

from voleith.circuit import Builder  # noqa: E402
from voleith import sha256_gadgets as g  # noqa: E402

K0 = 0x428A2F98  # FIPS 180-4 round constant K_0; three trailing zero bits.


def _words(wires, n):
    return [wires[32 * j:32 * j + 32] for j in range(n)]


def _maj_mixed_inputs(P, S):
    # x: bit i from S0 for even i, from P0 for odd i; y = P1;
    # z: bit i from S1 for odd i, from P2 for even i.
    x = [S[0][i] if i % 2 == 0 else P[0][i] for i in range(32)]
    z = [S[1][i] if i % 2 == 1 else P[2][i] for i in range(32)]
    return x, P[1], z


# (name, n_public words, n_secret words, construction text, build function).
# A build function takes (builder, public words, secret words) and returns
# the output wires.
CIRCUITS = [
    ("add_sec_sec", 0, 2, "add(S0, S1)",
     lambda b, P, S: g.add_w(b, S[0], S[1])),
    ("add_sec_pub", 1, 1, "add(S0, P0)",
     lambda b, P, S: g.add_w(b, S[0], P[0])),
    ("add_pub_sec", 1, 1, "add(P0, S0)",
     lambda b, P, S: g.add_w(b, P[0], S[0])),
    ("add_sec_const", 0, 1, "add(S0, const_word(0x428a2f98))",
     lambda b, P, S: g.add_w(b, S[0], g.const_word(K0))),
    ("add_multi_mixed", 2, 2,
     "add_multi([S0, P0, const_word(0), const_word(0x428a2f98), S1, P1])",
     lambda b, P, S: g.add_multi(b, [S[0], P[0], g.const_word(0), g.const_word(K0),
                                     S[1], P[1]])),
    ("xor_w_sec_const", 0, 1, "xor_w(S0, const_word(0x0000ffff))",
     lambda b, P, S: g.xor_w(b, S[0], g.const_word(0x0000FFFF))),
    ("ch_sec", 0, 3, "Ch(S0, S1, S2)",
     lambda b, P, S: g.ch(b, S[0], S[1], S[2])),
    ("ch_sec_pub_pub", 2, 1, "Ch(S0, P0, P1)",
     lambda b, P, S: g.ch(b, S[0], P[0], P[1])),
    ("ch_pub_sec_sec", 1, 2, "Ch(P0, S0, S1)",
     lambda b, P, S: g.ch(b, P[0], S[0], S[1])),
    ("maj_sec", 0, 3, "Maj(S0, S1, S2)",
     lambda b, P, S: g.maj(b, S[0], S[1], S[2])),
    ("maj_sec_pub_pub", 2, 1, "Maj(S0, P0, P1)",
     lambda b, P, S: g.maj(b, S[0], P[0], P[1])),
    ("maj_mixed_bits", 3, 2,
     "Maj(x, P1, z) with x[i] = S0[i] for even i, P0[i] for odd i, "
     "and z[i] = S1[i] for odd i, P2[i] for even i",
     lambda b, P, S: g.maj(b, *_maj_mixed_inputs(P, S))),
    ("big_sigma0_sec", 0, 1, "Σ0(S0)",
     lambda b, P, S: g.big_sigma0(b, S[0])),
    ("big_sigma1_sec", 0, 1, "Σ1(S0)",
     lambda b, P, S: g.big_sigma1(b, S[0])),
    ("small_sigma0_sec", 0, 1, "σ0(S0)",
     lambda b, P, S: g.small_sigma0(b, S[0])),
    ("small_sigma1_sec", 0, 1, "σ1(S0)",
     lambda b, P, S: g.small_sigma1(b, S[0])),
    ("big_sigma0_pub", 1, 0, "Σ0(P0)",
     lambda b, P, S: g.big_sigma0(b, P[0])),
    ("assert_add_sec_sec_pub", 1, 2, "assert_add(S0, S1, P0); no outputs",
     lambda b, P, S: g.assert_add(b, S[0], S[1], P[0])),
    ("assert_add_sec_pub_pub", 2, 1, "assert_add(S0, P0, P1); no outputs",
     lambda b, P, S: g.assert_add(b, S[0], P[0], P[1])),
    ("compress_pub_block", 16, 8,
     "compress(H = [S0..S7], W = [P0..P15]) without S; outputs: bit i of "
     "output word w is output 32w + i",
     lambda b, P, S: [x for w in g.compress(b, S[:8], P[:16]) for x in w]),
]

# Entries whose serialization is at most this long also carry it in hex.
HEX_LIMIT = 2048


def build(entry):
    _, n_pub, n_sec, _, fn = entry
    b = Builder(32 * n_pub, 32 * n_sec)
    out = fn(b, _words(b.public, n_pub), _words(b.secret, n_sec))
    b.outputs = list(out) if out is not None else []
    return b.build()


def make_entry(entry):
    name, n_pub, n_sec, text, _ = entry
    circ = build(entry)
    ser = circ.serialize()
    c = circ.counts()
    e = {
        "name": name,
        "construction": text,
        "n_public": 32 * n_pub,
        "n_secret": 32 * n_sec,
        "n_instructions": len(circ.instrs),
        "n_outputs": len(circ.outputs),
        "gate_counts": {"XOR": c["XOR"], "AND": c["AND"], "NOT": c["NOT"],
                        "ASSERT": c["ASSERT"],
                        "AND_secret_secret": c["AND_secret_secret"]},
        "serialization_len": len(ser),
        "sha256_of_serialization": hashlib.sha256(ser).hexdigest(),
    }
    if len(ser) <= HEX_LIMIT:
        e["serialization_hex"] = ser.hex()
    return e


def build_document():
    return {
        "spec": "SPEC.md v0.2, revision 2",
        "description": "Small circuits built with the gadgets of SPEC.md §7.4 and "
                       "serialized as in §7.6, for localising a builder mismatch.",
        "inputs": "Public word Pj is public input bits [32j, 32j+32); secret word Sj "
                  "is secret input bits [32j, 32j+32); bit 0 first. Unless the "
                  "construction says otherwise, the outputs are the 32 wires of the "
                  "returned word, bit 0 first.",
        "circuits": [make_entry(e) for e in CIRCUITS],
    }


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        HERE, "..", "..", "vectors", "gadgets-v0.2.json")
    doc = build_document()
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print("wrote", out, len(doc["circuits"]), "circuits")


if __name__ == "__main__":
    main()
