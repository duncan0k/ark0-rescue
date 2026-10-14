"""The fixed-rng known-answer vectors in vectors/statement1-v0.2.json."""

import hashlib
import json
import os
import unittest

import voleith
from voleith import params
from voleith import proof as P
from voleith import statements as st

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "vectors", "statement1-v0.2.json")


class TestVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, encoding="utf-8") as f:
            cls.doc = json.load(f)

    def test_header(self):
        d = self.doc
        circ = st.REGISTRY[st.STATEMENT1_ID].circuit()
        self.assertEqual(d["circuit"]["sha256_of_serialization"], circ.digest())
        self.assertEqual(d["circuit"]["n_witness"], circ.n_witness)
        self.assertEqual(d["proof_len"], voleith.proof_length(st.STATEMENT1_ID))
        self.assertEqual(d["protocol_version_byte"], params.VERSION)
        s = params.SPLIT
        self.assertEqual((d["params"]["tau"], d["params"]["tau0"], d["params"]["k0"],
                          d["params"]["tau1"], d["params"]["k1"]),
                         (s.tau, s.tau0, s.k0, s.tau1, s.k1))
        self.assertGreaterEqual(len(d["vectors"]), 3)

    def test_vectors_reproduce_and_verify(self):
        for v in self.doc["vectors"]:
            key = v["K_ascii"].encode("ascii")
            x = bytes.fromhex(v["witness_x"])
            y = bytes.fromhex(v["y"])
            self.assertEqual(st.s1_hmac(key, v["suffix"], x), y)
            stmt = voleith.statement1(key, v["suffix"], y)
            self.assertEqual(stmt.public_inputs.hex(), v["public_inputs"])
            msg = bytes.fromhex(v["message"])
            proof = bytes.fromhex(v["proof"])
            self.assertEqual(len(proof), v["proof_len"])
            self.assertEqual(hashlib.sha256(proof).hexdigest(), v["proof_sha256"])
            self.assertTrue(voleith.verify(stmt, msg, proof))
            rho = bytes.fromhex(v["rho"])
            again, trace = P._prove_impl(stmt, x, msg, lambda n: rho,
                                         enforce_relation=True, trace=True)
            self.assertEqual(again, proof, v["description"])
            for k, hexval in v["intermediates"].items():
                self.assertEqual(trace[k].hex(), hexval, k)


def apply_edit(proof, edit):
    op = edit["op"]
    if op == "none":
        return proof
    if op == "xor":
        b = bytearray(proof)
        b[edit["offset"]] ^= int(edit["mask"], 16)
        return bytes(b)
    if op == "truncate":
        return proof[:edit["length"]]
    if op == "append":
        return proof + bytes.fromhex(edit["data"])
    raise ValueError(op)


class TestNegativeVectors(unittest.TestCase):
    def test_negative_vectors_reject(self):
        with open(VECTORS, encoding="utf-8") as f:
            doc = json.load(f)
        negs = doc["negative_vectors"]
        self.assertGreaterEqual(len(negs), 30)
        for nv in negs:
            base = bytes.fromhex(doc["vectors"][nv["base_vector"]]["proof"])
            proof = apply_edit(base, nv["proof_edit"])
            stmt = voleith.Statement(nv["statement_id"], bytes.fromhex(nv["public_inputs"]))
            msg = bytes.fromhex(nv["message"])
            self.assertIs(nv["expected"], False)
            self.assertIs(voleith.verify(stmt, msg, proof), False, nv["description"])


if __name__ == "__main__":
    unittest.main()
