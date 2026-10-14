"""The SHA-256 compression circuit generator against hashlib and FIPS 180-4."""

import hashlib
import random
import unittest

from voleith import sha256_ref
from voleith import sha256_gadgets as g
from voleith.circuit import OP_XOR, OP_AND, OP_NOT, OP_MUL


class TestReferenceCompression(unittest.TestCase):
    def test_against_hashlib_single_block(self):
        rng = random.Random(1)
        for n in range(56):
            msg = bytes(rng.getrandbits(8) for _ in range(n))
            block = sha256_ref.pad_single_block(msg, 0)
            got = sha256_ref.words_to_bytes(sha256_ref.compress(sha256_ref.IV, block))
            self.assertEqual(got, hashlib.sha256(msg).digest())

    def test_against_hashlib_two_blocks(self):
        rng = random.Random(2)
        for n in range(0, 56, 5):
            m1 = bytes(rng.getrandbits(8) for _ in range(64))
            m2 = bytes(rng.getrandbits(8) for _ in range(n))
            mid = sha256_ref.compress(sha256_ref.IV, m1)
            out = sha256_ref.compress(mid, sha256_ref.pad_single_block(m2, 64))
            self.assertEqual(sha256_ref.words_to_bytes(out), hashlib.sha256(m1 + m2).digest())


class TestCompressionCircuit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.circ = g.build_compression_circuit()

    def run_circuit(self, state, block):
        vals, _, ok = self.circ.evaluate([], g.compression_inputs(state, block))
        self.assertTrue(ok)
        return g.words_from_bits(self.circ.output_bits(vals))

    def test_gate_types_only_xor_and_not(self):
        ops = {ins[0] for ins in self.circ.instrs}
        self.assertLessEqual(ops, {OP_XOR, OP_AND, OP_NOT, OP_MUL})
        self.assertEqual(self.circ.n_public, 0)
        self.assertEqual(self.circ.n_secret, 768)
        self.assertEqual(len(self.circ.outputs), 256)

    def test_gate_counts(self):
        c = self.circ.counts()
        self.assertEqual(c["AND"], 22573)
        self.assertEqual(c["AND_secret_secret"], 22573)
        self.assertEqual(c["XOR"], 111607)
        self.assertEqual(c["NOT"], 1891)
        self.assertEqual(c["ASSERT"], 0)

    def test_random_states_and_blocks(self):
        rng = random.Random(3)
        for _ in range(200):
            state = [rng.getrandbits(32) for _ in range(8)]
            block = bytes(rng.getrandbits(8) for _ in range(64))
            self.assertEqual(self.run_circuit(state, block), sha256_ref.compress(state, block))

    def test_hashlib_single_block_messages(self):
        rng = random.Random(4)
        for n in range(56):
            msg = bytes(rng.getrandbits(8) for _ in range(n))
            out = self.run_circuit(sha256_ref.IV, sha256_ref.pad_single_block(msg, 0))
            self.assertEqual(sha256_ref.words_to_bytes(out), hashlib.sha256(msg).digest())

    def test_hashlib_chained_two_block_messages(self):
        rng = random.Random(5)
        for _ in range(30):
            m1 = bytes(rng.getrandbits(8) for _ in range(64))
            m2 = bytes(rng.getrandbits(8) for _ in range(rng.randrange(56)))
            mid = self.run_circuit(sha256_ref.IV, m1)
            out = self.run_circuit(mid, sha256_ref.pad_single_block(m2, 64))
            self.assertEqual(sha256_ref.words_to_bytes(out), hashlib.sha256(m1 + m2).digest())

    def test_edge_inputs(self):
        for state in ([0] * 8, [0xFFFFFFFF] * 8):
            for block in (bytes(64), b"\xff" * 64):
                self.assertEqual(self.run_circuit(state, block), sha256_ref.compress(state, block))


if __name__ == "__main__":
    unittest.main()
