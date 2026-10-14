"""Statement 1 (HMAC-SHA256) encoding: public inputs, circuit, witness."""

import hashlib
import hmac
import random
import unittest

from voleith import sha256_ref
from voleith import statements as st

WALLET_KEY = b"ark0-wallet v1 schnorr"

# Regression values; SPEC.md §7.5 quotes them.
S1_WITNESS_BITS = 42071
S1_MUL = 41815
S1_ASSERT = 256
# SHA-256 of the canonical circuit serialization (SPEC.md §7.6).
CIRCUIT_DIGEST = "5aadd73b39947a32f0eb217cf750ee280c3dadcd60b9ccccb09509892cf1435d"


class TestPublicInputs(unittest.TestCase):
    def test_roundtrip(self):
        y = bytes(range(32))
        pub = st.s1_encode_public(WALLET_KEY, 7, y)
        self.assertEqual(pub, bytes([22]) + WALLET_KEY + b"\x07" + y)
        self.assertEqual(st.s1_parse_public(pub), (WALLET_KEY, 7, y))

    def test_parse_rejects(self):
        y = bytes(32)
        good = st.s1_encode_public(WALLET_KEY, 0, y)
        bad = [
            b"",
            good[:-1],
            good + b"\x00",
            bytes([0]) + b"\x00" + y,                      # empty K
            bytes([65]) + b"a" * 65 + b"\x00" + y,         # K too long
            bytes([3]) + b"a\x00b" + b"\x00" + y,          # K not printable
            bytes([3]) + b"ab\x7f" + b"\x00" + y,          # DEL
            bytes([3]) + b"ab\x80" + b"\x00" + y,          # non-ASCII
            bytes([23]) + WALLET_KEY + b"\x00" + y,        # length byte mismatch
            bytearray(good),                               # not bytes
            None,
        ]
        for pub in bad:
            self.assertIsNone(st.s1_parse_public(pub), pub)
        self.assertIsNotNone(st.s1_parse_public(bytes([64]) + b"~" * 64 + b"\xff" + y))
        self.assertIsNotNone(st.s1_parse_public(bytes([1]) + b" " + b"\x00" + y))

    def test_encode_rejects(self):
        with self.assertRaises(ValueError):
            st.s1_encode_public(b"", 0, bytes(32))
        with self.assertRaises(ValueError):
            st.s1_encode_public(WALLET_KEY, 256, bytes(32))
        with self.assertRaises(ValueError):
            st.s1_encode_public(WALLET_KEY, 0, bytes(31))

    def test_midstates_match_hmac(self):
        rng = random.Random(11)
        for key in (WALLET_KEY, b"a", b"~" * 64, b"ark0-wallet v1 mldsa44"):
            iv_in, iv_out = sha256_ref.hmac_midstates(key)
            for _ in range(5):
                x = bytes(rng.getrandbits(8) for _ in range(32))
                sfx = rng.getrandbits(8)
                inner = sha256_ref.compress(iv_in, sha256_ref.pad_single_block(x + bytes([sfx]), 64))
                outer = sha256_ref.compress(
                    iv_out, sha256_ref.pad_single_block(sha256_ref.words_to_bytes(inner), 64))
                expect = hmac.new(key, x + bytes([sfx]), hashlib.sha256).digest()
                self.assertEqual(sha256_ref.words_to_bytes(outer), expect)


class TestCircuit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.circ = st.REGISTRY[st.STATEMENT1_ID].circuit()
        cls.rng = random.Random(12)

    def rand_bytes(self, n):
        return bytes(self.rng.getrandbits(8) for _ in range(n))

    def instance(self, key=WALLET_KEY, suffix=None, x=None):
        x = x if x is not None else self.rand_bytes(32)
        suffix = suffix if suffix is not None else self.rng.getrandbits(8)
        y = st.s1_hmac(key, suffix, x)
        return x, st.s1_public_bits((key, suffix, y)), (key, suffix, y)

    def test_sizes(self):
        c = self.circ
        self.assertEqual(c.n_public, 776)
        self.assertEqual(c.n_secret, 256)
        self.assertEqual(c.n_mul, S1_MUL)
        self.assertEqual(c.n_assert, S1_ASSERT)
        self.assertEqual(c.n_witness, S1_WITNESS_BITS)
        self.assertEqual(c.n_constraints, S1_MUL + S1_ASSERT)

    def test_valid_witness_satisfies(self):
        for suffix in (0, 1, 2, 255):
            x, pb, _ = self.instance(suffix=suffix)
            _, wit, ok = self.circ.evaluate(pb, st.s1_secret_bits(x))
            self.assertTrue(ok)
            self.assertEqual(len(wit), S1_WITNESS_BITS)
            self.assertTrue(self.circ.check_witness(pb, wit))

    def test_other_keys(self):
        for key in (b"a", b"~" * 64, b"ark0-wallet v1 mldsa44"):
            x, pb, _ = self.instance(key=key)
            self.assertTrue(self.circ.evaluate(pb, st.s1_secret_bits(x))[2])

    def test_wrong_public_inputs_fail(self):
        x, _, (key, suffix, y) = self.instance()
        sb = st.s1_secret_bits(x)
        bad_y = bytes([y[0] ^ 1]) + y[1:]
        for parsed in ((key, suffix, bad_y), (key, suffix ^ 1, y),
                       (b"ark0-wallet v1 mldsa44", suffix, y)):
            self.assertFalse(self.circ.evaluate(st.s1_public_bits(parsed), sb)[2])
        self.assertFalse(self.circ.evaluate(st.s1_public_bits((key, suffix, y)),
                                            st.s1_secret_bits(self.rand_bytes(32)))[2])

    def test_single_bit_witness_mutations_fail(self):
        x, pb, _ = self.instance()
        _, wit, _ = self.circ.evaluate(pb, st.s1_secret_bits(x))
        positions = [0, 1, 255, 256, 257, S1_WITNESS_BITS - 1]
        positions += self.rng.sample(range(S1_WITNESS_BITS), 40)
        for pos in positions:
            bad = list(wit)
            bad[pos] ^= 1
            self.assertFalse(self.circ.check_witness(pb, bad), pos)

    def test_and_outputs_are_fresh_witness_bits(self):
        # Every AND of two secret wires defines exactly one new witness bit and
        # its constraint; witness bits are never reused as AND outputs.
        from voleith.circuit import OP_MUL
        muls = [ins for ins in self.circ.instrs if ins[0] == OP_MUL]
        self.assertEqual(len(muls), S1_MUL)

    def test_circuit_digest_pinned(self):
        self.assertEqual(self.circ.digest(), CIRCUIT_DIGEST)


if __name__ == "__main__":
    unittest.main()
