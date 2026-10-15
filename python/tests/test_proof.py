"""End-to-end prove/verify for statement 1, with negative tests."""

import hashlib
import random
import unittest

import voleith
from voleith import proof as P
from voleith import statements as st
from voleith.params import LAMBDA, MAX_MESSAGE_LEN, SPLIT, VERSION
from voleith import vc

WALLET_KEY = b"ark0-wallet v1 schnorr"
TAU = SPLIT.tau
PROOF_LEN = 2082 + 5339 * TAU  # SPEC.md §10 for statement 0x01


def seeded_rng(seed):
    """Deterministic rng(n) for tests and known-answer vectors."""
    state = {"ctr": 0}

    def rng(n):
        out = hashlib.shake_256(b"voleith-test-rng" + seed
                                + state["ctr"].to_bytes(4, "little")).digest(n)
        state["ctr"] += 1
        return out
    return rng


def sha(s):
    return hashlib.sha256(s).digest()


def wallet_case(i, suffix):
    x = sha(b"test seed %d" % i)
    stmt = voleith.statement1_for_seed(WALLET_KEY, suffix, x)
    msg = sha(b"rescue sighash %d" % i) + sha(b"network id") + sha(b"public key %d" % i)
    return x, stmt, msg


def flip(data, pos, mask=1):
    b = bytearray(data)
    b[pos] ^= mask
    return bytes(b)


class TestProofEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lay = P.layout(st.STATEMENT1_ID)
        cls.cases = []
        for i, suffix in enumerate((0, 1, 5)):
            x, stmt, msg = wallet_case(i, suffix)
            proof = voleith.prove(stmt, x, msg, rng=seeded_rng(b"case %d" % i))
            cls.cases.append((x, stmt, msg, proof))
        cls.x, cls.stmt, cls.msg, cls.proof = cls.cases[0]

    def assertRejects(self, stmt, msg, proof, why=""):
        self.assertIs(voleith.verify(stmt, msg, proof), False, why)

    # ------------------------------------------------------------- positive
    def test_valid_proofs_verify(self):
        for x, stmt, msg, proof in self.cases:
            self.assertIs(voleith.verify(stmt, msg, proof), True)

    def test_random_seeds_and_os_rng(self):
        rnd = random.Random(31)
        for _ in range(2):
            x = rnd.randbytes(32)
            suffix = rnd.randrange(256)
            stmt = voleith.statement1_for_seed(WALLET_KEY, suffix, x)
            msg = rnd.randbytes(rnd.randrange(200))
            proof = voleith.prove(stmt, x, msg)  # default rng: os.urandom
            self.assertTrue(voleith.verify(stmt, msg, proof))

    def test_empty_and_max_messages(self):
        for msg in (b"", bytes(MAX_MESSAGE_LEN)):
            proof = voleith.prove(self.stmt, self.x, msg, rng=seeded_rng(b"m"))
            self.assertTrue(voleith.verify(self.stmt, msg, proof))
        with self.assertRaises(ValueError):
            voleith.prove(self.stmt, self.x, bytes(MAX_MESSAGE_LEN + 1))

    def test_length_matches_formula(self):
        ell = st.REGISTRY[1].circuit().n_witness
        lhat = ell + 3 * LAMBDA
        formula = (2 + 16 + (TAU - 1) * ((lhat + 7) // 8) + 32 + (ell + 7) // 8 + 16
                   + sum(k * 16 + 32 for k in SPLIT.depths) + 16)
        self.assertEqual(sum(vc.opening_bytes(k) for k in SPLIT.depths), 2048 + 32 * TAU)
        self.assertEqual(formula, PROOF_LEN)
        self.assertEqual(voleith.proof_length(1), PROOF_LEN)
        for _, _, _, proof in self.cases:
            self.assertEqual(len(proof), PROOF_LEN)

    def test_determinism(self):
        x, stmt, msg, proof = self.cases[1]
        again = voleith.prove(stmt, x, msg, rng=seeded_rng(b"case 1"))
        self.assertEqual(again, proof)
        other = voleith.prove(stmt, x, msg, rng=seeded_rng(b"other"))
        self.assertNotEqual(other, proof)
        self.assertTrue(voleith.verify(stmt, msg, other))

    # ------------------------------------------------------- proof sections
    def test_flip_each_section(self):
        lay = self.lay
        positions = {
            "iv_pre": lay.off_iv_pre + 5,
            "c_1 first": lay.off_c,
            "c_8 middle": lay.off_c + 7 * lay.c_bytes + lay.c_bytes // 2,
            "last c last data bit": lay.off_c + (TAU - 1) * lay.c_bytes - 1,
            "u_tilde first": lay.off_u_tilde,
            "u_tilde last": lay.off_u_tilde + 31,
            "d first": lay.off_d,
            "d last data bit": lay.off_d + lay.d_bytes - 1,
            "a_tilde": lay.off_a_tilde + 3,
            "tree 0 co-path top": lay.off_open,
            "tree 7 co-path leaf level": lay.open_offsets[7] + (SPLIT.depths[7] - 1) * 16 + 3,
            "last tree hidden commitment": (lay.open_offsets[TAU - 1]
                                            + SPLIT.depths[TAU - 1] * 16 + 31),
            "chall3 first": lay.off_chall3,
            "chall3 last": lay.off_chall3 + 15,
        }
        for name, pos in positions.items():
            self.assertRejects(self.stmt, self.msg, flip(self.proof, pos), name)

    def test_header(self):
        self.assertRejects(self.stmt, self.msg, flip(self.proof, 0), "version")
        self.assertRejects(self.stmt, self.msg, flip(self.proof, 1), "statement id byte")
        self.assertRejects(self.stmt, self.msg, bytes([0x01]) + self.proof[1:], "version 1")
        self.assertRejects(self.stmt, self.msg, bytes([0x03]) + self.proof[1:], "version 3")

    def test_nonzero_padding_bits(self):
        lay = self.lay
        self.assertEqual(lay.lhat % 8, 7)
        self.assertEqual(lay.ell % 8, 7)
        self.assertRejects(self.stmt, self.msg,
                           flip(self.proof, lay.off_c + lay.c_bytes - 1, 0x80), "c_1 pad")
        self.assertRejects(self.stmt, self.msg,
                           flip(self.proof, lay.off_d + lay.d_bytes - 1, 0x80), "d pad")

    def test_random_flips(self):
        rnd = random.Random(32)
        for _ in range(4):
            pos = rnd.randrange(PROOF_LEN)
            self.assertRejects(self.stmt, self.msg, flip(self.proof, pos, 1 << rnd.randrange(8)))

    def test_truncated_and_extended(self):
        p = self.proof
        for bad in (b"", p[:1], p[:2], p[:-1], p[:-16], p[:PROOF_LEN // 2],
                    p + b"\x00", p + p[:16], p + bytes(1000)):
            self.assertRejects(self.stmt, self.msg, bad, len(bad))

    def test_format_checks_do_not_build_the_circuit(self):
        """Malformed inputs are rejected before the circuit is built (SPEC
        §11), so the first call in a process does not pay for it."""
        lay = self.lay
        bad_proofs = (b"", self.proof[:-1], self.proof + b"\x00", flip(self.proof, 0),
                      flip(self.proof, 1), flip(self.proof, lay.off_c + lay.c_bytes - 1, 0x80),
                      flip(self.proof, lay.off_d + lay.d_bytes - 1, 0x80))
        saved = st._Statement1._circuit
        st._Statement1._circuit = None
        P._LAYOUTS.clear()
        try:
            for bad in bad_proofs:
                self.assertRejects(self.stmt, self.msg, bad)
            self.assertRejects(voleith.Statement(2, self.stmt.public_inputs), self.msg,
                               self.proof)
            self.assertRejects(voleith.Statement(1, self.stmt.public_inputs[1:]), self.msg,
                               self.proof)
            self.assertRejects(self.stmt, bytes(MAX_MESSAGE_LEN + 1), self.proof)
            self.assertIsNone(st._Statement1._circuit)
            # A structurally valid input builds it.
            self.assertTrue(voleith.verify(self.stmt, self.msg, self.proof))
            self.assertIsNotNone(st._Statement1._circuit)
        finally:
            st._Statement1._circuit = saved

    def test_garbage_of_correct_length(self):
        rnd = random.Random(33)
        body = rnd.randbytes(PROOF_LEN - 2)
        self.assertRejects(self.stmt, self.msg, bytes([VERSION, 1]) + body)
        self.assertRejects(self.stmt, self.msg, bytes(PROOF_LEN))

    # ------------------------------------------------- statement and message
    def test_wrong_message(self):
        for msg in (self.msg[:-1], self.msg + b"\x00", b"", flip(self.msg, 0),
                    self.cases[1][2]):
            self.assertRejects(self.stmt, msg, self.proof)

    def test_wrong_public_inputs(self):
        key, suffix, y = st.s1_parse_public(self.stmt.public_inputs)
        bad = [
            voleith.statement1(key, suffix, flip(y, 31, 0x80)),
            voleith.statement1(key, suffix ^ 1, y),
            voleith.statement1(b"ark0-wallet v1 mldsa44", suffix, y),
            voleith.statement1(key + b" ", suffix, y),
            self.cases[1][1],
        ]
        for stmt in bad:
            self.assertRejects(stmt, self.msg, self.proof)

    def test_wrong_statement_id_and_types(self):
        pub = self.stmt.public_inputs
        for stmt in (voleith.Statement(2, pub), voleith.Statement(0, pub),
                     voleith.Statement(True, pub), voleith.Statement(1, bytearray(pub)),
                     voleith.Statement(1, pub + b"\x00"), voleith.Statement(1, b""),
                     (1, pub), None):
            self.assertRejects(stmt, self.msg, self.proof, repr(stmt)[:40])
        self.assertRejects(self.stmt, self.msg.decode("latin-1"), self.proof)
        self.assertRejects(self.stmt, bytearray(self.msg), self.proof)
        self.assertRejects(self.stmt, self.msg, bytearray(self.proof))
        self.assertRejects(self.stmt, self.msg, self.proof.hex())
        self.assertRejects(self.stmt, self.msg, None)
        self.assertRejects(self.stmt, bytes(MAX_MESSAGE_LEN + 1), self.proof)

    def test_proof_moved_between_cases(self):
        _, stmt1, msg1, proof1 = self.cases[1]
        self.assertRejects(self.stmt, self.msg, proof1)
        self.assertRejects(stmt1, self.msg, proof1)
        self.assertRejects(self.stmt, msg1, proof1)

    # ------------------------------------------------------- cheating prover
    def test_prover_refuses_invalid_witness(self):
        with self.assertRaises(ValueError):
            voleith.prove(self.stmt, flip(self.x, 0), self.msg, rng=seeded_rng(b"x"))
        with self.assertRaises(ValueError):
            voleith.prove(self.stmt, self.x[:31], self.msg)
        with self.assertRaises(ValueError):
            voleith.prove(voleith.Statement(9, b""), self.x, self.msg)

    def test_prover_rejects_non_int_statement_id(self):
        pub = self.stmt.public_inputs
        for sid in (True, 1.0, [1], None):
            with self.assertRaises(ValueError):
                voleith.prove(voleith.Statement(sid, pub), self.x, self.msg)

    def test_vole_consistency_check_is_load_bearing(self):
        """Wrong corrections c_i on rows QuickSilver never reads are caught by
        the VOLE consistency check alone (SPEC §5.4)."""
        lay = self.lay
        hash_mask_row = lay.ell + 128 + 5

        def run(tamper, seed):
            proof, _ = P._prove_impl(self.stmt, self.x, self.msg, seeded_rng(seed),
                                     enforce_relation=False, tamper_corrections=tamper)
            self.assertEqual(len(proof), PROOF_LEN)
            return proof

        # Control: the hook itself changes nothing.
        self.assertTrue(voleith.verify(self.stmt, self.msg, run(lambda cs, _: cs, b"t0")))

        # All corrections wrong: rejected unless every delta_i with i >= 1 is 0.
        for row in (hash_mask_row, lay.ell + 3, 7):
            def tamper_all(cs, _, row=row):
                return [c ^ (1 << row) for c in cs]
            self.assertRejects(self.stmt, self.msg, run(tamper_all, b"t1"), row)

        # Only c_4 wrong: undetectable exactly when delta_4 = 0 (the prover
        # "guessed" tree 4's challenge), rejected otherwise.
        def tamper_one(cs, _):
            cs[3] ^= 1 << hash_mask_row
            return cs
        for seed in (b"t2", b"t3", b"t4"):
            proof = run(tamper_one, seed)
            delta = int.from_bytes(proof[lay.off_chall3:lay.off_chall3 + 16], "little")
            delta_4 = SPLIT.challenge_index(delta, 4)
            self.assertIs(voleith.verify(self.stmt, self.msg, proof), delta_4 == 0, seed)

    def test_tampered_constraint_terms(self):
        """A prover that changes a single QuickSilver term A0_t or A1_t
        (SPEC §6.2) is caught by the final check: here the first constraint
        (a MUL), one in the middle and the last one (an ASSERT)."""
        n_constraints = st.REGISTRY[1].circuit().n_constraints

        def run(tamper, seed):
            proof, _ = P._prove_impl(self.stmt, self.x, self.msg, seeded_rng(seed),
                                     enforce_relation=False, tamper_terms=tamper)
            self.assertEqual(len(proof), PROOF_LEN)
            return proof

        # Control: the hook itself changes nothing.
        self.assertTrue(voleith.verify(self.stmt, self.msg, run(lambda a0, a1: (a0, a1), b"q0")))
        for t in (0, n_constraints // 2, n_constraints - 1):
            for which in (0, 1):
                def tamper(a0, a1, t=t, which=which):
                    (a0, a1)[which][t] ^= 1
                    return a0, a1
                self.assertRejects(self.stmt, self.msg, run(tamper, b"q1"), (t, which))

    def test_cheating_prover_with_wrong_seed(self):
        proof, _ = P._prove_impl(self.stmt, flip(self.x, 0), self.msg, seeded_rng(b"c1"),
                                 enforce_relation=False)
        self.assertEqual(len(proof), PROOF_LEN)
        self.assertRejects(self.stmt, self.msg, proof)

    def test_cheating_prover_with_inconsistent_witness(self):
        circ = st.REGISTRY[1].circuit()
        parsed = st.s1_parse_public(self.stmt.public_inputs)
        _, wit, ok = circ.evaluate(st.s1_public_bits(parsed), st.s1_secret_bits(self.x))
        self.assertTrue(ok)
        for pos in (256, len(wit) - 1):
            bad = list(wit)
            bad[pos] ^= 1
            proof, _ = P._prove_impl(self.stmt, self.x, self.msg, seeded_rng(b"c2"),
                                     enforce_relation=False, witness_bits_override=bad)
            self.assertRejects(self.stmt, self.msg, proof, pos)


if __name__ == "__main__":
    unittest.main()
