"""The per-gadget circuit digests in vectors/gadgets-v0.2.json (SPEC.md §7.6)."""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "..", "vectors", "gadgets-v0.2.json")
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import gen_gadget_vectors as gen  # noqa: E402

LABEL = b"VOLEitH-rescue circuit v0.1\x00"
OPERANDS = {1: 2, 2: 2, 3: 1, 4: 3}  # XOR, AND, NOT, ASSERT
NAMES = {1: "XOR", 2: "AND", 3: "NOT", 4: "ASSERT"}


def parse(ser):
    """Parse a serialization with the grammar of SPEC.md §7.6."""
    def u32(off):
        return int.from_bytes(ser[off:off + 4], "little"), off + 4

    if not ser.startswith(LABEL):
        raise ValueError("label")
    off = len(LABEL)
    n_pub, off = u32(off)
    n_sec, off = u32(off)
    n_ins, off = u32(off)
    instrs = []
    for _ in range(n_ins):
        op = ser[off]
        off += 1
        args = []
        for _ in range(OPERANDS[op]):
            a, off = u32(off)
            args.append(a)
        instrs.append((op, args))
    n_out, off = u32(off)
    outputs = []
    for _ in range(n_out):
        w, off = u32(off)
        outputs.append(w)
    if off != len(ser):
        raise ValueError("trailing bytes")
    return n_pub, n_sec, instrs, outputs


class TestGadgetVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS, encoding="utf-8") as f:
            cls.doc = json.load(f)
        cls.by_name = {c["name"]: c for c in cls.doc["circuits"]}

    def test_file_matches_generator(self):
        self.assertEqual(self.doc, gen.build_document())

    def test_required_gadgets_present(self):
        for name in ("add_sec_sec", "add_sec_pub", "add_sec_const", "add_multi_mixed",
                     "ch_sec", "ch_sec_pub_pub", "maj_sec", "maj_sec_pub_pub",
                     "maj_mixed_bits", "big_sigma0_sec", "big_sigma1_sec",
                     "small_sigma0_sec", "small_sigma1_sec", "assert_add_sec_sec_pub",
                     "compress_pub_block"):
            self.assertIn(name, self.by_name)

    def test_hex_serializations_follow_the_grammar(self):
        n = 0
        for c in self.doc["circuits"]:
            if "serialization_hex" not in c:
                continue
            n += 1
            ser = bytes.fromhex(c["serialization_hex"])
            self.assertEqual(len(ser), c["serialization_len"])
            n_pub, n_sec, instrs, outputs = parse(ser)
            self.assertEqual((n_pub, n_sec), (c["n_public"], c["n_secret"]))
            self.assertEqual(len(instrs), c["n_instructions"])
            self.assertEqual(len(outputs), c["n_outputs"])
            counts = {"XOR": 0, "AND": 0, "NOT": 0, "ASSERT": 0}
            for op, _ in instrs:
                counts[NAMES[op]] += 1
            for k, v in counts.items():
                self.assertEqual(v, c["gate_counts"][k], (c["name"], k))
            # Every operand and output is a constant, an input or an earlier wire.
            wire = 2 + n_pub + n_sec
            for op, args in instrs:
                for a in args:
                    self.assertLess(a, wire, c["name"])
                if op != 4:
                    wire += 1
            for w in outputs:
                self.assertLess(w, wire, c["name"])
        self.assertGreater(n, 10)

    def test_add_costs(self):
        # SPEC.md §7.4: 31 MULs for SEC + SEC, 30 with a public addend,
        # 30 - tz(κ) with a constant addend κ (tz(0x428a2f98) = 3).
        mul = {k: c["gate_counts"]["AND_secret_secret"] for k, c in self.by_name.items()}
        self.assertEqual(mul["add_sec_sec"], 31)
        self.assertEqual(mul["add_sec_pub"], 30)
        self.assertEqual(mul["add_pub_sec"], 30)
        self.assertEqual(mul["add_sec_const"], 27)
        self.assertEqual(self.by_name["assert_add_sec_sec_pub"]["gate_counts"]["ASSERT"], 32)

    def test_public_words_do_not_fold(self):
        # SPEC.md §7.2: only constants fold, so Σ0 on a PUB word emits the
        # same 64 XORs as on a SEC word, and a compression with a PUB block
        # has the gate counts of the all-SEC standalone circuit.
        self.assertEqual(self.by_name["big_sigma0_pub"]["gate_counts"],
                         self.by_name["big_sigma0_sec"]["gate_counts"])
        c = self.by_name["compress_pub_block"]["gate_counts"]
        self.assertEqual((c["AND"], c["XOR"], c["NOT"]), (22573, 111607, 1891))


if __name__ == "__main__":
    unittest.main()
