"""Exhaustive tests of the gadgets at reduced word sizes (encoding soundness).

For each gadget and every input, the constraint system must have exactly one
satisfying witness, and it must encode the intended function.
"""

import itertools
import unittest

from voleith import sha256_gadgets as g
from voleith.circuit import Builder


def all_witness_extensions(circ, pub_bits, secret_bits):
    """Number of assignments to the AND outputs that satisfy every constraint."""
    count = 0
    for tail in itertools.product((0, 1), repeat=circ.n_mul):
        if circ.check_witness(pub_bits, list(secret_bits) + list(tail)):
            count += 1
    return count


def to_bits(v, n):
    return [(v >> i) & 1 for i in range(n)]


def from_bits(bs):
    return sum(b << i for i, b in enumerate(bs))


class TestAdder(unittest.TestCase):
    def test_secret_plus_secret(self):
        for n in (1, 2, 4, 6):
            b = Builder(0, 2 * n)
            out = g.add_w(b, b.secret[:n], b.secret[n:])
            b.outputs = out
            circ = b.build()
            self.assertEqual(circ.n_mul, n - 1)
            for x in range(1 << n):
                for y in range(1 << n):
                    sb = to_bits(x, n) + to_bits(y, n)
                    vals, wit, ok = circ.evaluate([], sb)
                    self.assertTrue(ok)
                    self.assertEqual(from_bits(circ.output_bits(vals)), (x + y) % (1 << n))
                    if n <= 4:
                        self.assertEqual(all_witness_extensions(circ, [], sb), 1)
                        self.assertTrue(circ.check_witness([], wit))

    def test_secret_plus_public(self):
        n = 6
        b = Builder(n, n)
        out = g.add_w(b, b.public, b.secret)
        b.outputs = out
        circ = b.build()
        self.assertEqual(circ.n_mul, n - 2)
        for x in range(1 << n):
            for y in range(1 << n):
                vals, _, ok = circ.evaluate(to_bits(x, n), to_bits(y, n))
                self.assertTrue(ok)
                self.assertEqual(from_bits(circ.output_bits(vals)), (x + y) % (1 << n))

    def test_secret_plus_constant(self):
        n = 8
        for k in (1, 2, 0b10100, 0x80, 0xFF, 0x96):
            b = Builder(0, n)
            out = g.add_w(b, to_bits(k, n), b.secret)
            b.outputs = out
            circ = b.build()
            tz = (k & -k).bit_length() - 1
            self.assertEqual(circ.n_mul, max(0, n - 2 - tz))
            for y in range(1 << n):
                vals, _, ok = circ.evaluate([], to_bits(y, n))
                self.assertEqual(from_bits(circ.output_bits(vals)), (k + y) % (1 << n))

    def test_assert_add(self):
        for n in (1, 2, 3, 5):
            b = Builder(n, 2 * n)
            g.assert_add(b, b.secret[:n], b.secret[n:], b.public)
            circ = b.build()
            self.assertEqual(circ.n_mul, 0)
            self.assertEqual(circ.n_assert, n)
            for x in range(1 << n):
                for y in range(1 << n):
                    for z in range(1 << n):
                        _, _, ok = circ.evaluate(to_bits(z, n), to_bits(x, n) + to_bits(y, n))
                        self.assertEqual(ok, (x + y) % (1 << n) == z, (n, x, y, z))

    def test_add_multi_order_and_zero_dropping(self):
        n = 5
        b = Builder(n, 2 * n)
        zero = [0] * n
        out = g.add_multi(b, [b.secret[:n], zero, b.public, b.secret[n:]])
        b.outputs = out
        circ = b.build()
        # public + secret (n-2 ANDs), then + secret (n-1 ANDs); the zero word is dropped.
        self.assertEqual(circ.n_mul, (n - 2) + (n - 1))
        for x, y, p in itertools.product(range(1 << n), range(4), range(4)):
            vals, _, ok = circ.evaluate(to_bits(p, n), to_bits(x, n) + to_bits(y, n))
            self.assertEqual(from_bits(circ.output_bits(vals)), (x + y + p) % (1 << n))


KINDS = ("0", "1", "P", "S")


def build_bitfn(gadget, kinds):
    """Circuit for a 1-bit gadget whose three inputs have the given kinds."""
    n_pub = kinds.count("P")
    n_sec = kinds.count("S")
    b = Builder(n_pub, n_sec)
    pi = iter(b.public)
    si = iter(b.secret)
    wires = []
    for k in kinds:
        if k == "0":
            wires.append(0)
        elif k == "1":
            wires.append(1)
        elif k == "P":
            wires.append(next(pi))
        else:
            wires.append(next(si))
    out = gadget(b, [wires[0]], [wires[1]], [wires[2]])
    b.outputs = out
    return b.build()


def run_bitfn(circ, kinds, values):
    pub = [v for k, v in zip(kinds, values) if k == "P"]
    sec = [v for k, v in zip(kinds, values) if k == "S"]
    vals, wit, ok = circ.evaluate(pub, sec)
    return vals[circ.outputs[0]], wit, pub, sec, ok


class TestChMaj(unittest.TestCase):
    def check(self, gadget, fn, expected_mul):
        for kinds in itertools.product(KINDS, repeat=3):
            circ = build_bitfn(gadget, kinds)
            self.assertEqual(circ.n_mul, expected_mul(kinds), kinds)
            for values in itertools.product((0, 1), repeat=3):
                if any(k in "01" and int(k) != v for k, v in zip(kinds, values)):
                    continue
                out, wit, pub, sec, ok = run_bitfn(circ, kinds, values)
                self.assertTrue(ok)
                self.assertEqual(out, fn(*values), (kinds, values))
                self.assertEqual(all_witness_extensions(circ, pub, sec), 1)

    def test_ch(self):
        def expected(kinds):
            e, f, gg = (k == "S" for k in kinds)
            # Non-linear only if e is secret and f XOR g is secret.
            return 1 if e and (f or gg) else 0
        self.check(g.ch, lambda e, f, gg: (e & f) ^ ((1 - e) & gg), expected)

    def test_maj(self):
        def expected(kinds):
            return 1 if sum(k == "S" for k in kinds) >= 2 else 0
        self.check(g.maj, lambda x, y, z: (x & y) ^ (x & z) ^ (y & z), expected)


if __name__ == "__main__":
    unittest.main()
