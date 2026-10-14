"""The QuickSilver identity of SPEC §6.2 on small circuits.

For every constraint t, B_t = A0_t + A1_t * Delta + e_t * Delta^2, where e_t is
1 iff the constraint is violated by the committed witness.
"""

import random
import unittest

from voleith import gf128
from voleith import sha256_gadgets as g
from voleith.circuit import Builder


def small_circuit(n=4):
    """Public p, secret x, y: s = x + y; m = Maj(x, y, p); c = Ch(p, x, y);
    assert s + p = z for public z; and t = s + p as a computed sum."""
    b = Builder(2 * n, 2 * n)
    p, z = b.public[:n], b.public[n:]
    x, y = b.secret[:n], b.secret[n:]
    s = g.add_w(b, x, y)
    g.maj(b, x, y, p)
    g.ch(b, p, x, y)
    g.assert_add(b, s, p, z)
    g.add_multi(b, [s, p])
    return b.build()


def bits(v, n):
    return [(v >> i) & 1 for i in range(n)]


class TestQuickSilverIdentity(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(41)
        self.n = 4
        self.circ = small_circuit(self.n)

    def terms(self, pub, wit):
        delta = self.rng.getrandbits(128)
        tags = [self.rng.getrandbits(128) for _ in wit]
        keys = [t ^ (delta if w else 0) for t, w in zip(tags, wit)]
        a0, a1 = self.circ.prover_terms(pub, wit, tags)
        bt = self.circ.verifier_terms(pub, keys, delta)
        self.assertEqual(len(a0), self.circ.n_constraints)
        self.assertEqual(len(bt), self.circ.n_constraints)
        d2 = gf128.mul(delta, delta)
        errors = []
        for t in range(len(bt)):
            rest = bt[t] ^ a0[t] ^ gf128.mul(a1[t], delta)
            self.assertIn(rest, (0, d2), t)
            errors.append(1 if rest == d2 and d2 != 0 else 0)
        return errors

    def test_honest_witness_has_no_error_terms(self):
        n = self.n
        for _ in range(20):
            x, y, p = (self.rng.getrandbits(n) for _ in range(3))
            z = (x + y + p) % (1 << n)
            pub = bits(p, n) + bits(z, n)
            _, wit, ok = self.circ.evaluate(pub, bits(x, n) + bits(y, n))
            self.assertTrue(ok)
            self.assertEqual(sum(self.terms(pub, wit)), 0)

    def test_violations_show_up_as_delta_squared(self):
        n = self.n
        for _ in range(20):
            x, y, p = (self.rng.getrandbits(n) for _ in range(3))
            z = (x + y + p + 1 + self.rng.randrange((1 << n) - 1)) % (1 << n)  # wrong z
            pub = bits(p, n) + bits(z, n)
            _, wit, ok = self.circ.evaluate(pub, bits(x, n) + bits(y, n))
            self.assertFalse(ok)
            self.assertGreater(sum(self.terms(pub, wit)), 0)
        # A flipped AND output also violates its own constraint.
        x, y, p = 5, 9, 3
        z = (x + y + p) % (1 << n)
        pub = bits(p, n) + bits(z, n)
        _, wit, _ = self.circ.evaluate(pub, bits(x, n) + bits(y, n))
        for pos in range(2 * n, len(wit)):
            bad = list(wit)
            bad[pos] ^= 1
            self.assertGreater(sum(self.terms(pub, bad)), 0, pos)


if __name__ == "__main__":
    unittest.main()
