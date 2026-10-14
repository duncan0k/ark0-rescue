import random
import unittest

from voleith import gf128


def slow_mul(a, b):
    """Bit-serial reference: shift-and-add with reduction by X^128 = 0x87."""
    r = 0
    for i in range(127, -1, -1):
        r = gf128.mul_x(r)
        if (b >> i) & 1:
            r ^= a
    return r


class TestGF128(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(0xF128)

    def rand(self):
        return self.rng.getrandbits(128)

    def test_reduction_polynomial(self):
        # X^127 * X = X^128 = X^7 + X^2 + X + 1.
        self.assertEqual(gf128.mul(1 << 127, 2), 0x87)
        self.assertEqual(gf128.mul_x(1 << 127), 0x87)
        # X^254 reduces correctly (largest unreduced product).
        self.assertEqual(gf128.mul(1 << 127, 1 << 127), slow_mul(1 << 127, 1 << 127))

    def test_against_bit_serial_reference(self):
        for _ in range(300):
            a, b = self.rand(), self.rand()
            self.assertEqual(gf128.mul(a, b), slow_mul(a, b))

    def test_field_axioms(self):
        for _ in range(100):
            a, b, c = self.rand(), self.rand(), self.rand()
            self.assertEqual(gf128.mul(a, b), gf128.mul(b, a))
            self.assertEqual(gf128.mul(gf128.mul(a, b), c), gf128.mul(a, gf128.mul(b, c)))
            self.assertEqual(gf128.mul(a, b ^ c), gf128.mul(a, b) ^ gf128.mul(a, c))
            self.assertEqual(gf128.mul(a, 1), a)
            self.assertEqual(gf128.mul(a, 0), 0)

    def test_inverse(self):
        for _ in range(10):
            a = self.rand() | 1
            self.assertEqual(gf128.mul(a, gf128.inv(a)), 1)
        with self.assertRaises(ZeroDivisionError):
            gf128.inv(0)

    def test_fixed_mul(self):
        for _ in range(20):
            a = self.rand()
            fm = gf128.FixedMul(a)
            for _ in range(20):
                x = self.rand()
                self.assertEqual(fm(x), gf128.mul(a, x))
        self.assertEqual(gf128.FixedMul(0)(self.rand()), 0)

    def test_byte_encoding(self):
        self.assertEqual(gf128.to_bytes(1), b"\x01" + bytes(15))
        self.assertEqual(gf128.from_bytes(bytes(15) + b"\x80"), 1 << 127)
        with self.assertRaises(ValueError):
            gf128.from_bytes(b"\x00" * 15)


if __name__ == "__main__":
    unittest.main()
