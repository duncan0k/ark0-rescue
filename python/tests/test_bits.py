"""Bit-string encoding of SPEC §1.2: LSB first, zero padding checked."""

import unittest

from voleith import bits


class TestBits(unittest.TestCase):
    def test_roundtrip(self):
        for n in (1, 7, 8, 9, 15, 16, 17, 42455):
            for v in (0, 1, (1 << n) - 1, (1 << (n - 1)) | 1):
                data = bits.encode(v, n)
                self.assertEqual(len(data), (n + 7) // 8)
                self.assertEqual(bits.decode(data, n), v)

    def test_bit_order(self):
        self.assertEqual(bits.encode(1, 9), b"\x01\x00")
        self.assertEqual(bits.encode(1 << 8, 9), b"\x00\x01")
        self.assertEqual(bits.encode(0b10000000, 8), b"\x80")

    def test_padding_bits_rejected(self):
        # n = 9: the last byte has 1 data bit and 7 padding bits.
        for pad in range(1, 8):
            self.assertIsNone(bits.decode(b"\x00" + bytes([1 << pad]), 9))
        self.assertEqual(bits.decode(b"\x00\x01", 9), 1 << 8)
        # The lengths used by statement 0x01 have one padding bit each.
        for n in (42071, 42455):
            nb = (n + 7) // 8
            self.assertIsNone(bits.decode(bytes(nb - 1) + b"\x80", n))
            self.assertEqual(bits.decode(bytes(nb - 1) + b"\x40", n), 1 << (n - 1))

    def test_length_mismatch_rejected(self):
        self.assertIsNone(bits.decode(b"\x00", 9))
        self.assertIsNone(bits.decode(b"\x00\x00\x00", 9))
        with self.assertRaises(ValueError):
            bits.encode(1 << 9, 9)


if __name__ == "__main__":
    unittest.main()
