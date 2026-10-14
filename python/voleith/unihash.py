"""Universal hashes for the two consistency checks (SPEC.md §5.4, §6.3).

VOLEHash (keys s, t from chall1): for x of lhat = ell + 3*LAMBDA bits, split
x = (x0, x1) with |x0| = ell + LAMBDA, |x1| = 2*LAMBDA. Zero-pad x0 to n
128-bit blocks y_0..y_{n-1} and output

    ( sum_j y_j s^(n-j) + x1[0:128],  sum_j y_j t^(n-j) + x1[128:256] ),

32 bytes (s-part first). All exponents are >= 1, so each half is an
(n / 2^128)-almost uniform hash of x0.

ZKHash (keys r0, r1, s, t from chall2), FAEST v1.1 style with a full-width t:

    ZKHash(x_0..x_{C-1}; mask) = r0 * sum_i s^(C-1-i) x_i + r1 * sum_i t^(C-1-i) x_i + mask.
"""

from . import gf128
from .params import LAMBDA


class VoleHash:
    def __init__(self, chall1, ell):
        if len(chall1) != 32:
            raise ValueError("chall1 must be 32 bytes")
        self._ms = gf128.FixedMul(gf128.from_bytes(chall1[0:16]))
        self._mt = gf128.FixedMul(gf128.from_bytes(chall1[16:32]))
        self.n_in = ell + LAMBDA
        self.n_blocks = (self.n_in + 127) // 128
        self._in_mask = (1 << self.n_in) - 1

    def __call__(self, x):
        x0 = x & self._in_mask
        x1 = x >> self.n_in
        data = x0.to_bytes(16 * self.n_blocks, "little")
        ms = self._ms
        mt = self._mt
        hs = 0
        ht = 0
        for j in range(0, 16 * self.n_blocks, 16):
            y = int.from_bytes(data[j:j + 16], "little")
            hs = ms(hs ^ y)
            ht = mt(ht ^ y)
        hs ^= x1 & gf128.MASK
        ht ^= (x1 >> 128) & gf128.MASK
        return gf128.to_bytes(hs) + gf128.to_bytes(ht)


class ZkHash:
    def __init__(self, chall2):
        if len(chall2) != 64:
            raise ValueError("chall2 must be 64 bytes")
        self._r0 = gf128.from_bytes(chall2[0:16])
        self._r1 = gf128.from_bytes(chall2[16:32])
        self._ms = gf128.FixedMul(gf128.from_bytes(chall2[32:48]))
        self._mt = gf128.FixedMul(gf128.from_bytes(chall2[48:64]))

    def __call__(self, xs, mask):
        ms = self._ms
        mt = self._mt
        hs = 0
        ht = 0
        for x in xs:
            hs = ms(hs) ^ x
            ht = mt(ht) ^ x
        return gf128.mul(self._r0, hs) ^ gf128.mul(self._r1, ht) ^ mask
