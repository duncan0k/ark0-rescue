"""Arithmetic in GF(2^128) = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1).

Elements are Python ints in [0, 2^128): bit i is the coefficient of X^i.
The byte encoding is 16 bytes little-endian (byte 0 holds X^0..X^7).

This is reference code: it is not constant time.
"""

MASK = (1 << 128) - 1
# X^128 = X^7 + X^2 + X + 1 (mod the field polynomial).
_RED = 0x87


def from_bytes(b):
    if len(b) != 16:
        raise ValueError("GF(2^128) element must be 16 bytes")
    return int.from_bytes(b, "little")


def to_bytes(a):
    return a.to_bytes(16, "little")


def reduce(z):
    """Reduce a polynomial of degree < 255 modulo the field polynomial."""
    hi = z >> 128
    t = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7)
    lo = (z ^ t) & MASK
    hi2 = t >> 128
    return lo ^ hi2 ^ (hi2 << 1) ^ (hi2 << 2) ^ (hi2 << 7)


def clmul(a, b):
    """Carry-less product of two 128-bit polynomials (4-bit window)."""
    a2 = a << 1
    a4 = a << 2
    a8 = a << 3
    t = (0, a, a2, a2 ^ a, a4, a4 ^ a, a4 ^ a2, a4 ^ a2 ^ a,
         a8, a8 ^ a, a8 ^ a2, a8 ^ a2 ^ a, a8 ^ a4, a8 ^ a4 ^ a, a8 ^ a4 ^ a2,
         a8 ^ a4 ^ a2 ^ a)
    z = 0
    for sh in range(124, -1, -4):
        z = (z << 4) ^ t[(b >> sh) & 15]
    return z


def mul(a, b):
    return reduce(clmul(a, b))


def mul_x(a):
    """Multiply by X."""
    a <<= 1
    if a >> 128:
        a = (a & MASK) ^ _RED
    return a


def pow_(a, e):
    r = 1
    while e:
        if e & 1:
            r = mul(r, a)
        a = mul(a, a)
        e >>= 1
    return r


def inv(a):
    if a == 0:
        raise ZeroDivisionError("inverse of 0 in GF(2^128)")
    return pow_(a, (1 << 128) - 2)


class FixedMul:
    """Multiplication by a fixed element using 16 byte-indexed tables."""

    __slots__ = ("a", "_t")

    def __init__(self, a):
        self.a = a
        tables = []
        base = a  # a * X^(8k)
        for _ in range(16):
            row = [0] * 256
            p = base
            for j in range(8):
                row[1 << j] = p
                p = mul_x(p)
            for v in range(3, 256):
                low = v & -v
                if low != v:
                    row[v] = row[low] ^ row[v ^ low]
            tables.append(row)
            base = p  # base * X^8
        self._t = tuple(tables)

    def __call__(self, x):
        b = x.to_bytes(16, "little")
        t = self._t
        return (t[0][b[0]] ^ t[1][b[1]] ^ t[2][b[2]] ^ t[3][b[3]]
                ^ t[4][b[4]] ^ t[5][b[5]] ^ t[6][b[6]] ^ t[7][b[7]]
                ^ t[8][b[8]] ^ t[9][b[9]] ^ t[10][b[10]] ^ t[11][b[11]]
                ^ t[12][b[12]] ^ t[13][b[13]] ^ t[14][b[14]] ^ t[15][b[15]])
