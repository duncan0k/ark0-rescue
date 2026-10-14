"""Bit-string conventions (SPEC.md §1.2).

A bit string b[0..n) is held as the int sum(b[i] << i). Its byte encoding has
ceil(n/8) bytes: bit i is bit (i mod 8) of byte (i div 8), least significant
bit first. When n is not a multiple of 8 the unused high bits of the last byte
are padding bits and must be zero.
"""


def nbytes(nbits):
    return (nbits + 7) // 8


def encode(value, nbits):
    if value < 0 or value >> nbits:
        raise ValueError("value does not fit in the bit length")
    return value.to_bytes(nbytes(nbits), "little")


def decode(data, nbits):
    """Decode a bit string; return None if the length or a padding bit is wrong."""
    if len(data) != nbytes(nbits):
        return None
    value = int.from_bytes(data, "little")
    if value >> nbits:
        return None
    return value


def bit(value, i):
    return (value >> i) & 1
