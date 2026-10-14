"""Statement registry (SPEC.md §6-§7).

Statement 0x01 (web wallet v1, Schnorr derivation):
    public:  K (1..64 printable ASCII bytes), suffix (1 byte), y (32 bytes)
    witness: x (32 bytes)
    relation: HMAC-SHA256(K, x || suffix) = y
"""

import hmac
import hashlib
from dataclasses import dataclass

from . import sha256_ref
from .circuit import Builder
from . import sha256_gadgets as g


@dataclass(frozen=True)
class Statement:
    """A statement id plus its canonical public-input encoding."""
    statement_id: int
    public_inputs: bytes


# ------------------------------------------------------------ statement 1

STATEMENT1_ID = 0x01
S1_WITNESS_LEN = 32
S1_MAX_KEY_LEN = 64
# Public bits: IV_in (256) | IV_out (256) | T (256) | suffix (8).
S1_N_PUBLIC = 256 * 3 + 8


def s1_encode_public(key, suffix, y):
    if not isinstance(key, bytes) or not (1 <= len(key) <= S1_MAX_KEY_LEN):
        raise ValueError("K must be 1..64 bytes")
    if any(not (0x20 <= c <= 0x7E) for c in key):
        raise ValueError("K must be printable ASCII")
    if not isinstance(suffix, int) or not (0 <= suffix <= 255):
        raise ValueError("suffix must be one byte")
    if not isinstance(y, bytes) or len(y) != 32:
        raise ValueError("y must be 32 bytes")
    return bytes([len(key)]) + key + bytes([suffix]) + y


def s1_parse_public(pub):
    """Strict parser: returns (K, suffix, y) or None."""
    if not isinstance(pub, bytes) or len(pub) < 1:
        return None
    kl = pub[0]
    if not (1 <= kl <= S1_MAX_KEY_LEN):
        return None
    if len(pub) != 1 + kl + 1 + 32:
        return None
    key = pub[1:1 + kl]
    if any(not (0x20 <= c <= 0x7E) for c in key):
        return None
    return key, pub[1 + kl], pub[2 + kl:]


def s1_hmac(key, suffix, x):
    return hmac.new(key, x + bytes([suffix]), hashlib.sha256).digest()


def statement1(key, suffix, y):
    return Statement(STATEMENT1_ID, s1_encode_public(key, suffix, y))


def statement1_for_seed(key, suffix, x):
    """Statement for the web wallet v1 derivation y = HMAC-SHA256(K, x || suffix)."""
    return statement1(key, suffix, s1_hmac(key, suffix, x))


def _word_bits(words):
    return [(wd >> i) & 1 for wd in words for i in range(32)]


def s1_public_bits(parsed):
    key, suffix, y = parsed
    iv_in, iv_out = sha256_ref.hmac_midstates(key)
    y_words = sha256_ref.bytes_to_words(y)
    target = [(yw - ow) & 0xFFFFFFFF for yw, ow in zip(y_words, iv_out)]
    return (_word_bits(iv_in) + _word_bits(iv_out) + _word_bits(target)
            + [(suffix >> i) & 1 for i in range(8)])


def s1_secret_bits(x):
    """Witness bit 8n + b is bit b (LSB first) of x[n]."""
    return [(x[n] >> b) & 1 for n in range(32) for b in range(8)]


def build_statement1_circuit():
    b = Builder(S1_N_PUBLIC, 256)
    pub = b.public
    iv_in = [pub[32 * j:32 * j + 32] for j in range(8)]
    iv_out = [pub[256 + 32 * j:256 + 32 * j + 32] for j in range(8)]
    target = [pub[512 + 32 * j:512 + 32 * j + 32] for j in range(8)]
    suffix = pub[768:776]
    xs = b.secret

    def x_word(j):
        # Big-endian word j of x: bit i comes from byte 4j + 3 - i//8, bit i%8.
        return [xs[8 * (4 * j + 3 - i // 8) + (i % 8)] for i in range(32)]

    # Inner block: x (32 bytes) || suffix || 0x80 || 0^22 || be64(776).
    w8 = [0] * 23 + [1] + suffix
    inner_block = ([x_word(j) for j in range(8)] + [w8]
                   + [g.const_word(0)] * 6 + [g.const_word(776)])
    digest = g.compress(b, iv_in, inner_block)
    # Outer block: inner digest || 0x80 || 0^23 || be64(768).
    outer_block = (digest + [g.const_word(0x80000000)]
                   + [g.const_word(0)] * 6 + [g.const_word(768)])
    g.compress(b, iv_out, outer_block, final_state=target)
    return b.build()


class _Statement1:
    statement_id = STATEMENT1_ID
    witness_len = S1_WITNESS_LEN
    _circuit = None

    def circuit(self):
        if _Statement1._circuit is None:
            _Statement1._circuit = build_statement1_circuit()
        return _Statement1._circuit

    parse_public = staticmethod(s1_parse_public)
    public_bits = staticmethod(s1_public_bits)
    secret_bits = staticmethod(s1_secret_bits)

    @staticmethod
    def relation(parsed, witness):
        key, suffix, y = parsed
        return hmac.compare_digest(s1_hmac(key, suffix, witness), y)


REGISTRY = {STATEMENT1_ID: _Statement1()}
