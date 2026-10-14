"""SHA-256 compression as a Boolean circuit (SPEC.md §7.4).

A word is a list of 32 wire ids, least significant bit first (index i has
weight 2^i). Constant words use the constant wires 0 and 1. All word gadgets
emit their instructions bit by bit in ascending bit order.

Adder: ripple carry with one AND per carry bit,
    s_i = x_i ^ y_i ^ c_i,  c_0 = 0,
    c_{i+1} = ((x_i ^ c_i) & (y_i ^ c_i)) ^ c_i   (= maj(x_i, y_i, c_i)),
so a 32-bit addition of two secret words costs 31 AND gates.
"""

from .circuit import Builder, SEC, PUB, CONST
from . import sha256_ref
from .sha256_ref import K as K256

WORD = 32


def const_word(v):
    return [(v >> i) & 1 for i in range(WORD)]


def word_kind(b, w):
    k = CONST
    for x in w:
        kx = b.kind[x]
        if kx == SEC:
            return SEC
        if kx == PUB:
            k = PUB
    return k


def is_zero_word(w):
    return all(x == 0 for x in w)


def rotr(w, n):
    return [w[(i + n) % WORD] for i in range(WORD)]


def shr(w, n):
    return [w[i + n] if i + n < WORD else 0 for i in range(WORD)]


def xor_w(b, x, y):
    return [b.xor(x[i], y[i]) for i in range(len(x))]


def big_sigma0(b, a):
    return xor_w(b, xor_w(b, rotr(a, 2), rotr(a, 13)), rotr(a, 22))


def big_sigma1(b, e):
    return xor_w(b, xor_w(b, rotr(e, 6), rotr(e, 11)), rotr(e, 25))


def small_sigma0(b, x):
    return xor_w(b, xor_w(b, rotr(x, 7), rotr(x, 18)), shr(x, 3))


def small_sigma1(b, x):
    return xor_w(b, xor_w(b, rotr(x, 17), rotr(x, 19)), shr(x, 10))


def ch(b, e, f, g):
    """Ch(e,f,g) = g ^ (e & (f ^ g)), bit by bit."""
    out = []
    for i in range(len(e)):
        out.append(b.xor(g[i], b.and_(e[i], b.xor(f[i], g[i]))))
    return out


def maj(b, x, y, z):
    """Maj(x,y,z), bit by bit.

    If x_i is secret and y_i, z_i are not, Maj = (y & z) ^ (x & (y ^ z)), which
    is affine in x_i. Otherwise Maj = ((x ^ y) & (x ^ z)) ^ x.
    """
    out = []
    for i in range(len(x)):
        xi, yi, zi = x[i], y[i], z[i]
        if b.is_secret(xi) and not b.is_secret(yi) and not b.is_secret(zi):
            out.append(b.xor(b.and_(yi, zi), b.and_(xi, b.xor(yi, zi))))
        else:
            out.append(b.xor(b.and_(b.xor(xi, yi), b.xor(xi, zi)), xi))
    return out


def add_w(b, x, y):
    """x + y mod 2^n (n = len(x)) with the one-AND-per-bit ripple-carry adder."""
    n = len(x)
    out = []
    c = 0
    for i in range(n):
        out.append(b.xor(b.xor(x[i], y[i]), c))
        if i < n - 1:
            c = b.xor(b.and_(b.xor(x[i], c), b.xor(y[i], c)), c)
    return out


def add_multi(b, operands):
    """Sum of several words.

    Operands are reordered stably: non-secret words first, then secret words;
    all-zero constant words are dropped; the rest are added left to right.
    """
    nonsec = [w for w in operands if word_kind(b, w) != SEC]
    sec = [w for w in operands if word_kind(b, w) == SEC]
    ops = [w for w in nonsec + sec if not is_zero_word(w)]
    if not ops:
        return [0] * len(operands[0])
    acc = ops[0]
    for w in ops[1:]:
        acc = add_w(b, acc, w)
    return acc


def assert_add(b, x, y, z):
    """Constrain x + y = z mod 2^n (n = len(x)) for a non-secret word z,
    without new witness bits.

    The carry into bit i is c_i = x_i ^ y_i ^ z_i. The constraints are c_0 = 0
    and (x_i ^ c_i)(y_i ^ c_i) = c_{i+1} ^ c_i for i = 0..n-2.
    """
    n = len(x)
    c = [b.xor(b.xor(x[i], y[i]), z[i]) for i in range(n)]
    b.assert_mul(c[0], 1, 0)
    for i in range(n - 1):
        b.assert_mul(b.xor(x[i], c[i]), b.xor(y[i], c[i]), b.xor(c[i + 1], c[i]))


def compress(b, h_in, w_block, final_state=None):
    """SHA-256 compression of 16 message words under chaining value h_in.

    Without `final_state`, returns the 8 output words h_in + state.
    With `final_state` (8 non-secret words S), the circuit instead constrains
    the state after round 63 to equal S: the a- and e-updates of rounds 60..63
    become assert_add constraints, the asserted words are used from then on,
    and no feed-forward is computed. Returns None in that case.
    """
    w = list(w_block)
    for t in range(16, 64):
        w.append(add_multi(b, [small_sigma1(b, w[t - 2]), w[t - 7],
                               small_sigma0(b, w[t - 15]), w[t - 16]]))
    a, bb, c, d, e, f, g, h = h_in
    for t in range(64):
        s1 = big_sigma1(b, e)
        chv = ch(b, e, f, g)
        t1 = add_multi(b, [h, s1, chv, const_word(K256[t]), w[t]])
        s0 = big_sigma0(b, a)
        mj = maj(b, a, bb, c)
        t2 = add_multi(b, [s0, mj])
        if final_state is not None and t >= 60:
            e_new = final_state[4 + (63 - t)]
            a_new = final_state[63 - t]
            assert_add(b, d, t1, e_new)
            assert_add(b, t1, t2, a_new)
        else:
            e_new = add_multi(b, [d, t1])
            a_new = add_multi(b, [t1, t2])
        h, g, f, e, d, c, bb, a = g, f, e, e_new, c, bb, a, a_new
    if final_state is not None:
        return None
    return [add_multi(b, [h_in[i], v]) for i, v in enumerate((a, bb, c, d, e, f, g, h))]


# ------------------------------------------------------- standalone circuit

def build_compression_circuit():
    """SHA-256 compression with all 768 inputs secret: chaining value, then block.

    Secret input bit 32*j + i is bit i of word j, where words 0..7 are the
    chaining value and words 8..23 the message block (big-endian words).
    Outputs: 8 words (256 bits), word-major, least significant bit first.
    """
    b = Builder(0, 768)
    words = [b.secret[32 * j:32 * j + 32] for j in range(24)]
    out = compress(b, words[:8], words[8:])
    b.outputs = [x for w in out for x in w]
    return b.build()


def compression_inputs(state, block):
    words = list(state) + sha256_ref.block_words(block)
    return [(wd >> i) & 1 for wd in words for i in range(32)]


def words_from_bits(bits):
    return [sum(bits[32 * j + i] << i for i in range(32)) for j in range(len(bits) // 32)]
