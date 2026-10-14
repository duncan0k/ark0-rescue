"""Seed expansion, ConvertToVOLE and the row/column transposition (SPEC.md §5).

Bit vectors of length lhat are ints. The VOLE has LAMBDA = TAU*K columns:
column K*i + b belongs to tree i and bit b of its challenge Delta_i.
"""

from .params import TAU, K, N_LEAVES, LAMBDA, LAMBDA_BYTES
from .sym import xof, u8, u16le
from . import bits
from . import vc


def expand_leaf(sd, iv, tree, j, lhat):
    """r_{i,j} = SHAKE256["exp"](iv || u8(i) || u16le(N + j) || sd_{i,j}), first lhat bits."""
    data = xof("exp", iv + u8(tree) + u16le(N_LEAVES + j) + sd, bits.nbytes(lhat))
    return int.from_bytes(data, "little") & ((1 << lhat) - 1)


def convert_prover(rs):
    """u = sum_x r_x, v_b = sum_{x : bit b of x = 1} r_x."""
    u = 0
    v = [0] * K
    for x, r in enumerate(rs):
        u ^= r
        for b_ in range(K):
            if (x >> b_) & 1:
                v[b_] ^= r
    return u, v


def convert_verifier(rs, jstar):
    """q_b = sum_{x != j*} (bit b of (x XOR j*)) r_x, so that q_b = v_b + Delta_b u."""
    q = [0] * K
    for x, r in enumerate(rs):
        if x == jstar:
            continue
        y = x ^ jstar
        for b_ in range(K):
            if (y >> b_) & 1:
                q[b_] ^= r
    return q


def tree_roots(r, iv):
    data = xof("root", iv + r, TAU * LAMBDA_BYTES)
    return [data[i * LAMBDA_BYTES:(i + 1) * LAMBDA_BYTES] for i in range(TAU)]


def commit(r, iv, lhat):
    """Prover side. Returns (hcom, decommitments, corrections c_1..c_{TAU-1}, u, V columns)."""
    roots = tree_roots(r, iv)
    tree_hashes = []
    decom = []
    us = []
    cols = [0] * LAMBDA
    for i in range(TAU):
        h, nodes, sds, coms = vc.commit(roots[i], iv, i)
        tree_hashes.append(h)
        decom.append((nodes, coms))
        rs = [expand_leaf(sds[j], iv, i, j, lhat) for j in range(N_LEAVES)]
        u_i, v_i = convert_prover(rs)
        us.append(u_i)
        for b_ in range(K):
            cols[K * i + b_] = v_i[b_]
    u = us[0]
    corrections = [u ^ us[i] for i in range(1, TAU)]
    hcom = xof("hcom", b"".join(tree_hashes), 2 * LAMBDA_BYTES)
    return hcom, decom, corrections, u, cols


def challenge_index(delta, i):
    """Delta_i: bits K*i .. K*i+K-1 of Delta, least significant first."""
    return (delta >> (K * i)) & (N_LEAVES - 1)


def reconstruct(openings, corrections, delta, iv, lhat):
    """Verifier side. Returns (hcom, Q columns) with Q = V + u * Delta (columnwise)."""
    tree_hashes = []
    cols = [0] * LAMBDA
    for i in range(TAU):
        jstar = challenge_index(delta, i)
        h, sds = vc.reconstruct(openings[i], iv, i, jstar)
        tree_hashes.append(h)
        rs = [None if j == jstar else expand_leaf(sds[j], iv, i, j, lhat)
              for j in range(N_LEAVES)]
        q_i = convert_verifier(rs, jstar)
        for b_ in range(K):
            col = q_i[b_]
            if i > 0 and (jstar >> b_) & 1:
                col ^= corrections[i - 1]
            cols[K * i + b_] = col
    hcom = xof("hcom", b"".join(tree_hashes), 2 * LAMBDA_BYTES)
    return hcom, cols


# ------------------------------------------------------------ transposition

def _mask(s, nbytes_):
    if s >= 8:
        pat = b"\xff" * (s // 8) + b"\x00" * (s // 8)
    else:
        pat = {4: b"\x0f", 2: b"\x33", 1: b"\x55"}[s]
    return int.from_bytes(pat * (nbytes_ // len(pat)), "little")


def columns_to_rows(cols, nrows):
    """Transpose 128 column bit-vectors into the first nrows row elements.

    Row r is the GF(2^128) element whose bit j is bit r of column j.
    """
    assert len(cols) == 128
    width = 128 * ((nrows + 127) // 128)
    nb = width // 8
    wmask = (1 << width) - 1
    m = [c & wmask for c in cols]
    s = 64
    while s:
        mask = _mask(s, nb)
        for j in range(128):
            if j & s:
                continue
            a = m[j]
            b_ = m[j + s]
            t = ((a >> s) ^ b_) & mask
            m[j + s] = b_ ^ t
            m[j] = a ^ (t << s)
        s >>= 1
    rows = [0] * nrows
    for j in range(128):
        data = m[j].to_bytes(nb, "little")
        for blk in range(width // 128):
            r = 128 * blk + j
            if r < nrows:
                rows[r] = int.from_bytes(data[16 * blk:16 * blk + 16], "little")
    return rows
