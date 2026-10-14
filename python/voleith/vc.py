"""All-but-one vector commitment from a GGM tree with hashed leaves (SPEC.md §4).

Tree i has depth K and N = 2^K leaves. Nodes use heap numbering: the root is
node 1, the children of node n are 2n and 2n+1, and leaf j is node N + j.

    (left, right) = SHAKE256["ggm"](iv || u8(i) || u16le(n) || seed_n, 32)
    (sd_j, com_j) = SHAKE256["leaf"](iv || u8(i) || u16le(N + j) || seed_{N+j}, 48)
    h_i           = SHAKE256["tree"](iv || u8(i) || com_0 || ... || com_{N-1}, 32)

The opening for hidden leaf j* is the co-path (the sibling of every ancestor
of leaf j* at depths 1..K, top-down) plus com_{j*}.
"""

from .params import K, N_LEAVES, LAMBDA_BYTES
from .sym import xof, u8, u16le

SEED = LAMBDA_BYTES
COM = 2 * LAMBDA_BYTES
OPENING_BYTES = K * SEED + COM


def _expand(seed, iv, tree, node):
    out = xof("ggm", iv + u8(tree) + u16le(node) + seed, 2 * SEED)
    return out[:SEED], out[SEED:]


def _leaf(seed, iv, tree, j):
    out = xof("leaf", iv + u8(tree) + u16le(N_LEAVES + j) + seed, SEED + COM)
    return out[:SEED], out[SEED:]


def _tree_hash(iv, tree, coms):
    return xof("tree", iv + u8(tree) + b"".join(coms), COM)


def _path(jstar):
    """Heap indices of the co-path nodes of leaf j*, at depths 1..K."""
    return [((N_LEAVES + jstar) >> (K - d)) ^ 1 for d in range(1, K + 1)]


def commit(root, iv, tree):
    """Returns (h_i, nodes, leaf seeds sd_j, leaf commitments com_j)."""
    nodes = [None] * (2 * N_LEAVES)
    nodes[1] = root
    for n in range(1, N_LEAVES):
        nodes[2 * n], nodes[2 * n + 1] = _expand(nodes[n], iv, tree, n)
    sds = []
    coms = []
    for j in range(N_LEAVES):
        sd, com = _leaf(nodes[N_LEAVES + j], iv, tree, j)
        sds.append(sd)
        coms.append(com)
    return _tree_hash(iv, tree, coms), nodes, sds, coms


def open_(nodes, coms, jstar):
    return b"".join(nodes[n] for n in _path(jstar)) + coms[jstar]


def reconstruct(opening, iv, tree, jstar):
    """Returns (h_i, sds) where sds[j*] is None. `opening` must be OPENING_BYTES long."""
    if len(opening) != OPENING_BYTES:
        raise ValueError("bad opening length")
    nodes = [None] * (2 * N_LEAVES)
    for d, n in enumerate(_path(jstar)):
        nodes[n] = opening[d * SEED:(d + 1) * SEED]
    for n in range(2, N_LEAVES):
        if nodes[n] is not None:
            nodes[2 * n], nodes[2 * n + 1] = _expand(nodes[n], iv, tree, n)
    com_star = opening[K * SEED:]
    sds = []
    coms = []
    for j in range(N_LEAVES):
        if j == jstar:
            sds.append(None)
            coms.append(com_star)
        else:
            sd, com = _leaf(nodes[N_LEAVES + j], iv, tree, j)
            sds.append(sd)
            coms.append(com)
    return _tree_hash(iv, tree, coms), sds
