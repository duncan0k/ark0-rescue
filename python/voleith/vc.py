"""All-but-one vector commitment from a GGM tree with hashed leaves (SPEC.md §4).

Tree i has depth k and N = 2^k leaves. Nodes use heap numbering: the root is
node 1, the children of node n are 2n and 2n+1, and leaf j is node N + j.

    (left, right) = SHAKE256["ggm"](iv || u8(i) || u16le(n) || seed_n, 32)
    (sd_j, com_j) = SHAKE256["leaf"](iv || u8(i) || u16le(N + j) || seed_{N+j}, 48)
    h_i           = SHAKE256["tree"](iv || u8(i) || com_0 || ... || com_{N-1}, 32)

The opening for hidden leaf j* is the co-path (the sibling of every ancestor
of leaf j* at depths 1..k, top-down) plus com_{j*}.
"""

from .params import LAMBDA_BYTES
from .sym import xof, u8, u16le

SEED = LAMBDA_BYTES
COM = 2 * LAMBDA_BYTES


def opening_bytes(depth):
    """Length of the opening of a tree of the given depth."""
    return depth * SEED + COM


def _expand(seed, iv, tree, node):
    out = xof("ggm", iv + u8(tree) + u16le(node) + seed, 2 * SEED)
    return out[:SEED], out[SEED:]


def _leaf(seed, iv, tree, node):
    out = xof("leaf", iv + u8(tree) + u16le(node) + seed, SEED + COM)
    return out[:SEED], out[SEED:]


def tree_hash(iv, tree, coms):
    return xof("tree", iv + u8(tree) + b"".join(coms), COM)


def _path(depth, jstar):
    """Heap indices of the co-path nodes of leaf j*, at depths 1..depth."""
    n_leaves = 1 << depth
    return [((n_leaves + jstar) >> (depth - d)) ^ 1 for d in range(1, depth + 1)]


def commit(root, iv, tree, depth):
    """Returns (h_i, nodes, leaf seeds sd_j, leaf commitments com_j)."""
    n_leaves = 1 << depth
    nodes = [None] * (2 * n_leaves)
    nodes[1] = root
    for n in range(1, n_leaves):
        nodes[2 * n], nodes[2 * n + 1] = _expand(nodes[n], iv, tree, n)
    sds = []
    coms = []
    for j in range(n_leaves):
        sd, com = _leaf(nodes[n_leaves + j], iv, tree, n_leaves + j)
        sds.append(sd)
        coms.append(com)
    return tree_hash(iv, tree, coms), nodes, sds, coms


def open_(nodes, coms, depth, jstar):
    return b"".join(nodes[n] for n in _path(depth, jstar)) + coms[jstar]


def reconstruct(opening, iv, tree, depth, jstar):
    """Returns (h_i, sds) where sds[j*] is None. `opening` must be
    opening_bytes(depth) long."""
    if len(opening) != opening_bytes(depth):
        raise ValueError("bad opening length")
    n_leaves = 1 << depth
    nodes = [None] * (2 * n_leaves)
    for d, n in enumerate(_path(depth, jstar)):
        nodes[n] = opening[d * SEED:(d + 1) * SEED]
    for n in range(2, n_leaves):
        if nodes[n] is not None:
            nodes[2 * n], nodes[2 * n + 1] = _expand(nodes[n], iv, tree, n)
    com_star = opening[depth * SEED:]
    sds = []
    coms = []
    for j in range(n_leaves):
        if j == jstar:
            sds.append(None)
            coms.append(com_star)
        else:
            sd, com = _leaf(nodes[n_leaves + j], iv, tree, n_leaves + j)
            sds.append(sd)
            coms.append(com)
    return tree_hash(iv, tree, coms), sds
