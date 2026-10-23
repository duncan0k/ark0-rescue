//! All-but-one vector commitment from a GGM tree with hashed leaves
//! (SPEC.md §4).
//!
//! A tree of depth k has N = 2^k leaves in heap numbering: the root is node
//! 1, the children of node n are 2n and 2n+1, and leaf j is node N + j.

#![forbid(unsafe_code)]

use crate::params::{COM_BYTES, MAX_DEPTH, MAX_LEAVES, SEED_BYTES};
use crate::sym::{Tag, Xof};
#[cfg(feature = "prover")]
use zeroize::Zeroize;

pub type Seed = [u8; SEED_BYTES];
pub type Com = [u8; COM_BYTES];

/// Length of the opening of a tree of the given depth.
pub const fn opening_len(depth: usize) -> usize {
    depth * SEED_BYTES + COM_BYTES
}

/// Children of node n: SHAKE256[ggm](iv || u8(i) || u16le(n) || seed_n, 32),
/// read straight into `nodes[2n]` and `nodes[2n + 1]`.
#[inline]
fn expand(iv: &[u8; 16], tree: u8, n: usize, nodes: &mut [Seed]) {
    let (lo, hi) = nodes.split_at_mut(2 * n);
    let mut x = Xof::new(Tag::Ggm);
    x.update(iv)
        .update(&[tree])
        .update(&(n as u16).to_le_bytes())
        .update(&lo[n]);
    x.finalize_into(&mut hi[0]);
    x.read(&mut hi[1]);
}

/// (sd_j, com_j) = SHAKE256[leaf](iv || u8(i) || u16le(N + j) || seed, 48),
/// with `node` = N + j, read straight into `sd` and `com`.
#[inline]
fn leaf(iv: &[u8; 16], tree: u8, node: usize, seed: &Seed, sd: &mut Seed, com: &mut Com) {
    let mut x = Xof::new(Tag::Leaf);
    x.update(iv)
        .update(&[tree])
        .update(&(node as u16).to_le_bytes())
        .update(seed);
    x.finalize_into(sd);
    x.read(com);
}

/// Heap index of the co-path node of leaf j* at depth d (1..=depth).
#[inline]
fn copath(depth: usize, jstar: usize, d: usize) -> usize {
    (((1 << depth) + jstar) >> (depth - d)) ^ 1
}

/// Prover side: the expanded tree of one root. Its node and leaf seeds are
/// zeroized when it is dropped.
#[cfg(feature = "prover")]
pub struct Tree {
    pub hash: [u8; 32],
    depth: usize,
    nodes: Vec<Seed>,
    pub sds: Vec<Seed>,
    coms: Vec<Com>,
}

#[cfg(feature = "prover")]
pub fn commit(root: &Seed, iv: &[u8; 16], tree: u8, depth: usize) -> Tree {
    debug_assert!((1..=MAX_DEPTH).contains(&depth));
    let n_leaves = 1 << depth;
    let mut nodes = vec![[0u8; SEED_BYTES]; 2 * n_leaves];
    nodes[1] = *root;
    for n in 1..n_leaves {
        expand(iv, tree, n, &mut nodes);
    }
    let mut sds = vec![[0u8; SEED_BYTES]; n_leaves];
    let mut coms = vec![[0u8; COM_BYTES]; n_leaves];
    let mut th = Xof::new(Tag::Tree);
    th.update(iv).update(&[tree]);
    for j in 0..n_leaves {
        leaf(
            iv,
            tree,
            n_leaves + j,
            &nodes[n_leaves + j],
            &mut sds[j],
            &mut coms[j],
        );
        th.absorb(&coms[j]);
    }
    Tree {
        hash: th.finalize(),
        depth,
        nodes,
        sds,
        coms,
    }
}

#[cfg(feature = "prover")]
impl Drop for Tree {
    fn drop(&mut self) {
        self.nodes.zeroize();
        self.sds.zeroize();
        self.coms.zeroize();
    }
}

#[cfg(feature = "prover")]
impl Tree {
    /// The opening for hidden leaf j*: co-path seeds top-down, then com_{j*}.
    pub fn open(&self, jstar: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(opening_len(self.depth));
        for d in 1..=self.depth {
            out.extend_from_slice(&self.nodes[copath(self.depth, jstar, d)]);
        }
        out.extend_from_slice(&self.coms[jstar]);
        out
    }
}

/// Verifier side (SPEC.md §4.4): from an opening of `opening_len(depth)`
/// bytes and j*, recompute the tree commitment h_i and the leaf seeds sd_j
/// for j != j* (`sds[j*]` and entries from 2^depth on are left untouched).
pub fn reconstruct(
    opening: &[u8],
    iv: &[u8; 16],
    tree: u8,
    depth: usize,
    jstar: usize,
    sds: &mut [Seed; MAX_LEAVES],
) -> [u8; 32] {
    debug_assert!((1..=MAX_DEPTH).contains(&depth));
    debug_assert_eq!(opening.len(), opening_len(depth));
    let n_leaves = 1 << depth;
    let mut nodes = [[0u8; SEED_BYTES]; 2 * MAX_LEAVES];
    let mut known = [false; 2 * MAX_LEAVES];
    for d in 1..=depth {
        let n = copath(depth, jstar, d);
        nodes[n].copy_from_slice(&opening[(d - 1) * SEED_BYTES..d * SEED_BYTES]);
        known[n] = true;
    }
    for n in 2..n_leaves {
        if known[n] {
            expand(iv, tree, n, &mut nodes);
            known[2 * n] = true;
            known[2 * n + 1] = true;
        }
    }
    let mut th = Xof::new(Tag::Tree);
    th.update(iv).update(&[tree]);
    for j in 0..n_leaves {
        if j == jstar {
            th.absorb(&opening[depth * SEED_BYTES..]);
        } else {
            let mut com = [0u8; COM_BYTES];
            leaf(
                iv,
                tree,
                n_leaves + j,
                &nodes[n_leaves + j],
                &mut sds[j],
                &mut com,
            );
            th.absorb(&com);
        }
    }
    th.finalize()
}

#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;

    #[test]
    fn open_then_reconstruct() {
        let iv = [3u8; 16];
        let root = [9u8; 16];
        for depth in [4usize, 5, 6, 8] {
            let n_leaves = 1 << depth;
            let t = commit(&root, &iv, 5, depth);
            for jstar in [0usize, 1, n_leaves / 2 + 3, n_leaves - 2, n_leaves - 1] {
                let op = t.open(jstar);
                assert_eq!(op.len(), opening_len(depth));
                let mut sds = [[0u8; 16]; MAX_LEAVES];
                let h = reconstruct(&op, &iv, 5, depth, jstar, &mut sds);
                assert_eq!(h, t.hash);
                for (j, (got, want)) in sds.iter().zip(t.sds.iter()).enumerate() {
                    if j != jstar {
                        assert_eq!(got, want);
                    }
                }
                // A different tree index or hidden leaf changes the commitment.
                let mut sds2 = [[0u8; 16]; MAX_LEAVES];
                assert_ne!(reconstruct(&op, &iv, 6, depth, jstar, &mut sds2), t.hash);
                assert_ne!(
                    reconstruct(&op, &iv, 5, depth, jstar ^ 1, &mut sds2),
                    t.hash
                );
            }
        }
    }
}
