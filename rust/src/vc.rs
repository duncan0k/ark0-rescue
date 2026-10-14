//! All-but-one vector commitment from a GGM tree with hashed leaves
//! (SPEC.md §4).
//!
//! Tree i has depth K and N = 2^K leaves in heap numbering: the root is node
//! 1, the children of node n are 2n and 2n+1, and leaf j is node N + j.

#![forbid(unsafe_code)]

use crate::params::{COM_BYTES, K, N_LEAVES, OPENING_BYTES, SEED_BYTES};
use crate::sym::{Tag, Xof};

pub type Seed = [u8; SEED_BYTES];
pub type Com = [u8; COM_BYTES];

/// Children of node n: SHAKE256[ggm](iv || u8(i) || u16le(n) || seed_n, 32).
#[inline]
fn expand(iv: &[u8; 16], tree: u8, node: usize, seed: &Seed) -> (Seed, Seed) {
    let out: [u8; 2 * SEED_BYTES] = Xof::new(Tag::Ggm)
        .update(iv)
        .update(&[tree])
        .update(&(node as u16).to_le_bytes())
        .update(seed)
        .finalize();
    let mut l = [0u8; SEED_BYTES];
    let mut r = [0u8; SEED_BYTES];
    l.copy_from_slice(&out[..SEED_BYTES]);
    r.copy_from_slice(&out[SEED_BYTES..]);
    (l, r)
}

/// (sd_j, com_j) = SHAKE256[leaf](iv || u8(i) || u16le(N + j) || seed, 48).
#[inline]
fn leaf(iv: &[u8; 16], tree: u8, j: usize, seed: &Seed) -> (Seed, Com) {
    let out: [u8; SEED_BYTES + COM_BYTES] = Xof::new(Tag::Leaf)
        .update(iv)
        .update(&[tree])
        .update(&((N_LEAVES + j) as u16).to_le_bytes())
        .update(seed)
        .finalize();
    let mut sd = [0u8; SEED_BYTES];
    let mut com = [0u8; COM_BYTES];
    sd.copy_from_slice(&out[..SEED_BYTES]);
    com.copy_from_slice(&out[SEED_BYTES..]);
    (sd, com)
}

/// Heap index of the co-path node of leaf j* at depth d (1..=K).
#[inline]
fn copath(jstar: usize, d: usize) -> usize {
    ((N_LEAVES + jstar) >> (K - d)) ^ 1
}

/// Prover side: the expanded tree of one root.
#[cfg(test)]
pub struct Tree {
    pub hash: [u8; 32],
    nodes: Vec<Seed>,
    pub sds: Vec<Seed>,
    coms: Vec<Com>,
}

#[cfg(test)]
pub fn commit(root: &Seed, iv: &[u8; 16], tree: u8) -> Tree {
    let mut nodes = vec![[0u8; SEED_BYTES]; 2 * N_LEAVES];
    nodes[1] = *root;
    for n in 1..N_LEAVES {
        let (l, r) = expand(iv, tree, n, &nodes[n]);
        nodes[2 * n] = l;
        nodes[2 * n + 1] = r;
    }
    let mut sds = Vec::with_capacity(N_LEAVES);
    let mut coms = Vec::with_capacity(N_LEAVES);
    let mut th = Xof::new(Tag::Tree).update(iv).update(&[tree]);
    for j in 0..N_LEAVES {
        let (sd, com) = leaf(iv, tree, j, &nodes[N_LEAVES + j]);
        th.absorb(&com);
        sds.push(sd);
        coms.push(com);
    }
    Tree {
        hash: th.finalize(),
        nodes,
        sds,
        coms,
    }
}

#[cfg(test)]
impl Tree {
    /// The opening for hidden leaf j*: co-path seeds top-down, then com_{j*}.
    pub fn open(&self, jstar: usize) -> [u8; OPENING_BYTES] {
        let mut out = [0u8; OPENING_BYTES];
        for d in 1..=K {
            out[(d - 1) * SEED_BYTES..d * SEED_BYTES]
                .copy_from_slice(&self.nodes[copath(jstar, d)]);
        }
        out[K * SEED_BYTES..].copy_from_slice(&self.coms[jstar]);
        out
    }
}

/// Verifier side (SPEC.md §4.4): from an opening and j*, recompute the tree
/// commitment h_i and the leaf seeds sd_j for j != j* (`sds[j*]` is left
/// untouched).
pub fn reconstruct(
    opening: &[u8; OPENING_BYTES],
    iv: &[u8; 16],
    tree: u8,
    jstar: usize,
    sds: &mut [Seed; N_LEAVES],
) -> [u8; 32] {
    let mut nodes = [[0u8; SEED_BYTES]; 2 * N_LEAVES];
    let mut known = [false; 2 * N_LEAVES];
    for d in 1..=K {
        let n = copath(jstar, d);
        nodes[n].copy_from_slice(&opening[(d - 1) * SEED_BYTES..d * SEED_BYTES]);
        known[n] = true;
    }
    for n in 2..N_LEAVES {
        if known[n] {
            let (l, r) = expand(iv, tree, n, &nodes[n]);
            nodes[2 * n] = l;
            nodes[2 * n + 1] = r;
            known[2 * n] = true;
            known[2 * n + 1] = true;
        }
    }
    let mut th = Xof::new(Tag::Tree).update(iv).update(&[tree]);
    for j in 0..N_LEAVES {
        if j == jstar {
            th.absorb(&opening[K * SEED_BYTES..]);
        } else {
            let (sd, com) = leaf(iv, tree, j, &nodes[N_LEAVES + j]);
            th.absorb(&com);
            sds[j] = sd;
        }
    }
    th.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_then_reconstruct() {
        let iv = [3u8; 16];
        let root = [9u8; 16];
        let t = commit(&root, &iv, 5);
        for jstar in [0usize, 1, 77, 128, 254, 255] {
            let op = t.open(jstar);
            let mut sds = [[0u8; 16]; N_LEAVES];
            let h = reconstruct(&op, &iv, 5, jstar, &mut sds);
            assert_eq!(h, t.hash);
            for (j, (got, want)) in sds.iter().zip(t.sds.iter()).enumerate() {
                if j != jstar {
                    assert_eq!(got, want);
                }
            }
            // A different tree index or IV changes the commitment.
            let mut sds2 = [[0u8; 16]; N_LEAVES];
            assert_ne!(reconstruct(&op, &iv, 6, jstar, &mut sds2), t.hash);
        }
    }
}
