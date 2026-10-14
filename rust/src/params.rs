//! Protocol constants (SPEC.md §2). Nothing here is negotiable at run time.

#![forbid(unsafe_code)]

/// Protocol version byte, first byte of every proof and hashed into mu.
pub const VERSION: u8 = 0x01;
/// ASCII label used in every domain-separation tag.
pub const VERSION_LABEL: &str = "v0.1";

/// Security parameter and field size: GF(2^128).
pub const LAMBDA: usize = 128;
pub const LAMBDA_BYTES: usize = LAMBDA / 8;

/// Deepest GGM tree this crate supports, and its number of leaves.
pub const MAX_DEPTH: usize = 8;
pub const MAX_LEAVES: usize = 1 << MAX_DEPTH;

/// VOLE rows that mask the QuickSilver response (one field element).
pub const QS_MASK_BITS: usize = LAMBDA;
/// VOLE rows that mask the VOLE consistency hash (two field elements).
pub const VH_MASK_BITS: usize = 2 * LAMBDA;

/// Hedging randomness per proof.
pub const RHO_BYTES: usize = 32;
/// Largest message accepted by prove and verify.
pub const MAX_MESSAGE_LEN: usize = 65_535;
/// Proof header: version byte, statement id byte.
pub const HEADER_BYTES: usize = 2;

/// GGM node seeds and leaf seeds.
pub const SEED_BYTES: usize = LAMBDA_BYTES;
/// Leaf commitments.
pub const COM_BYTES: usize = 2 * LAMBDA_BYTES;

/// FAEST-style split of the LAMBDA challenge bits over tau GGM trees: the
/// first tau0 = LAMBDA mod tau trees have depth k0 = ceil(LAMBDA / tau), the
/// other tau1 = tau - tau0 trees depth k1 = floor(LAMBDA / tau). Tree i hides
/// the leaf whose index is bits [offset(i), offset(i) + depth(i)) of Delta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeSplit {
    tau: usize,
    tau0: usize,
    k0: usize,
    k1: usize,
}

impl TreeSplit {
    /// The split for tau trees, or None unless every depth is 1..=MAX_DEPTH.
    pub const fn for_tau(tau: usize) -> Option<TreeSplit> {
        if tau == 0 || tau > LAMBDA {
            return None;
        }
        let k0 = LAMBDA.div_ceil(tau);
        if k0 > MAX_DEPTH {
            return None;
        }
        Some(TreeSplit {
            tau,
            tau0: LAMBDA % tau,
            k0,
            k1: LAMBDA / tau,
        })
    }

    pub const fn tau(&self) -> usize {
        self.tau
    }

    /// (tau0, k0, tau1, k1).
    pub const fn shape(&self) -> (usize, usize, usize, usize) {
        (self.tau0, self.k0, self.tau - self.tau0, self.k1)
    }

    /// Depth of tree i.
    pub const fn depth(&self, i: usize) -> usize {
        if i < self.tau0 {
            self.k0
        } else {
            self.k1
        }
    }

    /// First bit of Delta (and first VOLE column) of tree i.
    pub const fn offset(&self, i: usize) -> usize {
        if i < self.tau0 {
            i * self.k0
        } else {
            self.tau0 * self.k0 + (i - self.tau0) * self.k1
        }
    }

    /// Length of the opening of tree i: its co-path seeds and one commitment.
    pub const fn opening_bytes(&self, i: usize) -> usize {
        self.depth(i) * SEED_BYTES + COM_BYTES
    }

    /// Offset of the opening of tree i within the openings.
    pub const fn opening_offset(&self, i: usize) -> usize {
        self.offset(i) * SEED_BYTES + i * COM_BYTES
    }

    /// Length of all openings.
    pub const fn openings_bytes(&self) -> usize {
        LAMBDA * SEED_BYTES + self.tau * COM_BYTES
    }

    /// The hidden leaf of tree i for challenge Delta.
    pub const fn challenge_index(&self, delta: u128, i: usize) -> usize {
        ((delta >> self.offset(i)) as usize) & ((1 << self.depth(i)) - 1)
    }
}

/// The parameter set of this version: 16 trees of depth 8.
pub const SPLIT: TreeSplit = match TreeSplit::for_tau(16) {
    Some(s) => s,
    None => panic!("invalid tree split"),
};

const _: () = assert!(SPLIT.offset(SPLIT.tau() - 1) + SPLIT.depth(SPLIT.tau() - 1) == LAMBDA);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faest_splits() {
        for (tau, shape) in [
            (16, (0, 8, 16, 8)),
            (22, (18, 6, 4, 5)),
            (24, (8, 6, 16, 5)),
            (26, (24, 5, 2, 4)),
            (32, (0, 4, 32, 4)),
        ] {
            let s = TreeSplit::for_tau(tau).unwrap();
            assert_eq!(s.shape(), shape);
            let total: usize = (0..tau).map(|i| s.depth(i)).sum();
            assert_eq!(total, LAMBDA);
            let mut off = 0;
            let mut open = 0;
            for i in 0..tau {
                assert_eq!(s.offset(i), off);
                assert_eq!(s.opening_offset(i), open);
                off += s.depth(i);
                open += s.opening_bytes(i);
            }
            assert_eq!(open, s.openings_bytes());
        }
        for bad in [0, 15, 129] {
            assert!(TreeSplit::for_tau(bad).is_none());
        }
    }

    #[test]
    fn challenge_decoding() {
        let s = TreeSplit::for_tau(24).unwrap();
        let delta: u128 = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
        let mut pos = 0;
        for i in 0..s.tau() {
            let mut want = 0;
            for b in 0..s.depth(i) {
                want |= (((delta >> (pos + b)) & 1) as usize) << b;
            }
            assert_eq!(s.challenge_index(delta, i), want);
            pos += s.depth(i);
        }
    }
}
