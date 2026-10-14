//! The universal hashes of the two consistency checks (SPEC.md §5.4, §6.3).

#![forbid(unsafe_code)]

use crate::bits;
use crate::gf128::{self, FixedMul};
use crate::params::LAMBDA;

/// VOLEHash with keys s, t (from chall1): for x of lhat = ell + 3*LAMBDA
/// bits, x0 = x[0, ell + LAMBDA) zero-padded to n_v 128-bit blocks y_j and
/// x1 = x[ell + LAMBDA, lhat),
/// `VH(x) = enc(P_s(x0) + x1[0,128)) || enc(P_t(x0) + x1[128,256))`,
/// `P_s(x0) = sum_j y_j s^(n_v - j)`.
pub struct VoleHash {
    ms: FixedMul,
    mt: FixedMul,
    n_in: usize,
    n_blocks: usize,
}

impl VoleHash {
    pub fn new(chall1: &[u8; 32], ell: usize) -> Self {
        let mut s = [0u8; 16];
        let mut t = [0u8; 16];
        s.copy_from_slice(&chall1[..16]);
        t.copy_from_slice(&chall1[16..]);
        let n_in = ell + LAMBDA;
        VoleHash {
            ms: FixedMul::new(gf128::from_bytes(&s)),
            mt: FixedMul::new(gf128::from_bytes(&t)),
            n_in,
            n_blocks: n_in.div_ceil(128),
        }
    }

    /// VH of a bit string of lhat bits given as `nbytes(lhat)` bytes.
    pub fn hash(&self, x: &[u8]) -> [u8; 32] {
        let mut hs = 0u128;
        let mut ht = 0u128;
        let full = self.n_in / 128;
        for chunk in x[..16 * full].chunks_exact(16) {
            let mut b = [0u8; 16];
            b.copy_from_slice(chunk);
            let y = u128::from_le_bytes(b);
            hs = self.ms.mul(hs ^ y);
            ht = self.mt.mul(ht ^ y);
        }
        if full < self.n_blocks {
            let y = bits::load_bits(x, 128 * full, self.n_in - 128 * full);
            hs = self.ms.mul(hs ^ y);
            ht = self.mt.mul(ht ^ y);
        }
        hs ^= bits::load_bits(x, self.n_in, 128);
        ht ^= bits::load_bits(x, self.n_in + 128, 128);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&gf128::to_bytes(hs));
        out[16..].copy_from_slice(&gf128::to_bytes(ht));
        out
    }
}

/// ZKHash with keys r0, r1, s, t (from chall2):
/// `ZKH(x; z) = r0 sum_i s^(C-1-i) x_i + r1 sum_i t^(C-1-i) x_i + z`.
pub struct ZkHash {
    r0: u128,
    r1: u128,
    ms: FixedMul,
    mt: FixedMul,
}

/// A running ZKHash (Horner: h = h * s + x_i).
#[derive(Clone, Copy, Default)]
pub struct ZkAcc {
    hs: u128,
    ht: u128,
}

impl ZkHash {
    pub fn new(chall2: &[u8; 64]) -> Self {
        let key = |k: usize| {
            let mut b = [0u8; 16];
            b.copy_from_slice(&chall2[16 * k..16 * k + 16]);
            gf128::from_bytes(&b)
        };
        ZkHash {
            r0: key(0),
            r1: key(1),
            ms: FixedMul::new(key(2)),
            mt: FixedMul::new(key(3)),
        }
    }

    #[inline]
    pub fn absorb(&self, acc: &mut ZkAcc, x: u128) {
        acc.hs = self.ms.mul(acc.hs) ^ x;
        acc.ht = self.mt.mul(acc.ht) ^ x;
    }

    pub fn finish(&self, acc: &ZkAcc, mask: u128) -> u128 {
        gf128::mul(self.r0, acc.hs) ^ gf128::mul(self.r1, acc.ht) ^ mask
    }
}
