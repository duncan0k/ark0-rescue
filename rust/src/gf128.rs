//! Arithmetic in GF(2^128) = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
//! (SPEC.md §1.3).
//!
//! An element is a `u128` whose bit i is the coefficient of X^i; its byte
//! encoding is the 16-byte little-endian form (byte 0 holds X^0..X^7).
//!
//! Portable code only: no carry-less multiply instruction is used, so a
//! generic x86-64 build behaves like any other target. The table lookups
//! depend on the operands, so this is not constant time; the verifier works
//! on public data only.

#![forbid(unsafe_code)]

/// X^128 = X^7 + X^2 + X + 1 modulo the field polynomial.
const RED: u128 = 0x87;

#[inline]
pub fn from_bytes(b: &[u8; 16]) -> u128 {
    u128::from_le_bytes(*b)
}

#[inline]
pub fn to_bytes(a: u128) -> [u8; 16] {
    a.to_le_bytes()
}

/// Multiplication by X.
#[inline]
pub fn mul_x(a: u128) -> u128 {
    (a << 1) ^ ((a >> 127) * RED)
}

/// Carry-less product of two 64-bit polynomials (4-bit window).
#[inline]
fn clmul64(a: u64, b: u64) -> u128 {
    let a = a as u128;
    let a2 = a << 1;
    let a4 = a << 2;
    let a8 = a << 3;
    let t = [
        0,
        a,
        a2,
        a2 ^ a,
        a4,
        a4 ^ a,
        a4 ^ a2,
        a4 ^ a2 ^ a,
        a8,
        a8 ^ a,
        a8 ^ a2,
        a8 ^ a2 ^ a,
        a8 ^ a4,
        a8 ^ a4 ^ a,
        a8 ^ a4 ^ a2,
        a8 ^ a4 ^ a2 ^ a,
    ];
    let mut z = 0u128;
    let mut sh = 64;
    while sh > 0 {
        sh -= 4;
        z = (z << 4) ^ t[((b >> sh) & 15) as usize];
    }
    z
}

/// Carry-less product of two 128-bit polynomials as (low, high) halves
/// (Karatsuba over 64-bit halves).
#[inline]
fn clmul128(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64(a0, b0);
    let hi = clmul64(a1, b1);
    let mid = clmul64(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    (lo ^ (mid << 64), hi ^ (mid >> 64))
}

/// Reduce lo + hi * X^128 modulo the field polynomial.
#[inline]
pub fn reduce(lo: u128, hi: u128) -> u128 {
    // hi * X^128 = hi * (X^7 + X^2 + X + 1); the part of degree >= 128 has
    // degree <= 6 and is folded once more.
    let t_lo = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
    let t_hi = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
    lo ^ t_lo ^ t_hi ^ (t_hi << 1) ^ (t_hi << 2) ^ (t_hi << 7)
}

/// Product in GF(2^128).
#[inline]
pub fn mul(a: u128, b: u128) -> u128 {
    let (lo, hi) = clmul128(a, b);
    reduce(lo, hi)
}

/// Multiplication by a fixed element with 16 byte-indexed tables (64 KiB):
/// table k, entry v holds a * X^(8k) * v(X).
pub struct FixedMul {
    t: Vec<[u128; 256]>,
}

impl FixedMul {
    pub fn new(a: u128) -> Self {
        let mut t = vec![[0u128; 256]; 16];
        let mut base = a;
        for row in t.iter_mut() {
            let mut p = base;
            for j in 0..8 {
                row[1 << j] = p;
                p = mul_x(p);
            }
            for v in 3..256usize {
                let low = v & v.wrapping_neg();
                if low != v {
                    row[v] = row[low] ^ row[v ^ low];
                }
            }
            base = p;
        }
        FixedMul { t }
    }

    #[inline]
    pub fn mul(&self, x: u128) -> u128 {
        let b = x.to_le_bytes();
        let mut z = 0u128;
        for (row, &byte) in self.t.iter().zip(b.iter()) {
            z ^= row[byte as usize];
        }
        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit-by-bit reference multiplication.
    fn mul_ref(a: u128, b: u128) -> u128 {
        let mut z = 0u128;
        let mut a = a;
        for i in 0..128 {
            if (b >> i) & 1 == 1 {
                z ^= a;
            }
            a = mul_x(a);
        }
        z
    }

    fn sample(i: u64) -> u128 {
        // xorshift-style deterministic values, plus edge cases
        let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xD1B5_4A32_D192_ED03;
        x ^= x >> 29;
        let y = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        ((x as u128) << 64) | (y ^ (y >> 31)) as u128
    }

    #[test]
    fn mul_matches_reference() {
        let edge = [
            0u128,
            1,
            2,
            RED,
            u128::MAX,
            1 << 127,
            (1 << 127) | 1,
            0xFFFF_FFFF_FFFF_FFFF,
        ];
        for &a in &edge {
            for &b in &edge {
                assert_eq!(mul(a, b), mul_ref(a, b));
            }
        }
        for i in 0..2000 {
            let (a, b) = (sample(2 * i), sample(2 * i + 1));
            assert_eq!(mul(a, b), mul_ref(a, b));
            assert_eq!(mul(a, b), mul(b, a));
        }
    }

    #[test]
    fn reduction_identity() {
        // X^127 * X = X^128 = X^7 + X^2 + X + 1
        assert_eq!(mul(1 << 127, 2), RED);
        assert_eq!(mul_x(1 << 127), RED);
        // (X^127)^2 = X^254 = X^126 * X^128 = X^126 (X^7 + X^2 + X + 1)
        let x126 = 1u128 << 126;
        assert_eq!(mul(1 << 127, 1 << 127), mul_ref(x126, RED));
    }

    #[test]
    fn fixed_mul_matches_mul() {
        for i in 0..50 {
            let a = sample(1000 + i);
            let fm = FixedMul::new(a);
            for j in 0..50 {
                let x = sample(5000 + 50 * i + j);
                assert_eq!(fm.mul(x), mul(a, x));
            }
            assert_eq!(fm.mul(0), 0);
            assert_eq!(fm.mul(1), a);
        }
    }
}
