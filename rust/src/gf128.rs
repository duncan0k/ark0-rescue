//! Arithmetic in GF(2^128) = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
//! (SPEC.md §1.3).
//!
//! An element is a `u128` whose bit i is the coefficient of X^i; its byte
//! encoding is the 16-byte little-endian form (byte 0 holds X^0..X^7).
//!
//! [`mul`], [`mul_x`] and [`reduce`] are constant time: no branch, memory
//! address or table index depends on an operand. [`mul`] uses PCLMULQDQ when
//! the running x86 CPU has it (checked at run time) and otherwise a portable
//! bit-serial masked multiplication. Both compute the same product.
//!
//! [`mul_public`] and [`FixedMul`] are for the verifier, which handles public
//! data only. With PCLMULQDQ they use the same constant-time multiplication
//! (it is faster than tables there); without it they fall back to
//! table-driven code that is not constant time (the operand indexes the
//! tables), because the portable constant-time multiplication is about four
//! times slower. The prover never calls them.

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

/// All ones if `bit` is 1, zero if it is 0 (`bit` must be 0 or 1).
#[inline(always)]
fn mask(bit: u128) -> u128 {
    0u128.wrapping_sub(bit)
}

/// Multiplication by X (constant time).
#[inline]
pub fn mul_x(a: u128) -> u128 {
    (a << 1) ^ (RED & mask(a >> 127))
}

/// Carry-less product of two 64-bit polynomials, bit-serial with masks: the
/// same 64 shifts, ANDs and XORs for every operand.
#[inline]
fn clmul64_ct(a: u64, b: u64) -> u128 {
    let a = a as u128;
    let mut z = 0u128;
    for i in 0..64 {
        z ^= (a << i) & mask(((b >> i) & 1) as u128);
    }
    z
}

/// Carry-less product of two 128-bit polynomials as (low, high) halves
/// (Karatsuba over 64-bit halves), constant time and portable.
#[inline]
fn clmul128_ct(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64_ct(a0, b0);
    let hi = clmul64_ct(a1, b1);
    let mid = clmul64_ct(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    (lo ^ (mid << 64), hi ^ (mid >> 64))
}

/// Carry-less product of two 64-bit polynomials (4-bit window). Not
/// constant time: `b` indexes the table. Public data only.
#[inline]
fn clmul64_vartime(a: u64, b: u64) -> u128 {
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

/// Whether [`mul`] uses a carry-less multiply instruction on this CPU.
#[inline]
pub fn has_clmul() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        crate::clmul::available()
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
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

/// Product in GF(2^128) with the portable constant-time multiplication.
#[inline]
pub fn mul_portable(a: u128, b: u128) -> u128 {
    let (lo, hi) = clmul128_ct(a, b);
    reduce(lo, hi)
}

/// Product in GF(2^128), constant time: PCLMULQDQ if the running CPU has
/// it, otherwise [`mul_portable`]. The choice depends only on the CPU.
#[inline]
pub fn mul(a: u128, b: u128) -> u128 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if let Some(z) = crate::clmul::mul(a, b) {
        return z;
    }
    mul_portable(a, b)
}

/// Product in GF(2^128) of public operands, for the verifier only: [`mul`]
/// if the CPU has a carry-less multiply instruction, otherwise a faster
/// table-driven multiplication that is not constant time.
#[inline]
pub fn mul_public(a: u128, b: u128) -> u128 {
    if has_clmul() {
        mul(a, b)
    } else {
        mul_vartime(a, b)
    }
}

/// Table-driven product (Karatsuba over 64-bit halves), not constant time.
#[inline]
fn mul_vartime(a: u128, b: u128) -> u128 {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let lo = clmul64_vartime(a0, b0);
    let hi = clmul64_vartime(a1, b1);
    let mid = clmul64_vartime(a0 ^ a1, b0 ^ b1) ^ lo ^ hi;
    reduce(lo ^ (mid << 64), hi ^ (mid >> 64))
}

/// Multiplication of public operands by a fixed public element, for the
/// verifier only. With a carry-less multiply instruction it is [`mul`];
/// otherwise it uses 16 byte-indexed tables (64 KiB), table k, entry v
/// holding a * X^(8k) * v(X), which is not constant time (the operand
/// indexes the tables).
pub struct FixedMul {
    a: u128,
    t: Option<Vec<[u128; 256]>>,
}

impl FixedMul {
    pub fn new(a: u128) -> Self {
        FixedMul {
            a,
            t: if has_clmul() {
                None
            } else {
                Some(Self::tables(a))
            },
        }
    }

    /// The table-driven form regardless of the CPU (for tests).
    #[cfg(test)]
    pub(crate) fn new_tables(a: u128) -> Self {
        FixedMul {
            a,
            t: Some(Self::tables(a)),
        }
    }

    fn tables(a: u128) -> Vec<[u128; 256]> {
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
        t
    }

    #[inline]
    pub fn mul(&self, x: u128) -> u128 {
        let Some(t) = &self.t else {
            return mul(self.a, x);
        };
        let b = x.to_le_bytes();
        let mut z = 0u128;
        for (row, &byte) in t.iter().zip(b.iter()) {
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
        for &a in &edge {
            for &b in &edge {
                assert_eq!(mul_portable(a, b), mul_ref(a, b));
            }
        }
        for i in 0..2000 {
            let (a, b) = (sample(2 * i), sample(2 * i + 1));
            assert_eq!(mul(a, b), mul_ref(a, b));
            assert_eq!(mul_portable(a, b), mul_ref(a, b));
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
    fn byte_order_known_answer() {
        // SPEC.md §1.3: bit i is the coefficient of X^i and byte 0 holds
        // X^0..X^7. X^127 is byte 15 = 0x80, X is byte 0 = 0x02, and
        // X^127 * X = X^128 = X^7 + X^2 + X + 1 is byte 0 = 0x87.
        let mut x127 = [0u8; 16];
        x127[15] = 0x80;
        let mut x1 = [0u8; 16];
        x1[0] = 0x02;
        let mut want = [0u8; 16];
        want[0] = 0x87;
        assert_eq!(to_bytes(mul(from_bytes(&x127), from_bytes(&x1))), want);
        assert_eq!(to_bytes(mul_x(from_bytes(&x127))), want);
        let fm = FixedMul::new(from_bytes(&x127));
        assert_eq!(to_bytes(fm.mul(from_bytes(&x1))), want);
        let fm = FixedMul::new_tables(from_bytes(&x127));
        assert_eq!(to_bytes(fm.mul(from_bytes(&x1))), want);
        assert_eq!(to_bytes(mul_portable(from_bytes(&x127), from_bytes(&x1))), want);
    }

    #[test]
    fn fixed_mul_matches_mul() {
        for i in 0..50 {
            let a = sample(1000 + i);
            let fm = FixedMul::new(a);
            let ft = FixedMul::new_tables(a);
            for j in 0..50 {
                let x = sample(5000 + 50 * i + j);
                assert_eq!(fm.mul(x), mul(a, x));
                assert_eq!(ft.mul(x), mul(a, x));
                assert_eq!(mul_public(a, x), mul(a, x));
                assert_eq!(mul_vartime(a, x), mul(a, x));
            }
            assert_eq!(fm.mul(0), 0);
            assert_eq!(fm.mul(1), a);
            assert_eq!(ft.mul(0), 0);
            assert_eq!(ft.mul(1), a);
        }
    }
}
