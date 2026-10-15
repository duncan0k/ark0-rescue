//! Carry-less multiplication with PCLMULQDQ (x86 and x86-64), selected at
//! run time with `is_x86_feature_detected!`.
//!
//! This module and [`crate::ffi`] are the only ones that may contain unsafe
//! code: calling a `#[target_feature]` function, which is sound only after
//! the feature has been detected on the running CPU.
//!
//! PCLMULQDQ runs in a fixed number of cycles independent of its operands,
//! and nothing here branches on or indexes by the operands.

#![allow(unsafe_code)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128};

/// Whether the running CPU has PCLMULQDQ (and SSE2, which the loads and
/// stores need). The detection result is cached by the standard library;
/// with `-C target-feature=+pclmulqdq` it is a compile-time constant.
#[inline]
pub fn available() -> bool {
    std::arch::is_x86_feature_detected!("pclmulqdq") && std::arch::is_x86_feature_detected!("sse2")
}

/// Carry-less product of two 128-bit polynomials as (low, high) halves.
///
/// # Safety
/// The CPU must support PCLMULQDQ and SSE2 (`available()` returned true).
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn clmul128_hw(a: u128, b: u128) -> (u128, u128) {
    let va = _mm_set_epi64x((a >> 64) as u64 as i64, a as u64 as i64);
    let vb = _mm_set_epi64x((b >> 64) as u64 as i64, b as u64 as i64);
    // Schoolbook: four 64x64 products.
    let lo = _mm_clmulepi64_si128(va, vb, 0x00);
    let hi = _mm_clmulepi64_si128(va, vb, 0x11);
    let m0 = _mm_clmulepi64_si128(va, vb, 0x01);
    let m1 = _mm_clmulepi64_si128(va, vb, 0x10);
    let mut out = [[0u8; 16]; 4];
    for (o, v) in out.iter_mut().zip([lo, hi, m0, m1]) {
        // Unaligned store into 16 writable bytes.
        _mm_storeu_si128(o.as_mut_ptr().cast::<__m128i>(), v);
    }
    let lo = u128::from_le_bytes(out[0]);
    let hi = u128::from_le_bytes(out[1]);
    let mid = u128::from_le_bytes(out[2]) ^ u128::from_le_bytes(out[3]);
    (lo ^ (mid << 64), hi ^ (mid >> 64))
}

/// Product in GF(2^128) with PCLMULQDQ.
///
/// # Safety
/// The CPU must support PCLMULQDQ and SSE2 (`available()` returned true).
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn mul_hw(a: u128, b: u128) -> u128 {
    let (lo, hi) = clmul128_hw(a, b);
    crate::gf128::reduce(lo, hi)
}

/// Product in GF(2^128) with PCLMULQDQ, or None if the running CPU lacks it.
#[inline]
pub fn mul(a: u128, b: u128) -> Option<u128> {
    if available() {
        // SAFETY: PCLMULQDQ and SSE2 were detected on the running CPU.
        Some(unsafe { mul_hw(a, b) })
    } else {
        None
    }
}
