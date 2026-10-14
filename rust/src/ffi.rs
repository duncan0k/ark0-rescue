//! C ABI for linking the verifier into C or C++ (see `include/voleith.h`).
//!
//! This is the only module that may contain unsafe code: turning the
//! caller's pointers into slices. Lengths are checked before any pointer is
//! read, and no panic crosses the boundary.

#![allow(unsafe_code)]

use core::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::params::MAX_MESSAGE_LEN;
use crate::statements::STATEMENT1_ID;

/// The slice at (ptr, len), or None for a null pointer with a nonzero length
/// or a length over isize::MAX.
///
/// # Safety
/// If `ptr` is not null, it must point to `len` readable bytes that stay
/// valid and unmodified for the returned lifetime.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() || len > isize::MAX as usize {
        return None;
    }
    // SAFETY: non-null, length checked, validity guaranteed by the caller.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Verify a statement 0x01 proof: K (`k`, `k_len` bytes), the suffix byte,
/// y (32 bytes at `y`), the message (`msg`, `msg_len` bytes) and the proof
/// (`proof`, `proof_len` bytes). Returns 1 if the proof is valid and 0
/// otherwise, including for every malformed input and any internal error.
///
/// # Safety
/// Each non-null pointer must point to at least as many readable bytes as
/// its length argument (32 for `y`), valid for the duration of the call.
/// A pointer may be null only if its length is 0 (`y` must not be null).
#[no_mangle]
pub unsafe extern "C" fn voleith_verify_s1(
    k: *const u8,
    k_len: usize,
    suffix: u8,
    y: *const u8,
    msg: *const u8,
    msg_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        // Length checks first: no pointer is read for an invalid length.
        if !(1..=64).contains(&k_len) || msg_len > MAX_MESSAGE_LEN || y.is_null() {
            return false;
        }
        if Some(proof_len) != crate::proof::proof_length(STATEMENT1_ID) {
            return false;
        }
        // SAFETY: lengths as given by the caller, see the function contract.
        let (Some(k), Some(y), Some(msg), Some(proof)) = (
            unsafe { slice(k, k_len) },
            unsafe { slice(y, 32) },
            unsafe { slice(msg, msg_len) },
            unsafe { slice(proof, proof_len) },
        ) else {
            return false;
        };
        let mut y32 = [0u8; 32];
        y32.copy_from_slice(y);
        let Some(public_inputs) = crate::statements::s1_encode_public(k, suffix, &y32) else {
            return false;
        };
        crate::proof::verify(STATEMENT1_ID, &public_inputs, msg, proof)
    }));
    match result {
        Ok(true) => 1,
        _ => 0,
    }
}
