//! `voleith_verify_s1` with arbitrary lengths and null pointers. Run it under
//! AddressSanitizer: every buffer is an exact-size heap allocation, so a read
//! past a declared length, or a read of a buffer whose length should have been
//! rejected first, is reported.
//!
//! Invariants: no crash, no panic (libfuzzer-sys aborts on any panic, even one
//! the shim would catch), the result is 0 or 1, and 1 only for a known-valid
//! (K, suffix, y, msg, proof).
//!
//! Input: u8 flags, then per pointer (k, y, msg, proof) a mode byte and a
//! length, u8 suffix, then the payload used to fill buffers or edit a base.
//! Modes per pointer:
//!   0: exact-size buffer of the declared length (length clamped so the
//!      buffer can be filled; for proof, 130218 is reachable);
//!   1: null pointer with length 0 (allowed by the header);
//!   2: null pointer with an arbitrary nonzero length (must return 0);
//!   3: a short buffer with an out-of-range length (k_len outside 1..64,
//!      msg_len > 65535, proof_len != 130218), which the length checks must
//!      reject before any read.
//! flags bit 0: start from a valid vector's fields (selector byte) and XOR the
//! payload into them, so mode-0 inputs reach the full verification.

#![no_main]

use libfuzzer_sys::fuzz_target;
use voleith::ffi::voleith_verify_s1;
use voleith_fuzz::{known, Reader, PROOF_LEN};

#[derive(Clone, Copy)]
enum Mode {
    Exact(usize),
    NullZero,
    NullLen(usize),
    ShortBad(usize),
}

fn mode(r: &mut Reader, max_valid: usize, valid: fn(usize) -> bool, default_len: usize) -> Mode {
    let m = r.u8();
    let len = r.u64() as usize;
    match m % 4 {
        0 => {
            // Bias toward the expected length.
            if m & 0x80 != 0 { Mode::Exact(default_len) } else { Mode::Exact(len % (max_valid + 1)) }
        }
        1 => Mode::NullZero,
        2 => Mode::NullLen(len.max(1)),
        _ => {
            if valid(len) { Mode::Exact(len % (max_valid + 1)) } else { Mode::ShortBad(len) }
        }
    }
}

/// An exact-size buffer of `len` bytes from `src` (cycled), with `base`
/// underneath when given.
fn buffer(len: usize, base: Option<&[u8]>, src: &[u8], cursor: &mut usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    if let Some(b) = base {
        let n = b.len().min(len);
        v[..n].copy_from_slice(&b[..n]);
    }
    // Sparse XOR edits from the payload: (u24 offset, mask) pairs when a base
    // is present; a straight fill otherwise.
    if base.is_some() {
        while *cursor + 4 <= src.len() {
            let off = u32::from_le_bytes([src[*cursor], src[*cursor + 1], src[*cursor + 2], 0]) as usize;
            let mask = src[*cursor + 3];
            *cursor += 4;
            if len > 0 {
                v[off % len] ^= mask;
            }
            if mask == 0 {
                break; // a zero mask ends this buffer's edits
            }
        }
    } else if !src.is_empty() {
        for b in v.iter_mut() {
            *b = src[*cursor % src.len()];
            *cursor += 1;
        }
    }
    v
}

struct Arg {
    buf: Option<Vec<u8>>,
    len: usize,
}

impl Arg {
    fn ptr(&self) -> *const u8 {
        match &self.buf {
            Some(b) if !b.is_empty() => b.as_ptr(),
            // An empty Vec has a dangling (non-null) pointer, which the
            // shim must never read for length 0.
            Some(b) => b.as_ptr(),
            None => std::ptr::null(),
        }
    }
}

fn arg(m: Mode, base: Option<&[u8]>, src: &[u8], cursor: &mut usize) -> Arg {
    match m {
        Mode::Exact(len) => Arg { buf: Some(buffer(len, base, src, cursor)), len },
        Mode::NullZero => Arg { buf: None, len: 0 },
        Mode::NullLen(len) => Arg { buf: None, len },
        // 4 real bytes, but an out-of-range length: must not be read.
        Mode::ShortBad(len) => Arg { buf: Some(buffer(4, base, src, cursor)), len },
    }
}

fuzz_target!(|data: &[u8]| {
    let k = known();
    let mut r = Reader::new(data);
    let flags = r.u8();
    let sel = r.u8() as usize % k.valid.len();
    let mk = mode(&mut r, 64, |l| (1..=64).contains(&l), k.valid[sel].key.len());
    let my = r.u8() % 4; // 0/3: 32-byte buffer, 1/2: null
    let mm = mode(&mut r, 65_535, |l| l <= 65_535, k.valid[sel].message.len());
    let mp = mode(&mut r, PROOF_LEN, |l| l == PROOF_LEN, PROOF_LEN);
    let suffix_raw = r.u8();
    let payload = r.rest();

    let v = &k.valid[sel];
    let from_base = flags & 1 != 0;
    let mut cur = 0usize;
    let ka = arg(mk, from_base.then_some(&v.key[..]), payload, &mut cur);
    let ya = match my {
        1 | 2 => Arg { buf: None, len: 32 },
        _ => Arg { buf: Some(buffer(32, from_base.then_some(&v.y[..]), payload, &mut cur)), len: 32 },
    };
    let ma = arg(mm, from_base.then_some(&v.message[..]), payload, &mut cur);
    let pa = arg(mp, from_base.then_some(&v.proof[..]), payload, &mut cur);
    let suffix = if from_base && flags & 2 == 0 { v.suffix } else { suffix_raw };

    // SAFETY: every non-null pointer points to `len` readable bytes, except
    // in mode 3 (ShortBad), where the length is out of range and the shim's
    // contract is that it is checked before any read (ASan verifies this).
    // A null y is outside the header's contract but the shim checks for it.
    let res = unsafe {
        voleith_verify_s1(ka.ptr(), ka.len, suffix, ya.ptr(), ma.ptr(), ma.len, pa.ptr(), pa.len)
    };
    assert!(res == 0 || res == 1, "result {res}");
    if res == 1 {
        // A null pointer with length 0 is the empty string (allowed by the
        // header; a valid vector has an empty message).
        let view = |a: &Arg| -> Option<Vec<u8>> {
            match (&a.buf, a.len) {
                (Some(b), _) => Some(b.clone()),
                (None, 0) => Some(Vec::new()),
                (None, _) => None,
            }
        };
        let (Some(kb), Some(yb), Some(mb), Some(pb)) = (view(&ka), ya.buf.clone(), view(&ma), view(&pa)) else {
            panic!("CRITICAL: accepted with a null pointer and a nonzero length");
        };
        assert!(
            kb.len() == ka.len && mb.len() == ma.len && pb.len() == pa.len,
            "CRITICAL: accepted with a declared length different from the buffer"
        );
        let (kb, mb, pb) = (&kb, &mb, &pb);
        let mut y = [0u8; 32];
        y.copy_from_slice(&yb);
        let pubi = voleith::s1_encode_public(kb, suffix, &y).expect("accepted a non-canonical K");
        assert!(k.contains(&pubi, mb, pb), "CRITICAL: FFI accepted a non-valid input");
    }
});
