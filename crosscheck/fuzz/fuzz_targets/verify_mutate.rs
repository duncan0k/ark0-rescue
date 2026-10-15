//! Structured mutations of the valid proofs in vectors/.
//!
//! The fuzz input is a mutation program: a base-vector selector, then up to
//! 16 operations on the (statement, message, proof) of that vector. libFuzzer
//! mutates and minimizes the program; the harness decodes it.
//!
//! Invariants:
//! - no panic;
//! - `verify` returns false whenever the result differs from the base triple
//!   (and true when it does not, as a sanity check of the oracle);
//! - each verification takes at most 2x the time of a valid one (Timing).

#![no_main]

use libfuzzer_sys::fuzz_target;
use voleith_fuzz::{known, sections, Reader, Timing, C_BYTES, D_BYTES, OFF_C, OFF_CHALL3, OFF_D, PROOF_LEN, STATEMENT_ID, TAU};

const MAX_OPS: usize = 16;

fn xor_at(buf: &mut Vec<u8>, off: usize, mask: u8) {
    if !buf.is_empty() {
        let i = off % buf.len();
        buf[i] ^= if mask == 0 { 1 } else { mask };
    }
}

/// Generic byte-level edits shared by proof, message and statement.
fn byte_op(r: &mut Reader, buf: &mut Vec<u8>, sel: u8) {
    match sel % 6 {
        // bit flip
        0 => {
            let off = r.u32() as usize;
            let bit = r.u8() % 8;
            xor_at(buf, off, 1 << bit);
        }
        // byte replace
        1 => {
            let off = r.u32() as usize;
            let v = r.u8();
            if !buf.is_empty() {
                let n = buf.len();
                buf[off % n] = v;
            }
        }
        // chunk swap
        2 => {
            let a = r.u32() as usize;
            let b = r.u32() as usize;
            let len = r.u16() as usize;
            let n = buf.len();
            if n > 1 {
                let len = len % (n / 2).max(1) + 1;
                let a = a % (n - len + 1);
                let b = b % (n - len + 1);
                if a + len <= b || b + len <= a {
                    for k in 0..len {
                        buf.swap(a + k, b + k);
                    }
                }
            }
        }
        // truncation
        3 => {
            let n = r.u32() as usize;
            let new_len = if buf.is_empty() { 0 } else { n % buf.len() };
            buf.truncate(new_len);
        }
        // extension
        4 => {
            let n = (r.u16() as usize % 1024) + 1;
            let v = r.u8();
            buf.extend(std::iter::repeat(v).take(n));
        }
        // splice of raw fuzz bytes
        _ => {
            let off = r.u32() as usize;
            let n = r.u8() as usize;
            let src = r.bytes(n);
            if !buf.is_empty() {
                let o = off % buf.len();
                for (k, &b) in src.iter().enumerate() {
                    if o + k < buf.len() {
                        buf[o + k] = b;
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let timing = Timing::get();
    let k = known();
    let secs = sections();
    let mut r = Reader::new(data);
    let base_idx = r.u8() as usize % k.valid.len();
    let base = &k.valid[base_idx];
    let mut pubi = base.public_inputs.clone();
    let mut msg = base.message.clone();
    let mut proof = base.proof.clone();

    for _ in 0..MAX_OPS {
        if r.is_empty() {
            break;
        }
        let op = r.u8();
        match op % 12 {
            // 0-1: generic byte-level edits of the proof (bit flips, byte
            // replacements, chunk swaps, truncations, extensions, splices).
            0 | 1 => {
                let sel = r.u8();
                byte_op(&mut r, &mut proof, sel);
            }
            // 2: header changes.
            2 => {
                let which = r.u8() as usize % 2;
                let v = r.u8();
                if proof.len() > which {
                    proof[which] = v;
                }
            }
            // 3: edit at a field boundary of a §10 section: first/last byte,
            // or the bytes just before/after it.
            3 => {
                let s = secs[r.u16() as usize % secs.len()];
                let pos = match r.u8() % 4 {
                    0 => s.start,
                    1 => s.start + s.len - 1,
                    2 => s.start.wrapping_sub(1),
                    _ => s.start + s.len,
                };
                let mask = r.u8();
                let bit_mode = r.u8() & 1 == 0;
                if pos < proof.len() {
                    proof[pos] ^= if bit_mode { 1 << (mask % 8) } else if mask == 0 { 0xff } else { mask };
                }
            }
            // 4: overwrite a whole section (zeros, ones, constant).
            4 => {
                let s = secs[r.u16() as usize % secs.len()];
                let v = match r.u8() % 3 {
                    0 => 0x00,
                    1 => 0xff,
                    _ => r.u8(),
                };
                if s.start + s.len <= proof.len() {
                    proof[s.start..s.start + s.len].fill(v);
                }
            }
            // 5: copy a section from another valid proof (cross splicing).
            5 => {
                let s = secs[r.u16() as usize % secs.len()];
                let other = &k.valid[r.u8() as usize % k.valid.len()];
                if s.start + s.len <= proof.len() {
                    proof[s.start..s.start + s.len]
                        .copy_from_slice(&other.proof[s.start..s.start + s.len]);
                }
            }
            // 6: swap two sections of equal length (e.g. two corrections,
            // two seeds, two commitments).
            6 => {
                let a = secs[r.u16() as usize % secs.len()];
                let b = secs[r.u16() as usize % secs.len()];
                if a.len == b.len && a.start != b.start && b.start + b.len <= proof.len() && a.start + a.len <= proof.len() {
                    for i in 0..a.len {
                        proof.swap(a.start + i, b.start + i);
                    }
                }
            }
            // 7: set padding bits of a correction or of d.
            7 => {
                let i = r.u8() as usize % TAU; // TAU-1 corrections + d
                let last = if i < TAU - 1 { OFF_C + (i + 1) * C_BYTES - 1 } else { OFF_D + D_BYTES - 1 };
                let mask = r.u8() & 0xfe; // bits above the used bit 0
                if last < proof.len() {
                    proof[last] |= if mask == 0 { 0x80 } else { mask };
                }
            }
            // 8: chall3 / Delta special values.
            8 => {
                if OFF_CHALL3 + 16 <= proof.len() {
                    let c = &mut proof[OFF_CHALL3..OFF_CHALL3 + 16];
                    match r.u8() % 4 {
                        0 => c.fill(0),
                        1 => c.fill(0xff),
                        2 => {
                            let other = &k.valid[r.u8() as usize % k.valid.len()];
                            c.copy_from_slice(&other.proof[OFF_CHALL3..OFF_CHALL3 + 16]);
                        }
                        _ => {
                            let b = r.u8() as usize % 128;
                            c[b / 8] ^= 1 << (b % 8);
                        }
                    }
                }
            }
            // 9: message edits.
            9 => {
                let sel = r.u8();
                if sel % 7 == 6 {
                    msg = k.valid[r.u8() as usize % k.valid.len()].message.clone();
                } else {
                    byte_op(&mut r, &mut msg, sel);
                }
            }
            // 10: statement edits, byte level.
            10 => {
                let sel = r.u8();
                byte_op(&mut r, &mut pubi, sel);
            }
            // 11: statement edits, field level (K, suffix, y).
            _ => {
                let kl = pubi.first().copied().unwrap_or(0) as usize;
                match r.u8() % 5 {
                    0 => {
                        // suffix
                        if 1 + kl < pubi.len() {
                            pubi[1 + kl] = r.u8();
                        }
                    }
                    1 => {
                        // a y bit
                        let b = r.u8() as usize;
                        if 2 + kl + 32 <= pubi.len() {
                            pubi[2 + kl + b % 32] ^= 1 << (b % 8);
                        }
                    }
                    2 => {
                        // K byte to another printable byte
                        let i = r.u8() as usize;
                        let v = 0x20 + r.u8() % 95;
                        if kl > 0 && 1 + kl <= pubi.len() {
                            pubi[1 + i % kl] = v;
                        }
                    }
                    3 => {
                        // the length byte
                        if !pubi.is_empty() {
                            pubi[0] = r.u8();
                        }
                    }
                    _ => {
                        pubi = k.valid[r.u8() as usize % k.valid.len()].public_inputs.clone();
                    }
                }
            }
        }
    }

    let unchanged = pubi == base.public_inputs && msg == base.message && proof == base.proof;
    let ok = timing.check(data, || voleith::verify(STATEMENT_ID, &pubi, &msg, &proof));
    if unchanged {
        assert!(ok, "oracle: the unmodified valid proof was rejected");
    } else if ok && !k.contains(&pubi, &msg, &proof) {
        panic!(
            "CRITICAL: verify accepted a modified proof (base {base_idx}, proof len {}, proof changed {}, msg changed {}, pub changed {})",
            proof.len(),
            proof != base.proof,
            msg != base.message,
            pubi != base.public_inputs,
        );
    }
    let _ = PROOF_LEN;
});
