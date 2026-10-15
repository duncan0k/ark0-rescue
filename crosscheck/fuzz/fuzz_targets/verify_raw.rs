//! Arbitrary bytes split into (statement id, public inputs, message, proof)
//! and passed to `voleith::verify`. Invariants: no panic, and no accept
//! unless the triple is one of the known-valid vectors.
//!
//! Input layout:
//!   u8 flags, u8 statement id, u16 |pub|, u32 |msg|, then pub, msg, proof
//!   (the proof is the rest of the input).
//! flags bit 0: zero-pad or truncate the proof to the statement 0x01 length;
//! bit 1: force the header bytes to 0x02 0x01; bit 2: force the statement id
//! to 0x01. Without them almost every input stops at steps 1–5; with them
//! the fuzzer reaches the padding checks and the full verification.

#![no_main]

use libfuzzer_sys::fuzz_target;
use voleith_fuzz::{known, Reader, Timing, PROOF_LEN, STATEMENT_ID};

fuzz_target!(|data: &[u8]| {
    let timing = Timing::get();
    let mut r = Reader::new(data);
    let flags = r.u8();
    let mut sid = r.u8();
    let pub_len = r.u16() as usize;
    let msg_len = r.u32() as usize % 70_000;
    let public_inputs = r.bytes(pub_len).to_vec();
    let message = r.bytes(msg_len).to_vec();
    let mut proof = r.rest().to_vec();
    if flags & 1 != 0 {
        proof.resize(PROOF_LEN, 0);
    }
    if flags & 2 != 0 && proof.len() >= 2 {
        proof[0] = 0x02;
        proof[1] = 0x01;
    }
    if flags & 4 != 0 {
        sid = STATEMENT_ID;
    }
    let ok = timing.check(data, || voleith::verify(sid, &public_inputs, &message, &proof));
    if ok {
        assert!(
            sid == STATEMENT_ID && known().contains(&public_inputs, &message, &proof),
            "CRITICAL: verify accepted an input that is not a known-valid proof"
        );
    }
});
