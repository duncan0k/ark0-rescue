//! Malformed inputs are rejected before the statement circuit is built
//! (SPEC.md §11: steps 1–6 need only fixed sizes). This file holds a single
//! test, so nothing else in its process builds the circuit first.

use voleith::circuit_info::circuit_is_built;
use voleith::params::VERSION;
use voleith::STATEMENT1_ID;

#[test]
fn format_checks_do_not_build_the_circuit() {
    assert!(!circuit_is_built(STATEMENT1_ID));
    let len = voleith::proof_length(STATEMENT1_ID).expect("registered");
    assert_eq!(len, 130_218);
    let key = b"ark0-wallet v1 schnorr";
    let y = [7u8; 32];
    let pub_inputs = voleith::s1_encode_public(key, 0, &y).unwrap();
    let msg = [0u8; 96];
    let long_msg = vec![0u8; 65_536];
    // A proof with a valid header, zero padding and a zero body: it passes
    // steps 1-6 and fails only at the final comparison.
    let mut proof = vec![0u8; len];
    proof[0] = VERSION;
    proof[1] = STATEMENT1_ID;
    let edit = |off: usize, v: u8| {
        let mut p = proof.clone();
        p[off] = v;
        p
    };
    let reject = |what: &str, sid: u8, p: &[u8], m: &[u8], pr: &[u8]| {
        assert!(!voleith::verify(sid, p, m, pr), "{what}");
        assert!(!circuit_is_built(STATEMENT1_ID), "{what} built the circuit");
    };
    reject("unknown statement id", 2, &pub_inputs, &msg, &proof);
    reject("public inputs", 1, &pub_inputs[1..], &msg, &proof);
    reject("message too long", 1, &pub_inputs, &long_msg, &proof);
    reject("empty proof", 1, &pub_inputs, &msg, &[]);
    reject("short proof", 1, &pub_inputs, &msg, &proof[..len - 1]);
    reject("version byte", 1, &pub_inputs, &msg, &edit(0, 0x01));
    reject("statement id byte", 1, &pub_inputs, &msg, &edit(1, 0x02));
    // The last byte of c_1 holds one padding bit (bit 7), as does d's.
    reject(
        "padding bit of c_1",
        1,
        &pub_inputs,
        &msg,
        &edit(18 + 5_306, 0x80),
    );
    reject(
        "padding bit of d",
        1,
        &pub_inputs,
        &msg,
        &edit(122_111 + 5_258, 0x80),
    );

    // The C ABI, with a wrong proof length.
    // SAFETY: every pointer comes from a live slice of at least the stated
    // length.
    let r = unsafe {
        voleith::ffi::voleith_verify_s1(
            key.as_ptr(),
            key.len(),
            0,
            y.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            proof.as_ptr(),
            len - 1,
        )
    };
    assert_eq!(r, 0);
    // The prover's input checks: unknown id, witness length, relation.
    #[cfg(feature = "prover")]
    {
        let x = [1u8; 32];
        let rho = [0u8; 32];
        assert!(voleith::prove(2, &pub_inputs, &x, &msg, &rho).is_err());
        assert!(voleith::prove(1, &pub_inputs, &x[..31], &msg, &rho).is_err());
        assert!(voleith::prove(1, &pub_inputs, &x, &msg, &rho).is_err());
        assert!(!circuit_is_built(STATEMENT1_ID), "prove built the circuit");
    }

    // A structurally valid proof costs a full verification.
    assert!(!voleith::verify(1, &pub_inputs, &msg, &proof));
    assert!(circuit_is_built(STATEMENT1_ID));
}
