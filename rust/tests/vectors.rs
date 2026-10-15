//! The fixed-rng known-answer vectors in vectors/statement1-v0.2.json.

mod common;

use common::{apply_edit, hex, load_json, str_of, to_hex, u64_of};
use voleith::circuit_info::{compression_circuit_digest, statement_circuit_info};
use voleith::params::SPLIT;
use voleith::STATEMENT1_ID;

fn doc() -> serde_json::Value {
    load_json("statement1-v0.2.json")
}

/// Offsets of statement 0x01 proofs under SPLIT (SPEC.md §10).
struct Offsets {
    u_tilde: usize,
    a_tilde: usize,
    chall3: usize,
    total: usize,
}

fn offsets() -> Offsets {
    let tau = SPLIT.tau();
    let u_tilde = 18 + (tau - 1) * 5_307;
    let a_tilde = u_tilde + 32 + 5_259;
    let chall3 = a_tilde + 16 + 2_048 + 32 * tau;
    Offsets {
        u_tilde,
        a_tilde,
        chall3,
        total: chall3 + 16,
    }
}

#[test]
fn circuit_matches_vector_header() {
    let d = doc();
    let c = &d["circuit"];
    let info = statement_circuit_info(STATEMENT1_ID).expect("registered");
    assert_eq!(to_hex(&info.digest), str_of(c, "sha256_of_serialization"));
    assert_eq!(
        to_hex(&info.digest),
        "5aadd73b39947a32f0eb217cf750ee280c3dadcd60b9ccccb09509892cf1435d"
    );
    assert_eq!(info.n_public as u64, u64_of(c, "n_public"));
    assert_eq!(info.n_secret_inputs as u64, u64_of(c, "n_secret_inputs"));
    assert_eq!(info.n_witness as u64, u64_of(c, "n_witness"));
    assert_eq!(info.n_constraints as u64, u64_of(c, "n_constraints"));
    assert_eq!(
        info.n_and_secret_secret as u64,
        u64_of(c, "n_and_secret_secret")
    );
    assert_eq!(info.n_assert as u64, u64_of(c, "n_assert"));
    let g = &c["gate_counts"];
    assert_eq!(info.gate_counts.xor as u64, u64_of(g, "XOR"));
    assert_eq!(info.gate_counts.and as u64, u64_of(g, "AND"));
    assert_eq!(info.gate_counts.not as u64, u64_of(g, "NOT"));
    assert_eq!(info.gate_counts.assert as u64, u64_of(g, "ASSERT"));
    assert_eq!(
        info.gate_counts.and_secret_secret as u64,
        u64_of(g, "AND_secret_secret")
    );
    assert_eq!(info.proof_len as u64, u64_of(&d, "proof_len"));
    assert_eq!(info.proof_len, 2_082 + 5_339 * SPLIT.tau());
    assert_eq!(info.proof_len, offsets().total);
    assert_eq!(voleith::proof_length(STATEMENT1_ID), Some(info.proof_len));
    assert_eq!(
        u64_of(&d, "protocol_version_byte"),
        u64::from(voleith::params::VERSION)
    );
    let p = &d["params"];
    let (tau0, k0, tau1, k1) = SPLIT.shape();
    assert_eq!(u64_of(p, "tau") as usize, SPLIT.tau());
    assert_eq!(
        (
            u64_of(p, "tau0") as usize,
            u64_of(p, "k0") as usize,
            u64_of(p, "tau1") as usize,
            u64_of(p, "k1") as usize
        ),
        (tau0, k0, tau1, k1)
    );
    assert_eq!(voleith::proof_length(2), None);
}

#[test]
fn compression_circuit_digest_matches_spec() {
    assert_eq!(
        to_hex(&compression_circuit_digest()),
        "c0a978cb3bf40e83098fbf7b74226c557842bc09892598b66bdf3c7225c29114"
    );
}

#[test]
fn valid_vectors_verify_with_matching_intermediates() {
    let d = doc();
    let vectors = d["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        let desc = str_of(v, "description");
        let sid = u64_of(v, "statement_id") as u8;
        let pub_inputs = hex(str_of(v, "public_inputs"));
        let msg = hex(str_of(v, "message"));
        let proof = hex(str_of(v, "proof"));
        assert_eq!(proof.len() as u64, u64_of(v, "proof_len"));
        assert_eq!(
            to_hex(&voleith::hash::sha256(&proof)),
            str_of(v, "proof_sha256")
        );
        let y = hex(str_of(v, "y"));
        let mut y32 = [0u8; 32];
        y32.copy_from_slice(&y);
        let key = str_of(v, "K_ascii").as_bytes();
        let suffix = u64_of(v, "suffix") as u8;
        assert_eq!(
            voleith::s1_encode_public(key, suffix, &y32).unwrap(),
            pub_inputs,
            "{desc}"
        );
        let x = hex(str_of(v, "witness_x"));
        let mut xs = x.clone();
        xs.push(suffix);
        assert_eq!(voleith::hash::hmac_sha256(key, &xs).to_vec(), y, "{desc}");

        assert!(voleith::verify(sid, &pub_inputs, &msg, &proof), "{desc}");
        let (ok, trace) = voleith::verify_traced(sid, &pub_inputs, &msg, &proof);
        assert!(ok);
        let t = trace.expect("trace");
        let im = &v["intermediates"];
        assert_eq!(to_hex(&t.mu), str_of(im, "mu"), "{desc} mu");
        assert_eq!(to_hex(&t.iv), str_of(im, "iv"), "{desc} iv");
        assert_eq!(
            to_hex(&t.tree_hashes.concat()),
            str_of(im, "tree_hashes"),
            "{desc} tree hashes"
        );
        assert_eq!(to_hex(&t.hcom), str_of(im, "hcom"), "{desc} hcom");
        assert_eq!(to_hex(&t.chall1), str_of(im, "chall1"), "{desc} chall1");
        assert_eq!(to_hex(&t.h_v), str_of(im, "h_v"), "{desc} h_v");
        assert_eq!(to_hex(&t.chall2), str_of(im, "chall2"), "{desc} chall2");
        assert_eq!(to_hex(&t.b_tilde), str_of(im, "b_tilde"), "{desc} b_tilde");
        assert_eq!(to_hex(&t.chall3), str_of(im, "chall3"), "{desc} chall3");
        // Fields read from the proof.
        let lay_iv_pre = &proof[2..18];
        assert_eq!(to_hex(lay_iv_pre), str_of(im, "iv_pre"));
        let o = offsets();
        assert_eq!(
            to_hex(&proof[o.u_tilde..o.u_tilde + 32]),
            str_of(im, "u_tilde")
        );
        assert_eq!(
            to_hex(&proof[o.a_tilde..o.a_tilde + 16]),
            str_of(im, "a_tilde")
        );
        assert_eq!(to_hex(&proof[o.chall3..]), str_of(im, "chall3"));
    }
}

#[test]
fn prover_reproduces_vectors_byte_for_byte() {
    let d = doc();
    for v in d["vectors"].as_array().unwrap() {
        let desc = str_of(v, "description");
        let sid = u64_of(v, "statement_id") as u8;
        let pub_inputs = hex(str_of(v, "public_inputs"));
        let msg = hex(str_of(v, "message"));
        let x = hex(str_of(v, "witness_x"));
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&hex(str_of(v, "rho")));
        let (proof, t) = voleith::prove_traced(sid, &pub_inputs, &x, &msg, &rho).expect("prove");
        assert_eq!(
            voleith::prove(sid, &pub_inputs, &x, &msg, &rho).expect("prove"),
            proof,
            "{desc} prove and prove_traced"
        );
        let im = &v["intermediates"];
        assert_eq!(to_hex(&t.mu), str_of(im, "mu"), "{desc} mu");
        assert_eq!(to_hex(&t.r), str_of(im, "r"), "{desc} r");
        assert_eq!(to_hex(&t.iv_pre), str_of(im, "iv_pre"), "{desc} iv_pre");
        assert_eq!(to_hex(&t.iv), str_of(im, "iv"), "{desc} iv");
        assert_eq!(to_hex(&t.roots), str_of(im, "roots"), "{desc} roots");
        assert_eq!(
            to_hex(&t.tree_hashes.concat()),
            str_of(im, "tree_hashes"),
            "{desc} tree hashes"
        );
        assert_eq!(to_hex(&t.hcom), str_of(im, "hcom"), "{desc} hcom");
        assert_eq!(to_hex(&t.chall1), str_of(im, "chall1"), "{desc} chall1");
        assert_eq!(to_hex(&t.u_tilde), str_of(im, "u_tilde"), "{desc} u_tilde");
        assert_eq!(to_hex(&t.h_v), str_of(im, "h_v"), "{desc} h_v");
        assert_eq!(to_hex(&t.chall2), str_of(im, "chall2"), "{desc} chall2");
        assert_eq!(to_hex(&t.a_tilde), str_of(im, "a_tilde"), "{desc} a_tilde");
        assert_eq!(to_hex(&t.b_tilde), str_of(im, "b_tilde"), "{desc} b_tilde");
        assert_eq!(to_hex(&t.chall3), str_of(im, "chall3"), "{desc} chall3");
        assert_eq!(to_hex(&proof), str_of(v, "proof"), "{desc} proof bytes");
    }
}

#[test]
fn prover_refuses_bad_inputs() {
    let d = doc();
    let v = &d["vectors"][0];
    let pub_inputs = hex(str_of(v, "public_inputs"));
    let msg = hex(str_of(v, "message"));
    let x = hex(str_of(v, "witness_x"));
    let rho = [0u8; 32];
    use voleith::ProveError::*;
    assert_eq!(
        voleith::prove(2, &pub_inputs, &x, &msg, &rho).unwrap_err(),
        UnknownStatement
    );
    assert_eq!(
        voleith::prove(1, &pub_inputs[1..], &x, &msg, &rho).unwrap_err(),
        MalformedPublicInputs
    );
    assert_eq!(
        voleith::prove(1, &pub_inputs, &x, &vec![0u8; 65_536], &rho).unwrap_err(),
        MessageTooLong
    );
    assert_eq!(
        voleith::prove(1, &pub_inputs, &x[..31], &msg, &rho).unwrap_err(),
        BadWitnessLength
    );
    let mut wrong = x.clone();
    wrong[0] ^= 1;
    assert_eq!(
        voleith::prove(1, &pub_inputs, &wrong, &msg, &rho).unwrap_err(),
        RelationFails
    );
    // A fresh rho gives a different proof that still verifies.
    let p1 = voleith::prove(1, &pub_inputs, &x, &msg, &[7u8; 32]).unwrap();
    assert_ne!(to_hex(&p1), str_of(v, "proof"));
    assert!(voleith::verify(1, &pub_inputs, &msg, &p1));
}

#[test]
fn negative_vectors_reject() {
    let d = doc();
    let negs = d["negative_vectors"].as_array().unwrap();
    assert_eq!(negs.len(), SPLIT.tau() + 28);
    for nv in negs {
        let desc = str_of(nv, "description");
        let base = &d["vectors"][u64_of(nv, "base_vector") as usize];
        let mut proof = hex(str_of(base, "proof"));
        apply_edit(&mut proof, &nv["proof_edit"]);
        let sid = u64_of(nv, "statement_id");
        assert!(sid <= 255);
        let pub_inputs = hex(str_of(nv, "public_inputs"));
        let msg = hex(str_of(nv, "message"));
        assert_eq!(nv["expected"].as_bool(), Some(false));
        assert!(
            !voleith::verify(sid as u8, &pub_inputs, &msg, &proof),
            "{desc}"
        );
    }
}

/// The C ABI agrees with the Rust API on the vectors and on bad pointers.
#[test]
fn ffi_verify_s1() {
    let d = doc();
    let call = |k: &[u8], suffix: u8, y: &[u8], msg: &[u8], proof: &[u8]| -> i32 {
        // SAFETY: every pointer comes from a live slice of the stated length.
        unsafe {
            voleith::ffi::voleith_verify_s1(
                k.as_ptr(),
                k.len(),
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                proof.len(),
            )
        }
    };
    for v in d["vectors"].as_array().unwrap() {
        let key = str_of(v, "K_ascii").as_bytes();
        let suffix = u64_of(v, "suffix") as u8;
        let y = hex(str_of(v, "y"));
        let msg = hex(str_of(v, "message"));
        let proof = hex(str_of(v, "proof"));
        assert_eq!(call(key, suffix, &y, &msg, &proof), 1);
        assert_eq!(call(key, suffix ^ 1, &y, &msg, &proof), 0);
        let mut bad = proof.clone();
        bad[offsets().chall3] ^= 1;
        assert_eq!(call(key, suffix, &y, &msg, &bad), 0);
        assert_eq!(call(key, suffix, &y, &msg, &proof[..proof.len() - 1]), 0);
        // Empty message: a null pointer with length 0 is allowed.
        if msg.is_empty() {
            // SAFETY: null only with length 0, other pointers from live slices.
            let r = unsafe {
                voleith::ffi::voleith_verify_s1(
                    key.as_ptr(),
                    key.len(),
                    suffix,
                    y.as_ptr(),
                    std::ptr::null(),
                    0,
                    proof.as_ptr(),
                    proof.len(),
                )
            };
            assert_eq!(r, 1);
        }
    }
    let v = &d["vectors"][0];
    let key = str_of(v, "K_ascii").as_bytes();
    let y = hex(str_of(v, "y"));
    let msg = hex(str_of(v, "message"));
    let proof = hex(str_of(v, "proof"));
    let suffix = u64_of(v, "suffix") as u8;
    // SAFETY: the null pointers are rejected before any read; the lengths of
    // the other pointers are those of live slices.
    unsafe {
        use voleith::ffi::voleith_verify_s1 as f;
        assert_eq!(
            f(
                std::ptr::null(),
                key.len(),
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                key.len(),
                suffix,
                std::ptr::null(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                key.len(),
                suffix,
                y.as_ptr(),
                std::ptr::null(),
                msg.len(),
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                key.len(),
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                0,
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                65,
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        // k_len 300 must not wrap to a valid length byte (300 mod 256 = 44).
        assert_eq!(
            f(
                key.as_ptr(),
                300,
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                key.len(),
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                65_536,
                proof.as_ptr(),
                proof.len()
            ),
            0
        );
        assert_eq!(
            f(
                key.as_ptr(),
                key.len(),
                suffix,
                y.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                proof.as_ptr(),
                usize::MAX
            ),
            0
        );
    }
}
