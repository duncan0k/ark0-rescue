//! The bulk differential set (vectors/statement1-v0.2-differential.json,
//! made by python/tools/gen_differential.py): the Rust verifier must return
//! the Python verifier's verdict on every case, and the Rust prover must
//! reproduce every valid proof from its inputs.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use common::{apply_edit, base64, hex, load_json, str_of, to_hex, u64_of};
use serde_json::Value;

const FILE: &str = "statement1-v0.2-differential.json";

fn threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 8)
}

/// Run `f` on every item with a few threads; returns the failures.
fn par_check<T: Sync>(items: &[T], f: impl Fn(&T) -> Option<String> + Sync) -> Vec<String> {
    let next = AtomicUsize::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..threads() {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                if let Some(msg) = f(&items[i]) {
                    failures.lock().unwrap().push(msg);
                }
            });
        }
    });
    failures.into_inner().unwrap()
}

fn case_message(c: &Value) -> Vec<u8> {
    match c["message"].as_str() {
        Some(h) => hex(h),
        None => vec![0u8; u64_of(c, "message_zeros") as usize],
    }
}

#[test]
fn differential_set_agrees_with_python() {
    let d = load_json(FILE);
    assert_eq!(str_of(&d, "format"), "voleith-differential-1");
    let valid = d["valid"].as_array().expect("valid cases");
    let mutated = d["mutated"].as_array().expect("mutated cases");
    assert!(valid.len() >= 100, "at least 100 valid cases");
    assert!(mutated.len() >= 300, "at least 300 mutated cases");
    let proofs: Vec<Vec<u8>> = valid
        .iter()
        .map(|v| base64(str_of(v, "proof_b64")))
        .collect();

    // Valid cases: Python accepted them; Rust must too.
    let failures = par_check(valid, |v| {
        let id = str_of(v, "id");
        let idx: usize = id.trim_start_matches("valid-").parse().unwrap();
        let proof = &proofs[idx];
        if to_hex(&voleith::hash::sha256(proof)) != str_of(v, "proof_sha256") {
            return Some(format!("{id}: proof hash"));
        }
        let expected = v["expected"].as_bool().unwrap();
        let got = voleith::verify(
            u64_of(v, "statement_id") as u8,
            &hex(str_of(v, "public_inputs")),
            &hex(str_of(v, "message")),
            proof,
        );
        (got != expected || !expected).then(|| format!("{id}: rust {got}, python {expected}"))
    });
    assert!(failures.is_empty(), "valid cases: {failures:?}");

    // Mutated cases: same verdict as Python on every one.
    let rejected = AtomicUsize::new(0);
    let failures = par_check(mutated, |c| {
        let id = str_of(c, "id");
        let sid = u64_of(c, "statement_id");
        let mut proof = proofs[u64_of(c, "base") as usize].clone();
        for e in c["proof_edits"].as_array().unwrap() {
            apply_edit(&mut proof, e);
        }
        let expected = c["expected"].as_bool().unwrap();
        let got = sid <= 255
            && voleith::verify(
                sid as u8,
                &hex(str_of(c, "public_inputs")),
                &case_message(c),
                &proof,
            );
        if !got {
            rejected.fetch_add(1, Ordering::Relaxed);
        }
        (got != expected).then(|| {
            format!(
                "{id} ({}): rust {got}, python {expected}",
                str_of(c, "description")
            )
        })
    });
    assert!(failures.is_empty(), "mutated cases: {failures:?}");
    println!(
        "differential: {} valid cases accepted, {} mutated cases agree ({} rejected by both)",
        valid.len(),
        mutated.len(),
        rejected.load(Ordering::Relaxed)
    );
}

#[test]
fn prover_reproduces_differential_proofs() {
    let d = load_json(FILE);
    let valid = d["valid"].as_array().expect("valid cases");
    let failures = par_check(valid, |v| {
        let id = str_of(v, "id");
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&hex(str_of(v, "rho")));
        match voleith::prove(
            u64_of(v, "statement_id") as u8,
            &hex(str_of(v, "public_inputs")),
            &hex(str_of(v, "witness_x")),
            &hex(str_of(v, "message")),
            &rho,
        ) {
            Ok((proof, _)) if base64(str_of(v, "proof_b64")) == proof => None,
            Ok(_) => Some(format!("{id}: proof bytes differ")),
            Err(e) => Some(format!("{id}: prover refused: {e:?}")),
        }
    });
    assert!(failures.is_empty(), "{failures:?}");
    println!("prover: {} proofs reproduced byte for byte", valid.len());
}
