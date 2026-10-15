//! Single-threaded median timings of `prove` and `verify` under the
//! parameter set of this version, for rust/CT-AUDIT.md (before and after the
//! constant-time prover).
//!
//! Run: `cargo bench --bench prove_verify -- [--runs 31]`
//!
//! The target has `harness = false`, so `cargo test --all-targets` runs it
//! too, without the `--bench` flag that `cargo bench` passes. Then it only
//! proves and verifies once, checks the result and exits.

use std::hint::black_box;
use std::time::{Duration, Instant};

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn summary(label: &str, mut v: Vec<Duration>) {
    v.sort();
    let n = v.len();
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!(
        "{label}: n {n}, median {:.3} ms, min {:.3} ms, max {:.3} ms",
        ms(v[n / 2]),
        ms(v[0]),
        ms(v[n - 1])
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bench = args.iter().any(|a| a == "--bench");
    let runs: usize = arg_value(&args, "--runs")
        .map(|r| r.parse().expect("runs"))
        .unwrap_or(31);

    let key = b"ark0-wallet v1 schnorr";
    let suffix = 0u8;
    let x = voleith::hash::sha256(b"voleith bench seed");
    let mut xs = x.to_vec();
    xs.push(suffix);
    let y = voleith::hash::hmac_sha256(key, &xs);
    let pub_inputs = voleith::s1_encode_public(key, suffix, &y).unwrap();
    let msg: Vec<u8> = (0..96u32).map(|i| (i * 7 + 3) as u8).collect();
    let rho = [7u8; 32];

    // Builds the circuit (once per process) and warms up.
    let proof = voleith::prove(1, &pub_inputs, &x, &msg, &rho).unwrap();
    assert!(voleith::verify(1, &pub_inputs, &msg, &proof));
    let digest: String = voleith::hash::sha256(&proof)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("proof {} bytes, sha256 {digest}", proof.len());
    assert_eq!(Some(proof.len()), voleith::proof_length(1));
    if !bench {
        // Smoke test under `cargo test`: one prove and one verify, checked
        // above, plus a rejected tampered proof. No measurement.
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 1;
        assert!(!voleith::verify(1, &pub_inputs, &msg, &bad));
        println!("not run with --bench: smoke test only, no measurement");
        return;
    }

    let mut tp = Vec::with_capacity(runs);
    let mut tv = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t = Instant::now();
        let p = voleith::prove(
            1,
            black_box(&pub_inputs),
            black_box(&x),
            black_box(&msg),
            black_box(&rho),
        )
        .unwrap();
        tp.push(t.elapsed());
        assert_eq!(p, proof);
        let t = Instant::now();
        let ok = voleith::verify(1, black_box(&pub_inputs), black_box(&msg), black_box(&p));
        tv.push(t.elapsed());
        assert!(ok);
    }
    summary("prove", tp);
    summary("verify", tv);
}
