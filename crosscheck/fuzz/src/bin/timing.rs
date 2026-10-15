//! Median verification time of a valid proof and of the costliest invalid
//! inputs, for the timing invariant (each call at most 2x a valid verify).
//! Usage: cargo run --release --bin timing [runs]

use std::time::{Duration, Instant};
use voleith_fuzz::{known, OFF_CHALL3, OFF_D, D_BYTES, STATEMENT_ID};

fn median(runs: usize, mut f: impl FnMut() -> bool) -> (Duration, bool) {
    let mut r = false;
    let mut ts: Vec<Duration> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            r = f();
            t.elapsed()
        })
        .collect();
    ts.sort();
    (ts[runs / 2], r)
}

fn main() {
    let runs: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(31);
    let k = known();
    let v = &k.valid[0];
    let _ = voleith::verify(STATEMENT_ID, &v.public_inputs, &v.message, &v.proof);
    let (base, ok) = median(runs, || voleith::verify(STATEMENT_ID, &v.public_inputs, &v.message, &v.proof));
    println!("valid proof (KAT 0)                     {base:>10.3?}  accept={ok}");
    let mut cases: Vec<(&str, Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut p = v.proof.clone();
    p[OFF_CHALL3..].fill(0xff);
    cases.push(("chall3 = ff..ff", v.public_inputs.clone(), v.message.clone(), p.clone()));
    let mut p2 = p.clone();
    p2[OFF_D..OFF_D + D_BYTES - 1].fill(0xff);
    cases.push(("chall3 = ff..ff, d = ff..ff", v.public_inputs.clone(), v.message.clone(), p2));
    cases.push(("chall3 = ff..ff, 65535-byte msg", v.public_inputs.clone(), vec![0xa5; 65_535], p.clone()));
    let mut p3 = v.proof.clone();
    p3[OFF_CHALL3..].fill(0);
    cases.push(("chall3 = 0", v.public_inputs.clone(), v.message.clone(), p3));
    let mut pk = v.public_inputs.clone();
    pk[0] = 0;
    cases.push(("bad public inputs (step 2)", pk, v.message.clone(), v.proof.clone()));
    let mut pp = v.proof.clone();
    pp[OFF_D + D_BYTES - 1] |= 0x80;
    cases.push(("padding bit of d (step 6)", v.public_inputs.clone(), v.message.clone(), pp));
    for (name, pubi, msg, proof) in &cases {
        let (t, ok) = median(runs, || voleith::verify(STATEMENT_ID, pubi, msg, proof));
        println!("{name:<40}{t:>10.3?}  accept={ok}  ratio={:.3}", t.as_secs_f64() / base.as_secs_f64());
    }
}
