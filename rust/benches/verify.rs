//! Single-threaded timings for NOTES.md: verification of a valid proof, the
//! costliest rejections, raw SHAKE256 leaf expansion, and a libsecp256k1
//! BIP-340 Schnorr verification in the same binary.
//!
//! Run: `cargo bench --bench verify -- [verify runs] [schnorr runs]`

use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use secp256k1::{Keypair, Secp256k1};
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn utc_now() -> String {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{:02}:{:02}:{:02}Z", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

struct Stats {
    n: usize,
    median: Duration,
    p99: Duration,
    min: Duration,
    max: Duration,
    mean: Duration,
}

fn stats(mut v: Vec<Duration>) -> Stats {
    v.sort();
    let n = v.len();
    let pct = |p: f64| v[((p * n as f64).ceil() as usize).clamp(1, n) - 1];
    let total: Duration = v.iter().sum();
    Stats {
        n,
        median: pct(0.5),
        p99: pct(0.99),
        min: v[0],
        max: v[n - 1],
        mean: total / n as u32,
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn report_ms(name: &str, s: &Stats) {
    println!(
        "{name:<44} n={:<6} median {:8.3} ms  p99 {:8.3} ms  min {:8.3}  max {:8.3}  mean {:8.3}",
        s.n,
        ms(s.median),
        ms(s.p99),
        ms(s.min),
        ms(s.max),
        ms(s.mean)
    );
}

fn time_verify(runs: usize, pub_inputs: &[u8], msg: &[u8], proof: &[u8], expect: bool) -> Stats {
    let mut v = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t = Instant::now();
        let ok = voleith::verify(
            black_box(1),
            black_box(pub_inputs),
            black_box(msg),
            black_box(proof),
        );
        v.push(t.elapsed());
        assert_eq!(ok, expect);
    }
    stats(v)
}

fn cpu_info() {
    let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") else {
        println!("cpu: /proc/cpuinfo not readable");
        return;
    };
    let field = |name: &str| {
        text.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    println!("cpu: {}", field("model name"));
    let flags = field("flags");
    let have: Vec<&str> = [
        "avx2",
        "avx512f",
        "avx512vl",
        "sha_ni",
        "aes",
        "vaes",
        "pclmulqdq",
        "vpclmulqdq",
        "bmi2",
    ]
    .into_iter()
    .filter(|f| flags.split_whitespace().any(|x| x == *f))
    .collect();
    println!("cpu flags (of interest): {}", have.join(" "));
    println!(
        "logical cpus visible: {}",
        text.lines().filter(|l| l.starts_with("processor")).count()
    );
}

fn main() {
    let nums: Vec<usize> = std::env::args().filter_map(|a| a.parse().ok()).collect();
    let runs = nums.first().copied().unwrap_or(300).max(200);
    let schnorr_runs = nums.get(1).copied().unwrap_or(20_000).max(10_000);
    println!("start {}", utc_now());
    cpu_info();
    println!(
        "compiled with target features: sse4.1={} avx2={} bmi2={} pclmulqdq={} avx512f={}",
        cfg!(target_feature = "sse4.1"),
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "bmi2"),
        cfg!(target_feature = "pclmulqdq"),
        cfg!(target_feature = "avx512f")
    );

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/statement1-v0.1.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let v = &doc["vectors"][0];
    let pub_inputs = hex(v["public_inputs"].as_str().unwrap());
    let msg = hex(v["message"].as_str().unwrap());
    let proof = hex(v["proof"].as_str().unwrap());

    // One-time setup: building the statement circuit.
    let t = Instant::now();
    assert_eq!(voleith::proof_length(1), Some(87_506));
    println!(
        "circuit build (once per process): {:.3} ms",
        ms(t.elapsed())
    );
    let t = Instant::now();
    assert!(voleith::verify(1, &pub_inputs, &msg, &proof));
    println!("first verify after build: {:.3} ms", ms(t.elapsed()));
    for _ in 0..5 {
        assert!(voleith::verify(1, &pub_inputs, &msg, &proof));
    }

    // Raw XOF work of the leaf expansions: 16 x 255 outputs of 5,307 bytes,
    // with SHAKE256 (the protocol) and, for comparison only, other Keccak XOFs.
    fn expansions<H: Update + ExtendableOutput>(mk: impl Fn() -> H) -> Stats {
        let mut buf = vec![0u8; 5307];
        let mut v = Vec::new();
        for _ in 0..15 {
            let t = Instant::now();
            for j in 0..16 * 255u32 {
                let mut h = mk();
                h.update(&[23u8]);
                h.update(b"VOLEitH-rescue/v0.1/exp");
                h.update(&[0u8; 16]);
                h.update(&j.to_le_bytes()[..3]);
                h.update(&[1u8; 16]);
                h.finalize_xof().read(&mut buf);
                black_box(&buf);
            }
            v.push(t.elapsed());
        }
        stats(v)
    }
    let mb = 16.0 * 255.0 * 5307.0 / 1e6;
    for (name, s) in [
        (
            "SHAKE256 leaf expansions only (21.65 MB)",
            expansions(sha3::Shake256::default),
        ),
        (
            "  same volume, SHAKE128 (not the protocol)",
            expansions(sha3::Shake128::default),
        ),
        (
            "  same volume, TurboSHAKE256 (not the protocol)",
            expansions(|| sha3::TurboShake256::from_core(sha3::TurboShake256Core::new(0x1f))),
        ),
        (
            "  same volume, TurboSHAKE128 (not the protocol)",
            expansions(|| sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(0x1f))),
        ),
    ] {
        report_ms(name, &s);
        println!("    = {:.0} MB/s", mb / s.median.as_secs_f64());
    }

    // Valid proof.
    let valid = time_verify(runs, &pub_inputs, &msg, &proof, true);
    report_ms("verify, valid proof", &valid);

    // Rejections. Every input that passes the format checks (steps 1-6) costs
    // the full verification; these fail only at the final comparison.
    let mut worst: (&str, Stats) = ("", stats(vec![Duration::ZERO]));
    let bad_runs = (runs / 2).max(100);
    let mut cases: Vec<(&str, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut p = proof.clone();
    p[84_914 + 3] ^= 1;
    cases.push(("reject: a_tilde bit flip (final check)", p, msg.clone()));
    let mut p = proof.clone();
    p[87_490 + 5] ^= 0x10;
    cases.push(("reject: chall3 bit flip (final check)", p, msg.clone()));
    // The longest message hashes the most into mu.
    cases.push((
        "reject: 65,535-byte message (final check)",
        proof.clone(),
        vec![0xa5u8; 65_535],
    ));
    let mut m = msg.clone();
    m[0] ^= 1;
    cases.push(("reject: message bit flip (final check)", proof.clone(), m));
    // Random body with a valid header and zero padding bits.
    let mut p = vec![0u8; 87_506];
    let mut x: u64 = 0x0123_4567_89ab_cdef;
    for b in p.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    p[0] = 1;
    p[1] = 1;
    for i in 0..15 {
        p[18 + (i + 1) * 5307 - 1] &= 0x7f;
    }
    p[79_655 + 5259 - 1] &= 0x7f;
    cases.push(("reject: random body, valid format", p, msg.clone()));
    for (name, p, m) in &cases {
        let s = time_verify(bad_runs, &pub_inputs, m, p, false);
        report_ms(name, &s);
        if s.p99 > worst.1.p99 {
            worst = (name, s);
        }
    }
    // Cheap rejections, for contrast.
    for (name, p) in [
        ("reject: length 87,505", proof[..87_505].to_vec()),
        ("reject: padding bit of d", {
            let mut p = proof.clone();
            p[79_655 + 5258] |= 0x80;
            p
        }),
    ] {
        let mut v = Vec::new();
        for _ in 0..1000 {
            let t = Instant::now();
            assert!(!voleith::verify(
                1,
                black_box(&pub_inputs),
                &msg,
                black_box(&p)
            ));
            v.push(t.elapsed());
        }
        let s = stats(v);
        println!(
            "{name:<44} n={:<6} median {:8.3} us  p99 {:8.3} us",
            s.n,
            us(s.median),
            us(s.p99)
        );
    }

    // libsecp256k1 BIP-340 Schnorr verification.
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_byte_array(&secp, [0x42u8; 32]).unwrap();
    let (xonly, _) = kp.x_only_public_key();
    let smsg = [0x5au8; 32];
    let sig = secp.sign_schnorr_no_aux_rand(&smsg, &kp);
    for _ in 0..1000 {
        assert!(secp.verify_schnorr(&sig, &smsg, &xonly).is_ok());
    }
    let mut sv = Vec::with_capacity(schnorr_runs);
    for _ in 0..schnorr_runs {
        let t = Instant::now();
        let ok = secp
            .verify_schnorr(black_box(&sig), black_box(&smsg), black_box(&xonly))
            .is_ok();
        sv.push(t.elapsed());
        assert!(ok);
    }
    let sch = stats(sv);
    println!(
        "{:<44} n={:<6} median {:8.3} us  p99 {:8.3} us  min {:8.3}  max {:8.3}",
        "libsecp256k1 BIP-340 Schnorr verify",
        sch.n,
        us(sch.median),
        us(sch.p99),
        us(sch.min),
        us(sch.max)
    );

    // Ratios and the implied validation weight.
    let ratio_p99 = valid.p99.as_secs_f64() / sch.median.as_secs_f64();
    let ratio_med = valid.median.as_secs_f64() / sch.median.as_secs_f64();
    let ratio_worst = worst.1.p99.as_secs_f64() / sch.median.as_secs_f64();
    let c = 1.25 * 50.0 * ratio_p99;
    let c_worst = 1.25 * 50.0 * ratio_worst;
    let budget = 87_600.0;
    println!("ratio median(rescue)/median(schnorr): {ratio_med:.0}");
    println!("ratio p99(rescue)/median(schnorr): {ratio_p99:.0}");
    println!(
        "implied weight C = 1.25 * 50 * p99/median_schnorr = {c:.0}  (budget ~{budget:.0}: {:.2}x)",
        c / budget
    );
    println!(
        "worst rejection: {} (p99 {:.3} ms) -> C = {c_worst:.0} ({:.2}x budget)",
        worst.0,
        ms(worst.1.p99),
        c_worst / budget
    );
    println!(
        "SUMMARY {{\"verify_median_ms\":{:.3},\"verify_p99_ms\":{:.3},\"worst_reject\":\"{}\",\"worst_reject_median_ms\":{:.3},\"worst_reject_p99_ms\":{:.3},\"schnorr_median_us\":{:.3},\"ratio_p99\":{:.1},\"C\":{:.0},\"C_worst\":{:.0}}}",
        ms(valid.median),
        ms(valid.p99),
        worst.0,
        ms(worst.1.median),
        ms(worst.1.p99),
        us(sch.median),
        ratio_p99,
        c,
        c_worst
    );
    println!("end {}", utc_now());
}
