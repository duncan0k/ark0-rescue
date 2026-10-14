//! Single-threaded timings for NOTES.md: verification under several tree
//! splits, interleaved with a libsecp256k1 BIP-340 Schnorr baseline in the
//! same binary, and the validation-weight rule of the v0.2 decision.
//!
//! Run: `cargo bench --features bench-splits --bench verify --
//! [--taus 22,24] [--runs 1000] [--schnorr 20000]`

use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use secp256k1::{Keypair, Secp256k1};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use voleith::params::TreeSplit;

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
}

fn stats(mut v: Vec<Duration>) -> Stats {
    v.sort();
    let n = v.len();
    let pct = |p: f64| v[((p * n as f64).ceil() as usize).clamp(1, n) - 1];
    Stats {
        n,
        median: pct(0.5),
        p99: pct(0.99),
        min: v[0],
        max: v[n - 1],
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
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
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let taus: Vec<usize> = arg_value(&args, "--taus")
        .unwrap_or("22,24")
        .split(',')
        .map(|t| t.parse().expect("tau"))
        .collect();
    let runs: usize = arg_value(&args, "--runs")
        .map(|v| v.parse().expect("runs"))
        .unwrap_or(1000)
        .max(200);
    let schnorr_runs: usize = arg_value(&args, "--schnorr")
        .map(|v| v.parse().expect("schnorr runs"))
        .unwrap_or(20_000)
        .max(10_000);
    let splits: Vec<TreeSplit> = taus
        .iter()
        .map(|&t| TreeSplit::for_tau(t).expect("supported tau"))
        .collect();
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

    // One statement 0x01 instance; one proof per split from the crate's prover.
    let key = b"ark0-wallet v1 schnorr";
    let suffix = 0u8;
    let x = voleith::hash::sha256(b"voleith bench seed");
    let mut xs = x.to_vec();
    xs.push(suffix);
    let y = voleith::hash::hmac_sha256(key, &xs);
    let pub_inputs = voleith::s1_encode_public(key, suffix, &y).unwrap();
    let mut msg = Vec::new();
    for part in [
        &b"bench sighash"[..],
        b"bench network id",
        b"bench public key",
    ] {
        msg.extend_from_slice(&voleith::hash::sha256(part));
    }
    let rho = [7u8; 32];
    let t = Instant::now();
    let _ = voleith::bench::proof_length(splits[0], 1);
    println!(
        "circuit build (once per process): {:.3} ms",
        ms(t.elapsed())
    );
    let mut proofs = Vec::new();
    for &s in &splits {
        let t = Instant::now();
        let p = voleith::bench::prove(s, 1, &pub_inputs, &x, &msg, &rho).unwrap();
        let dt = t.elapsed();
        assert_eq!(Some(p.len()), voleith::bench::proof_length(s, 1));
        assert!(voleith::bench::verify(s, 1, &pub_inputs, &msg, &p));
        let digest: String = voleith::hash::sha256(&p)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!(
            "tau {:2} {:?}: proof {} bytes, sha256 {}, prove {:.1} ms",
            s.tau(),
            s.shape(),
            p.len(),
            digest,
            ms(dt)
        );
        for _ in 0..5 {
            assert!(voleith::bench::verify(s, 1, &pub_inputs, &msg, &p));
        }
        proofs.push(p);
    }

    // Raw SHAKE256 speed, for context: 4,080 outputs of 5,307 bytes.
    let mut buf = vec![0u8; 5307];
    let mut v = Vec::new();
    for _ in 0..7 {
        let t = Instant::now();
        for j in 0..4080u32 {
            let mut h = sha3::Shake256::default();
            h.update(b"\x17VOLEitH-rescue/v0.2/exp");
            h.update(&j.to_le_bytes());
            h.finalize_xof().read(&mut buf);
            black_box(&buf);
        }
        v.push(t.elapsed());
    }
    let s = stats(v);
    println!(
        "SHAKE256: {:.0} MB/s",
        4080.0 * 5307.0 / s.median.as_secs_f64() / 1e6
    );

    // Valid proofs, interleaved across splits, in four segments with a
    // quarter of the Schnorr runs after each.
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_byte_array(&secp, [0x42u8; 32]).unwrap();
    let (xonly, _) = kp.x_only_public_key();
    let smsg = [0x5au8; 32];
    let sig = secp.sign_schnorr_no_aux_rand(&smsg, &kp);
    for _ in 0..1000 {
        assert!(secp.verify_schnorr(&sig, &smsg, &xonly).is_ok());
    }
    let mut times: Vec<Vec<Duration>> = vec![Vec::with_capacity(runs); splits.len()];
    let mut sch = Vec::with_capacity(schnorr_runs);
    for seg in 0..4 {
        for r in seg * runs / 4..(seg + 1) * runs / 4 {
            for k in 0..splits.len() {
                let i = (r + k) % splits.len();
                let t = Instant::now();
                let ok = voleith::bench::verify(
                    splits[i],
                    black_box(1),
                    black_box(&pub_inputs),
                    black_box(&msg),
                    black_box(&proofs[i]),
                );
                times[i].push(t.elapsed());
                assert!(ok);
            }
        }
        for _ in seg * schnorr_runs / 4..(seg + 1) * schnorr_runs / 4 {
            let t = Instant::now();
            let ok = secp
                .verify_schnorr(black_box(&sig), black_box(&smsg), black_box(&xonly))
                .is_ok();
            sch.push(t.elapsed());
            assert!(ok);
        }
    }
    let sch = stats(sch);
    println!(
        "libsecp256k1 BIP-340 Schnorr verify: n={} median {:.3} us  p99 {:.3} us  min {:.3}",
        sch.n,
        us(sch.median),
        us(sch.p99),
        us(sch.min)
    );

    // Rejections that fail only at the final comparison (full work).
    for (i, s) in splits.iter().enumerate() {
        let p = &proofs[i];
        let lay_len = p.len();
        let off_chall3 = lay_len - 16;
        let off_a_tilde = 2 + 16 + (s.tau() - 1) * 5307 + 32 + 5259;
        let mut flipped_a = p.clone();
        flipped_a[off_a_tilde + 3] ^= 1;
        let mut flipped_c = p.clone();
        flipped_c[off_chall3 + 5] ^= 0x10;
        let mut worst = Duration::ZERO;
        let mut med = Duration::ZERO;
        for bad in [&flipped_a, &flipped_c] {
            let mut v = Vec::new();
            for _ in 0..100 {
                let t = Instant::now();
                let ok = voleith::bench::verify(*s, 1, &pub_inputs, &msg, black_box(bad));
                v.push(t.elapsed());
                assert!(!ok);
            }
            let st = stats(v);
            worst = worst.max(st.p99);
            med = med.max(st.median);
        }
        println!(
            "tau {:2}: rejection at the final check: median {:.3} ms, p99 {:.3} ms",
            s.tau(),
            ms(med),
            ms(worst)
        );
    }

    // The rule: C = 1.25 * 50 * p99 / median(Schnorr) <= budget / 1.5,
    // budget = proof bytes + 50.
    println!("tau | shape | proof bytes | verify median | verify p99 | Schnorr median | C | budget | margin | C <= budget/1.5");
    for (i, s) in splits.iter().enumerate() {
        let st = stats(times[i].clone());
        let c = 1.25 * 50.0 * st.p99.as_secs_f64() / sch.median.as_secs_f64();
        let budget = (proofs[i].len() + 50) as f64;
        println!(
            "{} | {:?} | {} | {:.3} ms | {:.3} ms | {:.3} us | {:.0} | {:.0} | {:.2} | {}",
            s.tau(),
            s.shape(),
            proofs[i].len(),
            ms(st.median),
            ms(st.p99),
            us(sch.median),
            c,
            budget,
            budget / c,
            c <= budget / 1.5
        );
        println!(
            "SUMMARY {{\"tau\":{},\"n\":{},\"proof_bytes\":{},\"verify_median_ms\":{:.3},\"verify_p99_ms\":{:.3},\"verify_min_ms\":{:.3},\"verify_max_ms\":{:.3},\"schnorr_median_us\":{:.3},\"C\":{:.0},\"budget\":{:.0},\"margin\":{:.3},\"qualifies\":{}}}",
            s.tau(),
            st.n,
            proofs[i].len(),
            ms(st.median),
            ms(st.p99),
            ms(st.min),
            ms(st.max),
            us(sch.median),
            c,
            budget,
            budget / c,
            c <= budget / 1.5
        );
    }
    println!("end {}", utc_now());
}
