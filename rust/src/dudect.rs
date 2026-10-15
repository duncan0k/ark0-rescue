//! dudect-style statistical timing tests (Reparaz, Balasch, Verbauwhede,
//! "Dude, is my code constant time?", DATE 2017): fixed versus random
//! secret inputs, classes interleaved at random, Welch's t-test on the raw
//! timings and on timings cropped at several upper percentiles.
//!
//! A |t| below the threshold is evidence, not proof: it says that this
//! machine, this build and this number of samples showed no difference
//! between the classes. See rust/CT-AUDIT.md for the recorded results.
//!
//! The tests are `#[ignore]`d because timing is noisy on shared machines.
//! Run them on a quiet machine, single-threaded and optimised:
//!
//! ```text
//! cargo test --release --lib dudect -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `DUDECT_SAMPLES` (GF multiplication, default 200000) and
//! `DUDECT_PROVE_SAMPLES` (prove(), default 1000) set the measurement count.

use std::hint::black_box;
use std::time::Instant;

use crate::gf128::{self, FixedMul};

/// |t| above this suggests a timing difference (the usual TVLA threshold).
const T_THRESHOLD: f64 = 4.5;

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn from_time() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Rng(t ^ 0x5DEE_CE66_D1CE_4E5B)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn u128(&mut self) -> u128 {
        ((self.next() as u128) << 64) | self.next() as u128
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Welford's running mean and variance.
#[derive(Clone, Copy, Default)]
struct Moments {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }
}

/// Welch's t of class `a` against class `b`.
///
/// - Fewer than 2 samples in a class: the variance is undefined and the
///   test cannot decide, so the result is NaN. Every `|t| < threshold`
///   check is false for NaN, so an undecidable test fails rather than
///   passes.
/// - Zero variance in both classes: the classes are fully distinguishable
///   if their means differ, so the result is a signed infinity; equal means
///   give 0.
fn welch_t(a: &Moments, b: &Moments) -> f64 {
    if a.n < 2.0 || b.n < 2.0 {
        return f64::NAN;
    }
    let va = a.m2 / (a.n - 1.0);
    let vb = b.m2 / (b.n - 1.0);
    let den = (va / a.n + vb / b.n).sqrt();
    let diff = a.mean - b.mean;
    if den == 0.0 {
        if diff == 0.0 {
            0.0
        } else {
            diff.signum() * f64::INFINITY
        }
    } else {
        diff / den
    }
}

/// The result of one test: the largest |t| over the decidable crops (the
/// raw timings count as a crop), which crop gave it, the first undecidable
/// crop if any, and the class medians.
struct Report {
    max_t: f64,
    worst: String,
    undecidable: Option<String>,
    median_fixed: f64,
    median_random: f64,
    n: usize,
}

/// Welch's t over the raw timings and over timings at or below each of a
/// few upper percentiles of the pooled distribution (dudect's cropping,
/// which removes interrupts and other long-tail noise).
///
/// An undecidable crop (NaN, see [`welch_t`]) does not touch `max_t`, so a
/// leak found by another crop stays visible; it is recorded in
/// `undecidable` and makes the report fail [`Report::passes`].
fn analyse(samples: &[(bool, f64)]) -> Report {
    let mut pooled: Vec<f64> = samples.iter().map(|s| s.1).collect();
    pooled.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| pooled[((p * pooled.len() as f64) as usize).min(pooled.len() - 1)];
    let mut crops: Vec<(String, f64)> = vec![("raw".into(), f64::INFINITY)];
    for p in [0.99, 0.95, 0.90, 0.75, 0.50] {
        crops.push((format!("<= p{}", (p * 100.0) as u32), pct(p)));
    }
    let mut max_t = 0.0f64;
    let mut worst = String::new();
    let mut undecidable = None;
    for (name, cut) in &crops {
        let (mut f, mut r) = (Moments::default(), Moments::default());
        for &(fixed, x) in samples {
            if x <= *cut {
                if fixed {
                    f.push(x)
                } else {
                    r.push(x)
                }
            }
        }
        let t = welch_t(&f, &r);
        if t.is_nan() {
            undecidable.get_or_insert_with(|| name.clone());
            continue;
        }
        if t.abs() > max_t.abs() {
            max_t = t;
            worst = name.clone();
        }
    }
    let median = |want: bool| {
        let mut v: Vec<f64> = samples
            .iter()
            .filter(|s| s.0 == want)
            .map(|s| s.1)
            .collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    Report {
        max_t,
        worst,
        undecidable,
        median_fixed: median(true),
        median_random: median(false),
        n: samples.len(),
    }
}

impl Report {
    /// Whether a constant-time target passes: every crop decidable and
    /// every |t| below the threshold (an infinite t fails).
    fn passes(&self) -> bool {
        self.undecidable.is_none() && self.max_t.abs() < T_THRESHOLD
    }

    /// Whether a leak was detected: some decidable crop gave |t| above the
    /// threshold, infinities included. Undecidable crops neither add nor
    /// hide evidence.
    fn detects_leak(&self) -> bool {
        self.max_t.abs() > T_THRESHOLD
    }
}

fn print(label: &str, r: &Report) {
    println!(
        "dudect {label}: n {}, max |t| {:.2} ({}){}, median fixed {:.1} ns, random {:.1} ns",
        r.n,
        r.max_t.abs(),
        r.worst,
        match &r.undecidable {
            Some(c) => format!(", undecidable crop {c}"),
            None => String::new(),
        },
        r.median_fixed,
        r.median_random
    );
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Operations per GF measurement: enough to dwarf the timer's resolution.
const BATCH: usize = 64;

/// Measurements prepared at a time (64 KiB of classes and 2 MiB of
/// operands per chunk).
const CHUNK: usize = 1024;

/// Times `f` on batches of BATCH operand pairs, all equal to `fixed`
/// (class fixed) or all fresh from `random` (class random), in random class
/// order. As in dudect, the classes and operands of a whole chunk are
/// generated before any of its measurements, so both classes run exactly
/// the same code between the timer reads and only the operand values differ.
fn measure_gf(
    rng: &mut Rng,
    n: usize,
    fixed: (u128, u128),
    random: impl Fn(&mut Rng) -> (u128, u128),
    f: impl Fn(u128, u128) -> u128,
) -> Report {
    let warmup = n / 10;
    let mut classes = vec![false; CHUNK];
    let mut ops = vec![(0u128, 0u128); CHUNK * BATCH];
    let mut out = Vec::with_capacity(n);
    let mut done = 0;
    while done < n + warmup {
        for (c, batch) in classes.iter_mut().zip(ops.chunks_exact_mut(BATCH)) {
            *c = rng.next() & 1 == 0;
            for op in batch.iter_mut() {
                *op = if *c { fixed } else { random(rng) };
            }
        }
        for (&is_fixed, batch) in classes.iter().zip(ops.chunks_exact(BATCH)) {
            let t = Instant::now();
            let mut acc = 0u128;
            for &(a, b) in batch {
                acc ^= f(black_box(a), black_box(b));
            }
            black_box(acc);
            let dt = t.elapsed().as_nanos() as f64;
            // The first n/10 measurements warm up caches and frequency
            // scaling.
            if done >= warmup && out.len() < n {
                out.push((is_fixed, dt));
            }
            done += 1;
        }
    }
    analyse(&out)
}

/// A deliberately leaky multiplication: it skips the work when the low byte
/// of `a` is zero. Fixed-class operands get a zero low byte, so the harness
/// must flag it.
fn leaky_mul(a: u128, b: u128) -> u128 {
    if a & 0xff == 0 {
        return 0;
    }
    gf128::mul(a, b)
}

#[test]
#[ignore = "timing test: run explicitly on a quiet machine"]
fn dudect_gf128_mul() {
    let n = env_usize("DUDECT_SAMPLES", 200_000);
    let mut rng = Rng::from_time();
    println!("pclmulqdq in use: {}", gf128::has_clmul());

    let random = |r: &mut Rng| (r.u128(), r.u128());

    // Positive control: the harness must detect a known leak. Fixed-class
    // operands have a zero low byte, random ones never do.
    let control_fixed = (rng.u128() & !0xff, rng.u128());
    let control = measure_gf(
        &mut rng,
        n.min(20_000),
        control_fixed,
        |r| (r.u128() | 1, r.u128()),
        leaky_mul,
    );
    print("control (leaky by construction)", &control);
    assert!(
        control.detects_leak(),
        "the harness failed to detect a known leak"
    );

    let fixed = random(&mut rng);
    let ct = measure_gf(&mut rng, n, fixed, random, gf128::mul);
    print("gf128::mul", &ct);
    let portable = measure_gf(&mut rng, n, fixed, random, gf128::mul_portable);
    print("gf128::mul_portable", &portable);

    // For information only: the verifier's table-driven multiplication,
    // which the prover no longer uses, is expected to be variable time.
    let tables = FixedMul::new_tables(rng.u128());
    let fixed_table = measure_gf(&mut rng, n, fixed, random, |_, x| tables.mul(x));
    print("FixedMul tables (verifier only, not CT)", &fixed_table);

    assert!(ct.passes(), "gf128::mul: |t| too large");
    assert!(portable.passes(), "gf128::mul_portable: |t| too large");
}

#[test]
#[ignore = "timing test: run explicitly on a quiet machine"]
fn dudect_prove() {
    let n = env_usize("DUDECT_PROVE_SAMPLES", 1000);
    let mut rng = Rng::from_time();
    let key = b"ark0-wallet v1 schnorr";
    let suffix = 0u8;
    let msg = [0x42u8; 96];
    let instance = |x: [u8; 32]| {
        let mut xs = x.to_vec();
        xs.push(suffix);
        let y = crate::hash::hmac_sha256(key, &xs);
        crate::s1_encode_public(key, suffix, &y).unwrap()
    };
    let mut fixed_x = [0u8; 32];
    let mut fixed_rho = [0u8; 32];
    rng.fill(&mut fixed_x);
    rng.fill(&mut fixed_rho);
    let fixed_pub = instance(fixed_x);
    // Builds the circuit, warms up.
    crate::prove(1, &fixed_pub, &fixed_x, &msg, &fixed_rho).unwrap();

    // Every input is generated before the first measurement.
    let warmup = n / 10;
    let inputs: Vec<_> = (0..n + warmup)
        .map(|_| {
            if rng.next() & 1 == 0 {
                (true, fixed_pub.clone(), fixed_x, fixed_rho)
            } else {
                let mut x = [0u8; 32];
                let mut rho = [0u8; 32];
                rng.fill(&mut x);
                rng.fill(&mut rho);
                (false, instance(x), x, rho)
            }
        })
        .collect();
    let mut out = Vec::with_capacity(n);
    for (i, (is_fixed, pub_inputs, x, rho)) in inputs.iter().enumerate() {
        let t = Instant::now();
        let p = crate::prove(
            1,
            black_box(pub_inputs),
            black_box(x),
            black_box(&msg),
            black_box(rho),
        );
        let dt = t.elapsed().as_nanos() as f64;
        black_box(p.unwrap());
        if i >= warmup {
            out.push((*is_fixed, dt));
        }
    }
    let r = analyse(&out);
    print("prove()", &r);
    assert!(r.passes(), "prove(): |t| too large");
}

/// Welch's t must not pass a fully distinguishable sample: 100 samples of
/// 100 ns against 100 of 200 ns have zero variance in each class, and an
/// earlier version returned t = 0 for them (raw and every crop).
#[test]
fn welch_t_zero_variance_distinct_means() {
    let samples: Vec<(bool, f64)> = (0..200)
        .map(|i| (i % 2 == 0, if i % 2 == 0 { 100.0 } else { 200.0 }))
        .collect();
    let r = analyse(&samples);
    assert_eq!(r.max_t, f64::NEG_INFINITY);
    assert!(!r.passes());

    let (mut a, mut b) = (Moments::default(), Moments::default());
    for _ in 0..100 {
        a.push(100.0);
        b.push(200.0);
    }
    assert_eq!(welch_t(&a, &b), f64::NEG_INFINITY);
    assert_eq!(welch_t(&b, &a), f64::INFINITY);
    assert_eq!(welch_t(&a, &a), 0.0);
}

/// Fewer than 2 samples in a class is undecidable and must fail the test.
#[test]
fn welch_t_too_few_samples_fails() {
    let (mut a, mut b) = (Moments::default(), Moments::default());
    a.push(100.0);
    for x in [100.0, 101.0, 99.0] {
        b.push(x);
    }
    assert!(welch_t(&a, &b).is_nan());
    assert!(welch_t(&Moments::default(), &b).is_nan());
    let samples = [(true, 100.0), (false, 100.0), (false, 101.0)];
    let r = analyse(&samples);
    assert!(r.undecidable.is_some());
    assert!(!r.passes());
}

/// An undecidable crop must not hide a leak that another crop found
/// (review finding R1): the leak is still detected and the report still
/// fails as a constant-time target. Unequal class sizes on purpose.
#[test]
fn undecidable_crop_keeps_detected_leak() {
    // 101 fixed samples of 100 ns, 99 random of 200 ns: raw t = -inf, the
    // p50 crop keeps only the fixed class.
    let mut a: Vec<(bool, f64)> = vec![(true, 100.0); 101];
    a.extend(vec![(false, 200.0); 99]);
    // 100 fixed of 100 ns, 100 random at 200..299 ns: the p50 crop keeps a
    // single random sample.
    let mut b: Vec<(bool, f64)> = vec![(true, 100.0); 100];
    b.extend((0..100).map(|i| (false, 200.0 + i as f64)));
    for (samples, raw_infinite) in [(a, true), (b, false)] {
        let r = analyse(&samples);
        assert!(r.undecidable.is_some(), "a crop must be undecidable");
        assert!(r.detects_leak(), "max |t| {}", r.max_t);
        assert!(r.max_t < 0.0);
        assert_eq!(r.max_t.is_infinite(), raw_infinite);
        assert!(!r.passes());
    }
}
