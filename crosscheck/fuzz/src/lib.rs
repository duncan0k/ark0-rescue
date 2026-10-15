//! Shared helpers of the fuzz targets: the known-valid proofs from vectors/,
//! the SPEC.md §10 section table and a timing oracle.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const STATEMENT_ID: u8 = 1;
pub const PROOF_LEN: usize = 130_218;

/// One valid (statement, message, proof) triple.
#[derive(Clone)]
pub struct Valid {
    pub public_inputs: Vec<u8>,
    pub message: Vec<u8>,
    pub proof: Vec<u8>,
    /// K, suffix and y, decoded from the public inputs.
    pub key: Vec<u8>,
    pub suffix: u8,
    pub y: [u8; 32],
}

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

pub fn b64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64"),
        }
    };
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (k, &c) in chunk.iter().enumerate() {
            acc |= val(c) << (18 - 6 * k);
        }
        let n = chunk.len() - 1;
        for k in 0..n {
            out.push((acc >> (16 - 8 * k)) as u8);
        }
    }
    out
}

fn vectors_dir() -> PathBuf {
    if let Ok(d) = std::env::var("VOLEITH_VECTORS") {
        return PathBuf::from(d);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn field<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("missing field {k}"))
}

fn make(public_inputs: Vec<u8>, message: Vec<u8>, proof: Vec<u8>) -> Valid {
    let kl = public_inputs[0] as usize;
    let key = public_inputs[1..1 + kl].to_vec();
    let suffix = public_inputs[1 + kl];
    let mut y = [0u8; 32];
    y.copy_from_slice(&public_inputs[2 + kl..]);
    Valid { public_inputs, message, proof, key, suffix, y }
}

fn load() -> Vec<Valid> {
    let dir = vectors_dir();
    let mut out = Vec::new();
    let kat: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dir.join("statement1-v0.2.json")).expect("read KAT vectors"),
    )
    .expect("parse KAT vectors");
    for v in kat["vectors"].as_array().unwrap() {
        out.push(make(
            hex(field(v, "public_inputs")),
            hex(field(v, "message")),
            hex(field(v, "proof")),
        ));
    }
    // The differential set is optional (19 MB); VOLEITH_KAT_ONLY skips it.
    if std::env::var_os("VOLEITH_KAT_ONLY").is_none() {
        if let Ok(raw) = std::fs::read(dir.join("statement1-v0.2-differential.json")) {
            let diff: serde_json::Value = serde_json::from_slice(&raw).expect("parse differential");
            for v in diff["valid"].as_array().unwrap() {
                out.push(make(
                    hex(field(v, "public_inputs")),
                    hex(field(v, "message")),
                    b64(field(v, "proof_b64")),
                ));
            }
        }
    }
    for v in &out {
        assert_eq!(v.proof.len(), PROOF_LEN);
    }
    out
}

pub struct Known {
    pub valid: Vec<Valid>,
    set: HashSet<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl Known {
    /// True iff (pub, msg, proof) is one of the known-valid triples.
    pub fn contains(&self, public_inputs: &[u8], message: &[u8], proof: &[u8]) -> bool {
        // Cheap filter before building the key.
        if proof.len() != PROOF_LEN {
            return false;
        }
        self.set
            .contains(&(public_inputs.to_vec(), message.to_vec(), proof.to_vec()))
    }
}

/// The valid triples, loaded once per process.
pub fn known() -> &'static Known {
    static K: OnceLock<Known> = OnceLock::new();
    K.get_or_init(|| {
        let valid = load();
        let set = valid
            .iter()
            .map(|v| (v.public_inputs.clone(), v.message.clone(), v.proof.clone()))
            .collect();
        Known { valid, set }
    })
}

/// A named byte range of the proof (SPEC.md §10).
#[derive(Clone, Copy, Debug)]
pub struct Section {
    pub name: &'static str,
    pub index: usize,
    pub start: usize,
    pub len: usize,
}

pub const TAU: usize = 24;
pub const TAU0: usize = 8;
pub const C_BYTES: usize = 5_307;
pub const D_BYTES: usize = 5_259;
pub const OFF_IV_PRE: usize = 2;
pub const OFF_C: usize = 18;
pub const OFF_U_TILDE: usize = 122_079;
pub const OFF_D: usize = 122_111;
pub const OFF_A_TILDE: usize = 127_370;
pub const OFF_OPEN: usize = 127_386;
pub const OFF_CHALL3: usize = 130_202;

/// Every field of the §10 layout, down to single seeds and commitments of
/// each opening.
pub fn sections() -> &'static [Section] {
    static S: OnceLock<Vec<Section>> = OnceLock::new();
    S.get_or_init(|| {
        let mut s = vec![
            Section { name: "version", index: 0, start: 0, len: 1 },
            Section { name: "statement_id", index: 0, start: 1, len: 1 },
            Section { name: "iv_pre", index: 0, start: OFF_IV_PRE, len: 16 },
        ];
        for i in 0..TAU - 1 {
            s.push(Section { name: "c", index: i + 1, start: OFF_C + i * C_BYTES, len: C_BYTES });
        }
        s.push(Section { name: "u_tilde", index: 0, start: OFF_U_TILDE, len: 32 });
        s.push(Section { name: "d", index: 0, start: OFF_D, len: D_BYTES });
        s.push(Section { name: "a_tilde", index: 0, start: OFF_A_TILDE, len: 16 });
        let mut off = OFF_OPEN;
        for i in 0..TAU {
            let depth = if i < TAU0 { 6 } else { 5 };
            for d in 0..depth {
                s.push(Section { name: "open_seed", index: i * 8 + d, start: off, len: 16 });
                off += 16;
            }
            s.push(Section { name: "open_com", index: i, start: off, len: 32 });
            off += 32;
        }
        assert_eq!(off, OFF_CHALL3);
        s.push(Section { name: "chall3", index: 0, start: OFF_CHALL3, len: 16 });
        assert_eq!(OFF_CHALL3 + 16, PROOF_LEN);
        // Contiguous and complete.
        let mut pos = 0;
        for x in &s {
            assert_eq!(x.start, pos, "{x:?}");
            pos += x.len;
        }
        assert_eq!(pos, PROOF_LEN);
        s
    })
}

/// Minimal byte reader over the fuzz input; reads past the end give zeros.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
    pub fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    pub fn u64(&mut self) -> u64 {
        (self.u32() as u64) | ((self.u32() as u64) << 32)
    }
    /// Up to n bytes (fewer at the end of the input).
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        let end = (start + n).min(self.data.len());
        self.pos = end;
        &self.data[start..end]
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let n = self.data.len().saturating_sub(self.pos);
        self.bytes(n)
    }
}

/// Timing oracle: the baseline is the median of several valid verifications
/// in this process, measured at startup.
pub struct Timing {
    pub baseline: Duration,
    dir: Option<PathBuf>,
}

impl Timing {
    pub fn get() -> &'static Timing {
        static T: OnceLock<Timing> = OnceLock::new();
        T.get_or_init(|| {
            let k = known();
            let v = &k.valid[0];
            // Warm up (circuit build), then 9 timed runs.
            assert!(voleith::verify(STATEMENT_ID, &v.public_inputs, &v.message, &v.proof));
            let mut ts: Vec<Duration> = (0..9)
                .map(|_| {
                    let t = Instant::now();
                    assert!(voleith::verify(STATEMENT_ID, &v.public_inputs, &v.message, &v.proof));
                    t.elapsed()
                })
                .collect();
            ts.sort();
            let dir = std::env::var_os("VOLEITH_SLOW_DIR").map(PathBuf::from);
            if let Some(d) = &dir {
                let _ = std::fs::create_dir_all(d);
            }
            eprintln!("voleith-fuzz: valid-verify baseline {:?}", ts[4]);
            Timing { baseline: ts[4], dir }
        })
    }

    /// Run `f` (a verification); if it took over 2x the baseline, re-time it
    /// three times and, if the fastest run still exceeds 2x, record the input.
    pub fn check<F: FnMut() -> bool>(&self, input: &[u8], mut f: F) -> bool {
        let t = Instant::now();
        let r = f();
        let e = t.elapsed();
        if e > 2 * self.baseline {
            let best = (0..3)
                .map(|_| {
                    let t = Instant::now();
                    let r2 = f();
                    assert_eq!(r, r2, "verify is not deterministic");
                    t.elapsed()
                })
                .min()
                .unwrap();
            if best > 2 * self.baseline {
                eprintln!(
                    "voleith-fuzz: SLOW input: {:?} (first {:?}) vs baseline {:?}",
                    best, e, self.baseline
                );
                if let Some(d) = &self.dir {
                    let name = format!("slow-{:016x}", fxhash(input));
                    let _ = std::fs::write(d.join(name), input);
                }
            }
        }
        r
    }
}

pub fn fxhash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}
