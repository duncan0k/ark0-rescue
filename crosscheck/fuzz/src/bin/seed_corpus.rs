//! Writes the seed corpora of the three targets: corpus/<target>/seed-*.
//! Usage: cargo run --release --bin seed_corpus [out_dir]

use std::fs;
use std::path::PathBuf;
use voleith_fuzz::{known, sections};

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "corpus".into()));
    let k = known();
    let w = |t: &str, name: String, data: Vec<u8>| {
        let d = out.join(t);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join(name), data).unwrap();
    };

    // verify_raw: the KATs in the raw layout, with and without the flags.
    for (i, v) in k.valid.iter().take(4).enumerate() {
        for flags in [0u8, 7] {
            let mut s = vec![flags, 1];
            s.extend_from_slice(&(v.public_inputs.len() as u16).to_le_bytes());
            s.extend_from_slice(&(v.message.len() as u32).to_le_bytes());
            s.extend_from_slice(&v.public_inputs);
            s.extend_from_slice(&v.message);
            s.extend_from_slice(&v.proof);
            w("verify_raw", format!("seed-kat{i}-f{flags}"), s);
        }
    }
    w("verify_raw", "seed-empty".into(), vec![7, 1, 0, 0, 0, 0, 0, 0]);

    // verify_mutate: each base alone, then one program per op kind and per
    // section boundary of the first base.
    for i in 0..k.valid.len() {
        w("verify_mutate", format!("seed-base{i:03}"), vec![i as u8]);
    }
    for op in 0u8..12 {
        w("verify_mutate", format!("seed-op{op:02}"), vec![0, op, 1, 7, 0, 0, 0, 3, 1, 0, 0, 0, 0, 0]);
    }
    for (si, _) in sections().iter().enumerate() {
        let s = (si as u16).to_le_bytes();
        w("verify_mutate", format!("seed-bound{si:03}"), vec![1, 3, s[0], s[1], (si % 4) as u8, 0x5a, 0]);
    }

    // ffi: base vectors with their exact lengths, plus null/zero-length cases.
    for i in 0..4u8 {
        let mut s = vec![1, i];
        for _ in 0..3 {
            s.push(0x80); // k, then y below, msg, proof: exact default length
            s.extend_from_slice(&[0; 8]);
            if s.len() == 11 {
                s.push(0); // y: 32-byte buffer
            }
        }
        s.push(0); // suffix (base suffix with flags bit 1 clear)
        w("ffi", format!("seed-kat{i}"), s);
    }
    w("ffi", "seed-nulls".into(), vec![0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    eprintln!("seed corpora written to {}", out.display());
}
