//! Cross-check driver for the Rust implementation.
//!
//!   voleith-crosscheck prove  <cases.tsv> <proofs.txt>
//!   voleith-crosscheck verify <cases.tsv> <proofs.txt> <tests.tsv> <verdicts.tsv>
//!
//! cases.tsv:  id, public inputs, message, witness x, rho (hex; "-" = empty)
//! proofs.txt: one hex proof per case, in order
//! tests.tsv:  test id, case id, kind, target, bit, replacement public inputs
//!             target "none": the case as proved; "proof"/"msg": flip bit
//!             `bit` (LSB-first within each byte, bit = 8 * byte + k);
//!             "msg" with bit -1: append one 0x00 byte (empty message);
//!             "pub": replace the public inputs by the last column.
//! verdicts.tsv: test id, 1 (accept), 0 (reject) or E (panic)

use std::fs;
use std::io::Write;
use std::time::Instant;

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Case {
    public: Vec<u8>,
    msg: Vec<u8>,
    x: Vec<u8>,
    rho: [u8; 32],
}

fn cases(path: &str) -> Vec<Case> {
    fs::read_to_string(path)
        .expect("read cases")
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Case {
                public: unhex(f[1]),
                msg: unhex(f[2]),
                x: unhex(f[3]),
                rho: unhex(f[4]).try_into().expect("rho is 32 bytes"),
            }
        })
        .collect()
}

fn flip(buf: &mut Vec<u8>, bit: i64) {
    if bit < 0 {
        buf.push(0);
    } else {
        buf[(bit / 8) as usize] ^= 1 << (bit % 8);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cs = cases(&a[2]);
    match a[1].as_str() {
        "prove" => {
            let mut out = fs::File::create(&a[3]).expect("create proofs");
            let t = Instant::now();
            for c in &cs {
                let p = voleith::prove(voleith::STATEMENT1_ID, &c.public, &c.x, &c.msg, &c.rho)
                    .expect("prove failed");
                writeln!(out, "{}", hex(&p)).unwrap();
            }
            eprintln!("rust: proved {} cases in {:.2?}", cs.len(), t.elapsed());
        }
        "verify" => {
            let proofs: Vec<Vec<u8>> = fs::read_to_string(&a[3])
                .expect("read proofs")
                .lines()
                .filter(|l| !l.is_empty())
                .map(unhex)
                .collect();
            let tests = fs::read_to_string(&a[4]).expect("read tests");
            let mut out = fs::File::create(&a[5]).expect("create verdicts");
            let t = Instant::now();
            let mut n = 0;
            for l in tests.lines().filter(|l| !l.is_empty()) {
                let f: Vec<&str> = l.split('\t').collect();
                let ci: usize = f[1].parse().unwrap();
                let bit: i64 = f[4].parse().unwrap();
                let c = &cs[ci];
                let (mut public, mut msg, mut proof) = (c.public.clone(), c.msg.clone(), proofs[ci].clone());
                match f[3] {
                    "none" => {}
                    "proof" => flip(&mut proof, bit),
                    "msg" => flip(&mut msg, bit),
                    "pub" => public = unhex(f[5]),
                    t => panic!("unknown target {t}"),
                }
                let v = match std::panic::catch_unwind(|| {
                    voleith::verify(voleith::STATEMENT1_ID, &public, &msg, &proof)
                }) {
                    Ok(true) => "1",
                    Ok(false) => "0",
                    Err(_) => "E",
                };
                writeln!(out, "{}\t{}", f[0], v).unwrap();
                n += 1;
            }
            eprintln!("rust: verified {n} tests in {:.2?}", t.elapsed());
        }
        c => panic!("unknown command {c}"),
    }
}
