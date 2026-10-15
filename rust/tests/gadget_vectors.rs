//! The per-gadget circuit digests in vectors/gadgets-v0.2.json (SPEC.md §7.6).
//!
//! The gadgets of SPEC.md §7.4 are private to the crate, so this test
//! compiles the crate's circuit builder (src/circuit.rs) into the test and
//! writes the gadgets on top of it from the SPEC text. Rebuilding the
//! statement 0x01 and standalone compression circuits with these gadgets
//! must give the crate's own digests; then every circuit in the file must
//! give its listed digest and counts.

mod common;

#[allow(dead_code)]
#[path = "../src/gf128.rs"]
mod gf128;

#[allow(dead_code)]
#[path = "../src/circuit.rs"]
mod circuit;

mod sha256 {
    pub use voleith::hash::sha256;
}

use circuit::{Builder, Circuit, SEC};
use common::{load_json, str_of, to_hex, u64_of};
use voleith::circuit_info::{compression_circuit_digest, statement_circuit_info};
use voleith::STATEMENT1_ID;

type Word = [u32; 32];

/// FIPS 180-4 round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn const_word(v: u32) -> Word {
    core::array::from_fn(|i| (v >> i) & 1)
}

fn rotr(w: &Word, n: usize) -> Word {
    core::array::from_fn(|i| w[(i + n) % 32])
}

fn shr(w: &Word, n: usize) -> Word {
    core::array::from_fn(|i| if i + n < 32 { w[i + n] } else { 0 })
}

fn xor_w(b: &mut Builder, x: &Word, y: &Word) -> Word {
    core::array::from_fn(|i| b.xor(x[i], y[i]))
}

/// xor_w(xor_w(rotr(x, r1), rotr(x, r2)), third): the inner word is
/// complete before the outer one starts.
fn sigma(b: &mut Builder, x: &Word, r1: usize, r2: usize, third: Word) -> Word {
    let inner = xor_w(b, &rotr(x, r1), &rotr(x, r2));
    xor_w(b, &inner, &third)
}

fn big_sigma0(b: &mut Builder, a: &Word) -> Word {
    sigma(b, a, 2, 13, rotr(a, 22))
}

fn big_sigma1(b: &mut Builder, e: &Word) -> Word {
    sigma(b, e, 6, 11, rotr(e, 25))
}

fn small_sigma0(b: &mut Builder, x: &Word) -> Word {
    sigma(b, x, 7, 18, shr(x, 3))
}

fn small_sigma1(b: &mut Builder, x: &Word) -> Word {
    sigma(b, x, 17, 19, shr(x, 10))
}

fn ch(b: &mut Builder, e: &Word, f: &Word, g: &Word) -> Word {
    core::array::from_fn(|i| {
        let fg = b.xor(f[i], g[i]);
        let t = b.and(e[i], fg);
        b.xor(g[i], t)
    })
}

fn maj(b: &mut Builder, x: &Word, y: &Word, z: &Word) -> Word {
    core::array::from_fn(|i| {
        if b.is_secret(x[i]) && !b.is_secret(y[i]) && !b.is_secret(z[i]) {
            let yz = b.and(y[i], z[i]);
            let yxz = b.xor(y[i], z[i]);
            let t = b.and(x[i], yxz);
            b.xor(yz, t)
        } else {
            let xy = b.xor(x[i], y[i]);
            let xz = b.xor(x[i], z[i]);
            let t = b.and(xy, xz);
            b.xor(t, x[i])
        }
    })
}

fn add(b: &mut Builder, x: &Word, y: &Word) -> Word {
    let mut s = [0u32; 32];
    let mut c = 0u32;
    for i in 0..32 {
        let xy = b.xor(x[i], y[i]);
        s[i] = b.xor(xy, c);
        if i < 31 {
            let xc = b.xor(x[i], c);
            let yc = b.xor(y[i], c);
            let t = b.and(xc, yc);
            c = b.xor(t, c);
        }
    }
    s
}

fn has_sec(b: &Builder, w: &Word) -> bool {
    w.iter().any(|&x| b.kind(x) == SEC)
}

fn add_multi(b: &mut Builder, words: &[Word]) -> Word {
    let mut ops: Vec<Word> = words.iter().filter(|w| !has_sec(b, w)).copied().collect();
    ops.extend(words.iter().filter(|w| has_sec(b, w)).copied());
    ops.retain(|w| w.iter().any(|&x| x != 0));
    let Some((first, rest)) = ops.split_first() else {
        return const_word(0);
    };
    let mut acc = *first;
    for w in rest {
        acc = add(b, &acc, w);
    }
    acc
}

fn assert_add(b: &mut Builder, x: &Word, y: &Word, z: &Word) {
    let c: Word = core::array::from_fn(|i| {
        let xy = b.xor(x[i], y[i]);
        b.xor(xy, z[i])
    });
    b.assert_mul(c[0], 1, 0);
    for i in 0..31 {
        let l = b.xor(x[i], c[i]);
        let r = b.xor(y[i], c[i]);
        let o = b.xor(c[i + 1], c[i]);
        b.assert_mul(l, r, o);
    }
}

fn compress(b: &mut Builder, h: &[Word], block: &[Word], s: Option<&[Word]>) -> Vec<Word> {
    let mut w: Vec<Word> = block.to_vec();
    for t in 16..64 {
        let s1 = small_sigma1(b, &w[t - 2]);
        let s0 = small_sigma0(b, &w[t - 15]);
        let next = add_multi(b, &[s1, w[t - 7], s0, w[t - 16]]);
        w.push(next);
    }
    let mut st: [Word; 8] = core::array::from_fn(|i| h[i]);
    for t in 0..64 {
        let [a, bb, c, d, e, f, g, hh] = st;
        let s1 = big_sigma1(b, &e);
        let chv = ch(b, &e, &f, &g);
        let t1 = add_multi(b, &[hh, s1, chv, const_word(K[t]), w[t]]);
        let s0 = big_sigma0(b, &a);
        let mj = maj(b, &a, &bb, &c);
        let t2 = add_multi(b, &[s0, mj]);
        let (e2, a2) = match s {
            Some(s) if t >= 60 => {
                let (e2, a2) = (s[4 + 63 - t], s[63 - t]);
                assert_add(b, &d, &t1, &e2);
                assert_add(b, &t1, &t2, &a2);
                (e2, a2)
            }
            _ => {
                let e2 = add_multi(b, &[d, t1]);
                let a2 = add_multi(b, &[t1, t2]);
                (e2, a2)
            }
        };
        st = [a2, a, bb, c, e2, e, f, g];
    }
    if s.is_some() {
        return Vec::new();
    }
    (0..8).map(|i| add_multi(b, &[h[i], st[i]])).collect()
}

/// Public words P0.. and secret words S0.., 32 input bits each.
fn input_words(b: &Builder, n_pub: usize, n_sec: usize) -> (Vec<Word>, Vec<Word>) {
    let p = (0..n_pub)
        .map(|j| core::array::from_fn(|i| b.public(32 * j + i)))
        .collect();
    let s = (0..n_sec)
        .map(|j| core::array::from_fn(|i| b.secret(32 * j + i)))
        .collect();
    (p, s)
}

/// The circuit named in vectors/gadgets-v0.2.json.
fn build(name: &str, n_public: usize, n_secret: usize) -> Circuit {
    let mut b = Builder::new(n_public, n_secret);
    let (p, s) = input_words(&b, n_public / 32, n_secret / 32);
    let k0 = const_word(0x428a2f98);
    let out: Vec<Word> = match name {
        "add_sec_sec" => vec![add(&mut b, &s[0], &s[1])],
        "add_sec_pub" => vec![add(&mut b, &s[0], &p[0])],
        "add_pub_sec" => vec![add(&mut b, &p[0], &s[0])],
        "add_sec_const" => vec![add(&mut b, &s[0], &k0)],
        "add_multi_mixed" => {
            vec![add_multi(
                &mut b,
                &[s[0], p[0], const_word(0), k0, s[1], p[1]],
            )]
        }
        "xor_w_sec_const" => vec![xor_w(&mut b, &s[0], &const_word(0x0000_ffff))],
        "ch_sec" => vec![ch(&mut b, &s[0], &s[1], &s[2])],
        "ch_sec_pub_pub" => vec![ch(&mut b, &s[0], &p[0], &p[1])],
        "ch_pub_sec_sec" => vec![ch(&mut b, &p[0], &s[0], &s[1])],
        "maj_sec" => vec![maj(&mut b, &s[0], &s[1], &s[2])],
        "maj_sec_pub_pub" => vec![maj(&mut b, &s[0], &p[0], &p[1])],
        "maj_mixed_bits" => {
            let x: Word = core::array::from_fn(|i| if i % 2 == 0 { s[0][i] } else { p[0][i] });
            let z: Word = core::array::from_fn(|i| if i % 2 == 1 { s[1][i] } else { p[2][i] });
            vec![maj(&mut b, &x, &p[1], &z)]
        }
        "big_sigma0_sec" => vec![big_sigma0(&mut b, &s[0])],
        "big_sigma1_sec" => vec![big_sigma1(&mut b, &s[0])],
        "small_sigma0_sec" => vec![small_sigma0(&mut b, &s[0])],
        "small_sigma1_sec" => vec![small_sigma1(&mut b, &s[0])],
        "big_sigma0_pub" => vec![big_sigma0(&mut b, &p[0])],
        "assert_add_sec_sec_pub" => {
            assert_add(&mut b, &s[0], &s[1], &p[0]);
            Vec::new()
        }
        "assert_add_sec_pub_pub" => {
            assert_add(&mut b, &s[0], &p[0], &p[1]);
            Vec::new()
        }
        "compress_pub_block" => compress(&mut b, &s[..8], &p[..16], None),
        other => panic!("unknown gadget circuit {other}"),
    };
    b.outputs = out.iter().flatten().copied().collect();
    b.build()
}

/// The statement 0x01 circuit of SPEC.md §7.5, from the gadgets above.
fn statement1() -> Circuit {
    let mut b = Builder::new(776, 256);
    let (p, _) = input_words(&b, 24, 0);
    let x: Vec<Word> = (0..8)
        .map(|j| core::array::from_fn(|i| b.secret(8 * (4 * j + 3 - i / 8) + i % 8)))
        .collect();
    let w8: Word = core::array::from_fn(|i| match i {
        0..=22 => 0,
        23 => 1,
        _ => b.public(768 + i - 24),
    });
    let mut inner = x;
    inner.push(w8);
    inner.extend([const_word(0); 6]);
    inner.push(const_word(776));
    let mut outer = compress(&mut b, &p[0..8], &inner, None);
    outer.push(const_word(0x8000_0000));
    outer.extend([const_word(0); 6]);
    outer.push(const_word(768));
    compress(&mut b, &p[8..16], &outer, Some(&p[16..24]));
    b.build()
}

/// The standalone compression circuit of SPEC.md §7.4.
fn standalone_compression() -> Circuit {
    let mut b = Builder::new(0, 768);
    let (_, s) = input_words(&b, 0, 24);
    let out = compress(&mut b, &s[..8], &s[8..], None);
    b.outputs = out.iter().flatten().copied().collect();
    b.build()
}

#[test]
fn spec_gadgets_rebuild_the_crate_circuits() {
    let info = statement_circuit_info(STATEMENT1_ID).expect("registered");
    assert_eq!(statement1().digest(), info.digest);
    assert_eq!(
        standalone_compression().digest(),
        compression_circuit_digest()
    );
}

#[test]
fn gadget_circuits_match_the_vector_file() {
    let doc = load_json("gadgets-v0.2.json");
    let circuits = doc["circuits"].as_array().expect("circuits");
    assert!(circuits.len() >= 15);
    for c in circuits {
        let name = str_of(c, "name");
        let circ = build(
            name,
            u64_of(c, "n_public") as usize,
            u64_of(c, "n_secret") as usize,
        );
        let ser = circ.serialize();
        assert_eq!(ser.len() as u64, u64_of(c, "serialization_len"), "{name}");
        assert_eq!(
            to_hex(&circ.digest()),
            str_of(c, "sha256_of_serialization"),
            "{name}"
        );
        if let Some(h) = c.get("serialization_hex") {
            assert_eq!(to_hex(&ser), h.as_str().expect("hex"), "{name}");
        }
        assert_eq!(
            circ.instrs.len() as u64,
            u64_of(c, "n_instructions"),
            "{name}"
        );
        assert_eq!(circ.outputs.len() as u64, u64_of(c, "n_outputs"), "{name}");
        let g = circ.counts();
        let want = &c["gate_counts"];
        assert_eq!(g.xor as u64, u64_of(want, "XOR"), "{name}");
        assert_eq!(g.and as u64, u64_of(want, "AND"), "{name}");
        assert_eq!(g.not as u64, u64_of(want, "NOT"), "{name}");
        assert_eq!(g.assert as u64, u64_of(want, "ASSERT"), "{name}");
        assert_eq!(
            g.and_secret_secret as u64,
            u64_of(want, "AND_secret_secret"),
            "{name}"
        );
    }
}
