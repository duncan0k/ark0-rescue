//! SHA-256 compression as a Boolean circuit (SPEC.md §7.4).
//!
//! A word is 32 wire ids, least significant bit first. Word gadgets emit
//! their instructions bit by bit in ascending bit order; nested calls
//! evaluate their arguments left to right (each argument is bound with `let`
//! in that order below).

#![forbid(unsafe_code)]

use crate::circuit::{Builder, CONST, PUB, SEC};
use crate::sha256::K256;

pub type Word = [u32; 32];

pub fn const_word(v: u32) -> Word {
    let mut w = [0u32; 32];
    for (i, x) in w.iter_mut().enumerate() {
        *x = (v >> i) & 1;
    }
    w
}

fn word_kind(b: &Builder, w: &Word) -> u8 {
    let mut k = CONST;
    for &x in w {
        match b.kind(x) {
            SEC => return SEC,
            PUB => k = PUB,
            _ => {}
        }
    }
    k
}

fn is_zero_word(w: &Word) -> bool {
    w.iter().all(|&x| x == 0)
}

fn rotr(w: &Word, n: usize) -> Word {
    let mut out = [0u32; 32];
    for (i, x) in out.iter_mut().enumerate() {
        *x = w[(i + n) % 32];
    }
    out
}

fn shr(w: &Word, n: usize) -> Word {
    let mut out = [0u32; 32];
    for (i, x) in out.iter_mut().enumerate() {
        *x = if i + n < 32 { w[i + n] } else { 0 };
    }
    out
}

fn xor_w(b: &mut Builder, x: &Word, y: &Word) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        out[i] = b.xor(x[i], y[i]);
    }
    out
}

fn big_sigma0(b: &mut Builder, a: &Word) -> Word {
    let t = xor_w(b, &rotr(a, 2), &rotr(a, 13));
    xor_w(b, &t, &rotr(a, 22))
}

fn big_sigma1(b: &mut Builder, e: &Word) -> Word {
    let t = xor_w(b, &rotr(e, 6), &rotr(e, 11));
    xor_w(b, &t, &rotr(e, 25))
}

fn small_sigma0(b: &mut Builder, x: &Word) -> Word {
    let t = xor_w(b, &rotr(x, 7), &rotr(x, 18));
    xor_w(b, &t, &shr(x, 3))
}

fn small_sigma1(b: &mut Builder, x: &Word) -> Word {
    let t = xor_w(b, &rotr(x, 17), &rotr(x, 19));
    xor_w(b, &t, &shr(x, 10))
}

/// Ch(e,f,g)[i] = XOR(g[i], AND(e[i], XOR(f[i], g[i]))).
fn ch(b: &mut Builder, e: &Word, f: &Word, g: &Word) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        let fg = b.xor(f[i], g[i]);
        let t = b.and(e[i], fg);
        out[i] = b.xor(g[i], t);
    }
    out
}

/// Maj(x,y,z)[i] = XOR(AND(y,z), AND(x, XOR(y,z))) if x[i] is SEC and y[i],
/// z[i] are not; otherwise XOR(AND(XOR(x,y), XOR(x,z)), x).
fn maj(b: &mut Builder, x: &Word, y: &Word, z: &Word) -> Word {
    let mut out = [0u32; 32];
    for i in 0..32 {
        let (xi, yi, zi) = (x[i], y[i], z[i]);
        out[i] = if b.is_secret(xi) && !b.is_secret(yi) && !b.is_secret(zi) {
            let yz_and = b.and(yi, zi);
            let yz_xor = b.xor(yi, zi);
            let t = b.and(xi, yz_xor);
            b.xor(yz_and, t)
        } else {
            let xy = b.xor(xi, yi);
            let xz = b.xor(xi, zi);
            let t = b.and(xy, xz);
            b.xor(t, xi)
        };
    }
    out
}

/// x + y mod 2^32, ripple carry with one AND per carry bit.
fn add(b: &mut Builder, x: &Word, y: &Word) -> Word {
    let mut out = [0u32; 32];
    let mut c = 0u32;
    for i in 0..32 {
        let xy = b.xor(x[i], y[i]);
        out[i] = b.xor(xy, c);
        if i < 31 {
            let xc = b.xor(x[i], c);
            let yc = b.xor(y[i], c);
            let t = b.and(xc, yc);
            c = b.xor(t, c);
        }
    }
    out
}

/// Sum of several words: non-secret words first, then secret ones (stable),
/// all-zero constant words dropped, then folded left with `add`.
fn add_multi(b: &mut Builder, operands: &[Word]) -> Word {
    let mut ops: Vec<Word> = Vec::with_capacity(operands.len());
    for w in operands.iter().filter(|w| word_kind(b, w) != SEC) {
        ops.push(*w);
    }
    for w in operands.iter().filter(|w| word_kind(b, w) == SEC) {
        ops.push(*w);
    }
    ops.retain(|w| !is_zero_word(w));
    let Some((first, rest)) = ops.split_first() else {
        return const_word(0);
    };
    let mut acc = *first;
    for w in rest {
        acc = add(b, &acc, w);
    }
    acc
}

/// Constrain x + y = z (mod 2^32) for a non-secret word z, without new
/// witness bits: c_i = x_i ^ y_i ^ z_i, c_0 = 0 and
/// (x_i ^ c_i)(y_i ^ c_i) = c_{i+1} ^ c_i.
fn assert_add(b: &mut Builder, x: &Word, y: &Word, z: &Word) {
    let mut c = [0u32; 32];
    for i in 0..32 {
        let xy = b.xor(x[i], y[i]);
        c[i] = b.xor(xy, z[i]);
    }
    b.assert_mul(c[0], 1, 0);
    for i in 0..31 {
        let l = b.xor(x[i], c[i]);
        let r = b.xor(y[i], c[i]);
        let o = b.xor(c[i + 1], c[i]);
        b.assert_mul(l, r, o);
    }
}

/// SHA-256 compression of 16 block words under chaining value `h_in`.
///
/// Without `final_state` it returns the 8 output words h_in + state. With
/// `final_state` S (8 non-secret words) the a- and e-updates of rounds 60..63
/// become `assert_add` constraints against S, the asserted words are used
/// from then on, and nothing is returned.
pub fn compress(
    b: &mut Builder,
    h_in: &[Word; 8],
    block: &[Word; 16],
    final_state: Option<&[Word; 8]>,
) -> Option<[Word; 8]> {
    let mut w: Vec<Word> = block.to_vec();
    for t in 16..64 {
        let s1 = small_sigma1(b, &w[t - 2]);
        let w7 = w[t - 7];
        let s0 = small_sigma0(b, &w[t - 15]);
        let w16 = w[t - 16];
        let next = add_multi(b, &[s1, w7, s0, w16]);
        w.push(next);
    }
    let [mut a, mut bb, mut c, mut d, mut e, mut f, mut g, mut h] = *h_in;
    for t in 0..64 {
        let s1 = big_sigma1(b, &e);
        let chv = ch(b, &e, &f, &g);
        let t1 = add_multi(b, &[h, s1, chv, const_word(K256[t]), w[t]]);
        let s0 = big_sigma0(b, &a);
        let mj = maj(b, &a, &bb, &c);
        let t2 = add_multi(b, &[s0, mj]);
        let (e_new, a_new) = match final_state {
            Some(s) if t >= 60 => {
                let e_new = s[4 + (63 - t)];
                let a_new = s[63 - t];
                assert_add(b, &d, &t1, &e_new);
                assert_add(b, &t1, &t2, &a_new);
                (e_new, a_new)
            }
            _ => {
                let e_new = add_multi(b, &[d, t1]);
                let a_new = add_multi(b, &[t1, t2]);
                (e_new, a_new)
            }
        };
        h = g;
        g = f;
        f = e;
        e = e_new;
        d = c;
        c = bb;
        bb = a;
        a = a_new;
    }
    if final_state.is_some() {
        return None;
    }
    let state = [a, bb, c, d, e, f, g, h];
    let mut out = [[0u32; 32]; 8];
    for i in 0..8 {
        out[i] = add_multi(b, &[h_in[i], state[i]]);
    }
    Some(out)
}

/// The standalone compression circuit of SPEC.md §7.4: 768 secret inputs
/// (chaining value words 0..7, block words 0..15; bit i of word j is input
/// 32j + i) and 256 outputs (bit i of output word w is output 32w + i).
pub fn build_compression_circuit() -> crate::circuit::Circuit {
    let mut b = Builder::new(0, 768);
    let mut words = [[0u32; 32]; 24];
    for (j, word) in words.iter_mut().enumerate() {
        for (i, x) in word.iter_mut().enumerate() {
            *x = b.secret(32 * j + i);
        }
    }
    let mut h_in = [[0u32; 32]; 8];
    h_in.copy_from_slice(&words[..8]);
    let mut block = [[0u32; 32]; 16];
    block.copy_from_slice(&words[8..]);
    let out = compress(&mut b, &h_in, &block, None)
        .expect("compression without a final state returns words");
    b.outputs = out.iter().flat_map(|w| w.iter().copied()).collect();
    b.build()
}

/// The statement 0x01 circuit (SPEC.md §7.5): P = 776 public bits (IV_in,
/// IV_out, T, suffix), S = 256 secret bits (x).
pub fn build_statement1_circuit() -> crate::circuit::Circuit {
    let mut b = Builder::new(776, 256);
    let word_at = |b: &Builder, base: usize| -> Word {
        let mut w = [0u32; 32];
        for (i, x) in w.iter_mut().enumerate() {
            *x = b.public(base + i);
        }
        w
    };
    let mut iv_in = [[0u32; 32]; 8];
    let mut iv_out = [[0u32; 32]; 8];
    let mut target = [[0u32; 32]; 8];
    for j in 0..8 {
        iv_in[j] = word_at(&b, 32 * j);
        iv_out[j] = word_at(&b, 256 + 32 * j);
        target[j] = word_at(&b, 512 + 32 * j);
    }
    // Big-endian word j of x: bit i comes from byte 4j + 3 - i/8, bit i%8.
    let mut inner = [[0u32; 32]; 16];
    for (j, word) in inner.iter_mut().take(8).enumerate() {
        for (i, x) in word.iter_mut().enumerate() {
            *x = b.secret(8 * (4 * j + 3 - i / 8) + (i % 8));
        }
    }
    // W8 = suffix || 0x80 || 0x00 0x00 (big-endian): bits 0..22 zero, bit 23
    // one, bits 24..31 the suffix bits 0..7.
    for (i, x) in inner[8].iter_mut().enumerate() {
        *x = match i {
            0..=22 => 0,
            23 => 1,
            _ => b.public(768 + i - 24),
        };
    }
    for word in inner.iter_mut().take(15).skip(9) {
        *word = const_word(0);
    }
    inner[15] = const_word(776);
    let digest = compress(&mut b, &iv_in, &inner, None).expect("inner compression returns words");
    let mut outer = [[0u32; 32]; 16];
    outer[..8].copy_from_slice(&digest);
    outer[8] = const_word(0x8000_0000);
    for word in outer.iter_mut().take(15).skip(9) {
        *word = const_word(0);
    }
    outer[15] = const_word(768);
    compress(&mut b, &iv_out, &outer, Some(&target));
    b.build()
}

// Both tests evaluate circuits in the clear or compute prover terms.
#[cfg(all(test, feature = "prover"))]
mod tests {
    use super::*;
    use crate::gf128::{self, FixedMul};
    use crate::sha256;
    use crate::unihash::{CtMul, ZkAcc, ZkHash};

    fn bits_of_words(words: &[u32]) -> Vec<u8> {
        words
            .iter()
            .flat_map(|&w| (0..32).map(move |i| ((w >> i) & 1) as u8))
            .collect()
    }

    #[test]
    fn compression_circuit_matches_native() {
        let circ = build_compression_circuit();
        let c = circ.counts();
        assert_eq!((c.and, c.xor, c.not), (22_573, 111_607, 1_891));
        let mut x: u64 = 0x0123_4567_89ab_cdef;
        for _ in 0..3 {
            let mut state = [0u32; 8];
            let mut block = [0u8; 64];
            for s in state.iter_mut() {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *s = (x >> 32) as u32;
            }
            for byte in block.iter_mut() {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = (x >> 56) as u8;
            }
            let mut words = state.to_vec();
            for chunk in block.chunks_exact(4) {
                words.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
            let (vals, _, ok) = circ.evaluate(&[], &bits_of_words(&words));
            assert!(ok);
            let out: Vec<u8> = circ.outputs.iter().map(|&w| vals[w as usize]).collect();
            assert_eq!(out, bits_of_words(&sha256::compress(&state, &block)));
        }
    }

    /// The check of SPEC.md §6.3 (b~ = q~ + a~ Delta, with a~ = ZKH(A1; u*),
    /// b~ = ZKH(A0; v*), q~ = ZKH(B; q*)) fails when the prover changes any
    /// single term A0_t or A1_t of an honest witness, for every t. The
    /// circuit is the small one of python/tests/test_quicksilver.py with
    /// 32-bit words: s = x + y, Maj(x, y, p), Ch(p, x, y), s + p = z asserted
    /// for a public z, and s + p computed.
    #[test]
    fn quicksilver_check_rejects_any_single_tampered_term() {
        let mut state = 0x5eed_u64;
        let mut rand = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let lo = z ^ (z >> 31);
            ((lo as u128) << 64) | lo.rotate_left(17) as u128
        };
        let mut b = Builder::new(64, 64);
        let p: Word = core::array::from_fn(|i| b.public(i));
        let z: Word = core::array::from_fn(|i| b.public(32 + i));
        let x: Word = core::array::from_fn(|i| b.secret(i));
        let y: Word = core::array::from_fn(|i| b.secret(32 + i));
        let s = add(&mut b, &x, &y);
        maj(&mut b, &x, &y, &p);
        ch(&mut b, &p, &x, &y);
        assert_add(&mut b, &s, &p, &z);
        add_multi(&mut b, &[s, p]);
        let circ = b.build();
        assert!(circ.n_mul > 0 && circ.n_assert == 32);

        let (xv, yv, pv) = (rand() as u32, rand() as u32, rand() as u32);
        let zv = xv.wrapping_add(yv).wrapping_add(pv);
        let pub_bits = bits_of_words(&[pv, zv]);
        let (_, wit, ok) = circ.evaluate(&pub_bits, &bits_of_words(&[xv, yv]));
        assert!(ok);
        let delta = rand();
        let tags: Vec<u128> = wit.iter().map(|_| rand()).collect();
        let keys: Vec<u128> = tags
            .iter()
            .zip(&wit)
            .map(|(&t, &w)| t ^ (delta & 0u128.wrapping_sub(w as u128)))
            .collect();
        let (mut a0, mut a1, mut bt) = (Vec::new(), Vec::new(), Vec::new());
        circ.prover_terms(&pub_bits, &wit, &tags, |t0, t1| {
            a0.push(t0);
            a1.push(t1);
        });
        circ.verifier_terms(&pub_bits, &keys, delta, &FixedMul::new(delta), |t| {
            bt.push(t)
        });
        assert_eq!(a0.len(), circ.n_constraints);
        assert_eq!(bt.len(), circ.n_constraints);
        for (t, ((&b_t, &a0_t), &a1_t)) in bt.iter().zip(&a0).zip(&a1).enumerate() {
            assert_eq!(b_t, a0_t ^ gf128::mul(a1_t, delta), "honest term {t}");
        }

        let mut chall2 = [0u8; 64];
        for chunk in chall2.chunks_exact_mut(16) {
            chunk.copy_from_slice(&rand().to_le_bytes());
        }
        let zk = ZkHash::<CtMul>::new(&chall2);
        let zkh = |terms: &[u128], mask: u128| {
            let mut acc = ZkAcc::default();
            for &v in terms {
                zk.absorb(&mut acc, v);
            }
            zk.finish(&acc, mask)
        };
        let (u_star, v_star) = (rand(), rand());
        let q_tilde = zkh(&bt, v_star ^ gf128::mul(u_star, delta));
        let accepted = |a0: &[u128], a1: &[u128]| {
            zkh(a0, v_star) == q_tilde ^ gf128::mul(zkh(a1, u_star), delta)
        };
        assert!(accepted(&a0, &a1));
        for t in 0..circ.n_constraints {
            let e = rand() | 1;
            let mut bad = a0.clone();
            bad[t] ^= e;
            assert!(!accepted(&bad, &a1), "A0 term {t}");
            let mut bad = a1.clone();
            bad[t] ^= e;
            assert!(!accepted(&a0, &bad), "A1 term {t}");
        }
    }
}
