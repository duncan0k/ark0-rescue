//! Domain-separated SHAKE256 (SPEC.md §3).
//!
//! Every hash, PRG and random-oracle call is
//! `SHAKE256( u8(|T|) || T || data, L )` with
//! `T = "VOLEitH-rescue/v0.2/" || name`.
//!
//! SHAKE256 is a sponge over Keccak-f[1600] (FIPS 202) written here on top
//! of `keccak::f1600`, the permutation that the `sha3` crate uses. Input is
//! XORed into the state and output read from it in place: there is no
//! separate block buffer or output buffer, and the state is zeroized when
//! the sponge is dropped. The sponge lives on the heap, so moving an `Xof`
//! or `XofReader` moves a pointer and leaves no copy of the state behind. The test below checks it against `sha3` (a dev-dependency).

#![forbid(unsafe_code)]

use zeroize::Zeroize;

/// SHAKE256 rate in bytes (1600 - 2 * 256 bits).
const RATE: usize = 136;

/// The tag names of SPEC.md §3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Mu,
    /// Prover only.
    #[cfg(feature = "prover")]
    Rnd,
    Iv,
    /// Prover only.
    #[cfg(feature = "prover")]
    Root,
    Ggm,
    Leaf,
    Exp,
    Tree,
    Hcom,
    Ch1,
    Hv,
    Ch2,
    Ch3,
}

const PREFIX: &[u8] = b"VOLEitH-rescue/v0.2/";

impl Tag {
    fn name(self) -> &'static [u8] {
        match self {
            Tag::Mu => b"mu",
            #[cfg(feature = "prover")]
            Tag::Rnd => b"rnd",
            Tag::Iv => b"iv",
            #[cfg(feature = "prover")]
            Tag::Root => b"root",
            Tag::Ggm => b"ggm",
            Tag::Leaf => b"leaf",
            Tag::Exp => b"exp",
            Tag::Tree => b"tree",
            Tag::Hcom => b"hcom",
            Tag::Ch1 => b"ch1",
            Tag::Hv => b"hv",
            Tag::Ch2 => b"ch2",
            Tag::Ch3 => b"ch3",
        }
    }
}

/// The Keccak state and the byte position in its rate part. It lives on
/// the heap, inside an [`Xof`] and then an [`XofReader`], so that passing
/// either by value moves a pointer and never copies the state; it is
/// zeroized when dropped.
struct Sponge {
    state: [u64; 25],
    pos: usize,
}

impl Drop for Sponge {
    fn drop(&mut self) {
        self.state.zeroize();
        self.pos = 0;
    }
}

impl Sponge {
    #[inline]
    fn xor_byte(&mut self, i: usize, b: u8) {
        self.state[i / 8] ^= (b as u64) << (8 * (i % 8));
    }
}

/// A tagged SHAKE256 computation that is absorbing. The type states make
/// misuse impossible in every build: `finalize*` consumes the `Xof`, so
/// nothing can be absorbed after it and it cannot be finalized twice, and
/// only the [`XofReader`] it returns can read.
pub struct Xof(Box<Sponge>);

/// A finalized SHAKE256 computation that only reads output.
pub struct XofReader(Box<Sponge>);

impl Xof {
    pub fn new(tag: Tag) -> Self {
        let name = tag.name();
        let mut x = Xof(Box::new(Sponge {
            state: [0; 25],
            pos: 0,
        }));
        x.absorb(&[(PREFIX.len() + name.len()) as u8]);
        x.absorb(PREFIX);
        x.absorb(name);
        x
    }

    /// `absorb`, by value, for chains.
    #[inline]
    pub fn update(mut self, data: &[u8]) -> Self {
        self.absorb(data);
        self
    }

    pub fn absorb(&mut self, mut data: &[u8]) {
        let s = &mut *self.0;
        while !data.is_empty() {
            let take = (RATE - s.pos).min(data.len());
            let (mut head, rest) = data.split_at(take);
            // Bytes up to a lane boundary, whole lanes, then the tail.
            while s.pos % 8 != 0 && !head.is_empty() {
                s.xor_byte(s.pos, head[0]);
                s.pos += 1;
                head = &head[1..];
            }
            let lanes = head.chunks_exact(8);
            let tail = lanes.remainder();
            for w in lanes {
                s.state[s.pos / 8] ^= u64::from_le_bytes(w.try_into().expect("8 bytes"));
                s.pos += 8;
            }
            for &b in tail {
                s.xor_byte(s.pos, b);
                s.pos += 1;
            }
            data = rest;
            if s.pos == RATE {
                keccak::f1600(&mut s.state);
                s.pos = 0;
            }
        }
    }

    /// Pad (SHAKE domain bits 1111, then pad10*1) and start reading.
    pub fn finalize_xof(self) -> XofReader {
        let mut s = self.0;
        let pos = s.pos;
        s.xor_byte(pos, 0x1f);
        s.xor_byte(RATE - 1, 0x80);
        keccak::f1600(&mut s.state);
        s.pos = 0;
        XofReader(s)
    }

    /// Fill `out` with the first `out.len()` output bytes.
    pub fn finalize_into(self, out: &mut [u8]) {
        self.finalize_xof().read(out);
    }

    /// The first `N` output bytes. For secret output, prefer
    /// `finalize_into` a caller-owned (zeroizing) buffer.
    pub fn finalize<const N: usize>(self) -> [u8; N] {
        let mut out = [0u8; N];
        self.finalize_into(&mut out);
        out
    }
}

impl XofReader {
    /// Fill `out` with the next `out.len()` output bytes.
    pub fn read(&mut self, mut out: &mut [u8]) {
        let s = &mut *self.0;
        while !out.is_empty() {
            if s.pos == RATE {
                keccak::f1600(&mut s.state);
                s.pos = 0;
            }
            let take = (RATE - s.pos).min(out.len());
            let (mut head, rest) = out.split_at_mut(take);
            while s.pos % 8 != 0 && !head.is_empty() {
                head[0] = (s.state[s.pos / 8] >> (8 * (s.pos % 8))) as u8;
                s.pos += 1;
                head = &mut head[1..];
            }
            let mut lanes = head.chunks_exact_mut(8);
            for o in &mut lanes {
                o.copy_from_slice(&s.state[s.pos / 8].to_le_bytes());
                s.pos += 8;
            }
            for o in lanes.into_remainder() {
                *o = (s.state[s.pos / 8] >> (8 * (s.pos % 8))) as u8;
                s.pos += 1;
            }
            out = rest;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_prefix_matches_version_label() {
        let expect = format!("VOLEitH-rescue/{}/", crate::params::VERSION_LABEL);
        assert_eq!(PREFIX, expect.as_bytes());
    }

    /// SHAKE256 of the bytes, computed by this module's sponge (without a
    /// tag) and by the `sha3` crate.
    fn both(data: &[u8], split: usize, out_len: usize) -> (Vec<u8>, Vec<u8>) {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut x = Xof(Box::new(Sponge {
            state: [0; 25],
            pos: 0,
        }));
        x.absorb(&data[..split]);
        let x = x.update(&data[split..]);
        let mut a = vec![0u8; out_len];
        x.finalize_into(&mut a);
        let mut h = sha3::Shake256::default();
        h.update(data);
        let mut b = vec![0u8; out_len];
        h.finalize_xof().read(&mut b);
        (a, b)
    }

    #[test]
    fn sponge_matches_sha3() {
        let data: Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let lens = [0, 1, 7, 8, 9, 135, 136, 137, 271, 272, 273, 408, 999, 1000];
        for &n in &lens {
            for split in [0, n / 3, n / 2, n] {
                for out_len in [0, 1, 16, 135, 136, 137, 300, 5307] {
                    let (a, b) = both(&data[..n], split, out_len);
                    assert_eq!(a, b, "len {n} split {split} out {out_len}");
                }
            }
        }
        // A tagged Xof is SHAKE256 of u8(|T|) || T || data.
        let mut t = vec![(PREFIX.len() + 2) as u8];
        t.extend_from_slice(PREFIX);
        t.extend_from_slice(b"mu");
        t.extend_from_slice(&data[..200]);
        let tagged: [u8; 64] = Xof::new(Tag::Mu).update(&data[..200]).finalize();
        assert_eq!(tagged.to_vec(), both(&t, 0, 64).1);
    }

    /// Many small reads give the same bytes as one large read, for chunk
    /// patterns that cross the 136-byte rate boundary at every offset, and
    /// after absorbing inputs that end at, before and after a boundary.
    #[test]
    fn split_reads_match_one_read() {
        const TOTAL: usize = 3 * RATE + 17;
        let data: Vec<u8> = (0..300u32).map(|i| (i * 31 + 7) as u8).collect();
        let patterns: Vec<Vec<usize>> = vec![
            vec![1],
            vec![7],
            vec![8],
            vec![135, 1],
            vec![136],
            vec![137],
            vec![1, 135, 136, 2],
            vec![5, 200, 3, 64],
            vec![RATE - 1, 2, RATE - 2, 1],
        ];
        for in_len in [0, 1, 135, 136, 137, 271, 272, 300] {
            let mut whole = [0u8; TOTAL];
            Xof::new(Tag::Exp)
                .update(&data[..in_len])
                .finalize_into(&mut whole);
            for pat in &patterns {
                let mut r = Xof::new(Tag::Exp).update(&data[..in_len]).finalize_xof();
                let mut got = Vec::new();
                for &n in pat.iter().cycle() {
                    let n = n.min(TOTAL - got.len());
                    let mut buf = vec![0u8; n];
                    r.read(&mut buf);
                    got.extend_from_slice(&buf);
                    if got.len() == TOTAL {
                        break;
                    }
                }
                assert_eq!(got[..], whole[..], "input {in_len}, reads {pat:?}");
            }
            // Empty reads change nothing.
            let mut r = Xof::new(Tag::Exp).update(&data[..in_len]).finalize_xof();
            let mut got = [0u8; TOTAL];
            r.read(&mut []);
            r.read(&mut got[..RATE]);
            r.read(&mut []);
            r.read(&mut got[RATE..]);
            assert_eq!(got, whole);
        }
    }

    #[test]
    fn shake256_known_answer() {
        // FIPS 202 SHAKE256 of the empty string, first 32 bytes.
        let (out, _) = both(b"", 0, 32);
        let expect = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f,
        ];
        assert_eq!(out, expect);
    }
}
