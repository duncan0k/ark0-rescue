//! Domain-separated SHAKE256 (SPEC.md §3).
//!
//! Every hash, PRG and random-oracle call is
//! `SHAKE256( u8(|T|) || T || data, L )` with
//! `T = "VOLEitH-rescue/v0.1/" || name`.

#![forbid(unsafe_code)]

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// The tag names of SPEC.md §3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Mu,
    Rnd,
    Iv,
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

const PREFIX: &[u8] = b"VOLEitH-rescue/v0.1/";

impl Tag {
    fn name(self) -> &'static [u8] {
        match self {
            Tag::Mu => b"mu",
            Tag::Rnd => b"rnd",
            Tag::Iv => b"iv",
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

/// An incremental tagged SHAKE256 computation.
pub struct Xof(Shake256);

impl Xof {
    pub fn new(tag: Tag) -> Self {
        let name = tag.name();
        let mut h = Shake256::default();
        h.update(&[(PREFIX.len() + name.len()) as u8]);
        h.update(PREFIX);
        h.update(name);
        Xof(h)
    }

    #[inline]
    pub fn update(mut self, data: &[u8]) -> Self {
        self.0.update(data);
        self
    }

    #[inline]
    pub fn absorb(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Fill `out` with the first `out.len()` output bytes.
    #[inline]
    pub fn finalize_into(self, out: &mut [u8]) {
        let mut reader = self.0.finalize_xof();
        reader.read(out);
    }

    pub fn finalize<const N: usize>(self) -> [u8; N] {
        let mut out = [0u8; N];
        self.finalize_into(&mut out);
        out
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

    #[test]
    fn shake256_known_answer() {
        // FIPS 202 SHAKE256 of the empty string, first 32 bytes.
        let mut h = Shake256::default();
        h.update(b"");
        let mut out = [0u8; 32];
        h.finalize_xof().read(&mut out);
        let expect = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f,
        ];
        assert_eq!(out, expect);
    }
}
