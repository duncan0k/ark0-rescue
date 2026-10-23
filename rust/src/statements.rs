//! Statement registry (SPEC.md §7.5).
//!
//! Statement 0x01: public K (1..64 printable ASCII bytes), suffix (1 byte)
//! and y (32 bytes); witness x (32 bytes); relation
//! HMAC-SHA256(K, x || suffix) = y.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use crate::bits::nbytes;
use crate::circuit::{Circuit, GateCounts};
use crate::gadgets;
use crate::params::{TreeSplit, HEADER_BYTES, LAMBDA_BYTES, QS_MASK_BITS, SPLIT, VH_MASK_BITS};
use crate::sha256;
#[cfg(feature = "prover")]
use zeroize::Zeroizing;

pub const STATEMENT1_ID: u8 = 0x01;
#[cfg(feature = "prover")]
pub const S1_WITNESS_LEN: usize = 32;
const S1_MAX_KEY_LEN: usize = 64;
/// Public bits: IV_in (256) | IV_out (256) | T (256) | suffix (8).
const S1_N_PUBLIC: usize = 256 * 3 + 8;
/// Witness bits of the statement 0x01 circuit (SPEC.md §7.5). The proof
/// layout needs only this number, so no format check builds the circuit; a
/// test compares it with the built circuit.
const S1_N_WITNESS: usize = 42_071;

/// Parsed statement 0x01 public inputs.
#[derive(Clone, Copy, Debug)]
pub struct S1Public<'a> {
    pub key: &'a [u8],
    pub suffix: u8,
    pub y: &'a [u8; 32],
}

fn key_ok(key: &[u8]) -> bool {
    (1..=S1_MAX_KEY_LEN).contains(&key.len()) && key.iter().all(|c| (0x20..=0x7e).contains(c))
}

/// Strict parser of `u8(|K|) || K || u8(suffix) || y`.
pub fn s1_parse_public(pub_inputs: &[u8]) -> Option<S1Public<'_>> {
    let (&kl, rest) = pub_inputs.split_first()?;
    let kl = kl as usize;
    if !(1..=S1_MAX_KEY_LEN).contains(&kl) || pub_inputs.len() != kl + 34 {
        return None;
    }
    let key = &rest[..kl];
    if !key_ok(key) {
        return None;
    }
    let suffix = rest[kl];
    let y: &[u8; 32] = rest[kl + 1..].try_into().ok()?;
    Some(S1Public { key, suffix, y })
}

/// The canonical public inputs of statement 0x01, or None if K is not 1..64
/// printable ASCII bytes.
pub fn s1_encode_public(key: &[u8], suffix: u8, y: &[u8; 32]) -> Option<Vec<u8>> {
    if !key_ok(key) {
        return None;
    }
    let mut out = Vec::with_capacity(key.len() + 34);
    out.push(key.len() as u8);
    out.extend_from_slice(key);
    out.push(suffix);
    out.extend_from_slice(y);
    Some(out)
}

fn push_word_bits(out: &mut Vec<u8>, words: &[u32]) {
    for &w in words {
        for i in 0..32 {
            out.push(((w >> i) & 1) as u8);
        }
    }
}

/// The 776 public bits, computed natively.
pub fn s1_public_bits(p: &S1Public<'_>) -> Vec<u8> {
    let (iv_in, iv_out) = sha256::hmac_midstates(p.key);
    let mut target = [0u32; 8];
    for (j, t) in target.iter_mut().enumerate() {
        let yw = u32::from_be_bytes([p.y[4 * j], p.y[4 * j + 1], p.y[4 * j + 2], p.y[4 * j + 3]]);
        *t = yw.wrapping_sub(iv_out[j]);
    }
    let mut out = Vec::with_capacity(S1_N_PUBLIC);
    push_word_bits(&mut out, &iv_in);
    push_word_bits(&mut out, &iv_out);
    push_word_bits(&mut out, &target);
    for i in 0..8 {
        out.push((p.suffix >> i) & 1);
    }
    out
}

/// Witness bit 8n + b is bit b of x[n]. Allocated at its final size, so
/// the only copy is the returned vector (the prover zeroizes it).
#[cfg(feature = "prover")]
pub fn s1_secret_bits(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 * x.len());
    for &byte in x {
        for b in 0..8 {
            out.push((byte >> b) & 1);
        }
    }
    out
}

/// HMAC-SHA256(K, x || suffix). The copy of x is zeroized.
#[cfg(feature = "prover")]
pub fn s1_hmac(key: &[u8], suffix: u8, x: &[u8]) -> [u8; 32] {
    let mut m = Zeroizing::new(Vec::with_capacity(x.len() + 1));
    m.extend_from_slice(x);
    m.push(suffix);
    sha256::hmac_sha256(key, &m)
}

/// Field sizes and offsets of a proof for one statement id and tree split
/// (SPEC.md §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub split: TreeSplit,
    pub ell: usize,
    pub lhat: usize,
    pub c_bytes: usize,
    pub d_bytes: usize,
    pub off_iv_pre: usize,
    pub off_c: usize,
    pub off_u_tilde: usize,
    pub off_d: usize,
    pub off_a_tilde: usize,
    pub off_open: usize,
    pub off_chall3: usize,
    pub total: usize,
}

impl Layout {
    /// The layout for `ell` witness bits under `split`.
    pub const fn new(ell: usize, split: TreeSplit) -> Self {
        let lhat = ell + QS_MASK_BITS + VH_MASK_BITS;
        let c_bytes = nbytes(lhat);
        let d_bytes = nbytes(ell);
        let off_iv_pre = HEADER_BYTES;
        let off_c = off_iv_pre + LAMBDA_BYTES;
        let off_u_tilde = off_c + (split.tau() - 1) * c_bytes;
        let off_d = off_u_tilde + 2 * LAMBDA_BYTES;
        let off_a_tilde = off_d + d_bytes;
        let off_open = off_a_tilde + LAMBDA_BYTES;
        let off_chall3 = off_open + split.openings_bytes();
        Layout {
            split,
            ell,
            lhat,
            c_bytes,
            d_bytes,
            off_iv_pre,
            off_c,
            off_u_tilde,
            off_d,
            off_a_tilde,
            off_open,
            off_chall3,
            total: off_chall3 + LAMBDA_BYTES,
        }
    }

    /// The opening of tree i within a proof of this layout.
    pub fn opening<'p>(&self, proof: &'p [u8], i: usize) -> &'p [u8] {
        let off = self.off_open + self.split.opening_offset(i);
        &proof[off..off + self.split.opening_bytes(i)]
    }
}

/// The proof layout of a registered statement id under `split`, from fixed
/// sizes only: no circuit is built.
pub const fn layout_for(statement_id: u8, split: TreeSplit) -> Option<Layout> {
    match statement_id {
        STATEMENT1_ID => Some(Layout::new(S1_N_WITNESS, split)),
        _ => None,
    }
}

/// The proof layout of a registered statement id under SPLIT (SPEC.md §10).
pub const fn layout(statement_id: u8) -> Option<Layout> {
    layout_for(statement_id, SPLIT)
}

static STATEMENT1: OnceLock<Circuit> = OnceLock::new();

/// The circuit of a registered statement id, built on first use (once per
/// process). Callers run every format check first.
pub fn circuit(statement_id: u8) -> Option<&'static Circuit> {
    match statement_id {
        STATEMENT1_ID => Some(STATEMENT1.get_or_init(gadgets::build_statement1_circuit)),
        _ => None,
    }
}

/// Whether the circuit of a statement id has been built in this process (for
/// the test that malformed inputs never build it).
pub fn circuit_is_built(statement_id: u8) -> bool {
    match statement_id {
        STATEMENT1_ID => STATEMENT1.get().is_some(),
        _ => false,
    }
}

/// Circuit facts of a registered statement, for tests and tools.
#[derive(Clone, Debug)]
pub struct CircuitInfo {
    pub digest: [u8; 32],
    pub n_public: usize,
    pub n_secret_inputs: usize,
    pub n_witness: usize,
    pub n_constraints: usize,
    pub n_and_secret_secret: usize,
    pub n_assert: usize,
    pub gate_counts: GateCounts,
    pub proof_len: usize,
}

pub fn statement_circuit_info(statement_id: u8) -> Option<CircuitInfo> {
    let lay = layout(statement_id)?;
    let c = circuit(statement_id)?;
    Some(CircuitInfo {
        digest: c.digest(),
        n_public: c.n_public,
        n_secret_inputs: c.n_secret,
        n_witness: c.n_witness,
        n_constraints: c.n_constraints,
        n_and_secret_secret: c.n_mul,
        n_assert: c.n_assert,
        gate_counts: c.counts(),
        proof_len: lay.total,
    })
}

/// SHA-256 of the standalone compression circuit's serialization (SPEC.md §7.6).
pub fn compression_circuit_digest() -> [u8; 32] {
    gadgets::build_compression_circuit().digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_is_strict() {
        let y = [7u8; 32];
        let good = s1_encode_public(b"ark0-wallet v1 schnorr", 5, &y).unwrap();
        let p = s1_parse_public(&good).unwrap();
        assert_eq!(p.key, b"ark0-wallet v1 schnorr");
        assert_eq!(p.suffix, 5);
        assert_eq!(p.y, &y);
        assert!(s1_parse_public(&[]).is_none());
        let mut bad = good.clone();
        bad.push(0);
        assert!(s1_parse_public(&bad).is_none());
        assert!(s1_parse_public(&good[..good.len() - 1]).is_none());
        let mut bad = good.clone();
        bad[0] = 0;
        assert!(s1_parse_public(&bad).is_none());
        let mut bad = good.clone();
        bad[3] = 0x7f;
        assert!(s1_parse_public(&bad).is_none());
        assert!(s1_encode_public(&[], 0, &y).is_none());
        assert!(s1_encode_public(&[b'a'; 65], 0, &y).is_none());
        assert!(s1_encode_public(&[b'a'; 64], 0, &y).is_some());
        assert!(s1_encode_public(b"tab\there", 0, &y).is_none());
    }

    #[test]
    fn fixed_layout_matches_the_circuit() {
        let c = gadgets::build_statement1_circuit();
        assert_eq!(c.n_witness, S1_N_WITNESS);
        let lay = layout(STATEMENT1_ID).unwrap();
        assert_eq!(lay, Layout::new(c.n_witness, SPLIT));
        assert_eq!(lay.total, 130_218);
        assert_eq!(layout(0), None);
        assert_eq!(layout(2), None);
    }
}
