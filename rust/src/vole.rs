//! Leaf expansion, ConvertToVOLE and the column-to-row transposition
//! (SPEC.md §5.1–§5.3).
//!
//! A VOLE column or leaf expansion is a bit string of lhat bits held in
//! `nbytes(lhat)` bytes with zero padding bits.

#![forbid(unsafe_code)]

use crate::bits;
use crate::params::{K, N_LEAVES};
use crate::sym::{Tag, Xof};
use crate::vc::Seed;

/// r_{i,j}: the first lhat bits of SHAKE256[exp](iv || u8(i) || u16le(N + j) || sd).
#[inline]
pub fn expand_leaf(sd: &Seed, iv: &[u8; 16], tree: u8, j: usize, lhat: usize, out: &mut [u8]) {
    Xof::new(Tag::Exp)
        .update(iv)
        .update(&[tree])
        .update(&((N_LEAVES + j) as u16).to_le_bytes())
        .update(sd)
        .finalize_into(out);
    bits::clear_padding(out, lhat);
}

#[inline]
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// v ^= cur, then cur ^= left, in one pass.
#[inline]
fn xor_step(v: &mut [u8], cur: &mut [u8], left: &[u8]) {
    for ((v, c), l) in v.iter_mut().zip(cur.iter_mut()).zip(left.iter()) {
        *v ^= *c;
        *c ^= *l;
    }
}

/// Scratch space for `convert`: K pending left subtrees and the current one.
pub struct ConvertScratch {
    stack: Vec<Vec<u8>>,
    cur: Vec<u8>,
}

impl ConvertScratch {
    pub fn new(len: usize) -> Self {
        ConvertScratch {
            stack: vec![vec![0u8; len]; K],
            cur: vec![0u8; len],
        }
    }
}

/// ConvertToVOLE by FAEST's divide and conquer, streamed over x = 0..N:
/// with `leaf(x, buf)` writing the vector r'_x into `buf`,
/// `cols[b] = XOR of r'_x over x with bit b of x set` (b < K), and, if
/// `total` is given, `total = XOR of all r'_x`. `cols` must be K zeroed
/// slices of the vector length.
pub fn convert(
    scratch: &mut ConvertScratch,
    cols: &mut [&mut [u8]],
    mut total: Option<&mut [u8]>,
    mut leaf: impl FnMut(usize, &mut [u8]),
) {
    debug_assert_eq!(cols.len(), K);
    for x in 0..N_LEAVES {
        leaf(x, &mut scratch.cur);
        // cur is the subtree sum of the level-0 node x. Climb while it is a
        // right child: add it to that level's column and merge it with its
        // pending left sibling.
        let mut level = 0;
        while level < K && (x >> level) & 1 == 1 {
            if level + 1 == K && total.is_none() {
                xor_into(cols[level], &scratch.cur);
            } else {
                xor_step(cols[level], &mut scratch.cur, &scratch.stack[level]);
            }
            level += 1;
        }
        if level < K {
            std::mem::swap(&mut scratch.stack[level], &mut scratch.cur);
        } else if let Some(t) = total.as_deref_mut() {
            t.copy_from_slice(&scratch.cur);
        }
    }
}

/// 8x8 bit-matrix transpose: bit 8i + j of the input is bit 8j + i of the
/// output.
#[inline]
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
}

/// The first `nrows` rows of 128 columns stored back to back (`col_bytes`
/// bytes each): row r is the field element whose bit j is bit r of column j.
pub fn columns_to_rows(cols: &[u8], col_bytes: usize, nrows: usize) -> Vec<u128> {
    debug_assert_eq!(cols.len(), 128 * col_bytes);
    debug_assert!(nrows <= 8 * col_bytes);
    let columns: Vec<&[u8]> = cols.chunks_exact(col_bytes).collect();
    let mut rows = vec![0u128; nrows];
    for (byte, chunk) in rows.chunks_mut(8).enumerate() {
        let mut t = [0u64; 16];
        for (g, tg) in t.iter_mut().enumerate() {
            let mut x = 0u64;
            for c in 0..8 {
                x |= (columns[8 * g + c][byte] as u64) << (8 * c);
            }
            *tg = transpose8(x);
        }
        for (k, row) in chunk.iter_mut().enumerate() {
            let mut v = 0u128;
            for (g, tg) in t.iter().enumerate() {
                v |= (((tg >> (8 * k)) & 0xff) as u128) << (8 * g);
            }
            *row = v;
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transpose8_is_a_transpose() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..100 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let y = transpose8(x);
            for i in 0..8 {
                for j in 0..8 {
                    assert_eq!((x >> (8 * i + j)) & 1, (y >> (8 * j + i)) & 1);
                }
            }
        }
    }

    #[test]
    fn rows_match_naive_transpose() {
        let col_bytes = 13;
        let nrows = 101;
        let cols: Vec<u8> = (0..128 * col_bytes)
            .map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(7) as u8)
            .collect();
        let rows = columns_to_rows(&cols, col_bytes, nrows);
        for (r, row) in rows.iter().enumerate() {
            for j in 0..128 {
                let bit = (cols[j * col_bytes + r / 8] >> (r % 8)) & 1;
                assert_eq!(((row >> j) & 1) as u8, bit, "row {r} column {j}");
            }
        }
    }

    #[test]
    fn convert_matches_definition() {
        let len = 5;
        let leafvec =
            |x: usize| -> Vec<u8> { (0..len).map(|k| (x * 31 + k * 7 + 1) as u8).collect() };
        // Prover form: all leaves.
        let mut scratch = ConvertScratch::new(len);
        let mut cols = vec![vec![0u8; len]; K];
        let mut total = vec![0u8; len];
        {
            let mut refs: Vec<&mut [u8]> = cols.iter_mut().map(|c| c.as_mut_slice()).collect();
            convert(&mut scratch, &mut refs, Some(&mut total), |x, buf| {
                buf.copy_from_slice(&leafvec(x))
            });
        }
        for (b, col) in cols.iter().enumerate() {
            let mut expect = vec![0u8; len];
            for x in 0..N_LEAVES {
                if (x >> b) & 1 == 1 {
                    xor_into(&mut expect, &leafvec(x));
                }
            }
            assert_eq!(col, &expect);
        }
        let mut expect = vec![0u8; len];
        for x in 0..N_LEAVES {
            xor_into(&mut expect, &leafvec(x));
        }
        assert_eq!(total, expect);
        // Verifier form: leaf 0 is unknown (zero), no total.
        let mut scratch = ConvertScratch::new(len);
        let mut cols = vec![vec![0u8; len]; K];
        {
            let mut refs: Vec<&mut [u8]> = cols.iter_mut().map(|c| c.as_mut_slice()).collect();
            convert(&mut scratch, &mut refs, None, |x, buf| {
                if x == 0 {
                    buf.fill(0)
                } else {
                    buf.copy_from_slice(&leafvec(x))
                }
            });
        }
        for (b, col) in cols.iter().enumerate() {
            let mut expect = vec![0u8; len];
            for x in 1..N_LEAVES {
                if (x >> b) & 1 == 1 {
                    xor_into(&mut expect, &leafvec(x));
                }
            }
            assert_eq!(col, &expect);
        }
    }
}
