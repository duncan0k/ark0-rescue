//! Protocol constants of version 0.1 (SPEC.md §2). Nothing here is
//! negotiable at run time.

#![forbid(unsafe_code)]

/// Protocol version byte, first byte of every proof and hashed into mu.
pub const VERSION: u8 = 0x01;
/// ASCII label used in every domain-separation tag.
pub const VERSION_LABEL: &str = "v0.1";

/// Security parameter and field size: GF(2^128).
pub const LAMBDA: usize = 128;
pub const LAMBDA_BYTES: usize = LAMBDA / 8;

/// Number of GGM trees (small VOLE instances).
pub const TAU: usize = 16;
/// Tree depth; TAU * K = LAMBDA.
pub const K: usize = 8;
/// Leaves per tree.
pub const N_LEAVES: usize = 1 << K;

/// VOLE rows that mask the QuickSilver response (one field element).
pub const QS_MASK_BITS: usize = LAMBDA;
/// VOLE rows that mask the VOLE consistency hash (two field elements).
pub const VH_MASK_BITS: usize = 2 * LAMBDA;

/// Hedging randomness per proof.
pub const RHO_BYTES: usize = 32;
/// Largest message accepted by prove and verify.
pub const MAX_MESSAGE_LEN: usize = 65_535;
/// Proof header: version byte, statement id byte.
pub const HEADER_BYTES: usize = 2;

/// GGM node seeds and leaf seeds.
pub const SEED_BYTES: usize = LAMBDA_BYTES;
/// Leaf commitments.
pub const COM_BYTES: usize = 2 * LAMBDA_BYTES;
/// One tree opening: K co-path seeds, then the hidden leaf's commitment.
pub const OPENING_BYTES: usize = K * SEED_BYTES + COM_BYTES;

const _: () = assert!(TAU * K == LAMBDA);
const _: () = assert!(OPENING_BYTES == 160);
