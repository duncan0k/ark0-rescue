//! VOLE-in-the-head rescue proofs: Rust implementation of `SPEC.md` v0.2.
//!
//! The verifier follows SPEC.md §11: every length and format check happens
//! before any parsing of proof contents or hashing, and any failure is a
//! rejection. The prover reproduces the Python reference byte for byte for
//! the same randomness. Its field arithmetic on secret data is constant time
//! and it zeroizes its secrets when they go out of scope; see
//! `rust/CT-AUDIT.md` for what was checked and what remains.
//!
//! Unsafe code is forbidden in every module except [`ffi`], the C ABI shim,
//! and `clmul`, the PCLMULQDQ multiplication.

#![deny(unsafe_code)]

pub mod ffi;
pub mod params;

mod bits;
mod circuit;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod clmul;
#[cfg(test)]
mod dudect;
mod gadgets;
mod gf128;
mod proof;
mod sha256;
mod statements;
mod sym;
mod unihash;
mod vc;
mod vole;

pub use proof::{
    proof_length, prove, verify, verify_traced, ProveError, ProverTrace, VerifierTrace,
};

/// The prover with its intermediate values, secrets included: for the vector
/// tests only (feature `test-trace`).
#[cfg(feature = "test-trace")]
#[doc(hidden)]
pub use proof::prove_traced;
pub use statements::{s1_encode_public, STATEMENT1_ID};

/// Other tree splits, for the benchmark only (feature `bench-splits`).
#[cfg(feature = "bench-splits")]
pub use proof::bench;

/// Facts about a statement's circuit, for tests and tools.
pub mod circuit_info {
    pub use crate::circuit::GateCounts;
    pub use crate::statements::{
        circuit_is_built, compression_circuit_digest, statement_circuit_info, CircuitInfo,
    };
}

/// SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104), as used for the public
/// HMAC midstates of statement 0x01.
pub mod hash {
    pub use crate::sha256::{hmac_sha256, sha256};
}
