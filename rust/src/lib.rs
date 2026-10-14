//! VOLE-in-the-head rescue proofs: Rust implementation of `SPEC.md` v0.1.
//!
//! The verifier follows SPEC.md §11: every length and format check happens
//! before any parsing of proof contents or hashing, and any failure is a
//! rejection.
//!
//! Unsafe code is forbidden in every module except [`ffi`], the C ABI shim.

#![deny(unsafe_code)]

pub mod ffi;
pub mod params;

mod bits;
mod circuit;
mod gadgets;
mod gf128;
mod proof;
mod sha256;
mod statements;
mod sym;
mod unihash;
mod vc;
mod vole;

pub use proof::{proof_length, verify, verify_traced, VerifierTrace};
pub use statements::{s1_encode_public, STATEMENT1_ID};

/// Facts about a statement's circuit, for tests and tools.
pub mod circuit_info {
    pub use crate::circuit::GateCounts;
    pub use crate::statements::{compression_circuit_digest, statement_circuit_info, CircuitInfo};
}

/// SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104), as used for the public
/// HMAC midstates of statement 0x01.
pub mod hash {
    pub use crate::sha256::{hmac_sha256, sha256};
}
