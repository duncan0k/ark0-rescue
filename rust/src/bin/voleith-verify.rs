//! voleith-verify: verify a statement 0x01 proof (SPEC.md §11).
//!
//! ```text
//! voleith-verify --k <ascii K> --suffix <0..255> --y-hex <64 hex> --msg-hex <hex> --proof <file>
//! ```
//!
//! Prints `valid` and exits 0 for a valid proof, prints `invalid` and exits 1
//! for an invalid one, and exits 2 with a message on standard error for a
//! usage error: a missing, repeated or unknown option, a value outside its
//! domain (see `common`), or a proof file that cannot be read. A proof file
//! of the wrong length is an invalid proof. python/tools/verify_cli.py and
//! go/cmd/voleith-verify behave the same.

#![deny(unsafe_code)]

mod common;

use std::process::ExitCode;

use common::{parse_hex, parse_k, parse_options, parse_suffix, parse_y, read_limited};
use voleith::{proof_length, s1_encode_public, verify, STATEMENT1_ID};

const USAGE: &str = "usage: voleith-verify --k <ascii K> --suffix <0..255> --y-hex <64 hex> \
--msg-hex <hex> --proof <file>";

fn run() -> Result<bool, String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let opts = parse_options(&args, &["k", "suffix", "y-hex", "msg-hex", "proof"], &[])?;
    let key = parse_k(&opts["k"])?;
    let suffix = parse_suffix(&opts["suffix"])?;
    let y = parse_y(&opts["y-hex"])?;
    let msg = parse_hex("msg-hex", &opts["msg-hex"], common::MAX_MESSAGE_LEN)?;
    let limit = proof_length(STATEMENT1_ID).expect("statement 0x01 is registered");
    let proof = match read_limited(&opts["proof"], limit) {
        Ok(Ok(p)) => p,
        Ok(Err(())) => return Ok(false),
        Err(e) => return Err(format!("--proof: cannot read the file: {e}")),
    };
    let public_inputs = s1_encode_public(&key, suffix, &y).ok_or("--k: not a valid K")?;
    Ok(verify(STATEMENT1_ID, &public_inputs, &msg, &proof))
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            println!("valid");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("invalid");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("voleith-verify: {e}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
