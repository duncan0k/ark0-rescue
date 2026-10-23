//! voleith-prove: prove statement 0x01 with a real seed (SPEC.md §9).
//!
//! ```text
//! voleith-prove --k <ascii K> --suffix <0..255> --msg-hex <hex> --out <proof file> < seed.txt
//! ```
//!
//! Reads the seed x from standard input (64 hexadecimal digits and an
//! optional newline, nothing else), computes y = HMAC-SHA256(K, x || suffix),
//! draws rho from the operating system, proves with the constant-time
//! prover, verifies the proof, writes it to a new file and prints one line,
//! `y=<64 hex>`. The seed and rho are never printed, logged or written, and
//! are cleared before exit on every path.
//!
//! Exit codes: 0 success; 1 failure (the output file exists or cannot be
//! written, no OS randomness, the prover refused, the self-check failed);
//! 2 usage error (arguments or standard input malformed).

#![forbid(unsafe_code)]

mod common;

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use common::{parse_hex, parse_k, parse_options, parse_suffix, read_seed, to_hex};
use voleith::params::RHO_BYTES;
use voleith::{prove, s1_encode_public, verify, STATEMENT1_ID};
use zeroize::Zeroizing;

const USAGE: &str = "usage: voleith-prove --k <ascii K> --suffix <0..255> --msg-hex <hex> \
--out <proof file> < seed\n  standard input: the 32-byte seed as 64 hexadecimal digits \
and an optional newline";

enum Fail {
    Usage(String),
    Other(String),
}

/// Everything secret lives in this function's locals (in `Zeroizing`), so
/// it is cleared when `run` returns, whichever path it takes; `main` exits
/// only after that.
fn run() -> Result<String, Fail> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let opts = parse_options(&args, &["k", "suffix", "msg-hex", "out"]).map_err(Fail::Usage)?;
    let key = parse_k(&opts["k"]).map_err(Fail::Usage)?;
    let suffix = parse_suffix(&opts["suffix"]).map_err(Fail::Usage)?;
    let msg =
        parse_hex("msg-hex", &opts["msg-hex"], common::MAX_MESSAGE_LEN).map_err(Fail::Usage)?;
    let out = &opts["out"];
    if out.is_empty() {
        return Err(Fail::Usage("--out: empty path".into()));
    }
    if Path::new(out).exists() {
        return Err(Fail::Other(
            "the output file already exists; not overwritten".into(),
        ));
    }

    let mut stdin =
        common::raw_stdin().map_err(|_| Fail::Other("cannot open standard input".into()))?;
    let x = read_seed(&mut stdin).map_err(Fail::Usage)?;

    // y = HMAC-SHA256(K, x || suffix); the copy of x is cleared on drop.
    let mut m = Zeroizing::new([0u8; 33]);
    m[..32].copy_from_slice(&x[..]);
    m[32] = suffix;
    let y = voleith::hash::hmac_sha256(&key, &m[..]);
    drop(m);
    let public_inputs = s1_encode_public(&key, suffix, &y)
        .ok_or_else(|| Fail::Usage("--k: not a valid K".into()))?;

    let mut rho = Zeroizing::new([0u8; RHO_BYTES]);
    getrandom::fill(&mut rho[..])
        .map_err(|_| Fail::Other("no randomness from the operating system".into()))?;

    let proof = prove(STATEMENT1_ID, &public_inputs, &x[..], &msg, &rho)
        .map_err(|e| Fail::Other(format!("the prover refused: {e:?}")))?;
    drop(rho);
    drop(x);
    if !verify(STATEMENT1_ID, &public_inputs, &msg, &proof) {
        return Err(Fail::Other(
            "the proof does not verify; nothing written".into(),
        ));
    }

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| Fail::Other(format!("cannot create the output file: {e}")))?;
    if let Err(e) = f.write_all(&proof).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(out);
        return Err(Fail::Other(format!("cannot write the output file: {e}")));
    }
    Ok(to_hex(&y))
}

fn main() -> ExitCode {
    match run() {
        Ok(y) => {
            println!("y={y}");
            ExitCode::SUCCESS
        }
        Err(Fail::Usage(e)) => {
            eprintln!("voleith-prove: {e}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Fail::Other(e)) => {
            eprintln!("voleith-prove: {e}");
            ExitCode::from(1)
        }
    }
}
