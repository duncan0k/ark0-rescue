//! voleith-prove: prove statement 0x01 with a real seed (SPEC.md §9).
//!
//! ```text
//! <restore command> | voleith-prove --k <ascii K> --suffix <0..255> --msg-hex <hex> --out <proof file> [--require-mlock]
//! ```
//!
//! Turns off crash dumps and crash reporting for its process
//! (`common::os::no_crash_dumps`), and with `--require-mlock` (Linux only)
//! locks all its memory, before it reads anything; a failure of either is
//! an error and nothing is read. Then it reads the seed x from standard
//! input (64 hexadecimal digits and an optional newline, nothing else),
//! computes y = HMAC-SHA256(K, x || suffix), draws rho from the operating
//! system, proves with the constant-time prover, verifies the proof, writes
//! it to a temporary file next to the output, syncs it, gives it the output
//! name without ever replacing a file, and prints one line, `y=<64 hex>`.
//! The seed and rho are never printed, logged or written. README.md says
//! which copies of them are cleared.
//!
//! Exit codes: 0 success; 1 failure (crash dumps cannot be turned off,
//! memory cannot be locked, the output file exists or cannot be written, no
//! OS randomness, the prover refused, the self-check failed); 2 usage error
//! (arguments or standard input malformed). Built with the `cli` profile, a
//! panic ends the process at once.

#![deny(unsafe_code)]

mod common;

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use common::{os, parse_hex, parse_k, parse_options, parse_suffix, read_seed, to_hex};
use voleith::params::RHO_BYTES;
use voleith::{prove, s1_encode_public, verify, STATEMENT1_ID};
use zeroize::Zeroizing;

const USAGE: &str = "usage: voleith-prove --k <ascii K> --suffix <0..255> --msg-hex <hex> \
--out <proof file> [--require-mlock] < seed\n  standard input: the 32-byte seed as 64 \
hexadecimal digits and an optional newline\n  --require-mlock: lock all memory first \
(Linux only)";

enum Fail {
    Usage(String),
    Other(String),
}

/// Faults injected by the tests (feature `fault-injection` only), from the
/// comma-separated words of the environment variable VOLEITH_FAULT: `rng`
/// (the random source fails), `rho=<64 hex>` (a fixed rho), `panic` (a
/// panic inside prove), `write` (writing fails after half of the proof),
/// `sync` (the sync fails), `publish` (naming the file fails), `remove`
/// (removing the temporary file fails).
#[derive(Default)]
struct Faults {
    rng: bool,
    rho: Option<[u8; RHO_BYTES]>,
    #[cfg_attr(not(feature = "fault-injection"), allow(dead_code))]
    panic: bool,
    write: bool,
    sync: bool,
    publish: bool,
    remove: bool,
}

impl Faults {
    #[cfg(feature = "fault-injection")]
    fn from_env() -> Self {
        let mut f = Faults::default();
        let v = std::env::var("VOLEITH_FAULT").unwrap_or_default();
        for w in v.split(',').filter(|w| !w.is_empty()) {
            match w {
                "rng" => f.rng = true,
                "panic" => f.panic = true,
                "write" => f.write = true,
                "sync" => f.sync = true,
                "publish" => f.publish = true,
                "remove" => f.remove = true,
                _ => {
                    let h = w.strip_prefix("rho=").expect("VOLEITH_FAULT word");
                    let b = parse_hex("rho", std::ffi::OsStr::new(h), RHO_BYTES).unwrap();
                    f.rho = Some(b.try_into().expect("32 bytes"));
                }
            }
        }
        f
    }

    #[cfg(not(feature = "fault-injection"))]
    fn from_env() -> Self {
        Faults::default()
    }
}

fn injected(what: &str) -> std::io::Error {
    std::io::Error::other(format!("injected {what} failure"))
}

/// Removes the temporary file after a failure, and says so if it cannot.
fn discard(tmp: &Path, msg: String, faults: &Faults) -> String {
    let r = if faults.remove {
        Err(injected("remove"))
    } else {
        std::fs::remove_file(tmp)
    };
    match r {
        Ok(()) => msg,
        Err(e) => format!(
            "{msg}; the temporary file {} could not be removed ({e}): delete it",
            tmp.display()
        ),
    }
}

/// Writes `proof` to a new temporary file in the directory of `out`, syncs
/// and closes it, then gives it the name `out` without replacing any file.
/// On failure the temporary file is removed (or the error says it could not
/// be). Returns warnings for a published proof.
fn write_new(out: &Path, proof: &[u8], faults: &Faults) -> Result<Vec<String>, String> {
    let dir = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let base = out.file_name().expect("checked in run");
    let mut created: Option<(PathBuf, File)> = None;
    for n in 0..100 {
        let mut name = OsString::from(".");
        name.push(base);
        name.push(format!(".{}.{n}.tmp", std::process::id()));
        let p = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(f) => {
                created = Some((p, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "cannot create a temporary file in {}: {e}",
                    dir.display()
                ))
            }
        }
    }
    let (tmp, mut f) = created.ok_or("cannot create a temporary file: 100 names taken")?;
    let written = if faults.write {
        f.write_all(&proof[..proof.len() / 2])
            .and_then(|()| Err(injected("write")))
    } else {
        f.write_all(proof)
    }
    .and_then(|()| {
        if faults.sync {
            Err(injected("sync"))
        } else {
            f.sync_all()
        }
    });
    drop(f);
    if let Err(e) = written {
        let msg = format!("cannot write the temporary file {}: {e}", tmp.display());
        return Err(discard(&tmp, msg, faults));
    }
    let published = if faults.publish {
        Err(injected("publish"))
    } else {
        os::publish_no_replace(&tmp, out)
    };
    let mut warnings = Vec::new();
    match published {
        Err(e) => {
            let msg = format!(
                "cannot name the proof file {} (it is never overwritten): {e}",
                out.display()
            );
            return Err(discard(&tmp, msg, faults));
        }
        Ok(Some(e)) => warnings.push(format!(
            "the proof is in {}, but the temporary file {} could not be removed ({e}): delete it",
            out.display(),
            tmp.display()
        )),
        Ok(None) => {}
    }
    if let Err(e) = os::sync_dir(&dir) {
        warnings.push(format!(
            "the proof is in {}, but its directory could not be synced: {e}",
            out.display()
        ));
    }
    Ok(warnings)
}

/// Everything secret lives in this function's locals (in `Zeroizing`), so
/// it is cleared when `run` returns, whichever path it takes; `main` exits
/// only after that.
fn run() -> Result<(String, Vec<String>), Fail> {
    let faults = Faults::from_env();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let opts = parse_options(
        &args,
        &["k", "suffix", "msg-hex", "out"],
        &["require-mlock"],
    )
    .map_err(Fail::Usage)?;
    let key = parse_k(&opts["k"]).map_err(Fail::Usage)?;
    let suffix = parse_suffix(&opts["suffix"]).map_err(Fail::Usage)?;
    let msg =
        parse_hex("msg-hex", &opts["msg-hex"], common::MAX_MESSAGE_LEN).map_err(Fail::Usage)?;
    let out = PathBuf::from(&opts["out"]);
    if out.as_os_str().is_empty() || out.file_name().is_none() {
        return Err(Fail::Usage("--out: not a file name".into()));
    }
    let require_mlock = opts.contains_key("require-mlock");
    if require_mlock && !cfg!(target_os = "linux") {
        return Err(Fail::Usage(
            "--require-mlock is supported on Linux only".into(),
        ));
    }
    if out.exists() {
        return Err(Fail::Other(
            "the output file already exists; not overwritten".into(),
        ));
    }

    // Before anything is read: no crash dumps, and locked memory if asked.
    os::no_crash_dumps().map_err(|e| Fail::Other(format!("{e}; nothing read")))?;
    #[cfg(target_os = "linux")]
    if require_mlock {
        os::lock_all_memory().map_err(|e| Fail::Other(format!("{e}; nothing read")))?;
    }

    let mut stdin =
        common::raw_stdin().map_err(|_| Fail::Other("cannot open standard input".into()))?;
    let mut x = Zeroizing::new([0u8; 32]);
    read_seed(&mut stdin, &mut x).map_err(Fail::Usage)?;

    // y = HMAC-SHA256(K, x || suffix); the copy of x is cleared on drop.
    let mut m = Zeroizing::new([0u8; 33]);
    m[..32].copy_from_slice(&x[..]);
    m[32] = suffix;
    let y = voleith::hash::hmac_sha256(&key, &m[..]);
    drop(m);
    let public_inputs = s1_encode_public(&key, suffix, &y)
        .ok_or_else(|| Fail::Usage("--k: not a valid K".into()))?;

    let mut rho = Zeroizing::new([0u8; RHO_BYTES]);
    let drawn = match (faults.rng, faults.rho) {
        (true, _) => Err(()),
        (false, Some(r)) => {
            rho.copy_from_slice(&r);
            Ok(())
        }
        (false, None) => getrandom::fill(&mut rho[..]).map_err(|_| ()),
    };
    drawn.map_err(|()| Fail::Other("no randomness from the operating system".into()))?;

    #[cfg(feature = "fault-injection")]
    voleith::fault::panic_in_prove(faults.panic);
    let proof = prove(STATEMENT1_ID, &public_inputs, &x[..], &msg, &rho)
        .map_err(|e| Fail::Other(format!("the prover refused: {e:?}")))?;
    drop(rho);
    drop(x);
    if !verify(STATEMENT1_ID, &public_inputs, &msg, &proof) {
        return Err(Fail::Other(
            "the proof does not verify; nothing written".into(),
        ));
    }
    let warnings = write_new(&out, &proof, &faults).map_err(Fail::Other)?;
    Ok((to_hex(&y), warnings))
}

/// The value of VOLEITH_ALLOW_FAULT_INJECTION under which a build with the
/// test-only feature `fault-injection` runs at all.
#[cfg(feature = "fault-injection")]
const FAULT_INJECTION_ALLOWED: &str = "tests";

/// A build with `fault-injection` can fix rho, bypass the OS random
/// source and force a panic: it refuses to run, before reading any
/// argument or input, unless the tests allow it explicitly.
#[cfg(feature = "fault-injection")]
fn refuse_fault_injection_build() -> bool {
    if std::env::var("VOLEITH_ALLOW_FAULT_INJECTION").as_deref() == Ok(FAULT_INJECTION_ALLOWED) {
        eprintln!("voleith-prove: warning: test build with fault injection; never use a real seed");
        return false;
    }
    eprintln!(
        "voleith-prove: this build has the test-only feature fault-injection and does not \
         run (set VOLEITH_ALLOW_FAULT_INJECTION={FAULT_INJECTION_ALLOWED} in tests only); \
         nothing read. Build with --features cli."
    );
    true
}

fn main() -> ExitCode {
    #[cfg(feature = "fault-injection")]
    if refuse_fault_injection_build() {
        return ExitCode::from(1);
    }
    match run() {
        Ok((y, warnings)) => {
            println!("y={y}");
            for w in warnings {
                eprintln!("voleith-prove: warning: {w}");
            }
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
