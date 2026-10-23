//! The command-line tools voleith-prove and voleith-verify (feature `cli`):
//! a round trip with the seed of the first proof vector, every rejection
//! path, and that the seed never appears in standard output, standard error
//! or the proof file.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{hex, load_json, str_of, u64_of};

const PROVE: &str = env!("CARGO_BIN_EXE_voleith-prove");
const VERIFY: &str = env!("CARGO_BIN_EXE_voleith-verify");

/// The first proof vector: K, suffix, message, the test seed x and y.
struct Case {
    k: String,
    suffix: String,
    msg_hex: String,
    x_hex: String,
    y_hex: String,
}

fn case() -> Case {
    let d = load_json("statement1-v0.2.json");
    let v = &d["vectors"][0];
    Case {
        k: str_of(v, "K_ascii").into(),
        suffix: u64_of(v, "suffix").to_string(),
        msg_hex: str_of(v, "message").into(),
        x_hex: str_of(v, "witness_x").into(),
        y_hex: str_of(v, "y").into(),
    }
}

fn tmp(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{}-{n}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

struct Out {
    /// The exit code, or -1 if a signal ended the process.
    code: i32,
    /// The signal that ended the process (Unix).
    signal: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(bin: &str, args: &[&str], stdin: &[u8]) -> Out {
    run_env(bin, args, stdin, None, &[])
}

/// Runs `bin`, in directory `cwd` if given, with extra environment `env`.
fn run_env(
    bin: &str,
    args: &[&str],
    stdin: &[u8],
    cwd: Option<&Path>,
    env: &[(&str, &str)],
) -> Out {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn");
    {
        use std::io::Write;
        let mut si = child.stdin.take().unwrap();
        // The tool may exit before reading everything.
        let _ = si.write_all(stdin);
    }
    let o = child.wait_with_output().expect("wait");
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&o.status);
    #[cfg(not(unix))]
    let signal = None;
    Out {
        code: o.status.code().unwrap_or(-1),
        signal,
        stdout: o.stdout,
        stderr: o.stderr,
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8], url: bool) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..=c.len() {
            let mut ch = B64[(n >> (18 - 6 * k) & 63) as usize];
            if url && ch == b'+' {
                ch = b'-';
            } else if url && ch == b'/' {
                ch = b'_';
            }
            out.push(ch as char);
        }
    }
    out
}

/// The forms in which an 8-byte fragment of `secret` could appear: raw
/// bytes; hexadecimal (matched without regard to case); decimal bytes
/// separated by ", ", "," or " " (as in a Rust or Python list); the
/// fragment as a little- and big-endian u64 in decimal; and base64 in the
/// standard and URL alphabets, at each of the three alignments a fragment
/// can have inside a longer encoded string (8 characters, i.e. 6 aligned
/// bytes, of every 8-byte fragment).
fn secret_forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = Vec::new();
    for w in secret.windows(8) {
        v.push(w.to_vec());
        let h: String = w.iter().map(|b| format!("{b:02x}")).collect();
        v.push(h.into_bytes());
        for sep in [", ", ",", " "] {
            let d: Vec<String> = w.iter().map(|b| b.to_string()).collect();
            v.push(d.join(sep).into_bytes());
        }
        let a: [u8; 8] = w.try_into().unwrap();
        v.push(u64::from_le_bytes(a).to_string().into_bytes());
        v.push(u64::from_be_bytes(a).to_string().into_bytes());
    }
    for shift in 0..3 {
        let tail = &secret[shift..];
        let full = tail.len() / 3 * 4;
        for url in [false, true] {
            let e = base64(tail, url);
            let e = &e.as_bytes()[..full];
            for k in (0..).map(|k| 4 * k).take_while(|&k| k + 8 <= full) {
                v.push(e[k..k + 8].to_vec());
            }
        }
    }
    v
}

/// The first form of a secret found in `data`, if any. Hexadecimal is
/// matched without regard to case.
fn find_secret(forms: &[Vec<u8>], data: &[u8]) -> Option<String> {
    let lower = data.to_ascii_lowercase();
    for f in forms {
        for hay in [data, &lower[..]] {
            if hay.windows(f.len()).any(|w| w == &f[..]) {
                return Some(String::from_utf8_lossy(f).into_owned());
            }
        }
    }
    None
}

/// No form of any secret in any of the outputs.
fn assert_clean(secrets: &[&[u8]], outputs: &[(&str, &[u8])]) {
    let forms: Vec<Vec<u8>> = secrets.iter().flat_map(|s| secret_forms(s)).collect();
    for (name, o) in outputs {
        if let Some(f) = find_secret(&forms, o) {
            panic!("{name} contains a secret fragment ({f:?})");
        }
    }
}

/// Neither output contains the seed in any form of `secret_forms`.
fn assert_no_seed(x_hex: &str, outputs: &[&[u8]]) {
    let named: Vec<(&str, &[u8])> = outputs.iter().map(|o| ("output", *o)).collect();
    assert_clean(&[&hex(x_hex)], &named);
}

/// Every file under `dir`, recursively, with its contents.
fn all_files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(all_files(&p));
        } else {
            out.push((p.clone(), std::fs::read(&p).unwrap()));
        }
    }
    out
}

/// A fresh, empty directory, with a `tmp` subdirectory for TMPDIR.
fn fresh_dir(name: &str) -> PathBuf {
    let d = tmp(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("tmp")).unwrap();
    d
}

fn prove_args<'a>(c: &'a Case, out: &'a str) -> Vec<&'a str> {
    vec![
        "--k",
        &c.k,
        "--suffix",
        &c.suffix,
        "--msg-hex",
        &c.msg_hex,
        "--out",
        out,
    ]
}

fn verify_args<'a>(c: &'a Case, y: &'a str, msg: &'a str, proof: &'a str) -> Vec<&'a str> {
    vec![
        "--k",
        &c.k,
        "--suffix",
        &c.suffix,
        "--y-hex",
        y,
        "--msg-hex",
        msg,
        "--proof",
        proof,
    ]
}

#[test]
fn round_trip() {
    let c = case();
    let len = voleith::proof_length(voleith::STATEMENT1_ID).unwrap();
    // Every accepted form of standard input.
    let forms = [
        format!("{}\n", c.x_hex),
        c.x_hex.clone(),
        format!("{}\r\n", c.x_hex),
        format!("{}\n", c.x_hex.to_ascii_uppercase()),
    ];
    for (i, input) in forms.iter().enumerate() {
        let out = tmp("proof.bin");
        let outs = out.to_str().unwrap();
        let p = run(PROVE, &prove_args(&c, outs), input.as_bytes());
        assert_eq!(
            p.code,
            0,
            "form {i}: {}",
            String::from_utf8_lossy(&p.stderr)
        );
        assert_eq!(p.stdout, format!("y={}\n", c.y_hex).as_bytes(), "form {i}");
        assert!(p.stderr.is_empty(), "form {i}");
        let proof = std::fs::read(&out).unwrap();
        assert_eq!(proof.len(), len);
        assert_no_seed(&c.x_hex, &[&p.stdout, &p.stderr, &proof]);

        let v = run(VERIFY, &verify_args(&c, &c.y_hex, &c.msg_hex, outs), b"");
        assert_eq!(
            (v.code, v.stdout.as_slice()),
            (0, &b"valid\n"[..]),
            "form {i}"
        );
        assert!(v.stderr.is_empty());

        if i == 0 {
            // Upper-case public hexadecimal is accepted too.
            let (yu, mu) = (c.y_hex.to_ascii_uppercase(), c.msg_hex.to_ascii_uppercase());
            let v = run(VERIFY, &verify_args(&c, &yu, &mu, outs), b"");
            assert_eq!(v.code, 0);
            // Another y, message or suffix, or one changed proof byte.
            let mut y2 = hex(&c.y_hex);
            y2[31] ^= 1;
            let y2 = common::to_hex(&y2);
            let v = run(VERIFY, &verify_args(&c, &y2, &c.msg_hex, outs), b"");
            assert_eq!((v.code, v.stdout.as_slice()), (1, &b"invalid\n"[..]));
            let v = run(VERIFY, &verify_args(&c, &c.y_hex, "00", outs), b"");
            assert_eq!(v.code, 1);
            let mut a = verify_args(&c, &c.y_hex, &c.msg_hex, outs);
            a[3] = "1";
            assert_eq!(run(VERIFY, &a, b"").code, 1);
            let bad = tmp("tampered.bin");
            let mut t = proof.clone();
            t[len / 2] ^= 0x10;
            std::fs::write(&bad, &t).unwrap();
            let bads = bad.to_str().unwrap();
            let v = run(VERIFY, &verify_args(&c, &c.y_hex, &c.msg_hex, bads), b"");
            assert_eq!((v.code, v.stdout.as_slice()), (1, &b"invalid\n"[..]));
            // A short or a long file is an invalid proof, not a usage error.
            std::fs::write(&bad, &proof[..len - 1]).unwrap();
            assert_eq!(
                run(VERIFY, &verify_args(&c, &c.y_hex, &c.msg_hex, bads), b"").code,
                1
            );
            let mut long = proof.clone();
            long.push(0);
            std::fs::write(&bad, &long).unwrap();
            assert_eq!(
                run(VERIFY, &verify_args(&c, &c.y_hex, &c.msg_hex, bads), b"").code,
                1
            );
            // The proof is not overwritten.
            let p = run(PROVE, &prove_args(&c, outs), forms[0].as_bytes());
            assert_eq!(p.code, 1);
            assert!(p.stdout.is_empty());
            assert_eq!(std::fs::read(&out).unwrap(), proof);
            assert_no_seed(&c.x_hex, &[&p.stdout, &p.stderr]);
        }
    }
}

#[test]
fn prove_rejects_bad_standard_input() {
    let c = case();
    let x = &c.x_hex;
    let bad_inputs: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"\n".to_vec(),
        format!("{}\n", &x[..63]).into_bytes(),
        x.as_bytes()[..63].to_vec(),
        format!("{}0\n", x).into_bytes(),
        format!("{}00", x).into_bytes(),
        format!("{}g\n", &x[..63]).into_bytes(),
        format!("g{}\n", &x[1..]).into_bytes(),
        format!("{} \n", &x[..63]).into_bytes(),
        format!(" {}\n", x).into_bytes(),
        format!("{} \n", x).into_bytes(),
        format!("{}\n\n", x).into_bytes(),
        format!("{}\nabc\n", x).into_bytes(),
        format!("{}\n{}\n", x, x).into_bytes(),
        format!("{}\r", x).into_bytes(),
        format!("{}\n\r", x).into_bytes(),
        format!("0x{}\n", &x[..62]).into_bytes(),
        format!("{}\0", x).into_bytes(),
        vec![b'a'; 4096],
    ];
    for (i, input) in bad_inputs.iter().enumerate() {
        let out = tmp("never.bin");
        let p = run(PROVE, &prove_args(&c, out.to_str().unwrap()), input);
        assert_eq!(p.code, 2, "input {i}");
        assert!(p.stdout.is_empty(), "input {i}");
        assert!(!out.exists(), "input {i}: a proof file was written");
        assert_no_seed(x, &[&p.stdout, &p.stderr]);
        // The input is never echoed.
        let err = String::from_utf8_lossy(&p.stderr);
        assert!(
            !err.contains(&x[..16]) && !err.contains("aaaaaaaa"),
            "input {i}"
        );
    }
}

#[test]
fn prove_rejects_bad_arguments() {
    let c = case();
    let out = tmp("never.bin");
    let outs = out.to_str().unwrap().to_string();
    let long_msg = "0".repeat(2 * 65_535 + 1);
    let stdin = format!("{}\n", c.x_hex);
    let base = prove_args(&c, &outs);
    let with = |i: usize, v| {
        let mut a = base.clone();
        a[i] = v;
        a
    };
    let cases: Vec<Vec<&str>> = vec![
        with(1, ""), // K empty
        with(
            1,
            "a234567890123456789012345678901234567890123456789012345678901234x",
        ), // 65
        with(1, "tab\there"),
        with(1, "del\x7f"),
        with(1, "caf\u{e9}"),
        with(1, "new\nline"),
        with(3, "256"),
        with(3, "-1"),
        with(3, "01"),
        with(3, ""),
        with(3, "x"),
        with(3, "4294967296"),
        with(3, "18446744073709551616"),
        with(5, "0"),
        with(5, "0g"),
        with(5, &long_msg),
        with(7, ""),
        base[..6].to_vec(),
        [&base[..], &["--out", "x"]].concat(),
        [&base[..], &["--extra"]].concat(),
        [&base[..], &["--seed", "00"]].concat(),
        [&base[..], &["--require-mlock", "--require-mlock"]].concat(),
        [&base[..], &["--require-mlock", "1"]].concat(),
        with(0, "-k"),
        with(0, "--K"),
        vec![],
    ];
    for (i, a) in cases.iter().enumerate() {
        let p = run(PROVE, a, stdin.as_bytes());
        assert_eq!(p.code, 2, "case {i}: {a:?}");
        assert!(p.stdout.is_empty(), "case {i}");
        assert!(!out.exists(), "case {i}");
        assert_no_seed(&c.x_hex, &[&p.stdout, &p.stderr]);
    }
    // A 64-byte K and a 65,535-byte message are within the limits: the tool
    // computes y for this K and the proof verifies.
    let k64 = "~".repeat(64);
    let max_msg = "ab".repeat(65_535);
    let mut a = base.clone();
    a[1] = &k64;
    a[5] = &max_msg;
    let p = run(PROVE, &a, stdin.as_bytes());
    assert_eq!(p.code, 0, "{}", String::from_utf8_lossy(&p.stderr));
    assert_no_seed(&c.x_hex, &[&p.stdout, &p.stderr]);
    let y = String::from_utf8(p.stdout).unwrap();
    let y = y.trim_end().strip_prefix("y=").unwrap().to_string();
    let v = run(
        VERIFY,
        &[
            "--k",
            &k64,
            "--suffix",
            &c.suffix,
            "--y-hex",
            &y,
            "--msg-hex",
            &max_msg,
            "--proof",
            &outs,
        ],
        b"",
    );
    assert_eq!(v.code, 0);
}

#[test]
fn verify_rejects_bad_arguments() {
    let c = case();
    let proof = tmp("dummy.bin");
    std::fs::write(&proof, [0u8; 16]).unwrap();
    let ps = proof.to_str().unwrap().to_string();
    let missing = tmp("missing.bin");
    let ms = missing.to_str().unwrap().to_string();
    let long_msg = "0".repeat(2 * 65_535 + 1);
    let base = verify_args(&c, &c.y_hex, &c.msg_hex, &ps);
    let with = |i: usize, v| {
        let mut a = base.clone();
        a[i] = v;
        a
    };
    let y63 = &c.y_hex[..63];
    let y65 = format!("{}0", c.y_hex);
    let yg = format!("{}g", &c.y_hex[..63]);
    let mut cases: Vec<Vec<&str>> = vec![
        with(1, ""),
        with(
            1,
            "a234567890123456789012345678901234567890123456789012345678901234x",
        ),
        with(1, "tab\there"),
        with(3, "256"),
        with(3, "-1"),
        with(3, "4294967296"),
        with(5, ""),
        with(7, "0"),
        with(7, "zz"),
        with(7, &long_msg),
        base[..8].to_vec(),
        [&base[..], &["--proof", "x"]].concat(),
        [&base[..], &["--extra"]].concat(),
        vec![],
    ];
    for y in [y63, y65.as_str(), yg.as_str()] {
        let mut a = base.clone();
        a[5] = y;
        cases.push(a);
    }
    let mut a = base.clone();
    a[9] = &ms;
    cases.push(a);
    for (i, a) in cases.iter().enumerate() {
        let v = run(VERIFY, a, b"");
        assert_eq!(v.code, 2, "case {i}: {:?}", &a[..a.len().min(8)]);
        assert!(v.stdout.is_empty(), "case {i}");
        assert!(!v.stderr.is_empty(), "case {i}");
    }
    // Well-formed arguments and a 16-byte file: invalid, not a usage error.
    let v = run(VERIFY, &base, b"");
    assert_eq!((v.code, v.stdout.as_slice()), (1, &b"invalid\n"[..]));
}

/// The scanner finds each form of a fragment, written independently of
/// `secret_forms`, inside other data; and it does not flag unrelated data.
#[test]
fn scanner_finds_every_form() {
    let secret = hex(&case().x_hex);
    let forms = secret_forms(&secret);
    let pad = |mid: &[u8]| -> Vec<u8> {
        let mut v = b"noise \x00\x01 ".to_vec();
        v.extend_from_slice(mid);
        v.extend_from_slice(b" \xffmore");
        v
    };
    let hex_upper: String = secret[3..14].iter().map(|b| format!("{b:02X}")).collect();
    let mut positives: Vec<(String, Vec<u8>)> = vec![
        ("raw".into(), pad(&secret[10..18])),
        ("hex upper".into(), pad(hex_upper.as_bytes())),
        (
            "debug list".into(),
            pad(format!("{:?}", &secret[20..30]).as_bytes()),
        ),
        (
            "python list".into(),
            pad(format!("{:?}", secret[1..12].to_vec())
                .replace(", ", ",")
                .as_bytes()),
        ),
        (
            "u64 le".into(),
            pad(u64::from_le_bytes(secret[5..13].try_into().unwrap())
                .to_string()
                .as_bytes()),
        ),
    ];
    // base64 of a longer string with the secret at each alignment.
    for prefix in 0..3 {
        for url in [false, true] {
            let mut data = vec![0x5au8; prefix];
            data.extend_from_slice(&secret);
            data.extend_from_slice(b"tail");
            positives.push((
                format!("base64 prefix {prefix} url {url}"),
                pad(base64(&data, url).as_bytes()),
            ));
        }
    }
    // 8 bytes at an odd offset, in base64.
    positives.push((
        "base64 fragment".into(),
        pad(base64(&secret[7..15], false).as_bytes()),
    ));
    for (name, data) in &positives {
        assert!(find_secret(&forms, data).is_some(), "{name} not found");
    }
    let other = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let negatives = [
        other.clone(),
        base64(&other, false).into_bytes(),
        format!("{other:?}").into_bytes(),
        secret[..7].to_vec(),
    ];
    for data in &negatives {
        assert!(find_secret(&forms, data).is_none());
    }
}

/// Faults injected into voleith-prove (feature `fault-injection`): a
/// failing random source, failing writes, sync, naming and removal, and a
/// panic inside prove. In each case the exit code is right, no proof file
/// appears under the final name, and no form of the seed or rho appears in
/// standard output, standard error or any file in the working directory
/// (where the output and temporary files go, with TMPDIR pointing into it).
#[cfg(feature = "fault-injection")]
#[test]
fn faults_leak_nothing() {
    let c = case();
    let rho_hex = "a1c0d00d362bfb8d8bee5be89c3a50fe46893f2eb486fa70475e61c7dcf7a8e5";
    let (x, rho) = (hex(&c.x_hex), hex(rho_hex));
    let stdin = format!("{}\n", c.x_hex);
    // VOLEITH_TEST_EXPECT_ABORT=1: the binaries were built with the `cli`
    // profile, so a panic must abort.
    let expect_abort = std::env::var_os("VOLEITH_TEST_EXPECT_ABORT").is_some();
    let scenarios: &[(&str, i32)] = &[
        ("", 0),
        ("rng", 1),
        ("write", 1),
        ("write,remove", 1),
        ("sync", 1),
        ("publish", 1),
        ("publish,remove", 1),
        ("panic", 101),
    ];
    for (i, (fault, want)) in scenarios.iter().enumerate() {
        let dir = fresh_dir(&format!("fault-{i}"));
        let tmpdir = dir.join("tmp");
        let tmps = tmpdir.to_str().unwrap();
        let spec = format!("{fault},rho={rho_hex}");
        let env = [
            ("VOLEITH_FAULT", spec.as_str()),
            ("TMPDIR", tmps),
            ("TMP", tmps),
            ("TEMP", tmps),
            ("RUST_BACKTRACE", "full"),
        ];
        let mut args = prove_args(&c, "proof.bin");
        args[7] = "proof.bin";
        let o = run_env(PROVE, &args, stdin.as_bytes(), Some(&dir), &env);
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        if *fault == "panic" {
            #[cfg(unix)]
            let aborted = o.signal == Some(6);
            #[cfg(not(unix))]
            let aborted = false;
            assert!(
                aborted || o.code == 101,
                "panic: {:?} {:?}",
                o.code,
                o.signal
            );
            if expect_abort {
                assert!(aborted, "built with --profile cli, a panic must abort");
            }
            assert!(err.contains("fault injection: panic inside prove"), "{err}");
        } else {
            assert_eq!(o.code, *want, "{fault}: {err}");
        }
        let files = all_files(&dir);
        let names: Vec<String> = files
            .iter()
            .map(|(p, _)| p.strip_prefix(&dir).unwrap().display().to_string())
            .collect();
        match *fault {
            "" => {
                assert_eq!(names, ["proof.bin"], "{fault}");
                assert_eq!(o.stdout, format!("y={}\n", c.y_hex).as_bytes());
            }
            "write,remove" | "publish,remove" => {
                // The temporary file stays, the error names it.
                assert_eq!(names.len(), 1, "{fault}: {names:?}");
                assert!(names[0].starts_with(".proof.bin.") && names[0].ends_with(".tmp"));
                assert!(err.contains("could not be removed"), "{fault}: {err}");
                assert!(err.contains(&names[0]), "{fault}: {err}");
                assert!(o.stdout.is_empty());
            }
            _ => {
                assert!(names.is_empty(), "{fault}: {names:?}");
                assert!(o.stdout.is_empty());
            }
        }
        let mut outputs: Vec<(&str, &[u8])> = vec![("stdout", &o.stdout), ("stderr", &o.stderr)];
        for (p, data) in &files {
            outputs.push((p.to_str().unwrap(), data));
        }
        assert_clean(&[&x, &rho], &outputs);
    }
}

/// `--require-mlock` (Linux): locks memory before reading and proves, or,
/// where the memory limit is too low for an unprivileged user, fails with
/// exit 1 before reading anything. Elsewhere it is a usage error.
#[test]
fn require_mlock() {
    let c = case();
    let out = tmp("mlock.bin");
    let mut args = prove_args(&c, out.to_str().unwrap());
    args.push("--require-mlock");
    let p = run(PROVE, &args, format!("{}\n", c.x_hex).as_bytes());
    let err = String::from_utf8_lossy(&p.stderr).into_owned();
    if cfg!(target_os = "linux") {
        if p.code == 0 {
            assert_eq!(p.stdout, format!("y={}\n", c.y_hex).as_bytes());
            assert!(out.exists());
        } else {
            assert_eq!(p.code, 1, "{err}");
            assert!(err.contains("nothing read"), "{err}");
            assert!(!out.exists());
        }
    } else {
        assert_eq!(p.code, 2, "{err}");
    }
    assert_no_seed(&c.x_hex, &[&p.stdout, &p.stderr]);
}
