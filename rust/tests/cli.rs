//! The command-line tools voleith-prove and voleith-verify (feature `cli`):
//! a round trip with the seed of the first proof vector, every rejection
//! path, and that the seed never appears in standard output, standard error
//! or the proof file.

mod common;

use std::path::PathBuf;
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
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(bin: &str, args: &[&str], stdin: &[u8]) -> Out {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        use std::io::Write;
        let mut si = child.stdin.take().unwrap();
        // The tool may exit before reading everything.
        let _ = si.write_all(stdin);
    }
    let o = child.wait_with_output().expect("wait");
    Out {
        code: o.status.code().expect("exit code"),
        stdout: o.stdout,
        stderr: o.stderr,
    }
}

/// Neither output contains the seed: no 8 consecutive bytes of it raw, and
/// no 16 consecutive digits of its hexadecimal form in either case.
fn assert_no_seed(x_hex: &str, outputs: &[&[u8]]) {
    let x = hex(x_hex);
    let lower = x_hex.to_ascii_lowercase();
    for o in outputs {
        let text = String::from_utf8_lossy(o).to_ascii_lowercase();
        for w in lower.as_bytes().windows(16) {
            let w = std::str::from_utf8(w).unwrap();
            assert!(!text.contains(w), "seed digits {w} in the output");
        }
        for w in x.windows(8) {
            assert!(!o.windows(8).any(|b| b == w), "seed bytes in the output");
        }
    }
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
