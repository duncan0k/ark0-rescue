//! Argument and input parsing shared by voleith-prove and voleith-verify.
//!
//! The rules are those of python/tools/verify_cli.py and
//! go/cmd/voleith-verify, so that all three accept and reject the same
//! command lines:
//!
//! - every option is `--name value` (two arguments), given exactly once;
//!   an unknown, missing or repeated option is a usage error;
//! - `--k`: 1 to 64 bytes, each in 0x20..0x7E (SPEC.md §7.5);
//! - `--suffix`: a decimal integer 0..255 without sign or leading zeros;
//! - `--y-hex`: exactly 64 hexadecimal digits;
//! - `--msg-hex`: an even number of hexadecimal digits, at most 131,070
//!   (65,535 bytes); may be empty.
//!
//! Hexadecimal digits may be upper or lower case. Values are checked as the
//! bytes the operating system passed, so a value that is not UTF-8 fails
//! the same check in all three, and a file name need not be UTF-8.

#![allow(dead_code)]

pub mod os;

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;

use zeroize::Zeroizing;

pub const MAX_MESSAGE_LEN: usize = 65_535;

/// The values of `names`, each given exactly once as `--name value`, and
/// the `flags` that are present (each at most once, as `--flag`, mapped to
/// an empty value).
pub fn parse_options(
    args: &[OsString],
    names: &[&'static str],
    flags: &[&'static str],
) -> Result<HashMap<&'static str, OsString>, String> {
    let mut out = HashMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let opt = a.to_str().and_then(|s| s.strip_prefix("--"));
        if let Some(flag) = opt.and_then(|s| flags.iter().find(|n| **n == s)) {
            if out.insert(*flag, OsString::new()).is_some() {
                return Err(format!("--{flag} given twice"));
            }
            continue;
        }
        let Some(name) = opt.and_then(|s| names.iter().find(|n| **n == s)) else {
            return Err("unknown argument".into());
        };
        let Some(v) = it.next() else {
            return Err(format!("--{name} needs a value"));
        };
        if out.insert(*name, v.clone()).is_some() {
            return Err(format!("--{name} given twice"));
        }
    }
    for n in names {
        if !out.contains_key(n) {
            return Err(format!("--{n} missing"));
        }
    }
    Ok(out)
}

/// K: 1 to 64 printable ASCII bytes.
pub fn parse_k(s: &OsStr) -> Result<Vec<u8>, String> {
    let k = s.as_encoded_bytes();
    if k.is_empty() || k.len() > 64 {
        return Err("--k: K must be 1 to 64 bytes long".into());
    }
    if !k.iter().all(|&c| (0x20..=0x7e).contains(&c)) {
        return Err("--k: K must be printable ASCII (0x20..0x7E)".into());
    }
    Ok(k.to_vec())
}

/// suffix: "0" to "255", no sign, no leading zero.
pub fn parse_suffix(s: &OsStr) -> Result<u8, String> {
    let b = s.as_encoded_bytes();
    let err = || "--suffix: must be a decimal integer from 0 to 255".to_string();
    // Length and characters first: at most 3 digits, so the value below
    // cannot overflow.
    if b.is_empty()
        || b.len() > 3
        || !b.iter().all(u8::is_ascii_digit)
        || (b[0] == b'0' && b.len() > 1)
    {
        return Err(err());
    }
    let v = b.iter().fold(0u16, |v, &c| 10 * v + (c - b'0') as u16);
    u8::try_from(v).map_err(|_| err())
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Public hexadecimal: an even number of digits, at most `2 * max_bytes`.
pub fn parse_hex(name: &str, s: &OsStr, max_bytes: usize) -> Result<Vec<u8>, String> {
    let b = s.as_encoded_bytes();
    if b.len() > 2 * max_bytes {
        return Err(format!("--{name}: longer than {max_bytes} bytes"));
    }
    if b.len() % 2 != 0 {
        return Err(format!("--{name}: odd number of hexadecimal digits"));
    }
    b.chunks_exact(2)
        .map(|p| Some(hex_digit(p[0])? << 4 | hex_digit(p[1])?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| format!("--{name}: not hexadecimal"))
}

/// y: exactly 32 bytes in hexadecimal.
pub fn parse_y(s: &OsStr) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err("--y-hex: must be exactly 64 hexadecimal digits".into());
    }
    let v = parse_hex("y-hex", s, 32)?;
    let mut y = [0u8; 32];
    y.copy_from_slice(&v);
    Ok(y)
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The value of a hexadecimal digit and 1, or (0, 0) for any other byte,
/// without a branch or table lookup on `c` (it is a seed digit).
#[inline]
fn hex_digit_ct(c: u8) -> (u8, u8) {
    let d = c.wrapping_sub(b'0');
    let l = (c | 0x20).wrapping_sub(b'a');
    let is_d = core::hint::black_box((d < 10) as u8);
    let is_l = core::hint::black_box((l < 6) as u8);
    let val = (d & 0u8.wrapping_sub(is_d)) | (l.wrapping_add(10) & 0u8.wrapping_sub(is_l));
    (val, is_d | is_l)
}

/// The 32-byte seed from `r` into `x`: exactly 64 hexadecimal digits, then
/// nothing, "\n" or "\r\n", then end of input. Reads at most 67 bytes into
/// a zeroizing buffer and decodes in place into the caller's `x`; on error
/// `x` is all zero. The error never contains the input.
pub fn read_seed(r: &mut impl Read, x: &mut [u8; 32]) -> Result<(), String> {
    const CAP: usize = 67;
    let err = || {
        "standard input must be exactly 64 hexadecimal digits and an optional newline".to_string()
    };
    x.fill(0);
    let mut buf = Zeroizing::new([0u8; CAP]);
    let mut n = 0;
    while n < CAP {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("cannot read standard input".into()),
        }
    }
    let ok_end = match n {
        64 => true,
        65 => buf[64] == b'\n',
        66 => buf[64] == b'\r' && buf[65] == b'\n',
        _ => false,
    };
    if !ok_end {
        return Err(err());
    }
    let mut valid = 1u8;
    for (i, xi) in x.iter_mut().enumerate() {
        let (hi, vh) = hex_digit_ct(buf[2 * i]);
        let (lo, vl) = hex_digit_ct(buf[2 * i + 1]);
        *xi = hi << 4 | lo;
        valid &= vh & vl;
    }
    if valid != 1 {
        x.fill(0);
        return Err(err());
    }
    Ok(())
}

/// Standard input as an unbuffered file, so that no copy of what is read
/// stays in the standard library's stdin buffer.
pub fn raw_stdin() -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        Ok(File::from(std::io::stdin().as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        Ok(File::from(
            std::io::stdin().as_handle().try_clone_to_owned()?,
        ))
    }
}

/// At most `limit` bytes of the file at `path`, or an error if it is longer
/// (the caller then knows the proof cannot be valid).
pub fn read_limited(path: &OsStr, limit: usize) -> std::io::Result<Result<Vec<u8>, ()>> {
    let mut v = Vec::with_capacity(limit + 1);
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut v)?;
    Ok(if v.len() > limit { Err(()) } else { Ok(v) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_never_replaces() {
        let dir = std::env::temp_dir().join(format!("voleith-publish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (tmp, dest) = (dir.join("t"), dir.join("d"));
        std::fs::write(&tmp, b"new").unwrap();
        std::fs::write(&dest, b"old").unwrap();
        let e = os::publish_no_replace(&tmp, &dest).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"new");
        std::fs::remove_file(&dest).unwrap();
        assert!(os::publish_no_replace(&tmp, &dest).unwrap().is_none());
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert!(!tmp.exists());
        os::sync_dir(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hex_digit_ct_matches_hex_digit() {
        for c in 0..=255u8 {
            let (v, ok) = hex_digit_ct(c);
            match hex_digit(c) {
                Some(d) => assert_eq!((v, ok), (d, 1), "{c}"),
                None => assert_eq!((v, ok), (0, 0), "{c}"),
            }
        }
    }

    #[test]
    fn message_limit() {
        let h = |s: &str| parse_hex("msg-hex", OsStr::new(s), MAX_MESSAGE_LEN);
        assert!(h(&"00".repeat(65_535)).is_ok());
        assert!(h(&"00".repeat(65_536)).is_err());
        assert_eq!(h(""), Ok(vec![]));
    }

    #[test]
    fn suffix_forms() {
        for (s, v) in [("0", Some(0)), ("7", Some(7)), ("255", Some(255))] {
            assert_eq!(parse_suffix(OsStr::new(s)).ok(), v);
        }
        for s in [
            "",
            "256",
            "999",
            "-1",
            "+1",
            "01",
            "1 ",
            " 1",
            "1e2",
            "0x1",
            "1000",
            "4294967296",
            "18446744073709551616",
            "000",
        ] {
            assert!(parse_suffix(OsStr::new(s)).is_err(), "{s:?}");
        }
    }
}
