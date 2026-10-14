//! Helpers shared by the integration tests: JSON vectors, hex and base64.

#![allow(dead_code)]

use serde_json::Value;

pub fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("vectors")
}

pub fn load_json(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("valid JSON")
}

pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn base64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("bad base64 character {c}"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() % 4 == 0, "base64 length");
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks_exact(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c);
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    out
}

pub fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("field {key} is not a string"))
}

pub fn u64_of(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("field {key} is not an integer"))
}

/// Apply the proof edits of the vector files (xor, set, truncate, append,
/// prepend) in order.
pub fn apply_edit(proof: &mut Vec<u8>, edit: &Value) {
    match str_of(edit, "op") {
        "none" => {}
        "xor" => {
            let off = u64_of(edit, "offset") as usize;
            proof[off] ^= hex(str_of(edit, "mask"))[0];
        }
        "set" => {
            let off = u64_of(edit, "offset") as usize;
            let data = hex(str_of(edit, "data"));
            proof[off..off + data.len()].copy_from_slice(&data);
        }
        "truncate" => proof.truncate(u64_of(edit, "length") as usize),
        "append" => proof.extend_from_slice(&hex(str_of(edit, "data"))),
        "prepend" => {
            let mut data = hex(str_of(edit, "data"));
            data.extend_from_slice(proof);
            *proof = data;
        }
        op => panic!("unknown edit {op}"),
    }
}
