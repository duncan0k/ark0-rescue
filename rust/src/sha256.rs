//! SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), used natively for the
//! public HMAC midstates of statement 0x01, the circuit digest (SPEC.md
//! §7.6) and the prover's relation check.

#![forbid(unsafe_code)]

use zeroize::{Zeroize, Zeroizing};

pub const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 compression of one 64-byte block under chaining value `state`.
pub fn compress(state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for (t, chunk) in block.chunks_exact(4).enumerate() {
        w[t] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let out = [a, b, c, d, e, f, g, h];
    let mut res = [0u32; 8];
    for i in 0..8 {
        res[i] = state[i].wrapping_add(out[i]);
    }
    // The message schedule holds the block (the witness, in the prover).
    w.zeroize();
    res
}

/// Incremental SHA-256. The chaining value and the buffered input are
/// zeroized when it is dropped.
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            state: IV,
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.buf.zeroize();
    }
}

impl Sha256 {
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            self.state = compress(&self.state, &self.buf);
            self.buf_len = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.state = compress(&self.state, &b);
            b.zeroize();
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        pad[pad_len..pad_len + 8].copy_from_slice(&bit_len.to_be_bytes());
        self.update(&pad[..pad_len + 8]);
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::default();
    h.update(data);
    h.finalize()
}

/// The 64-byte block (key || 0...) XOR pad; `key` must be at most 64 bytes.
fn key_block(key: &[u8], pad: u8) -> [u8; 64] {
    let mut kb = [pad; 64];
    for (k, &b) in kb.iter_mut().zip(key.iter()) {
        *k ^= b;
    }
    kb
}

/// (IV_in, IV_out): chaining values after the K^ipad and K^opad blocks.
/// `key` must be at most 64 bytes.
pub fn hmac_midstates(key: &[u8]) -> ([u32; 8], [u32; 8]) {
    debug_assert!(key.len() <= 64);
    (
        compress(&IV, &key_block(key, 0x36)),
        compress(&IV, &key_block(key, 0x5c)),
    )
}

/// HMAC-SHA256 (RFC 2104). Keys longer than one block are hashed first.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let hashed;
    let key = if key.len() > 64 {
        hashed = sha256(key);
        &hashed[..]
    } else {
        key
    };
    let mut inner = Sha256::default();
    inner.update(&key_block(key, 0x36));
    inner.update(msg);
    let ih = Zeroizing::new(inner.finalize());
    let mut outer = Sha256::default();
    outer.update(&key_block(key, 0x5c));
    outer.update(&*ih);
    outer.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Incremental updates across block boundaries.
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let mut h = Sha256::default();
        for chunk in data.chunks(37) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), sha256(&data));
    }

    #[test]
    fn hmac_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_from_midstates() {
        // HMAC(K, m) for a one-block tail, via the midstates.
        let key = b"ark0-wallet v1 schnorr";
        let msg = [0x42u8; 33];
        let (iv_in, iv_out) = hmac_midstates(key);
        let mut block = [0u8; 64];
        block[..33].copy_from_slice(&msg);
        block[33] = 0x80;
        block[56..].copy_from_slice(&((64 + 33) as u64 * 8).to_be_bytes());
        let inner = compress(&iv_in, &block);
        let mut ob = [0u8; 64];
        for (i, w) in inner.iter().enumerate() {
            ob[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        ob[32] = 0x80;
        ob[56..].copy_from_slice(&((64 + 32) as u64 * 8).to_be_bytes());
        let outer = compress(&iv_out, &ob);
        let mut y = [0u8; 32];
        for (i, w) in outer.iter().enumerate() {
            y[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        assert_eq!(y, hmac_sha256(key, &msg));
    }
}
