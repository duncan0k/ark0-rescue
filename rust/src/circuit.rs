//! Generic constraint layer: a straight-line Boolean program (SPEC.md §7.1–§7.3).
//!
//! Wires 0 and 1 are the constants; then come the public input bits, then the
//! secret input bits; every emitted XOR/AND/NOT creates the next wire. An
//! output is SEC if any input is SEC, otherwise PUB. An AND of two SEC wires
//! (MUL) creates a witness bit and the constraint `a*b = out`; ASSERT(a,b,c)
//! adds the constraint `a*b = c`. Constants are folded by fixed local rules,
//! so the instruction list depends only on wire kinds, never on public values.

#![forbid(unsafe_code)]

use crate::gf128::{self, FixedMul};
use crate::sha256;

pub const CONST: u8 = 0;
pub const PUB: u8 = 1;
pub const SEC: u8 = 2;

/// An instruction as built, in call order (serialized by `Circuit::digest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instr {
    Xor(u32, u32),
    /// AND with at most one SEC input (linear in the witness).
    And(u32, u32),
    /// AND of two SEC inputs: a new witness bit and a constraint.
    Mul(u32, u32),
    Not(u32),
    Assert(u32, u32, u32),
}

/// The same instruction with operand kinds resolved, for evaluation with
/// MACs (prover) or keys (verifier). `S` = SEC operand, `P` = PUB or CONST
/// operand; for mixed operations the SEC operand comes first.
#[derive(Clone, Copy, Debug)]
enum Op {
    XorSS(u32, u32),
    XorSP(u32, u32),
    XorPP(u32, u32),
    NotS(u32),
    NotP(u32),
    AndSP(u32, u32),
    AndPP(u32, u32),
    Mul(u32, u32),
    /// Operands and a mask of which are SEC (bit 0: a, bit 1: b, bit 2: c).
    Assert(u32, u32, u32, u8),
}

/// Emits a canonical instruction list (SPEC.md §7.2).
pub struct Builder {
    n_public: usize,
    n_secret: usize,
    kind: Vec<u8>,
    instrs: Vec<Instr>,
    ops: Vec<Op>,
    n_mul: usize,
    n_assert: usize,
    pub outputs: Vec<u32>,
}

impl Builder {
    pub fn new(n_public: usize, n_secret: usize) -> Self {
        let mut kind = vec![CONST, CONST];
        kind.extend(std::iter::repeat_n(PUB, n_public));
        kind.extend(std::iter::repeat_n(SEC, n_secret));
        Builder {
            n_public,
            n_secret,
            kind,
            instrs: Vec::new(),
            ops: Vec::new(),
            n_mul: 0,
            n_assert: 0,
            outputs: Vec::new(),
        }
    }

    pub fn public(&self, i: usize) -> u32 {
        debug_assert!(i < self.n_public);
        (2 + i) as u32
    }

    pub fn secret(&self, i: usize) -> u32 {
        debug_assert!(i < self.n_secret);
        (2 + self.n_public + i) as u32
    }

    pub fn kind(&self, w: u32) -> u8 {
        self.kind[w as usize]
    }

    pub fn is_secret(&self, w: u32) -> bool {
        self.kind(w) == SEC
    }

    fn emit(&mut self, ins: Instr, op: Op, kind: u8) -> u32 {
        self.instrs.push(ins);
        self.ops.push(op);
        self.kind.push(kind);
        (self.kind.len() - 1) as u32
    }

    pub fn xor(&mut self, a: u32, b: u32) -> u32 {
        if a <= 1 && b <= 1 {
            return a ^ b;
        }
        let (a, b) = if a <= 1 { (b, a) } else { (a, b) };
        if b <= 1 {
            return if b == 0 { a } else { self.not(a) };
        }
        let (sa, sb) = (self.is_secret(a), self.is_secret(b));
        let op = match (sa, sb) {
            (true, true) => Op::XorSS(a, b),
            (true, false) => Op::XorSP(a, b),
            (false, true) => Op::XorSP(b, a),
            (false, false) => Op::XorPP(a, b),
        };
        let kind = if sa || sb { SEC } else { PUB };
        self.emit(Instr::Xor(a, b), op, kind)
    }

    pub fn and(&mut self, a: u32, b: u32) -> u32 {
        if a <= 1 && b <= 1 {
            return a & b;
        }
        let (a, b) = if a <= 1 { (b, a) } else { (a, b) };
        if b <= 1 {
            return if b == 1 { a } else { 0 };
        }
        match (self.is_secret(a), self.is_secret(b)) {
            (true, true) => {
                self.n_mul += 1;
                self.emit(Instr::Mul(a, b), Op::Mul(a, b), SEC)
            }
            (true, false) => self.emit(Instr::And(a, b), Op::AndSP(a, b), SEC),
            (false, true) => self.emit(Instr::And(a, b), Op::AndSP(b, a), SEC),
            (false, false) => self.emit(Instr::And(a, b), Op::AndPP(a, b), PUB),
        }
    }

    pub fn not(&mut self, a: u32) -> u32 {
        if a <= 1 {
            return 1 - a;
        }
        if self.is_secret(a) {
            self.emit(Instr::Not(a), Op::NotS(a), SEC)
        } else {
            self.emit(Instr::Not(a), Op::NotP(a), PUB)
        }
    }

    /// The constraint a * b = c over GF(2).
    pub fn assert_mul(&mut self, a: u32, b: u32, c: u32) {
        let mask = (self.is_secret(a) as u8)
            | ((self.is_secret(b) as u8) << 1)
            | ((self.is_secret(c) as u8) << 2);
        self.instrs.push(Instr::Assert(a, b, c));
        self.ops.push(Op::Assert(a, b, c, mask));
        self.n_assert += 1;
    }

    pub fn build(self) -> Circuit {
        Circuit {
            n_public: self.n_public,
            n_secret: self.n_secret,
            n_wires: self.kind.len(),
            n_mul: self.n_mul,
            n_assert: self.n_assert,
            n_witness: self.n_secret + self.n_mul,
            n_constraints: self.n_mul + self.n_assert,
            instrs: self.instrs,
            ops: self.ops,
            outputs: self.outputs,
        }
    }
}

/// Gate counts in the form of the vectors' `gate_counts` (AND includes MUL).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GateCounts {
    pub xor: usize,
    pub and: usize,
    pub not: usize,
    pub assert: usize,
    pub and_secret_secret: usize,
}

pub struct Circuit {
    pub n_public: usize,
    pub n_secret: usize,
    pub n_wires: usize,
    pub n_mul: usize,
    pub n_assert: usize,
    /// Witness bits: secret inputs, then MUL outputs.
    pub n_witness: usize,
    /// Constraints: MULs and ASSERTs in instruction order.
    pub n_constraints: usize,
    pub instrs: Vec<Instr>,
    ops: Vec<Op>,
    pub outputs: Vec<u32>,
}

#[inline]
fn mask(bit: u128) -> u128 {
    0u128.wrapping_sub(bit)
}

impl Circuit {
    pub fn counts(&self) -> GateCounts {
        let mut c = GateCounts::default();
        for ins in &self.instrs {
            match ins {
                Instr::Xor(..) => c.xor += 1,
                Instr::And(..) => c.and += 1,
                Instr::Mul(..) => {
                    c.and += 1;
                    c.and_secret_secret += 1;
                }
                Instr::Not(..) => c.not += 1,
                Instr::Assert(..) => c.assert += 1,
            }
        }
        c
    }

    /// Canonical serialization (SPEC.md §7.6).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + 13 * self.instrs.len() + 4 * self.outputs.len());
        out.extend_from_slice(b"VOLEitH-rescue circuit v0.1\x00");
        out.extend_from_slice(&(self.n_public as u32).to_le_bytes());
        out.extend_from_slice(&(self.n_secret as u32).to_le_bytes());
        out.extend_from_slice(&(self.instrs.len() as u32).to_le_bytes());
        for ins in &self.instrs {
            let (code, operands): (u8, &[u32]) = match ins {
                Instr::Xor(a, b) => (1, &[*a, *b][..]),
                Instr::And(a, b) | Instr::Mul(a, b) => (2, &[*a, *b][..]),
                Instr::Not(a) => (3, &[*a][..]),
                Instr::Assert(a, b, c) => (4, &[*a, *b, *c][..]),
            };
            out.push(code);
            for w in operands {
                out.extend_from_slice(&w.to_le_bytes());
            }
        }
        out.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for w in &self.outputs {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// SHA-256 of the canonical serialization.
    pub fn digest(&self) -> [u8; 32] {
        sha256::sha256(&self.serialize())
    }

    /// Evaluate in the clear. Returns every wire value, the witness bits and
    /// whether every ASSERT holds. The work and the memory accesses depend
    /// only on the instruction list, never on the wire values.
    pub fn evaluate(&self, public_bits: &[u8], secret_bits: &[u8]) -> (Vec<u8>, Vec<u8>, bool) {
        assert_eq!(public_bits.len(), self.n_public, "public input length");
        assert_eq!(secret_bits.len(), self.n_secret, "secret input length");
        let mut vals: Vec<u8> = Vec::with_capacity(self.n_wires);
        vals.extend_from_slice(&[0, 1]);
        vals.extend_from_slice(public_bits);
        vals.extend_from_slice(secret_bits);
        let mut witness: Vec<u8> = Vec::with_capacity(self.n_witness);
        witness.extend_from_slice(secret_bits);
        // OR of (a & b) ^ c over every ASSERT: no branch on wire values.
        let mut bad = 0u8;
        for ins in &self.instrs {
            match *ins {
                Instr::Xor(a, b) => {
                    let v = vals[a as usize] ^ vals[b as usize];
                    vals.push(v);
                }
                Instr::And(a, b) => {
                    let v = vals[a as usize] & vals[b as usize];
                    vals.push(v);
                }
                Instr::Mul(a, b) => {
                    let v = vals[a as usize] & vals[b as usize];
                    vals.push(v);
                    witness.push(v);
                }
                Instr::Not(a) => {
                    let v = vals[a as usize] ^ 1;
                    vals.push(v);
                }
                Instr::Assert(a, b, c) => {
                    bad |= (vals[a as usize] & vals[b as usize]) ^ vals[c as usize];
                }
            }
        }
        (vals, witness, bad == 0)
    }

    /// Prover terms (SPEC.md §6.2) for every constraint in order:
    /// `sink(A0_t, A1_t)` with A0 = v_a v_b and A1 = b_a v_b + b_b v_a + v_c.
    /// `tags[r]` is the VOLE tag v[r] of witness bit r.
    pub fn prover_terms(
        &self,
        public_bits: &[u8],
        witness_bits: &[u8],
        tags: &[u128],
        mut sink: impl FnMut(u128, u128),
    ) {
        assert_eq!(public_bits.len(), self.n_public, "public input length");
        assert_eq!(witness_bits.len(), self.n_witness, "witness length");
        assert!(tags.len() >= self.n_witness, "tag length");
        let mut bits: Vec<u8> = Vec::with_capacity(self.n_wires);
        let mut macs: Vec<u128> = Vec::with_capacity(self.n_wires);
        bits.extend_from_slice(&[0, 1]);
        bits.extend_from_slice(public_bits);
        bits.extend_from_slice(&witness_bits[..self.n_secret]);
        macs.resize(2 + self.n_public, 0);
        macs.extend_from_slice(&tags[..self.n_secret]);
        let mut wi = self.n_secret;
        for op in &self.ops {
            let (bit, mac) = match *op {
                Op::XorSS(a, b) | Op::XorPP(a, b) => (
                    bits[a as usize] ^ bits[b as usize],
                    macs[a as usize] ^ macs[b as usize],
                ),
                Op::XorSP(s, p) => (bits[s as usize] ^ bits[p as usize], macs[s as usize]),
                Op::NotS(a) | Op::NotP(a) => (bits[a as usize] ^ 1, macs[a as usize]),
                Op::AndSP(s, p) => {
                    let bp = bits[p as usize];
                    (bits[s as usize] & bp, macs[s as usize] & mask(bp as u128))
                }
                Op::AndPP(a, b) => (bits[a as usize] & bits[b as usize], 0),
                Op::Mul(a, b) => {
                    let (ba, ma) = (bits[a as usize] as u128, macs[a as usize]);
                    let (bb, mb) = (bits[b as usize] as u128, macs[b as usize]);
                    let (bz, mz) = (witness_bits[wi], tags[wi]);
                    wi += 1;
                    sink(gf128::mul(ma, mb), (mb & mask(ba)) ^ (ma & mask(bb)) ^ mz);
                    (bz, mz)
                }
                Op::Assert(a, b, c, _) => {
                    let (ba, ma) = (bits[a as usize] as u128, macs[a as usize]);
                    let (bb, mb) = (bits[b as usize] as u128, macs[b as usize]);
                    sink(
                        gf128::mul(ma, mb),
                        (mb & mask(ba)) ^ (ma & mask(bb)) ^ macs[c as usize],
                    );
                    continue;
                }
            };
            bits.push(bit);
            macs.push(mac);
        }
    }

    /// Verifier terms (SPEC.md §6.2, §7.3) for every constraint in order:
    /// `sink(B_t)` with B_t = q_a q_b + q_c Delta. `keys[r]` is the key q[r] of
    /// witness bit r after the witness correction; a PUB or CONST wire with bit
    /// p has key p * Delta.
    pub fn verifier_terms(
        &self,
        public_bits: &[u8],
        keys: &[u128],
        delta: u128,
        mul_delta: &FixedMul,
        mut sink: impl FnMut(u128),
    ) {
        debug_assert_eq!(public_bits.len(), self.n_public);
        debug_assert!(keys.len() >= self.n_witness);
        // SEC wires hold keys, PUB/CONST wires hold their bit (0 or 1).
        let mut vals: Vec<u128> = Vec::with_capacity(self.n_wires);
        vals.extend_from_slice(&[0, 1]);
        vals.extend(public_bits.iter().map(|&b| b as u128));
        vals.extend_from_slice(&keys[..self.n_secret]);
        let key_of = |v: u128, sec: bool| if sec { v } else { delta & mask(v) };
        let mut wi = self.n_secret;
        for op in &self.ops {
            let v = match *op {
                Op::XorSS(a, b) | Op::XorPP(a, b) => vals[a as usize] ^ vals[b as usize],
                Op::XorSP(s, p) => vals[s as usize] ^ (delta & mask(vals[p as usize])),
                Op::NotS(a) => vals[a as usize] ^ delta,
                Op::NotP(a) => vals[a as usize] ^ 1,
                Op::AndSP(s, p) => vals[s as usize] & mask(vals[p as usize]),
                Op::AndPP(a, b) => vals[a as usize] & vals[b as usize],
                Op::Mul(a, b) => {
                    let kz = keys[wi];
                    wi += 1;
                    sink(gf128::mul_public(vals[a as usize], vals[b as usize]) ^ mul_delta.mul(kz));
                    kz
                }
                Op::Assert(a, b, c, m) => {
                    let ka = key_of(vals[a as usize], m & 1 != 0);
                    let kb = key_of(vals[b as usize], m & 2 != 0);
                    let kc = key_of(vals[c as usize], m & 4 != 0);
                    sink(gf128::mul_public(ka, kb) ^ mul_delta.mul(kc));
                    continue;
                }
            };
            vals.push(v);
        }
    }
}
