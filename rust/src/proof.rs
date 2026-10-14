//! Prover and verifier (SPEC.md §6, §8–§11).

#![forbid(unsafe_code)]

use crate::bits;
use crate::gf128::{self, FixedMul};
use crate::params::{
    K, LAMBDA, LAMBDA_BYTES, MAX_MESSAGE_LEN, N_LEAVES, OPENING_BYTES, RHO_BYTES, TAU, VERSION,
};
use crate::statements::{self, Layout, StatementDef};
use crate::sym::{Tag, Xof};
use crate::unihash::{VoleHash, ZkAcc, ZkHash};
use crate::vc;
use crate::vole::{self, ConvertScratch};

/// Proof length in bytes for a registered statement id.
pub fn proof_length(statement_id: u8) -> Option<usize> {
    statements::lookup(statement_id).map(|d| d.layout.total)
}

/// mu = SHAKE256[mu](u8(version) || u8(sid) || u16le(|pub|) || pub || u64le(|m|) || m, 32).
/// `public_inputs` is at most 255 bytes long here (canonical inputs only).
fn compute_mu(statement_id: u8, public_inputs: &[u8], message: &[u8]) -> [u8; 32] {
    Xof::new(Tag::Mu)
        .update(&[VERSION, statement_id])
        .update(&(public_inputs.len() as u16).to_le_bytes())
        .update(public_inputs)
        .update(&(message.len() as u64).to_le_bytes())
        .update(message)
        .finalize()
}

/// Sum_{i<128} X^i * rows[i] in GF(2^128) (q*, v* of SPEC.md §6.3).
fn mask_element(rows: &[u128]) -> u128 {
    let mut z = 0u128;
    for &r in rows[..LAMBDA].iter().rev() {
        z = gf128::mul_x(z) ^ r;
    }
    z
}

fn arr16(b: &[u8]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    a
}

/// Values the verifier recomputes, for comparison with the vectors'
/// intermediates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierTrace {
    pub mu: [u8; 32],
    pub iv: [u8; 16],
    pub tree_hashes: Vec<[u8; 32]>,
    pub hcom: [u8; 32],
    pub chall1: [u8; 32],
    pub h_v: Vec<u8>,
    pub chall2: Vec<u8>,
    pub b_tilde: [u8; 16],
    pub chall3: [u8; 16],
}

/// True iff `proof` is a valid proof for (statement_id, public_inputs)
/// bound to `message` (SPEC.md §11). Every malformed input yields false.
pub fn verify(statement_id: u8, public_inputs: &[u8], message: &[u8], proof: &[u8]) -> bool {
    verify_impl(statement_id, public_inputs, message, proof, None)
}

/// `verify`, also returning the recomputed values when the input passed the
/// format checks (steps 1–6).
pub fn verify_traced(
    statement_id: u8,
    public_inputs: &[u8],
    message: &[u8],
    proof: &[u8],
) -> (bool, Option<VerifierTrace>) {
    let mut trace = VerifierTrace::default();
    let mut reached = false;
    let ok = verify_impl(
        statement_id,
        public_inputs,
        message,
        proof,
        Some((&mut trace, &mut reached)),
    );
    (ok, if reached { Some(trace) } else { None })
}

fn verify_impl(
    statement_id: u8,
    public_inputs: &[u8],
    message: &[u8],
    proof: &[u8],
    trace: Option<(&mut VerifierTrace, &mut bool)>,
) -> bool {
    // 1. A registered statement id.
    let Some(def) = statements::lookup(statement_id) else {
        return false;
    };
    // 2. Canonical public inputs.
    let Some(parsed) = statements::s1_parse_public(public_inputs) else {
        return false;
    };
    // 3. Message length.
    if message.len() > MAX_MESSAGE_LEN {
        return false;
    }
    // 4. Proof length.
    let lay = &def.layout;
    if proof.len() != lay.total {
        return false;
    }
    // 5. Header.
    if proof[0] != VERSION || proof[1] != statement_id {
        return false;
    }
    // 6. Every padding bit of the corrections and of d is zero.
    for i in 0..TAU - 1 {
        let off = lay.off_c + i * lay.c_bytes;
        if !bits::is_canonical(&proof[off..off + lay.c_bytes], lay.lhat) {
            return false;
        }
    }
    if !bits::is_canonical(&proof[lay.off_d..lay.off_d + lay.d_bytes], lay.ell) {
        return false;
    }
    let public_bits = statements::s1_public_bits(&parsed);
    verify_core(
        def,
        statement_id,
        public_inputs,
        &public_bits,
        message,
        proof,
        trace,
    )
}

/// Steps 7–11 on an input that passed the format checks; the work does not
/// depend on the proof contents.
fn verify_core(
    def: &StatementDef,
    statement_id: u8,
    public_inputs: &[u8],
    public_bits: &[u8],
    message: &[u8],
    proof: &[u8],
    trace: Option<(&mut VerifierTrace, &mut bool)>,
) -> bool {
    let lay: &Layout = &def.layout;
    let (ell, lhat, cb) = (lay.ell, lay.lhat, lay.c_bytes);
    let iv_pre = &proof[lay.off_iv_pre..lay.off_iv_pre + LAMBDA_BYTES];
    let c_all = &proof[lay.off_c..lay.off_c + (TAU - 1) * cb];
    let u_tilde = &proof[lay.off_u_tilde..lay.off_u_tilde + 2 * LAMBDA_BYTES];
    let d_enc = &proof[lay.off_d..lay.off_d + lay.d_bytes];
    let a_tilde = arr16(&proof[lay.off_a_tilde..lay.off_a_tilde + LAMBDA_BYTES]);
    let chall3 = arr16(&proof[lay.off_chall3..lay.off_chall3 + LAMBDA_BYTES]);

    // 7. mu, iv, Delta.
    let mu = compute_mu(statement_id, public_inputs, message);
    let iv: [u8; 16] = Xof::new(Tag::Iv).update(iv_pre).update(&mu).finalize();
    let delta = gf128::from_bytes(&chall3);

    // 8. Trees, leaf expansions, VOLE keys Q (columns), hcom, chall1.
    let mut cols = vec![0u8; LAMBDA * cb];
    let mut tree_hashes = [[0u8; 32]; TAU];
    let mut sds = [[0u8; 16]; N_LEAVES];
    let mut scratch = ConvertScratch::new(cb);
    for i in 0..TAU {
        let jstar = chall3[i] as usize;
        let mut opening = [0u8; OPENING_BYTES];
        let off = lay.off_open + i * OPENING_BYTES;
        opening.copy_from_slice(&proof[off..off + OPENING_BYTES]);
        tree_hashes[i] = vc::reconstruct(&opening, &iv, i as u8, jstar, &mut sds);
        let tree_cols = &mut cols[K * i * cb..K * (i + 1) * cb];
        let mut col_refs: Vec<&mut [u8]> = tree_cols.chunks_exact_mut(cb).collect();
        // q_{i,b} = XOR over j != j* with bit b of (j XOR j*) set: stream
        // x = j XOR j*, where x = 0 is the hidden leaf.
        vole::convert(&mut scratch, &mut col_refs, None, |x, buf| {
            if x == 0 {
                buf.fill(0);
            } else {
                let j = x ^ jstar;
                vole::expand_leaf(&sds[j], &iv, i as u8, j, lhat, buf);
            }
        });
        if i > 0 {
            let c_i = &c_all[(i - 1) * cb..i * cb];
            for (b, col) in col_refs.iter_mut().enumerate() {
                if (jstar >> b) & 1 == 1 {
                    for (q, c) in col.iter_mut().zip(c_i.iter()) {
                        *q ^= *c;
                    }
                }
            }
        }
    }
    let mut hh = Xof::new(Tag::Hcom);
    for h in &tree_hashes {
        hh.absorb(h);
    }
    let hcom: [u8; 32] = hh.finalize();
    let chall1: [u8; 32] = Xof::new(Tag::Ch1)
        .update(&mu)
        .update(&hcom)
        .update(c_all)
        .update(iv_pre)
        .finalize();

    // 9. VOLE consistency: h_V from VH(Q_j) + Delta_j * u_tilde, then chall2.
    let vh = VoleHash::new(&chall1, ell);
    let mut hv = Xof::new(Tag::Hv);
    for (j, col) in cols.chunks_exact(cb).enumerate() {
        let mut h = vh.hash(col);
        if (delta >> j) & 1 == 1 {
            for (a, b) in h.iter_mut().zip(u_tilde.iter()) {
                *a ^= *b;
            }
        }
        hv.absorb(&h);
    }
    let h_v: [u8; 32] = hv.finalize();
    let chall2: [u8; 64] = Xof::new(Tag::Ch2)
        .update(&chall1)
        .update(u_tilde)
        .update(&h_v)
        .update(d_enc)
        .finalize();

    // 10. Witness correction Q_j += Delta_j * d on rows [0, ell), rows, keys,
    // constraint terms, ZKHash.
    for (j, col) in cols.chunks_exact_mut(cb).enumerate() {
        if (delta >> j) & 1 == 1 {
            for (q, d) in col.iter_mut().zip(d_enc.iter()) {
                *q ^= *d;
            }
        }
    }
    let rows = vole::columns_to_rows(&cols, cb, ell + LAMBDA);
    let zk = ZkHash::new(&chall2);
    let mul_delta = FixedMul::new(delta);
    let mut acc = ZkAcc::default();
    def.circuit
        .verifier_terms(public_bits, &rows[..ell], delta, &mul_delta, |b| {
            zk.absorb(&mut acc, b)
        });
    let q_tilde = zk.finish(&acc, mask_element(&rows[ell..]));
    let b_tilde = gf128::to_bytes(q_tilde ^ gf128::mul(gf128::from_bytes(&a_tilde), delta));

    // 11. chall3' and the comparison.
    let check: [u8; 16] = Xof::new(Tag::Ch3)
        .update(&chall2)
        .update(&a_tilde)
        .update(&b_tilde)
        .finalize();
    if let Some((t, reached)) = trace {
        *reached = true;
        *t = VerifierTrace {
            mu,
            iv,
            tree_hashes: tree_hashes.to_vec(),
            hcom,
            chall1,
            h_v: h_v.to_vec(),
            chall2: chall2.to_vec(),
            b_tilde,
            chall3: check,
        };
    }
    let mut diff = 0u8;
    for (a, b) in check.iter().zip(chall3.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ------------------------------------------------------------------ prover

/// Why `prove` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveError {
    UnknownStatement,
    MalformedPublicInputs,
    MessageTooLong,
    BadWitnessLength,
    RelationFails,
}

/// Prover-side values, for comparison with the vectors' intermediates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProverTrace {
    pub mu: [u8; 32],
    pub r: [u8; 16],
    pub iv_pre: [u8; 16],
    pub iv: [u8; 16],
    pub roots: Vec<u8>,
    pub tree_hashes: Vec<[u8; 32]>,
    pub hcom: [u8; 32],
    pub chall1: [u8; 32],
    pub u_tilde: [u8; 32],
    pub h_v: [u8; 32],
    pub chall2: Vec<u8>,
    pub a_tilde: [u8; 16],
    pub b_tilde: [u8; 16],
    pub chall3: [u8; 16],
}

/// Proof of knowledge of `witness` for the statement, bound to `message`
/// (SPEC.md §9). `rho` is the 32 bytes of hedging randomness (the output of
/// the single rng(32) call of the reference); it must be fresh and secret for
/// real use.
///
/// This prover is for tests and tools: it is not constant time and does not
/// zeroize its secrets.
pub fn prove(
    statement_id: u8,
    public_inputs: &[u8],
    witness: &[u8],
    message: &[u8],
    rho: &[u8; RHO_BYTES],
) -> Result<(Vec<u8>, ProverTrace), ProveError> {
    let def = statements::lookup(statement_id).ok_or(ProveError::UnknownStatement)?;
    let parsed =
        statements::s1_parse_public(public_inputs).ok_or(ProveError::MalformedPublicInputs)?;
    if message.len() > MAX_MESSAGE_LEN {
        return Err(ProveError::MessageTooLong);
    }
    if witness.len() != statements::S1_WITNESS_LEN {
        return Err(ProveError::BadWitnessLength);
    }
    if &statements::s1_hmac(parsed.key, parsed.suffix, witness) != parsed.y {
        return Err(ProveError::RelationFails);
    }
    let lay = &def.layout;
    let circ = &def.circuit;
    let (ell, lhat, cb) = (lay.ell, lay.lhat, lay.c_bytes);
    let public_bits = statements::s1_public_bits(&parsed);
    let (_, w_bits, ok) = circ.evaluate(&public_bits, &statements::s1_secret_bits(witness));
    if !ok {
        return Err(ProveError::RelationFails);
    }

    // Phase 1: randomness, IV, VOLE commitment, chall1.
    let mu = compute_mu(statement_id, public_inputs, message);
    let rnd: [u8; 32] = Xof::new(Tag::Rnd)
        .update(&(witness.len() as u16).to_le_bytes())
        .update(witness)
        .update(&mu)
        .update(rho)
        .finalize();
    let r = arr16(&rnd[..16]);
    let iv_pre = arr16(&rnd[16..]);
    let iv: [u8; 16] = Xof::new(Tag::Iv).update(&iv_pre).update(&mu).finalize();
    let roots: [u8; TAU * 16] = Xof::new(Tag::Root).update(&iv).update(&r).finalize();

    let mut trees = Vec::with_capacity(TAU);
    let mut v_cols = vec![0u8; LAMBDA * cb];
    let mut us = vec![vec![0u8; cb]; TAU];
    let mut scratch = ConvertScratch::new(cb);
    for i in 0..TAU {
        let tree = vc::commit(&arr16(&roots[16 * i..16 * i + 16]), &iv, i as u8);
        let tree_cols = &mut v_cols[K * i * cb..K * (i + 1) * cb];
        let mut col_refs: Vec<&mut [u8]> = tree_cols.chunks_exact_mut(cb).collect();
        vole::convert(
            &mut scratch,
            &mut col_refs,
            Some(us[i].as_mut_slice()),
            |j, buf| {
                vole::expand_leaf(&tree.sds[j], &iv, i as u8, j, lhat, buf);
            },
        );
        trees.push(tree);
    }
    let u = us[0].clone();
    let mut c_all = Vec::with_capacity((TAU - 1) * cb);
    for u_i in &us[1..] {
        c_all.extend(u.iter().zip(u_i.iter()).map(|(a, b)| a ^ b));
    }
    let mut hh = Xof::new(Tag::Hcom);
    for t in &trees {
        hh.absorb(&t.hash);
    }
    let hcom: [u8; 32] = hh.finalize();
    let chall1: [u8; 32] = Xof::new(Tag::Ch1)
        .update(&mu)
        .update(&hcom)
        .update(&c_all)
        .update(&iv_pre)
        .finalize();

    // Phase 2: VOLE consistency hash and witness commitment, chall2.
    let vh = VoleHash::new(&chall1, ell);
    let u_tilde = vh.hash(&u);
    let mut hv = Xof::new(Tag::Hv);
    for col in v_cols.chunks_exact(cb) {
        hv.absorb(&vh.hash(col));
    }
    let h_v: [u8; 32] = hv.finalize();
    let mut d_enc = vec![0u8; lay.d_bytes];
    for (k, byte) in d_enc.iter_mut().enumerate() {
        let mut w = 0u8;
        for b in 0..8 {
            if let Some(&bit) = w_bits.get(8 * k + b) {
                w |= bit << b;
            }
        }
        *byte = w ^ u[k];
    }
    bits::clear_padding(&mut d_enc, ell);
    let chall2: [u8; 64] = Xof::new(Tag::Ch2)
        .update(&chall1)
        .update(&u_tilde)
        .update(&h_v)
        .update(&d_enc)
        .finalize();

    // Phase 3: QuickSilver, chall3.
    let rows = vole::columns_to_rows(&v_cols, cb, ell + LAMBDA);
    let zk = ZkHash::new(&chall2);
    let mut acc0 = ZkAcc::default();
    let mut acc1 = ZkAcc::default();
    circ.prover_terms(&public_bits, &w_bits, &rows[..ell], |a0, a1| {
        zk.absorb(&mut acc0, a0);
        zk.absorb(&mut acc1, a1);
    });
    let u_star = bits::load_bits(&u, ell, LAMBDA);
    let v_star = mask_element(&rows[ell..]);
    let a_tilde = gf128::to_bytes(zk.finish(&acc1, u_star));
    let b_tilde = gf128::to_bytes(zk.finish(&acc0, v_star));
    let chall3: [u8; 16] = Xof::new(Tag::Ch3)
        .update(&chall2)
        .update(&a_tilde)
        .update(&b_tilde)
        .finalize();

    // Phase 4: open all but one leaf per tree; assemble.
    let mut proof = Vec::with_capacity(lay.total);
    proof.extend_from_slice(&[VERSION, statement_id]);
    proof.extend_from_slice(&iv_pre);
    proof.extend_from_slice(&c_all);
    proof.extend_from_slice(&u_tilde);
    proof.extend_from_slice(&d_enc);
    proof.extend_from_slice(&a_tilde);
    for (i, t) in trees.iter().enumerate() {
        proof.extend_from_slice(&t.open(chall3[i] as usize));
    }
    proof.extend_from_slice(&chall3);
    debug_assert_eq!(proof.len(), lay.total);

    let trace = ProverTrace {
        mu,
        r,
        iv_pre,
        iv,
        roots: roots.to_vec(),
        tree_hashes: trees.iter().map(|t| t.hash).collect(),
        hcom,
        chall1,
        u_tilde,
        h_v,
        chall2: chall2.to_vec(),
        a_tilde,
        b_tilde,
        chall3,
    };
    Ok((proof, trace))
}
