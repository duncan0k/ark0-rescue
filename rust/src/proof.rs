//! Prover and verifier (SPEC.md §6, §8–§11).
//!
//! `verify` and `prove` use the parameter set of this version
//! (`params::SPLIT`). Other tree splits are reachable only through the
//! `bench` module, which exists only with the `bench-splits` feature. The
//! prover's intermediate values, which include secrets, are reachable only
//! through `prove_traced`, which exists only with the `test-trace` feature.

#![forbid(unsafe_code)]

use crate::bits;
use crate::circuit::Circuit;
use crate::gf128::{self, FixedMul};
use crate::params::{LAMBDA, LAMBDA_BYTES, MAX_LEAVES, MAX_MESSAGE_LEN, RHO_BYTES, VERSION};
use crate::statements::{self, Layout, STATEMENT1_ID};
use crate::sym::{Tag, Xof};
use crate::unihash::{CtMul, VoleHash, ZkAcc, ZkHash};
use crate::vc;
use crate::vole::{self, ConvertScratch};
use zeroize::{Zeroize, Zeroizing};

/// Proof length in bytes for a registered statement id.
pub fn proof_length(statement_id: u8) -> Option<usize> {
    statements::layout(statement_id).map(|l| l.total)
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

/// Equality of two byte strings of the same length without an early exit:
/// the time does not depend on where they differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
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
    match statements::layout(statement_id) {
        Some(lay) => verify_impl(&lay, statement_id, public_inputs, message, proof, None),
        None => false,
    }
}

/// `verify`, also returning the recomputed values when the input passed the
/// format checks (steps 1–6).
pub fn verify_traced(
    statement_id: u8,
    public_inputs: &[u8],
    message: &[u8],
    proof: &[u8],
) -> (bool, Option<VerifierTrace>) {
    let Some(lay) = statements::layout(statement_id) else {
        return (false, None);
    };
    let mut trace = VerifierTrace::default();
    let mut reached = false;
    let ok = verify_impl(
        &lay,
        statement_id,
        public_inputs,
        message,
        proof,
        Some((&mut trace, &mut reached)),
    );
    (ok, if reached { Some(trace) } else { None })
}

/// Steps 2–11 for a registered statement id (step 1) and its layout. The
/// format checks (steps 2–6) use fixed sizes only; the statement's circuit is
/// built or looked up after them.
fn verify_impl(
    lay: &Layout,
    statement_id: u8,
    public_inputs: &[u8],
    message: &[u8],
    proof: &[u8],
    trace: Option<(&mut VerifierTrace, &mut bool)>,
) -> bool {
    // 2. Canonical public inputs, by the rules of this statement id.
    let parsed = match statement_id {
        STATEMENT1_ID => statements::s1_parse_public(public_inputs),
        _ => None,
    };
    let Some(parsed) = parsed else {
        return false;
    };
    // 3. Message length.
    if message.len() > MAX_MESSAGE_LEN {
        return false;
    }
    // 4. Proof length.
    if proof.len() != lay.total {
        return false;
    }
    // 5. Header.
    if proof[0] != VERSION || proof[1] != statement_id {
        return false;
    }
    // 6. Every padding bit of the corrections and of d is zero.
    for i in 0..lay.split.tau() - 1 {
        let off = lay.off_c + i * lay.c_bytes;
        if !bits::is_canonical(&proof[off..off + lay.c_bytes], lay.lhat) {
            return false;
        }
    }
    if !bits::is_canonical(&proof[lay.off_d..lay.off_d + lay.d_bytes], lay.ell) {
        return false;
    }
    let Some(circuit) = statements::circuit(statement_id) else {
        return false;
    };
    let public_bits = statements::s1_public_bits(&parsed);
    verify_core(
        circuit,
        lay,
        statement_id,
        public_inputs,
        &public_bits,
        message,
        proof,
        trace,
    )
}

/// Steps 7–11 on an input that passed the format checks. The work is
/// bounded and independent of secret data, but not constant: each set bit of
/// Delta adds an XOR of u_tilde and of d and, outside tree 0, of a correction.
#[allow(clippy::too_many_arguments)]
fn verify_core(
    circuit: &Circuit,
    lay: &Layout,
    statement_id: u8,
    public_inputs: &[u8],
    public_bits: &[u8],
    message: &[u8],
    proof: &[u8],
    trace: Option<(&mut VerifierTrace, &mut bool)>,
) -> bool {
    let split = lay.split;
    let tau = split.tau();
    let (ell, lhat, cb) = (lay.ell, lay.lhat, lay.c_bytes);
    let iv_pre = &proof[lay.off_iv_pre..lay.off_iv_pre + LAMBDA_BYTES];
    let c_all = &proof[lay.off_c..lay.off_c + (tau - 1) * cb];
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
    let mut tree_hashes = Vec::with_capacity(tau);
    let mut sds = [[0u8; 16]; MAX_LEAVES];
    let mut scratch = ConvertScratch::new(cb);
    for i in 0..tau {
        let depth = split.depth(i);
        let jstar = split.challenge_index(delta, i);
        let opening = lay.opening(proof, i);
        tree_hashes.push(vc::reconstruct(
            opening, &iv, i as u8, depth, jstar, &mut sds,
        ));
        let first = split.offset(i);
        let tree_cols = &mut cols[first * cb..(first + depth) * cb];
        let mut col_refs: Vec<&mut [u8]> = tree_cols.chunks_exact_mut(cb).collect();
        // q_{i,b} = XOR over j != j* with bit b of (j XOR j*) set: stream
        // x = j XOR j*, where x = 0 is the hidden leaf.
        vole::convert(&mut scratch, &mut col_refs, None, |x, buf| {
            if x == 0 {
                buf.fill(0);
            } else {
                let j = x ^ jstar;
                vole::expand_leaf(&sds[j], &iv, i as u8, depth, j, lhat, buf);
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
    let vh = VoleHash::<FixedMul>::new(&chall1, ell);
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
    let zk = ZkHash::<FixedMul>::new(&chall2);
    let mul_delta = FixedMul::new(delta);
    let mut acc = ZkAcc::default();
    circuit.verifier_terms(public_bits, &rows[..ell], delta, &mul_delta, |b| {
        zk.absorb(&mut acc, b)
    });
    let q_tilde = zk.finish(&acc, mask_element(&rows[ell..]));
    let b_tilde = gf128::to_bytes(q_tilde ^ gf128::mul_public(gf128::from_bytes(&a_tilde), delta));

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
            tree_hashes,
            hcom,
            chall1,
            h_v: h_v.to_vec(),
            chall2: chall2.to_vec(),
            b_tilde,
            chall3: check,
        };
    }
    ct_eq(&check, &chall3)
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

/// The prover's intermediate values, for comparison with the vectors'
/// intermediates; only `prove_traced` (cargo feature `test-trace`) fills it.
/// It holds the root seed `r` and the tree roots, from which the witness can
/// be recovered, so it has no `Debug`, `prove` never produces it, and it is
/// zeroized when dropped.
#[doc(hidden)]
#[derive(Default)]
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

impl Drop for ProverTrace {
    fn drop(&mut self) {
        self.r.zeroize();
        self.roots.zeroize();
    }
}

/// Proof of knowledge of `witness` for the statement, bound to `message`
/// (SPEC.md §9). `rho` is the 32 bytes of hedging randomness (the output of
/// the single rng(32) call of the reference); it must be fresh and secret for
/// real use.
///
/// The field arithmetic and the control flow on secret data are constant
/// time, and every secret buffer the prover allocates is zeroized before it
/// is freed; the stack the prover used is overwritten before returning (best
/// effort). The caller owns `witness` and `rho` and must clear them itself.
/// See rust/CT-AUDIT.md for what was checked and what remains.
pub fn prove(
    statement_id: u8,
    public_inputs: &[u8],
    witness: &[u8],
    message: &[u8],
    rho: &[u8; RHO_BYTES],
) -> Result<Vec<u8>, ProveError> {
    let lay = statements::layout(statement_id).ok_or(ProveError::UnknownStatement)?;
    let res = prove_impl(
        &lay,
        statement_id,
        public_inputs,
        witness,
        message,
        rho,
        None,
    );
    scrub_stack();
    res
}

/// Overwrite with zeros the stack below the caller's frame, where the frames
/// of `prove_impl` and its callees held copies of secrets (seeds, hash
/// states, field elements). Best effort: the compiler decides frame layout,
/// so this covers `SCRUB_BYTES` below this frame and nothing else.
#[inline(never)]
fn scrub_stack() {
    const SCRUB_BYTES: usize = 64 * 1024;
    let mut buf = [0u8; SCRUB_BYTES];
    buf.zeroize();
    core::hint::black_box(&buf);
}

/// `prove`, also returning the prover's intermediate values, secrets
/// included. For the vector tests only (cargo feature `test-trace`).
#[cfg(feature = "test-trace")]
#[doc(hidden)]
pub fn prove_traced(
    statement_id: u8,
    public_inputs: &[u8],
    witness: &[u8],
    message: &[u8],
    rho: &[u8; RHO_BYTES],
) -> Result<(Vec<u8>, ProverTrace), ProveError> {
    let lay = statements::layout(statement_id).ok_or(ProveError::UnknownStatement)?;
    let mut trace = ProverTrace::default();
    let proof = prove_impl(
        &lay,
        statement_id,
        public_inputs,
        witness,
        message,
        rho,
        Some(&mut trace),
    );
    scrub_stack();
    Ok((proof?, trace))
}

fn prove_impl(
    lay: &Layout,
    statement_id: u8,
    public_inputs: &[u8],
    witness: &[u8],
    message: &[u8],
    rho: &[u8; RHO_BYTES],
    trace: Option<&mut ProverTrace>,
) -> Result<Vec<u8>, ProveError> {
    let parsed = match statement_id {
        STATEMENT1_ID => statements::s1_parse_public(public_inputs),
        _ => None,
    }
    .ok_or(ProveError::MalformedPublicInputs)?;
    if message.len() > MAX_MESSAGE_LEN {
        return Err(ProveError::MessageTooLong);
    }
    if witness.len() != statements::S1_WITNESS_LEN {
        return Err(ProveError::BadWitnessLength);
    }
    if !ct_eq(&statements::s1_hmac(parsed.key, parsed.suffix, witness), parsed.y) {
        return Err(ProveError::RelationFails);
    }
    let circ = statements::circuit(statement_id).ok_or(ProveError::UnknownStatement)?;
    let split = lay.split;
    let tau = split.tau();
    let (ell, lhat, cb) = (lay.ell, lay.lhat, lay.c_bytes);
    let public_bits = statements::s1_public_bits(&parsed);
    // Every secret buffer below is Zeroizing (or zeroizes itself on drop:
    // vc::Tree, ConvertScratch, ZkAcc) and is allocated at its final size,
    // so no reallocation leaves a copy behind.
    let secret_bits = Zeroizing::new(statements::s1_secret_bits(witness));
    let (wires, w_bits, ok) = circ.evaluate(&public_bits, &secret_bits);
    let (_wires, w_bits) = (Zeroizing::new(wires), Zeroizing::new(w_bits));
    if !ok {
        return Err(ProveError::RelationFails);
    }

    // Phase 1: randomness, IV, VOLE commitment, chall1.
    let mu = compute_mu(statement_id, public_inputs, message);
    let rnd: Zeroizing<[u8; 32]> = Zeroizing::new(
        Xof::new(Tag::Rnd)
            .update(&(witness.len() as u16).to_le_bytes())
            .update(witness)
            .update(&mu)
            .update(rho)
            .finalize(),
    );
    let r: &[u8] = &rnd[..16];
    let iv_pre = arr16(&rnd[16..]);
    let iv: [u8; 16] = Xof::new(Tag::Iv).update(&iv_pre).update(&mu).finalize();
    let mut roots = Zeroizing::new(vec![0u8; tau * LAMBDA_BYTES]);
    Xof::new(Tag::Root)
        .update(&iv)
        .update(r)
        .finalize_into(&mut roots);

    let mut trees = Vec::with_capacity(tau);
    let mut v_cols = Zeroizing::new(vec![0u8; LAMBDA * cb]);
    let mut us = Zeroizing::new(vec![vec![0u8; cb]; tau]);
    let mut scratch = ConvertScratch::new(cb);
    for (i, u_i) in us.iter_mut().enumerate() {
        let depth = split.depth(i);
        let root: &[u8; 16] = roots[16 * i..16 * i + 16].try_into().expect("16 bytes");
        let tree = vc::commit(root, &iv, i as u8, depth);
        let first = split.offset(i);
        let tree_cols = &mut v_cols[first * cb..(first + depth) * cb];
        let mut col_refs: Vec<&mut [u8]> = tree_cols.chunks_exact_mut(cb).collect();
        vole::convert(
            &mut scratch,
            &mut col_refs,
            Some(u_i.as_mut_slice()),
            |j, buf| {
                vole::expand_leaf(&tree.sds[j], &iv, i as u8, depth, j, lhat, buf);
            },
        );
        trees.push(tree);
    }
    let u = Zeroizing::new(us[0].clone());
    let mut c_all = Vec::with_capacity((tau - 1) * cb);
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
    let vh = VoleHash::<CtMul>::new(&chall1, ell);
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
    let rows = Zeroizing::new(vole::columns_to_rows(&v_cols, cb, ell + LAMBDA));
    let zk = ZkHash::<CtMul>::new(&chall2);
    let mut acc0 = ZkAcc::default();
    let mut acc1 = ZkAcc::default();
    circ.prover_terms(&public_bits, &w_bits, &rows[..ell], |a0, a1| {
        zk.absorb(&mut acc0, a0);
        zk.absorb(&mut acc1, a1);
    });
    let u_star = Zeroizing::new(bits::load_bits(&u, ell, LAMBDA));
    let v_star = Zeroizing::new(mask_element(&rows[ell..]));
    let a_tilde = gf128::to_bytes(zk.finish(&acc1, *u_star));
    let b_tilde = gf128::to_bytes(zk.finish(&acc0, *v_star));
    let chall3: [u8; 16] = Xof::new(Tag::Ch3)
        .update(&chall2)
        .update(&a_tilde)
        .update(&b_tilde)
        .finalize();

    // Phase 4: open all but one leaf per tree; assemble.
    let delta = gf128::from_bytes(&chall3);
    let mut proof = Vec::with_capacity(lay.total);
    proof.extend_from_slice(&[VERSION, statement_id]);
    proof.extend_from_slice(&iv_pre);
    proof.extend_from_slice(&c_all);
    proof.extend_from_slice(&u_tilde);
    proof.extend_from_slice(&d_enc);
    proof.extend_from_slice(&a_tilde);
    for (i, t) in trees.iter().enumerate() {
        proof.extend_from_slice(&t.open(split.challenge_index(delta, i)));
    }
    proof.extend_from_slice(&chall3);
    debug_assert_eq!(proof.len(), lay.total);

    if let Some(slot) = trace {
        *slot = ProverTrace {
            mu,
            r: arr16(r),
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
    }
    Ok(proof)
}

/// Other tree splits, for the benchmark only (cargo feature `bench-splits`).
/// Nothing outside this module, including `verify` and the C ABI, can use a
/// split other than `params::SPLIT`.
#[cfg(feature = "bench-splits")]
pub mod bench {
    use super::{prove_impl, verify_impl, ProveError};
    use crate::params::{TreeSplit, RHO_BYTES};
    use crate::statements;

    /// Proof length for a registered statement id under `split`.
    pub fn proof_length(split: TreeSplit, statement_id: u8) -> Option<usize> {
        statements::layout_for(statement_id, split).map(|l| l.total)
    }

    /// `verify` under `split`.
    pub fn verify(
        split: TreeSplit,
        statement_id: u8,
        public_inputs: &[u8],
        message: &[u8],
        proof: &[u8],
    ) -> bool {
        match statements::layout_for(statement_id, split) {
            Some(lay) => verify_impl(&lay, statement_id, public_inputs, message, proof, None),
            None => false,
        }
    }

    /// `prove` under `split`.
    pub fn prove(
        split: TreeSplit,
        statement_id: u8,
        public_inputs: &[u8],
        witness: &[u8],
        message: &[u8],
        rho: &[u8; RHO_BYTES],
    ) -> Result<Vec<u8>, ProveError> {
        let lay =
            statements::layout_for(statement_id, split).ok_or(ProveError::UnknownStatement)?;
        prove_impl(
            &lay,
            statement_id,
            public_inputs,
            witness,
            message,
            rho,
            None,
        )
    }
}
