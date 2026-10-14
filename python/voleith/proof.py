"""VOLEitH prover and verifier (SPEC.md §6, §8, §9).

prove(statement, witness, message, rng) -> proof bytes
verify(statement, message, proof) -> bool
"""

import hmac
import os

from . import bits, gf128, vc, vole
from .params import (VERSION, LAMBDA, LAMBDA_BYTES, TAU, QS_MASK_BITS,
                     VH_MASK_BITS, RHO_BYTES, MAX_MESSAGE_LEN, HEADER_BYTES)
from .statements import REGISTRY, Statement
from .sym import xof, xof_parts, u8, u16le, u64le
from .unihash import VoleHash, ZkHash


class Layout:
    """Field sizes and offsets of a proof for one statement id (SPEC.md §8)."""

    def __init__(self, circuit):
        self.ell = circuit.n_witness
        self.n_constraints = circuit.n_constraints
        self.lhat = self.ell + QS_MASK_BITS + VH_MASK_BITS
        self.c_bytes = bits.nbytes(self.lhat)
        self.d_bytes = bits.nbytes(self.ell)
        self.off_iv_pre = HEADER_BYTES
        self.off_c = self.off_iv_pre + LAMBDA_BYTES
        self.off_u_tilde = self.off_c + (TAU - 1) * self.c_bytes
        self.off_d = self.off_u_tilde + 2 * LAMBDA_BYTES
        self.off_a_tilde = self.off_d + self.d_bytes
        self.off_open = self.off_a_tilde + LAMBDA_BYTES
        self.off_chall3 = self.off_open + TAU * vc.OPENING_BYTES
        self.total = self.off_chall3 + LAMBDA_BYTES


_LAYOUTS = {}


def layout(statement_id):
    if statement_id not in _LAYOUTS:
        _LAYOUTS[statement_id] = Layout(REGISTRY[statement_id].circuit())
    return _LAYOUTS[statement_id]


def proof_length(statement_id):
    return layout(statement_id).total


def compute_mu(statement_id, public_inputs, message):
    return xof_parts("mu", [u8(VERSION), u8(statement_id),
                            u16le(len(public_inputs)), public_inputs,
                            u64le(len(message)), message], 2 * LAMBDA_BYTES)


def _q_star(rows, ell):
    """sum_{i<LAMBDA} X^i * rows[ell + i] in GF(2^128)."""
    z = 0
    for i in range(LAMBDA):
        z ^= rows[ell + i] << i
    return gf128.reduce(z)


def _bits_to_int(bit_list):
    """The int whose bit i is bit_list[i]."""
    if not bit_list:
        return 0
    return int("".join("1" if b else "0" for b in reversed(bit_list)), 2)


# --------------------------------------------------------------------- prover

def prove(statement, witness, message, rng=None):
    """Proof of knowledge of `witness` for `statement`, bound to `message`.

    `rng(n)` must return n bytes; it is called exactly once, with
    n = RHO_BYTES. Raises ValueError on malformed input or if the witness
    does not satisfy the relation.
    """
    if rng is None:
        rng = os.urandom
    return _prove_impl(statement, witness, message, rng, enforce_relation=True)[0]


def _prove_impl(statement, witness, message, rng, enforce_relation, trace=False,
                witness_bits_override=None):
    """Prover core. `enforce_relation=False` and `witness_bits_override` exist
    only so tests can play a cheating prover; prove() never uses them."""
    if not isinstance(statement, Statement) or statement.statement_id not in REGISTRY:
        raise ValueError("unknown statement")
    sdef = REGISTRY[statement.statement_id]
    parsed = sdef.parse_public(statement.public_inputs)
    if parsed is None:
        raise ValueError("malformed public inputs")
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_LEN:
        raise ValueError("message must be bytes of length <= %d" % MAX_MESSAGE_LEN)
    if not isinstance(witness, bytes) or len(witness) != sdef.witness_len:
        raise ValueError("witness must be %d bytes" % sdef.witness_len)
    if enforce_relation and not sdef.relation(parsed, witness):
        raise ValueError("witness does not satisfy the relation")

    circ = sdef.circuit()
    lay = layout(statement.statement_id)
    ell, lhat = lay.ell, lay.lhat
    pub_bits = sdef.public_bits(parsed)
    _, wit_bits, ok = circ.evaluate(pub_bits, sdef.secret_bits(witness))
    if enforce_relation and not ok:
        raise ValueError("witness does not satisfy the constraint system")
    if witness_bits_override is not None:
        if enforce_relation or len(witness_bits_override) != len(wit_bits):
            raise ValueError("witness override is for cheating-prover tests only")
        wit_bits = list(witness_bits_override)

    # Phase 1: randomness, IV, VOLE commitment, chall1.
    mu = compute_mu(statement.statement_id, statement.public_inputs, message)
    rho = rng(RHO_BYTES)
    if not isinstance(rho, bytes) or len(rho) != RHO_BYTES:
        raise ValueError("rng must return %d bytes" % RHO_BYTES)
    rnd = xof("rnd", u16le(len(witness)) + witness + mu + rho, 2 * LAMBDA_BYTES)
    r, iv_pre = rnd[:LAMBDA_BYTES], rnd[LAMBDA_BYTES:]
    iv = xof("iv", iv_pre + mu, LAMBDA_BYTES)
    hcom, decom, corrections, u, v_cols = vole.commit(r, iv, lhat)
    c_enc = [bits.encode(c, lhat) for c in corrections]
    chall1 = xof_parts("ch1", [mu, hcom] + c_enc + [iv_pre], 2 * LAMBDA_BYTES)

    # Phase 2: VOLE consistency hash and witness commitment, chall2.
    vh = VoleHash(chall1, ell)
    u_tilde = vh(u)
    h_v = xof("hv", b"".join(vh(col) for col in v_cols), 2 * LAMBDA_BYTES)
    w_int = _bits_to_int(wit_bits)
    d = w_int ^ (u & ((1 << ell) - 1))
    d_enc = bits.encode(d, ell)
    chall2 = xof_parts("ch2", [chall1, u_tilde, h_v, d_enc], 4 * LAMBDA_BYTES)

    # Phase 3: QuickSilver, chall3.
    rows = vole.columns_to_rows(v_cols, ell + LAMBDA)
    a0, a1 = circ.prover_terms(pub_bits, wit_bits, rows)
    u_star = (u >> ell) & gf128.MASK
    v_star = _q_star(rows, ell)
    zk = ZkHash(chall2)
    a_tilde = gf128.to_bytes(zk(a1, u_star))
    b_tilde = gf128.to_bytes(zk(a0, v_star))
    chall3 = xof_parts("ch3", [chall2, a_tilde, b_tilde], LAMBDA_BYTES)

    # Phase 4: open all but one leaf per tree.
    delta = gf128.from_bytes(chall3)
    openings = []
    for i in range(TAU):
        nodes, coms = decom[i]
        openings.append(vc.open_(nodes, coms, vole.challenge_index(delta, i)))

    proof = b"".join([bytes([VERSION, statement.statement_id]), iv_pre] + c_enc
                     + [u_tilde, d_enc, a_tilde] + openings + [chall3])
    if len(proof) != lay.total:
        raise AssertionError("internal error: proof length")
    info = None
    if trace:
        info = {"mu": mu, "rho": rho, "iv_pre": iv_pre, "iv": iv, "hcom": hcom,
                "chall1": chall1, "u_tilde": u_tilde, "h_v": h_v,
                "chall2": chall2, "a_tilde": a_tilde, "b_tilde": b_tilde,
                "chall3": chall3}
    return proof, info


# ------------------------------------------------------------------- verifier

def verify(statement, message, proof):
    """True iff `proof` is a valid proof for `statement` bound to `message`.

    Every length and format check happens before any hashing; any malformed
    input yields False.
    """
    # 1. Statement: known id, canonical public inputs.
    if not isinstance(statement, Statement):
        return False
    sid = statement.statement_id
    if type(sid) is not int or sid not in REGISTRY:
        return False
    sdef = REGISTRY[sid]
    parsed = sdef.parse_public(statement.public_inputs)
    if parsed is None:
        return False
    # 2. Message and proof types and lengths.
    if not isinstance(message, bytes) or len(message) > MAX_MESSAGE_LEN:
        return False
    if not isinstance(proof, bytes):
        return False
    lay = layout(sid)
    if len(proof) != lay.total:
        return False
    # 3. Header.
    if proof[0] != VERSION or proof[1] != sid:
        return False
    # 4. Bit strings with padding: every padding bit must be zero.
    corrections = []
    for i in range(TAU - 1):
        off = lay.off_c + i * lay.c_bytes
        c = bits.decode(proof[off:off + lay.c_bytes], lay.lhat)
        if c is None:
            return False
        corrections.append(c)
    d = bits.decode(proof[lay.off_d:lay.off_d + lay.d_bytes], lay.ell)
    if d is None:
        return False
    return _verify_core(statement, parsed, sdef, lay, message, proof, corrections, d)


def _verify_core(statement, parsed, sdef, lay, message, proof, corrections, d):
    ell, lhat = lay.ell, lay.lhat
    iv_pre = proof[lay.off_iv_pre:lay.off_iv_pre + LAMBDA_BYTES]
    u_tilde = proof[lay.off_u_tilde:lay.off_u_tilde + 2 * LAMBDA_BYTES]
    a_tilde = proof[lay.off_a_tilde:lay.off_a_tilde + LAMBDA_BYTES]
    openings = [proof[lay.off_open + i * vc.OPENING_BYTES:
                      lay.off_open + (i + 1) * vc.OPENING_BYTES] for i in range(TAU)]
    chall3 = proof[lay.off_chall3:lay.off_chall3 + LAMBDA_BYTES]
    c_enc = [proof[lay.off_c + i * lay.c_bytes:lay.off_c + (i + 1) * lay.c_bytes]
             for i in range(TAU - 1)]
    d_enc = proof[lay.off_d:lay.off_d + lay.d_bytes]

    mu = compute_mu(statement.statement_id, statement.public_inputs, message)
    iv = xof("iv", iv_pre + mu, LAMBDA_BYTES)
    delta = gf128.from_bytes(chall3)

    # Reconstruct the VOLE keys Q = V + u * Delta and the commitment.
    hcom, q_cols = vole.reconstruct(openings, corrections, delta, iv, lhat)
    chall1 = xof_parts("ch1", [mu, hcom] + c_enc + [iv_pre], 2 * LAMBDA_BYTES)

    # VOLE consistency: recompute h_V from Q and u_tilde.
    vh = VoleHash(chall1, ell)
    parts = []
    for j in range(LAMBDA):
        qh = vh(q_cols[j])
        if (delta >> j) & 1:
            qh = bytes(x ^ y for x, y in zip(qh, u_tilde))
        parts.append(qh)
    h_v = xof("hv", b"".join(parts), 2 * LAMBDA_BYTES)
    chall2 = xof_parts("ch2", [chall1, u_tilde, h_v, d_enc], 4 * LAMBDA_BYTES)

    # Witness keys: q_r + d_r * Delta for r < ell.
    for j in range(LAMBDA):
        if (delta >> j) & 1:
            q_cols[j] ^= d
    rows = vole.columns_to_rows(q_cols, ell + LAMBDA)

    # QuickSilver: recompute b_tilde and chall3.
    circ = sdef.circuit()
    b_terms = circ.verifier_terms(sdef.public_bits(parsed), rows, delta)
    zk = ZkHash(chall2)
    q_tilde = zk(b_terms, _q_star(rows, ell))
    b_tilde = q_tilde ^ gf128.mul(gf128.from_bytes(a_tilde), delta)
    chall3_check = xof_parts("ch3", [chall2, a_tilde, gf128.to_bytes(b_tilde)],
                             LAMBDA_BYTES)
    return hmac.compare_digest(chall3_check, chall3)
