"""Generic constraint layer: a straight-line Boolean program (SPEC.md §7).

Wires
  0 and 1 are the constants 0 and 1 (kind CONST);
  2 .. 2+n_public-1 are public input bits (kind PUB);
  the next n_secret wires are secret input bits (kind SEC);
  every XOR/AND/NOT instruction that is not folded away creates the next wire.

Kinds propagate statically: an instruction output is SEC if any input is SEC,
otherwise PUB. Only an AND of two SEC wires is non-linear: its output is a new
witness bit, and the instruction carries the degree-2 constraint
out = a * b. ASSERT(a, b, c) adds the constraint a * b = c without creating a
wire. Every SEC wire is an affine function (over GF(2)) of the witness bits,
whose coefficients may depend on public bits.

The builder folds constants with fixed local rules (see Builder), so the
instruction list -- and therefore the witness layout -- depends only on which
wires are constant, public or secret, never on public values.
"""

import hashlib

from . import gf128

CONST, PUB, SEC = 0, 1, 2

# Instruction codes. OP_MUL is an AND of two SEC wires.
OP_XOR, OP_AND, OP_NOT, OP_ASSERT, OP_MUL = 1, 2, 3, 4, 5

# Serialization codes for the circuit digest (OP_MUL is serialized as AND).
_SER_CODE = {OP_XOR: 1, OP_AND: 2, OP_MUL: 2, OP_NOT: 3, OP_ASSERT: 4}

# Specialised verifier codes (operand kinds resolved at build time).
_V_XOR_SS, _V_XOR_SP, _V_XOR_PP, _V_NOT_S, _V_NOT_P = 0, 1, 2, 3, 4
_V_AND_SP, _V_AND_PP, _V_MUL, _V_ASSERT = 5, 6, 7, 8


class Builder:
    """Emits a canonical instruction list. Constant wires are exactly 0 and 1."""

    def __init__(self, n_public, n_secret):
        self.n_public = n_public
        self.n_secret = n_secret
        self.kind = [CONST, CONST] + [PUB] * n_public + [SEC] * n_secret
        self.public = list(range(2, 2 + n_public))
        self.secret = list(range(2 + n_public, 2 + n_public + n_secret))
        self.instrs = []
        self.n_mul = 0
        self.n_assert = 0
        self.outputs = []

    def _emit(self, instr, kind):
        self.instrs.append(instr)
        self.kind.append(kind)
        return len(self.kind) - 1

    def xor(self, a, b):
        if a <= 1 and b <= 1:
            return a ^ b
        if a <= 1:
            a, b = b, a
        if b <= 1:
            return a if b == 0 else self.not_(a)
        k = SEC if (self.kind[a] == SEC or self.kind[b] == SEC) else PUB
        return self._emit((OP_XOR, a, b), k)

    def and_(self, a, b):
        if a <= 1 and b <= 1:
            return a & b
        if a <= 1:
            a, b = b, a
        if b <= 1:
            return a if b == 1 else 0
        ka, kb = self.kind[a], self.kind[b]
        if ka == SEC and kb == SEC:
            self.n_mul += 1
            return self._emit((OP_MUL, a, b), SEC)
        k = SEC if (ka == SEC or kb == SEC) else PUB
        return self._emit((OP_AND, a, b), k)

    def not_(self, a):
        if a <= 1:
            return 1 - a
        return self._emit((OP_NOT, a), self.kind[a])

    def assert_mul(self, a, b, c):
        """Constraint a * b = c (over GF(2))."""
        self.instrs.append((OP_ASSERT, a, b, c))
        self.n_assert += 1

    def is_secret(self, w):
        return self.kind[w] == SEC

    def build(self):
        return Circuit(self)


class Circuit:
    def __init__(self, b):
        self.n_public = b.n_public
        self.n_secret = b.n_secret
        self.instrs = tuple(b.instrs)
        self.kind = tuple(b.kind)
        self.n_wires = len(b.kind)
        self.n_mul = b.n_mul
        self.n_assert = b.n_assert
        self.n_witness = b.n_secret + b.n_mul
        self.n_constraints = b.n_mul + b.n_assert
        self.outputs = tuple(b.outputs)
        self._vprog = self._compile_verifier()

    # ------------------------------------------------------------------ stats
    def counts(self):
        c = {"XOR": 0, "AND": 0, "NOT": 0, "ASSERT": 0, "AND_secret_secret": 0}
        for ins in self.instrs:
            op = ins[0]
            if op == OP_XOR:
                c["XOR"] += 1
            elif op == OP_AND:
                c["AND"] += 1
            elif op == OP_MUL:
                c["AND"] += 1
                c["AND_secret_secret"] += 1
            elif op == OP_NOT:
                c["NOT"] += 1
            else:
                c["ASSERT"] += 1
        return c

    def serialize(self):
        """Canonical byte serialization (SPEC.md §7.6)."""
        out = [b"VOLEitH-rescue circuit v0.1\x00",
               self.n_public.to_bytes(4, "little"),
               self.n_secret.to_bytes(4, "little"),
               len(self.instrs).to_bytes(4, "little")]
        for ins in self.instrs:
            out.append(bytes([_SER_CODE[ins[0]]]))
            for w in ins[1:]:
                out.append(w.to_bytes(4, "little"))
        out.append(len(self.outputs).to_bytes(4, "little"))
        for w in self.outputs:
            out.append(w.to_bytes(4, "little"))
        return b"".join(out)

    def digest(self):
        return hashlib.sha256(self.serialize()).hexdigest()

    # ------------------------------------------------------ clear evaluation
    def evaluate(self, public_bits, secret_bits):
        """Evaluate in the clear. Returns (wire values, witness bits, all_asserts_hold)."""
        if len(public_bits) != self.n_public or len(secret_bits) != self.n_secret:
            raise ValueError("input length mismatch")
        vals = [0, 1]
        vals.extend(public_bits)
        vals.extend(secret_bits)
        witness = list(secret_bits)
        ok = True
        append = vals.append
        for ins in self.instrs:
            op = ins[0]
            if op == OP_XOR:
                append(vals[ins[1]] ^ vals[ins[2]])
            elif op == OP_AND:
                append(vals[ins[1]] & vals[ins[2]])
            elif op == OP_MUL:
                v = vals[ins[1]] & vals[ins[2]]
                append(v)
                witness.append(v)
            elif op == OP_NOT:
                append(vals[ins[1]] ^ 1)
            else:
                if (vals[ins[1]] & vals[ins[2]]) != vals[ins[3]]:
                    ok = False
        return vals, witness, ok

    def check_witness(self, public_bits, witness_bits):
        """True iff the given full witness satisfies every constraint."""
        if len(public_bits) != self.n_public or len(witness_bits) != self.n_witness:
            raise ValueError("input length mismatch")
        vals = [0, 1]
        vals.extend(public_bits)
        vals.extend(witness_bits[:self.n_secret])
        wi = self.n_secret
        append = vals.append
        for ins in self.instrs:
            op = ins[0]
            if op == OP_XOR:
                append(vals[ins[1]] ^ vals[ins[2]])
            elif op == OP_AND:
                append(vals[ins[1]] & vals[ins[2]])
            elif op == OP_MUL:
                w = witness_bits[wi]
                wi += 1
                if (vals[ins[1]] & vals[ins[2]]) != w:
                    return False
                append(w)
            elif op == OP_NOT:
                append(vals[ins[1]] ^ 1)
            else:
                if (vals[ins[1]] & vals[ins[2]]) != vals[ins[3]]:
                    return False
        return True

    def output_bits(self, vals):
        return [vals[w] for w in self.outputs]

    # ------------------------------------------------------- prover (MACs)
    def prover_terms(self, public_bits, witness_bits, witness_macs):
        """QuickSilver terms (A0_t, A1_t) for every constraint t, in order.

        A SEC wire is carried as (mac << 1) | bit, a PUB/CONST wire as its bit
        (its MAC is 0), so XOR, NOT and AND-with-a-public-bit are uniform.
        For a constraint a*b = c: A0 = m_a m_b, A1 = b_a m_b + b_b m_a + m_c.
        """
        mul = gf128.mul
        vals = [0, 1]
        vals.extend(public_bits)
        for i in range(self.n_secret):
            vals.append((witness_macs[i] << 1) | witness_bits[i])
        wi = self.n_secret
        a0 = []
        a1 = []
        append = vals.append
        for ins in self.instrs:
            op = ins[0]
            if op == OP_XOR:
                append(vals[ins[1]] ^ vals[ins[2]])
            elif op == OP_MUL:
                x = vals[ins[1]]
                y = vals[ins[2]]
                mz = witness_macs[wi]
                z = (mz << 1) | witness_bits[wi]
                wi += 1
                append(z)
                mx = x >> 1
                my = y >> 1
                a0.append(mul(mx, my))
                a1.append((my if x & 1 else 0) ^ (mx if y & 1 else 0) ^ mz)
            elif op == OP_NOT:
                append(vals[ins[1]] ^ 1)
            elif op == OP_AND:
                append(vals[ins[1]] * vals[ins[2]])
            else:
                x = vals[ins[1]]
                y = vals[ins[2]]
                z = vals[ins[3]]
                mx = x >> 1
                my = y >> 1
                a0.append(mul(mx, my))
                a1.append((my if x & 1 else 0) ^ (mx if y & 1 else 0) ^ (z >> 1))
        return a0, a1

    # ------------------------------------------------------ verifier (keys)
    def _compile_verifier(self):
        kind = self.kind
        prog = []
        for ins in self.instrs:
            op = ins[0]
            if op == OP_XOR or op == OP_AND:
                a, b = ins[1], ins[2]
                sa, sb = kind[a] == SEC, kind[b] == SEC
                if sa and sb:
                    if op != OP_XOR:
                        raise AssertionError("AND of two secret wires must be OP_MUL")
                    prog.append((_V_XOR_SS, a, b))
                elif sa or sb:
                    if sb:
                        a, b = b, a
                    prog.append((_V_XOR_SP if op == OP_XOR else _V_AND_SP, a, b))
                else:
                    prog.append((_V_XOR_PP if op == OP_XOR else _V_AND_PP, a, b))
            elif op == OP_MUL:
                prog.append((_V_MUL, ins[1], ins[2]))
            elif op == OP_NOT:
                prog.append((_V_NOT_S if kind[ins[1]] == SEC else _V_NOT_P, ins[1]))
            else:
                a, b, c = ins[1], ins[2], ins[3]
                prog.append((_V_ASSERT, a, b, c,
                             kind[a] == SEC, kind[b] == SEC, kind[c] == SEC))
        return tuple(prog)

    def verifier_terms(self, public_bits, witness_keys, delta):
        """QuickSilver terms B_t = k_a k_b + k_c * delta for every constraint t.

        A SEC wire is carried as its key k = m + bit * delta; a PUB/CONST wire
        as its bit (its key is bit * delta).
        """
        mul = gf128.mul
        mul_delta = gf128.FixedMul(delta)
        vals = [0, 1]
        vals.extend(public_bits)
        vals.extend(witness_keys[:self.n_secret])
        wi = self.n_secret
        out = []
        append = vals.append
        for ins in self._vprog:
            op = ins[0]
            if op == _V_XOR_SS:
                append(vals[ins[1]] ^ vals[ins[2]])
            elif op == _V_MUL:
                kz = witness_keys[wi]
                wi += 1
                append(kz)
                out.append(mul(vals[ins[1]], vals[ins[2]]) ^ mul_delta(kz))
            elif op == _V_XOR_SP:
                append(vals[ins[1]] ^ delta if vals[ins[2]] else vals[ins[1]])
            elif op == _V_NOT_S:
                append(vals[ins[1]] ^ delta)
            elif op == _V_AND_SP:
                append(vals[ins[1]] if vals[ins[2]] else 0)
            elif op == _V_XOR_PP:
                append(vals[ins[1]] ^ vals[ins[2]])
            elif op == _V_AND_PP:
                append(vals[ins[1]] & vals[ins[2]])
            elif op == _V_NOT_P:
                append(vals[ins[1]] ^ 1)
            else:
                _, a, b, c, sa, sb, sc = ins
                ka = vals[a] if sa else (delta if vals[a] else 0)
                kb = vals[b] if sb else (delta if vals[b] else 0)
                kc = vals[c] if sc else (delta if vals[c] else 0)
                out.append(mul(ka, kb) ^ mul_delta(kc))
        return out
