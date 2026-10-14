"""Generate vectors/statement1-v0.2-differential.json, the bulk differential set.

Usage: python -I python/tools/gen_differential.py [--valid N] [--jobs J] [output]

The set has two parts:

- `valid`: random statement 0x01 instances (random printable K of 1..64 bytes,
  random suffix, seed x, message and prover randomness rho) with the proof the
  Python prover made for them;
- `mutated`: edits of those proofs, statements and messages (bit flips in
  every proof section, truncations, extensions, wrong messages, wrong or
  malformed statements, proofs moved between instances, sections swapped
  between proofs, random proof bodies).

Every random choice comes from SHAKE256 streams keyed by MASTER_SEED and a
per-case label, so the file is reproducible; each case also records its own
inputs, so no stream is needed to use it. The Python verifier is the oracle:
`expected` is what voleith.verify returned for the case, and every valid case
must verify. Independent verifiers must return `expected` on every case.

Proofs are stored once, base64-encoded, in the valid cases; a mutated case
names its base proof and lists `proof_edits`, applied in order:

  {"op": "xor", "offset": n, "mask": "hh"}     XOR one byte with a nonzero mask
  {"op": "set", "offset": n, "data": hex}      overwrite bytes in place
  {"op": "truncate", "length": n}              keep the first n bytes
  {"op": "append", "data": hex}                append bytes
  {"op": "prepend", "data": hex}               prepend bytes

A mutated case's message is `message` (hex), or, when `message` is null,
`message_zeros` zero bytes (used for the over-long message).
"""

import argparse
import base64
import hashlib
import json
import multiprocessing
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import voleith  # noqa: E402
from voleith import proof as P  # noqa: E402
from voleith import statements as st  # noqa: E402
from voleith.params import MAX_MESSAGE_LEN, RHO_BYTES, VERSION  # noqa: E402

MASTER_SEED = b"voleith differential set v0.2 / 2026-10-14"
FORMAT = "voleith-differential-1"


class Stream:
    """Deterministic byte stream: SHAKE256(MASTER_SEED || label || counter)."""

    def __init__(self, label):
        self.label = label
        self.ctr = 0

    def bytes(self, n):
        out = hashlib.shake_256(MASTER_SEED + b"/" + self.label
                                + self.ctr.to_bytes(8, "little")).digest(n)
        self.ctr += 1
        return out

    def below(self, n):
        """Uniform integer in [0, n) (rejection sampling)."""
        if n <= 1:
            return 0
        nb = (n.bit_length() + 7) // 8 + 1
        lim = (256 ** nb // n) * n
        while True:
            v = int.from_bytes(self.bytes(nb), "little")
            if v < lim:
                return v % n

    def printable(self, n):
        return bytes(0x20 + self.below(95) for _ in range(n))


# ------------------------------------------------------------- valid cases

def valid_inputs(i):
    """(K, suffix, x, message, rho) of valid case i."""
    s = Stream(b"valid %d" % i)
    klen = {0: 1, 1: 64}.get(i, 1 + s.below(64))
    key = s.printable(klen)
    suffix = {2: 0, 3: 255}.get(i, s.below(256))
    x = s.bytes(32)
    if i == 4:
        mlen = 0
    elif i == 5:
        mlen = MAX_MESSAGE_LEN
    elif i % 2 == 0:
        mlen = 96  # rescue sighash || network id || public key
    else:
        mlen = s.below(300)
    msg = s.bytes(mlen) if mlen else b""
    rho = s.bytes(RHO_BYTES)
    return key, suffix, x, msg, rho


def make_valid(i):
    key, suffix, x, msg, rho = valid_inputs(i)
    stmt = voleith.statement1_for_seed(key, suffix, x)

    def rng(n):
        if n != RHO_BYTES:
            raise AssertionError("prover asked for %d bytes" % n)
        return rho

    proof = voleith.prove(stmt, x, msg, rng=rng)
    ok = voleith.verify(stmt, msg, proof)
    _, _, y = st.s1_parse_public(stmt.public_inputs)
    return {
        "id": "valid-%03d" % i,
        "statement_id": stmt.statement_id,
        "K_ascii": key.decode("ascii"),
        "suffix": suffix,
        "y": y.hex(),
        "public_inputs": stmt.public_inputs.hex(),
        "witness_x": x.hex(),
        "message": msg.hex(),
        "rho": rho.hex(),
        "proof_sha256": hashlib.sha256(proof).hexdigest(),
        "proof_b64": base64.b64encode(proof).decode("ascii"),
        "expected": ok,
    }


# ----------------------------------------------------------- mutated cases

def apply_edits(proof, edits):
    p = bytearray(proof)
    for e in edits:
        op = e["op"]
        if op == "xor":
            p[e["offset"]] ^= int(e["mask"], 16)
        elif op == "set":
            data = bytes.fromhex(e["data"])
            p[e["offset"]:e["offset"] + len(data)] = data
        elif op == "truncate":
            del p[e["length"]:]
        elif op == "append":
            p += bytes.fromhex(e["data"])
        elif op == "prepend":
            p[0:0] = bytes.fromhex(e["data"])
        else:
            raise ValueError(op)
    return bytes(p)


def sections(lay):
    """(name, offset, length, data bits) of every proof section; data bits is
    the number of meaningful bits (the rest of the last byte is padding)."""
    out = [("version", 0, 1, 8), ("statement id", 1, 1, 8),
           ("iv_pre", lay.off_iv_pre, 16, 128)]
    tau = lay.split.tau
    for i in range(tau - 1):
        out.append(("c_%d" % (i + 1), lay.off_c + i * lay.c_bytes, lay.c_bytes, lay.lhat))
    out.append(("u_tilde", lay.off_u_tilde, 32, 256))
    out.append(("d", lay.off_d, lay.d_bytes, lay.ell))
    out.append(("a_tilde", lay.off_a_tilde, 16, 128))
    for i in range(tau):
        off = lay.open_offsets[i]
        k = lay.split.depths[i]
        out.append(("open_%d co-path seeds" % i, off, k * 16, k * 128))
        out.append(("open_%d hidden commitment" % i, off + k * 16, 32, 256))
    out.append(("chall3", lay.off_chall3, 16, 128))
    return out


class Mutator:
    def __init__(self, valid, lay):
        self.valid = valid
        self.lay = lay
        self.cases = []
        self.secs = sections(lay)

    def add(self, kind, desc, base, edits=(), sid=None, pub=None, msg=None,
            msg_zeros=None):
        v = self.valid[base]
        case = {
            "id": "mut-%03d" % len(self.cases),
            "kind": kind,
            "description": desc,
            "base": base,
            "statement_id": v["statement_id"] if sid is None else sid,
            "public_inputs": v["public_inputs"] if pub is None else pub.hex(),
            "message": (v["message"] if msg is None else msg.hex()) if msg_zeros is None else None,
            "proof_edits": list(edits),
        }
        if msg_zeros is not None:
            case["message_zeros"] = msg_zeros
        self.cases.append(case)

    def flip_in(self, s, name, off, nbytes_, nbits):
        """A one-bit flip at a random data bit of a section."""
        pos = s.below(nbits)
        return {"op": "xor", "offset": off + pos // 8, "mask": "%02x" % (1 << (pos % 8))}

    def build(self, n_random_flips):
        lay = self.lay
        nv = len(self.valid)
        total = lay.total
        pick = Stream(b"mutation bases")
        # Mutated cases repeat their message in full, so bases come from the
        # cases with short messages; the long-message case gets its own edits.
        pool = [i for i, v in enumerate(self.valid) if len(v["message"]) <= 2 * 1024]
        long_msg = [i for i, v in enumerate(self.valid) if len(v["message"]) > 2 * 1024]

        def base():
            return pool[pick.below(len(pool))]

        for bi in long_msg:
            m0 = bytearray(bytes.fromhex(self.valid[bi]["message"]))
            m0[len(m0) // 2] ^= 0x01
            self.add("message", "bit flip in the middle of a %d-byte message" % len(m0), bi,
                     msg=bytes(m0))
            self.add("flip", "chall3 bit flip, %d-byte message" % len(m0), bi,
                     [{"op": "xor", "offset": lay.off_chall3 + 7, "mask": "10"}])

        # 1. Single-bit flips in every section.
        s = Stream(b"section flips")
        per_section = {"version": 0, "statement id": 0, "iv_pre": 4, "u_tilde": 4, "d": 6,
                       "a_tilde": 4, "chall3": 6}
        for name, off, nb, nbits in self.secs:
            if name.startswith("c_"):
                count = 3
            elif name.startswith("open_"):
                count = 2 if name.endswith("seeds") else 1
            else:
                count = per_section[name]
            for _ in range(count):
                e = self.flip_in(s, name, off, nb, nbits)
                self.add("flip", "bit flip in %s (byte %d)" % (name, e["offset"]), base(), [e])
        # Header bytes set to other values.
        for val in (0x00, 0x01, 0x02, 0x80, 0xFF):
            if val != VERSION:
                self.add("header", "version byte set to 0x%02x" % val, base(),
                         [{"op": "set", "offset": 0, "data": "%02x" % val}])
            if val != st.STATEMENT1_ID:
                self.add("header", "statement id byte set to 0x%02x" % val, base(),
                         [{"op": "set", "offset": 1, "data": "%02x" % val}])
        # Padding bits (lhat and ell are 7 mod 8: one padding bit each).
        for name, off, nb, nbits in self.secs:
            if nbits % 8:
                for pbit in range(nbits % 8, 8):
                    self.add("padding", "padding bit %d of %s set" % (pbit, name), base(),
                             [{"op": "xor", "offset": off + nb - 1, "mask": "%02x" % (1 << pbit)}])

        # 2. Multi-byte edits.
        s = Stream(b"multi-byte")
        for _ in range(40):
            pos = s.below(total)
            mask = 1 + s.below(255)
            self.add("byte", "byte %d XOR 0x%02x" % (pos, mask), base(),
                     [{"op": "xor", "offset": pos, "mask": "%02x" % mask}])
        for _ in range(20):
            a = self.secs[s.below(len(self.secs))]
            b = self.secs[s.below(len(self.secs))]
            ea = self.flip_in(s, a[0], a[1], a[2], a[3])
            eb = self.flip_in(s, b[0], b[1], b[2], b[3])
            if ea["offset"] == eb["offset"] and ea["mask"] == eb["mask"]:
                eb = {"op": "xor", "offset": (ea["offset"] + 1) % total, "mask": "01"}
            self.add("two-flips", "bit flips in %s and %s" % (a[0], b[0]), base(), [ea, eb])
        for name, off, nb, nbits in self.secs:
            if name in ("iv_pre", "u_tilde", "a_tilde", "chall3") or name in (
                    "open_0 co-path seeds", "open_9 hidden commitment", "c_7"):
                self.add("zero-section", "%s set to zero" % name, base(),
                         [{"op": "set", "offset": off, "data": "00" * nb}])

        # 3. Truncations and 4. extensions.
        s = Stream(b"lengths")
        lengths = [0, 1, 2, 17, 18, lay.off_u_tilde, lay.off_open, lay.off_chall3,
                   total - 16, total - 1] + [s.below(total) for _ in range(6)]
        for n in lengths:
            self.add("truncate", "proof truncated to %d bytes" % n, base(),
                     [{"op": "truncate", "length": n}])
        self.add("extend", "one zero byte appended", base(), [{"op": "append", "data": "00"}])
        self.add("extend", "one random byte appended", base(),
                 [{"op": "append", "data": s.bytes(1).hex()}])
        self.add("extend", "16 random bytes appended", base(),
                 [{"op": "append", "data": s.bytes(16).hex()}])
        b0 = base()
        self.add("extend", "proof appended to itself", b0,
                 [{"op": "append", "data": base64.b64decode(self.valid[b0]["proof_b64"]).hex()}])
        self.add("extend", "one byte prepended", base(), [{"op": "prepend", "data": "01"}])
        self.add("extend", "header repeated (two bytes prepended)", base(),
                 [{"op": "prepend", "data": "0101"}])
        self.add("extend", "last byte dropped, zero byte prepended", base(),
                 [{"op": "truncate", "length": total - 1}, {"op": "prepend", "data": "00"}])

        # 5. Wrong messages.
        s = Stream(b"messages")
        for _ in range(3):
            bi = base()
            m0 = bytes.fromhex(self.valid[bi]["message"])
            self.add("message", "message with one extra byte", bi, msg=m0 + s.bytes(1))
            if m0:
                self.add("message", "other random message of the same length", bi,
                         msg=s.bytes(len(m0)))
                self.add("message", "message without its last byte", bi, msg=m0[:-1])
                pos = s.below(8 * len(m0))
                mm = bytearray(m0)
                mm[pos // 8] ^= 1 << (pos % 8)
                self.add("message", "message bit flip", bi, msg=bytes(mm))
                self.add("message", "empty message", bi, msg=b"")
            else:
                self.add("message", "one zero byte instead of the empty message", bi,
                         msg=b"\x00")
            other = (bi + 1 + s.below(nv - 1)) % nv
            self.add("message", "message of another valid case", bi,
                     msg=bytes.fromhex(self.valid[other]["message"]))
        self.add("message", "message of 65,536 zero bytes (over the limit)", base(),
                 msg_zeros=MAX_MESSAGE_LEN + 1)

        # 6. Wrong and malformed statements.
        s = Stream(b"statements")
        for _ in range(2):
            bi = base()
            pub0 = bytes.fromhex(self.valid[bi]["public_inputs"])
            key, suffix, y = st.s1_parse_public(pub0)
            enc = st.s1_encode_public
            other_key = s.printable(1 + s.below(64))
            if other_key == key:
                other_key = other_key[:-1] + bytes([0x20 + (other_key[-1] - 0x1f) % 95])
            self.add("statement", "other random K", bi, pub=enc(other_key, suffix, y))
            kk = bytearray(key)
            j = s.below(len(kk))
            kk[j] = 0x20 + (kk[j] - 0x20 + 1 + s.below(94)) % 95
            self.add("statement", "K with one character changed", bi, pub=enc(bytes(kk), suffix, y))
            if len(key) < 64:
                self.add("statement", "K with one character appended", bi,
                         pub=enc(key + b"a", suffix, y))
            if len(key) > 1:
                self.add("statement", "K without its last character", bi,
                         pub=enc(key[:-1], suffix, y))
            self.add("statement", "suffix XOR 1", bi, pub=enc(key, suffix ^ 1, y))
            self.add("statement", "suffix + 128", bi, pub=enc(key, (suffix + 128) % 256, y))
            pos = s.below(256)
            yy = bytearray(y)
            yy[pos // 8] ^= 1 << (pos % 8)
            self.add("statement", "y bit flip", bi, pub=enc(key, suffix, bytes(yy)))
            other = (bi + 1 + s.below(nv - 1)) % nv
            oy = bytes.fromhex(self.valid[other]["y"])
            self.add("statement", "y of another valid case", bi, pub=enc(key, suffix, oy))
            for sid in (0x00, 0x02, 0xFF):
                self.add("statement", "statement id 0x%02x" % sid, bi, sid=sid)
            # Malformed public-input encodings.
            self.add("malformed", "K length byte 0", bi, pub=b"\x00" + pub0[1:])
            self.add("malformed", "K length byte 65 with 65 bytes of K", bi,
                     pub=bytes([65]) + s.printable(65) + bytes([suffix]) + y)
            for bad in (0x1F, 0x7F, 0x80, 0x00):
                kb = bytearray(key)
                kb[s.below(len(kb))] = bad
                self.add("malformed", "K contains byte 0x%02x" % bad, bi,
                         pub=bytes([len(kb)]) + bytes(kb) + bytes([suffix]) + y)
            self.add("malformed", "public inputs with a trailing byte", bi, pub=pub0 + b"\x00")
            self.add("malformed", "public inputs without the last byte", bi, pub=pub0[:-1])
            self.add("malformed", "empty public inputs", bi, pub=b"")
            self.add("malformed", "length byte one too large", bi,
                     pub=bytes([pub0[0] + 1]) + pub0[1:])

        # 7. Proofs moved between instances and sections swapped between proofs.
        s = Stream(b"cross")
        for _ in range(10):
            a = base()
            b = (a + 1 + s.below(nv - 1)) % nv
            self.add("cross", "proof of %s with statement and message of %s"
                     % (self.valid[a]["id"], self.valid[b]["id"]), a,
                     pub=bytes.fromhex(self.valid[b]["public_inputs"]),
                     msg=bytes.fromhex(self.valid[b]["message"]))
        for _ in range(4):
            a = base()
            b = (a + 1 + s.below(nv - 1)) % nv
            self.add("cross", "proof of %s with statement of %s, own message"
                     % (self.valid[a]["id"], self.valid[b]["id"]), a,
                     pub=bytes.fromhex(self.valid[b]["public_inputs"]))
        swap_names = ["iv_pre", "c_1", "c_15", "u_tilde", "d", "a_tilde", "chall3",
                      "open_3 co-path seeds", "open_12 hidden commitment"]
        tau = lay.split.tau
        for name in swap_names + ["c_%d" % (2 + s.below(tau - 3)),
                                  "open_%d co-path seeds" % s.below(tau)]:
            sec = [x for x in self.secs if x[0] == name][0]
            a = base()
            b = (a + 1 + s.below(nv - 1)) % nv
            pb = base64.b64decode(self.valid[b]["proof_b64"])
            self.add("swap", "%s taken from the proof of %s" % (name, self.valid[b]["id"]), a,
                     [{"op": "set", "offset": sec[1], "data": pb[sec[1]:sec[1] + sec[2]].hex()}])

        # 8. Random bodies with a valid header and zero padding (full verifier work).
        s = Stream(b"random bodies")
        for r in range(3):
            body = bytearray(s.bytes(total))
            body[0] = VERSION
            body[1] = st.STATEMENT1_ID
            for name, off, nb, nbits in self.secs:
                if nbits % 8:
                    body[off + nb - 1] &= (1 << (nbits % 8)) - 1
            self.add("random-body", "random proof body %d (valid header, zero padding)" % r,
                     base(), [{"op": "set", "offset": 0, "data": bytes(body).hex()}])
        b0 = base()
        self.add("random-body", "all-zero body with a valid header", b0,
                 [{"op": "set", "offset": 2, "data": "00" * (total - 2)}])
        self.add("random-body", "chall3 replaced by random bytes", base(),
                 [{"op": "set", "offset": lay.off_chall3, "data": s.bytes(16).hex()}])

        # 9. Uniformly random single-bit flips anywhere in the proof.
        s = Stream(b"random flips")
        for _ in range(n_random_flips):
            pos = s.below(8 * total)
            self.add("random-flip", "bit %d of byte %d" % (pos % 8, pos // 8), base(),
                     [{"op": "xor", "offset": pos // 8, "mask": "%02x" % (1 << (pos % 8))}])
        return self.cases


def verify_case(args):
    sid, pub_hex, msg, proof = args
    stmt = voleith.Statement(sid, bytes.fromhex(pub_hex))
    t0 = time.perf_counter()
    ok = voleith.verify(stmt, msg, proof)
    return ok, time.perf_counter() - t0


def case_message(case):
    if case["message"] is None:
        return bytes(case["message_zeros"])
    return bytes.fromhex(case["message"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--valid", type=int, default=100)
    ap.add_argument("--random-flips", type=int, default=60)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("output", nargs="?", default=os.path.join(
        HERE, "..", "..", "vectors", "statement1-v0.2-differential.json"))
    args = ap.parse_args()

    lay = P.layout(st.STATEMENT1_ID)
    t0 = time.time()
    with multiprocessing.Pool(args.jobs) as pool:
        valid = pool.map(make_valid, range(args.valid), chunksize=1)
        bad = [v["id"] for v in valid if v["expected"] is not True]
        if bad:
            raise SystemExit("valid cases that do not verify: %s" % bad)
        print("valid cases: %d (%.0f s)" % (len(valid), time.time() - t0), flush=True)

        cases = Mutator(valid, lay).build(args.random_flips)
        work = []
        for c in cases:
            proof = apply_edits(base64.b64decode(valid[c["base"]]["proof_b64"]), c["proof_edits"])
            work.append((c["statement_id"], c["public_inputs"], case_message(c), proof))
        results = pool.map(verify_case, work, chunksize=1)
    for c, (ok, _) in zip(cases, results):
        c["expected"] = ok
    n_true = sum(1 for c in cases if c["expected"])
    print("mutated cases: %d, of which the Python verifier accepts %d (%.0f s)"
          % (len(cases), n_true, time.time() - t0), flush=True)

    kinds = {}
    for c in cases:
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    doc = {
        "format": FORMAT,
        "spec": "SPEC.md v0.2",
        "statement_id": st.STATEMENT1_ID,
        "proof_len": lay.total,
        "generator": "python/tools/gen_differential.py",
        "master_seed": MASTER_SEED.decode("ascii"),
        "stream_note": ("case inputs come from SHAKE256(master_seed || '/' || label || "
                        "u64le(counter)); labels: 'valid <i>', 'section flips', 'multi-byte', "
                        "'lengths', 'messages', 'statements', 'cross', 'random bodies', "
                        "'random flips', 'mutation bases'"),
        "rng_note": "the prover calls rng(32) exactly once; rho is that output",
        "edit_note": ("proof_edits apply in order to the decoded proof of valid[base]: "
                      "xor(offset, mask), set(offset, data), truncate(length), append(data), "
                      "prepend(data); message null means message_zeros zero bytes"),
        "counts": {"valid": len(valid), "mutated": len(cases),
                   "mutated_accepted_by_python": n_true, "mutated_by_kind": kinds},
        "valid": valid,
        "mutated": cases,
    }
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote", os.path.normpath(args.output), os.path.getsize(args.output), "bytes")


if __name__ == "__main__":
    main()
