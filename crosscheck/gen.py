"""Generate the cross-check cases and tests.

  python3 gen.py <seed> <outdir>

Writes <outdir>/cases.tsv (100 statement 0x01 cases) and <outdir>/tests.tsv
(per case: the valid proof, 5 proof bit flips, 1 message change, 1 statement
change). y = HMAC-SHA256(K, x || u8(suffix)) is computed with Python's hmac
module, independently of every implementation under test.

Proof bit flips walk the SPEC.md §10 layout field by field (every seed and
commitment of every opening is its own field), round-robin, so 500 flips
cover all 182 fields at least twice.
"""
import hashlib
import hmac
import os
import random
import sys

TAU, TAU0 = 24, 8
C_BYTES, D_BYTES = 5307, 5259
PROOF_LEN = 130218


def sections():
    s = [("version", 0, 1), ("statement_id", 1, 1), ("iv_pre", 2, 16)]
    off = 18
    for i in range(1, TAU):
        s.append(("c_%d" % i, off, C_BYTES))
        off += C_BYTES
    assert off == 122079
    s += [("u_tilde", 122079, 32), ("d", 122111, D_BYTES), ("a_tilde", 127370, 16)]
    off = 127386
    for i in range(TAU):
        for d in range(6 if i < TAU0 else 5):
            s.append(("open_%d_seed_%d" % (i, d), off, 16))
            off += 16
        s.append(("open_%d_com" % i, off, 32))
        off += 32
    assert off == 130202
    s.append(("chall3", 130202, 16))
    pos = 0
    for _, start, n in s:
        assert start == pos
        pos += n
    assert pos == PROOF_LEN
    return s


PRINTABLE = bytes(range(0x20, 0x7F))


def encode_public(k, suffix, y):
    return bytes([len(k)]) + k + bytes([suffix]) + y


def main():
    seed, out = int(sys.argv[1]), sys.argv[2]
    rng = random.Random(seed)
    os.makedirs(out, exist_ok=True)
    secs = sections()
    cases, tests = [], []
    flip_no = 0
    for ci in range(100):
        k = bytes(rng.choice(PRINTABLE) for _ in range(rng.randint(1, 64)))
        suffix = rng.randint(0, 255)
        x = rng.randbytes(32)
        y = hmac.new(k, x + bytes([suffix]), hashlib.sha256).digest()
        mlen = [0, 1, 96, rng.randint(0, 4096), 65535][ci % 5]
        msg = rng.randbytes(mlen)
        rho = rng.randbytes(32)
        pub = encode_public(k, suffix, y)
        cases.append((ci, pub, msg, x, rho))
        h = lambda b: b.hex() if b else "-"
        tests.append(("valid", ci, "valid", "none", -1, "-"))
        for _ in range(5):
            name, start, n = secs[flip_no % len(secs)]
            flip_no += 1
            tests.append(("flip:" + name, ci, "proof_bit", "proof",
                          8 * start + rng.randrange(8 * n), "-"))
        if mlen:
            tests.append(("msg_bit", ci, "msg_bit", "msg", rng.randrange(8 * mlen), "-"))
        else:
            tests.append(("msg_append", ci, "msg_append", "msg", -1, "-"))
        kind = ci % 3
        if kind == 0:  # one bit of y
            yb = bytearray(y)
            b = rng.randrange(256)
            yb[b // 8] ^= 1 << (b % 8)
            np, what = encode_public(k, suffix, bytes(yb)), "stmt_y_bit"
        elif kind == 1:  # another suffix
            np, what = encode_public(k, suffix ^ rng.randint(1, 255), y), "stmt_suffix"
        else:  # one character of K replaced by another printable one
            kb = bytearray(k)
            i = rng.randrange(len(k))
            kb[i] = rng.choice([c for c in PRINTABLE if c != kb[i]])
            np, what = encode_public(bytes(kb), suffix, y), "stmt_key_char"
        tests.append((what, ci, what, "pub", -1, np.hex()))
    with open(os.path.join(out, "cases.tsv"), "w") as f:
        for ci, pub, msg, x, rho in cases:
            f.write("%d\t%s\t%s\t%s\t%s\n" % (ci, h(pub), h(msg), h(x), h(rho)))
    with open(os.path.join(out, "tests.tsv"), "w") as f:
        for ti, (label, ci, kind, target, bit, np) in enumerate(tests):
            f.write("%d\t%d\t%s\t%s\t%d\t%s\t%s\n" % (ti, ci, kind, target, bit, np, label))
    print("wrote %d cases, %d tests (%d proof flips over %d fields)"
          % (len(cases), len(tests), flip_no, len(secs)))


if __name__ == "__main__":
    main()
