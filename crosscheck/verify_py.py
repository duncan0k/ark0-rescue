"""Python-reference driver: python3 -I verify_py.py <python_dir> <cases.tsv>
<proofs.txt> <tests.tsv> <verdicts.tsv> [workers]. Same formats as the Rust
driver (src/main.rs)."""
import multiprocessing
import sys
import time

sys.path.insert(0, sys.argv[1])
import voleith  # noqa: E402
from voleith.statements import Statement  # noqa: E402

unhex = lambda s: b"" if s == "-" else bytes.fromhex(s)
CASES, PROOFS = None, None


def load(cases_path, proofs_path):
    global CASES, PROOFS
    CASES = [l.rstrip("\n").split("\t") for l in open(cases_path) if l.strip()]
    PROOFS = [unhex(l.strip()) for l in open(proofs_path) if l.strip()]


def run(line):
    f = line.rstrip("\n").split("\t")
    ci, target, bit = int(f[1]), f[3], int(f[4])
    pub, msg, proof = unhex(CASES[ci][1]), bytearray(unhex(CASES[ci][2])), bytearray(PROOFS[ci])
    if target == "proof":
        proof[bit // 8] ^= 1 << (bit % 8)
    elif target == "msg":
        if bit < 0:
            msg.append(0)
        else:
            msg[bit // 8] ^= 1 << (bit % 8)
    elif target == "pub":
        pub = unhex(f[5])
    else:
        assert target == "none", target
    try:
        ok = voleith.verify(Statement(0x01, pub), bytes(msg), bytes(proof)) is True
    except Exception as e:  # an exception is a bug; report it as a distinct verdict
        sys.stderr.write("python: test %s raised %r\n" % (f[0], e))
        return f[0], "E"
    return f[0], "1" if ok else "0"


def main():
    _, _, cases_path, proofs_path, tests_path, out_path = sys.argv[:6]
    workers = int(sys.argv[6]) if len(sys.argv) > 6 else 4
    tests = [l for l in open(tests_path) if l.strip()]
    t = time.time()
    with multiprocessing.Pool(workers, initializer=load, initargs=(cases_path, proofs_path)) as p:
        res = p.map(run, tests, chunksize=4)
    with open(out_path, "w") as f:
        for ti, v in res:
            f.write("%s\t%s\n" % (ti, v))
    sys.stderr.write("python: verified %d tests in %.1f s (%d workers)\n"
                     % (len(tests), time.time() - t, workers))


if __name__ == "__main__":
    main()
