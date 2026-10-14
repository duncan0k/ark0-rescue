"""Measure prove/verify time of the Python reference (NOTES.md).

Usage: python -I python/tools/bench.py [runs]
"""

import hashlib
import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import voleith  # noqa: E402
from voleith import statements as st  # noqa: E402


def main():
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    t0 = time.perf_counter()
    st.REGISTRY[st.STATEMENT1_ID].circuit()
    t_build = time.perf_counter() - t0
    key = b"ark0-wallet v1 schnorr"
    msg = hashlib.sha256(b"bench").digest() * 3
    tp, tv = [], []
    for i in range(runs):
        x = os.urandom(32)
        stmt = voleith.statement1_for_seed(key, i % 256, x)
        t0 = time.perf_counter()
        proof = voleith.prove(stmt, x, msg)
        t1 = time.perf_counter()
        ok = voleith.verify(stmt, msg, proof)
        t2 = time.perf_counter()
        if not ok:
            raise SystemExit("verification failed")
        tp.append(t1 - t0)
        tv.append(t2 - t1)
    print("python", platform.python_version(), platform.machine(), platform.processor())
    print("circuit build (once): %.3f s" % t_build)
    print("proof bytes: %d" % len(proof))
    print("prove  median %.3f s  min %.3f s  max %.3f s  (%d runs)"
          % (statistics.median(tp), min(tp), max(tp), runs))
    print("verify median %.3f s  min %.3f s  max %.3f s  (%d runs)"
          % (statistics.median(tv), min(tv), max(tv), runs))


if __name__ == "__main__":
    main()
