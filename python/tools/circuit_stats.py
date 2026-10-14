"""Print gate counts, witness size and proof size (SPEC.md §7.5, §10).

Usage: python -I python/tools/circuit_stats.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from voleith import proof as P  # noqa: E402
from voleith import sha256_gadgets as g  # noqa: E402
from voleith import statements as st  # noqa: E402


def main():
    gen = g.build_compression_circuit()
    print("SHA-256 compression, all 768 inputs variable:")
    print("  counts:", gen.counts())
    print("  digest:", gen.digest())
    c = st.REGISTRY[st.STATEMENT1_ID].circuit()
    lay = P.layout(st.STATEMENT1_ID)
    print("Statement 0x01 (HMAC-SHA256, two compressions):")
    print("  counts:", c.counts())
    print("  public bits:", c.n_public, " secret input bits:", c.n_secret)
    print("  witness bits ell:", c.n_witness, " constraints C:", c.n_constraints)
    print("  lhat:", lay.lhat, " correction bytes:", lay.c_bytes, " d bytes:", lay.d_bytes)
    print("  proof bytes:", lay.total)
    print("  circuit digest:", c.digest())


if __name__ == "__main__":
    main()
