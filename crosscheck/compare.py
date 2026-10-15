"""Compare the verdicts of the three verifiers:
  python3 compare.py <workdir> <findings_dir>
Expected: accept for kind "valid", reject for every other test, identical
across rust, python and go. Every disagreement, and every test where all
three agree on the wrong verdict, is saved under <findings_dir>."""
import collections
import json
import os
import sys

work, findings = sys.argv[1], sys.argv[2]
impls = ["rust", "python", "go"]
verdicts = {}
for i in impls:
    verdicts[i] = dict(l.rstrip("\n").split("\t") for l in open(os.path.join(work, "verdicts-%s.tsv" % i)) if l.strip())
tests = [l.rstrip("\n").split("\t") for l in open(os.path.join(work, "tests.tsv")) if l.strip()]
cases = [l.rstrip("\n").split("\t") for l in open(os.path.join(work, "cases.tsv")) if l.strip()]
proofs = [l.strip() for l in open(os.path.join(work, "proofs.txt")) if l.strip()]
stats = collections.Counter()
bad = 0
for t in tests:
    ti, ci, kind = t[0], int(t[1]), t[2]
    want = "1" if kind == "valid" else "0"
    got = {i: verdicts[i].get(ti, "missing") for i in impls}
    stats[(kind, "/".join(got[i] for i in impls))] += 1
    if any(v != want for v in got.values()):
        bad += 1
        os.makedirs(findings, exist_ok=True)
        rec = {"test": t, "expected": want, "verdicts": got,
               "case": cases[ci], "proof_hex": proofs[ci]}
        with open(os.path.join(findings, "test-%s.json" % ti), "w") as f:
            json.dump(rec, f)
for (kind, v), n in sorted(stats.items()):
    print("%-14s rust/python/go = %-7s %4d" % (kind, v, n))
print("tests %d, mismatches %d" % (len(tests), bad))
sys.exit(1 if bad else 0)
