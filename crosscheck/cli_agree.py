"""The three verify commands agree (NOTES.md, "2026-10-23 tools and
verifier-only build").

Usage: python3 -I crosscheck/cli_agree.py <work dir> <command> ...
where each command is a verify command line prefix, e.g.
  rust/target/release/voleith-verify
  "python3 -I python/tools/verify_cli.py"
  crosscheck/work/voleith-verify-go
(crosscheck/cli.sh builds and passes all three).

Cases, each run through every command with the same arguments:
- the 4 proofs of vectors/statement1-v0.2.json (valid);
- 20 cases of vectors/statement1-v0.2-differential.json: 10 valid ones
  (every tenth) and 10 mutated ones, the first of each of ten kinds whose
  statement a command line can express (statement 0x01, canonical public
  inputs); the file gives each expected verdict;
- usage errors and edge cases that must give exit code 2 or 1 everywhere.

Every command must give exactly the expected exit code (0 valid, 1
invalid, 2 usage error) and stdout ("valid\\n", "invalid\\n" or nothing).
Standard library only.
"""

import base64
import json
import os
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC = os.path.join(ROOT, "vectors", "statement1-v0.2.json")
DIFF = os.path.join(ROOT, "vectors", "statement1-v0.2-differential.json")


def parse_pub(pub):
    """(K, suffix, y) of a canonical statement 0x01 encoding, or None."""
    if len(pub) < 1 or not 1 <= pub[0] <= 64 or len(pub) != pub[0] + 34:
        return None
    k = pub[1:1 + pub[0]]
    if any(not 0x20 <= c <= 0x7E for c in k):
        return None
    return k.decode("ascii"), pub[1 + pub[0]], pub[2 + pub[0]:]


def apply_edits(proof, edits):
    b = bytearray(proof)
    for e in edits:
        op = e["op"]
        if op == "xor":
            b[e["offset"]] ^= int(e["mask"], 16)
        elif op == "set":
            d = bytes.fromhex(e["data"])
            b[e["offset"]:e["offset"] + len(d)] = d
        elif op == "truncate":
            del b[e["length"]:]
        elif op == "append":
            b += bytes.fromhex(e["data"])
        elif op == "prepend":
            b[0:0] = bytes.fromhex(e["data"])
        else:
            raise ValueError(op)
    return bytes(b)


def cases(work):
    """(name, args, expected exit code)."""
    out = []

    def add(name, k, suffix, y, msg, proof, expect):
        path = os.path.join(work, name + ".bin")
        with open(path, "wb") as f:
            f.write(proof)
        args = ["--k", k, "--suffix", str(suffix), "--y-hex", y.hex(),
                "--msg-hex", msg.hex(), "--proof", path]
        out.append((name, args, expect))
        return args

    with open(VEC, encoding="utf-8") as f:
        vec = json.load(f)
    for i, v in enumerate(vec["vectors"]):
        add("vector-%d" % i, v["K_ascii"], v["suffix"], bytes.fromhex(v["y"]),
                bytes.fromhex(v["message"]), bytes.fromhex(v["proof"]), 0)
    first = out[0][1]

    with open(DIFF, encoding="utf-8") as f:
        diff = json.load(f)
    valid = diff["valid"]
    for v in valid[::10]:
        assert v["expected"] is True
        add(v["id"], v["K_ascii"], v["suffix"], bytes.fromhex(v["y"]),
            bytes.fromhex(v["message"]), base64.b64decode(v["proof_b64"]), 0)
    kinds = set()
    for m in diff["mutated"]:
        if len(kinds) == 10:
            break
        if m["kind"] in kinds or m["statement_id"] != 1:
            continue
        p = parse_pub(bytes.fromhex(m["public_inputs"]))
        if p is None:
            continue
        if m["message"] is None:
            msg = bytes(m["message_zeros"])
        else:
            msg = bytes.fromhex(m["message"])
        if len(msg) > 65535:
            continue
        base = base64.b64decode(valid[m["base"]]["proof_b64"])
        proof = apply_edits(base, m["proof_edits"])
        assert m["expected"] is False
        kinds.add(m["kind"])
        add(m["id"] + "-" + m["kind"], p[0], p[1], p[2], msg, proof, 1)
    assert len(kinds) == 10, kinds

    # Usage errors and edge cases, from the arguments of vector 0.
    def edit(i, value):
        a = list(first)
        a[i] = value
        return a

    missing = os.path.join(work, "does-not-exist.bin")
    usage = [
        ("k-empty", edit(1, ""), 2),
        ("k-65", edit(1, "k" * 65), 2),
        ("k-64", edit(1, "~" * 64), 1),
        ("k-tab", edit(1, "a\tb"), 2),
        ("k-del", edit(1, "a\x7f"), 2),
        ("k-non-ascii", edit(1, "café"), 2),
        ("suffix-256", edit(3, "256"), 2),
        ("suffix-neg", edit(3, "-1"), 2),
        ("suffix-lead0", edit(3, "01"), 2),
        ("suffix-plus", edit(3, "+1"), 2),
        ("suffix-space", edit(3, " 1"), 2),
        ("suffix-2^32", edit(3, "4294967296"), 2),
        ("suffix-2^64", edit(3, "18446744073709551616"), 2),
        ("suffix-long", edit(3, "9" * 400), 2),
        ("suffix-000", edit(3, "000"), 2),
        ("y-63", edit(5, first[5][:63]), 2),
        ("y-65", edit(5, first[5] + "0"), 2),
        ("y-nonhex", edit(5, first[5][:63] + "g"), 2),
        ("y-space", edit(5, first[5][:62] + " 0"), 2),
        ("y-upper", edit(5, first[5].upper()), 0),
        ("msg-odd", edit(7, "0"), 2),
        ("msg-nonhex", edit(7, "zz"), 2),
        ("msg-space", edit(7, "00 00"), 2),
        ("msg-empty", edit(7, ""), 1),
        ("msg-65535", edit(7, "00" * 65535), 1),
        ("msg-too-long", edit(7, "0" * 131071), 2),
        ("proof-missing", edit(9, missing), 2),
        ("proof-dir", edit(9, work), 2),
        ("no-args", [], 2),
        ("missing-proof", first[:8], 2),
        ("repeated", first + ["--k", "x"], 2),
        ("unknown", first + ["--x", "1"], 2),
        ("dangling", first + ["--k"], 2),
        ("single-dash", ["-k"] + first[1:], 2),
        ("equals-form", ["--k=" + first[1]] + first[2:], 2),
        ("double-dash", first + ["--"], 2),
    ]
    short = os.path.join(work, "short.bin")
    with open(short, "wb") as f:
        f.write(b"\x02\x01")
    usage.append(("proof-short", edit(9, short), 1))
    long = os.path.join(work, "long.bin")
    with open(first[9], "rb") as f, open(long, "wb") as g:
        g.write(f.read() + b"\x00")
    usage.append(("proof-long", edit(9, long), 1))
    return out, usage


def run(cmd, args):
    r = subprocess.run(shlex.split(cmd) + args, stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=600)
    return r.returncode, r.stdout


def main():
    work, cmds = sys.argv[1], sys.argv[2:]
    os.makedirs(work, exist_ok=True)
    proofs, usage = cases(work)
    want_out = {0: b"valid\n", 1: b"invalid\n", 2: b""}
    bad = 0
    counts = {}
    for group, items in (("proofs", proofs), ("usage", usage)):
        for name, args, expect in items:
            got = [run(c, args) for c in cmds]
            ok = all(g == (expect, want_out[expect]) for g in got)
            counts[(group, ok)] = counts.get((group, ok), 0) + 1
            if not ok:
                bad += 1
                print("MISMATCH %s: expected %d, got %s" % (
                    name, expect, [(g[0], g[1].decode(errors="replace").strip())
                                   for g in got]))
    n_valid = sum(1 for _, _, e in proofs if e == 0)
    print("commands: %d" % len(cmds))
    print("proof cases: %d (%d valid, %d invalid), agreeing with the expected verdict: %d"
          % (len(proofs), n_valid, len(proofs) - n_valid, counts.get(("proofs", True), 0)))
    print("usage and edge cases: %d, agreeing: %d"
          % (len(usage), counts.get(("usage", True), 0)))
    print("mismatches: %d" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
