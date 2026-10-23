"""Verify a statement 0x01 proof (SPEC.md §11) from the command line.

Usage:
  python -I python/tools/verify_cli.py --k <ascii K> --suffix <0..255>
      --y-hex <64 hex> --msg-hex <hex> --proof <file>

Prints "valid" and exits 0 for a valid proof, prints "invalid" and exits 1
for an invalid one, and exits 2 with a message on standard error for a usage
error. The same command line gives the same result with the Rust
voleith-verify and the Go go/cmd/voleith-verify:

- every option is "--name value" (two arguments), given exactly once; an
  unknown, missing or repeated option is a usage error;
- --k: 1 to 64 bytes, each in 0x20..0x7E;
- --suffix: a decimal integer 0..255 without sign or leading zeros;
- --y-hex: exactly 64 hexadecimal digits;
- --msg-hex: an even number of hexadecimal digits, at most 131,070 (65,535
  bytes); may be empty;
- --proof: a readable file; one of the wrong length is an invalid proof.

Hexadecimal digits may be upper or lower case. Standard library only.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import voleith  # noqa: E402

USAGE = ("usage: verify_cli.py --k <ascii K> --suffix <0..255> --y-hex <64 hex> "
         "--msg-hex <hex> --proof <file>")
NAMES = ("k", "suffix", "y-hex", "msg-hex", "proof")
MAX_MESSAGE_LEN = 65535
HEX = frozenset(b"0123456789abcdefABCDEF")


class Usage(Exception):
    pass


def parse_options(args):
    out = {}
    i = 0
    while i < len(args):
        a = args[i]
        name = a[2:] if a.startswith("--") else None
        if name not in NAMES:
            raise Usage("unknown argument")
        if i + 1 >= len(args):
            raise Usage("--%s needs a value" % name)
        if name in out:
            raise Usage("--%s given twice" % name)
        out[name] = args[i + 1]
        i += 2
    for n in NAMES:
        if n not in out:
            raise Usage("--%s missing" % n)
    return out


def arg_bytes(s):
    """The bytes of a command-line argument as the operating system gave them."""
    return os.fsencode(s)


def parse_k(s):
    k = arg_bytes(s)
    if not 1 <= len(k) <= 64:
        raise Usage("--k: K must be 1 to 64 bytes long")
    if any(not 0x20 <= c <= 0x7E for c in k):
        raise Usage("--k: K must be printable ASCII (0x20..0x7E)")
    return k


def parse_suffix(s):
    b = arg_bytes(s)
    ok = (1 <= len(b) <= 3 and all(0x30 <= c <= 0x39 for c in b)
          and (b[0] != 0x30 or len(b) == 1))
    if not ok or int(b) > 255:
        raise Usage("--suffix: must be a decimal integer from 0 to 255")
    return int(b)


def parse_hex(name, s, max_bytes):
    b = arg_bytes(s)
    if len(b) > 2 * max_bytes:
        raise Usage("--%s: longer than %d bytes" % (name, max_bytes))
    if len(b) % 2:
        raise Usage("--%s: odd number of hexadecimal digits" % name)
    if any(c not in HEX for c in b):
        raise Usage("--%s: not hexadecimal" % name)
    return bytes.fromhex(b.decode("ascii"))


def parse_y(s):
    if len(arg_bytes(s)) != 64:
        raise Usage("--y-hex: must be exactly 64 hexadecimal digits")
    return parse_hex("y-hex", s, 32)


def run(args):
    o = parse_options(args)
    key = parse_k(o["k"])
    suffix = parse_suffix(o["suffix"])
    y = parse_y(o["y-hex"])
    msg = parse_hex("msg-hex", o["msg-hex"], MAX_MESSAGE_LEN)
    limit = voleith.proof_length(voleith.STATEMENT1_ID)
    try:
        with open(o["proof"], "rb") as f:
            proof = f.read(limit + 1)
    except OSError as e:
        raise Usage("--proof: cannot read the file: %s" % e.strerror)
    if len(proof) > limit:
        return False
    try:
        return voleith.verify(voleith.statement1(key, suffix, y), msg, proof) is True
    except Exception as e:  # SPEC.md §11: any internal error is a rejection
        sys.stderr.write("verify_cli.py: internal error, rejected: %r\n" % (e,))
        return False


def main():
    try:
        ok = run(sys.argv[1:])
    except Usage as e:
        sys.stderr.write("verify_cli.py: %s\n%s\n" % (e, USAGE))
        return 2
    print("valid" if ok else "invalid")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
