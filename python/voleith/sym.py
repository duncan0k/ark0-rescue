"""Domain-separated SHAKE256 calls (SPEC.md §3).

Every hash, PRG and random-oracle call in the protocol is

    SHAKE256( u8(len(T)) || T || data , out_len )

with the ASCII tag T = "VOLEitH-rescue/" + VERSION_LABEL + "/" + name.
Every `data` is a concatenation of fixed-length fields, or of fields whose
length is fixed by the statement id, or of explicitly length-prefixed fields,
so each tag's input encoding is injective.
"""

import hashlib

from .params import VERSION_LABEL

_PREFIX = "VOLEitH-rescue/" + VERSION_LABEL + "/"

TAG_NAMES = ("mu", "rnd", "iv", "root", "ggm", "leaf", "exp", "tree", "hcom",
             "ch1", "hv", "ch2", "ch3")


def _encode_tag(name):
    if name not in TAG_NAMES:
        raise ValueError("unknown tag " + name)
    t = (_PREFIX + name).encode("ascii")
    return bytes([len(t)]) + t


_TAGS = {n: _encode_tag(n) for n in TAG_NAMES}


def tag_bytes(name):
    return _TAGS[name]


def xof(name, data, out_len):
    """SHAKE256 over the encoded tag followed by `data`."""
    h = hashlib.shake_256(_TAGS[name])
    h.update(data)
    return h.digest(out_len)


def xof_parts(name, parts, out_len):
    h = hashlib.shake_256(_TAGS[name])
    for p in parts:
        h.update(p)
    return h.digest(out_len)


def u8(v):
    return bytes([v])


def u16le(v):
    return v.to_bytes(2, "little")


def u64le(v):
    return v.to_bytes(8, "little")
