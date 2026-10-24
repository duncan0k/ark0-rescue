"""Check an strace log of execve and execveat calls against an allow-list.

Usage:
  python3 -I exec_trace.py pin PINS.json [--tool PATH]... [--proxy PATH OTHER]... [--dir DIR]...
  python3 -I exec_trace.py LOG --root PATH [--expect PATH]... [--pins PINS.json]
      [--allow PATH]... [--allow-link PATH TARGET]... [--allow-prefix DIR]...
      [--allow-build-scripts DIR]...

Every path is a whole argument of its own (--proxy and --allow-link take
two), never two paths joined by a separator, so paths may hold `=`,
`->` or spaces.
  python3 -I exec_trace.py verify PINS.json
  python3 -I exec_trace.py stderr STRACE_PATH < standard error of the traced build

`pin` records, before the builds, for each tool: the path as written,
what it resolves to, and that file's device, inode and SHA-256; for each
directory: the path, what it resolves to, and its device and inode (no
hash). A --proxy PATH OTHER must be the same file as OTHER
(os.path.samefile), which holds whether rustup installed PATH as a
symbolic link to OTHER or as a hard link of it. `--pins` checks a log
against that fixed record instead of resolving the tools again, and
`verify` checks, after the builds, that nothing in the record changed.

The log comes from

  strace -f --quiet=attach,personality -e trace=execve,execveat \\
      -e signal=none -o LOG PATH ...

`--quiet=attach,personality` is strace's -q without the second q: exits
are still written (`PID +++ exited with N +++`), which the end-of-log
check below needs; -qq would hide them. Every line must have one of these
forms, or the check fails:

  PID execve("PATH", ...) = RESULT
  PID execveat(AT_FDCWD, "PATH", ...) = RESULT
  PID execve("PATH", ... <unfinished ...>        (completed later by)
  PID <... execve resumed>...) = RESULT          (the same PID)
  PID +++ exited with N +++
  PID +++ killed by SIGNAME +++                  (also "(core dumped)")
  PID +++ superseded by execve in pid N +++

RESULT is `0` (the program ran) or `-1 ERRNO (text)` (it did not).
Unfinished and resumed lines are joined per PID. A resumed line without
its unfinished line, an unfinished line never resumed, a result of `?`, a
path with an escape (a backslash), and an execveat whose directory is not
AT_FDCWD or whose path is not absolute (the program it ran cannot be
named) all fail the check, as does any other line.

The log must end normally: its first line is the root process's exec of
the --root program (= 0), its last line is that process's
`+++ exited with 0 +++`, and every --expect program ran. An empty log, a
log cut off after any line before the root's exit, and a log without the
root's exit all fail. This catches a trace that strace could not finish
writing in an ordinary build; it is not a proof against someone who can
write to the log or the disk during the build (README.md, "Windows").

Every program that ran must be an absolute path without empty, `.` or
`..` components, and be allowed both as written and resolved
(os.path.realpath, against the resolved allowed place): an --allow entry
exactly, which is --allow PATH (resolving to itself: not a link) or
--allow-link PATH TARGET (a link that must resolve to TARGET), so that a
tool that has become a link elsewhere fails; under an --allow-prefix
directory (or a pinned directory, against its pinned resolved form); or,
for --allow-build-scripts
DIR, exactly DIR/<one component>/build-script-build (cargo's layout of
host build scripts: <target dir>/<profile>/build/<package>-<hash>/).
Exit 0 and a summary if so; exit 1 with the reasons otherwise.
"""

import os
import re
import sys

_PID = r"(?P<pid>\d+)\s+"
_PATH = r'"(?P<path>[^"\\]*)"'
_RESULT = r"\)\s*=\s*(?P<result>0|-1 [A-Z0-9]+ \(.*\))$"
_CALL = (r"(?P<call>execve)\(" + _PATH
         + r"|(?P<call2>execveat)\((?P<dirfd>[A-Z_0-9]+), " + _PATH.replace("path", "path2"))
FULL = re.compile(_PID + "(?:" + _CALL + ")" + r".*?" + _RESULT)
UNFINISHED = re.compile(_PID + "(?:" + _CALL + ")" + r".* <unfinished \.\.\.>$")
RESUMED = re.compile(_PID + r"<\.\.\. (?P<call>execve|execveat) resumed>.*?" + _RESULT)
EXITED = re.compile(_PID + r"\+\+\+ exited with (?P<status>\d+) \+\+\+$")
KILLED = re.compile(_PID + r"\+\+\+ killed by SIG[A-Z0-9]+( \(core dumped\))? \+\+\+$")
SUPERSEDED = re.compile(_PID + r"\+\+\+ superseded by execve in pid \d+ \+\+\+$")


class Log:
    """What a log says: execs that ran (pid, path, line), exit lines
    (pid, status or None, line), the first and last lines, and errors."""

    def __init__(self):
        self.ran, self.exits, self.errors = [], [], []
        self.first = None  # (kind, pid, path, result)
        self.last = None   # (kind, pid, status)


def parse(lines):
    log, pending = Log(), {}

    def target(m, n):
        if m.group("call"):
            return m.group("call"), m.group("path")
        dirfd, path = m.group("dirfd"), m.group("path2")
        if dirfd != "AT_FDCWD" or not path.startswith("/"):
            log.errors.append("line %d: execveat(%s, %r) does not name the program" % (n, dirfd, path))
            return "execveat", None
        return "execveat", path

    def done(pid, path, result, n, first):
        if first and log.first is None:
            log.first = ("exec", pid, path, result)
        if result == "0" and path is not None:
            log.ran.append((pid, path, n))
        log.last = ("exec", pid, None)

    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        is_first = log.first is None and not pending
        m = FULL.match(line)
        if m:
            call, path = target(m, n)
            done(m.group("pid"), path, m.group("result"), n, is_first)
            continue
        m = UNFINISHED.match(line)
        if m:
            pid = m.group("pid")
            if pid in pending:
                log.errors.append("line %d: PID %s has two unfinished execs" % (n, pid))
            call, path = target(m, n)
            pending[pid] = (call, path, n, is_first)
            log.last = ("unfinished", pid, None)
            continue
        m = RESUMED.match(line)
        if m:
            pid = m.group("pid")
            if pid not in pending:
                log.errors.append("line %d: resumed exec of PID %s without its start" % (n, pid))
                continue
            call, path, start, was_first = pending.pop(pid)
            if call != m.group("call"):
                log.errors.append("line %d: %s resumed as %s" % (n, call, m.group("call")))
                continue
            done(pid, path, m.group("result"), n, was_first)
            continue
        for rx, kind in ((EXITED, "exited"), (KILLED, "killed"), (SUPERSEDED, "superseded")):
            m = rx.match(line)
            if m:
                break
        if m:
            pid = m.group("pid")
            if log.first is None and not pending:
                log.first = (kind, pid, None, None)
            status = int(m.group("status")) if kind == "exited" else None
            if kind != "superseded":
                log.exits.append((pid, status, n))
            log.last = (kind, pid, status)
            continue
        log.errors.append("line %d: cannot parse: %s" % (n, line[:200]))
        log.last = ("unparsable", None, None)
    for pid, (call, path, start, _) in sorted(pending.items()):
        log.errors.append("line %d: exec of PID %s never resumed" % (start, pid))
    return log


def path_error(p):
    """Why `p` is not an acceptable program path, or None."""
    if not p.startswith("/"):
        return "is not absolute"
    comps = p[1:].split("/")
    if any(c in ("", ".", "..") for c in comps):
        return "has an empty, . or .. component"
    return None


def _under(p, d):
    return p.startswith(d.rstrip("/") + "/")


def _build_script(p, d):
    if not _under(p, d):
        return False
    rest = p[len(d.rstrip("/")) + 1:].split("/")
    return len(rest) == 2 and rest[0] not in ("", ".", "..") and rest[1] == "build-script-build"


def split_allow(a):
    """(path, the file it must resolve to) of an allowed tool or place: a
    pair as given, or a path that must resolve to itself. Paths are never
    joined into one string, so a path may hold any character."""
    if isinstance(a, tuple):
        return a
    return a, a


def allowed(p, allow, prefixes, build_dirs, real=os.path.realpath):
    """Whether `p` is allowed, as written and resolved."""
    rp = real(p)
    if any(p == path and rp == target for path, target in map(split_allow, allow)):
        return True
    if any(_under(p, d) and _under(rp, target) for d, target in map(split_allow, prefixes)):
        return True
    return any(_build_script(p, d) and _build_script(rp, real(d)) for d in build_dirs)


def check(lines, root, expect, allow, prefixes, build_dirs, real=os.path.realpath):
    """(sorted distinct programs that ran, errors)."""
    log = parse(lines)
    errors = list(log.errors)
    places = [x for a in list(allow) + list(prefixes) for x in split_allow(a)]
    for place in [root] + list(expect) + places + list(build_dirs):
        why = path_error(place)
        if why:
            errors.append("allowed place %s %s" % (place, why))
    # A normal end: the root's exec first, its exit 0 last, every expected
    # program run.
    if log.first is None:
        errors.append("the log is empty")
        root_pid = None
    elif log.first[0] != "exec" or log.first[2] != root or log.first[3] != "0":
        errors.append("the log does not start with the exec of %s" % root)
        root_pid = None
    else:
        root_pid = log.first[1]
    if root_pid is not None and log.last != ("exited", root_pid, 0):
        errors.append("the log does not end with the exit (0) of the root process %s: "
                      "incomplete or cut off" % root_pid)
    progs = sorted(set(p for _, p, _ in log.ran))
    for e in expect:
        if e not in progs:
            errors.append("expected %s to run, it did not" % e)
    for p in progs:
        why = path_error(p)
        if why:
            errors.append("ran %s, which %s" % (p, why))
        elif not allowed(p, allow, prefixes, build_dirs, real):
            errors.append("ran %s, which is not allowed" % p)
    return progs, errors


def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _identity(path):
    st = os.stat(path)
    return {"dev": st.st_dev, "ino": st.st_ino}


def pin(tools, proxies, dirs):
    """The pin record: for each tool, the path as written, the file it
    resolves to (os.path.realpath), that file's device, inode and SHA-256;
    for each proxy (PATH, OTHER), the same, after checking that PATH is the
    same file as OTHER (os.path.samefile: a symbolic link to it or a hard
    link of it); for each directory, the path, its resolved form, device
    and inode. Raises ValueError on a bad path or a proxy that is another
    file."""
    rec = {"tools": [], "dirs": []}
    for path, same_as in [(t, None) for t in tools] + [tuple(p) for p in proxies]:
        why = path_error(path)
        if why:
            raise ValueError("%s %s" % (path, why))
        if same_as is not None and not os.path.samefile(path, same_as):
            raise ValueError("%s is not the same file as %s" % (path, same_as))
        resolved = os.path.realpath(path)
        if not os.path.isfile(resolved):
            raise ValueError("%s does not resolve to a file" % path)
        e = {"path": path, "resolved": resolved, "sha256": _sha256(resolved)}
        e.update(_identity(resolved))
        if same_as is not None:
            e["same_as"] = same_as
        rec["tools"].append(e)
    for d in dirs:
        why = path_error(d)
        if why:
            raise ValueError("%s %s" % (d, why))
        e = {"path": d, "resolved": os.path.realpath(d)}
        e.update(_identity(e["resolved"]))
        rec["dirs"].append(e)
    return rec


def unchanged(rec):
    """Errors if anything recorded by pin() has changed."""
    errors = []
    for e in rec["tools"] + rec["dirs"]:
        try:
            resolved = os.path.realpath(e["path"])
            if resolved != e["resolved"]:
                errors.append("%s now resolves to %s, not %s" % (e["path"], resolved, e["resolved"]))
                continue
            if _identity(resolved) != {"dev": e["dev"], "ino": e["ino"]}:
                errors.append("%s is another file now (device or inode)" % resolved)
            if "sha256" in e and _sha256(resolved) != e["sha256"]:
                errors.append("%s has changed (SHA-256)" % resolved)
            if "same_as" in e and not os.path.samefile(e["path"], e["same_as"]):
                errors.append("%s is no longer the same file as %s" % (e["path"], e["same_as"]))
        except OSError as x:
            errors.append("%s: %s" % (e["path"], x))
    return errors


def load_pins(f):
    """The pin record in file F, checked to have the structure pin()
    writes; raises ValueError otherwise, so that a malformed pin file is
    reported like any other bad input, not with a traceback."""
    import json
    rec = json.load(f)

    def bad(why):
        raise ValueError("malformed pin file: %s" % why)

    def is_int(v):
        return isinstance(v, int) and not isinstance(v, bool)

    if not isinstance(rec, dict) or set(rec) != {"tools", "dirs"}:
        bad("not an object with exactly 'tools' and 'dirs'")
    for kind, keys, optional in (("tools", {"path", "resolved", "dev", "ino", "sha256"}, {"same_as"}),
                                 ("dirs", {"path", "resolved", "dev", "ino"}, set())):
        if not isinstance(rec[kind], list):
            bad("'%s' is not a list" % kind)
        for i, e in enumerate(rec[kind]):
            if not isinstance(e, dict) or not keys <= set(e) <= keys | optional:
                bad("%s[%d] does not have the fields %s" % (kind, i, sorted(keys)))
            for k in ("path", "resolved") + (("same_as",) if "same_as" in e else ()):
                if not isinstance(e[k], str):
                    bad("%s[%d].%s is not a string" % (kind, i, k))
            if not (is_int(e["dev"]) and is_int(e["ino"])):
                bad("%s[%d].dev or .ino is not an integer" % (kind, i))
            if "sha256" in e and not (isinstance(e["sha256"], str)
                                      and re.fullmatch(r"[0-9a-f]{64}", e["sha256"])):
                bad("%s[%d].sha256 is not 64 hex digits" % (kind, i))
    return rec


def pinned_places(rec):
    """(--allow entries, --allow-prefix entries) from a pin record."""
    return ([(e["path"], e["resolved"]) for e in rec["tools"]],
            [(e["path"], e["resolved"]) for e in rec["dirs"]])


def options(argv, arity):
    """[(option, [values])] for ARGV, where ARITY maps each option to its
    number of values; every value is a whole argument, never split."""
    out, i = [], 0
    while i < len(argv):
        opt = argv[i]
        if opt not in arity:
            raise ValueError("unknown option %s" % opt)
        n = arity[opt]
        vals = argv[i + 1:i + 1 + n]
        if len(vals) != n:
            raise ValueError("%s takes %d value(s)" % (opt, n))
        out.append((opt, vals))
        i += 1 + n
    return out


def main_pin(argv):
    """pin OUT.json [--tool PATH]... [--proxy PATH OTHER]... [--dir DIR]..."""
    import json
    out, tools, proxies, dirs = argv[0], [], [], []
    for opt, vals in options(argv[1:], {"--tool": 1, "--proxy": 2, "--dir": 1}):
        if opt == "--proxy":
            proxies.append(tuple(vals))
        else:
            {"--tool": tools, "--dir": dirs}[opt].append(vals[0])
    rec = pin(tools, proxies, dirs)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1, sort_keys=True)
    for e in rec["tools"]:
        print("pinned %s %s -> %s (device %d, inode %d)"
              % (e["sha256"], e["path"], e["resolved"], e["dev"], e["ino"]))
    for e in rec["dirs"]:
        print("pinned directory %s -> %s (device %d, inode %d)"
              % (e["path"], e["resolved"], e["dev"], e["ino"]))
    return 0


def strace_lines(text, strace="/usr/bin/strace"):
    """The lines of a traced build's standard error that strace wrote (its
    messages start with "<its path>: " or "strace: "); compiler warnings
    and other lines of cargo and rustc are not."""
    prefixes = (strace + ": ", "strace: ")
    return [l for l in text.splitlines() if l.startswith(prefixes)]


def main_stderr(argv):
    """stderr STRACE_PATH < text: exit 1 if strace wrote any line."""
    bad = strace_lines(sys.stdin.read(), argv[0])
    for l in bad:
        sys.stderr.write("exec_trace.py: strace: %s\n" % l)
    return 1 if bad else 0


def main_verify(argv):
    """verify PINS.json"""
    import json
    with open(argv[0], encoding="utf-8") as f:
        rec = load_pins(f)
    errors = unchanged(rec)
    for e in errors:
        sys.stderr.write("exec_trace.py: %s\n" % e)
    if errors:
        return 1
    print("pins: %d tools and %d directories unchanged" % (len(rec["tools"]), len(rec["dirs"])))
    return 0


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    try:
        if argv[0] == "pin":
            return main_pin(argv[1:])
        if argv[0] == "verify":
            return main_verify(argv[1:])
        if argv[0] == "stderr":
            return main_stderr(argv[1:])
    except (ValueError, KeyError, OSError, IndexError) as e:
        sys.stderr.write("exec_trace.py: %s: %s\n" % (argv[0], e))
        return 1
    try:
        return main_check(argv[0], argv[1:])
    except (ValueError, OSError, UnicodeDecodeError, KeyError) as e:
        sys.stderr.write("exec_trace.py: %s\n" % e)
        return 1


def main_check(log, rest):
    """LOG --root PATH [--expect PATH]... [--pins PINS.json] [--allow PATH]...
    [--allow-link PATH TARGET]... [--allow-prefix DIR]... [--allow-build-scripts DIR]..."""
    import json
    root, expect, allow, prefixes, build_dirs = None, [], [], [], []
    arity = {"--root": 1, "--expect": 1, "--allow": 1, "--allow-link": 2, "--allow-prefix": 1,
             "--allow-build-scripts": 1, "--pins": 1}
    for opt, vals in options(rest, arity):
        if opt == "--root":
            root = vals[0]
        elif opt == "--expect":
            expect.append(vals[0])
        elif opt == "--allow":
            allow.append(vals[0])
        elif opt == "--allow-link":
            allow.append(tuple(vals))
        elif opt == "--allow-prefix":
            prefixes.append(vals[0])
        elif opt == "--allow-build-scripts":
            build_dirs.append(vals[0])
        else:  # --pins
            with open(vals[0], encoding="utf-8") as f:
                a, p = pinned_places(load_pins(f))
            allow.extend(a)
            prefixes.extend(p)
    if root is None:
        raise ValueError("--root is required")
    with open(log, encoding="utf-8", errors="strict") as f:
        lines = f.readlines()
    progs, errors = check(lines, root, expect, allow, prefixes, build_dirs)
    for e in errors:
        sys.stderr.write("exec_trace.py: %s\n" % e)
    if errors:
        return 1
    print("exec trace: %d lines, ends with the exit 0 of root %s, %d distinct programs ran, all allowed"
          % (len(lines), root, len(progs)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
