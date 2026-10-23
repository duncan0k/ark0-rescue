"""Check an strace log of execve and execveat calls against an allow-list.

Usage:
  python3 -I exec_trace.py LOG --root PATH [--expect PATH]...
      [--allow PATH]... [--allow-prefix DIR]... [--allow-build-scripts DIR]...

The log comes from

  strace -f --quiet=attach,personality -e trace=execve,execveat \\
      -e signal=none -o LOG PATH ...

`--quiet=attach,personality` is strace's -q without the second q: exits
are still written (`PID +++ exited with N +++`), which the completeness
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

The log must be complete: its first line is the root process's exec of
the --root program (= 0), its last line is that process's
`+++ exited with 0 +++`, and every --expect program ran. An empty log, a
log cut off after any line before the root's exit, and a log without the
root's exit all fail.

Every program that ran must be an absolute path without empty, `.` or
`..` components, and be allowed both as written and resolved
(os.path.realpath, against the resolved allowed place): an --allow entry
exactly, which is `PATH` (resolving to itself: not a link) or
`PATH->TARGET` (a link that must resolve to TARGET), so that a tool that
has become a link elsewhere fails; under an --allow-prefix directory; or,
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
    """(path, the file it must resolve to) of an --allow entry."""
    path, sep, target = a.partition("->")
    return path, (target if sep else path)


def allowed(p, allow, prefixes, build_dirs, real=os.path.realpath):
    """Whether `p` is allowed, as written and resolved."""
    rp = real(p)
    if any(p == path and rp == target for path, target in map(split_allow, allow)):
        return True
    if any(_under(p, d) and _under(rp, real(d)) for d in prefixes):
        return True
    return any(_build_script(p, d) and _build_script(rp, real(d)) for d in build_dirs)


def check(lines, root, expect, allow, prefixes, build_dirs, real=os.path.realpath):
    """(sorted distinct programs that ran, errors)."""
    log = parse(lines)
    errors = list(log.errors)
    places = [x for a in allow for x in split_allow(a)]
    for place in [root] + list(expect) + places + list(prefixes) + list(build_dirs):
        why = path_error(place)
        if why:
            errors.append("allowed place %s %s" % (place, why))
    # Completeness: the root's exec first, its exit 0 last, every expected
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


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    log, rest = argv[0], argv[1:]
    root, expect, allow, prefixes, build_dirs = None, [], [], [], []
    if len(rest) % 2:
        sys.stderr.write("exec_trace.py: options take one value each\n")
        return 2
    for opt, val in zip(rest[::2], rest[1::2]):
        if opt == "--root":
            root = val
        elif opt == "--expect":
            expect.append(val)
        elif opt == "--allow":
            allow.append(val)
        elif opt == "--allow-prefix":
            prefixes.append(val)
        elif opt == "--allow-build-scripts":
            build_dirs.append(val)
        else:
            sys.stderr.write("exec_trace.py: unknown option %s\n" % opt)
            return 2
    if root is None:
        sys.stderr.write("exec_trace.py: --root is required\n")
        return 2
    with open(log, encoding="utf-8", errors="strict") as f:
        lines = f.readlines()
    progs, errors = check(lines, root, expect, allow, prefixes, build_dirs)
    for e in errors:
        sys.stderr.write("exec_trace.py: %s\n" % e)
    if errors:
        return 1
    print("exec trace: %d lines, complete (root %s exited 0), %d distinct programs ran, all allowed"
          % (len(lines), root, len(progs)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
