"""Check an strace log of execve and execveat calls against an allow-list.

Usage:
  python3 -I exec_trace.py LOG [--allow PATH]... [--allow-prefix DIR]...
      [--allow-glob PATTERN]...

The log comes from `strace -f -qq -e trace=execve,execveat -e signal=none
-o LOG`. Every line must have one of these forms, or the check fails:

  PID execve("PATH", ...) = RESULT
  PID execveat(AT_FDCWD, "PATH", ...) = RESULT
  PID execve("PATH", ... <unfinished ...>        (completed later by)
  PID <... execve resumed>...) = RESULT          (the same PID)

RESULT is `0` (the program ran) or `-1 ERRNO (text)` (it did not). With
-f, an exec that another traced process interrupts is written as an
unfinished line and a resumed line; they are joined per PID. A resumed
line without its unfinished line, an unfinished line never resumed, a
result of `?`, a path with an escape (a backslash), and an execveat whose
directory is not AT_FDCWD or whose path is not absolute (the program it
ran cannot be named) all fail the check, as does any other line.

Every program that ran must be an --allow path, under an --allow-prefix
directory, or match an --allow-glob (fnmatch, where * also matches /).
Exit 0 and a summary if so; exit 1 with the reasons otherwise.
"""

import fnmatch
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


def parse(lines):
    """(programs that ran, errors) for the lines of a log."""
    ran, errors, pending = [], [], {}

    def target(m, n):
        if m.group("call"):
            return m.group("call"), m.group("path"), None
        dirfd, path = m.group("dirfd"), m.group("path2")
        if dirfd != "AT_FDCWD" or not path.startswith("/"):
            errors.append("line %d: execveat(%s, %r) does not name the program" % (n, dirfd, path))
            return "execveat", None, None
        return "execveat", path, None

    def finish(path, result):
        if result == "0" and path is not None:
            ran.append(path)

    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        m = FULL.match(line)
        if m:
            call, path, _ = target(m, n)
            finish(path, m.group("result"))
            continue
        m = UNFINISHED.match(line)
        if m:
            pid = m.group("pid")
            if pid in pending:
                errors.append("line %d: PID %s has two unfinished execs" % (n, pid))
            call, path, _ = target(m, n)
            pending[pid] = (call, path, n)
            continue
        m = RESUMED.match(line)
        if m:
            pid = m.group("pid")
            if pid not in pending:
                errors.append("line %d: resumed exec of PID %s without its start" % (n, pid))
                continue
            call, path, start = pending.pop(pid)
            if call != m.group("call"):
                errors.append("line %d: %s resumed as %s" % (n, call, m.group("call")))
                continue
            finish(path, m.group("result"))
            continue
        errors.append("line %d: cannot parse: %s" % (n, line[:200]))
    for pid, (call, path, start) in sorted(pending.items()):
        errors.append("line %d: exec of PID %s never resumed" % (start, pid))
    return ran, errors


def check(lines, allow, prefixes, globs):
    """(sorted distinct programs that ran, errors)."""
    ran, errors = parse(lines)
    progs = sorted(set(ran))
    for p in progs:
        ok = (p in allow
              or any(p.startswith(d.rstrip("/") + "/") for d in prefixes)
              or any(fnmatch.fnmatchcase(p, g) for g in globs))
        if not ok:
            errors.append("ran %s, which is not allowed" % p)
    return progs, errors


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    log, rest = argv[0], argv[1:]
    allow, prefixes, globs = set(), [], []
    if len(rest) % 2:
        sys.stderr.write("exec_trace.py: options take one value each\n")
        return 2
    for opt, val in zip(rest[::2], rest[1::2]):
        if opt == "--allow":
            allow.add(val)
        elif opt == "--allow-prefix":
            prefixes.append(val)
        elif opt == "--allow-glob":
            globs.append(val)
        else:
            sys.stderr.write("exec_trace.py: unknown option %s\n" % opt)
            return 2
    with open(log, encoding="utf-8", errors="strict") as f:
        lines = f.readlines()
    progs, errors = check(lines, allow, prefixes, globs)
    for e in errors:
        sys.stderr.write("exec_trace.py: %s\n" % e)
    if errors:
        return 1
    print("exec trace: %d exec lines, %d distinct programs ran, all allowed"
          % (len(lines), len(progs)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
