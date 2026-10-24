"""Tests of exec_trace.py on recorded strace lines.

Run: python3 -I rust/windows/test_exec_trace.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import exec_trace as et  # noqa: E402

TC = "/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu"
RUSTC = TC + "/bin/rustc"
PROXY = "/root/.cargo/bin/cargo"
CARGO = TC + "/bin/cargo"
BUILD = "/b/windows-build-1/cli/build"

# Lines as strace 6.8 wrote them for build-windows.sh (arguments shortened).
ROOT_EXEC = '5200  execve("%s", ["%s", "build"], 0x7ffd /* 9 vars */) = 0\n' % (PROXY, PROXY)
ROOT_CARGO = '5200  execve("%s", ["%s"..., "build"], 0x5550 /* 14 vars */) = 0\n' % (CARGO, CARGO[:32])
COMPLETE = ('5221  execve("/usr/bin/x86_64-w64-mingw32-dlltool", ["/usr/bin/x86_64-w64-mingw32-dllt"..., '
            '"-d", "/tmp/x"...], 0x55d0 /* 12 vars */) = 0\n')
SPLIT = [
    '5223  execve("%s", ["%s"..., "--crate-name", "cfg_if"], 0x5600 /* 14 vars */ <unfinished ...>\n'
    % (RUSTC, RUSTC[:32]),
    '5224  execve("%s", ["%s"..., "--crate-name", "keccak"], 0x5601 /* 14 vars */ <unfinished ...>\n'
    % (RUSTC, RUSTC[:32]),
    "5223  <... execve resumed>)             = 0\n",
    "5224  <... execve resumed>)             = 0\n",
]
FAILED = ('5230  execve("/root/.cargo/bin/cc", ["cc", "-m64"], 0x5602 /* 14 vars */) '
          '= -1 ENOENT (No such file or directory)\n')
EXECVEAT_OK = ('5240  execveat(AT_FDCWD, "/usr/bin/x86_64-w64-mingw32-as", ["as"], 0x5603 /* 3 vars */, 0) '
               '= 0\n')
EXECVEAT_FD = '5241  execveat(3, "", ["x"], 0x5604 /* 3 vars */, AT_EMPTY_PATH) = 0\n'
EXECVEAT_REL = '5242  execveat(AT_FDCWD, "as", ["as"], 0x5605 /* 3 vars */, 0) = 0\n'
CHILD_EXITS = ["5221  +++ exited with 0 +++\n", "5223  +++ exited with 0 +++\n",
               "5224  +++ exited with 1 +++\n", "5240  +++ killed by SIGKILL +++\n"]
ROOT_EXIT = "5200  +++ exited with 0 +++\n"

ALLOW = [(PROXY, "/root/.cargo/bin/rustup"), "/usr/bin/x86_64-w64-mingw32-dlltool",
         "/usr/bin/x86_64-w64-mingw32-as"]
LINKS = {PROXY: "/root/.cargo/bin/rustup"}


def whole(middle=None):
    """A complete log: the root's execs, `middle`, the children's exits and
    the root's exit."""
    if middle is None:
        middle = SPLIT + [COMPLETE, FAILED, EXECVEAT_OK]
    return [ROOT_EXEC, ROOT_CARGO] + middle + CHILD_EXITS + [ROOT_EXIT]


def run_check(lines, expect=(CARGO, RUSTC), allow=ALLOW, prefixes=(TC,), build_dirs=(BUILD,), real=None):
    return et.check(lines, PROXY, list(expect), list(allow), list(prefixes), list(build_dirs),
                    real or (lambda p: LINKS.get(p, os.path.normpath(p))))


class Parse(unittest.TestCase):
    def test_complete_line(self):
        log = et.parse([COMPLETE])
        self.assertEqual([p for _, p, _ in log.ran], ["/usr/bin/x86_64-w64-mingw32-dlltool"])
        self.assertEqual(log.errors, [])

    def test_split_lines_are_joined_per_pid(self):
        log = et.parse(SPLIT)
        self.assertEqual(log.errors, [])
        self.assertEqual([p for _, p, _ in log.ran], [RUSTC, RUSTC])

    def test_split_failed_exec_is_not_a_run(self):
        log = et.parse([SPLIT[0], "5223  <... execve resumed>)             = -1 EACCES (Permission denied)\n"])
        self.assertEqual((log.ran, log.errors), ([], []))

    def test_failed_exec_is_not_a_run(self):
        log = et.parse([FAILED])
        self.assertEqual((log.ran, log.errors), ([], []))

    def test_execveat(self):
        self.assertEqual([p for _, p, _ in et.parse([EXECVEAT_OK]).ran], ["/usr/bin/x86_64-w64-mingw32-as"])
        for line in (EXECVEAT_FD, EXECVEAT_REL):
            errors = et.parse([line]).errors
            self.assertEqual(len(errors), 1, line)
            self.assertIn("does not name the program", errors[0])

    def test_split_execveat(self):
        log = et.parse(['7  execveat(AT_FDCWD, "/bin/true", ["true"], 0x1 /* 1 var */, 0 <unfinished ...>\n',
                        "7  <... execveat resumed>) = 0\n"])
        self.assertEqual(([p for _, p, _ in log.ran], log.errors), (["/bin/true"], []))

    def test_exit_lines(self):
        log = et.parse(CHILD_EXITS + ["9  +++ killed by SIGSEGV (core dumped) +++\n",
                                      "9  +++ superseded by execve in pid 8 +++\n"])
        self.assertEqual(log.errors, [])
        self.assertEqual(len(log.exits), 5)

    def test_unparsable_lines_fail(self):
        bad = [
            "garbage\n",
            '5250  execve("/usr/bin/a\\"b", ["x"], 0x1 /* 1 var */) = 0\n',  # escaped path
            '5251  execve("/usr/bin/x", ["x"], 0x1 /* 1 var */) = ?\n',      # no result
            "5252  +++ exited with x +++\n",
            '5253  open("/etc/passwd", O_RDONLY) = 3\n',
            '5254  execve("/usr/bin/x", ["x"]',                                # cut off
            "5255  --- SIGCHLD {si_signo=SIGCHLD} ---\n",
            "strace: /dev/full: No space left on device\n",
        ]
        for line in bad:
            log = et.parse([line])
            self.assertTrue(log.errors, line)
            self.assertEqual(log.ran, [], line)

    def test_unpaired_split_lines_fail(self):
        self.assertTrue(et.parse([SPLIT[0]]).errors)  # never resumed
        self.assertTrue(et.parse([SPLIT[2]]).errors)  # resumed without start
        self.assertTrue(et.parse([SPLIT[0], SPLIT[0]]).errors)  # two unfinished
        self.assertTrue(et.parse([SPLIT[0], "5223  <... execveat resumed>) = 0\n"]).errors)


class Complete(unittest.TestCase):
    def test_whole_log_passes(self):
        progs, errors = run_check(whole())
        self.assertEqual(errors, [])
        self.assertEqual(len(progs), 5)

    def test_empty_log(self):
        for lines in ([], ["\n", "\n"]):
            errors = run_check(lines)[1]
            self.assertIn("the log is empty", errors)

    def test_cut_after_any_complete_line(self):
        log = whole()
        for k in range(1, len(log)):  # every prefix that ends before the root's exit
            errors = run_check(log[:k])[1]
            self.assertTrue(any("does not end with the exit" in e or "never resumed" in e for e in errors),
                            "cut after line %d passed" % k)

    def test_without_the_roots_exit(self):
        errors = run_check(whole()[:-1])[1]
        self.assertTrue(any("does not end with the exit (0) of the root process 5200" in e for e in errors))

    def test_root_exit_not_last_or_not_zero(self):
        log = whole()
        errors = run_check(log[:-1] + ["5200  +++ exited with 101 +++\n"])[1]
        self.assertTrue(any("does not end with the exit" in e for e in errors))
        errors = run_check(log[:-1] + [ROOT_EXIT, COMPLETE])[1]
        self.assertTrue(any("does not end with the exit" in e for e in errors))

    def test_first_line_must_be_the_roots_exec(self):
        errors = run_check(whole()[1:])[1]
        self.assertIn("the log does not start with the exec of %s" % PROXY, errors)
        errors = run_check([FAILED] + whole())[1]
        self.assertIn("the log does not start with the exec of %s" % PROXY, errors)

    def test_expected_programs_must_run(self):
        errors = run_check(whole([COMPLETE]))[1]
        self.assertIn("expected %s to run, it did not" % RUSTC, errors)


class Paths(unittest.TestCase):
    def run_one(self, path, real=None):
        line = '6000  execve("%s", ["x"], 0x1 /* 1 var */) = 0\n' % path
        return run_check(whole(SPLIT + [line, "6000  +++ exited with 0 +++\n"]), real=real)[1]

    def test_review_examples(self):
        for p in ("/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu/../../evil",
                  "/b/windows-build-1/../../evil/build/x/build-script-build",
                  "/b/windows-build-1/cli/build/../../../evil/build/x/build-script-build"):
            errors = self.run_one(p)
            self.assertTrue(any(p in e and "component" in e for e in errors), (p, errors))

    def test_bad_components(self):
        for p in ("usr/bin/as", "/usr//bin/as", "/usr/bin/./as", "/usr/bin/as/", TC + "/./bin/rustc"):
            self.assertTrue(any("component" in e or "not absolute" in e for e in self.run_one(p)), p)

    def test_build_script_layout(self):
        self.assertEqual(self.run_one(BUILD + "/getrandom-a39b601e21c5b728/build-script-build"), [])
        for p in (BUILD + "/a/b/build-script-build",            # two components
                  BUILD + "/build-script-build",                # none
                  BUILD + "/x/build-script-build-2",            # another name
                  "/b/windows-build-1/other/build/x/build-script-build"):
            self.assertTrue(any("not allowed" in e for e in self.run_one(p)), p)

    def test_prefix_is_a_whole_directory(self):
        self.assertTrue(any("not allowed" in e for e in self.run_one(TC + "-evil/rustc")))

    def test_resolved_path_must_stay_in_place(self):
        # A symlink inside the toolchain that points outside it.
        links = dict(LINKS, **{TC + "/bin/link": "/evil/rustc"})
        real = lambda p: links.get(p, os.path.normpath(p))  # noqa: E731
        errors = self.run_one(TC + "/bin/link", real=real)
        self.assertTrue(any("not allowed" in e for e in errors), errors)
        # An allowed tool that has become a link elsewhere.
        links = dict(LINKS, **{"/usr/bin/x86_64-w64-mingw32-as": "/tmp/evil-as"})
        errors = run_check(whole(), real=lambda p: links.get(p, os.path.normpath(p)))[1]
        self.assertTrue(any("x86_64-w64-mingw32-as, which is not allowed" in e for e in errors), errors)

    def test_link_entries(self):
        # The proxy must resolve to rustup; resolving elsewhere fails.
        links = {PROXY: "/tmp/evil-cargo"}
        errors = run_check(whole(), real=lambda p: links.get(p, os.path.normpath(p)))[1]
        self.assertTrue(any(PROXY + ", which is not allowed" in e for e in errors), errors)

    def test_failed_exec_of_anything_is_fine(self):
        self.assertEqual(run_check(whole(SPLIT + [FAILED.replace("/root/.cargo/bin/cc", "/../x")]))[1], [])


class Stderr(unittest.TestCase):
    def test_warnings_pass_strace_lines_fail(self):
        self.assertEqual(et.strace_lines("warning: unused variable: `x`\n   Compiling foo\n"), [])
        self.assertEqual(et.strace_lines(""), [])
        self.assertEqual(et.strace_lines("note: strace: not at the start\n"), [])
        text = ("warning: x\n/usr/bin/strace: /dev/full: No space left on device\n"
                "strace: write: Input/output error\n")
        self.assertEqual(len(et.strace_lines(text)), 2)
        self.assertEqual(et.strace_lines("/opt/strace: x\n", "/opt/strace"), ["/opt/strace: x"])


class Pins(unittest.TestCase):
    """pin() and unchanged() on real files in a fresh temporary directory."""

    def setUp(self):
        import tempfile
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="exec-trace-test."))
        self.rustup = os.path.join(self.d, "rustup")
        with open(self.rustup, "wb") as f:
            f.write(b"rustup binary")
        self.tool = os.path.join(self.d, "tool")
        with open(self.tool, "wb") as f:
            f.write(b"tool binary")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d)

    def proxy(self, kind):
        cargo = os.path.join(self.d, "cargo-" + kind)
        (os.symlink if kind == "symlink" else os.link)(self.rustup, cargo)
        return cargo

    def test_proxy_as_symbolic_or_hard_link(self):
        for kind in ("symlink", "hardlink"):
            cargo = self.proxy(kind)
            rec = et.pin([self.tool], [(cargo, self.rustup)], [self.d])
            e = rec["tools"][1]
            self.assertEqual(e["path"], cargo)
            self.assertEqual(e["resolved"], self.rustup if kind == "symlink" else cargo)
            self.assertEqual(et.unchanged(rec), [], kind)
            # The pinned entry admits the proxy's exec in a log.
            allow, prefixes = et.pinned_places(rec)
            log = ['1  execve("%s", ["cargo"], 0x1 /* 1 var */) = 0\n' % cargo,
                   "1  +++ exited with 0 +++\n"]
            self.assertEqual(et.check(log, cargo, [], allow, prefixes, [])[1], [], kind)

    def test_proxy_that_is_another_file_fails(self):
        other = os.path.join(self.d, "cargo-copy")
        with open(other, "wb") as f:
            f.write(b"rustup binary")
        with self.assertRaises(ValueError):
            et.pin([], [(other, self.rustup)], [])

    def test_changes_after_pinning_are_found(self):
        link = os.path.join(self.d, "ld")
        os.symlink(self.tool, link)
        rec = et.pin([link], [], [self.d])
        self.assertEqual(et.unchanged(rec), [])
        with open(self.tool, "ab") as f:  # same file, new content
            f.write(b"!")
        self.assertTrue(any("SHA-256" in e for e in et.unchanged(rec)))
        rec = et.pin([link], [], [])
        evil = os.path.join(self.d, "evil")
        with open(evil, "wb") as f:
            f.write(b"evil")
        os.remove(link)
        os.symlink(evil, link)  # the link now points elsewhere
        self.assertTrue(any("now resolves to" in e for e in et.unchanged(rec)))
        rec = et.pin([self.tool], [], [])
        with open(self.tool, "rb") as f:
            same = f.read()
        new = self.tool + ".new"
        with open(new, "wb") as f:  # replaced by a copy: another inode
            f.write(same)
        os.replace(new, self.tool)
        errors = et.unchanged(rec)
        self.assertTrue(any("another file" in e for e in errors), errors)

    def test_paths_with_separators(self):
        # A CARGO_HOME with `=`, `->` and a space: pinned and checked as is.
        home = os.path.join(self.d, "a=b->c d")
        os.mkdir(home)
        rustup = os.path.join(home, "rustup")
        with open(rustup, "wb") as f:
            f.write(b"rustup")
        cargo = os.path.join(home, "cargo")
        os.symlink(rustup, cargo)
        pins = os.path.join(self.d, "pins.json")
        self.assertEqual(et.main(["pin", pins, "--proxy", cargo, rustup, "--dir", home]), 0)
        log = os.path.join(self.d, "log")
        with open(log, "w") as f:
            f.write('1  execve("%s", ["cargo"], 0x1 /* 1 var */) = 0\n1  +++ exited with 0 +++\n' % cargo)
        self.assertEqual(et.main([log, "--root", cargo, "--pins", pins]), 0)
        self.assertEqual(et.main(["verify", pins]), 0)
        self.assertEqual(et.main([log, "--root", cargo, "--allow-link", cargo, rustup]), 0)

    def test_options(self):
        self.assertEqual(et.options(["--proxy", "a=b", "c", "--tool", "x"], {"--proxy": 2, "--tool": 1}),
                         [("--proxy", ["a=b", "c"]), ("--tool", ["x"])])
        for bad in (["--proxy", "a"], ["--tool"], ["--other", "x"], ["x"]):
            with self.assertRaises(ValueError):
                et.options(bad, {"--proxy": 2, "--tool": 1})

    def test_bad_paths_are_not_pinned(self):
        for p in ("relative", self.d + "/../x", self.d + "//tool"):
            with self.assertRaises(ValueError):
                et.pin([p], [], [])


if __name__ == "__main__":
    unittest.main()
