"""Tests of exec_trace.py on recorded strace lines.

Run: python3 -I rust/windows/test_exec_trace.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import exec_trace as et  # noqa: E402

RUSTC = "/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu/bin/rustc"

# Lines as strace 6.8 wrote them for build-windows.sh (arguments shortened).
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


class Parse(unittest.TestCase):
    def test_complete_line(self):
        self.assertEqual(et.parse([COMPLETE]), (["/usr/bin/x86_64-w64-mingw32-dlltool"], []))

    def test_split_lines_are_joined_per_pid(self):
        ran, errors = et.parse(SPLIT)
        self.assertEqual(errors, [])
        self.assertEqual(ran, [RUSTC, RUSTC])

    def test_split_failed_exec_is_not_a_run(self):
        lines = [SPLIT[0], "5223  <... execve resumed>)             = -1 EACCES (Permission denied)\n"]
        self.assertEqual(et.parse(lines), ([], []))

    def test_failed_exec_is_not_a_run(self):
        self.assertEqual(et.parse([FAILED]), ([], []))

    def test_execveat(self):
        self.assertEqual(et.parse([EXECVEAT_OK]), (["/usr/bin/x86_64-w64-mingw32-as"], []))
        for line in (EXECVEAT_FD, EXECVEAT_REL):
            ran, errors = et.parse([line])
            self.assertEqual(len(errors), 1, line)
            self.assertIn("does not name the program", errors[0])

    def test_split_execveat(self):
        lines = ['7  execveat(AT_FDCWD, "/bin/true", ["true"], 0x1 /* 1 var */, 0 <unfinished ...>\n',
                 "7  <... execveat resumed>) = 0\n"]
        self.assertEqual(et.parse(lines), (["/bin/true"], []))

    def test_unparsable_lines_fail(self):
        bad = [
            "garbage\n",
            '5250  execve("/usr/bin/a\\"b", ["x"], 0x1 /* 1 var */) = 0\n',  # escaped path
            '5251  execve("/usr/bin/x", ["x"], 0x1 /* 1 var */) = ?\n',      # no result
            "5252  +++ exited with 0 +++\n",
            '5253  open("/etc/passwd", O_RDONLY) = 3\n',
            '5254  execve("/usr/bin/x", ["x"]',                                # cut off
        ]
        for line in bad:
            ran, errors = et.parse([line])
            self.assertTrue(errors, line)
            self.assertEqual(ran, [], line)

    def test_unpaired_split_lines_fail(self):
        self.assertTrue(et.parse([SPLIT[0]])[1])  # never resumed
        self.assertTrue(et.parse([SPLIT[2]])[1])  # resumed without start
        self.assertTrue(et.parse([SPLIT[0], SPLIT[0]])[1])  # two unfinished
        mixed = [SPLIT[0], "5223  <... execveat resumed>) = 0\n"]
        self.assertTrue(et.parse(mixed)[1])

    def test_blank_lines_are_ignored(self):
        self.assertEqual(et.parse(["\n", COMPLETE, "\n"])[1], [])


class Check(unittest.TestCase):
    LOG = SPLIT + [COMPLETE, FAILED, EXECVEAT_OK]

    def test_allowed(self):
        progs, errors = et.check(
            self.LOG,
            {"/usr/bin/x86_64-w64-mingw32-dlltool", "/usr/bin/x86_64-w64-mingw32-as"},
            ["/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu"], [])
        self.assertEqual(errors, [])
        self.assertEqual(len(progs), 3)

    def test_disallowed_program_fails(self):
        progs, errors = et.check(self.LOG, {"/usr/bin/x86_64-w64-mingw32-dlltool"},
                                 ["/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu"], [])
        self.assertEqual(errors, ["ran /usr/bin/x86_64-w64-mingw32-as, which is not allowed"])

    def test_prefix_is_a_directory(self):
        # /root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu-evil is not under the prefix.
        log = ['1  execve("/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu-evil/rustc", [], 0x1) = 0\n']
        errors = et.check(log, set(), ["/root/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu"], [])[1]
        self.assertTrue(errors)

    def test_glob(self):
        log = ['1  execve("/b/windows-build-1/cli/build/getrandom-ab12/build-script-build", [], 0x1) = 0\n']
        self.assertEqual(et.check(log, set(), [], ["/b/windows-build-1/*/build/*/build-script-build"])[1], [])

    def test_a_failed_exec_of_anything_is_fine(self):
        self.assertEqual(et.check([FAILED], set(), [], []), ([], []))


if __name__ == "__main__":
    unittest.main()
