# voleith (Rust)

Verifier, constant-time prover and C ABI for the VOLE-in-the-head rescue
proofs of `../SPEC.md` (v0.2, version byte 0x02, statement 0x01). History,
measurements and checks are in `../NOTES.md`; the prover's constant-time
review is in `CT-AUDIT.md`.

## Features

| feature | default | what it adds |
|---|---|---|
| `prover` | on | `prove` and everything only the prover uses |
| `cli` | off | the tools `voleith-prove` and `voleith-verify` (implies `prover`; adds `getrandom`) |
| `test-trace` | off | `prove_traced`, for the vector tests only; never in a build that sees a real seed |
| `bench-splits` | off | other tree splits, for `benches/verify.rs` only |

## Verifier-only static library (Bitcoin Core)

```
cargo build --release --no-default-features --lib
# target/release/libvoleith.a, C header include/voleith.h
cargo rustc --release --no-default-features --lib -- --print native-static-libs
bash check-verifier-only.sh     # nm: voleith_verify_s1 exported, no prover symbol
```

## Command-line tools

```
cargo build --profile cli --features cli          # target/cli/voleith-prove, target/cli/voleith-verify
<restore command> | target/cli/voleith-prove --k <ascii K> --suffix <0..255> --msg-hex <hex> --out <proof file> [--require-mlock]
target/cli/voleith-verify --k <ascii K> --suffix <0..255> --y-hex <64 hex> --msg-hex <hex> --proof <file>
```

The `cli` profile is the release profile with `panic = "abort"`: a panic
ends the process at once. Build the tools with it (`build-windows.sh`
does), and with `--features cli` only, never `--all-features`: the
test-only feature `fault-injection` can fix `rho`, bypass the random
source and force a panic. A binary built with it refuses to run (exit 1,
nothing read) unless `VOLEITH_ALLOW_FAULT_INJECTION=tests` is set, which
only the tests do; `build-windows.sh` checks that its binaries do not
contain it.

`voleith-prove`, in order:

1. checks its arguments (exit 2 on a usage error);
2. turns off crash dumps and crash reporting for its own process, and with
   `--require-mlock` (Linux only) locks all its memory; if either fails it
   exits 1 without reading anything (see "What stays private" below);
3. reads the seed `x` from standard input: 64 hexadecimal digits and an
   optional newline (`\n` or `\r\n`), nothing else (exit 2 otherwise; the
   input is never echoed);
4. computes `y = HMAC-SHA256(K, x ‖ suffix)`, draws `rho` from the
   operating system, proves with the constant-time prover and verifies the
   proof;
5. writes the proof to a new temporary file next to `--out`, syncs and
   closes it, and gives it the name `--out` without ever replacing an
   existing file; on any failure it removes the temporary file (and says
   so, with its name, if it cannot);
6. prints one line, `y=<64 hex>`, and exits 0. Any other failure exits 1.

`voleith-verify` prints `valid` (exit 0) or `invalid` (exit 1); 2 is a
usage error. `../python/tools/verify_cli.py` (run with `python -I`) and
`../go/cmd/voleith-verify` take the same arguments and give the same
answers; `bash ../crosscheck/cli.sh` checks that they agree.

Command lines are limited in length: on Windows to 32,767 characters in
all, so `--msg-hex` can carry at most about 16 kB there (the rescue lane
uses 96 bytes).

### What stays private

The seed and `rho` never appear in the command line, the environment,
standard output, standard error, the proof file or any other file the tool
writes (`tests/cli.rs` scans for every 8-byte fragment of both in raw,
hexadecimal, decimal and base64 form, also under injected failures and an
injected panic).

Crash dumps and reports, before anything is read (a failure exits 1):

- Linux: `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, 0)`: no
  core dump, and no ptrace or `/proc/<pid>/mem` access by other processes
  of the user. With `--require-mlock`, `mlockall(MCL_CURRENT |
  MCL_FUTURE)` keeps every page out of swap; it needs `RLIMIT_MEMLOCK` of
  at least 128 MiB (`ulimit -l`) or root. Use it on a machine outside the
  trust boundary.
- Windows: `SetErrorMode` (no error dialogs);
  `WerAddExcludedApplication("voleith-prove.exe", FALSE)`, which excludes
  the program from Windows Error Reporting for the current user (a
  persistent per-user registry setting); `SetUnhandledExceptionFilter`
  with a filter that calls `TerminateProcess`, so an unhandled exception
  never reaches WER or a just-in-time debugger; and a panic hook that
  calls `TerminateProcess` instead of `abort`, whose `__fastfail` goes to
  WER. Not covered: a `__fastfail` from elsewhere (e.g. an allocation
  failure) relies on the WER exclusion alone, whether WER's LocalDumps
  honour that exclusion has not been checked on Windows, and a process
  of the same user can still read the tool's memory while it runs.
  `--require-mlock` is a usage error on Windows: the machine is the trust
  boundary there, and swap is not a goal.

Cleared in memory (zeroized when no longer needed, at the latest when
`run()` returns, before the process exits):

- the standard-input buffer with the hex digits (read through an
  unbuffered handle, so the standard library keeps no copy), the decoded
  seed, the HMAC input `x ‖ suffix`, the SHA-256 state that absorbed it
  and the inner digest, and `rho`;
- in the prover: the witness and wire values, the VOLE tags, columns and
  rows, the tree roots and seeds, the root seed `r` and every SHAKE256
  state (a sponge that absorbs and squeezes in place); afterwards 64 KiB of
  the stack below the prover is overwritten.

Not cleared:

- copies made by moving or passing values (a seed read from a slice, the
  SHA-256 and Keccak working variables) in registers and in stack slots
  outside the scrubbed region; they remain until overwritten or until the
  process exits, which it does right after writing the proof;
- the same after a panic: the process ends at once, without clearing,
  and nothing is written;
- what is outside the tool: the pipe buffer of the operating system and
  the memory of the program that restores the seed;
- swap and hibernation files, except with `--require-mlock` on Linux.

## Windows

`build-windows.sh` cross-compiles both tools for `x86_64-pc-windows-gnu`
on Linux and builds them twice from empty target directories
(`target/windows-build-1` and `-2`; it refuses to run if they exist); it
fails unless the two builds are byte-identical and free of local paths:

```
bash build-windows.sh            # out: target/windows-out/*.exe and their SHA-256
```

The SHA-256 values in `../NOTES.md` are claimed for this environment
only, which the script checks and otherwise refuses to build:

- Ubuntu 24.04 (x86_64) with `gcc-mingw-w64-x86-64-win32` and
  `gcc-mingw-w64-base` 13.2.0-6ubuntu1+26.1, `binutils-mingw-w64-x86-64`
  2.41.90.20240122-1ubuntu1+11.4 and `mingw-w64-x86-64-dev` 11.0.1-3build1
  (`apt-get install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64`);
- the rustup toolchain 1.97.0 (rustc commit 2d8144b78) with the target
  `x86_64-pc-windows-gnu` (`windows/rust-toolchain.toml`);
- no `.cargo/config` or `.cargo/config.toml` above the checkout or in
  `CARGO_HOME`.

The tools that run are called by absolute path, never found on `PATH`:
the linker `/usr/bin/x86_64-w64-mingw32-gcc-win32` with its `collect2`
and `ld`, `dlltool` (`-Cdlltool`) with the `as` it calls, and the host
`gcc-13`, `collect2` and `ld` that link getrandom's build script. The
script checks that each belongs to its package (`dpkg -S`), prints its
SHA-256 (`../NOTES.md` records them), and, with `strace` installed,
fails if the first build ran any other program than these, the
toolchain's and the build scripts. `bash check-windows-shadowing.sh`
puts stand-ins of the same names first on `PATH` and checks that the
build gives the same two files.

cargo runs under `env -i` with `LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH=0`
and nothing else that cargo or rustc reads, apart from the network
settings for crate downloads, so the caller's `RUSTFLAGS`, `CARGO_*` and
`RUSTUP_TOOLCHAIN` do not matter. The path of the checkout does not
matter either. The binaries are not committed.

On the Windows machine, in `cmd.exe`, pipe the seed from the restore step
straight into the tool, so that it is never written to a file, a command
line or an environment variable. For example, with a backup encrypted
with GnuPG (Gpg4win) whose plaintext is the 64 hex digits:

```
gpg --decrypt seed-backup.gpg | voleith-prove.exe --k "ark0-wallet v1 schnorr" --suffix 0 --msg-hex <hex> --out proof.bin
voleith-verify.exe --k "ark0-wallet v1 schnorr" --suffix 0 --y-hex <y> --msg-hex <hex> --proof proof.bin
```

`cmd.exe` passes the bytes of a pipe unchanged; a CRLF line ending is
accepted, a byte-order mark is not (the tool then exits 2). Windows
PowerShell 5.1 re-encodes what it pipes between programs; use `cmd.exe`.

A file is fine only for the public test seed of the vectors (the
`witness_x` of the first vector in `../vectors/statement1-v0.2.json`),
for a trial run:

```
echo b4fa168d8247e91dad1b76e9c7908b2a661afcbbd0e6e4be05a6a7c201091142> testseed.txt
voleith-prove.exe --k "ark0-wallet v1 schnorr" --suffix 0 --msg-hex 00 --out trial.bin < testseed.txt
```

It must print
`y=5518fad24b026591734a86b9e6f23b81798acf882d6ba90eb9b61fd9e550e7ec`.

The two .exe files were run under wine 9.0 on Linux (NOTES.md), not yet on
Windows itself. A human review of the constant-time prover
(`CT-AUDIT.md`) is still open; NOTES.md asks for it before any real seed
is used.
