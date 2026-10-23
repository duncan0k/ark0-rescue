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
cargo build --release --features cli
target/release/voleith-prove --k <ascii K> --suffix <0..255> --msg-hex <hex> --out <proof file> < seed.txt
target/release/voleith-verify --k <ascii K> --suffix <0..255> --y-hex <64 hex> --msg-hex <hex> --proof <file>
```

`voleith-prove` reads the seed `x` from standard input, as 64 hexadecimal
digits and an optional newline (`\n` or `\r\n`) and nothing else; it never
echoes it. Give it a file or a pipe (`< seed.txt`), not the keyboard: a
terminal shows what is typed. The tool computes
`y = HMAC-SHA256(K, x ‖ suffix)`, draws `rho` from the operating system,
proves with the constant-time prover, verifies the proof, writes it to a
new file (it never overwrites one) and prints one line, `y=<64 hex>`. The
seed and `rho` are cleared before exit. Exit codes: 0 success, 1 failure,
2 usage error (arguments or standard input malformed).

`voleith-verify` prints `valid` (exit 0) or `invalid` (exit 1); 2 is a
usage error. `../python/tools/verify_cli.py` (run with `python -I`) and
`../go/cmd/voleith-verify` take the same arguments and give the same
answers; `bash ../crosscheck/cli.sh` checks that they agree.

Command lines are limited in length: on Windows to 32,767 characters in
all, so `--msg-hex` can carry at most about 16 kB there (the rescue lane
uses 96 bytes).

## Windows

`build-windows.sh` cross-compiles both tools for `x86_64-pc-windows-gnu`
on Linux with mingw-w64 from the distribution's packages (Ubuntu 24.04:
`apt-get install gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64`) and the
exact Rust toolchain of `windows/rust-toolchain.toml`:

```
bash build-windows.sh            # out: target/windows-out/*.exe and their SHA-256
```

It builds twice from empty target directories (`target/windows-build-1`
and `-2`; it refuses to run if they exist) and fails unless the two
builds are byte-identical and free of local paths. Anyone with the same
toolchain and mingw-w64 packages gets the same SHA-256 (`../NOTES.md`
records them), wherever the checkout is. The binaries are not committed.

On the Windows machine:

```
voleith-prove.exe --k "ark0-wallet v1 schnorr" --suffix 0 --msg-hex <hex> --out proof.bin < seed.txt
voleith-verify.exe --k "ark0-wallet v1 schnorr" --suffix 0 --y-hex <y> --msg-hex <hex> --proof proof.bin
```

Run it from `cmd.exe`, whose `<` passes the file byte for byte
(PowerShell has no `<` and re-encodes what it pipes). `seed.txt` holds the
64 hex digits; a CRLF line ending is accepted, a byte-order mark is not
(the tool then exits 2). Delete the file securely afterwards; the tools
cannot clear copies of the seed outside their own memory.

The two .exe files were run under wine 9.0 on Linux (NOTES.md), not yet on
Windows itself. A human review of the constant-time prover
(`CT-AUDIT.md`) is still open; NOTES.md asks for it before any real seed
is used.
