#!/usr/bin/env bash
# Cross-compiles voleith-prove.exe and voleith-verify.exe for
# x86_64-pc-windows-gnu from Linux, reproducibly (README.md, "Windows").
#
# Needs: rustup, and mingw-w64 from the distribution's packages (Ubuntu
# 24.04: gcc-mingw-w64-x86-64 and binutils-mingw-w64-x86-64). The Rust
# toolchain is the exact version in windows/rust-toolchain.toml; rustup
# installs it and the target on first use.
#
# Usage: bash rust/build-windows.sh [out dir]   (default rust/target/windows-out)
# Builds twice, each time from an empty target directory, checks that the
# two builds are byte-identical, copies the .exe files to the out dir and
# prints their SHA-256. Every local path that could enter the binaries
# (this checkout, the target directory, CARGO_HOME, RUSTUP_HOME) is
# remapped, the linker writes no timestamp into the PE header, and the
# symbol table is stripped.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/target/windows-out}
TARGET=x86_64-pc-windows-gnu
CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
CARGO_HOME=$(cd "$CARGO_HOME" && pwd -P)
RUSTUP_HOME=$(cd "$RUSTUP_HOME" && pwd -P)
ROOT=$(cd "$HERE/.." && pwd -P)
BINS=(voleith-prove voleith-verify)

command -v x86_64-w64-mingw32-gcc > /dev/null || {
  echo "x86_64-w64-mingw32-gcc not found: install gcc-mingw-w64-x86-64" >&2
  exit 1
}

# rustup picks the toolchain from windows/rust-toolchain.toml in the
# current directory.
cd "$HERE/windows"
rustc --version
x86_64-w64-mingw32-gcc --version | head -n 1
x86_64-w64-mingw32-ld --version | head -n 1

build() { # n
  local tdir=$HERE/target/windows-build-$1
  if [ -e "$tdir" ]; then
    echo "$tdir exists; remove it first" >&2
    exit 1
  fi
  local flags=(
    "--remap-path-prefix=$tdir=/target"
    "--remap-path-prefix=$ROOT=/src"
    "--remap-path-prefix=$CARGO_HOME=/cargo"
    "--remap-path-prefix=$RUSTUP_HOME=/rustup"
    "-Clink-arg=-Wl,--no-insert-timestamp"
    # No COFF symbol table: the import library that dlltool makes for
    # getrandom's raw-dylib link to bcryptprimitives.dll names its symbols
    # after rustc's random temporary path, which made voleith-prove.exe
    # differ between builds and leaked the local path.
    "-Cstrip=symbols"
  )
  local bin_args=()
  for b in "${BINS[@]}"; do bin_args+=(--bin "$b"); done
  local encoded
  encoded=$(IFS=$'\x1f'; echo "${flags[*]}")
  CARGO_ENCODED_RUSTFLAGS="$encoded" \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    SOURCE_DATE_EPOCH=0 \
    cargo build --quiet --locked --profile cli --features cli --target "$TARGET" \
    --manifest-path "$HERE/Cargo.toml" --target-dir "$tdir" "${bin_args[@]}"
}

build 1
build 2
mkdir -p "$OUT"
status=0
for b in "${BINS[@]}"; do
  one=$HERE/target/windows-build-1/$TARGET/cli/$b.exe
  two=$HERE/target/windows-build-2/$TARGET/cli/$b.exe
  if cmp -s "$one" "$two"; then
    echo "$b.exe: the two builds are identical"
  else
    echo "$b.exe: the two builds DIFFER" >&2
    status=1
  fi
  cp "$one" "$OUT/$b.exe"
done
# Local paths left in the binaries (there should be none).
# A path also counts with its separators turned into underscores, as in
# dlltool's symbol names.
leak=()
for p in "$ROOT" "$CARGO_HOME" "$RUSTUP_HOME" "$HOME/" /tmp/; do
  leak+=(-e "$p" -e "$(printf '%s' "$p" | tr '/.-' '___')")
done
for b in "${BINS[@]}"; do
  if strings -a "$OUT/$b.exe" | grep -F "${leak[@]}" > /dev/null; then
    echo "$b.exe contains a local path" >&2
    status=1
  fi
done
(cd "$OUT" && sha256sum "${BINS[@]/%/.exe}")
exit $status
