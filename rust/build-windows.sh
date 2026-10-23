#!/usr/bin/env bash
# Cross-compiles voleith-prove.exe and voleith-verify.exe for
# x86_64-pc-windows-gnu from Linux, reproducibly (README.md, "Windows").
#
# The hashes in NOTES.md are claimed for this environment, which the script
# checks and refuses to build without:
# - Ubuntu 24.04 (x86_64) packages, exact versions: gcc-mingw-w64-x86-64-win32
#   13.2.0-6ubuntu1+26.1, gcc-mingw-w64-base 13.2.0-6ubuntu1+26.1,
#   binutils-mingw-w64-x86-64 2.41.90.20240122-1ubuntu1+11.4,
#   mingw-w64-x86-64-dev 11.0.1-3build1;
# - the rustup toolchain 1.97.0 (rustc 2d8144b78 2026-07-07) with the target
#   x86_64-pc-windows-gnu (rust-toolchain.toml in windows/);
# - no cargo configuration file in any directory above the build directory
#   or in CARGO_HOME.
# cargo runs under `env -i` with a fixed environment: RUSTUP_TOOLCHAIN,
# LC_ALL=C, TZ=UTC, SOURCE_DATE_EPOCH=0, the rustflags below, the linker,
# and nothing else that cargo or rustc reads (no RUSTFLAGS, CARGO_BUILD_*,
# CARGO_PROFILE_*, CARGO_TARGET_*, RUSTC_WRAPPER, CC, ...). Only the
# network settings for downloading crates pass through (proxy variables and
# CA files); `--locked` pins every crate by checksum.
#
# Usage: bash rust/build-windows.sh [out dir]   (default rust/target/windows-out)
# Builds twice, each time from an empty target directory, checks that the
# two builds are byte-identical, copies the .exe files to the out dir and
# prints their SHA-256. Every local path that could enter the binaries
# (this checkout, the target directory, CARGO_HOME, RUSTUP_HOME) is
# remapped, the linker writes no timestamp into the PE header, and the
# symbol table is stripped.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd -P)
OUT=${1:-$HERE/target/windows-out}
TARGET=x86_64-pc-windows-gnu
TOOLCHAIN=1.97.0
RUSTC_COMMIT=2d8144b7880597b6e6d3dfd63a9a9efae3f533d3
LINKER=x86_64-w64-mingw32-gcc-win32
PACKAGES=(
  "gcc-mingw-w64-x86-64-win32 13.2.0-6ubuntu1+26.1"
  "gcc-mingw-w64-base 13.2.0-6ubuntu1+26.1"
  "binutils-mingw-w64-x86-64 2.41.90.20240122-1ubuntu1+11.4"
  "mingw-w64-x86-64-dev 11.0.1-3build1"
)
CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}
RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
CARGO_HOME=$(cd "$CARGO_HOME" && pwd -P)
RUSTUP_HOME=$(cd "$RUSTUP_HOME" && pwd -P)
ROOT=$(cd "$HERE/.." && pwd -P)
BINS=(voleith-prove voleith-verify)
BUILD_DIR=$HERE/windows

refuse() {
  echo "build-windows.sh: $*; not building" >&2
  exit 1
}

# The mingw-w64 packages.
command -v dpkg-query > /dev/null || refuse "dpkg-query not found (the recorded environment is Ubuntu 24.04)"
for p in "${PACKAGES[@]}"; do
  name=${p%% *}
  want=${p#* }
  have=$(dpkg-query -W -f='${Version}' "$name" 2> /dev/null || true)
  [ "$have" = "$want" ] || refuse "$name is '${have:-not installed}', the hashes are for $want"
done

# No cargo configuration that could change the build.
d=$BUILD_DIR
while :; do
  for f in "$d/.cargo/config" "$d/.cargo/config.toml"; do
    if [ -e "$f" ]; then refuse "$f exists"; fi
  done
  if [ "$d" = / ]; then break; fi
  d=$(dirname "$d")
done
for f in "$CARGO_HOME/config" "$CARGO_HOME/config.toml"; do
  if [ -e "$f" ]; then refuse "$f exists"; fi
done

# The fixed environment of every cargo and rustc run.
CLEAN_ENV=(
  "PATH=$CARGO_HOME/bin:/usr/bin:/bin"
  "HOME=$HOME"
  "CARGO_HOME=$CARGO_HOME"
  "RUSTUP_HOME=$RUSTUP_HOME"
  "RUSTUP_TOOLCHAIN=$TOOLCHAIN"
  "LC_ALL=C"
  "TZ=UTC"
  "SOURCE_DATE_EPOCH=0"
)
for v in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy \
  SSL_CERT_FILE CARGO_HTTP_CAINFO; do
  if [ -n "${!v:-}" ]; then CLEAN_ENV+=("$v=${!v}"); fi
done
clean() { (cd "$BUILD_DIR" && env -i "${CLEAN_ENV[@]}" "$@"); }

# The toolchain, exactly.
clean rustup toolchain install "$TOOLCHAIN" --profile minimal --target "$TARGET" > /dev/null 2>&1 ||
  refuse "cannot install the toolchain $TOOLCHAIN with $TARGET"
vv=$(clean rustc -vV)
grep -qx "release: $TOOLCHAIN" <<< "$vv" || refuse "rustc is not $TOOLCHAIN"
grep -qx "commit-hash: $RUSTC_COMMIT" <<< "$vv" || refuse "rustc is not commit $RUSTC_COMMIT"
clean rustup target list --installed | grep -qx "$TARGET" || refuse "target $TARGET not installed"
command -v "$LINKER" > /dev/null || refuse "$LINKER not found"
clean rustc --version
clean cargo --version
"$LINKER" --version | head -n 1
x86_64-w64-mingw32-ld --version | head -n 1

build() { # n
  local tdir=$HERE/target/windows-build-$1
  if [ -e "$tdir" ]; then
    refuse "$tdir exists; remove it first"
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
  clean "CARGO_ENCODED_RUSTFLAGS=$encoded" \
    "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=$LINKER" \
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
# The features are exactly `cli` (above); as a second check, the string
# that a build with the test-only feature fault-injection carries in its
# refusal message must be absent.
for b in "${BINS[@]}"; do
  if strings -a "$OUT/$b.exe" | grep -q VOLEITH_ALLOW_FAULT_INJECTION; then
    echo "$b.exe was built with fault-injection" >&2
    status=1
  fi
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
