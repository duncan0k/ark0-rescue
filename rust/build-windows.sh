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
#   or in CARGO_HOME;
# - the tools that run, by absolute path, each owned by its package
#   (dpkg -S) and listed with its SHA-256 (TOOLS below): the mingw-w64
#   linker driver (rustc's linker), its collect2 and ld, dlltool (rustc's
#   -Cdlltool, for getrandom's raw-dylib import) and the as it calls, and
#   the host gcc, collect2 and ld that link getrandom's build script (their
#   versions are recorded, not required: the build script only prints cfg
#   lines). A tool that is a symbolic link must resolve to a file of the
#   same package.
# Both builds run under strace (execve and execveat, with -f), and
# windows/exec_trace.py fails the build if any program other than these,
# the toolchain's own and the build scripts ran, or if any line of the
# trace cannot be parsed (split unfinished/resumed lines are joined per
# PID). strace (/usr/bin/strace, package strace) is required: without it
# the script refuses, unless --unpublished says that the hashes of this
# build will not be published.
# cargo runs under `env -i` with a fixed environment: RUSTUP_TOOLCHAIN,
# LC_ALL=C, TZ=UTC, SOURCE_DATE_EPOCH=0, the rustflags below, the linker,
# and nothing else that cargo or rustc reads (no RUSTFLAGS, CARGO_BUILD_*,
# CARGO_PROFILE_*, CARGO_TARGET_*, RUSTC_WRAPPER, CC, ...). Only the
# network settings for downloading crates pass through (proxy variables and
# CA files); `--locked` pins every crate by checksum.
#
# Usage: bash rust/build-windows.sh [--unpublished] [out dir]
#   (default out dir rust/target/windows-out)
# Builds twice, each time from an empty target directory, checks that the
# two builds are byte-identical, copies the .exe files to the out dir and
# prints their SHA-256. Every local path that could enter the binaries
# (this checkout, the target directory, CARGO_HOME, RUSTUP_HOME) is
# remapped, the linker writes no timestamp into the PE header, and the
# symbol table is stripped.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd -P)
OUT=
UNPUBLISHED=0
for a in "$@"; do
  case "$a" in
    --unpublished) UNPUBLISHED=1 ;;
    -*)
      echo "build-windows.sh: unknown option $a" >&2
      exit 2
      ;;
    *)
      if [ -n "$OUT" ]; then
        echo "build-windows.sh: one out dir only" >&2
        exit 2
      fi
      OUT=$a
      ;;
  esac
done
OUT=${OUT:-$HERE/target/windows-out}
# Overridable only to test the refusal: a published build needs the file
# to belong to the package strace.
STRACE=${WINDOWS_BUILD_STRACE:-/usr/bin/strace}
PYTHON=/usr/bin/python3
# Where the two build directories go (check-windows-shadowing.sh moves them).
BASE=${WINDOWS_BUILD_BASE:-$HERE/target}
TARGET=x86_64-pc-windows-gnu
TOOLCHAIN=1.97.0
RUSTC_COMMIT=2d8144b7880597b6e6d3dfd63a9a9efae3f533d3
LINKER=/usr/bin/x86_64-w64-mingw32-gcc-win32
DLLTOOL=/usr/bin/x86_64-w64-mingw32-dlltool
HOST_CC=/usr/bin/x86_64-linux-gnu-gcc-13
# path|owning package[|package of the link target, if it differs]
TOOLS=(
  "$LINKER|gcc-mingw-w64-x86-64-win32"
  "/usr/lib/gcc/x86_64-w64-mingw32/13-win32/collect2|gcc-mingw-w64-x86-64-win32"
  "/usr/bin/x86_64-w64-mingw32-ld|binutils-mingw-w64-x86-64"
  "$DLLTOOL|binutils-mingw-w64-x86-64"
  "/usr/bin/x86_64-w64-mingw32-as|binutils-mingw-w64-x86-64"
  "$HOST_CC|gcc-13-x86-64-linux-gnu"
  "/usr/libexec/gcc/x86_64-linux-gnu/13/collect2|gcc-13-x86-64-linux-gnu"
  "/usr/bin/ld|binutils|binutils-x86-64-linux-gnu"
)
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

# The exec trace, required for a build whose hashes are published.
TRACED=1
if [ -x "$STRACE" ] && [ "$(dpkg -S "$STRACE" 2> /dev/null | cut -d: -f1 || true)" = strace ]; then
  :
elif [ "$UNPUBLISHED" = 1 ]; then
  TRACED=0
  echo "build-windows.sh: no $STRACE from package strace: building UNTRACED (--unpublished)" >&2
else
  refuse "$STRACE (package strace) is required to trace the build; use --unpublished for a build whose hashes are not published"
fi
[ -x "$PYTHON" ] || refuse "$PYTHON not found"

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

# The tools: absolute paths, owned by the expected packages.
for t in "${TOOLS[@]}"; do
  IFS='|' read -r f pkg tpkg <<< "$t"
  [ -x "$f" ] || refuse "$f not found"
  for g in "$f|$pkg" "$(readlink -f "$f")|${tpkg:-$pkg}"; do
    owner=$(dpkg -S "${g%%|*}" 2> /dev/null | cut -d: -f1 || true)
    [ "$owner" = "${g#*|}" ] || refuse "${g%%|*} belongs to '${owner:-no package}', not ${g#*|}"
  done
done
# The linker drivers find collect2 and ld (or the host's collect2) in their
# own directories, not on PATH; check that they resolve to the listed files.
[ "$(env -i "$LINKER" -print-prog-name=collect2)" = /usr/lib/gcc/x86_64-w64-mingw32/13-win32/collect2 ] ||
  refuse "$LINKER does not use the listed collect2"
[ "$(readlink -f "$(env -i "$LINKER" -print-prog-name=ld)")" = /usr/bin/x86_64-w64-mingw32-ld ] ||
  refuse "$LINKER does not use the listed ld"
[ "$(env -i "$HOST_CC" -print-prog-name=collect2)" = /usr/libexec/gcc/x86_64-linux-gnu/13/collect2 ] ||
  refuse "$HOST_CC does not use the listed collect2"

# The fixed environment of every cargo and rustc run. PATH has system
# directories only; cargo and rustup are called by absolute path.
CLEAN_ENV=(
  "PATH=/usr/bin:/bin"
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
CARGO=$CARGO_HOME/bin/cargo
RUSTUP=$CARGO_HOME/bin/rustup
RUSTC=$CARGO_HOME/bin/rustc

# The toolchain, exactly.
clean "$RUSTUP" toolchain install "$TOOLCHAIN" --profile minimal --target "$TARGET" > /dev/null 2>&1 ||
  refuse "cannot install the toolchain $TOOLCHAIN with $TARGET"
vv=$(clean "$RUSTC" -vV)
grep -qx "release: $TOOLCHAIN" <<< "$vv" || refuse "rustc is not $TOOLCHAIN"
grep -qx "commit-hash: $RUSTC_COMMIT" <<< "$vv" || refuse "rustc is not commit $RUSTC_COMMIT"
clean "$RUSTUP" target list --installed | grep -qx "$TARGET" || refuse "target $TARGET not installed"
clean "$RUSTC" --version
clean "$CARGO" --version
for t in "${TOOLS[@]}"; do
  IFS='|' read -r f pkg tpkg <<< "$t"
  pkg=${tpkg:-$pkg}
  echo "tool $(sha256sum "$f" | cut -d' ' -f1) $f$([ -L "$f" ] && echo " -> $(readlink -f "$f")") ($pkg $(dpkg-query -W -f='${Version}' "$pkg"))"
done
TOOLCHAIN_DIR=$(dirname "$(dirname "$(clean "$RUSTUP" which rustc)")")

build() { # n
  local tdir=$BASE/windows-build-$1
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
    "-Cdlltool=$DLLTOOL"
  )
  local bin_args=()
  for b in "${BINS[@]}"; do bin_args+=(--bin "$b"); done
  local encoded
  encoded=$(IFS=$'\x1f'; echo "${flags[*]}")
  local trace=()
  if [ "$TRACED" = 1 ]; then
    mkdir -p "$tdir"
    trace=("$STRACE" -f -qq -e trace=execve,execveat -e signal=none -o "$tdir/exec.log")
  fi
  clean "CARGO_ENCODED_RUSTFLAGS=$encoded" \
    "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=$LINKER" \
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$HOST_CC" \
    "${trace[@]}" "$CARGO" build --quiet --locked --profile cli --features cli --target "$TARGET" \
    --manifest-path "$HERE/Cargo.toml" --target-dir "$tdir" "${bin_args[@]}"
  if [ "$TRACED" = 1 ]; then
    # Every program the build executed: the toolchain's, the build
    # scripts', or one of TOOLS; any unreadable line fails.
    local allow=(--allow "$CARGO" --allow-prefix "$TOOLCHAIN_DIR"
      --allow-glob "$tdir/*/build/*/build-script-build")
    for t in "${TOOLS[@]}"; do allow+=(--allow "${t%%|*}"); done
    "$PYTHON" -I "$HERE/windows/exec_trace.py" "$tdir/exec.log" "${allow[@]}" ||
      refuse "build $1 ran a program that is not allowed, or its trace cannot be read"
  fi
}

build 1
build 2
mkdir -p "$OUT"
status=0
for b in "${BINS[@]}"; do
  one=$BASE/windows-build-1/$TARGET/cli/$b.exe
  two=$BASE/windows-build-2/$TARGET/cli/$b.exe
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
if [ "$TRACED" = 0 ]; then
  echo "UNPUBLISHED BUILD: not traced; do not publish these hashes" >&2
fi
exit $status
