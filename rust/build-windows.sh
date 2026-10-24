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
# Before build 1, every allowed tool and the toolchain directory are
# pinned: for a tool, the path, the file it resolves to, and that file's
# device, inode and SHA-256; for the directory, the path, what it resolves
# to, and its device and inode (no hash: its contents are the toolchain's,
# checked by version and commit above). Both builds are checked against
# the pins, and at the end nothing pinned may have changed. Both builds run under strace (execve and execveat, with -f,
# exits written), and windows/exec_trace.py fails the build if the trace
# shows a program other than the pinned tools, the toolchain's own and the
# build scripts, if any line cannot be parsed (split unfinished/resumed
# lines are joined per PID), or if it does not start with cargo's exec and
# end with its exit 0; strace's status must be 0 and none of its own
# messages may appear on standard error (compiler warnings may). strace
# (/usr/bin/strace, package strace) is required: without it the script
# refuses, unless --unpublished says that the hashes of this build will
# not be published.
#
# Threat model: these checks catch an accidentally contaminated build
# environment (a stray tool on PATH, a cargo configuration, another
# toolchain or package version, a fault-injection build, a local path in a
# binary) on a build machine that nobody else writes to during the build.
# They do not defend against someone who can change that machine during
# the build (fill the disk under the trace, swap a tool and back, edit the
# trace): whoever can do that can as well replace the compiler.
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
vv=$(clean "$RUSTC" -vV) || refuse "rustc -vV failed"
grep -qx "release: $TOOLCHAIN" <<< "$vv" || refuse "rustc is not $TOOLCHAIN"
grep -qx "commit-hash: $RUSTC_COMMIT" <<< "$vv" || refuse "rustc is not commit $RUSTC_COMMIT"
# No pipe into an early-exiting grep: under pipefail its exit could make
# the writer die of SIGPIPE and the pipeline report a failure.
targets=$(clean "$RUSTUP" target list --installed) || refuse "cannot list the installed targets"
grep -qxF "$TARGET" <<< "$targets" || refuse "target $TARGET not installed"
clean "$RUSTC" --version
clean "$CARGO" --version
for t in "${TOOLS[@]}"; do
  IFS='|' read -r f pkg tpkg <<< "$t"
  pkg=${tpkg:-$pkg}
  # Each value on its own, so that a failure is not printed as an empty
  # field.
  h=$(sha256sum -- "$f") || refuse "cannot hash $f"
  h=${h%% *}
  r=$(readlink -f -- "$f") || refuse "cannot resolve $f"
  v=$(dpkg-query -W -f='${Version}' "$pkg") || refuse "cannot read the version of $pkg"
  if [ "$r" = "$f" ]; then
    echo "tool $h $f ($pkg $v)"
  else
    echo "tool $h $f -> $r ($pkg $v)"
  fi
done
rustc_path=$(clean "$RUSTUP" which rustc) || refuse "rustup which rustc failed"
TOOLCHAIN_DIR=${rustc_path%/bin/rustc}
[ "$TOOLCHAIN_DIR/bin/rustc" = "$rustc_path" ] && [ -d "$TOOLCHAIN_DIR" ] ||
  refuse "unexpected rustc path: $rustc_path"

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
  # printf, not echo: echo would take a leading -n or -e as an option.
  encoded=$(IFS=$'\x1f'; printf '%s' "${flags[*]}")
  local trace=()
  if [ "$TRACED" = 1 ]; then
    mkdir -p "$tdir"
    # --quiet=attach,personality (-q, not -qq): exit lines are written,
    # and exec_trace.py needs the root's `+++ exited with 0 +++`.
    trace=("$STRACE" -f --quiet=attach,personality -e trace=execve,execveat
      -e signal=none -o "$tdir/exec.log")
  fi
  local cmd=(clean "CARGO_ENCODED_RUSTFLAGS=$encoded"
    "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=$LINKER"
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$HOST_CC"
    "${trace[@]}" "$CARGO" build --quiet --locked --profile cli --features cli --target "$TARGET"
    --manifest-path "$HERE/Cargo.toml" --target-dir "$tdir" "${bin_args[@]}")
  if [ "$TRACED" = 0 ]; then
    "${cmd[@]}"
    return
  fi
  # strace exits with cargo's status, but reports its own errors (a log it
  # cannot write: a full disk, an I/O error) on standard error, with lines
  # that start with "$STRACE: " or "strace: ", and may still exit 0. The
  # traced build's standard error is read through a pipe that this script
  # consumes (command substitution), shown in full, and the build fails on
  # a non-zero status or on any line strace wrote; compiler warnings pass.
  local rc=0 errout
  exec 3>&1
  errout=$("${cmd[@]}" 2>&1 1>&3 3>&-) || rc=$?
  exec 3>&-
  if [ -n "$errout" ]; then
    sed "s/^/build $1 stderr: /" <<< "$errout" >&2
  fi
  if [ "$rc" -ne 0 ]; then
    refuse "build $1 under strace exited $rc"
  fi
  "$PYTHON" -I "$HERE/windows/exec_trace.py" stderr "$STRACE" <<< "$errout" ||
    refuse "build $1: strace reported an error (above)"
  # Every program the build executed: the toolchain's, the build
  # scripts', or one of the tools pinned before build 1; the log must start
  # with the root's exec and end with its exit 0, cargo, rustc and the
  # linker must have run, and every line must be readable.
  "$PYTHON" -I "$HERE/windows/exec_trace.py" "$tdir/exec.log" --root "$CARGO" --pins "$PINS" \
    --expect "$TOOLCHAIN_DIR/bin/cargo" --expect "$TOOLCHAIN_DIR/bin/rustc" --expect "$LINKER" \
    --allow-build-scripts "$tdir/cli/build" ||
    refuse "build $1: the exec trace is unreadable, does not end normally or shows a program that is not allowed"
}

# Pin, once and before build 1, every allowed tool (path as written, the
# file it resolves to, that file's device, inode and SHA-256) and the
# toolchain directory (path, resolved path, device, inode; no hash). Both
# builds are checked against this record, and at the end nothing in it
# may have changed.
PINS=$BASE/windows-build-pins.json
if [ "$TRACED" = 1 ]; then
  pin_args=(--proxy "$CARGO" "$CARGO_HOME/bin/rustup" --dir "$TOOLCHAIN_DIR")
  for t in "${TOOLS[@]}"; do pin_args+=(--tool "${t%%|*}"); done
  mkdir -p "$BASE"
  "$PYTHON" -I "$HERE/windows/exec_trace.py" pin "$PINS" "${pin_args[@]}" ||
    refuse "cannot pin the tools"
fi
build 1
build 2
if [ "$TRACED" = 1 ]; then
  "$PYTHON" -I "$HERE/windows/exec_trace.py" verify "$PINS" ||
    refuse "a pinned tool or directory changed during the builds"
fi
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
# The number of places in FILE (lines, to grep -a) that contain one of the
# fixed strings given as -e arguments. grep reads the whole file itself,
# with no pipe that an early exit could break, and "the scan failed"
# (return 2, nothing printed) is kept apart from "none found" (0).
count_in() {
  local file=$1 n rc
  shift
  n=$(grep -a -c -F "$@" -- "$file") && rc=0 || rc=$?
  if [ "$rc" -gt 1 ] || ! [[ "$n" =~ ^[0-9]+$ ]]; then
    return 2
  fi
  echo "$n"
}
scan() { # label file strings...
  local label=$1 file=$2 n
  shift 2
  if ! n=$(count_in "$file" "$@"); then
    echo "$label: the scan of $file failed" >&2
    status=1
    return
  fi
  if [ "$n" -ne 0 ]; then
    echo "$label: found in $file" >&2
    status=1
  fi
}
MARKER=VOLEITH_ALLOW_FAULT_INJECTION
# Positive control: the marker followed by 64 MiB more is still found.
control=$BASE/windows-build-1/marker-control.bin
{
  printf 'xx%s\n' "$MARKER"
  head -c 67108864 /dev/zero
} > "$control"
n=$(count_in "$control" -e "$MARKER") || refuse "the scan of the marker control failed"
[ "$n" -ge 1 ] || refuse "the marker scan misses a marker followed by 64 MiB"
echo "marker scan: control with the marker and 64 MiB after it found"
# The features are exactly `cli` (above); as a second check, the string
# that a build with the test-only feature fault-injection carries in its
# refusal message must be absent.
for b in "${BINS[@]}"; do
  scan "fault-injection marker in $b.exe" "$OUT/$b.exe" -e "$MARKER"
done
# Local paths left in the binaries (there should be none).
# A path also counts with its separators turned into underscores, as in
# dlltool's symbol names.
leak=()
for p in "$ROOT" "$CARGO_HOME" "$RUSTUP_HOME" "$HOME/" /tmp/; do
  u=$(printf '%s' "$p" | tr '/.-' '___') || refuse "cannot form the underscore form of $p"
  leak+=(-e "$p" -e "$u")
done
# Positive control: a file holding each form of one local path (as is, and
# with separators turned into underscores) in 64 MiB is found by the same
# patterns.
root_u=$(printf '%s' "$ROOT" | tr '/.-' '___') || refuse "cannot form the underscore form of $ROOT"
for form in "$ROOT" "$root_u"; do
  {
    head -c 33554432 /dev/zero
    printf '%s\n' "$form"
    head -c 33554432 /dev/zero
  } > "$control"
  n=$(count_in "$control" "${leak[@]}") || refuse "the scan of the local-path control failed"
  [ "$n" -ge 1 ] || refuse "the local-path scan misses $form"
done
echo "local-path scan: controls with the checkout path, plain and as underscores, found"
for b in "${BINS[@]}"; do
  scan "a local path in $b.exe" "$OUT/$b.exe" "${leak[@]}"
done
(cd "$OUT" && sha256sum "${BINS[@]/%/.exe}")
if [ "$TRACED" = 0 ]; then
  echo "UNPUBLISHED BUILD: not traced; do not publish these hashes" >&2
fi
exit $status
