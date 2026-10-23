#!/usr/bin/env bash
# build-windows.sh ignores tools of the same names earlier on PATH.
#
# Puts stand-ins for cc, ld and x86_64-w64-mingw32-{gcc,gcc-win32,as,
# dlltool,ld} (symbolic links to /bin/false, so that any use fails the
# build) into a fresh directory under /tmp, puts that directory first on
# PATH, checks that the shell now finds the stand-ins (positive control),
# runs build-windows.sh with its build directories in the same place, and
# compares the two .exe files with those of a normal run. The directory is
# removed afterwards.
#
# Usage: bash rust/check-windows-shadowing.sh [reference out dir]
#   (default rust/target/windows-out, from a normal `bash build-windows.sh`)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd -P)
REF=${1:-$HERE/target/windows-out}
BINS=(voleith-prove voleith-verify)
for b in "${BINS[@]}"; do
  [ -f "$REF/$b.exe" ] || {
    echo "no $REF/$b.exe: run build-windows.sh first" >&2
    exit 1
  }
done

DIR=$(mktemp -d /tmp/voleith-shadow.XXXXXX)
trap 'rm -r -- "$DIR"' EXIT
mkdir "$DIR/bin"
TOOLS=(cc ld x86_64-w64-mingw32-gcc x86_64-w64-mingw32-gcc-win32
  x86_64-w64-mingw32-as x86_64-w64-mingw32-dlltool x86_64-w64-mingw32-ld)
for t in "${TOOLS[@]}"; do
  ln -s /bin/false "$DIR/bin/$t"
done
export PATH="$DIR/bin:$PATH"
for t in "${TOOLS[@]}"; do
  [ "$(command -v "$t")" = "$DIR/bin/$t" ] || {
    echo "the stand-in for $t is not found first on PATH" >&2
    exit 1
  }
done
echo "stand-ins first on PATH: ${TOOLS[*]}"

WINDOWS_BUILD_BASE=$DIR bash "$HERE/build-windows.sh" "$DIR/out"
status=0
for b in "${BINS[@]}"; do
  if cmp -s "$REF/$b.exe" "$DIR/out/$b.exe"; then
    echo "$b.exe: the same as the reference"
  else
    echo "$b.exe: DIFFERS from the reference" >&2
    status=1
  fi
done
[ $status -eq 0 ] && echo OK || echo FAIL
exit $status
