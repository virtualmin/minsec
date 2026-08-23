#!/bin/bash
# Fail if a binary requires a glibc newer than the supported floor (default
# 2.28 = EL8) or links anything beyond glibc itself. Works for any ELF
# architecture (readelf, not objdump). Usage: scripts/check-glibc.sh <binary> [floor]
set -euo pipefail
bin=$1; floor=${2:-2.28}
need=$(readelf --wide --dyn-syms "$bin" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1)
libs=$(readelf --wide -d "$bin" | awk '/NEEDED/ {gsub(/[][]/,"",$5); print $5}' | tr '\n' ' ')
echo "$bin: needs glibc $need; NEEDED: $libs"
if [ "$(printf '%s\n%s\n' "$floor" "$need" | sort -V | tail -1)" != "$floor" ]; then
    echo "ERROR: requires glibc $need > floor $floor" >&2; exit 1
fi
for l in $libs; do
    case $l in libc.so.6|libgcc_s.so.1|ld-linux-*|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1) ;;
        *) echo "ERROR: unexpected shared library dependency $l" >&2; exit 1;;
    esac
done
