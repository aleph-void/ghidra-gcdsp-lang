#!/usr/bin/env bash
# test/dis.sh <cases.txt> <out.txt>
# Decodes each hex string (4 hex digits per 16-bit word) of cases.txt at inst:0x1000 and writes
# "<hex> <len-bytes> <text>" ("BAD" if rejected).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
IN=$(readlink -f "$1"); OUT=$(readlink -m "$2"); shift 2
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/gcdsp-ee.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-processor GCDSP:BE:16:default -noanalysis -scriptPath "$HERE" \
	-postScript EveryEntry.java "$IN" "$OUT" "$@" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
