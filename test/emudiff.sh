#!/usr/bin/env bash
# test/emudiff.sh <language-id> <vectors.txt> <out.txt> [steps]   (GHIDRA_INSTALL_DIR set)
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; IN=$(readlink -f "$2"); OUT=$(readlink -m "$3"); STEPS=${4:-1}
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/gcdsp-emu.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript EmuDiff.java "$IN" "$OUT" "$STEPS" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
