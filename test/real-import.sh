#!/usr/bin/env bash
# test/real-import.sh <language-id> <raw.bin> <out-prefix> [decompile=1|0]
# Imports a raw DSP image at inst:0 (no forced analysis options), runs the default auto-analysis,
# then RealCheck.java writes the instruction list and the counts.   (GHIDRA_INSTALL_DIR set)
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; BIN=$(readlink -f "$2"); OUT=$(readlink -m "$3"); DEC=${4:-1}
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/gcdsp-real.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" -loader BinaryLoader \
	-loader-baseAddr inst:0 -processor "$LANG_ID" -scriptPath "$HERE" \
	-postScript RealCheck.java "$OUT" "$DEC" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT.txt ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
