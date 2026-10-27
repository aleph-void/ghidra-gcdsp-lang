#!/usr/bin/env bash
# test/real-import.sh <language-id> <ucode.bin> <out-prefix> [decompile=1|0]
# Imports a raw DSP ucode with GCDSPLoader (dsp_rom.bin and dsp_coef.bin next to it are loaded too),
# runs the default auto-analysis, then RealCheck.java writes the instruction list and the counts.
# GHIDRA_INSTALL_DIR must be set.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; BIN=$(readlink -f "$2"); OUT=$(readlink -m "$3"); DEC=${4:-1}
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/gcdsp-real.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" -loader GCDSPLoader \
	-processor "$LANG_ID" -scriptPath "$HERE" \
	-postScript RealCheck.java "$OUT" "$DEC" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT.txt ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
