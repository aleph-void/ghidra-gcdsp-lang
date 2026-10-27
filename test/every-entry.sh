#!/usr/bin/env bash
# Every-entry test: test/every-entry.sh <language-id> <out.txt> <cases.txt> [ctx=value ...] [-- <cases.txt> [ctx=value ...]] ...
# Decodes every case (hex strings, 4 digits per word, one per line; optional context fields) and
# reports the SLEIGH constructors (in every subtable) never reached.  GHIDRA_INSTALL_DIR must be set.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; OUT=$(readlink -m "$2"); shift 2
ARGS=(); first=1
for a in "$@"; do
	if [[ $first == 1 ]]; then ARGS+=("$(readlink -f "$a")"); first=0
	elif [[ $a == -- ]]; then ARGS+=("--"); first=1
	else ARGS+=("$a"); fi
done
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/gcdsp-ee.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-processor "$LANG_ID" -noanalysis -scriptPath "$HERE" \
	-postScript EveryEntry.java "$OUT" "${ARGS[@]}" -deleteProject >"$PROJ/log.txt" 2>&1 \
	|| { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -20 >&2; exit 1; }
cat "$OUT"
