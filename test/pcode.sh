#!/usr/bin/env bash
# test/pcode.sh <language-id> <hex> [<hex> ...]   prints the p-code of the given instructions
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1; shift
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/gcdsp-pc.XXXXXX"); trap 'rm -rf "$PROJ"' EXIT
head -c 64 /dev/zero > "$PROJ/zero.bin"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$PROJ/zero.bin" -loader BinaryLoader \
	-processor "$LANG_ID" -noanalysis -scriptPath "$HERE" -postScript PcodeDump.java "$@" -deleteProject 2>&1 \
	| grep -E "PcodeDump.java>|ERROR|Exception" | sed 's/^INFO  PcodeDump.java> //; s/ (GhidraScript)$//'
