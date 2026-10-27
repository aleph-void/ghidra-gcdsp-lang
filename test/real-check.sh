#!/usr/bin/env bash
# Real code: the DSPSpy test programs and Dolphin's free DSP ROM (GPL-2.0-or-later, fetched by pinned
# commit and SHA-256, never committed), assembled with DSPTool.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module> test/real-check.sh <workdir>
#
# For every program: GCDSPLoader import (the free ROM and coefficients are loaded next to it), default
# auto-analysis, then every instruction Ghidra found is re-decoded by DSPTool from its own words and
# compared (length and text, under the rules of cmp_dolphin.py); function count, bad-instruction and
# error bookmarks and decompiler failures are counted.  Exit status 0 only if there is no unexplained
# difference, no bookmark and no decompile failure.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "${1:?usage: real-check.sh <workdir>}" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
[[ -d $W/dolphin/.git ]] || "$HERE/fetch-dolphin.sh" "$W" || exit 2
[[ -x $W/dsptool ]] || "$HERE/build-dsptool.sh" "$W" || exit 2
D=$W/dolphin; T=$W/dsptool
R=$W/real; rm -rf "$R"; mkdir -p "$R/work/tests" "$R/img"
cp "$D"/Source/DSPSpy/tests/*.inc "$R/work/tests/"
cp "$D"/Source/DSPSpy/tests/*.ds "$D"/docs/DSP/free_dsp_rom/dsp_rom.ds "$R/work/"
fail=0
echo "== the free ROM source assembles to Dolphin's dsp_rom.bin"
(cd "$R/work" && "$T" -o "$R/dsp_rom.bin" dsp_rom.ds >/dev/null) && cmp "$R/dsp_rom.bin" "$D/Data/Sys/GC/dsp_rom.bin" \
	&& echo "identical" || { echo "FAILED"; fail=1; }
tot_ins=0; tot_fun=0; tot_bad=0; tot_dec=0
for f in "$R"/work/*_test.ds; do
	n=$(basename "$f" .ds)
	(cd "$R/work" && "$T" -o "$R/img/$n.bin" "$n.ds" >"$R/$n.log" 2>&1) || { echo "assembly of $n failed"; fail=1; continue; }
	mkdir -p "$R/img/$n"; mv "$R/img/$n.bin" "$R/img/$n/$n.bin"
	cp "$D/Data/Sys/GC/dsp_rom.bin" "$D/Data/Sys/GC/dsp_coef.bin" "$R/img/$n/"
	"$HERE/real-import.sh" GCDSP:BE:16:default "$R/img/$n/$n.bin" "$R/$n" 1 || { echo "import of $n failed"; fail=1; continue; }
	ins=$(awk '$1=="instructions"{print $2}' "$R/$n.txt"); fun=$(awk '$1=="functions"{print $2}' "$R/$n.txt")
	bad=$(awk '$1=="bad-instruction-bookmarks"||$1=="other-error-bookmarks"{s+=$2} END{print s+0}' "$R/$n.txt")
	dec=$(awk '$1=="decompile-failures"||$1=="decompile-timeouts"{s+=$2} END{print s+0}' "$R/$n.txt")
	cmpout=$(python3 "$HERE/real_compare.py" "$T" "$R/$n.insns" "$R/dw" "$n") || { fail=1; }
	echo "$cmpout" | head -3
	echo "   functions $fun, error bookmarks $bad, decompile failures $dec"
	tot_ins=$((tot_ins+ins)); tot_fun=$((tot_fun+fun)); tot_bad=$((tot_bad+bad)); tot_dec=$((tot_dec+dec))
	((bad+dec)) && fail=1
done
echo "TOTAL: $tot_ins instructions, $tot_fun functions, $tot_bad error bookmarks, $tot_dec decompile failures"
((fail)) && { echo "REAL-CODE CHECK FAILED"; exit 1; }
echo "REAL-CODE CHECK PASSED"
