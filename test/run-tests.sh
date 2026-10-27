#!/usr/bin/env bash
# Runs the GCDSP verification suite.
#
#   GHIDRA_INSTALL_DIR=<Ghidra with this module linked into Ghidra/Processors/GCDSP> \
#     test/run-tests.sh [--real] [--n <random-cases-per-opcode>] <workdir>
#
# Needs: python3, g++ (C++23), git and network access (the first run fetches Dolphin's DSP manual and
# DSPTool sources at pinned commits, see fetch-dolphin.sh; nothing is committed).  --real adds
# real-check.sh (the DSPSpy programs and the free DSP ROM).  Exit status 0 only if every step passes.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(dirname "$HERE")
REAL=0; N=150
while [[ ${1:-} == --* ]]; do
	case $1 in --real) REAL=1; shift ;; --n) N=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;; esac
done
W=$(mkdir -p "${1:?usage: run-tests.sh [--real] <workdir>}" && cd "$1" && pwd)
export TMPDIR=${TMPDIR:-$W}
fail=0
step() { echo "== $*"; }
ok() { "$@" || { echo "FAILED: $*"; fail=1; }; }

step "fetch and build the reference tools (cached in $W)"
[[ -d $W/dolphin/.git ]] || ok "$HERE/fetch-dolphin.sh" "$W"
[[ -x $W/dsptool ]] || ok "$HERE/build-dsptool.sh" "$W"
export DSPTOOL=$W/dsptool GCDSP_MANUAL_TEX=$W/dolphin/docs/DSP/GameCube_DSP_Users_Manual/GameCube_DSP_Users_Manual.tex
[[ -x $DSPTOOL && -f $GCDSP_MANUAL_TEX ]] || { echo "reference tools missing"; exit 2; }

step "specs compile (sleigh -l: no unresolved pattern conflicts)"
for s in GCDSP GCDSP_exact; do
	out=$("$GHIDRA_INSTALL_DIR/support/sleigh" -l "$MOD/data/languages/$s.slaspec" 2>&1)
	if grep -q "ERROR" <<<"$out"; then echo "$out" | grep ERROR | head; echo "FAILED: $s"; fail=1; else echo "$s compiles"; fi
	sz=$(stat -c %s "$MOD/data/languages/$s.sla"); ((sz < 16000000)) || { echo "FAILED: $s.sla is $sz bytes"; fail=1; }
done

step "decode: all 65,536 first words x 3 second words, Ghidra against Dolphin's DSPTool and the manual's opcode table"
python3 - "$W" <<'PY'
import sys
W = sys.argv[1]
with open(f"{W}/all.txt", "w") as f:
    for w in range(65536):
        for w1 in (0x1234, 0x0000, 0xFFFF): f.write(f"{w:04x}{w1:04x}\n")
with open(f"{W}/first.txt", "w") as f:
    for w in range(65536): f.write(f"{w:04x}1234\n")
PY
ok "$HERE/dis.sh" "$W/all.txt" "$W/all.gh"
ok python3 "$HERE/dolphin_dis.py" "$DSPTOOL" "$W/all.txt" "$W/all.dol" "$W/dw"
ok python3 "$HERE/cmp_dolphin.py" "$W/all.gh" "$W/all.dol" "GCDSP vs DSPTool"
ok "$HERE/dis.sh" "$W/first.txt" "$W/first.gh"
ok python3 "$HERE/dolphin_dis.py" "$DSPTOOL" "$W/first.txt" "$W/first.dol" "$W/dw"
ok python3 "$HERE/check_table.py" "$GCDSP_MANUAL_TEX" "$W/first.gh" "$W/first.dol"

step "every constructor is reached (both languages; loop context set for the loop-end constructors)"
for l in default exact; do
	out=$("$HERE/every-entry.sh" GCDSP:BE:16:$l "$W/ee.$l.txt" "$W/all.txt" -- "$W/first.txt" hasloopjumpback=1 loopjumpbackaddr=9 loopenddepth=1 loopstackdepth=1 \
		-- "$W/first.txt" hasloopjumpback=1 loopjumpbackaddr=9 loopenddepth=2 loopstackdepth=2 \
		-- "$W/first.txt" hasloopjumpback=1 loopjumpbackaddr=9 loopenddepth=3 loopstackdepth=3 \
		-- "$W/first.txt" hasloopjumpback=1 loopjumpbackaddr=9 loopenddepth=0 loopstackdepth=0 | tail -1)
	echo "$l: $out"
	grep -q " 0 not reached" <<<"$out" || { echo FAILED; fail=1; }
done

step "p-code: hand-computed emulator cases (the manual's pseudo-code), a deliberately wrong expectation must be reported"
ok "$HERE/emu-test.sh" "$HERE/emu/cases.txt" "$W/emu"
tail -qn1 "$W"/emu/default.txt "$W"/emu/exact.txt

step "p-code: $N random instructions per opcode against the manual-derived model (both languages)"
ok python3 "$HERE/sem_diff.py" "$W/sd-default" "$N" 1 default
ok python3 "$HERE/sem_diff.py" "$W/sd-exact" "$N" 2 exact
step "p-code: the comparison must fail when the model is wrong"
if GCDSP_MUTATE=1 python3 "$HERE/sem_diff.py" "$W/sd-mut" 10 3 default ADD SUB >"$W/mut.txt" 2>&1; then
	echo "FAILED: the mutated model went undetected"; fail=1
else head -2 "$W/mut.txt"; echo "mutation detected"; fi

if ((REAL)); then
	step "real code"
	ok "$HERE/real-check.sh" "$W"
fi
((fail)) && { echo "SOME CHECKS FAILED"; exit 1; }
echo "ALL CHECKS PASSED"
