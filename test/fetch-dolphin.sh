#!/usr/bin/env bash
# test/fetch-dolphin.sh <workdir>
# Fetches, at pinned commits, the pieces of Dolphin (GPL-2.0-or-later) and {fmt} (MIT) that the suite uses:
#   - the DSP User's Manual (the opcode tables of the model in gcdsp_model.py),
#   - DSPTool's sources (Source/DSPTool, Source/Core/Core/DSP, parts of Source/Core/Common), built as a
#     black box by build-dsptool.sh: the module never reads or copies them,
#   - the free-DSP-ROM source and binaries and the DSPSpy test programs, the real code of the suite.
# Everything lands in <workdir>/dolphin and is checked against test/real/SHA256SUMS.  Nothing is committed.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "${1:?usage: fetch-dolphin.sh <workdir>}" && cd "$1" && pwd)
DOLPHIN_URL=https://github.com/dolphin-emu/dolphin.git
DOLPHIN_SHA=3eb30c7620b4475b2e0404228ba0d2b238a132f1
FMT_URL=https://github.com/fmtlib/fmt.git
FMT_SHA=f87a75e15262614ce8aa0e6a0664df9d0823fb92
if [[ ! -d $W/dolphin/.git ]]; then
	git init -q "$W/dolphin"
	git -C "$W/dolphin" remote add origin "$DOLPHIN_URL"
	git -C "$W/dolphin" sparse-checkout set --no-cone /Source/DSPTool /Source/Core/Core/DSP /Source/Core/Common \
		/Source/Core/Core/Host.h /Source/DSPSpy/tests /docs/DSP /Data/Sys/GC/dsp_rom.bin /Data/Sys/GC/dsp_coef.bin \
		/Source/Core/Common/Logging
fi
git -C "$W/dolphin" fetch -q --depth 1 --filter=blob:none origin "$DOLPHIN_SHA"
git -C "$W/dolphin" checkout -q FETCH_HEAD
if [[ ! -d $W/fmt/.git ]]; then git init -q "$W/fmt"; git -C "$W/fmt" remote add origin "$FMT_URL"; fi
git -C "$W/fmt" fetch -q --depth 1 origin "$FMT_SHA"
git -C "$W/fmt" checkout -q FETCH_HEAD
(cd "$W/dolphin" && sha256sum -c --quiet "$HERE/real/SHA256SUMS") || { echo "checksum mismatch" >&2; exit 1; }
echo "fetched Dolphin $DOLPHIN_SHA and fmt $FMT_SHA into $W"
