#!/usr/bin/env bash
# test/build-dsptool.sh <workdir>   (after fetch-dolphin.sh)
# Builds Dolphin's DSPTool (assembler and disassembler for the GameCube DSP) from the fetched sources
# with g++ (C++23), without the rest of Dolphin.  Used only as a black-box reference.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(cd "${1:?usage: build-dsptool.sh <workdir>}" && pwd)
D=$W/dolphin; F=$W/fmt; B=$W/dsptool-build
[[ -x $W/dsptool ]] && { echo "$W/dsptool exists"; exit 0; }
mkdir -p "$B"; cd "$B"
CXX="g++ -std=c++23 -O1 -w -DDATA_DIR=\"/x/\" -I$D/Source/Core -I$F/include"
for f in "$D"/Source/DSPTool/DSPTool.cpp "$D"/Source/DSPTool/StubHost.cpp \
	"$D"/Source/Core/Core/DSP/{DSPAssembler,DSPDisassembler,DSPTables,DSPCodeUtil,LabelMap}.cpp \
	"$D"/Source/Core/Common/{StringUtil,FileUtil,IOFile,CommonFuncs,MsgHandler}.cpp "$F"/src/format.cc "$F"/src/os.cc \
	"$HERE/dsptool_stub.cpp"; do
	$CXX -c "$f" -o "$(basename "$f").o"
done
g++ ./*.o -o "$W/dsptool"
echo "built $W/dsptool"
