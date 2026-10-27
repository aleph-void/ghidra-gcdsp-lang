# Credits

This is a derivative of **ghidra-gcdsp-lang**, the GameCube/Wii DSP processor module for Ghidra.

| | |
|---|---|
| Upstream | https://github.com/Pokechu22/ghidra-gcdsp-lang |
| Upstream commit | `2e9eeb7f9409617f88f09eef95e1a976b369563d` (merge of pull request #1 from Tilka, 2025-04-27) |
| License | Apache License 2.0 (`LICENSE`; upstream shipped the Ghidra template `LICENSE.txt`, which names the license) |
| Original authors | Pokechu22 (@Pokechu22; the SLEIGH specification, README), Tilka (@Tilka; pull request #1, "Update MMIO labels") |

The upstream history is a single squashed commit by Pokechu22 that includes Tilka's pull request. Copyright
and license headers are kept as they were. Everything the original authors wrote stays under the Apache
License 2.0, and so do the modifications listed below.

## Sources used by the changes below

* Duddie's **GameCube DSP User's Manual** v0.1.8 (reverse-engineered by Duddie, maintained in the Dolphin
  repository, `docs/DSP/GameCube_DSP_Users_Manual`; GNU Free Documentation License 1.2 or later). It is the
  reference for the opcode table and the pseudo-code of every instruction; the test model
  (`test/gcdsp_model.py`) is written from it. It is fetched at test time (pinned commit and SHA-256), not
  copied into this repository.
* **Dolphin's DSPTool** (GPL-2.0-or-later) was built from source and run as a black box (assembler and
  disassembler) for differential testing. Its sources, its opcode tables and its DSP interpreter were not
  read, and nothing in this repository is taken from them. Dolphin's free DSP ROM source and the DSPSpy test
  programs (GPL-2.0-or-later) are fetched at test time as sample code and are not part of this repository.
* The Ghidra SLEIGH documentation and the Ghidra source code of the sleigh compiler and emulator (Apache-2.0).

## What Ghidra-Rare changed

All changes are commits on the `ghidra-rare` branch on top of the upstream commit.

* The specification is split into `GCDSP.sinc` (all instructions) and two thin wrappers selecting options:
  `GCDSP.slaspec` (language `GCDSP:BE:16:default`, as before) and `GCDSP_exact.slaspec` (new language
  `GCDSP:BE:16:exact`: `$cr` and 40-bit saturation modelled at run time).
* `inst` is now the default address space and a `pc` register is defined (the emulator needs both); data
  accesses name the `data` space explicitly. Default entry symbols `MAIN` (0x0010) and `IROM_START` (0x8000) added.
* Decoding: `SBCLR`/`SBSET` accept all words 0x12xx/0x13xx (bits 3-7 are don't-care in the manual's table) and
  their polarity was swapped (SBCLR set the bit); extension `'NOP` accepts low bits 01-11; words 0x0001-0x0003 decode as `NOP`
  (Dolphin does); `0010 101x` decodes as a no-op `UNUSED2A` (the manual: "seems to do nothing").
* Semantics, found by the emulator comparison against the manual-derived model: the product register
  (`$prod.l/.m1/.h/.m2`, with `$sr.AM` doubling) replaces an unrelated 40-bit pseudo register;
  `ADDR`/`SUBR` add the register to the middle of the accumulator; `CLRL` rounds to even; `ADDPAXZ` per
  the manual; `CMPAXH` operand size; overflow flag of `SUB`/`CMP`/`NEG`/`CMPI` (`sborrow`); `LSRNRX`/`ASRNRX`
  shift operand; extension opcodes run in parallel with the main opcode (sources read before, destination written
  after); `$sr`, `$cr` and `$prod.h` accessed as registers (`MRR`, `LRI`, `LR`, `SR`, ...); `CALLcc`/`CALLRcc`
  keep `$st0` when not taken and store word addresses; `RTI` restores `$sr`; unconditional `IF`; `LRR*`
  update the pointer before writing the destination; flag macros no longer take the high bytes of a
  big-endian register (`reg:4` on a fixed register); the saturation macros (never compiled upstream) work;
  the two-way shifts are exact p-code (no `twowaylogicalshift` pcodeop).
* Hardware loops rewritten so that they nest (a loop instruction that starts another loop's body hung the
  emulator): the zero-count test sits in the loop instruction and the counter decrement and jump back in the
  last body instruction.
* New: `GCDSPLoader` (raw ucode dumps, with `dsp_rom.bin`/`dsp_coef.bin` picked up next to them) replacing
  the 25-step manual import; `build.gradle`, `extension.properties`; the test suite under `test/`;
  `GHIDRA-RARE.md`; the full Apache-2.0 `LICENSE`; README updates.
