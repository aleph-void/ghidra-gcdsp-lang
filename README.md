A SLEIGH processor spec for [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for the GameCube/Wii DSP chip.

This repository is the Ghidra-Rare fork of [Pokechu22/ghidra-gcdsp-lang](https://github.com/Pokechu22/ghidra-gcdsp-lang)
(original authors: Pokechu22 and Tilka; see [CREDITS.md](CREDITS.md)). It targets Ghidra 12.1.x (built and tested
with 12.1.3, 12.1.4 and 12.2). What was changed, how it was verified and what is still missing is in
[GHIDRA-RARE.md](GHIDRA-RARE.md); prebuilt extension zips are on the Releases page of this repository.

## Languages

| Language ID | |
|---|---|
| `GCDSP:BE:16:default` | the original behaviour: `$cr` is assumed to be 0x00ff (so `LRS`/`SRS`/`SRSH` show their real address), reads of `$ac0.m`/`$ac1.m` do not saturate. Use this one to read code |
| `GCDSP:BE:16:exact` | nothing is assumed: `LRS`/`SRS`/`SRSH` use `$cr` at run time (needed for the Zelda ucode, which sets `$cr` to 4) and `$ac0.m`/`$ac1.m` reads saturate in 40-bit mode. Noisier decompiler output |

## Installation

Install the extension zip with File &rarr; Install Extensions, or put (or symlink) this repository into the
Ghidra install as `Ghidra/Processors/GCDSP`, such that `Ghidra/Processors/GCDSP/data` is the path to the `data`
folder. Ghidra compiles the `.slaspec` files when the language is first used. (A source checkout needs
`test/build-jar.sh` once to build `lib/GCDSP.jar`, the loader; the release zip contains it.)

## Usage

DSP code lives in instruction RAM at `inst:0000` (the default address space of this language; the original
module had `data` as the default, which is why it asked for `inst:0000` explicitly). The hardware vectors
(`RST0`..`RST7`, 2 words each, `inst:0000`-`000f`), the conventional main entry `MAIN` (`inst:0010`), the
boot ROM entry `IROM_START` (`inst:8000`) and the memory-mapped registers (`data:ff00`-`ffff`) are labelled.

1. Select File &rarr; Import File and choose a file containing DSP ucode (e.g. one dumped by Dolphin when `DumpUCode` is set to `True`).
2. Pick the format **GameCube/Wii DSP ucode (raw binary)** and the language `GCDSP:BE:16:default`. Click OK.
   The loader creates `iram` (the ucode), `irom`, `dram`, `coef` and `ifx` (volatile registers). If the files
   `dsp_rom.bin` and `dsp_coef.bin` are in the same folder as the ucode, they are loaded into `irom` (`inst:8000`)
   and `coef` (`data:1000`) so that calls into the boot ROM resolve and analysis follows them. Dolphin's
   [free DSP rom](https://github.com/dolphin-emu/dolphin/blob/master/Data/Sys/GC/dsp_rom.bin?raw=true) and
   [free DSP coef](https://github.com/dolphin-emu/dolphin/blob/master/Data/Sys/GC/dsp_coef.bin?raw=true) will work.
3. Run analysis as normal (headless: `-loader GCDSPLoader`).

The original manual procedure (Raw Binary loader, block name `iram`, base address `inst:0000`, deleting the
default `irom` and `coef` blocks, then File &rarr; Add To Program for `dsp_rom.bin` at `inst:8000` and
`dsp_coef.bin` at `data:1000`) still works but is no longer needed.

## Known limitations of the original module

The original README listed only the import procedure; the rest comes from the `TODO`/`unimpl` comments of the
specification and from testing. Status in this fork:

| Limitation | Status |
|---|---|
| Import needs 25 manual steps | Fixed: `GCDSPLoader` |
| `$sr` could not be read or written as a register (the flags are separate pseudo registers) | Fixed: `MRR`, `LRI`, `LR`, `SR`, `SRR*`, ... assemble and split `$sr` |
| `$cr` assumed 0x00ff (wrong for the Zelda ucode) | Fixed in `GCDSP:BE:16:exact`; the default language keeps the assumption on purpose |
| Reads of `$ac0.m`/`$ac1.m` never saturate in 40-bit mode (the option did not even compile) | Fixed in `GCDSP:BE:16:exact` |
| `LSRN`/`ASRN` and friends were opaque `pcodeop`s | Fixed: exact p-code |
| Extension opcodes ran after the main opcode ("not emulated" in parallel) | Fixed: sources read before, destination written after |
| `$sr.AM` (multiply by 2) ignored; product register not the `$prod.*` registers | Fixed |
| `ADDR`/`SUBR`/`CLRL`/`ADDPAXZ`/`CMPAXH`/`SUB`/`NEG` flag and value errors, `SBCLR`/`SBSET` swapped | Fixed |
| `RTI` "TODO: return address", `CALLR` "TODO: update stack", `IF` unimplemented, `CALLcc` clobbers `$st0` | Fixed |
| Nested hardware loops hang when an inner loop starts the outer body | Fixed |
| Two loops that end on the same instruction | Remaining: the innermost is modelled (context size) |
| Wrap registers `$wr0`-`$wr3` (circular addressing) | Remaining: the wrap rule is not in the manual |
| `$sr.SU` (unsigned multiply) | Remaining: not in the manual |
| Hardware stacks `$st0`-`$st3` (push/pop on access, depth limits, STOVF) | Remaining: `$st0` holds the return address, the others are plain registers |
| Interrupts, DMA, accelerator, mailboxes | Remaining: hardware state |

## Manuals

The only manual is the [GameCube DSP User's Manual](https://github.com/dolphin-emu/dolphin/tree/master/docs/DSP/GameCube_DSP_Users_Manual), which is unfortunately incomplete.  I plan on adding to it with information I've found while working on this.

There is also documentation in Dolphin's [DSPTables.cpp](https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/Core/DSP/DSPTables.cpp) and in [Dolphin's interpreter](https://github.com/dolphin-emu/dolphin/tree/master/Source/Core/Core/DSP/Interpreter).  However, DSPTables is a bit confusing to read with regards to instruction decoding, and some of the interpreter comments (e.g. those for `'LD`) are incorrect.  The code itself can also be used as a reference.
