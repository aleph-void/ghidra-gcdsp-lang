# GCDSP: verification notes (Ghidra-Rare)

Languages `GCDSP:BE:16:default` and `GCDSP:BE:16:exact` (see README.md). Provenance and the list of changes are
in [CREDITS.md](CREDITS.md). Everything below is reproduced by

    GHIDRA_INSTALL_DIR=<Ghidra with this module linked as Ghidra/Processors/GCDSP> test/run-tests.sh [--real] [--n 150] <workdir>

(needs python3, g++ with C++23, git and network access: the first run fetches Dolphin's DSP manual and DSPTool
sources at pinned commits, see `test/fetch-dolphin.sh`; nothing fetched is committed). Run against Ghidra
12.1.4; the release zips also build for 12.1.3 and 12.2 (the specs are compiled with each version's SLEIGH compiler).

## Results

| Area | Result |
|---|---|
| Build | Both specs compile on 12.1.3, 12.1.4 and 12.2 with `sleigh -l` (no pattern conflicts); `.sla` about 28 KB |
| Decode vs Dolphin DSPTool | All 65,536 first words x 3 second words (196,608 cases): 130,212 exact, 2,109 both invalid, 68,584 explained, 0 unexplained. Explained classes are display only (see below) plus the four operand-field disagreements between the manual and DSPTool |
| Decode vs the manual's opcode table | 64,976 of 65,536 first words agree with manual and DSPTool; the other 560 are documented (`0010 101x` no-op, `0001`-`0003` NOP, Dolphin's spelling of conditions x8-xB) |
| Every constructor reached | 481/481 in both languages (loop-end constructors with loop context set) |
| Semantics | 58 (default) / 61 (exact) hand-computed emulator cases from the manual's pseudo-code (ALU and flags, shifts, product register and `$sr.AM`, loads/stores with pointer update, `$sr` access, extension parallel semantics, IF, jumps, calls, LOOP/LOOPI/BLOOP/BLOOPI incl. nested and zero count, 40-bit saturation, `$cr`), 0 failures; one deliberately wrong expectation is reported. 12,000 random single instructions per language (100 per opcode x 120 opcode forms, random registers, flags, `$sr.SXM`, memory) agree with an independent model written from the manual (`test/gcdsp_model.py`); a mutated model is detected. |
| Real code | 24 DSPSpy test programs (Dolphin, GPL-2.0-or-later; assembled with DSPTool; imported with `GCDSPLoader` with Dolphin's free ROM next to them), full auto-analysis: 8,780 instructions, 640 functions, 0 bad-instruction or error bookmarks, 0 decompile failures or timeouts; every instruction re-decoded by DSPTool from its own words: 0 unexplained differences. The free ROM source assembles to the shipped `dsp_rom.bin` |
| Doesn't work | Wrap registers `$wr0`-`$wr3` ignored; `$sr.SU` unsigned multiply ignored; hardware stack behaviour of `$st0`-`$st3` (push/pop on access, depth limits, STOVF); two loops ending on one instruction; interrupts, DMA, accelerator, mailboxes. Reasons below |
| Unverified | MADDC/MSUBC/ADDPAXZ/CLRL operand fields (manual and DSPTool disagree); flag C of MOVP/MOVNP/MOVPZ/MULxx (manual: "changes", formula not given; the module clears it); `IFcc` before a two-word instruction; behaviour on hardware (no hardware tests) |

## Method

* **Decode.** DSPTool (Dolphin's assembler and disassembler, built from source and used as a black box) decodes
  every first word with three second words; the text is compared after case/space folding and the display rules
  of `test/cmp_dolphin.py`. `test/check_table.py` compares the mnemonic with the manual's "Instructions sorted by
  opcode" table.
* **Semantics.** `test/gcdsp_model.py` implements the instruction set from the manual's operation pseudo-code,
  the flag rules and the register descriptions only. `test/sem_diff.py` generates random instructions
  (including a random valid extension for each arithmetic opcode), runs each in Ghidra's emulator
  (`test/EmuDiff.java`) and compares all registers, status bits, memory and the PC. The hand cases
  (`test/emu/cases.txt`) are separate and were worked out from the manual by hand; they run through
  disassembly first so that the loop context is set as in a real analysis.
* **Real code.** `test/real-check.sh`.

## Display rules (the "explained" decode classes)

`LRS/SRS/SRSH/SI` show the full address (`0xff00 | m`, `$cr` assumed 0xff in the default language) where DSPTool shows
the 8-bit field; named hardware registers (`@CMBL`) are numbers here (the pspec labels them); 8-bit and 16-bit
immediates print signed here, unsigned there; `ADDIS/CMPIS/CMPI` operate on `$acD` (manual) where DSPTool prints
`$acD.m`; `INCM/DECM/ADDI` print `$acsD` (manual); `BLOOP/BLOOPI` show the address after the loop end (label placement);
the `N` forms show the index register that is added; shifts: DSPTool prints the signed 6-bit field, the module the
amount in the direction of the mnemonic; `SBCLR/SBSET` show the status bit name; extension `'NOP` with low bits 01-11
(manual: `0000 00xx`; DSPTool rejects them).

## Manual versus Dolphin's disassembler

For four instructions DSPTool's operand fields differ from the manual (v0.1.8); this module follows the manual and
the question stays open without hardware:

| Instruction | Manual | DSPTool |
|---|---|---|
| ADDPAXZ `1111 10sd` | `$acD` = bit 8, `$axS` = bit 9 | bits swapped (assembler and disassembler agree with each other) |
| CLRL `1111 110r` | `$acR.l`, r = bit 8 | always `$ac1.l`, bit 8 ignored (its assembler encodes `$ac0.l` and `$ac1.l` identically) |
| MADDC/MSUBC `1110 1xst` | `$acS.m, $axT.h` | `$acS.m, $ax1.l/$ax1.h` (its assembler accepts `$ax1.l` and `$ax0.h`, a third reading) |

## Confirmed bugs in the reference tools

* DSPTool's assembler encodes `clrl $ac0.l` and `clrl $ac1.l` identically (`0xFC00`) and rejects `maddc $ac0.m, $ax1.h`
  although its own disassembler prints that operand for `0xE900`.
* The manual: ADDPAXZ's pseudo-code names `$ax.h` where its description says `$axS`; MULC's description says `$axS.h`
  for `$axT.h`; the S32 flag column is 0 for MOV where the result can exceed 32 bits (the module computes it).

## Doesn't work

| Gap | Why |
|---|---|
| Wrap registers `$wr0`-`$wr3` ignored (circular addressing; the module increments like `$wr` = 0xffff) | the manual does not say how `$wr` is applied; the only descriptions are in GPL sources that were not read for this module |
| `$sr.SU` (unsigned multiply) ignored | the manual says "operands are unsigned" without saying which operand of which instruction |
| `$st0`-`$st3` are plain registers (`CALL` writes the return address to `$st0`; no push/pop on access, no depth limit, no STOVF) | the manual does not specify register-access side effects |
| Two loops ending on the same instruction: only the innermost jumps back | loop state is kept in the 64-bit disassembly context, which has no room for a second back edge |
| Interrupts, `HALT` (an endless loop), DMA, accelerator, mailboxes | hardware state outside the instruction set |
| 40-bit saturation and the run-time `$cr` exist only in `GCDSP:BE:16:exact` | they make decompiler output much noisier; the default language assumes 16-bit stores and `$cr` = 0xff |
