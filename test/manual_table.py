#!/usr/bin/env python3
"""Opcode patterns transcribed (mechanically) from the "Instructions sorted by opcode" table of the
GameCube DSP User's Manual v0.1.8 (Duddie; GFDL, docs/DSP/GameCube_DSP_Users_Manual in the Dolphin
repository).  usage: manual_table.py <tex>  -> prints "name pattern" lines (also importable)."""
import re, sys

def load(tex):
    t = open(tex).read()
    t = t[t.index('Instructions sorted by opcode'):]
    main, ext = [], []
    cur = main
    for line in t.split('\n'):
        if 'Extension Opcodes' in line:
            cur = ext
        m = re.match(r'\\OpcodeRow\{([01a-z ]+)\}\{(.*?)\}', line)
        if m:
            cur.append((m.group(2), m.group(1).replace(' ', '')))
    return main, ext

def match(pat, w):
    """pat: 16 or 32 chars of 0/1/letters; w: 32-bit value (first word in the high half when 32)."""
    n = len(pat)
    for i, c in enumerate(pat):
        if c in '01':
            bit = (w >> (n - 1 - i)) & 1
            if bit != int(c):
                return False
    return True

if __name__ == '__main__':
    m, e = load(sys.argv[1])
    for n, p in m + e:
        print(n, p)
