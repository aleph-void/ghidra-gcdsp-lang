#!/usr/bin/env python3
"""Disassemble cases (hex strings, 4 hex digits per word, one case per line) with Dolphin's DSPTool,
as a black box.  Output lines: "<hex> <nwords> <text>" ("UNKNOWN" for unknown opcodes).
usage: dolphin_dis.py <dsptool> <cases.txt> <out.txt> <workdir>"""
import re, struct, subprocess, sys, os
tool, cases, out, wd = sys.argv[1:5]
os.makedirs(wd, exist_ok=True)
lines = [l.strip() for l in open(cases) if l.strip()]
CH = 10000
res = []
for c0 in range(0, len(lines), CH):
    chunk = lines[c0:c0 + CH]
    words = []
    for l in chunk:
        w = [int(l[i:i + 4], 16) for i in range(0, len(l), 4)]
        w = (w + [0, 0])[:2] + [0]          # case = 2 words + a nop pad: keeps cases aligned
        words += w
    bf = os.path.join(wd, 'in.bin'); tf = os.path.join(wd, 'out.txt')
    open(bf, 'wb').write(b''.join(struct.pack('>H', x) for x in words))
    subprocess.run([tool, '-d', '-o', tf, bf], check=True, stdout=subprocess.DEVNULL)
    byaddr = {}
    for t in open(tf):
        m = re.match(r'^([0-9a-f]{4}) ((?:[0-9a-f]{4} ?)+?)\s+(\S.*?)\s*$', t.rstrip('\n'))
        if not m:
            continue
        byaddr[int(m.group(1), 16)] = (len(m.group(2).split()), m.group(3))
    for i, l in enumerate(chunk):
        n, txt = byaddr[3 * i]
        res.append(f"{l} {n} {txt.replace(chr(9), ' ')}")
open(out, 'w').write('\n'.join(res) + '\n')
