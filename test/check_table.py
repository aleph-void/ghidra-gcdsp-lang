#!/usr/bin/env python3
"""Compare the mnemonic Ghidra decodes (and Dolphin's) for every 16-bit first word against the
manual's opcode table.  usage: check_table.py <manual.tex> <ghidra.out> <dolphin.out>  (the cases
files hold <word><word2> lines with word2 = 1234, one per first word, in order)."""
import sys, re, collections
sys.path.insert(0, __import__('os').path.dirname(__file__))
from manual_table import load, match
main, ext = load(sys.argv[1])
CC = {'GE','L','G','LE','NZ','Z','NC','C','X8','X9','XA','XB','LNZ','LZ','O',''}
FAM = [('CALLR','CALLRcc'),('CALL','CALLcc'),('RET','RETcc'),('RTI','RTIcc'),('IF','IFcc'),('JR','JRcc'),('JMPR','JMPR'),('JMP','JMP'),('J','Jcc')]
def fam(m):
    m = m.upper()
    for p, n in FAM:
        if m.startswith(p) and m[len(p):] in CC:
            return n if m[len(p):] or p in ('JMP','JMPR') else n
    return m
def manual_names(w):
    names = [n for n, p in main if match(p[:16], w)]
    return sorted(set('Jcc' if n == 'JMP' else n for n in names))
def load_out(p):
    d = {}
    for l in open(p):
        h, n, t = l.rstrip('\n').split(' ', 2) if l.count(' ') >= 2 else (l.split()[0], l.split()[1], 'BAD')
        d[int(h[:4], 16)] = t
    return d
g, dol = load_out(sys.argv[2]), load_out(sys.argv[3])
def base(t):
    if t == 'BAD' or 'UNKNOWN' in t.upper(): return None
    return fam(t.split("'")[0].split()[0])
bad = collections.Counter(); ex = {}
n_ok = 0
for w in range(65536):
    man = manual_names(w)
    gm, dm = base(g[w]), base(dol[w])
    man_s = man[0] if len(man) == 1 else ('/'.join(man) if man else None)
    if man_s in ('JMP',): man_s = 'Jcc'
    norm = lambda x: {'JMP':'Jcc','JMPR':'JRcc','CALLR':'CALLRcc'}.get(x, x)
    ok = (norm(gm) == norm(man_s)) if man_s else gm is None
    # unconditional spellings
    if gm in ('JMP','JMPR','CALL','RET','RTI','IF') : ok = ok or True
    key = (man_s, gm, dm)
    if man_s == gm and gm == dm: n_ok += 1; continue
    bad[key] += 1; ex.setdefault(key, []).append(w)
ALLOWED = {   # documented in GHIDRA-RARE.md
    (None, 'UNUSED2A', None): "0010 101x: not in the manual's table; decoded as a no-op (the manual: 'seems to do nothing')",
    (None, 'NOP', 'NOP'): "0001-0003: unassigned in the manual; Dolphin and this module treat them as NOP",
    ('JRcc', 'JMPR', 'JMPR'): "unconditional JRcc spelled JMPR (both tools)", ('JRcc', 'JRcc', 'JMPR'): "Dolphin spells condition x8-xB differently",
    ('Jcc', 'Jcc', 'JMP'): "Dolphin spells condition x8-xB differently", ('Jcc', 'JMP', 'JMP'): "unconditional Jcc spelled JMP (both tools)",
}
bad_total = 0
print(f"manual == ghidra == dolphin on {n_ok}/65536 first words")
for k, n in sorted(bad.items(), key=lambda x: -x[1]):
    e = ex[k]
    tag = 'documented' if k in ALLOWED else 'UNEXPLAINED'
    if k not in ALLOWED: bad_total += n
    print(f"{n:6d} manual={k[0]} ghidra={k[1]} dolphin={k[2]}  e.g. {e[0]:04x}..{e[-1]:04x}  [{tag}]")
sys.exit(1 if bad_total else 0)
