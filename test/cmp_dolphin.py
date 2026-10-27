#!/usr/bin/env python3
"""Compare Ghidra decode output (dis.sh) with Dolphin DSPTool output (dolphin_dis.py).
usage: cmp_dolphin.py <ghidra.out> <dolphin.out> [label] [-v]
Exact = same text after case/space folding.  Explained = same instruction after the display rules in
RULES below (each documented in GHIDRA-RARE.md).  Anything else is "unexplained".  Exit 1 if any."""
import sys, re, collections, os, xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
PSPEC = os.path.join(HERE, '..', 'data', 'languages', 'GCDSP.pspec')
SYM = {s.get('name').lower(): int(s.get('address').split(':')[1], 16)
       for s in ET.parse(PSPEC).getroot().iter('symbol') if s.get('address', '').startswith('data:')}
SRBITS = ['sr_logic_zero_', 'sr_overflow_sticky_', 'sr_100_', 'sr_int_enable_', 'sr_400_',
          'sr_ext_int_enable_', 'sr_1000_', 'sr_mul_modify_']

def fold(t):
    t = re.sub(r'\s+', ' ', t.lower().replace('\t', ' ')).strip()
    t = re.sub(r' ?: ?', ' : ', t) if "'" in t.split(' ')[0] else t
    t = re.sub(r'^(j|call)mpr?x([89ab])\b', lambda m: m.group(1)[0] + ('r' if 'r' in m.group(0)[:6] else '') + 'x' + m.group(2), t) if False else t
    t = re.sub(r'^jmprx([89ab])\b', r'jrx\1', t)
    t = re.sub(r'^jmpx([89ab])\b', r'jx\1', t)
    return re.sub(r"^([^ $@#]+)(?=[$@#])", r"\1 ", t)       # Dolphin glues long mnemonics to the operands

def num(m):
    return str(int(m.group(0), 16))

def canon_common(t):
    return re.sub(r'0x[0-9a-f]+', num, t)

def mnem(t):
    return t.split(' ')[0]

MANUAL_VS_DOLPHIN = {'maddc', 'msubc', 'addpaxz', 'clrl'}

def rules(g, d):
    """Return (rule-name, g2, d2) after applying display rules to both strings; or None."""
    gm, dm = mnem(g).split("'")[0], mnem(d).split("'")[0]
    applied = []
    # R0: named hardware registers (Dolphin prints COEF_A1_0, CMBL, ... for data addresses >= 0xff00)
    def sym(m):
        nm = m.group(2).lower()
        return m.group(1) + (str(SYM[nm]) if nm in SYM else m.group(2))
    d2 = re.sub(r'(@|, |^[a-z0-9]+ )([a-z][a-z0-9_]*)\b(?!\.)', lambda m: sym(m) if m.group(2).lower() in SYM else m.group(0), d)
    if d2 != d: applied.append('hwreg-name')
    d = d2
    # R1: LRS/SRS/SRSH/SI show the full address (CR assumed 0xff, SI always 0xFF00|M); Dolphin shows the 8-bit field
    if re.match(r'(lrs|srs|srsh|si)\b', gm):
        g2 = re.sub(r'@(\d+)', lambda m: '@' + str(int(m.group(1)) & 0xff), canon_common(g))
        d2 = re.sub(r'@(\d+)', lambda m: '@' + str(int(m.group(1)) & 0xff), canon_common(d))
        if g2 != canon_common(g): applied.append('addr8')
        g, d = g2, d2
    # R2: 8-bit immediates: Ghidra prints sign-extended (negative) values, Dolphin the raw byte
    if gm in ('lris', 'addis', 'cmpis', 'addi', 'cmpi'):
        mask = 0xffff if gm in ('addi', 'cmpi') else 0xff
        g2 = re.sub(r'#(-\d+)', lambda m: '#' + str(int(m.group(1)) & mask), canon_common(g))
        if g2 != canon_common(g): applied.append('imm8')
        g = g2
    # R3: ADDIS/CMPIS operate on the 24-bit $acD.hm; the manual spells the operand $acD, Dolphin $acD.m
    if gm in ('addis', 'cmpis', 'cmpi'):
        d2 = re.sub(r'\$ac(\d)\.m', r'$acc\1', d)
        if d2 != d: applied.append('acc-name')
        d = d2
    # R4: INCM/DECM: the manual spells the operand $acsD (24-bit), Dolphin $acD.m
    if re.match(r'(incm|decm|addi)\b', gm):
        d2 = re.sub(r'\$ac(\d)\.m', r'$acs\1', d, count=1)
        if d2 != d: applied.append('acs-name')
        d = d2
    # R5: BLOOP/BLOOPI show the address after the loop end (label placement), Dolphin the last loop address
    if gm in ('bloop', 'bloopi'):
        g2 = re.sub(r', (\d+)$', lambda m: ', ' + str((int(m.group(1)) - 1) & 0xffff), canon_common(g))
        d2 = canon_common(d)
        if g2 != canon_common(g): applied.append('bloop+1')
        g, d = g2, d2
    # R6: the index register that is added by the N forms is shown (it is the same field as $ar)
    g2 = re.sub(r', \$ix\d(?= :|$)', '', g) if re.search(r"(rrn|subarn|addarn|'?\w*n\b)", g) else g
    if "'" in mnem(g) or re.match(r'(ilrrn|lrrn|srrn)', gm):
        g2 = re.sub(r', \$ix\d$', '', g)
        g2 = re.sub(r"(\$ix\d)(?= :)", '', g2) if False else g2
    if gm in ('ilrrn', 'lrrn', 'srrn'):
        g2 = re.sub(r', \$ix\d$', '', g)
    if g2 != g: applied.append('ix-shown'); g = g2
    # R7: shift amounts: Dolphin prints the signed 6-bit field, Ghidra the amount in the direction of the instruction
    if gm in ('lsl', 'asl') and dm == gm:
        d2 = re.sub(r'#(-?\d+)', lambda m: '#' + str(int(m.group(1)) & 63), canon_common(d))
        if d2 != canon_common(d): applied.append('shift')
        g, d = canon_common(g), d2
    if gm in ('lsr', 'asr') and dm == gm:
        d2 = re.sub(r'#(-?\d+)', lambda m: '#' + str((-int(m.group(1))) & 63), canon_common(d))
        if d2 != canon_common(d): applied.append('shift')
        g, d = canon_common(g), d2
    # R8: SBCLR/SBSET #n -> status bit name
    if gm in ('sbclr', 'sbset') and dm == gm:
        mm = re.search(r'#(0x[0-9a-f]+|\d+)', d)
        if mm:
            n = int(mm.group(1), 0) & 7
            d = f"{dm} {SRBITS[n]}"; applied.append('sr-bit')
    # R10: condition names for 8..B
    g = re.sub(r'^(j|jr|call|callr|ret|rti|if)(x[89ab])\b', r'\1\2', g)
    return applied, canon_common(g), canon_common(d)

def load(p):
    d = []
    for l in open(p):
        parts = l.rstrip('\n').split(' ', 2)
        d.append((parts[0], int(parts[1]), parts[2] if len(parts) > 2 else ''))
    return d

def main():
    g, d = load(sys.argv[1]), load(sys.argv[2])
    label = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('-') else ''
    verbose = '-v' in sys.argv
    assert [x[0] for x in g] == [x[0] for x in d]
    agree = both_bad = 0
    expl = collections.Counter(); unexp = collections.Counter(); ex = {}
    for (h, gn, gt), (_, dn, dt) in zip(g, d):
        dbad = 'unknown opcode' in dt.lower() or "'xxx" in dt.lower()
        gbad = gt == 'BAD'
        if gbad and dbad: both_bad += 1; continue
        # C1: the manual lists the extension 'NOP as 0000 00xx (any low two bits); Dolphin rejects 01..03
        if dbad and "'xxx" in dt.lower() and not gbad and (int(h[2:4], 16) & 0x7c) == 0 and "'" not in gt \
                and mnem(fold(gt)) == mnem(fold(dt)).split("'")[0]:
            expl["ext-nop-low-bits"] += 1; continue
        if not gbad and not dbad and gn == dn * 2 and fold(gt) == fold(dt): agree += 1; continue
        if gbad or dbad or gn != dn * 2:
            k = ('ghidra-bad dolphin=' + mnem(fold(dt)) if gbad else
                 'dolphin-invalid ghidra=' + mnem(fold(gt)) if dbad else 'length ' + mnem(fold(gt)))
            unexp[k] += 1; ex.setdefault(k, []).append((h, gt, dt)); continue
        applied, g2, d2 = rules(fold(gt), fold(dt))
        # C2: operand encodings where the manual and Dolphin's disassembler disagree (see GHIDRA-RARE.md)
        if g2 != d2 and mnem(g2).split("'")[0] in MANUAL_VS_DOLPHIN:
            expl['manual-vs-dolphin:' + mnem(g2).split("'")[0]] += 1; continue
        if g2 == d2:
            for a in applied: expl[a] += 1
            if not applied: expl['(none)'] += 1
        else:
            k = 'text ' + mnem(g2)
            unexp[k] += 1; ex.setdefault(k, []).append((h, gt, dt))
    print(f"{label}: {len(g)} cases: {agree} exact, {both_bad} both invalid, {sum(expl.values())} explained "
          f"({', '.join(f'{k} {v}' for k, v in sorted(expl.items()))}), {sum(unexp.values())} unexplained")
    for k, n in unexp.most_common(80 if not verbose else 10**6):
        e = ex[k][0]
        print(f"  {n:6d} {k}   e.g. {e[0]} ghidra={e[1]!r} dolphin={e[2]!r}")
    sys.exit(1 if unexp else 0)
main()
