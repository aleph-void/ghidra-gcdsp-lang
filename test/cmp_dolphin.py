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

def manual_vs_dolphin(g, d):
    """True when g and d differ only by the documented operand-field disagreement between the manual
    (followed by this module) and Dolphin's disassembler:
      ADDPAXZ  the s and d bits are swapped (manual "1111 10sd": $acD is bit 8, $axS is bit 9);
      CLRL     Dolphin prints $ac1.l whatever bit 8 says (manual "1111 110r");
      MADDC/MSUBC  second operand: manual $axT.h (T = bit 8), Dolphin $ax1.l / $ax1.h."""
    gm = mnem(g).split("'")[0]
    gp, dp = (g.split(' : ') + [''])[:2], (d.split(' : ') + [''])[:2]
    if gp[1] != dp[1]: return False                 # the extension part must agree exactly
    a, b = gp[0].split(' ', 1)[1], dp[0].split(' ', 1)[1]
    if gm == 'addpaxz':
        m = re.fullmatch(r'\$acc(\d), \$ax(\d)', a); n = re.fullmatch(r'\$acc(\d), \$ax(\d)', b)
        return bool(m and n and m.group(1) == n.group(2) and m.group(2) == n.group(1))
    if gm == 'clrl':
        return re.fullmatch(r'\$ac[01]\.l', a) is not None and b == '$ac1.l'
    m = re.fullmatch(r'\$ac(\d)\.m, \$ax(\d)\.h', a); n = re.fullmatch(r'\$ac(\d)\.m, \$ax1\.([lh])', b)
    return bool(m and n and m.group(1) == n.group(1) and m.group(2) == ('1' if n.group(2) == 'h' else '0'))

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

def classify(h, gn, gt, dn, dt):
    """Classify one case: ('exact',) ('both-invalid',) ('explained', name) or ('diff', key)."""
    dbad = 'unknown opcode' in dt.lower() or "'xxx" in dt.lower()
    gbad = gt == 'BAD'
    if gbad and dbad: return ('both-invalid',)
    # C0: 0010 101x mmmm mmmm is unused ("seems to do nothing" per the manual); the module decodes it as a no-op
    if dbad and not gbad and (int(h[:2], 16) & 0xfe) == 0x2a and mnem(fold(gt)) == 'unused2a':
        return ('explained', 'unused-2a-noop')
    # C1: the manual lists the extension 'NOP as 0000 00xx (any low two bits); Dolphin rejects 01..03
    if dbad and "'xxx" in dt.lower() and not gbad and (int(h[2:4], 16) & 0x7c) == 0 and "'" not in gt \
            and mnem(fold(gt)) == mnem(fold(dt)).split("'")[0]:
        return ('explained', 'ext-nop-low-bits')
    if gbad or dbad or gn != dn * 2:
        k = ('ghidra-bad dolphin=' + mnem(fold(dt)) if gbad else
             'dolphin-invalid ghidra=' + mnem(fold(gt)) if dbad else 'length ' + mnem(fold(gt)))
        return ('diff', k)
    if fold(gt) == fold(dt): return ('exact',)
    applied, g2, d2 = rules(fold(gt), fold(dt))
    # C2: operand encodings where the manual and Dolphin's disassembler disagree (see GHIDRA-RARE.md)
    if g2 != d2 and mnem(g2).split("'")[0] in MANUAL_VS_DOLPHIN and manual_vs_dolphin(g2, d2):
        return ('explained', 'manual-vs-dolphin:' + mnem(g2).split("'")[0])
    if g2 == d2:
        return ('explained', ','.join(applied) if applied else '(none)')
    return ('diff', 'text ' + mnem(g2))

def main():
    g, d = load(sys.argv[1]), load(sys.argv[2])
    label = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('-') else ''
    verbose = '-v' in sys.argv
    assert [x[0] for x in g] == [x[0] for x in d]
    agree = both_bad = 0
    expl = collections.Counter(); unexp = collections.Counter(); ex = {}
    for (h, gn, gt), (_, dn, dt) in zip(g, d):
        c = classify(h, gn, gt, dn, dt)
        if c[0] == 'exact': agree += 1
        elif c[0] == 'both-invalid': both_bad += 1
        elif c[0] == 'explained':
            for a in c[1].split(','): expl[a] += 1
        else:
            unexp[c[1]] += 1; ex.setdefault(c[1], []).append((h, gt, dt))
    print(f"{label}: {len(g)} cases: {agree} exact, {both_bad} both invalid, {sum(expl.values())} explained "
          f"({', '.join(f'{k} {v}' for k, v in sorted(expl.items()))}), {sum(unexp.values())} unexplained")
    for k, n in unexp.most_common(80 if not verbose else 10**6):
        e = ex[k][0]
        print(f"  {n:6d} {k}   e.g. {e[0]} ghidra={e[1]!r} dolphin={e[2]!r}")
    sys.exit(1 if unexp else 0)

if __name__ == '__main__':
    main()
