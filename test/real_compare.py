#!/usr/bin/env python3
"""Compare the instructions Ghidra found in an image (RealCheck .insns) with Dolphin's DSPTool decode of
the same words, and with the assembler's image.  usage: real_compare.py <dsptool> <name.insns> <workdir> [label]
Every Ghidra instruction is re-decoded by DSPTool from its own words (so a data-in-code desync of
DSPTool's linear sweep cannot cause a false difference); lengths and text must agree under the rules of
cmp_dolphin.py.  Prints counts; exit 1 on an unexplained difference."""
import sys, os, subprocess, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cmp_dolphin as cd
tool, insns, wd = sys.argv[1:4]
label = sys.argv[4] if len(sys.argv) > 4 else os.path.basename(insns)
os.makedirs(wd, exist_ok=True)
rows = [l.rstrip('\n').split('\t') for l in open(insns)]
cases = os.path.join(wd, 'real-cases.txt')
with open(cases, 'w') as f:
    for a, hexw, t in rows: f.write(hexw + '\n')
out = os.path.join(wd, 'real-dol.txt')
subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dolphin_dis.py'),
                tool, cases, out, os.path.join(wd, 'dw')], check=True)
dol = [l.rstrip('\n').split(' ', 2) for l in open(out)]
cnt = collections.Counter(); diffs = []
for (a, hexw, t), (h, dn, dt) in zip(rows, dol):
    gn = len(hexw) // 4
    t = t.lstrip('_')                                  # Ghidra prefixes a delay-slot instruction (after IFcc) with _
    t = cd.re.sub(r' (->|=>)0x[0-9a-f]+', '', t)       # loop annotations added by the module's display
    c = cd.classify(hexw[:4] + '0000', gn * 2, t, int(dn), dt)
    cnt[c[0]] += 1
    if c[0] == 'diff': diffs.append((a, hexw, t, dt, c[1]))
    if c[0] == 'explained': cnt['explained:' + c[1].split(':')[0].split(',')[0]] += 1
print(f"{label}: {len(rows)} instructions: " + ', '.join(f"{k} {v}" for k, v in sorted(cnt.items())))
for d in diffs[:10]: print('  DIFF', d)
sys.exit(1 if diffs else 0)
