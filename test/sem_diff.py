#!/usr/bin/env python3
"""Random single-instruction comparison of Ghidra's p-code (emulator) with gcdsp_model.py (written from
the manual).  usage: sem_diff.py <workdir> <cases-per-opcode> <seed> <variant: default|exact> [name ...]
Needs GHIDRA_INSTALL_DIR and GCDSP_MANUAL_TEX (the Dolphin manual, .tex).  Exit 1 on any difference."""
import sys, os, random, subprocess, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcdsp_model as gm
from gcdsp_model import Model, State, vector_line, parse_result, to_regs, M16, M40, s8
from manual_table import load, match

HERE = os.path.dirname(os.path.abspath(__file__))
wd, N, seed, variant = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
only = set(a.upper() for a in sys.argv[5:])
os.makedirs(wd, exist_ok=True)
rng = random.Random(seed)
main, ext = gm.tables()
model = Model(variant)
SKIP = {'LOOP', 'LOOPI', 'BLOOP', 'BLOOPI', 'HALT', 'JMP', 'IFcc'}
IFNEXT = 0x7600     # INC $acc0: the instruction executed (or skipped) by IFcc

def interesting16():
    return rng.choice([0, 1, 0xffff, 0x7fff, 0x8000, 0x8001, 0x00ff, 0xff00, 0x4000, 0xc000, rng.getrandbits(16), rng.getrandbits(16), rng.getrandbits(16)])

def acc40():
    return gm.s40(rng.choice([0, 1, -1, 0x7fffffffff, -0x8000000000, 0x7fffffff, -0x80000000, 0x80000000, 0xffff, 0x10000,
                              rng.getrandbits(40), rng.getrandbits(40), rng.getrandbits(32), gm.s16(rng.getrandbits(16)) << 16,
                              rng.getrandbits(40), rng.getrandbits(24) << 16]))

def window_addr():
    return rng.choice([rng.randrange(0x110, 0x1e0), rng.randrange(0x110, 0x1e0), 0xff00 + rng.randrange(0x40)])

def rand_state():
    s = State()
    s.ar = [rng.randrange(0x110, 0x1e0) for _ in range(4)]
    s.ix = [rng.choice([0, 1, 2, 3, 0xffff, 0xfffe, 0xfffd, 0x10, 0xfff0]) for _ in range(4)]
    s.wr = [0xffff] * 4
    s.st = [rng.getrandbits(16) for _ in range(4)]
    s.cr = 0xff if variant == 'default' else rng.choice([0xff, 0xff, 0x01])
    s.pl, s.pm1, s.ph, s.pm2 = interesting16(), interesting16(), rng.getrandbits(8), rng.choice([0, 0, 0, 1, interesting16()])
    s.axl = [interesting16(), interesting16()]; s.axh = [interesting16(), interesting16()]
    s.acc = [acc40(), acc40()]
    s.sr = [rng.getrandbits(1) for _ in range(16)]
    s.sr[8] = 0
    for a in list(range(0x100, 0x200)) + list(range(0xff00, 0xff40)):
        if rng.random() < 0.7: s.dmem[a] = rng.getrandbits(16)
    for a in range(0x100, 0x200):
        if rng.random() < 0.7: s.imem[a] = rng.getrandbits(16)
    return s

def fill(pat, rng, ext_pat=None):
    """random 16/32-bit word(s) matching a manual pattern"""
    bits = ''.join(c if c in '01' else str(rng.getrandbits(1)) for c in pat)
    v = int(bits, 2)
    return [v >> 16, v & M16] if len(pat) == 32 else [v]

def make_case(name, pat):
    code = fill(pat, rng)
    w0 = code[0]
    if w0 >= 0x3000:                                    # arithmetic: choose a valid extension
        while True:
            en, ep = rng.choice(ext)
            if rng.random() < 0.15: en, ep = "'NOP", "xxxxxxxx000000xx"
            e = int(''.join(c if c in '01' else str(rng.getrandbits(1)) for c in ep[8:]), 2)
            if (w0 >> 12) == 3: e &= 0x7f
            w = (w0 & 0xff00) | e
            if (w0 >> 12) == 3: w |= (w0 & 0x80)
            code = [w]
            if model.decode_ext(w) is not None: break
    s = rand_state()
    if name in ('LR', 'SR'): code[1] = window_addr()
    if name == 'SI' : code[0] = (code[0] & 0xff00) | rng.randrange(0x40)
    if name in ('LRS', 'SRS', 'SRSH'):
        code[0] = (code[0] & 0xff00) | (rng.randrange(0x40) if s.cr == 0xff else rng.getrandbits(8))
    if name in ('LRR', 'LRRD', 'LRRI', 'LRRN') :
        a = (code[0] >> 5) & 3
        if (code[0] & 0x1f) == a: code[0] ^= 1 << 3 if a < 4 else 0
        if (code[0] & 0x1f) == a: code[0] = (code[0] & ~0x1f) | 0x1c
    if name in ('ILRR', 'ILRRD', 'ILRRI', 'ILRRN'): pass
    if name == 'IFcc': code = [code[0], IFNEXT]
    if name in ('JRcc', 'CALLRcc', 'RETcc', 'RTIcc', 'Jcc', 'CALLcc'): pass
    return code, s

def expected(code, s0):
    s = s0.copy()
    ok = model.step(s, code + [0, 0])
    return ok, s

def load_res(path):
    out = {}
    for l in open(path):
        vid, status, pc, regs, mem = parse_result(l)
        out[vid] = (status, pc, regs, mem)
    return out

def compare(vid, name, code, ca, exp, got):
    status, pc, regs, mem = got
    ok, s = exp
    probs = []
    if status != 'ok': return [f"emulator: {status}"]
    want = to_regs(s)
    # pc / st0 encodings from the model
    if isinstance(s.pc, tuple): wantpc = ('A', s.pc[1])
    else: wantpc = ('R', s.pc)
    gpc = got[1]
    if isinstance(wantpc, tuple) and wantpc[0] == 'A':
        pass
    return probs

def main_run():
    cases = []   # (id, name, code, state)
    names = [(n, p) for n, p in main if n not in SKIP and (not only or n.upper() in only)]
    for n, p in names:
        for _ in range(N):
            code, s = make_case(n, p)
            cases.append((n, code, s))
    # IFcc separately (2 instructions)
    if not only or 'IFCC' in only:
        for _ in range(N):
            code, s = make_case('IFcc', '00000010' '0111' 'cccc'.replace('c', 'x'))
            cases.append(('IFcc', code, s))
    vf = os.path.join(wd, 'vec.txt'); rf = os.path.join(wd, 'res.txt')
    with open(vf, 'w') as f:
        for i, (n, code, s) in enumerate(cases):
            f.write(vector_line(i, code, s) + '\n')
    lang = 'GCDSP:BE:16:' + variant
    subprocess.run([os.path.join(HERE, 'emudiff.sh'), lang, vf, rf, '1'], check=True)
    res = {}
    for l in open(rf):
        vid, status, pc, regs, mem = parse_result(l)
        res[int(vid)] = (status, pc, regs, mem, l)
    buckets = collections.defaultdict(list)
    ndec = nfail = 0
    for i, (n, code, s0) in enumerate(cases):
        s = s0.copy()
        if not model.step(s, code + [0, 0]):
            buckets[n].append((i, 'model could not decode ' + ' '.join(f'{w:04x}' for w in code)))
            continue
        status, pcr, regs, mem, line = res[i]
        ca = regs.get('ca', 0)
        diffs = []
        if status != 'ok':
            diffs.append('emulator ' + status[:60])
        else:
            want = to_regs(s)
            for k, v in want.items():
                if k == 'st0' and isinstance(s.st[0], tuple): v = ca + s.st[0][1]
                elif k == 'st0' and isinstance(s.st[0], int): pass
                if k in regs and regs[k] != v and not (k.startswith('SR_') and False):
                    diffs.append(f"{k}: ghidra {regs[k]:x} model {v:x}")
            wm = {}
            for a, v in s.dmem.items():
                if v and (0x100 <= a < 0x200 or 0xff00 <= a < 0xff40): wm[f'd{a:04x}'] = v
            for a, v in s.imem.items():
                if v and 0x100 <= a < 0x200: wm[f'i{a:04x}'] = v
            if wm != mem:
                ks = sorted(set(wm) | set(mem))
                diffs.append('mem: ' + ' '.join(f"{k} ghidra {mem.get(k, 0):x} model {wm.get(k, 0):x}" for k in ks if wm.get(k, 0) != mem.get(k, 0))[:150])
            if isinstance(s.pc, tuple):
                if pcr is not None and False: pass
            # pc
            line_pc = line.split('|')[2]
            if isinstance(s.pc, tuple):
                tgt = s.pc[1] if s.pc[0] == 'J' else None
                if line_pc != 'A%x' % tgt and not (line_pc.isalnum() and False):
                    if not (line_pc.startswith('A') and int(line_pc[1:], 16) == tgt):
                        diffs.append(f"pc: ghidra {line_pc} model A{tgt:x}")
            else:
                if line_pc != '%x' % s.pc: diffs.append(f"pc: ghidra {line_pc} model {s.pc:x}")
        if diffs:
            nfail += 1
            buckets[n].append((i, ' '.join(f'{w:04x}' for w in code) + ' :: ' + '; '.join(diffs)))
        else:
            ndec += 1
    print(f"{variant}: {len(cases)} cases over {len(names)} opcodes: {ndec} agree, {nfail} differ")
    for n, l in sorted(buckets.items(), key=lambda x: -len(x[1])):
        print(f"  {n}: {len(l)} differ, e.g. {l[0][1][:230]}")
        if only:
            for e in l[1:6]: print("      ", e[1][:230])
    return 1 if buckets else 0

sys.exit(main_run())
