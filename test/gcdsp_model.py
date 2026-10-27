#!/usr/bin/env python3
"""An independent model of the GameCube DSP, written from the GameCube DSP User's Manual
(Duddie, v0.1.8, GFDL; "Alphabetical list of opcodes" operation sections and "Instructions sorted by
opcode").  It is NOT derived from the SLEIGH module or from Dolphin's source: it is the oracle for the
emulator comparison in sem_diff.py.

What it models (everything the manual specifies):
  - all main opcodes (including the 40-bit accumulators, flags, product register with $sr.AM doubling),
  - extension opcodes executed in parallel with the main opcode (extension reads see the state before
    the main opcode, and its register writes land after it),
  - 40-bit mode sign extension on writes to $acX.m and saturation on reads (exact variant only),
  - $sr bit access through MRR/LRI/... (bit 8 reads 0), 8-bit $cr/$acX.h/$prod.h.
What it does not model (the manual does not say): wrap registers $wr, hardware stack behaviour of
$st0-$st3, the unsigned-multiply mode $sr.SU, interrupts.
"""
import re, sys, os, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manual_table import load, match

M40 = (1 << 40) - 1
M16 = 0xffff

def s40(v):
    v &= M40
    return v - (1 << 40) if v >> 39 else v

def s32(v):
    v &= 0xffffffff
    return v - (1 << 32) if v >> 31 else v

def s16(v):
    v &= 0xffff
    return v - (1 << 16) if v >> 15 else v

def s8(v):
    v &= 0xff
    return v - 256 if v >> 7 else v

SRBITS = ['C', 'O', 'Z', 'S', 'AS', 'TB', 'LZ', 'OS', 'B8', 'IE', 'B10', 'EIE', 'B12', 'AM', 'SXM', 'SU']
SRNAMES = ['SR_CARRY_', 'SR_OVERFLOW_', 'SR_ARITH_ZERO_', 'SR_SIGN_', 'SR_OVER_32_', 'SR_TOP2BITS_',
           'SR_LOGIC_ZERO_', 'SR_OVERFLOW_STICKY_', 'SR_100_', 'SR_INT_ENABLE_', 'SR_400_',
           'SR_EXT_INT_ENABLE_', 'SR_1000_', 'SR_MUL_MODIFY_', 'SR_40_MODE_', 'SR_MUL_UNSIGNED_']

MAIN, EXT = None, None
_TEX = os.environ.get('GCDSP_MANUAL_TEX')


def tables():
    global MAIN, EXT
    if MAIN is None:
        MAIN, EXT = load(_TEX)
    return MAIN, EXT


class State:
    def __init__(self):
        self.ar = [0] * 4; self.ix = [0] * 4; self.wr = [0xffff] * 4; self.st = [0] * 4
        self.cr = 0
        self.pl = self.pm1 = self.ph = self.pm2 = 0
        self.axl = [0, 0]; self.axh = [0, 0]
        self.acc = [0, 0]                      # signed 40-bit
        self.sr = [0] * 16
        self.dmem = {}; self.imem = {}
        self.pc = 0                            # relative, in words
        self.st0_set = False

    def copy(self):
        n = State.__new__(State)
        n.__dict__.update({k: (v[:] if isinstance(v, list) else (dict(v) if isinstance(v, dict) else v))
                           for k, v in self.__dict__.items()})
        return n

    # ---- product -----------------------------------------------------------------------
    def prod(self):
        return s8(self.ph) * (1 << 32) + (((self.pm1 + self.pm2) & 0x1ffff) << 16) + self.pl

    def set_prod(self, v):
        self.pl = v & M16; self.pm1 = (v >> 16) & M16; self.ph = (v >> 32) & 0xff; self.pm2 = 0

    # ---- status register -----------------------------------------------------------------
    def sr_value(self):
        return sum(b << i for i, b in enumerate(self.sr) if i != 8)

    def set_sr(self, v):
        self.sr = [(v >> i) & 1 for i in range(16)]
        self.sr[8] = 0


class Model:
    """variant: 'default' (CR assumed 0xff, no saturation) or 'exact'."""

    def __init__(self, variant='default'):
        self.exact = variant == 'exact'

    # ---- register file -------------------------------------------------------------------
    def rd(self, s, idx, sat=False):
        if idx < 4: return s.ar[idx]
        if idx < 8: return s.ix[idx - 4]
        if idx < 12: return s.wr[idx - 8]
        if idx < 16: return s.st[idx - 12]
        if idx in (16, 17): return (s8(s.acc[idx - 16] >> 32)) & M16
        if idx == 18: return s.cr & 0xff
        if idx == 19: return s.sr_value()
        if idx == 20: return s.pl
        if idx == 21: return s.pm1
        if idx == 22: return s.ph & 0xff
        if idx == 23: return s.pm2
        if idx in (24, 25): return s.axl[idx - 24]
        if idx in (26, 27): return s.axh[idx - 26]
        if idx in (28, 29): return s.acc[idx - 28] & M16
        a = s.acc[idx - 30]
        if sat and self.exact and s.sr[14] and a != s32(a):
            return 0x7fff if a > 0 else 0x8000
        return (a >> 16) & M16

    def wr_(self, s, idx, v, ext=True):
        v &= M16
        if idx < 4: s.ar[idx] = v
        elif idx < 8: s.ix[idx - 4] = v
        elif idx < 12: s.wr[idx - 8] = v
        elif idx < 16: s.st[idx - 12] = v
        elif idx in (16, 17):
            k = idx - 16
            s.acc[k] = s40((s.acc[k] & 0xffffffff) | ((v & 0xff) << 32))
        elif idx == 18: s.cr = v & 0xff
        elif idx == 19: s.set_sr(v)
        elif idx == 20: s.pl = v
        elif idx == 21: s.pm1 = v
        elif idx == 22: s.ph = v & 0xff
        elif idx == 23: s.pm2 = v
        elif idx in (24, 25): s.axl[idx - 24] = v
        elif idx in (26, 27): s.axh[idx - 26] = v
        elif idx in (28, 29):
            k = idx - 28
            s.acc[k] = s40((s.acc[k] & ~0xffff) | v)
        else:
            k = idx - 30
            if ext and s.sr[14]:
                s.acc[k] = s40(s16(v) << 16)
            else:
                s.acc[k] = s40((s.acc[k] & ~(0xffff << 16)) | (v << 16))

    # ---- flags -----------------------------------------------------------------------------
    @staticmethod
    def _tb(v):
        t = v & 0xc0000000
        return int(t == 0 or t == 0xc0000000)

    def flags40(self, s, v, c=0, o=0):
        v = s40(v)
        s.sr[0] = c; s.sr[1] = o; s.sr[2] = int(v == 0); s.sr[3] = int(v < 0)
        s.sr[4] = int(v != s32(v)); s.sr[5] = self._tb(v & M40)
        s.sr[7] |= o

    def flags16(self, s, r16, acc, c=0, o=0, as_=None):
        r = s16(r16)
        s.sr[0] = c; s.sr[1] = o; s.sr[2] = int(r == 0); s.sr[3] = int(r < 0)
        s.sr[4] = int(acc != s32(acc)) if as_ is None else as_
        s.sr[5] = int((r16 & 0xc000) in (0, 0xc000))
        s.sr[7] |= o

    def add40(self, s, a, b):
        """a + b with the manual's carry (A > C, unsigned) and overflow (signed) rules; returns result"""
        a, b = s40(a), s40(b)
        r = s40(a + b)
        c = int((a & M40) > (r & M40))
        o = int(a + b != r)
        if os.environ.get('GCDSP_MUTATE'): c ^= 1          # used by run-tests.sh to prove that a wrong model is caught
        self.flags40(s, r, c, o)
        return r

    def sub40(self, s, a, b):
        a, b = s40(a), s40(b)
        r = s40(a - b)
        c = int((a & M40) >= (r & M40))
        o = int(a - b != r)
        self.flags40(s, r, c, o)
        return r

    # ---- helpers ---------------------------------------------------------------------------
    def cond(self, s, cc):
        O, S, Z, C, AS, TB, LZ = s.sr[1], s.sr[3], s.sr[2], s.sr[0], s.sr[4], s.sr[5], s.sr[6]
        return [O == S, O != S, O == S and not Z, O != S or Z, not Z, Z, not C, C,
                not AS, AS, (AS or TB) and not Z, (not AS and not TB) or Z, not LZ, LZ, O, True][cc]

    def mult(self, s, a, b):
        p = s16(a) * s16(b)
        if not s.sr[13]:
            p *= 2
        return p

    def dread(self, s, a):
        return s.dmem.get(a & M16, 0)

    def dwrite(self, s, a, v):
        s.dmem[a & M16] = v & M16

    # ---- decoding --------------------------------------------------------------------------
    def decode(self, w0, w1):
        main, ext = tables()
        hits = [(n, p) for n, p in main if match(p[:16], w0)]
        if not hits:
            return None
        name, pat = hits[0]
        f = {}
        for letter in set(c for c in pat if c.isalpha() and c != 'x'):
            val = 0
            if len(pat) == 32:
                bits = [(pat[i], i) for i in range(32) if pat[i] == letter]
                w = (w0 << 16) | w1
                for _, i in bits:
                    val = (val << 1) | ((w >> (31 - i)) & 1)
            else:
                for i in range(16):
                    if pat[i] == letter:
                        val = (val << 1) | ((w0 >> (15 - i)) & 1)
            f[letter] = val
        return name, f, len(pat) // 16

    def decode_ext(self, w0):
        main, ext = tables()
        e = w0 & 0xff
        if (w0 >> 12) == 3:                     # 9-bit main opcodes: the extension has 7 bits
            e &= 0x7f
        for n, p in sorted(ext, key=lambda x: -sum(c in '01' for c in x[1][8:])):   # most specific first ('LDAX before 'LD)
            if match(p[8:], e):
                f = {}
                for letter in set(c for c in p[8:] if c.isalpha() and c != 'x'):
                    val = 0
                    for i in range(8, 16):
                        if p[i] == letter:
                            val = (val << 1) | ((e >> (15 - i)) & 1)
                    f[letter] = val
                return n, f
        return None

    # ---- execution -------------------------------------------------------------------------
    def step(self, s, code, depth=0):
        """Execute one instruction (code = list of 16-bit words, code[0] at pc 0) on s; returns True if
        it decoded.  s.pc holds the new pc (relative words)."""
        w0 = code[0]; w1 = code[1] if len(code) > 1 else 0
        d = self.decode(w0, w1)
        if d is None:
            return False
        name, f, nw = d
        if w0 >= 0x3000:                       # arithmetic opcodes carry an extension in the low byte
            e = self.decode_ext(w0)
            deferred = []
            old = s.copy()
            if e is not None:
                self.run_ext(s, old, e[0], e[1], deferred)
            s.pc = 1
            self.run_main(s, name, f, w0, w1)
            for (idx, v) in deferred:
                self.wr_(s, idx, v, True)
            return True
        if name == 'IFcc':
            ok = self.cond(s, f['c'])
            nxt = self.decode(code[1], code[2] if len(code) > 2 else 0)
            if ok:
                self.step(s, code[1:])
            s.pc = 1 + nxt[2]
            return True
        s.pc = nw
        self.run_main(s, name, f, w0, w1, code)
        return True

    # ---- extension opcodes (read the old state, writes to registers are deferred) -------------
    def run_ext(self, s, old, name, f, deferred):
        R = lambda idx, sat=False: self.rd(old, idx, sat)
        def load(a): return self.dread(old, a)
        if name in ("'NOP",):
            return
        if name == "'DR": s.ar[f['r']] = (s.ar[f['r']] - 1) & M16
        elif name == "'IR": s.ar[f['r']] = (s.ar[f['r']] + 1) & M16
        elif name == "'NR": s.ar[f['r']] = (s.ar[f['r']] + s.ix[f['r']]) & M16
        elif name == "'MV": deferred.append((24 + f['d'], R(28 + f['s'], True)))
        elif name in ("'S", "'SN"):
            a = f['d']; self.dwrite(s, old.ar[a], R(28 + f['s'], True))
            s.ar[a] = (old.ar[a] + (1 if name == "'S" else old.ix[a])) & M16
        elif name in ("'L", "'LN"):
            a = f['s']; deferred.append((24 + f['d'], load(old.ar[a])))
            s.ar[a] = (old.ar[a] + (1 if name == "'L" else old.ix[a])) & M16
        elif name in ("'LS", "'LSN", "'LSM", "'LSNM", "'SL", "'SLN", "'SLM", "'SLNM"):
            ls = name.startswith("'LS")
            n0 = 'N' in name[3:] if ls else 'N' in name[3:]
            nn = name[3:] if ls else name[3:]
            idx0 = 'N' in nn
            idx3 = 'M' in nn
            sreg = 30 + f['s']
            if ls:      # load with ar0, store with ar3
                deferred.append((24 + f['d'], load(old.ar[0])))
                self.dwrite(s, old.ar[3], R(sreg, True))
            else:       # store with ar0, load with ar3
                deferred.append((24 + f['d'], load(old.ar[3])))
                self.dwrite(s, old.ar[0], R(sreg, True))
            s.ar[0] = (old.ar[0] + (old.ix[0] if idx0 else 1)) & M16
            s.ar[3] = (old.ar[3] + (old.ix[3] if idx3 else 1)) & M16
        elif name in ("'LD", "'LDN", "'LDM", "'LDNM"):
            sa = f['s']
            deferred.append((24 + 2 * f['d'], load(old.ar[sa])))        # ax0.l / ax0.h
            deferred.append((25 + 2 * f['r'], load(old.ar[3])))         # ax1.l / ax1.h
            s.ar[sa] = (old.ar[sa] + (old.ix[sa] if 'N' in name[3:] else 1)) & M16
            s.ar[3] = (old.ar[3] + (old.ix[3] if 'M' in name[3:] else 1)) & M16
        elif name in ("'LDAX", "'LDAXN", "'LDAXM", "'LDAXNM"):
            sa = f['s']; r = f['r']
            deferred.append((26 + r, load(old.ar[sa])))                  # axR.h
            deferred.append((24 + r, load(old.ar[3])))                   # axR.l
            s.ar[sa] = (old.ar[sa] + (old.ix[sa] if 'N' in name[5:] else 1)) & M16
            s.ar[3] = (old.ar[3] + (old.ix[3] if 'M' in name[5:] else 1)) & M16
        else:
            raise KeyError(name)

    # ---- main opcodes -----------------------------------------------------------------------
    def run_main(self, s, name, f, w0, w1, code=None):
        A = lambda k: s.acc[k]
        def setacc(k, v): s.acc[k] = s40(v)
        R = self.rd
        D = f.get('d', 0)
        if name == 'NOP' or name == 'NX': return
        if name == 'DAR': s.ar[D] = (s.ar[D] - 1) & M16
        elif name == 'IAR': s.ar[D] = (s.ar[D] + 1) & M16
        elif name == 'SUBARN': s.ar[D] = (s.ar[D] - s.ix[D]) & M16
        elif name == 'ADDARN': s.ar[D] = (s.ar[D] + s.ix[f['s']]) & M16
        elif name == 'HALT': s.pc = 0
        elif name == 'LRI': self.wr_(s, D, w1)
        elif name == 'LR': self.wr_(s, D, self.dread(s, w1))
        elif name == 'SR': self.dwrite(s, w1, self.rd(s, f['s'], True))
        elif name == 'LRIS': self.wr_(s, 24 + D, s8(f['i']) & M16)
        elif name == 'ADDI':
            k = D; setacc(k, self.add40(s, A(k), s16(w1) << 16))
        elif name == 'ADDIS':
            k = D; setacc(k, self.add40(s, A(k), s8(f['i']) << 16))
        elif name == 'CMPI': self.sub40(s, A(D), s16(w1) << 16)
        elif name == 'CMPIS': self.sub40(s, A(D), s8(f['i']) << 16)
        elif name in ('XORI', 'ANDI', 'ORI'):
            m = (A(D) >> 16) & M16
            m = {'XORI': m ^ w1, 'ANDI': m & w1, 'ORI': m | w1}[name]
            s.acc[D] = s40((s.acc[D] & ~(M16 << 16)) | (m << 16))
            self.flags16(s, m, s.acc[D])
        elif name == 'ANDF':
            s.sr[6] = int(((A(D) >> 16) & w1 & M16) == 0)
        elif name == 'ANDCF':
            s.sr[6] = int(((A(D) >> 16) & w1 & M16) == (w1 & M16))
        elif name in ('LSRN', 'ASRN', 'LSRNR', 'ASRNR', 'LSRNRX', 'ASRNRX'):
            if name in ('LSRN', 'ASRN'): k, amt = 0, s.acc[1] >> 16
            elif name.endswith('RX'): k, amt = D, s.axh[f['s']]
            else: k, amt = D, s.acc[1 - D] >> 16
            amt &= M16
            logical = name.startswith('LSR')
            v = A(k)
            if amt & 64:
                n = amt & 63
                if n != 0:
                    sh = 64 - n
                    v = ((v & M40) >> sh) if logical else (v >> sh)
            else:
                v = v << (amt & 63)
            setacc(k, v); self.flags40(s, A(k))
        elif name in ('ILRR', 'ILRRD', 'ILRRI', 'ILRRN'):
            a = f['s']
            self.wr_(s, 30 + D, s.imem.get(s.ar[a], 0))
            s.ar[a] = (s.ar[a] + {'ILRR': 0, 'ILRRD': -1, 'ILRRI': 1, 'ILRRN': s.ix[a]}[name]) & M16
        elif name in ('LRR', 'LRRD', 'LRRI', 'LRRN'):
            a = f['s']
            v = self.dread(s, s.ar[a])
            s.ar[a] = (s.ar[a] + {'LRR': 0, 'LRRD': -1, 'LRRI': 1, 'LRRN': s.ix[a]}[name]) & M16
            self.wr_(s, D, v)
        elif name in ('SRR', 'SRRD', 'SRRI', 'SRRN'):
            a = f['d']
            self.dwrite(s, s.ar[a], R(s, f['s'], True))
            s.ar[a] = (s.ar[a] + {'SRR': 0, 'SRRD': -1, 'SRRI': 1, 'SRRN': s.ix[a]}[name]) & M16
        elif name == 'MRR':
            v = R(s, f['s'], True); self.wr_(s, D, v)
        elif name in ('LSL', 'ASL'):
            setacc(f['r'], A(f['r']) << f['i']); self.flags40(s, A(f['r']))
        elif name in ('LSR', 'ASR'):
            k = f['r']; i = f['i']; v = A(k)
            if i != 0:
                v = ((v & M40) >> (64 - i)) if name == 'LSR' else (v >> (64 - i))
            setacc(k, v); self.flags40(s, A(k))
        elif name == 'SBCLR': s.sr[6 + f['i']] = 0
        elif name == 'SBSET': s.sr[6 + f['i']] = 1
        elif name == 'SI': self.dwrite(s, 0xff00 | f['m'], w1)
        elif name in ('LRS', 'SRS', 'SRSH'):
            base = (s.cr & 0xff) << 8 if self.exact else 0xff00
            a = base | f['m']
            if name == 'LRS': self.wr_(s, 24 + D, self.dread(s, a))
            elif name == 'SRS': self.dwrite(s, a, R(s, 28 + f['s'], True))
            else: self.dwrite(s, a, R(s, 16 + f['s']))
        # ---- control flow ---------------------------------------------------------------------
        elif name == 'Jcc':
            if self.cond(s, f['c']): s.pc = ('J', w1)
        elif name == 'CALLcc':
            if self.cond(s, f['c']): s.st[0] = ('RET', 2); s.pc = ('J', w1)
        elif name == 'RETcc':
            if self.cond(s, f['c']): s.pc = ('J', s.st[0])
        elif name == 'RTIcc':
            if self.cond(s, f['c']):
                s.set_sr(s.st[1]); s.pc = ('J', s.st[0])
        elif name == 'JRcc':
            if self.cond(s, f['c']): s.pc = ('J', R(s, f['r']))
        elif name == 'CALLRcc':
            if self.cond(s, f['c']): s.st[0] = ('RET', 1); s.pc = ('J', R(s, f['r']))
        # ---- arithmetic (the extension was handled by the caller) ------------------------------------------
        else:
            self.run_arith(s, name, f)

    def run_arith(self, s, name, f):
        A = lambda k: s.acc[k]
        def setacc(k, v): s.acc[k] = s40(v)
        D = f.get('d', 0); Rr = f.get('r', 0); S = f.get('s', 0); T = f.get('t', 0)
        ax = lambda k: s32((s.axh[k] << 16) | s.axl[k])
        axreg = lambda sel: [s.axl[0], s.axl[1], s.axh[0], s.axh[1]][sel]
        # ---- adds / subs / moves ---------------------------------------------------------------------
        if name == 'ADD': setacc(D, self.add40(s, A(D), A(1 - D)))
        elif name == 'ADDAX': setacc(D, self.add40(s, A(D), ax(S)))
        elif name == 'ADDAXL': setacc(D, self.add40(s, A(D), s.axl[S]))
        elif name == 'ADDR': setacc(D, self.add40(s, A(D), s16(axreg(S)) << 16))
        elif name == 'ADDP': setacc(D, self.add40(s, A(D), s.prod()))
        elif name == 'SUB': setacc(D, self.sub40(s, A(D), A(1 - D)))
        elif name == 'SUBAX': setacc(D, self.sub40(s, A(D), ax(S)))
        elif name == 'SUBR': setacc(D, self.sub40(s, A(D), s16(axreg(S)) << 16))
        elif name == 'SUBP': setacc(D, self.sub40(s, A(D), s.prod()))
        elif name == 'INC': setacc(D, self.add40(s, A(D), 1))
        elif name == 'DEC': setacc(D, self.sub40(s, A(D), 1))
        elif name == 'INCM': setacc(D, self.add40(s, A(D), 0x10000))
        elif name == 'DECM': setacc(D, self.sub40(s, A(D), 0x10000))
        elif name == 'NEG': setacc(D, self.sub40(s, 0, A(D)))
        elif name == 'CMP': self.sub40(s, A(0), A(1))
        elif name == 'CMPAXH': self.sub40(s, A(S), s16(s.axh[Rr]) << 16)
        elif name == 'MOV': setacc(D, A(1 - D)); self.flags40(s, A(D))
        elif name == 'MOVAX': setacc(D, ax(S)); self.flags40(s, A(D))
        elif name == 'MOVR': setacc(D, s16(axreg(S)) << 16); self.flags40(s, A(D))
        elif name == 'MOVP': setacc(D, s.prod()); self.flags40(s, A(D))
        elif name == 'MOVNP': setacc(D, -s.prod()); self.flags40(s, A(D))
        elif name == 'MOVPZ': setacc(D, (s.prod() >> 16) << 16); self.flags40(s, A(D))
        elif name == 'ADDPAXZ':
            setacc(D, (s.prod() + ax(S)) >> 16 << 16)
            self.flags40(s, A(D))
        elif name == 'CLR': setacc(Rr, 0); self.flags40(s, 0)
        elif name == 'CLRL':
            v = A(Rr)
            v = (v + 0x8000) if (v & 0x10000) else (v + 0x7fff)
            setacc(Rr, v & ~0xffff); self.flags40(s, A(Rr))
        elif name == 'ABS': setacc(D, abs(A(D))); self.flags40(s, A(D))
        elif name == 'TST': self.flags40(s, A(Rr))
        elif name == 'TSTAXH': self.flags16(s, s.axh[Rr], 0, as_=0)
        elif name == 'TSTPROD': self.flags40(s, s.prod())
        elif name == 'LSL16': setacc(Rr, A(Rr) << 16); self.flags40(s, A(Rr))
        elif name == 'LSR16': setacc(Rr, (A(Rr) & M40) >> 16); self.flags40(s, A(Rr))
        elif name == 'ASR16': setacc(Rr, A(Rr) >> 16); self.flags40(s, A(Rr))
        # ---- logic on acD.m ---------------------------------------------------------------------------
        elif name in ('XORR', 'ANDR', 'ORR'):
            m = (A(D) >> 16) & M16; x = s.axh[S]
            m = {'XORR': m ^ x, 'ANDR': m & x, 'ORR': m | x}[name]
            s.acc[D] = s40((s.acc[D] & ~(M16 << 16)) | (m << 16)); self.flags16(s, m, s.acc[D])
        elif name in ('XORC', 'ANDC', 'ORC'):
            m = (A(D) >> 16) & M16; x = (A(1 - D) >> 16) & M16
            m = {'XORC': m ^ x, 'ANDC': m & x, 'ORC': m | x}[name]
            s.acc[D] = s40((s.acc[D] & ~(M16 << 16)) | (m << 16)); self.flags16(s, m, s.acc[D])
        elif name == 'NOT':
            m = ~((A(D) >> 16) & M16) & M16
            s.acc[D] = s40((s.acc[D] & ~(M16 << 16)) | (m << 16)); self.flags16(s, m, s.acc[D])
        # ---- multiplier -----------------------------------------------------------------------------
        elif name == 'CLRP':
            s.pl, s.pm1, s.ph, s.pm2 = 0, 0xfff0, 0xff, 0x0010
        elif name == 'SET15': s.sr[15] = 1
        elif name == 'CLR15': s.sr[15] = 0
        elif name == 'SET40': s.sr[14] = 1
        elif name == 'SET16': s.sr[14] = 0
        elif name == 'M0': s.sr[13] = 1
        elif name == 'M2': s.sr[13] = 0
        elif name in ('MUL', 'MADD', 'MSUB'):
            p = self.mult(s, s.axl[S], s.axh[S])
            self._mulacc(s, name, p)
        elif name == 'MULAXH': s.set_prod(self.mult(s, s.axh[0], s.axh[0]))
        elif name in ('MADDX', 'MSUBX', 'MULX'):
            p = self.mult(s, s.axl[0] if not S else s.axh[0], s.axl[1] if not T else s.axh[1])
            self._mulacc(s, name, p)
        elif name in ('MADDC', 'MSUBC', 'MULC'):
            p = self.mult(s, (s.acc[S] >> 16) & M16, s.axh[T])
            self._mulacc(s, name, p)
        elif name in ('MULMVZ', 'MULAC', 'MULMV', 'MULXMVZ', 'MULXAC', 'MULXMV', 'MULCMVZ', 'MULCAC', 'MULCMV'):
            if name.startswith('MULX'): p = self.mult(s, s.axl[0] if not S else s.axh[0], s.axl[1] if not T else s.axh[1])
            elif name.startswith('MULC'): p = self.mult(s, (s.acc[S] >> 16) & M16, s.axh[T])
            else: p = self.mult(s, s.axl[S], s.axh[S])
            kind = name[-3:] if name.endswith('MVZ') else name[-2:]
            old = s.prod()
            if name.endswith('MVZ'):
                setacc(Rr, (old >> 16) << 16)
            elif name.endswith('MV'):
                setacc(Rr, old)
            else:
                setacc(Rr, A(Rr) + old)
            s.set_prod(p)
            self.flags40(s, A(Rr))
        else:
            raise KeyError(name)

    def _mulacc(self, s, name, p):
        if name.startswith('MADD'): s.set_prod(s.prod() + p)
        elif name.startswith('MSUB'): s.set_prod(s.prod() - p)
        else: s.set_prod(p)


# ---- state <-> vector text ---------------------------------------------------------------------
def to_regs(s):
    d = {}
    for i in range(4): d[f'ar{i}'] = s.ar[i]
    for i in range(4): d[f'ix{i}'] = s.ix[i]
    for i in range(4): d[f'wr{i}'] = s.wr[i]
    for i in range(4): d[f'st{i}'] = s.st[i] if isinstance(s.st[i], int) else 0
    d['cr'] = s.cr
    d['prod.l'] = s.pl; d['prod.m1'] = s.pm1; d['prod.h'] = s.ph & 0xff; d['prod.m2'] = s.pm2
    for k in range(2):
        d[f'ax{k}.l'] = s.axl[k]; d[f'ax{k}.h'] = s.axh[k]
        d[f'acc{k}'] = s.acc[k] & M40
    for n, b in zip(SRNAMES, s.sr): d[n] = b
    return d


def vector_line(vid, code, s):
    regs = to_regs(s)
    r = ','.join(f'{k}={v:x}' for k, v in regs.items())
    m = ','.join([f'd{a:04x}={v:04x}' for a, v in sorted(s.dmem.items()) if v] +
                 [f'i{a:04x}={v:04x}' for a, v in sorted(s.imem.items()) if v])
    return f"{vid}|{''.join(f'{w:04x}' for w in code)}|{r}|{m}"


def parse_result(line):
    f = line.rstrip('\n').split('|')
    vid, status, pc = f[0], f[1], f[2]
    regs = {}
    if f[3]:
        for kv in f[3].split(','):
            k, v = kv.split('=')
            regs[k] = int(v, 16)
    mem = {}
    if len(f) > 4 and f[4]:
        for kv in f[4].split(','):
            k, v = kv.split('=')
            mem[k] = int(v, 16)
    return vid, status, (int(pc, 16) if pc else None), regs, mem
