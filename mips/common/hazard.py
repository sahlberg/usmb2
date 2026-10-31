#!/usr/bin/python3 -I
"""Check MIPS-I (R3000) hazards in `objdump -d` output that qemu does not emulate:
 - load delay: the instruction after a load must not read the loaded register
 - HI/LO: mfhi/mflo must not be followed within 2 instructions by mult/div/mthi/mtlo
Branch delay slots are followed into both the fall-through and the branch target."""
import re, sys
LOADS = {'lb','lbu','lh','lhu','lw','lwl','lwr'}
BRANCH = re.compile(r'^(b|beq|bne|beqz|bnez|blez|bgtz|bltz|bgez|bltzal|bgezal|j|jal|jr|jalr|bal|b)$')
ins = []
for line in open(sys.argv[1]):
    m = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\S+)\s*(.*)', line)
    if m:
        a, op, args = int(m.group(1), 16), m.group(2), m.group(3).split('#')[0].split('<')[0].strip()
        ins.append((a, op, [x.strip() for x in args.split(',')] if args else []))
byaddr = {a: i for i, (a, _, _) in enumerate(ins)}
def regs_read(op, args):
    r = set()
    for i, x in enumerate(args):
        for m in re.findall(r'\$?\b(zero|at|v[01]|a[0-3]|t[0-9]|s[0-8]|k[01]|gp|sp|fp|ra)\b', x):
            if '(' in x or i > 0 or op in ('sb','sh','sw','swl','swr','jr','jalr','mthi','mtlo','mult','multu','div','divu') or BRANCH.match(op):
                r.add(m)
    if op in ('lwl', 'lwr') and args:  # merge loads also read the destination
        r.add(args[0].lstrip('$'))
    return r
def target(op, args):
    if BRANCH.match(op) and op not in ('jr', 'jalr') and args:
        try: return int(args[-1], 16)
        except ValueError: return None
def nexts(i):
    """indices of instructions that can execute right after ins[i]"""
    out = [i + 1] if i + 1 < len(ins) else []
    if i > 0 and BRANCH.match(ins[i-1][1]):           # i is a delay slot
        t = target(ins[i-1][1], ins[i-1][2])
        if t is not None and t in byaddr: out.append(byaddr[t])
        if ins[i-1][1] in ('b', 'j', 'jr', 'jal', 'jalr', 'bal'): out = out[1:]
    return out
bad = 0
for i, (a, op, args) in enumerate(ins):
    if op in LOADS and args:
        d = args[0].lstrip('$')
        for n in nexts(i):
            # an lwr/lwl pair to the same register may be back to back on MIPS-I
            if op in ('lwl', 'lwr') and ins[n][1] in ('lwl', 'lwr') and ins[n][1] != op and ins[n][2][:1] == args[:1]:
                continue
            if d != 'zero' and d in regs_read(ins[n][1], ins[n][2]):
                print('load hazard at %x: %s %s -> %x: %s %s' % (a, op, ','.join(args), ins[n][0], ins[n][1], ','.join(ins[n][2]))); bad += 1
    if op in ('mfhi', 'mflo'):
        for n in nexts(i):
            for m in [n] + nexts(n):
                if ins[m][1] in ('mult','multu','div','divu','mthi','mtlo'):
                    print('hi/lo hazard at %x' % a); bad += 1
sys.exit(1 if bad else 0)
