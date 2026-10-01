#!/usr/bin/env python3
"""Rebuild tiny_elf (B-9, idx 522438 repro input): minimal 64-byte ELF64, e_shoff=0xFFFFFF00.

The tiny_elf in this directory is byte-identical to this script's output; the script exists for readability and auditability.
Usage: python3 make_tiny_elf.py tiny_elf
"""
import struct
import sys

def main():
    e_ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8  # ELF64/LSB/ver1
    hdr = e_ident
    hdr += struct.pack('<HHIQQQIHHHHHH',
        2,          # e_type = ET_EXEC
        0x3e,       # e_machine = x86-64
        1,          # e_version
        0,          # e_entry
        0,          # e_phoff
        0xFFFFFF00, # e_shoff  <- wild section-table offset (trigger point)
        0,          # e_flags
        64,         # e_ehsize
        0, 0,       # e_phentsize, e_phnum
        64, 1, 0)   # e_shentsize, e_shnum, e_shstrndx
    assert len(hdr) == 64, len(hdr)
    out = sys.argv[1] if len(sys.argv) > 1 else 'tiny_elf'
    open(out, 'wb').write(hdr)
    print('wrote', out, len(hdr), 'bytes')

if __name__ == '__main__':
    main()
