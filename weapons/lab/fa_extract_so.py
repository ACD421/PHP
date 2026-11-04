#!/usr/bin/env python3
# fa_extract_so.py — zif_system for STRIPPED PHP shared objects: the
# zend_function_entry {fname, handler} pairs live in .data.rel.ro with the
# pointers stored as R_X86_64_RELATIVE addends. Find "system\0", match
# relocs whose addend == that vaddr, take the +8 reloc's addend as the
# handler (must land in an exec segment).
import struct, subprocess, sys

def segments(d):
    e_phoff, = struct.unpack_from('<Q', d, 0x20)
    entsz, num = struct.unpack_from('<HH', d, 0x36)
    segs = []
    for i in range(num):
        o = e_phoff + i * entsz
        t, fl = struct.unpack_from('<II', d, o)
        off, va, _, fsz = struct.unpack_from('<QQQQ', d, o + 8)
        if t == 1:
            segs.append((va, fsz, off, fl))
    return segs

def off2va(segs, fo):
    for va, fsz, off, fl in segs:
        if off <= fo < off + fsz:
            return va + (fo - off)
    return None

def va_exec(segs, va):
    for v, fsz, off, fl in segs:
        if v <= va < v + fsz:
            return bool(fl & 1)
    return False

def main(path):
    d = open(path, 'rb').read()
    segs = segments(d)
    rel = subprocess.run(['readelf', '-r', '-W', path], capture_output=True, text=True).stdout
    add_by_off, rel_at = {}, {}
    for line in rel.splitlines():
        t = line.split()
        if len(t) >= 4 and t[2] == 'R_X86_64_RELATIVE':
            try:
                off = int(t[0], 16); add = int(t[3], 16)
            except ValueError:
                continue
            add_by_off.setdefault(add, []).append(off)
            rel_at[off] = add
    # candidate "system\0" strings (may be merge-tails: pointer mid-string)
    i = d.find(b'system\x00')
    while i != -1:
        sv = off2va(segs, i)
        if sv is not None:
            for entry_off in add_by_off.get(sv, []):
                h = rel_at.get(entry_off + 8)          # handler follows fname
                if h and va_exec(segs, h):
                    print('%s: zif_system=0x%x (via fname@0x%x)' % (path, h, sv))
                    return h
        i = d.find(b'system\x00', i + 1)
    print('%s: zif_system NOT FOUND' % path)
    return None

if __name__ == '__main__':
    for p in sys.argv[1:]:
        main(p)
