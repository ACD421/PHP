#!/usr/bin/env python3
# fa_dump_handlers.py — dump std_object_handlers from a PHP ELF and label each
# slot with the symbol name it points to. Receipt-grade handler-offset table.
import subprocess, sys, struct

path = sys.argv[1]
nm = subprocess.run(['nm', path], capture_output=True, text=True).stdout
syms = {}
for line in nm.splitlines():
    parts = line.split()
    if len(parts) == 3:
        try:
            syms[int(parts[0], 16)] = parts[2]
        except ValueError:
            pass

soh = None
for addr, name in syms.items():
    if name == 'std_object_handlers':
        soh = addr
        break
if soh is None:
    print('std_object_handlers not found'); sys.exit(1)
print('std_object_handlers = 0x%x' % soh)

# map vaddr -> file offset via program headers
d = open(path, 'rb').read()
e_phoff, = struct.unpack_from('<Q', d, 0x20)
e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
segs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, = struct.unpack_from('<I', d, off)
    p_offset, p_vaddr, p_filesz = struct.unpack_from('<QQQ', d, off + 8)
    if p_type == 1:
        segs.append((p_vaddr, p_filesz, p_offset))

def v2o(va):
    for v, sz, o in segs:
        if v <= va < v + sz:
            return o + (va - v)
    return None

# relocations (RELATIVE and sym-based) carry the initialized pointer values
rel = subprocess.run(['readelf', '-r', '-W', path], capture_output=True, text=True).stdout
relmap = {}
for line in rel.splitlines():
    t = line.split()
    if len(t) >= 4:
        try:
            off = int(t[0], 16)
        except ValueError:
            continue
        if t[2] == 'R_X86_64_RELATIVE':
            relmap[off] = int(t[3], 16)
        elif t[2] == 'R_X86_64_64':
            add = t[5] if '+' in t[4] else 0
            m = [a for a in syms.values()]
            # sym name is t[4]; find its address
            for addr, name in syms.items():
                if name == t[4]:
                    relmap[off] = addr + int(add)
                    break

for i in range(30):
    va = soh + i * 8
    ptr = relmap.get(va, 0)
    lbl = syms.get(ptr, '')
    print('  +%-4d 0x%012x  %s' % (i * 8, ptr, lbl))
