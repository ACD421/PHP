#!/usr/bin/env python3
# extract_syms.py — offline zif_system/zend_empty_array extraction for any
# php ELF (works stripped). zif_system via the zend_function_entry walk:
# entry = {const char *fname; zif_handler handler; ...}; fname points at a
# C string "system". Validate: plain2 -> zif_system=0x523c60.
import struct, sys, subprocess

def parse_elf(path):
    d = open(path, 'rb').read()
    e_phoff, = struct.unpack_from('<Q', d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', d, off)
        p_offset, p_vaddr, _, p_filesz = struct.unpack_from('<QQQQ', d, off + 8)
        if p_type == 1:
            segs.append((p_vaddr, p_filesz, p_offset, p_flags))
    return d, segs

def off_to_vaddr(segs, foff):
    for vaddr, filesz, offset, flags in segs:
        if offset <= foff < offset + filesz:
            return vaddr + (foff - offset), flags
    return None, None

def vaddr_to_off(segs, va):
    for vaddr, filesz, offset, flags in segs:
        if vaddr <= va < vaddr + filesz:
            return offset + (va - vaddr)
    return None

def find_zif_system(path):
    d, segs = parse_elf(path)
    cands = []
    i = d.find(b'system\x00')
    while i != -1:
        if i > 0 and d[i-1] == 0:  # standalone C string
            va, fl = off_to_vaddr(segs, i)
            if va is not None:
                cands.append(va)
        i = d.find(b'system\x00', i + 1)
    for sv in cands:
        ptr = struct.pack('<Q', sv)
        j = d.find(ptr)
        while j != -1:
            va, fl = off_to_vaddr(segs, j)
            if va is not None and not (fl & 1):  # entry in a data segment
                handler, = struct.unpack_from('<Q', d, j + 8)
                hoff = vaddr_to_off(segs, handler)
                if hoff is not None:
                    _, hfl = off_to_vaddr(segs, hoff)
                    if hfl is not None and (hfl & 1):  # handler in exec segment
                        cands.append(('HIT', handler))
                        return handler
            j = d.find(ptr, j + 1)
    return None

def find_zend_empty_array(path):
    out = subprocess.run(['nm', '-D', path], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == 'zend_empty_array':
            return int(parts[0], 16)
    return None

if __name__ == '__main__':
    for path in sys.argv[1:]:
        zif = find_zif_system(path)
        zea = find_zend_empty_array(path)
        print(f"{path}:",
              f"zif_system=0x{zif:x}" if zif else "zif_system NOT FOUND",
              f"zend_empty_array=0x{zea:x}" if zea else "zend_empty_array NOT FOUND", sep='  ')
