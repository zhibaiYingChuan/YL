# -*- coding: utf-8 -*-
"""dump ld-linux 与 libc 的 PT_DYNAMIC 条目，检查 0x1fd08 是否等于某个 d_ptr。"""
import struct

FILES = [
    r"g:\Yl\fixtures\runtime\ld-linux-x86-64.so.2",
    r"g:\Yl\fixtures\runtime\libc.so.6",
]

DT_NAMES = {
    0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
    5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
    10: "STRSZ", 11: "SYMENT", 12: "INIT", 13: "FINI", 14: "SONAME",
    15: "RPATH", 16: "SYMBOLIC", 17: "REL", 18: "RELSZ", 19: "RELENT",
    20: "PLTREL", 21: "DEBUG", 22: "TEXTREL", 23: "JMPREL",
    24: "BIND_NOW", 25: "INIT_ARRAY", 26: "FINI_ARRAY", 27: "INIT_ARRAYSZ",
    28: "FINI_ARRAYSZ", 29: "RUNPATH", 30: "FLAGS", 32: "PREINIT_ARRAY",
    33: "PREINIT_ARRAYSZ", 0x6ffffff0: "VERSYM", 0x6ffffff9: "RELACOUNT",
    0x6ffffffb: "FLAGS_1", 0x6ffffffc: "VERDEF", 0x6ffffffd: "VERDEFNUM",
    0x6ffffffe: "VERNEED", 0x6fffffff: "VERNEEDNUM", 0x6ffffef5: "GNU_HASH",
    0x6ffffef6: "TLSDESC_PLT", 0x6ffffef7: "TLSDESC_GOT",
}

def parse(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF"
    (_, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
     e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = (
        data[0:16], *struct.unpack_from("<HHIQQQIHHHHHH", data, 16))
    loads, dynamics = [], []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _, p_filesz, _, _) = struct.unpack_from(
            "<IIQQQQQQ", data, off)
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
        elif p_type == 2:  # PT_DYNAMIC
            dynamics.append((p_offset, p_vaddr, p_filesz))

    def v2o(vaddr):
        for (po, pv, pf) in loads:
            if pv <= vaddr < pv + pf:
                return po + (vaddr - pv)
        return None

    print(f"=== {path} ===")
    for (doff, dvaddr, dsz) in dynamics:
        print(f"PT_DYNAMIC vaddr=0x{dvaddr:x} off=0x{doff:x} size=0x{dsz:x}")
        n = dsz // 16
        for i in range(n):
            tag, val = struct.unpack_from("<qQ", data, doff + i * 16)
            tag_u = tag & 0xFFFFFFFFFFFFFFFF
            name = DT_NAMES.get(tag_u, f"tag=0x{tag_u:x}")
            mark = "   <<< 0x1fd08" if val == 0x1fd08 else ""
            if tag == 0:
                break
            print(f"  [{i:2}] {name:18s} val=0x{val:x}{mark}")
    print()

for p in FILES:
    parse(p)
    print()