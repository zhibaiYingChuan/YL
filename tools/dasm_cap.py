#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 capstone 反汇编 ELF 指定 vaddr 区域，并标注最近的符号。
用法: python dasm_cap.py <elf> <vaddr_hex> <len_hex>  (vaddr 为文件内 vaddr/偏移)
"""
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

path = sys.argv[1]
vaddr = int(sys.argv[2], 16)
span = int(sys.argv[3], 16)

data = open(path, "rb").read()

# 段映射 vaddr -> fileoff
segs = []
e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize = struct.unpack_from("<H", data, 54)[0]
e_phnum = struct.unpack_from("<H", data, 56)[0]
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, o)
    p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, o + 8)
    if p_type == 1:
        segs.append((p_vaddr, p_offset, p_filesz))


def v2o(a):
    for pv, po, ps in segs:
        if pv <= a < pv + ps:
            return po + (a - pv)
    return None


def o2v(a):
    for pv, po, ps in segs:
        if po <= a < po + ps:
            return pv + (a - po)
    return None


# 符号表（.dynsym）用于标注
def load_symbols():
    # 解析节表找 .dynsym/.symtab 与 .dynstr/.strtab
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sections.append(struct.unpack_from("<IIQQQQIIQQ", data, off))
    shstr_off = sections[e_shstrndx][4]
    shstr = data[shstr_off:]
    def sname(off):
        e = shstr.index(b"\x00", off)
        return shstr[off:e].decode()
    syms = []
    for sh in sections:
        name = sname(sh[0])
        if name == ".dynsym":
            entsize = sh[9] or 24
            off = sh[4]
            size = sh[5]
            addr = sh[3]
            strtab_sec = None
            for sh2 in sections:
                if sname(sh2[0]) == ".dynstr":
                    strtab_sec = sh2
            st = strtab_sec[4] if strtab_sec else 0
            strdata = data[st:] if strtab_sec else b""
            for i in range(size // entsize):
                (st_name, st_info, st_other, st_shndx,
                 st_value, st_size) = struct.unpack_from("<IBBHQQ", data, off + i * entsize)
                if st_name and st_value and st_name < len(strdata):
                    e = strdata.index(b"\x00", st_name)
                    nm = strdata[st_name:e].decode(errors="replace")
                    syms.append((st_value, nm, st_size))
    syms.sort()
    return syms


syms = load_symbols()

print(f"== {path} vaddr=0x{vaddr:x} span=0x{span:x} ==")
off = v2o(vaddr)
if off is None:
    print("vaddr 不在任何段内")
    sys.exit(1)
end = min(vaddr + span, o2v(off + span) or vaddr + span)

cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = False
code = data[off:off + (end - vaddr)]


def sym_at(a):
    for sv, nm, ss in syms:
        if sv <= a < sv + max(ss, 1):
            return nm
    return None


prev_sym = sym_at(vaddr)
if prev_sym:
    print(f";; 当前符号: {prev_sym}")
for insn in cs.disasm(code, vaddr):
    s = sym_at(insn.address)
    if s is not None and s != prev_sym:
        print(f";; {s}")
        prev_sym = s
    print(f"  0x{insn.address:07x}: {insn.mnemonic:8s} {insn.op_str}")

print()
print("== 符号上下文 ==")
shown = 0
for sv, nm, ss in syms:
    if sv <= vaddr < sv + max(ss, 1) or (sv >= vaddr - 0x80 and sv < vaddr + span + 0x80):
        print(f"  0x{sv:x} +0x{ss:x}  {nm}")
        shown += 1
        if shown > 60:
            break