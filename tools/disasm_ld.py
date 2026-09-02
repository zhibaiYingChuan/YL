# -*- coding: utf-8 -*-
"""反汇编 ld-linux-x86-64.so.2 中三个命中 0x1fd08 访问失败的 RIP。
用法: python tools/disasm_ld.py
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ELF_PATH = r"g:\Yl\fixtures\runtime\ld-linux-x86-64.so.2"
LOAD_BIAS = 0x2700000  # 运行时基址（来自动态装载日志）

RIPS = [0x271e80e, 0x271e855, 0x27020fd]

with open(ELF_PATH, "rb") as f:
    data = f.read()

assert data[:4] == b"\x7fELF", "不是 ELF 文件"

# 解析 ELF64 header
(e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
 e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = (
    data[0:16], *struct.unpack_from("<HHIQQQIHHHHHH", data, 16))

print(f"entry=0x{e_entry:x} phoff=0x{e_phoff:x} phnum={e_phnum} phentsize={e_phentsize}")

# 解析 PT_LOAD
loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = \
        struct.unpack_from("<IIQQQQQQ", data, off)
    if p_type == 1:  # PT_LOAD
        loads.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align))
        print(f"LOAD off=0x{p_offset:x} vaddr=0x{p_vaddr:x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x} flags={p_flags:#x}")

print()


def vaddr_to_offset(vaddr: int) -> int | None:
    """把 vaddr 映射到文件偏移（基于 PT_LOAD）。"""
    for (_, _, p_offset, p_vaddr, p_filesz, _, _) in loads:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for rip in RIPS:
    vaddr = rip - LOAD_BIAS
    foff = vaddr_to_offset(vaddr)
    print(f"===== rip=0x{rip:x} vaddr=0x{vaddr:x} file=0x{foff:x} =====")
    if foff is None:
        print("  未命中任何 PT_LOAD（可能落在未映射文件区域）")
        continue
    # 取前后 48 字节
    start = max(0, foff - 32)
    end = min(len(data), foff + 64)
    code = data[start:end]
    for ins in md.disasm(code, vaddr - (foff - start)):
        mark = "  <<<<" if ins.address == vaddr else ""
        ops = ins.op_str
        if "mem" in str(ins.operands):
            # 标记含内存操作数的指令
            pass
        print(f"  0x{ins.address:07x}: {ins.mnemonic:8s} {ops}{mark}")
    print()