#!/usr/bin/env python3
"""反汇编 ld-linux-x86-64.so.2 的 0x1e80e 与 0xf5c2 窗口，识别访问未绝对化
DT_VERDEF(0x1fd08) 的指令所属函数。用法: python tools/dump_rtld_region.py"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PATH = r"G:\Yl\fixtures\runtime\ld-linux-x86-64.so.2"
data = open(PATH, "rb").read()

(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
segs = []
for i in range(e_phnum):
    (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsize)
    segs.append(dict(type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz, align=p_align))

TEXT = next(s for s in segs if s["type"] == 1 and s["flags"] & 1)

def disasm_window(file_off, size=0x240, count=200, label=""):
    """按文件偏移反汇编窗口，标出 0x1e80e/0xf5c2 目标。"""
    print(f"\n===== {label} file 0x{file_off:x} ~ 0x{file_off+size:x} (vaddr 0x{TEXT['vaddr']+file_off-TEXT['offset']:x}) =====")
    # 先定位文件偏移属于哪个 PT_LOAD 的 vaddr
    for s in segs:
        if s["type"] == 1 and s["offset"] <= file_off < s["offset"] + s["filesz"]:
            va = s["vaddr"] + (file_off - s["offset"])
            break
    else:
        print("  不在可加载段")
        return
    blob = data[file_off:file_off + size]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    n = 0
    for ins in md.disasm(blob, va):
        if n >= count:
            break
        mark = ""
        if ins.address == 0x1e80e or ins.address == 0xf5c2:
            mark = "   <<<<<< 关注点"
        # 提取内存操作数（访问目标），标出常量 0x1fd08 / 0x20230 / 0x25 / 0x723566
        ops = ins.op_str
        extra = []
        for const in (0x1fd08, 0x20230, 0x25, 0x723566, 0x724d08, 0x705025):
            if ("+ 0x%x" % const) in ops or ("- 0x%x" % const) in ops:
                extra.append("含0x%x" % const)
        if len(ins.groups) and any(g == 0 for g in ins.groups):  # jump 组
            pass
        if extra:
            mark += "  << " + ",".join(extra)
        print(f"  0x{ins.address:07x}: {ins.mnemonic:8s} {ins.op_str}{mark}")
        n += 1

disasm_window(0x1e500, 0x380, 240, "0x1e80e 附近（__rtld_mutex_init / _dl_lookup_symbol_x 归属）")
disasm_window(0xf400, 0x300, 180, "0xf5c2 附近")