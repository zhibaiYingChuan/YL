# -*- coding: utf-8 -*-
"""反汇编 _dl_lookup_direct 入口 0xd0a0-0xd2a0，含分支目标。"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM

ELF_PATH = r"g:\Yl\fixtures\runtime\ld-linux-x86-64.so.2"

with open(ELF_PATH, "rb") as f:
    data = f.read()

header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
e_phoff = header[4]
e_phentsize = header[8]
e_phnum = header[9]
loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    (p_type, _, p_offset, p_vaddr, _, p_filesz, _, _) = struct.unpack_from("<IIQQQQQQ", data, off)
    if p_type == 1:
        loads.append((p_offset, p_vaddr, p_filesz))

def v2o(vaddr):
    for (po, pv, pf) in loads:
        if pv <= vaddr < pv + pf:
            return po + (vaddr - pv)
    return None

START_V = 0xd0b0
START_O = v2o(START_V)
if START_O is None:
    raise RuntimeError(f"无法将虚拟地址 0x{START_V:x} 转换为文件偏移")
code = data[START_O : START_O + 0x210]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

lines = []
for ins in md.disasm(code, START_V):
    mems = []
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            base = ins.reg_name(op.mem.base) if op.mem.base else "?"
            disp = op.mem.disp
            mems.append(f"[{base}{disp:+x}]")
    mem_txt = ("  MEM:" + " ".join(mems)) if mems else ""
    jmp = ""
    for op in ins.operands:
        if op.type == 3:  # IMM
            jmp = f"  -> 0x{op.imm:x}"
    lines.append(f"0x{ins.address:06x}: {ins.mnemonic:8s} {ins.op_str}{mem_txt}{jmp}")

with open(r"g:\Yl\tools\lookup_disasm.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print(f"wrote {len(lines)} lines")