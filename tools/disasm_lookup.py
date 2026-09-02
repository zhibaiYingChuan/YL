# -*- coding: utf-8 -*-
"""反汇编 _dl_lookup_direct (vaddr 0xd0b0) 前 160 字节，并标注含内存访问的操作数。"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM

ELF_PATH = r"g:\Yl\fixtures\runtime\ld-linux-x86-64.so.2"

with open(ELF_PATH, "rb") as f:
    data = f.read()

# PT_LOAD 映射表
(_, _, _, _, _, e_phoff, _, _, _, e_phentsize, e_phnum, _, _, _) = (
    data[0:16], *struct.unpack_from("<HHIQQQIHHHHHH", data, 16))
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
LEN = 220
code = data[START_O:START_O + LEN]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for ins in md.disasm(code, START_V):
    mems = []
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            base = op.mem.base if op.mem.base else 0
            disp = op.mem.disp
            # 打印访问形式 [reg+disp]
            regname = ins.reg_name(base) if base else "?"
            seg = ""
            mems.append(f"[{regname}{disp:+x}]")
    mem_txt = ("  MEM:" + " ".join(mems)) if mems else ""
    print(f"0x{ins.address:06x}: {ins.mnemonic:8s} {ins.op_str}{mem_txt}")