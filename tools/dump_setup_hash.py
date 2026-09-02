#!/usr/bin/env python3
"""解析 ld-linux-x86-64.so.2 动态符号表，反汇编 _dl_setup_hash/_dl_lookup_direct/__rtld_mutex_init，
提取 struct link_map 中 GNU hash 相关字段的偏移（用于模拟器填充）。"""
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PATH = r"G:\Yl\fixtures\runtime\ld-linux-x86-64.so.2"

def read_elf(path):
    data = open(path, "rb").read()
    ident = data[:16]
    assert ident[:4] == b"\x7fELF" and ident[4] == 2, "not 64-bit ELF"
    # 64 位 ELF Ehdr（偏移 16 起）：H(e_type) H(e_machine) I(e_version) Q(e_entry)
    # Q(e_phoff) Q(e_shoff) I(e_flags) 6×H(程序/节头相关)，共 48 字节
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    print(f"[诊断] e_phoff=0x{e_phoff:x} e_phnum={e_phnum} e_phentsize={e_phentsize} e_entry=0x{e_entry:x}")
    segs = []
    for i in range(e_phnum):
        (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i*e_phentsize)
        segs.append(dict(type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr,
                         filesz=p_filesz, memsz=p_memsz, align=p_align))
    return data, segs, e_entry

data, segs, e_entry = read_elf(PATH)

def vaddr_to_offset(va):
    for s in segs:
        if s["type"] == 1 and s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return s["offset"] + (va - s["vaddr"])
    return None

def offset_to_vaddr(off):
    for s in segs:
        if s["type"] == 1 and s["offset"] <= off < s["offset"] + s["filesz"]:
            return s["vaddr"] + (off - s["offset"])
    return None

for s in segs:
    print(f"  seg type={s['type']} flags={s['flags']:#x} off=0x{s['offset']:x} vaddr=0x{s['vaddr']:x} filesz=0x{s['filesz']:x} memsz=0x{s['memsz']:x}")

dyn = next(s for s in segs if s["type"] == 2)
dyn_data = data[dyn["offset"]:dyn["offset"]+dyn["filesz"]]
tags = {}
i = 0
entries = []
while True:
    tag, val = struct.unpack_from("<qQ", dyn_data, i*16)
    if tag == 0:
        break
    entries.append((tag, val))
    tags[tag] = val
    i += 1
print(f"[诊断] PT_DYNAMIC off=0x{dyn['offset']:x} filesz=0x{dyn['filesz']:x} 条目数={i}")
print(f"[诊断] 前12个动态条目: {[(hex(t), hex(v)) for t, v in entries[:12]]}")

def dt(tag):
    return tags.get(tag)

symtab_va = dt(6); strtab_va = dt(5); sym_size = 24
sym_off = vaddr_to_offset(symtab_va); str_off = vaddr_to_offset(strtab_va)
print(f"[诊断] DT_SYMTAB=0x{symtab_va:x} -> file 0x{sym_off:x} | DT_STRTAB=0x{strtab_va:x} -> file 0x{str_off:x}")
print(f"[诊断] DT_GNU_HASH=0x{dt(0x6ffffef5):x} DT_HASH=0x{dt(4) if 4 in tags else 0:x} DT_STRSZ=0x{dt(10):x}")

def load_syms():
    syms = {}
    # 用 SysV hash 表（DT_HASH@0x2f0）读 nchain 确定 .dynsym 条目数
    nb, nc = struct.unpack_from("<II", data, vaddr_to_offset(dt(4)))
    count = nc  # nchain == .dynsym 条目数（含索引 0 的 NUL 符号）
    off = sym_off
    for _ in range(count):
        (st_name, st_info, st_other, st_shndx, st_value, st_size) = struct.unpack_from("<IBBHQQ", data, off)
        if st_name:
            if str_off + st_name >= len(data):
                break
            name_end = data.find(b"\x00", str_off + st_name)
            if name_end < 0:
                break
            name = data[str_off + st_name:name_end].decode("latin1")
            syms[name] = dict(st_value=st_value, st_size=st_size)
        off += sym_size
    return syms

syms = load_syms()

def disasm_between(start_va, stop_va, count=80):
    """反汇编从 start_va 起 count 条指令，附带字节与文件偏移。"""
    off0 = vaddr_to_offset(start_va)
    if off0 is None:
        print(f"  <vaddr 0x{start_va:x} 不在可加载段>")
        return
    end_off = vaddr_to_offset(stop_va) if stop_va else min(off0 + 256, len(data))
    blob = data[off0:off0+256]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    n = 0
    for ins in md.disasm(blob, start_va):
        if n >= count:
            break
        print(f"  0x{ins.address:07x}: {ins.mnemonic:8s} {ins.op_str}")
        n += 1

for name in ["_dl_setup_hash", "_dl_lookup_direct", "__rtld_mutex_init"]:
    sym = syms.get(name)
    if not sym:
        print(f"[{name}] 未找到")
        continue
    print(f"\n===== {name} @ 0x{sym['st_value']:07x} size=0x{sym['st_size']:x} =====")
    disasm_between(sym["st_value"], sym["st_value"] + sym["st_size"])

# 版本信息参考
print("\n===== 版本相关常量 =====")
print("DT_VERSYM:", hex(dt(0x6ffffff0)) if 0x6ffffff0 in tags else "无")
print("DT_VERDEF:", hex(dt(0x6ffffffc)) if 0x6ffffffc in tags else "无")
print("DT_VERNEED:", hex(dt(0x6ffffffd)) if 0x6ffffffd in tags else "无")

# ===== 无符号定位：通过字符串交叉引用（RIP-relative）找函数 =====
# ld.so 被 strip，_dl_setup_hash/_dl_lookup_direct/__rtld_mutex_init 不在 .dynsym。
# 用 assert 消息 "dl-mutex.c" 的 rodata 地址反查引用它的代码（__rtld_mutex_init）。

TEXT_VA = next(s["vaddr"] for s in segs if s["type"] == 1 and s["flags"] & 1)  # 可执行段
TEXT_OFF = next(s["offset"] for s in segs if s["type"] == 1 and s["flags"] & 1)
TEXT_SIZE = next(s["filesz"] for s in segs if s["type"] == 1 and s["flags"] & 1)


def find_rip_refs(target_va, blob=None, blob_va=None, near=0):
    """在代码段中扫描所有 RIP-relative 引用 target_va（或 ±near 范围）的指令。"""
    if blob is None:
        blob = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
        blob_va = TEXT_VA
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    hits = []
    for ins in md.disasm(blob, blob_va):
        if "rip" not in ins.op_str:
            continue
        op = ins.op_str.split("[")[-1].split("]")[0] if "[" in ins.op_str else ins.op_str
        op = op.replace("rip", "").strip()
        try:
            disp = int(op.replace(" ", ""), 16) if op else 0
        except Exception:
            continue
        ref = (ins.address + ins.size + disp) & 0xFFFFFFFFFFFFFFFF
        if near and abs(ref - target_va) <= near:
            hits.append((ins.address, ins.mnemonic, ins.op_str, ref))
        elif ref == target_va:
            hits.append((ins.address, ins.mnemonic, ins.op_str, ref))
    return hits


# 定位 "dl-mutex.c" 字符串（__rtld_mutex_init 的 assert 消息）
for needle in [b"dl-mutex.c", b"Assertion 'sym != NULL'"]:
    idx = data.find(needle)
    if idx < 0:
        print(f"[定位] 字符串 {needle!r} 未找到")
        continue
    str_va = offset_to_vaddr(idx)
    print(f"[定位] 字符串 {needle!r} @ file 0x{idx:x} vaddr=0x{str_va:x}")
    hits = find_rip_refs(str_va)
    print(f"[定位] 引用该字符串的 RIP 指令: {[(hex(a), m, o, hex(r)) for a, m, o, r in hits]}")
    if not hits:
        near_hits = find_rip_refs(str_va, near=0x20)
        print(f"[定位] 近似命中(±32B): {[(hex(a), m, o, hex(r)) for a, m, o, r in near_hits][:10]}")
    for ins_va, m, o, r in hits[:3]:
        # 反汇编引用点之前 64 字节到之后 48 字节
        pre = vaddr_to_offset(ins_va - 64)
        blob = data[pre:pre + 112]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        print(f"--- 引用点 0x{ins_va:x} 附近反汇编 ---")
        for i in md.disasm(blob, ins_va - 64):
            if i.address > ins_va + 48:
                break
            mark = "  <<<" if i.address == ins_va else ""
            print(f"  0x{i.address:07x}: {i.mnemonic:8s} {i.op_str}{mark}")

# __rtld_mutex_init 大概在 0x1e700..0x1e900（引用 __FILE__/__PRETTY_FUNCTION__ 的 lea 在 0x1e849..0x1e8c5）
print("\n===== _dl_lookup_direct @ 0xd0b0 反汇编 =====")
blob_off = vaddr_to_offset(0xd0b0)
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
for ins in md.disasm(data[blob_off:blob_off + 0x340], 0xd0b0):
    mark = ""
    if "call" in ins.mnemonic or "jmp" in ins.mnemonic:
        mark = "   <<< BRANCH"
    print(f"  0x{ins.address:07x}: {ins.mnemonic:8s} {ins.op_str}{mark}")