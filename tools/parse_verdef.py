#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 libc.so.6 的 ELF 动态段：DT_VERDEF/DT_VERNEED 链与版本哈希。
用途：核实 __rtld_mutex_init 版本校验失败的根因（l_versions[2] 缺失）。
"""
import struct
import sys

ELFCLASS32 = 1
ELFCLASS64 = 2
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_GNU_HASH = 0x6ffffef5
DT_VERSYM = 0x6ffffff0
DT_VERDEF = 0x6ffffffc
DT_VERNEED = 0x6ffffffd
DT_VERNEEDNUM = 0x6ffffffe
DT_VERDEFNUM = 0x6fffffff


def elf_hash(name: bytes) -> int:
    h = 0
    for c in name:
        h = (h << 4) + c
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
            h &= ~g
    return h & 0xFFFFFFFF


def gnu_hash(name: bytes) -> int:
    h = 5381
    for c in name:
        h = (h << 5) + c
    return h & 0xFFFFFFFF


def parse(path: str):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF", "not ELF"
    ei_class = data[4]
    assert ei_class == ELFCLASS64, "only 64-bit supported"
    ei_data = data[5]
    assert ei_data == 1, "only little-endian"

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    # 段表
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = struct.unpack_from("<IIQQQQIIQQ", data, off)
        sections.append(sh)

    # 段名表
    shstr_off = sections[e_shstrndx][4]
    shstr_size = sections[e_shstrndx][5]
    shstr = data[shstr_off:shstr_off + shstr_size]

    def sec_name(off):
        end = shstr.index(b"\x00", off)
        return shstr[off:end].decode()

    secinfo = {}
    for i, sh in enumerate(sections):
        name = sec_name(sh[0])
        secinfo[name] = sh  # (name,type,flags,addr,offset,size,link,info,align,entsize)

    def dump_sec(name):
        if name not in secinfo:
            print(f"[sec] {name}: 不存在")
            return None
        sh = secinfo[name]
        off = sh[4]
        size = sh[5]
        addr = sh[3]
        print(f"[sec] {name}: vaddr=0x{addr:x} offset=0x{off:x} size=0x{size:x}")
        return data[off:off + size]

    # 程序头，找 PT_DYNAMIC 与 PT_LOAD 映射
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    # vaddr -> file offset 转换（用 PT_LOAD）
    loads = []
    dynamic_vaddr = None
    dynamic_filesz = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        ph = struct.unpack_from("<IIQQQQQQ", data, off)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = ph
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        if p_type == PT_DYNAMIC:
            dynamic_vaddr = p_vaddr
            dynamic_filesz = p_filesz

    def v2o(vaddr):
        for lv, lo, lfs in loads:
            if lv <= vaddr < lv + lfs:
                return lo + (vaddr - lv)
        return None

    print(f"\n[dyn] dynamic_vaddr=0x{dynamic_vaddr:x} filesz=0x{dynamic_filesz:x}")
    doff = v2o(dynamic_vaddr)
    assert doff is not None
    entries = {}
    n = 0
    while True:
        tag, val = struct.unpack_from("<qQ", data, doff + n * 16)
        if tag == DT_NULL:
            break
        entries[tag] = val
        n += 1
    print(f"[dyn] total_entries={n}")
    names = {
        1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH", 5: "STRTAB",
        6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT", 10: "STRSZ",
        11: "SYMENT", 13: "RELSZ", 14: "REL", 15: "RELENT", 16: "PLTREL",
        17: "DEBUG", 18: "TEXTREL", 19: "JMPREL", 20: "BIND_NOW", 21: "INIT",
        22: "FINI", 23: "SONAME", 24: "RPATH", 25: "SYMBOLIC", 26: "RELATIVE",
        27: "SYMINFO", 28: "MOVE", 29: "LIB", 30: "INIT_ARRAY", 31: "FINI_ARRAY",
        32: "INIT_ARRAYSZ", 33: "FINI_ARRAYSZ", 34: "RUNPATH", 35: "FLAGS",
        0x6ffffff0: "VERSYM", 0x6ffffffc: "VERDEF", 0x6ffffffd: "VERNEED",
        0x6ffffffe: "VERNEEDNUM", 0x6fffffff: "VERDEFNUM",
        0x6ffffef5: "GNU_HASH", 0x6ffffffb: "FLAGS_1", 0x6ffffff8: "RELRSZ",
        0x6ffffff9: "RELR", 0x6ffffffa: "RELRENT",
    }
    for tag in sorted(entries, key=lambda t: t if t >= 0 else t + (1 << 64)):
        v = entries[tag]
        name = names.get(tag if tag >= 0 else tag + (1 << 64), hex(tag))
        print(f"  DT_{name:<12} tag=0x{tag if tag>=0 else tag+(1<<64):x} value=0x{v:x}")

    # 字符串表
    strtab_v = entries.get(DT_STRTAB)
    strtab_off = v2o(strtab_v)
    strtab_end = strtab_off + entries.get(10, 0)

    def cstr(off):
        end = data.index(b"\x00", off, strtab_end)
        return data[off:end]

    # ---- DT_VERDEF ----
    print("\n[VERDEF]")
    if DT_VERDEF in entries:
        vd = entries[DT_VERDEF]
        vd_off = v2o(vd)
        vd_num = entries.get(DT_VERDEFNUM, 0)
        print(f"  vaddr=0x{vd:x} file_offset=0x{vd_off:x} VERDEFNUM={vd_num}")
        cursor = vd_off
        idx = 0
        while True:
            hdr = data[cursor:cursor + 20]
            if len(hdr) < 20:
                print("  [链断裂: 不足20字节]")
                break
            (vd_version, vd_flags, vd_ndx, vd_cnt,
             vd_hash, vd_aux, vd_next) = struct.unpack_from("<HHHHIII", hdr)
            print(f"  entry#{idx} vd_version={vd_version} vd_flags=0x{vd_flags:x} "
                  f"vd_ndx={vd_ndx} vd_cnt={vd_cnt} vd_hash=0x{vd_hash:08x} "
                  f"vd_aux=0x{vd_aux:x} vd_next=0x{vd_next:x} (chain_next@0x{cursor+vd_next:x})")
            # 辅助项
            acursor = cursor + vd_aux
            for _ in range(vd_cnt):
                (vda_name, vda_next, vda_hash, vda_flags,
                 vda_other) = struct.unpack_from("<IIIIH", data[acursor:acursor + 18])
                name = cstr(strtab_off + vda_name)
                print(f"    aux vda_name_off=0x{vda_name:x} name={name.decode(errors='replace')} "
                      f"elf_hash=0x{elf_hash(name):08x} gnu_hash=0x{gnu_hash(name):08x}")
                if vda_next == 0:
                    break
                acursor += vda_next
            if vd_next == 0:
                break
            cursor += vd_next
            idx += 1
        print(f"  [链总条目] {idx + 1}")
    else:
        print("  无 DT_VERDEF")

    # ---- DT_VERNEED ----
    print("\n[VERNEED]")
    if DT_VERNEED in entries:
        vn = entries[DT_VERNEED]
        vn_off = v2o(vn)
        vn_num = entries.get(DT_VERNEEDNUM, 0)
        print(f"  vaddr=0x{vn:x} file_offset=0x{vn_off:x} VERNEEDNUM={vn_num}")
        cursor = vn_off
        for idx in range(vn_num):
            hdr = data[cursor:cursor + 16]
            if len(hdr) < 16:
                print("  [链断裂]")
                break
            (vn_version, vn_cnt, vn_file, vn_aux,
             vn_next) = struct.unpack_from("<HHIIII", hdr)
            fname = cstr(strtab_off + vn_file)
            print(f"  file#{idx} vn_version={vn_version} vn_cnt={vn_cnt} "
                  f"vn_file=0x{vn_file:x} name={fname.decode(errors='replace')} "
                  f"vn_aux=0x{vn_aux:x} vn_next=0x{vn_next:x}")
            acursor = cursor + vn_aux
            for _ in range(vn_cnt):
                (vna_hash, vna_flags, vna_other, vna_name,
                 vna_next) = struct.unpack_from("<IIHHI", data[acursor:acursor + 16])
                name = cstr(strtab_off + vna_name)
                print(f"    aux vna_hash=0x{vna_hash:08x} vna_other={vna_other} "
                      f"name={name.decode(errors='replace')}")
                if vna_next == 0:
                    break
                acursor += vna_next
            if vn_next == 0:
                break
            cursor += vn_next
    else:
        print("  无 DT_VERNEED")

    # ---- 期望哈希 0x9691a75 反查 ----
    print("\n[哈希反查] 期望 0x9691a75 =", 0x9691a75)
    for cand in [b"GLIBC_2.2.5", b"GLIBC_2.34", b"GLIBC_2.35", b"GLIBC_2.36",
                 b"GLIBC_PRIVATE", b"GLIBC_2.3", b"GLIBC_2.4", b"GLIBC_2.33",
                 b"pthread_mutex_lock"]:
        print(f"  {cand.decode():<20} elf_hash=0x{elf_hash(cand):08x} gnu_hash=0x{gnu_hash(cand):08x}")

    # ---- VERSYM 索引检查 pthread_mutex_lock ----
    print("\n[VERSYM]")
    if DT_VERSYM in entries:
        vs_v = entries[DT_VERSYM]
        vs_off = v2o(vs_v)
        # 符号表
        sym_v = entries.get(DT_SYMTAB)
        sym_off = v2o(sym_v)
        sym_ent = entries.get(11, 24)
        # GNU hash
        gh_v = entries.get(DT_GNU_HASH)
        print(f"  versyms vaddr=0x{vs_v:x} symtab vaddr=0x{sym_v:x} gnu_hash vaddr=0x{gh_v:x}")
        if gh_v is not None and sym_v is not None:
            gh_off = v2o(gh_v)
            nbuckets, symoffset, nwords, bloom_shift = struct.unpack_from(
                "<IIII", data, gh_off)
            buckets_off = gh_off + 16 + nwords * 8
            chains_off = buckets_off + nbuckets * 4
            # 找 pthread_mutex_lock in symtab
            # 直接顺序扫描符号表名字段（简化）
            strstr_off = v2o(strtab_v)
            found = False
            for i in range(symoffset, 200000):
                soff = sym_off + i * 24
                if soff + 24 > len(data):
                    break
                (st_name, st_info, st_other,
                 st_shndx, st_value, st_size) = struct.unpack_from("<IBBHQQ", data, soff)
                if st_name == 0:
                    continue
                nm = cstr(strstr_off + st_name)
                if nm == b"pthread_mutex_lock":
                    vs = struct.unpack_from("<H", data, vs_off + i * 2)[0]
                    print(f"  pthread_mutex_lock symidx={i} hidden_ndx=0x{vs:x} ndx={vs & 0x7fff}")
                    found = True
                    break
            if not found:
                print("  pthread_mutex_lock 未在 symtab 直接命中（可能版本化，需走链）")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else r"g:\Yl\fixtures\runtime\libc.so.6"
    parse(path)