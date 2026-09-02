#!/usr/bin/env python3
"""dump libc.so.6 的 GNU hash 头与 Verdef/Verneed 结构，验证 hook 写入字段的真实文件值。
用法: python tools/dump_libc_gnuhash.py"""
import struct

PATH = r"G:\Yl\fixtures\runtime\libc.so.6"
data = open(PATH, "rb").read()

# 解析 ELF 头与程序头
(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
segs = []
for i in range(e_phnum):
    (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsize)
    segs.append(dict(type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr,
                     filesz=p_filesz, memsz=p_memsz, align=p_align))

def v2o(va):
    for s in segs:
        if s["type"] == 1 and s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return s["offset"] + (va - s["vaddr"])
    return None

def o2v(off):
    for s in segs:
        if s["type"] == 1 and s["offset"] <= off < s["offset"] + s["filesz"]:
            return s["vaddr"] + (off - s["offset"])
    return None

# 解析 PT_DYNAMIC
dyn = next(s for s in segs if s["type"] == 2)
tags = {}
i = 0
while True:
    tag, val = struct.unpack_from("<qQ", data, dyn["offset"] + i * 16)
    if tag == 0:
        break
    tags[tag] = val
    i += 1

def dt(t):
    return tags.get(t)

gnu_hash_va = dt(0x6ffffef5)
versym_va = dt(0x6ffffff0)
verdef_va = dt(0x6ffffffc)
verneed_va = dt(0x6ffffffd)

print("=== GNU hash 头 (va=0x%x, 文件偏移 0x%x) ===" % (gnu_hash_va, v2o(gnu_hash_va)))
gh_off = v2o(gnu_hash_va)
nb, so, bm_nw, bm_shift = struct.unpack_from("<IIII", data, gh_off)
print("nbuckets=%d (0x%x)  symoffset=%d  bitmask_nwords=%d  bloom_shift=%d" % (nb, nb, so, bm_nw, bm_shift))
print("   => bloom 数组起始 va=0x%x (0x%x 偏移), buckets 起始 va=0x%x, chain 起始 va=0x%x" % (
    gnu_hash_va + 0x10, gh_off + 0x10,
    gnu_hash_va + 0x10 + bm_nw * 8,
    gnu_hash_va + 0x10 + bm_nw * 8 + nb * 4))
print("   => 与 hook 打印对比: bitmask(写)=0x7053d8(=0x7053c8+0x10) buckets(写)=0x705bd8 chain_zero(写)=0x706bd4")
print("   => 文件导出的 bloom_shift=%d, hook 写入 shift=14 (0xe) %s" % (
    bm_shift, "一致" if bm_shift == 14 else "【不一致!】"))
print("   => nbuckets 文件=%d, hook/glibc 写入=1023 %s" % (nb, "一致" if nb == 1023 else "【不一致!】"))

# bucket 数组首个有效值（用于对照 _dl_lookup_direct 期望的索引）
buckets_va = gnu_hash_va + 0x10 + bm_nw * 8
bo = v2o(buckets_va)
print("\n=== buckets[0..8] (va=0x%x) ===" % buckets_va)
vals = struct.unpack_from("<8I", data, bo)
print("  " + " ".join("%d" % v for v in vals))

hash_va = dt(4) if 4 in tags else 0
print("\n=== DT_HASH va=0x%x (nbuckets,nchain) ===" % hash_va)
if hash_va:
    hn, hc = struct.unpack_from("<II", data, v2o(hash_va))
    print("  nchain=%d (dynsym 条目数)" % hc)

# Verdef
print("\n=== Verdef va=0x%x 前 3 项 ===" % (verdef_va or 0))
if verdef_va:
    vo = v2o(verdef_va)
    for k in range(3):
        if vo is None or vo >= len(data) - 20:
            break
        vd_version, vd_flags, vd_ndx, vd_cnt, vd_hash, vd_aux, vd_next = struct.unpack_from("<HHHHIIi", data, vo)
        print("  #%d: version=%d flags=%d ndx=%d cnt=%d hash=0x%x aux_off=0x%x next=0x%x" %
              (k, vd_version, vd_flags, vd_ndx, vd_cnt, vd_hash, vd_aux, vd_next))
        # aux 结构: vda_name(4) vda_next(4)
        if vd_aux:
            vda_name, vda_next = struct.unpack_from("<II", data, vo + vd_aux)
            print("    aux[0]: name_off=0x%x next=0x%x" % (vda_name, vda_next))
        if vd_next == 0:
            break
        vo += vd_next

# Verneed
print("\n=== Verneed va=0x%x 前 2 项 ===" % (verneed_va or 0))
if verneed_va:
    vno = v2o(verneed_va)
    for k in range(2):
        if vno is None or vno >= len(data) - 20:
            break
        vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from("<HHIII", data, vno)
        print("  #%d: version=%d cnt=%d file_off=0x%x aux_off=0x%x next=0x%x" %
              (k, vn_version, vn_cnt, vn_file, vn_aux, vn_next))
        if vn_aux:
            vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from("<IHHII", data, vno + vn_aux)
            print("    aux[0]: hash=0x%x flags=%d other=%d name_off=0x%x next=0x%x" %
                  (vna_hash, vna_flags, vna_other, vna_name, vna_next))
        if vn_next == 0:
            break
        vno += vn_next

# 静态字符串表定位 "pthread_mutex_lock" 的 hash 与原字符串
print("\n=== 'pthread_mutex_lock' 版本字符串 ===")
idx = data.find(b"pthread_mutex_lock")
if idx >= 0:
    print("  字符串 @ file 0x%x (%r)" % (idx, data[idx:idx + 40]))
    after = data[idx+40:idx+64]
    print("  紧随其后: %r" % after)