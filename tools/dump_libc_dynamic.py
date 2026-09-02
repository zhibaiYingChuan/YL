# 只读诊断：dump libc.so.6 的 PT_DYNAMIC 全部条目，供与仿真内存 0x91ebc0 内容对比。
import struct

LIBC = r'G:\Yl\fixtures\runtime\libc.so.6'
data = open(LIBC, 'rb').read()

e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum = struct.unpack_from('<H', data, 0x38)[0]

phdrs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', data, off)
    p_offset, p_vaddr = struct.unpack_from('<QQ', data, off + 8)
    p_filesz, p_memsz = struct.unpack_from('<QQ', data, off + 32)
    p_align = struct.unpack_from('<Q', data, off + 48)[0]
    phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz, p_align))

print('=== Program Headers ===')
for i, (pt, pf, po, pv, pfs, pms, pa) in enumerate(phdrs):
    print(f'  [{i}] type={pt} flags={pf:#x} off=0x{po:x} vaddr=0x{pv:x} filesz=0x{pfs:x} memsz=0x{pms:x} align=0x{pa:x}')

dyn_phdr = next((p for p in phdrs if p[0] == 2), None)
assert dyn_phdr, 'no PT_DYNAMIC'
dyn_off, dyn_vaddr, dyn_size = dyn_phdr[2], dyn_phdr[3], dyn_phdr[5]
print(f'\n=== PT_DYNAMIC off=0x{dyn_off:x} vaddr=0x{dyn_vaddr:x} size=0x{dyn_size:x} ===')

TAG_NAMES = {
    0: 'DT_NULL', 1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT',
    4: 'DT_HASH', 5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA',
    8: 'DT_RELASZ', 9: 'DT_RELAENT', 10: 'DT_STRSZ', 11: 'DT_SYMENT',
    12: 'DT_INIT', 13: 'DT_FINI', 14: 'DT_SONAME', 15: 'DT_RPATH',
    16: 'DT_SYMBOLIC', 17: 'DT_REL', 18: 'DT_RELSZ', 19: 'DT_RELENT',
    20: 'DT_PLTREL', 21: 'DT_DEBUG', 22: 'DT_TEXTREL', 23: 'DT_JMPREL',
    24: 'DT_BIND_NOW', 25: 'DT_INIT_ARRAY', 26: 'DT_FINI_ARRAY',
    27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ', 29: 'DT_RUNPATH',
    30: 'DT_FLAGS', 32: 'DT_PREINIT_ARRAY', 33: 'DT_PREINIT_ARRAYSZ',
    0x6ffffef5: 'DT_GNU_HASH', 0x6ffffff0: 'DT_VERSYM', 0x6ffffffc: 'DT_VERDEF',
    0x6ffffffd: 'DT_VERNEED', 0x6ffffffe: 'DT_VERNEEDNUM', 0x6fffffff: 'DT_VERDEFNUM',
    0x6ffffff9: 'DT_RELACOUNT', 0x6ffffffb: 'DT_FLAGS_1',
}

count = 0
for i in range(dyn_size // 16):
    tag, val = struct.unpack_from('<qQ', data, dyn_off + i * 16)
    name = TAG_NAMES.get(tag, f'?0x{tag & 0xffffffff:x}')
    print(f'  [{i}] tag={name} (0x{tag & 0xffffffff:x}) val=0x{val:x}')
    count += 1
    if tag == 0:
        break
print(f'total entries={count}')