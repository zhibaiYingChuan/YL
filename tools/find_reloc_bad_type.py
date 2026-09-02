# 定位 ld.so 中 _dl_reloc_bad_type：字符串 xref → lea 引用 → 函数与调用点
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

LD = r'G:\Yl\fixtures\runtime\ld-linux-x86-64.so.2'
data = open(LD, 'rb').read()

# 搜索目标字符串
targets = [b'unexpected reloc type 0x', b'unexpected PLT reloc type 0x', b'error while loading shared libraries']
for t in targets:
    offs = []
    start = 0
    while True:
        i = data.find(t, start)
        if i < 0:
            break
        offs.append(i)
        start = i + 1
    print(f'string {t!r}: offs={[hex(o) for o in offs]}')

# PT_LOAD 段：文件偏移 -> vaddr
assert data[:4] == b'\x7fELF'
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum = struct.unpack_from('<H', data, 0x38)[0]

def off_to_vaddr(off):
    for i in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from('<IIQQQQQQ', data, e_phoff + i * e_phentsize)
        if p_type == 1 and p_offset <= off < p_offset + p_filesz:
            return p_vaddr + (off - p_offset)
    return None

str_vaddrs = {}
for t in targets:
    for off in [i for i in range(len(data)) if data.startswith(t, i)]:
        v = off_to_vaddr(off)
        if v is not None:
            str_vaddrs.setdefault(t, []).append(v)
print('str vaddrs:', {k.decode(): [hex(x) for x in v] for k, v in str_vaddrs.items()})

# 在 .text 中找 lea reg,[rip+disp32] 与 mov reg,imm64 引用这些字符串
# 解析 PT_LOAD 中可执行段（flags & 1）
exec_segs = []
for i in range(e_phnum):
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
        struct.unpack_from('<IIQQQQQQ', data, e_phoff + i * e_phentsize)
    if p_type == 1 and p_flags & 1:
        exec_segs.append((p_offset, p_vaddr, p_filesz))

all_vaddrs = set()
for vs in str_vaddrs.values():
    all_vaddrs.update(vs)

hits = []
for (p_off, p_vaddr, p_filesz) in exec_segs:
    text = data[p_off:p_off + p_filesz]
    for idx in range(len(text) - 7):
        b = text[idx]
        # lea r64,[rip+disp32]: 48 8d /r 且 modrm.mod==0, rm==101b
        if b == 0x48 and text[idx+1] == 0x8d and (text[idx+2] & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', text, idx + 3)[0]
            target = p_vaddr + idx + 7 + disp
            if target in all_vaddrs:
                hits.append((p_off + idx, target))
        # movabs r64, imm64
        if b == 0x48 and text[idx+1] in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
            imm = struct.unpack_from('<Q', text, idx + 2)[0]
            if imm in all_vaddrs:
                hits.append((p_off + idx, imm))

print('xref hits (file_off, str_vaddr):', [(hex(o), hex(v)) for o, v in hits])

# 对每个命中点反汇编 -0x40..+0x60 窗口
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
for (foff, _v) in hits:
    print(f'\n==== window around xref @ file_off=0x{foff:x} ====')
    start = max(0, foff - 0x80)
    for ins in md.disasm(data[start:foff + 0x60], off_to_vaddr(start) or start):
        mark = '  <-- XREF' if ins.address == off_to_vaddr(foff) else ''
        print(f'  0x{ins.address:x}: {ins.mnemonic:12s} {ins.op_str}{mark}')

# 在 exec 段中搜索 "call 0x10c90" / "jmp 0x10c90" 的调用点
print('\n==== call/jmp xrefs to _dl_reloc_bad_type (0x10c90) ====')
for (p_off, p_vaddr, p_filesz) in exec_segs:
    text = data[p_off:p_off + p_filesz]
    for idx in range(len(text) - 5):
        b = text[idx]
        if b == 0xE8:  # call rel32
            disp = struct.unpack_from('<i', text, idx + 1)[0]
            target = p_vaddr + idx + 5 + disp
            if target == 0x10c90:
                print(f'CALL   file_off=0x{p_off+idx:x} guest_rip=0x{0x2700000+p_off+idx:x}')
        elif b == 0xE9:  # jmp rel32
            disp = struct.unpack_from('<i', text, idx + 1)[0]
            target = p_vaddr + idx + 5 + disp
            if target == 0x10c90:
                print(f'JMP    file_off=0x{p_off+idx:x} guest_rip=0x{0x2700000+p_off+idx:x}')

# 反汇编每个调用点附近窗口
print('\n==== disasm around call sites ====')
for (p_off, p_vaddr, p_filesz) in exec_segs:
    text = data[p_off:p_off + p_filesz]
    for idx in range(len(text) - 5):
        if text[idx] == 0xE8:
            disp = struct.unpack_from('<i', text, idx + 1)[0]
            target = p_vaddr + idx + 5 + disp
            if target == 0x10c90:
                foff = p_off + idx
                print(f'\n-- call site @ file_off=0x{foff:x} --')
                for ins in md.disasm(data[foff - 0x60:foff + 0x20], off_to_vaddr(foff - 0x60)):
                    mark = '  <-- CALL' if ins.address == off_to_vaddr(foff) else ''
                    print(f'  0x{ins.address:x}: {ins.mnemonic:10s} {ins.op_str}{mark}')