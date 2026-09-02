# 验证 libc.so.6 文件的 .rela.dyn 表内容，与 guest 日志中的 rela 条目对比。
# 只读诊断：不改任何执行状态。
import struct

LIBC = r'G:\Yl\fixtures\runtime\libc.so.6'
data = open(LIBC, 'rb').read()

# === 解析 ELF header ===
e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
e_phnum = struct.unpack_from('<H', data, 0x38)[0]

phdrs = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from('<II', data, off)
    p_offset, p_vaddr = struct.unpack_from('<QQ', data, off + 8)
    p_filesz, p_memsz = struct.unpack_from('<QQ', data, off + 32)
    phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

def vaddr_to_offset(vaddr):
    for p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz in phdrs:
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None

# === 找 .dynamic 段（PT_DYNAMIC=2）===
dyn_phdr = next((p for p in phdrs if p[0] == 2), None)
assert dyn_phdr, 'no PT_DYNAMIC'
dyn_file_off = dyn_phdr[2]
dyn_vaddr = dyn_phdr[3]
dyn_size = dyn_phdr[5]

dyns = []
for i in range(dyn_size // 16):
    tag, val = struct.unpack_from('<qQ', data, dyn_file_off + i * 16)
    dyns.append((tag, val))
    if tag == 0:
        break

dyn = {tag: val for tag, val in dyns if tag > 0}
print('=== libc .dynamic 关键 tag ===')
for tag in (1, 7, 8, 9, 5, 6, 0x6ffffef5):
    if tag in dyn:
        print(f'  tag=0x{tag:x} val=0x{dyn[tag]:x}')

rela_off = vaddr_to_offset(dyn.get(7, 0))
rela_sz = dyn.get(8, 0)
rela_ent = dyn.get(9, 0x18)
print(f'DT_RELA vaddr=0x{dyn.get(7,0):x} file_off=0x{rela_off or 0:x} relasz=0x{rela_sz:x} relaent=0x{rela_ent:x}')

# === dump 首项与若干项 ===
def dump_entry(idx):
    off = rela_off + idx * rela_ent
    r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, off)
    return r_offset, r_info, r_addend, off

print('\n=== .rela.dyn 前 6 项（文件） ===')
for i in range(6):
    if i * rela_ent >= rela_sz:
        break
    ro, ri, ra, off = dump_entry(i)
    typ = ri & 0xffffffff
    sym = ri >> 32
    print(f'  idx={i} off=0x{off:x} r_offset=0x{ro:x} r_info=0x{ri:x} type=0x{typ:x} symndx=0x{sym:x} addend=0x{ra:x}')

# === 找 symndx=0x707 的项 ===
print('\n=== symndx=0x707 的条目 ===')
count = 0
n = rela_sz // rela_ent
for i in range(n):
    ro, ri, ra, off = dump_entry(i)
    if ri >> 32 == 0x707:
        print(f'  idx={i} r_offset=0x{ro:x} r_info=0x{ri:x} type=0x{ri&0xffffffff:x} addend=0x{ra:x}')
        count += 1
        if count >= 12:
            break
if count == 0:
    print('  （无）')

# === 找 r_offset=0x2168f8 的项 ===
print('\n=== r_offset=0x2168f8 的条目 ===')
for i in range(n):
    ro, ri, ra, off = dump_entry(i)
    if ro == 0x2168f8:
        print(f'  idx={i} (idx hex=0x{i:x} offt=0x{i*rela_ent:x}) r_info=0x{ri:x} type=0x{ri&0xffffffff:x} symndx=0x{ri>>32:x} addend=0x{ra:x}')
        break
else:
    print('  （文件中无 r_offset=0x2168f8 的条目）')

# === 检查 guest 日志 rela 条目 (0x725270+0x84b8 / 24 非整数) → 检查对应文件偏移 0x84b8 处是表内还是表外 ===
print('\n=== rela 表内 0x84b8 偏移处（rbx=0x72c2a8 相对表起点） ===')
if rela_off is not None:
    n_off = 0x84b8
    if n_off + 24 <= rela_sz:
        ro, ri, ra, off = struct.unpack_from('<QQq', data, rela_off + n_off)
        print(f'  文件内[+0x84b8]={ro:#x} {ri:#x} type=0x{ri&0xffffffff:x} symndx=0x{ri>>32:x} addend=0x{ra:x}')
    else:
        print(f'  0x84b8 超出表大小 0x{rela_sz:x}（表尾）')

# === 对照 guest 日志：0x725270 首项内容 ===
print('\n=== guest 内存 0x725270 处首项（日志 rela_content） ===')
print('  日志预期: r_offset=0x2168f0 r_info=0x8(RELATIVE) addend=0x21b580')