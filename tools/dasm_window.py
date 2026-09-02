# 反汇编 ld.so 的模块版本检查窗口（guest 0x2715ee2-0x2715f4b → 文件 offset 0x15e00-0x16050）
# 用法: python tools/dasm_window.py [起始文件偏移hex] [长度hex]
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

LD = r'G:\Yl\fixtures\runtime\ld-linux-x86-64.so.2'
data = open(LD, 'rb').read()

start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x15d80
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x300

# ---- 解析 .dynsym /.dynstr 构建符号表 ----
e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]

def read_section(i):
    off = e_shoff + i * e_shentsize
    return struct.unpack_from('<IIQQQQIIQQ', data, off)

sections = [read_section(i) for i in range(e_shnum)]
shstr = sections[e_shstrndx]
shstr_off = shstr[4]

def sh_name(i):
    name_off = sections[i][0]
    end = data.index(b'\x00', shstr_off + name_off)
    return data[shstr_off + name_off:end].decode()

syms = {}   # st_value -> [names]   (仅 SHN_UNDEF 之外)
dynsym_i = next(i for i, s in enumerate(sections) if sh_name(i) == '.dynsym')
dynstr_i = next(i for i, s in enumerate(sections) if sh_name(i) == '.dynstr')
ds = sections[dynsym_i]
dstr = sections[dynstr_i]
ds_off, ds_size = ds[4], ds[5]
dstr_off = dstr[4]
for i in range(ds_size // 24):
    off = ds_off + i * 24
    name_off, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data[off:off+24])
    if name_off == 0 or shndx == 0:
        continue
    end = data.index(b'\x00', dstr_off + name_off)
    name = data[dstr_off + name_off:end].decode()
    syms.setdefault(value & ~0xf, []).append(name)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# 先将 PT_LOAD 段布局打印出现
print('=== PT_LOAD 布局 ===')
p_off = struct.unpack_from('<Q', data, 32)[0]
p_sz = struct.unpack_from('<H', data, 54)[0]
p_n = struct.unpack_from('<H', data, 56)[0]
for i in range(p_n):
    o = p_off + i * p_sz
    t = struct.unpack_from('<I', data, o)[0]
    po, pv, filesz, msz, align = struct.unpack_from('<QQQQQ', data, o + 8)
    if t == 1:
        print(f'  off=0x{po:x} vaddr=0x{pv:x} filesz=0x{filesz:x} memsz=0x{msz:x}')

print(f'\n=== 反汇编 文件offset 0x{start:x} .. 0x{start+length:x} ===')
p = start
while p < start + length:
    ins = data[p]
    for i in md.disasm(data[p:p+16], p):
        # 符号标注
        ann = syms.get(i.address & ~0xf)
        label = f'  <== {ann[0]}' if ann else ''
        print(f'  0x{i.address:x}: {i.mnemonic} {i.op_str}{label}')
        p = i.address + i.size
        break
    else:
        # 未解码/数据
        print(f'  0x{p:x}: .byte 0x{ins:02x}')
        p += 1