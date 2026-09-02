# 临时诊断脚本：解析 ld.so 符号表，定位给定地址所属函数/符号
import struct, sys

path = sys.argv[1]
targets = [int(x, 16) for x in sys.argv[2:]]
data = open(path, 'rb').read()
shoff = struct.unpack_from('<Q', data, 0x28)[0]
shentsize = struct.unpack_from('<H', data, 0x3a)[0]
shnum = struct.unpack_from('<H', data, 0x3c)[0]
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]

def section_name(i):
    shstr = sections[int.from_bytes(data[0x20:0x28], 'little'.encode and 'little')] if False else None
    return None

# 收集 sy表
syms = []  # (name, value, size, type)
for sh in sections:
    if sh[1] == 2:  # SHT_SYMTAB
        strtab = sections[sh[6]]
        strings = data[strtab[4]:strtab[4] + strtab[5]]
        entsize = sh[9]
        for off in range(sh[4], sh[4] + sh[5], entsize):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, off)
            end = strings.find(b'\0', st_name)
            if end == -1:
                end = len(strings)
            name = strings[st_name:end].decode(errors='replace') if st_name else ''
            if name:
                syms.append((name, st_value, st_size, st_info & 0xf))

for t in targets:
    # 找包含 t 或最接近的符号
    best = None
    for name, v, size, typ in syms:
        if v <= t < v + max(size, 1) or (best is None and v <= t):
            if best is None or v > best[1]:
                best = (name, v, size, typ)
    # 也按 function 找上限
    funcs = sorted([s for s in syms if s[3] == 2], key=lambda s: s[1])
    prev = None
    for name, v, size, typ in funcs:
        if v <= t:
            prev = (name, v, size)
        else:
            break
    print(f"target 0x{t:x}: containing_sym={best} prev_func={prev}")

# 节信息帮助
print("--- 节表 ---")
for i, sh in enumerate(sections):
    if sh[1] == 8:  # SHT_NOBITS skip
        continue
    print(f"  [{i}] type=0x{sh[1]:x} addr=0x{sh[4]:x} off=0x{sh[5]:x} size=0x{sh[6]:x}")