# 读取静态 ELF 中指定虚拟地址处的字符串（用于定位断言失败信息）
import struct
import sys

data = open(sys.argv[1], "rb").read()

# 解析 PT_LOAD 段
segments = []
e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize = struct.unpack_from("<H", data, 54)[0]
e_phnum = struct.unpack_from("<H", data, 56)[0]
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    if p_type == 1:
        p_offset, p_vaddr, _pad, p_filesz = struct.unpack_from("<QQQQ", data, off + 8)
        segments.append((p_vaddr, p_offset, p_filesz))


def read_cstr(addr):
    for vaddr, offset, filesz in segments:
        if vaddr <= addr < vaddr + filesz:
            file_off = offset + (addr - vaddr)
            end = data.find(b"\0", file_off)
            if end == -1:
                end = len(data)
            return data[file_off:end].decode(errors="replace")
    return None


for arg in sys.argv[2:]:
    addr = int(arg, 16)
    print(f"0x{addr:x}: {read_cstr(addr)!r}")