# 分析 ld-linux 断言字符串交叉引用与 main_map RIP-relative 访问
# 用法: python tools/analyze_main_map.py fixtures/runtime/ld-linux-x86-64.so.2 <assumed_base_hex>
import struct
import sys

path = sys.argv[1]
assumed_base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x24000000
data = open(path, "rb").read()

# 解析 PT_LOAD 段: (vaddr, offset, filesz, memsz, flags)
segments = []
e_phoff = struct.unpack_from("<Q", data, 32)[0]
e_phentsize = struct.unpack_from("<H", data, 54)[0]
e_phnum = struct.unpack_from("<H", data, 56)[0]
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_flags = struct.unpack_from("<II", data, off)
    p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off + 8)
    if p_type == 1:
        segments.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))

def v2o(addr):
    for vaddr, offset, filesz, memsz, flags in segments:
        if vaddr <= addr < vaddr + filesz:
            return offset + (addr - vaddr)
    return None

def o2v(off):
    for vaddr, offset, filesz, memsz, flags in segments:
        if offset <= off < offset + filesz:
            return vaddr + (off - offset)
    return None

def read_cstr_file(off):
    end = data.find(b"\0", off)
    if end == -1:
        end = len(data)
    return data[off:end]

e_entry = struct.unpack_from("<Q", data, 24)[0]
print(f"== ld-linux e_entry=0x{e_entry:x} ==")
print(f"== assumed_base=0x{assumed_base:x} => entry runtime=0x{assumed_base+e_entry:x} ==")

# 1) 定位断言字符串
target = b"main_map != NULL"
hits = []
i = 0
while True:
    i = data.find(target, i)
    if i == -1:
        break
    hits.append(i)
    i += 1
print(f"\n== assert string 'main_map != NULL' found at {len(hits)} file offsets ==")
assert_str_offset = None
for h in hits:
    # 打印完整断言消息
    start = data.rfind(b"\x00", 0, h) + 1
    end = data.find(b"\0", h)
    full = data[start:end]
    print(f"  file_off=0x{h:x} vaddr=0x{o2v(h):x}")
    print(f"     '{full.decode(errors='replace')}'")
    if assert_str_offset is None and b"Assertion `main_map != NULL" in full:
        assert_str_offset = h

# 2) 找 assert_fail 消息引用的 RIP-relative LEA 指令。
#    __assert_fail 的第 3 个参数(rdx)是断言表达式字符串 vaddr。
#    搜索 disp32 = str_vaddr - (next_rip)，即寻找小端位移指向该字符串。
print(f"\n== LEA/RIP-rel reference to assert string (vaddr=0x{o2v(assert_str_offset):x}) ==")
str_vaddr = o2v(assert_str_offset)
refs = []
i = 0
while True:
    start = i
    i = data.find(struct.pack("<i", 0), i)  # 遍历要选 disp32 模式，这里简化搜索常见模式
    if i == -1:
        break
    i += 1
# 改为直接搜索 4 字节小端位移，d = target_vaddr - (rip_after) among 0x8d/0x48.
str_lo = struct.pack("<I", str_vaddr & 0xffffffff)
# 反方向找: disp32 编码为小端有符号 32 位
# 我们遍历所有可能指令流成本高; 用 find 在小窗口内找 0x8d/0x8b 后跟 disp
print("  (见下方软反汇编结果，在其附近核对)")

# 3) 最小软反汇编：定位 main_map 检查/断言调用。
#    runtime.rs 中断言观测点为 rip=0x2420e30 / 0x2420e4f → 相对 base 偏移
if assumed_base:
    for probe_off in [0x20e30, 0x20e4f]:
        off = probe_off  # 假定 vaddr==offset (段0/1 offset==vaddr)
        v = o2v(off)
        print(f"\n== bytes around vaddr=0x{v:x} (file_off=0x{off:x}) ==")
        start = off - 48
        if start < 0:
            start = 0
        for k in range(start, start + 96):
            if v2o(v) is not None and start <= v2o(v) < start + 96:
                pass
        chunk = data[start:start + 128]
        print(" ".join(f"{b:02x}" for b in chunk))