# 查找 ld.so 中所有 call/jmp 目标落在 [0x10df0, 0x10e60] 区间的指令位置（xref）
# 用法: python tools/find_xref.py <起始hex> <结束hex>
import struct, sys

LD = r'G:\Yl\fixtures\runtime\ld-linux-x86-64.so.2'
data = open(LD, 'rb').read()

lo = int(sys.argv[1], 16)
hi = int(sys.argv[2], 16)

hits = []
i = 0
while i < len(data) - 4:
    b = data[i]
    if b in (0xE8, 0xE9):  # call rel32 / jmp rel32
        rel = struct.unpack_from('<i', data, i + 1)[0]
        target = i + 5 + rel
        if lo <= target < hi:
            hits.append((i, 'call' if b == 0xE8 else 'jmp', target))
    # 也扫 0F 8x 条件跳转 rel32
    if b == 0x0F and i + 6 <= len(data) and data[i+1] in range(0x80, 0x90):
        rel = struct.unpack_from('<i', data, i + 2)[0]
        target = i + 6 + rel
        if lo <= target < hi:
            hits.append((i, 'jcc', target))
    i += 1

print(f'=== xref 到 0x{lo:x}..0x{hi:x} ===')
for off, kind, target in sorted(hits):
    print(f'  0x{off:x}: {kind} 0x{target:x}')

if not hits:
    print('  (无)')