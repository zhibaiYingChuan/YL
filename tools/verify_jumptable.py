# 只读验证 ld.so 跳转表（0x2c120，39 槽 x 4B disp32），计算每个 type 的目标 handler。
import struct

LD = r'G:\Yl\fixtures\runtime\ld-linux-x86-64.so.2'
data = open(LD, 'rb').read()

TABLE_VA = 0x2c120   # lea rdi,[rip+0x1abf5] @ 0x11524 -> 表 vaddr
N = 0x26             # 槽 0..0x25（39 个）

# 表在文件中偏移 = vaddr（该段 off==vaddr）
table_off = TABLE_VA

print('=== ld.so 跳转表 @0x2c120（type -> target） ===')
targets = {}
for i in range(N):
    disp = struct.unpack_from('<i', data, table_off + i * 4)[0]
    # add rax, rdi 后跳转：目标 = 表基 + disp32
    target = (TABLE_VA + disp) & 0xffffffff
    targets[i] = target
    print(f'  type={i:2d} (0x{i:02x}) disp={disp:+8d} target=0x{target:x}')

# 检查哪些 target == 0x11ab0 / 0x11ab8 / _dl_reloc_bad_type(0x10c90)
print('\n=== 关键目标检查 ===')
for i, t in targets.items():
    if t in (0x11ab0, 0x11ab8, 0x10c90, 0x11558, 0x11ae8, 0x11ac0, 0x119b0):
        print(f'  type={i} -> 0x{t:x}  <-- 可疑')

# type=1 (R_X86_64_64) 与 type=8 (RELATIVE) 的目标
print(f'\ntype=1 target=0x{targets[1]:x}')
print(f'type=8 target=0x{targets[8]:x}')