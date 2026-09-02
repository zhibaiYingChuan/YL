"""构造无需 macOS/远程节点的最小 x86_64 Mach-O 控制台 fixture。"""
from pathlib import Path
import struct
import sys


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def build():
    vmaddr = 0x100000000
    fileoff = 0x1000
    message = b"macho-runtime-ok\n"
    # write(1, message, len)；exit(7)，均使用 Darwin UNIX syscall 类别。
    # 使用明确的 64 位立即数，避免汇编器和宿主平台差异。
    code = bytes.fromhex(
        "48b8 0100000200000000"  # rax = 0x02000001
        "48c7c7 01000000"
        "48be 3710000001000000"  # rsi = vmaddr + dataoff (message)
        "48c7c2 11000000"
        "0f05"
        "48b8 0100000200000000"  # rax = 0x02000001 (Darwin exit)
        "48c7c7 07000000"
        "0f05"
    )
    # 修正第二个 syscall：Darwin exit 是 class|1 = 0x02000001，write 是 class|4。
    code = code.replace(bytes.fromhex("48b8 0100000200000000"), bytes.fromhex("48b8 0400000200000000"), 1)
    entryoff = fileoff
    dataoff = fileoff + len(code)
    commands_size = 72 + 24
    header = struct.pack("<8I", 0xfeedfacf, 0x01000007, 3, 2, 2, commands_size, 0, 0)
    segment = u32(0x19) + u32(72) + b"__TEXT".ljust(16, b"\0") + u64(vmaddr) + u64(0x2000) + u64(0) + u64(dataoff + len(message)) + u32(7) + u32(5) + u32(0) + u32(0)
    main = u32(0x80000028) + u32(24) + u64(entryoff) + u64(0)
    image = bytearray(header + segment + main)
    image.extend(b"\0" * (fileoff - len(image)))
    image.extend(code)
    image.extend(message)
    image.extend(b"\0" * (0x2000 - len(image) + fileoff))
    return bytes(image)


out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/macho_console_fixture")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(build())
print(f"built Mach-O fixture: {out} ({out.stat().st_size} bytes)")
