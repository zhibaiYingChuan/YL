"""构造无需远程节点工具链的最小 Mach-O 控制台 fixture。"""
from pathlib import Path
import struct
import sys


def u32(value):
    return struct.pack("<I", value)


def u64(value):
    return struct.pack("<Q", value)


def build_x86_64():
    vmaddr = 0x100000000
    fileoff = 0x1000
    message = b"macho-runtime-ok\n"
    # write(1, message, len)；exit(7)，均使用 Darwin UNIX syscall 类别。
    code = bytes.fromhex(
        "48b8 0100000200000000"
        "48c7c7 01000000"
        "48be 3710000001000000"
        "48c7c2 11000000"
        "0f05"
        "48b8 0100000200000000"
        "48c7c7 07000000"
        "0f05"
    )
    # 修正第一个 syscall：Darwin write 是 class|4，exit 是 class|1。
    code = code.replace(
        bytes.fromhex("48b8 0100000200000000"),
        bytes.fromhex("48b8 0400000200000000"),
        1,
    )
    entryoff = fileoff
    dataoff = fileoff + len(code)
    cputype = 0x01000007
    cpusubtype = 3
    return vmaddr, fileoff, message, code, entryoff, dataoff, cputype, cpusubtype


def arm64_movz(register, immediate):
    return u32(0xD2800000 | ((immediate & 0xFFFF) << 5) | register)


def arm64_movk(register, immediate, shift):
    return u32(
        0xF2800000
        | ((immediate & 0xFFFF) << 5)
        | ((shift // 16) << 21)
        | register
    )


def arm64_adr(register, offset):
    if not -(1 << 20) <= offset < (1 << 20):
        raise ValueError("arm64 ADR 偏移超出范围")
    encoded = offset & 0x1FFFFF
    immlo = encoded & 0x3
    immhi = encoded >> 2
    return u32(0x10000000 | (immlo << 29) | (immhi << 5) | register)


def build_arm64():
    vmaddr = 0x100000000
    fileoff = 0x1000
    message = b"macho-runtime-ok\n"
    # arm64 Darwin ABI：x0/x1/x2 传 write 参数，x16 传 syscall 编号，svc #0x80 触发系统调用。
    code = b"".join(
        [
            arm64_movz(0, 1),
            arm64_adr(1, 40),
            arm64_movz(2, len(message)),
            arm64_movz(16, 4),
            arm64_movk(16, 0x200, 16),
            u32(0xD4001001),
            arm64_movz(0, 7),
            arm64_movz(16, 1),
            arm64_movk(16, 0x200, 16),
            u32(0xD4001001),
        ]
    )
    entryoff = fileoff
    dataoff = fileoff + len(code)
    cputype = 0x0100000C
    cpusubtype = 0
    return vmaddr, fileoff, message, code, entryoff, dataoff, cputype, cpusubtype


def build(architecture):
    if architecture == "x86_64":
        vmaddr, fileoff, message, code, entryoff, dataoff, cputype, cpusubtype = build_x86_64()
    elif architecture == "arm64":
        vmaddr, fileoff, message, code, entryoff, dataoff, cputype, cpusubtype = build_arm64()
    else:
        raise ValueError(f"不支持的 Mach-O 架构：{architecture}")

    commands_size = 72 + 24
    # mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    # filetype=2 (MH_EXECUTE)，ncmds=2（LC_SEGMENT_64 + LC_MAIN）
    header = struct.pack(
        "<8I", 0xFEEDFACF, cputype, cpusubtype, 2, 2, commands_size, 0, 0
    )
    segment = (
        u32(0x19)
        + u32(72)
        + b"__TEXT".ljust(16, b"\0")
        + u64(vmaddr)
        + u64(0x2000)
        + u64(0)
        + u64(dataoff + len(message))
        + u32(7)
        + u32(5)
        + u32(0)
        + u32(0)
    )
    main = u32(0x80000028) + u32(24) + u64(entryoff) + u64(0)
    image = bytearray(header + segment + main)
    image.extend(b"\0" * (fileoff - len(image)))
    image.extend(code)
    image.extend(message)
    image.extend(b"\0" * (0x2000 - len(image) + fileoff))
    return bytes(image)


out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/macho_console_fixture")
architecture = sys.argv[2] if len(sys.argv) > 2 else "x86_64"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(build(architecture))
print(f"built {architecture} Mach-O fixture: {out} ({out.stat().st_size} bytes)")
