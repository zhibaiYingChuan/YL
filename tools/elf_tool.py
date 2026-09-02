# 通用 ELF 工具：按符号名查询地址 / 按地址查询符号 / 打印段列表
import struct
import sys

data = open(sys.argv[1], "rb").read()
shoff = struct.unpack_from("<Q", data, 0x28)[0]
shentsize = struct.unpack_from("<H", data, 0x3a)[0]
shnum = struct.unpack_from("<H", data, 0x3c)[0]
sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
syscalls = []  # 保存符号表

mode = sys.argv[2]
if mode == "sym":  # 查找符号
    targets = sys.argv[3:]
    for i, sh in enumerate(sections):
        if sh[1] == 2:  # SHT_SYMTAB
            symtab = sh
            strtab = sections[sh[6]]
            strings = data[strtab[4] : strtab[4] + strtab[5]]
            entsize = symtab[9]
            for off in range(symtab[4], symtab[4] + symtab[5], entsize):
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    "<IBBHQQ", data, off
                )
                if not st_name:
                    continue
                end = strings.find(b"\0", st_name)
                name = strings[st_name:end].decode(errors="replace")
                if name in targets:
                    print(f"{name} 0x{st_value:x} sz={st_size} type={st_info & 0xf}")
elif mode == "addr":  # 找包含某地址的函数
    addr = int(sys.argv[3], 16)
    for i, sh in enumerate(sections):
        if sh[1] == 2:
            symtab = sh
            strtab = sections[sh[6]]
            strings = data[strtab[4] : strtab[4] + strtab[5]]
            entsize = symtab[9]
            for off in range(symtab[4], symtab[4] + symtab[5], entsize):
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    "<IBBHQQ", data, off
                )
                if st_info & 0xF == 2 and st_value and st_value <= addr < st_value + st_size:
                    end = strings.find(b"\0", st_name) if st_name else 0
                    name = strings[st_name:end].decode(errors="replace") if st_name else ""
                    print(f"0x{addr:x} in {name} 0x{st_value:x} sz={st_size}")
                    break
elif mode == "phdr":  # 打印所有 program headers
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    print(f"e_phoff=0x{e_phoff:x} e_phentsize={e_phentsize} e_phnum={e_phnum}")
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<QQQQQQ", data, off + 8
        )
        print(
            f"  [{i}] type={p_type} flags=0x{p_flags:x} vaddr=0x{p_vaddr:x} "
            f"offset=0x{p_offset:x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x}"
        )