import struct, sys

data = open(sys.argv[1], 'rb').read()
shoff = struct.unpack_from('<Q', data, 0x28)[0]
shentsize = struct.unpack_from('<H', data, 0x3a)[0]
shnum = struct.unpack_from('<H', data, 0x3c)[0]
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
for i, sh in enumerate(sections):
    if sh[1] == 2:
        symtab = sh
        strtab = sections[sh[6]]
        strings = data[strtab[4]:strtab[4] + strtab[5]]
        entsize = symtab[9]
        for off in range(symtab[4], symtab[4] + symtab[5], entsize):
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', data, off)
            end = strings.find(b'\0', st_name)
            if end == -1:
                end = len(strings)
            name = strings[st_name:end].decode(errors='replace') if st_name else ''
            if name in {'main', '_start', '__libc_start_main', 'printf', 'puts', 'exit', '_exit'} or 0x408000 <= st_value < 0x408800 or 0x4a6c00 <= st_value < 0x4a6d20:
                print(name, hex(st_value), st_size)
