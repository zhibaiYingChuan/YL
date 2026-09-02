"""解析静态 ELF 的 PT_LOAD 段，将 vaddr 映射到文件偏移，并 dump 指定地址范围字节。"""
import struct
import sys


def load_segments(path):
    with open(path, "rb") as f:
        data = f.read()
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        (p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack_from(
            "<QQQQQQ", data, off + 8
        )
        segs.append(
            {
                "type": p_type,
                "flags": p_flags,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
            }
        )
    return data, segs


def vaddr_to_offset(segs, vaddr):
    for s in segs:
        if s["type"] == 1 and s["vaddr"] <= vaddr < s["vaddr"] + s["filesz"]:
            return s["offset"] + (vaddr - s["vaddr"])
    return None


def main():
    path = sys.argv[1]
    start = int(sys.argv[2], 16)
    end = int(sys.argv[3], 16)
    data, segs = load_segments(path)
    for s in segs:
        print(
            f"PT_LOAD flags=0x{s['flags']:x} vaddr=0x{s['vaddr']:x} "
            f"filesz=0x{s['filesz']:x} memsz=0x{s['memsz']:x}"
        )
    ofs = vaddr_to_offset(segs, start)
    if ofs is None:
        print("起始地址不在文件范围内")
        return
    row = []
    for i in range(end - start):
        o = ofs + i
        if o < len(data):
            row.append(data[o])
        else:
            row.append(0)
    # 每 16 字节一行，两侧显示
    for i in range(0, len(row), 16):
        chunk = row[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"0x{start + i:08x}  {hexs:<47}  {chars}")


if __name__ == "__main__":
    main()