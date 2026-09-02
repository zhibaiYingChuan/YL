# 最小 x86-64 反汇编器：定位 main_map 检查与断言调用
# 只解码需要的指令子集: lea rip-rel, cmp [rip+disp], test/jcc, mov, call, sub/add (栈), xor, mov imm
import struct
import sys

path = sys.argv[1]
base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x24000000
start_off = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x20da0
data = open(path, "rb").read()

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

def o2v(off):
    for vaddr, offset, filesz, memsz, flags in segments:
        if offset <= off < offset + filesz:
            return vaddr + (off - offset)
    return None

def next_rip(vaddr, insn_len):
    return vaddr + insn_len

R8 = ["al","cl","dl","bl","spl","bpl","sil","dil"]
R16= ["ax","cx","dx","bx","sp","bp","si","di"]
R32= ["eax","ecx","edx","ebx","esp","ebp","esi","edi"]
R64= ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"]
def rname(rex, field, b64):
    idx = field | (8 if rex & 1 else 0) if b64 and (rex & 1) else 0
    return R64[idx] if b64 else R32[idx]

def decode_mem(rex, m, p, bytesarr):
    # returns (text, consumed, has_rip)
    mod = (m >> 6) & 3
    rm = m & 7
    if mod == 0 and rm == 5:
        disp = struct.unpack_from("<i", bytesarr, p)[0]
        return (f"[rip+0x{disp:x}]", 4, True)
    base = rname(rex, rm, True)
    text = f"[{base}]"
    consumed = 0
    if mod == 1:
        disp = struct.unpack_from("<b", bytesarr, p)[0]
        text = f"[{base}{disp:+d}]" if disp else f"[{base}]"
        consumed = 1
    elif mod == 2:
        disp = struct.unpack_from("<i", bytesarr, p)[0]
        text = f"[{base}{disp:+x}]" if disp else f"[{base}]"
        consumed = 4
    return (text, consumed, False)

p = start_off
v = o2v(p)
print(f"== disasm at file_off=0x{p:x} vaddr=0x{v:x} (base 0x{base:x}) ==")
n = 0
end_off = min(len(data), start_off + 512)
while p < end_off and n < 80:
    rip_v = o2v(p)
    b0 = data[p]
    st = p
    if b0 == 0x48 and p + 2 < len(data):
        rex = 0x48
        op = data[p+1]
        # 48 89 /r : mov r64, r/m64 ; 48 8b /r: mov r64, r/m64
        if op in (0x89, 0x8b):
            m = data[p+2]
            mod, rm = (m>>6)&3, m&7
            reg = ((m>>3)&7) | 8
            if mod == 3:
                src = R64[rm | 8]
            else:
                txt, cons, rip = decode_mem(rex, m, p+3, data)
                src = txt
            dst = R64[reg]
            ins = "mov" + (f" {dst}, {src} = [RIPBASE+0x{int(rip_v+3+ (0 if mod==3 else (1 if mod==1 else 4)) + (p+3-st +0)):x}]" if False else "")
            ln = 3 + (0 if mod==3 else (0 if (mod==0 and rm==5) else (1 if mod==1 else 4)))
            # recompute
            ln = 2
            if mod != 3:
                ln += 0 if (mod==0 and rm==5) else (1 if mod==1 else 4)
                # rm==4 SIB not handled
            text = f"mov {dst}, {src}"
            print(f"  0x{rip_v:x}: {text}")
            p += 3 + (0 if mod==3 else (0 if (mod==0 and rm==5) else (1 if mod==1 else 4)))
            n += 1
            continue
        elif op == 0xc7:
            # mov dword ptr [..], imm32
            m = data[p+2]
            mod, rm = (m>>6)&3, m&7
            txt, cons, rip = decode_mem(rex, m, p+3, data)
            imm = struct.unpack_from("<I", data, p+3+cons)[0]
            print(f"  0x{rip_v:x}: mov DWORD PTR {txt}, 0x{imm:x}")
            p += 3 + cons + 4
            n += 1
            continue
    if b0 == 0x83:  # op /ib
        m = data[p+1]
        mod, rm = (m>>6)&3, m&7
        op = (m>>3)&7
        opr = {0:"add",5:"sub",7:"cmp"}.get(op, f"op{op}")
        if mod == 3:
            txt = R64[rm]
            ln = 2
        else:
            txt, cons, rip = decode_mem(rex if False else 0, m, p+2, data)
            ln = 2 + cons
        imm = struct.unpack_from("<b", data, p+ln)[0]
        print(f"  0x{rip_v:x}: {opr} {txt}, 0x{imm:x}" + (" (RIP-REL)" if 'rip' in txt else ""))
        p += ln + 1
        n += 1
        continue
    if b0 in (0x74,0x75,0x7c,0x7d,0x70,0x71,0x72,0x73,0x76,0x77,0x7e,0x7f,0x78,0x79,0x7a,0x7b,0x0f):
        pass
    if b0 in (0x74,0x75,0x7c,0x7d,0x70,0x71,0x72,0x73,0x76,0x77,0x7e,0x7f,0x78,0x79,0x7a,0x7b):
        disp = struct.unpack_from("<b", data, p+1)[0]
        cc = {0x74:"je",0x75:"jne",0x7c:"jl",0x7d:"jge",0x7f:"jg",0x7e:"jle",0x78:"js",0x73:"jnc",0x72:"jc"}.get(b0,f"j{hex(b0)}")
        print(f"  0x{rip_v:x}: {cc} +0x{disp:x}  (-> 0x{rip_v+2+disp:x})")
        p += 2
        n += 1
        continue
    if b0 in (0x05,0x25):  # op eax, imm32 (add/xor/sub/cmp/test eax)
        opr = {0x05:"add eax",0x25:"and eax"}.get(b0,f"op eax")
        imm = struct.unpack_from("<i", data, p+1)[0]
        print(f"  0x{rip_v:x}: ??? {opr}, 0x{imm&0xffffffff:x}")
        p += 5
        n += 1
        continue
    if b0 == 0x0f:
        op = data[p+1]
        if op in (0x84,0x85,0x8f,0x8c,0x8d,0x86,0x87,0x82,0x83,0x80,0x81,0x88,0x89,0x8a,0x8b,0x9c,0x9d,0x9e,0x9f,0x90,0x91):
            disp = struct.unpack_from("<i", data, p+2)[0]
            cc = {0x84:"je",0x85:"jne",0x8f:"jg",0x8c:"jl",0x8d:"jge",0x86:"jbe",0x87:"ja",0x82:"jb",0x83:"jae",0x80:"jo",0x81:"jno",0x88:"js",0x89:"jns",0x9c:"jl"/**/,0x9e:"jle",0x9f:"jg"}.get(op,f"jcc{hex(op)}")
            # change 0x9c->jsetc etc
            ccmap={0x84:"je",0x85:"jne",0x87:"ja",0x86:"jbe",0x82:"jb",0x83:"jae",0x8f:"jg",0x8e:"jle",0x8c:"jl",0x8d:"jge",0x80:"jo",0x81:"jno",0x88:"js",0x89:"jns",0x9c:"jsetc",0x90:"jseto",0x91:"jsetno"}
            cc = ccmap.get(op, f"jcc{op:x}")
            print(f"  0x{rip_v:x}: {cc} +0x{disp:x}  (-> 0x{rip_v+6+disp:x})")
            p += 6
            n += 1
            continue
        # setcc 0x0f 0x90-0x9f
        if 0x90 <= op <= 0x9f:
            print(f"  0x{rip_v:x}: setcc{op-0x90}")
            p += 2
            n += 1
            continue
        if op == 0xb7:  # movzx r32, r/m16
            m = data[p+2]
            mod, rm = (m>>6)&3, m&7
            reg = ((m>>3)&7) | 8
            if mod==3:
                txt=R16[rm]
            else:
                txt,cons,rip=decode_mem(0,m,p+3,data)
            print(f"  0x{rip_v:x}: movzx {R32[reg]}, {txt}")
            p += 3 + (0 if mod==3 else (1 if mod==1 else 4))
            n += 1
            continue
        p += 2
        n += 1
        continue
    if b0 == 0xe8:  # call rel32
        disp = struct.unpack_from("<i", data, p+1)[0]
        print(f"  0x{rip_v:x}: call 0x{rip_v+5+disp:x}")
        p += 5
        n += 1
        continue
    if b0 == 0xe9:
        disp = struct.unpack_from("<i", data, p+1)[0]
        print(f"  0x{rip_v:x}: jmp 0x{rip_v+5+disp:x}")
        p += 5
        n += 1
        continue
    if b0 == 0x85:  # test r/m32, r32
        m = data[p+1]
        mod, rm = (m>>6)&3, m&7
        reg=((m>>3)&7)|8
        if mod==3:
            txt=R64[rm]
        else:
            txt,cons,rip=decode_mem(0,m,p+2,data)
        print(f"  0x{rip_v:x}: test {txt}, {R64[reg]}")
        p += 2 + (0 if mod==3 else (1 if mod==1 else 4))
        n+=1
        continue
    if b0 in (0x48, 0x4c, 0x49, 0x4d, 0x41, 0x44, 0x40):
        # REX prefix - attempt continued decoding with length-1 stepping to avoid infinite loop
        print(f"  0x{rip_v:x}: REX {b0:02x} op=0x{data[p+1]:02x} (raw {data[p+1]:02x})")
        # minimal: skip second byte, print raw
        p += 2
        n += 1
        continue
    # default: print raw byte, advance 1
    print(f"  0x{rip_v:x}: db 0x{b0:02x}  ({chr(b0) if 32<=b0<127 else '.'})")
    p += 1
    n += 1

print(f"\n== done {n} instructions ==")