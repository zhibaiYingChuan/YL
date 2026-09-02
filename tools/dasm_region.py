# 反汇编 ld-linux 中特定 RIP 区域（用于定位 main_map 断言）
# 用法: python tools/dasm_region.py <elf> <base_hex> <off_hex> <len>
import struct, sys

path, base = sys.argv[1], int(sys.argv[2],16)
off = int(sys.argv[3],16)
span = int(sys.argv[4],16)
data = open(path,"rb").read()

# 段映射 vaddr->fileoff (offset==vaddr 简化，但按真实 PT_LOAD 映射)
segs=[]
p_off=struct.unpack_from("<Q",data,32)[0]; p_sz=struct.unpack_from("<H",data,54)[0]; p_n=struct.unpack_from("<H",data,56)[0]
for i in range(p_n):
    o=p_off+i*p_sz
    t,f=struct.unpack_from("<II",data,o)
    po,pv,_,ps,pm=struct.unpack_from("<QQQQQ",data,o+8)
    if t==1: segs.append((pv,po,ps,pm,f))
def v2o(a):
    for pv,po,ps,pm,f in segs:
        if pv<=a<pv+ps: return po+(a-pv)
def o2v(a):
    for pv,po,ps,pm,f in segs:
        if po<=a<po+ps: return pv+(a-po)

R8=("al","cl","dl","bl","spl","bpl","sil","dil")
R16=("ax","cx","dx","bx","sp","bp","si","di")
R32=("eax","ecx","edx","ebx","esp","ebp","esi","edi")
R64=("rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi")
J64SH={0: "jo",1:"jno",2:"jb",3:"jae",4:"je",5:"jne",6:"jbe",7:"ja",8:"js",9:"jns",0xa:"jp",0xb:"jnp",0xc:"jl",0xd:"jge",0xe:"jle",0xf:"jg"}
def reg(rex,field,cls):
    l=rex&1
    if cls==0: return R8[field|(8 if l else 0)]
    r=R16 if cls==1 else R32 if cls==2 else R64
    return r[field|(8 if l else 0)]
def mem_ofs(m,rexl,base_i):
    mod=m>>6
    if mod==0 and base_i==5: return "rip"
    return None

p=off
while p<off+span and p<len(data):
    v=o2v(p)
    b0=data[p]
    line=[]
    # REX prefixes
    rex=None
    while b0 in (0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f):
        rex=b0 if rex is None else rex
        p+=1; b0=data[p]
    rex=rex or 0
    # operand-size / address 等不做，仅常见模式
    try:
        if b0==0x90 and (p+1!=off): pass
        # 长度不会再解析在前缀后错位
    except: pass
    # decode
    sz=0
    txt=""
    skip1=False
    if b0 in (0x8d,0x8b,0x89,0xc7):  # lea/mov r/m
        m=data[p+1]
        mod,rm=(m>>6)&3,m&7
        regf=(m>>3)&7
        rexl=rex&1
        dst=reg(rex,regf,3)
        # modrm 地址
        if mod==3:
            src=R64[rm|(8 if rexl else 0)]
            extra=0
        else:
            # RIP or SIB 或 base
            if mod==0 and rm==5:
                d=struct.unpack_from("<i",data,p+2)[0]
                src=f"qword [rip+0x{d:x}]"
                eff=o2v(p+2+4)
                srcglob=f" -> data 0x{eff+base:x}" if eff and d==0 else ""
                # 解析目标全局虚址
                tvaddr = (p+6) + d  # rip_next + disp
                extra=4
            elif rm==4:
                # SIB
                sib=data[p+2]
                base_reg=sib&7
                if mod==0 and base_reg==5:
                    src="[SIB-no-base]"
                else:
                    src=f"[{R64[base_reg|(8 if (rex&1) else 0)]}]"
                extra=0
                if mod==1:
                    src+=f"{struct.unpack_from('<b',data,p+3)[0]:+d}"; extra=1
                elif mod==2:
                    src+=f"[+{struct.unpack_from('<i',data,p+3)[0]:x}]"; extra=4
            else:
                base=R64[rm|(8 if rexl else 0)]
                src=f"[{base}]"
                extra=0
                if mod==1:
                    src=f"[{base}{struct.unpack_from('<b',data,p+2)[0]:+d}]"; extra=1
                elif mod==2:
                    src=f"[{base}+{struct.unpack_from('<i',data,p+2)[0]:x}]"; extra=4
        if b0==0x8d:
            txt=f"lea {dst}, {src}"
        else:
            txt=f"mov {dst}, {src}"
        # for mov dst r/m <- we reversed reg/dst incorrectly for 89; fix:
        if b0==0x89:
            txt=f"mov {src}, {dst}"
        if b0 in (0x8d,0x8b):
            sz=2+extra
        else:
            sz=2+extra
        if b0==0xc7:
            # imm32
            imm=struct.unpack_from("<i",data,p+2+extra)[0]
            txt=f"mov DWORD PTR {src}, 0x{imm&0xffffffff:x}"
            sz=2+extra+4
        print(f"  0x{v:x}: {txt}")
        p+=sz; continue
    if b0==0x83:
        m=data[p+1]; mod,rm=(m>>6)&3,m&7
        op=(m>>3)&7
        opr={0:"add",1:"or",5:"sub",7:"cmp"}.get(op,f"op{op}")
        if mod==3:
            src=R64[rm|(8 if (rex&1) else 0)]
            extra=0
        else:
            if mod==0 and rm==5:
                d=struct.unpack_from("<i",data,p+2)[0]; src=f"[rip+0x{d:x}]"; extra=4
            elif rm==4:
                sib=data[p+2];base_reg=sib&7
                src=f"[{R64[base_reg|(8 if rex&1 else 0)]}]";extra=0
                if mod==1: extra=1;src+=f'{struct.unpack_from("<b",data,p+3)[0]:+d}'
                elif mod==2: extra=4;src+=f'+{struct.unpack_from("<i",data,p+3)[0]:x}'
            else:
                base=R64[rm|(8 if rex&1 else 0)]
                if mod==0: src=f"[{base}]";extra=0
                elif mod==1: extra=1;src=f"[{base}{struct.unpack_from('<b',data,p+2)[0]:+d}]"
                else: extra=4;src=f"[{base}+{struct.unpack_from('<i',data,p+2)[0]:x}]"
        imm=struct.unpack_from("<b",data,p+2+extra)[0]
        txt=f"{opr} {src}, 0x{imm:x}"
        if opr=="cmp" and mod==0 and rm==5: txt+="   <-- 内存比较候选"
        print(f"  0x{v:x}: {txt}")
        p+=2+extra+1; continue
    if b0 in (0x80,0x81):  # cmp/test r/m, imm
        osz=1 if b0==0x80 else 4
        m=data[p+1];mod,rm=(m>>6)&3,m&7
        op=(m>>3)&7
        opr={7:"cmp",6:"and",0:"add",4:"and",5:"sub"}.get(op,f"op{op}")
        if mod==3: extra=0;src=R64[rm|(8 if rex&1 else 0)]
        else:
            if mod==0 and rm==5: extra=4; src=f"[rip+0x{struct.unpack_from('<i',data,p+2)[0]:x}]"
            elif rm==4: sib=data[p+2];base=sib&7;extra=(1 if mod==1 else 4 if mod==2 else 0);src=f"[{R64[base|(8 if rex&1 else 0)]}+disp]"
            else: extra=(1 if mod==1 else 4 if mod==2 else 0);src=f"[{R64[rm|(8 if rex&1 else 0)]}+disp]"
        imm=struct.unpack_from("<i",data,p+2+extra)[0]
        txt=f"{opr} {src}, 0x{imm&0xffffffff:x}"
        if opr=="cmp" and mod==0 and rm==5: txt+="   <-- 内存比较候选"
        print(f"  0x{v:x}: {txt}")
        p+=2+extra+osz; continue
    if b0 in (0x74,0x75,0x7c,0x7d,0x76,0x77,0x70,0x71,0x72,0x73,0x78,0x79,0x7a,0x7b,0x7e,0x7f):
        d=struct.unpack_from("<b",data,p+1)[0]
        cc={0x74:"je",0x75:"jne",0x76:"jbe",0x77:"ja",0x7c:"jl",0x7d:"jge",0x7e:"jle",0x7f:"jg",0x70:"jo",0x71:"jno",0x72:"jb",0x73:"jae",0x78:"js",0x79:"jns",0x7a:"jp",0x7b:"jnp"}[b0]
        print(f"  0x{v:x}: {cc} 0x{v+2+d:x}")
        p+=2; continue
    if b0==0x0f and data[p+1] in range(0x80,0x90):
        d=struct.unpack_from("<i",data,p+2)[0]
        cc=J64SH[data[p+1]&0xf]
        print(f"  0x{v:x}: {cc} 0x{v+6+d:x}")
        p+=6; continue
    if b0==0xe8:
        d=struct.unpack_from("<i",data,p+1)[0]
        print(f"  0x{v:x}: call 0x{v+5+d:x}")
        p+=5; continue
    if b0==0xe9:
        d=struct.unpack_from("<i",data,p+1)[0]
        print(f"  0x{v:x}: jmp 0x{v+5+d:x}")
        p+=5; continue
    if b0==0xf7:
        # test [rip+..], -1 或 neg
        m=data[p+1];mod,rm=(m>>6)&3,m&7;op=(m>>3)&7
        if mod!=3 and mod==0 and rm==5:
            d=struct.unpack_from("<i",data,p+2)[0]
            print(f"  0x{v:x}: f7 /{op} [rip+0x{d:x}]  <-- 内存检查候选 (测试/求反)")
            p+=6; continue
        if mod==3:
            print(f"  0x{v:x}: f7 /{op} {R64[rm|(8 if rex&1 else 0)]}")
            p+=2; continue
        print(f"  0x{v:x}: f7 /{op} (其余内存寻址未展开)")
        p+=6; continue
    if b0==0x88:  # mov r/m8, r8
        m=data[p+1];mod,rm=(m>>6)&3,m&7
        print(f"  0x{v:x}: mov r/m8<-, byte  (未展开)")
        p+=2; continue
    if b0 == 0x48 or (b0&0xf0)==0x40:
        pass  # 已在顶部吃掉前缀
    # 其他: 打印首字节，步进1
    print(f"  0x{v:x}: db {b0:02x}")
    p+=1