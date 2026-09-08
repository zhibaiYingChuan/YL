//! Linux x86_64 syscall 到宿主 Windows 的最小原生桥接。
//!
//! 处理解释器当前真实 ELF 初始化和输出路径所需的系统调用；未知调用明确报错。

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use daoti_common::DaotiError;

use super::runtime::{MemPerm, MemoryModel, MemoryRegion, RuntimeSyscallEvent, SyscallHandler};
use crate::bilateral::network::BilateralLadderNetwork;
use crate::codec::{Decoder, Encoder, SyscallCodec};

pub const SYS_WRITE: u64 = 1;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_DUP3: u64 = 292;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_STATFS: u64 = 137;
pub const SYS_FSTATFS: u64 = 138;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_STATX: u64 = 332;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_MINICORE: u64 = 27;
pub const SYS_MLOCK: u64 = 149;
pub const SYS_MUNLOCK: u64 = 150;
pub const SYS_MLOCKALL: u64 = 151;
pub const SYS_MUNLOCKALL: u64 = 152;
pub const SYS_MREMAP: u64 = 25;
pub const MREMAP_MAYMOVE: u64 = 1;
pub const MREMAP_FIXED: u64 = 2;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_GETRESUID: u64 = 118;
pub const SYS_GETRESGID: u64 = 119;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_UMASK: u64 = 95;
pub const SYS_GETPGID: u64 = 121;
pub const SYS_GETPGRP: u64 = 111;
pub const SYS_SETSID: u64 = 112;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_UNAME: u64 = 63;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_READV: u64 = 19;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_EVENTFD2: u64 = 290;
pub const SYS_TIMERFD_CREATE: u64 = 283;
pub const SYS_TIMERFD_SETTIME: u64 = 286;
pub const SYS_TIMERFD_GETTIME: u64 = 287;
pub const SYS_POLL: u64 = 7;
pub const SYS_PPOLL: u64 = 271;
pub const SYS_SELECT: u64 = 23;
pub const SYS_EPOLL_WAIT: u64 = 232;
pub const SYS_EPOLL_PWAIT: u64 = 281;
pub const SYS_EPOLL_CTL: u64 = 233;
pub const SYS_EPOLL_CREATE1: u64 = 291;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_CONNECT: u64 = 42;
pub const SYS_SENDTO: u64 = 44;
pub const SYS_SENDMSG: u64 = 46;
pub const SYS_RECVMSG: u64 = 47;
pub const SYS_RECVFROM: u64 = 45;
pub const SYS_SHUTDOWN: u64 = 48;
pub const SYS_BIND: u64 = 49;
pub const SYS_LISTEN: u64 = 50;
pub const SYS_GETSOCKNAME: u64 = 51;
pub const SYS_GETPEERNAME: u64 = 52;
pub const SYS_SOCKETPAIR: u64 = 53;
pub const SYS_SETSOCKOPT: u64 = 54;
pub const SYS_GETSOCKOPT: u64 = 55;
pub const SYS_ACCEPT4: u64 = 288;
pub const SYS_BRK: u64 = 12;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_EXIT: u64 = 60;
pub const SYS_RAISE: u64 = 117;
pub const SYS_TKILL: u64 = 200;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_FUTEX: u64 = 202;
pub const SYS_SCHED_SETAFFINITY: u64 = 203;
pub const SYS_SCHED_GETAFFINITY: u64 = 204;
const FUTEX_CMD_MASK: u64 = 0x7f;
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_GET_ROBUST_LIST: u64 = 274;
pub const SYS_RSEQ: u64 = 334;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_READLINK: u64 = 89;
pub const SYS_GETTID: u64 = 186;
pub const SYS_GETPID: u64 = 39;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_READ: u64 = 0;
pub const SYS_GETRLIMIT: u64 = 163;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_TGKILL: u64 = 234;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_MMAP: u64 = 9;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_FAILED: i64 = -1;

/// PT_TLS 布局描述（vaddr、filesz、memsz、align）。
///
/// 静态 TLS 初始化镜像内容需在重定位全部写完后从内存
/// `[addr+vaddr, addr+vaddr+filesz)` 读取（其中可能含 RELATIVE 修正后的绝对指针）。
#[derive(Debug, Default)]
struct AppliedRelocations {
    tls: Option<(u64, u64, u64, u64)>,
    curbrk: Option<u64>,
}

/// 向上对齐到 align（align 应为 2 的幂；<=1 时原样返回）。
fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

/// 对 fd-mmap 装载的 ELF 副本应用装载期重定位。
///
/// 解释执行中的 ld.so 通过 openat+mmap 装载 libc 等共享库时，本 bridge 仅复制了
/// PT_LOAD 段内容，未应用 .rela.dyn 的 RELATIVE/GLOB_DAT/JUMP_SLOT 重定位，导致
/// libc 的 GOT 槽（如 __curbrk）读取为 0。此函数在装载后立即补上这些重定位：
/// - RELATIVE(8) / IRELATIVE(37)：值 = 装载基址 + addend
/// - GLOB_DAT(6) / JUMP_SLOT(7) / TYPE64(2)：值 = 基址 + 符号 st_value + addend
/// - TPOFF64(18)：local-exec TLS 槽值 = 符号 st_value + addend - align_up(memsz, align)
///   对 sym=0 的 local TLS 槽 st_value=0（块内偏移编码在 addend，如 0x219f70 → -0x90）
/// - DTPMOD64(16)/DTPOFF64(17)：dynamic TLS 由 ld.so 运行时填充，本处跳过
///   未定义符号（st_shndx == SHN_UNDEF）跳过，交给动态链接器运行时解析。
///   返回重定位摘要，含找到的 PT_TLS 布局（vaddr/filesz/memsz/align）。
fn apply_elf_runtime_relocations(
    memory: &mut MemoryModel,
    bytes: &[u8],
    addr: u64,
) -> Result<AppliedRelocations, DaotiError> {
    const ELF64_PHENT: usize = 56;
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_TLS: u32 = 7;
    const DT_NULL: i64 = 0;
    const DT_SYMTAB: i64 = 6;
    const DT_RELA: i64 = 7;
    const DT_RELASZ: i64 = 8;
    const DT_JMPREL: i64 = 23;
    const DT_PLTRELSZ: i64 = 2;
    const SHN_UNDEF: u16 = 0;
    const R_X86_64_64: u32 = 2;
    const R_X86_64_GLOB_DAT: u32 = 6;
    const R_X86_64_JUMP_SLOT: u32 = 7;
    const R_X86_64_RELATIVE: u32 = 8;
    const R_X86_64_DTPMOD64: u32 = 16;
    const R_X86_64_DTPOFF64: u32 = 17;
    const R_X86_64_TPOFF64: u32 = 18;
    const R_X86_64_IRELATIVE: u32 = 37;

    if bytes.len() < 64 {
        return Ok(AppliedRelocations::default());
    }
    let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    if e_phnum == 0 || e_phentsize < ELF64_PHENT {
        return Ok(AppliedRelocations::default());
    }
    let ph_end = e_phoff
        .checked_add(e_phnum as u64 * e_phentsize as u64)
        .ok_or_else(|| DaotiError::Other("ELF program header 范围溢出".into()))?;
    if ph_end as usize > bytes.len() {
        return Ok(AppliedRelocations::default());
    }

    // 收集 PT_LOAD 段（vaddr 基址、memsz、文件偏移、filesz），用于 vaddr→文件偏移换算
    let mut loads: Vec<(u64, u64, u64, u64)> = Vec::new();
    let mut dynamic: Option<(u64, u64)> = None;
    // PT_TLS：静态 TLS 块的初始化镜像来源（vaddr、filesz、memsz、align）
    let mut tls: Option<(u64, u64, u64, u64)> = None;
    for i in 0..e_phnum {
        let base = e_phoff as usize + i * e_phentsize;
        let p_type = u32::from_le_bytes(bytes[base..base + 4].try_into().unwrap());
        let p_offset = u64::from_le_bytes(bytes[base + 8..base + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(bytes[base + 16..base + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(bytes[base + 32..base + 40].try_into().unwrap());
        let p_memsz = u64::from_le_bytes(bytes[base + 40..base + 48].try_into().unwrap());
        let p_align = u64::from_le_bytes(bytes[base + 48..base + 56].try_into().unwrap());
        match p_type {
            PT_LOAD => loads.push((p_vaddr, p_memsz, p_offset, p_filesz)),
            PT_DYNAMIC => dynamic = Some((p_offset, p_filesz)),
            PT_TLS => tls = Some((p_vaddr, p_filesz, p_memsz, p_align)),
            _ => {}
        }
    }
    let vaddr_to_offset = |va: u64, len: u64| -> Option<usize> {
        for &(v, m, o, f) in &loads {
            if va >= v
                && va
                    .checked_add(len)
                    .is_some_and(|end| end <= v.saturating_add(m) && (va - v) + len <= f)
            {
                return Some((o + (va - v)) as usize);
            }
        }
        None
    };

    let (dyn_off, dyn_filesz) = match dynamic {
        Some(value) => value,
        None => return Ok(AppliedRelocations::default()),
    };
    // 扫描动态段收集 DT_RELA / DT_JMPREL / DT_SYMTAB
    let mut dt_symtab: Option<u64> = None;
    let mut dt_strtab: Option<u64> = None;
    let mut dt_hash: Option<u64> = None;
    let mut dt_rela: Option<(u64, u64)> = None;
    let mut dt_jmprel: Option<(u64, u64)> = None;
    let mut off: usize = 0;
    while off + 16 <= dyn_filesz as usize {
        let tag = i64::from_le_bytes(
            bytes[dyn_off as usize + off..dyn_off as usize + off + 8]
                .try_into()
                .unwrap(),
        );
        let val = u64::from_le_bytes(
            bytes[dyn_off as usize + off + 8..dyn_off as usize + off + 16]
                .try_into()
                .unwrap(),
        );
        match tag {
            DT_NULL => break,
            DT_SYMTAB => dt_symtab = Some(val),
            4 => dt_hash = Some(val),
            5 => dt_strtab = Some(val),
            DT_RELA => dt_rela = Some((val, 0)),
            DT_RELASZ => {
                if let Some(entry) = dt_rela.as_mut() {
                    entry.1 = val;
                }
            }
            DT_JMPREL => dt_jmprel = Some((val, 0)),
            DT_PLTRELSZ => {
                if let Some(entry) = dt_jmprel.as_mut() {
                    entry.1 = val;
                }
            }
            _ => {}
        }
        off += 16;
    }

    let find_symbol_value = |wanted: &[u8]| {
        dt_hash
            .and_then(|hash| vaddr_to_offset(hash, 8))
            .and_then(|hash_off| {
                let nchain =
                    u32::from_le_bytes(bytes[hash_off + 4..hash_off + 8].try_into().ok()?) as u64;
                let symtab = dt_symtab?;
                let strtab = dt_strtab?;
                (0..nchain).find_map(|index| {
                    let sym_off = vaddr_to_offset(symtab + index * 24, 24)?;
                    let name_offset =
                        u32::from_le_bytes(bytes[sym_off..sym_off + 4].try_into().ok()?) as u64;
                    let name_off = vaddr_to_offset(strtab + name_offset, 1)?;
                    let name = bytes[name_off..]
                        .split(|byte| *byte == 0)
                        .next()
                        .unwrap_or_default();
                    if name == wanted {
                        Some(u64::from_le_bytes(
                            bytes[sym_off + 8..sym_off + 16].try_into().ok()?,
                        ))
                    } else {
                        None
                    }
                })
            })
    };
    let curbrk_symbol_value = find_symbol_value(b"__curbrk");
    let sbrk_symbol_value = find_symbol_value(b"__sbrk");
    let sbrk_ready_flag = sbrk_symbol_value.and_then(|sbrk| {
        let code =
            vaddr_to_offset(sbrk, 0x30).and_then(|offset| bytes.get(offset..offset + 0x30))?;
        for index in 0..code.len().saturating_sub(7) {
            if code[index..index + 2] == [0x80, 0x3d] && code[index + 6] == 0 {
                let displacement =
                    i32::from_le_bytes(code[index + 2..index + 6].try_into().ok()?) as i64;
                let next = sbrk + index as u64 + 7;
                return Some(next.wrapping_add_signed(displacement));
            }
        }
        None
    });
    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut curbrk_addr = None;
    let reloc_tables: [(Option<(u64, u64)>, &str); 2] = [(dt_rela, "rela"), (dt_jmprel, "jmprel")];
    for (table, label) in reloc_tables {
        let Some((base_vaddr, size)) = table else {
            continue;
        };
        let count = size / 24;
        for k in 0..count {
            let Some(entry_off) = vaddr_to_offset(base_vaddr + k * 24, 24) else {
                skipped += 1;
                continue;
            };
            let r_offset = u64::from_le_bytes(bytes[entry_off..entry_off + 8].try_into().unwrap());
            let r_info =
                u64::from_le_bytes(bytes[entry_off + 8..entry_off + 16].try_into().unwrap());
            let r_addend =
                i64::from_le_bytes(bytes[entry_off + 16..entry_off + 24].try_into().unwrap());
            let r_type = (r_info & 0xffff_ffff) as u32;
            let r_sym = (r_info >> 32) as u32;
            let target = addr.wrapping_add(r_offset);
            let value: Option<u64> = match r_type {
                R_X86_64_RELATIVE | R_X86_64_IRELATIVE => Some(addr.wrapping_add_signed(r_addend)),
                R_X86_64_TPOFF64 => {
                    // local-exec TLS 槽：值 = st_value + addend - align_up(memsz, align)。
                    // x86-64 为 TLS Variant I：TP 指向 TCB 末尾，静态 TLS 块在 TP 负方向，
                    // local TLS 变量槽 = 块内偏移 - 块大小。sym=0 时 st_value=0
                    //（fixture 槽 0x219f70：sym=0 addend=0 memsz=0x90 align=8 → -0x90）。
                    let Some((_, _, memsz, align)) = tls else {
                        skipped += 1;
                        continue;
                    };
                    let sym_value = if r_sym == 0 {
                        0
                    } else {
                        let Some(symtab) = dt_symtab else {
                            skipped += 1;
                            continue;
                        };
                        let Some(sym_off) = vaddr_to_offset(symtab + r_sym as u64 * 24, 24) else {
                            skipped += 1;
                            continue;
                        };
                        u64::from_le_bytes(bytes[sym_off + 8..sym_off + 16].try_into().unwrap())
                    };
                    Some(
                        sym_value
                            .wrapping_add_signed(r_addend)
                            .wrapping_sub(align_up(memsz, align)),
                    )
                }
                R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_64 => {
                    let Some(symtab) = dt_symtab else {
                        skipped += 1;
                        continue;
                    };
                    let Some(sym_off) = vaddr_to_offset(symtab + r_sym as u64 * 24, 24) else {
                        skipped += 1;
                        continue;
                    };
                    let st_name =
                        u32::from_le_bytes(bytes[sym_off..sym_off + 4].try_into().unwrap()) as u64;
                    let st_shndx =
                        u16::from_le_bytes(bytes[sym_off + 6..sym_off + 8].try_into().unwrap());
                    let st_value =
                        u64::from_le_bytes(bytes[sym_off + 8..sym_off + 16].try_into().unwrap());
                    if st_shndx == SHN_UNDEF {
                        let is_curbrk = dt_strtab
                            .and_then(|strtab| vaddr_to_offset(strtab + st_name, 1))
                            .is_some_and(|name_off| {
                                bytes[name_off..]
                                    .split(|byte| *byte == 0)
                                    .next()
                                    .is_some_and(|value| value == b"__curbrk")
                            });
                        if is_curbrk {
                            let Some(curbrk_offset) = curbrk_symbol_value else {
                                skipped += 1;
                                continue;
                            };
                            Some(addr.wrapping_add(curbrk_offset))
                        } else {
                            skipped += 1;
                            continue;
                        }
                    } else {
                        Some(addr.wrapping_add(st_value).wrapping_add_signed(r_addend))
                    }
                }
                R_X86_64_DTPMOD64 | R_X86_64_DTPOFF64 => {
                    // dynamic TLS 由 ld.so 运行时填充（__tls_get_addr 路径），此处跳过。
                    skipped += 1;
                    continue;
                }
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            if let Some(value) = value {
                let bytes_value = value.to_le_bytes();
                if memory.write(target, &bytes_value).is_err() {
                    skipped += 1;
                    continue;
                }
                applied += 1;
                if r_type == R_X86_64_GLOB_DAT && value != 0 {
                    let Some(curbrk_offset) = curbrk_symbol_value else {
                        continue;
                    };
                    if value == addr.wrapping_add(curbrk_offset) {
                        curbrk_addr = Some(value);
                    }
                }
                if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                    eprintln!(
                        "TRACE runtime-reloc bias=0x{addr:x} table={label} offset=0x{r_offset:x} target=0x{target:x} type={r_type} sym={r_sym} value=0x{value:x}"
                    );
                }
            }
        }
    }
    if let Some(curbrk) = curbrk_addr {
        // glibc __sbrk 的快速路径用该字节表示 __curbrk 已可由 brk 更新。
        // fd-mmap 副本没有真实 ld.so 的早期初始化副作用，需在 GOT 就绪后补齐。
        if let Some(flag_offset) = sbrk_ready_flag {
            let flag_addr = addr + flag_offset;
            memory.write(flag_addr, &[1])?;
            if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                eprintln!(
                    "TRACE runtime-reloc curbrk=0x{curbrk:x} curbrk-ready flag=0x{flag_addr:x}"
                );
            }
        }
    }
    if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
        eprintln!("TRACE runtime-reloc done bias=0x{addr:x} applied={applied} skipped={skipped}");
    }
    Ok(AppliedRelocations {
        tls,
        curbrk: curbrk_addr,
    })
}

pub trait OutputSink: Send {
    fn write_all(&mut self, data: &[u8]) -> Result<(), DaotiError>;
}

pub struct StdoutSink;

/// 将解释器 stdout 捕获到内存，供跨平台执行结果统一返回。
#[derive(Clone, Default)]
pub struct BufferSink(pub std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl BufferSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.lock().map(|data| data.clone()).unwrap_or_default()
    }
}

impl OutputSink for BufferSink {
    fn write_all(&mut self, data: &[u8]) -> Result<(), DaotiError> {
        self.0
            .lock()
            .map_err(|_| DaotiError::Other("stdout 缓冲区锁已损坏".into()))?
            .extend_from_slice(data);
        Ok(())
    }
}

impl OutputSink for StdoutSink {
    fn write_all(&mut self, data: &[u8]) -> Result<(), DaotiError> {
        io::stdout().write_all(data).map_err(DaotiError::Io)
    }
}

pub type RuntimeSyscallObserver =
    Box<dyn FnMut(&RuntimeSyscallEvent, &Result<i64, DaotiError>) + Send>;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ShadowInferenceRecord {
    pub nr: u64,
    pub name: String,
    pub prediction: Option<String>,
    pub confidence: Option<f64>,
    #[serde(default)]
    pub actual_result: Option<i64>,
    #[serde(default)]
    pub actual_success: bool,
    #[serde(default)]
    pub actual_error: Option<String>,
    #[serde(default)]
    pub actual_windows_op: Option<String>,
    pub error: Option<String>,
}

fn actual_windows_operation(event: &RuntimeSyscallEvent) -> Option<String> {
    Some(
        match event.nr {
            SYS_OPENAT => "CreateFileW",
            SYS_CLOSE => "CloseHandle",
            SYS_READ => "ReadFile",
            SYS_WRITE | SYS_WRITEV => "WriteFile",
            SYS_FSTAT | SYS_NEWFSTATAT => "GetFileInformationByHandle",
            SYS_MMAP => "VirtualAlloc",
            SYS_MPROTECT => "VirtualProtect",
            SYS_MADVISE => "VirtualQuery",
            SYS_BRK => "VirtualAlloc",
            SYS_GETPID => "GetCurrentProcessId",
            SYS_GETTID => "GetCurrentThreadId",
            SYS_CLOCK_GETTIME => "GetSystemTimeAsFileTime",
            SYS_EXIT | SYS_EXIT_GROUP => "ExitProcess",
            _ => return None,
        }
        .to_string(),
    )
}

/// 构造只读影子推理观测器；推理结果仅写入记录，不参与 syscall 返回值。
pub fn shadow_inference_observer(
    network: BilateralLadderNetwork,
    codec: SyscallCodec,
    records: std::sync::Arc<std::sync::Mutex<Vec<ShadowInferenceRecord>>>,
) -> RuntimeSyscallObserver {
    Box::new(move |runtime_event, actual_result| {
        let result = runtime_event.to_syscall_event(0).and_then(|event| {
            let vector = codec.encode(&event)?;
            let output = network.forward(vector)?;
            let outcome = codec.decode(&output)?;
            Ok((outcome.windows_op, outcome.confidence))
        });
        let (actual_result, actual_success, actual_error) = match actual_result {
            Ok(value) => (Some(*value), true, None),
            Err(error) => (None, false, Some(error.to_string())),
        };
        let actual_windows_op = actual_windows_operation(runtime_event);
        let record = match result {
            Ok((prediction, confidence)) => ShadowInferenceRecord {
                nr: runtime_event.nr,
                name: runtime_event.name.to_string(),
                prediction: Some(prediction),
                confidence: Some(confidence),
                actual_result,
                actual_success,
                actual_error,
                actual_windows_op: actual_windows_op.clone(),
                error: None,
            },
            Err(error) => ShadowInferenceRecord {
                nr: runtime_event.nr,
                name: runtime_event.name.to_string(),
                prediction: None,
                confidence: None,
                actual_result,
                actual_success,
                actual_error,
                actual_windows_op,
                error: Some(error.to_string()),
            },
        };
        if let Ok(mut records) = records.lock() {
            records.push(record);
        }
    })
}

type PipeBuffer = std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>;
type PipeHandle = (PipeBuffer, bool);
type EpollRegistration = (i32, u32, u64);

/// socket 状态：family/type/protocol、双向缓冲（socketpair 才连接）、方向关闭位与选项表。
/// 与 pipe2 相同，socket fd 独立于文件 fd 编号空间维护。
#[derive(Clone)]
struct SocketState {
    family: u32,
    sock_type: u32,
    /// 接收缓冲：我方读取，对端写入。
    rx: Option<PipeBuffer>,
    /// 发送缓冲：我方写入，对端读取。
    tx: Option<PipeBuffer>,
    /// shutdown 位：bit0=SHUT_RD 关闭，bit1=SHUT_WR 关闭。
    shutdown: u8,
    /// 选项表：key=(level, optname) → 原始值字节。
    options: HashMap<(u32, u32), Vec<u8>>,
    /// bind 设置的本地端口（网络字节序大端），None = 未绑定。
    bound_port: Option<u16>,
    /// listen 是否已进入监听状态。
    listening: bool,
    /// 待 accept 的连接队列：每项为 (client_to_server, server_to_client) 双向缓冲。
    pending: std::collections::VecDeque<(PipeBuffer, PipeBuffer)>,
}

pub struct NativeSyscallBridge<S: OutputSink> {
    sink: S,
    observer: Option<RuntimeSyscallObserver>,
    exit_code: Option<i32>,
    fs_base: Option<u64>,
    heap_start: u64,
    current_brk: u64,
    heap_end: u64,
    tls_locale: Option<u64>,
    clear_child_tid: Option<u64>,
    pointer_guard: u64,
    stack_guard: u64,
    allowed_roots: Vec<PathBuf>,
    current_dir: PathBuf,
    /// 进程 umask（SYS_UMASK 维护），初始 022，符合 Unix 常规默认。
    umask: u32,
    files: HashMap<i32, (Vec<u8>, usize)>,
    /// 管道缓冲：pipe2 分配两个 fd 指向同一共享缓冲（读端消费、写端追加）。
    /// Linux dirfd 与文件 fd 共用编号空间，这里用单独表避免改动现有文件语义。
    pipes: HashMap<i32, PipeHandle>,
    /// eventfd2 计数器：读返回计数并清零，写累加。
    eventfds: HashMap<i32, u64>,
    /// timerfd：CLOCK_MONOTONIC 下记录本次到期时刻（纳秒单调时钟）；None 表示未 arm。
    timerfds: HashMap<i32, Option<u64>>,
    epolls: HashMap<i32, Vec<EpollRegistration>>,
    /// socket 描述符表：socket()/socketpair() 分配，sendto/recvfrom/shutdown 操作。
    sockets: HashMap<i32, SocketState>,
    /// 目录句柄：每个条目保存宿主目录路径与下一个待返回子项序号。
    /// Linux 的 dirfd 与文件 fd 共用编号空间，这里用单独表避免改动现有文件语义。
    dirs: HashMap<i32, (PathBuf, usize)>,
    next_fd: i32,
    /// 主程序 PT_LOAD 已映射区间 [(start,end)…]，用于关联 mmap 返回值。
    main_ptload_ranges: Vec<(u64, u64)>,
    /// 最近一次 fd-mmap 装载 ELF 的静态 TLS 初始化镜像（如 libc 的 PT_TLS）。
    /// ARCH_SET_FS 设置 fs 时复制到 fs - align_up(memsz, align)，建立 TP 负方向静态 TLS 块。
    elf_tls: Option<ElfTlsImage>,
}

/// PT_TLS 初始化镜像：重定位后的 image 内容、memsz、align。
struct ElfTlsImage {
    image: Vec<u8>,
    memsz: u64,
    align: u64,
}

fn relocate_tls_image_internal_pointers(
    image: &mut [u8],
    load_bias: u64,
    load_ranges: &[(u64, u64)],
) {
    for chunk in image.as_chunks_mut::<8>().0 {
        let value = u64::from_le_bytes(*chunk);
        if load_ranges
            .iter()
            .any(|(start, end)| value >= *start && value < *end)
        {
            chunk.copy_from_slice(&value.wrapping_add(load_bias).to_le_bytes());
        }
    }
}

impl<S: OutputSink> NativeSyscallBridge<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            observer: None,
            exit_code: None,
            fs_base: None,
            heap_start: 0,
            current_brk: 0,
            heap_end: 0,
            tls_locale: None,
            clear_child_tid: None,
            pointer_guard: 0,
            stack_guard: 0,
            allowed_roots: Vec::new(),
            current_dir: PathBuf::new(),
            umask: 0o22,
            files: HashMap::new(),
            pipes: HashMap::new(),
            eventfds: HashMap::new(),
            timerfds: HashMap::new(),
            epolls: HashMap::new(),
            sockets: HashMap::new(),
            dirs: HashMap::new(),
            next_fd: 3,
            main_ptload_ranges: Vec::new(),
            elf_tls: None,
        }
    }

    /// 设置只读 syscall 观测器；观测器失败不会影响 syscall 执行，因为回调不返回错误。
    pub fn with_observer(mut self, observer: RuntimeSyscallObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// 设置主程序 PT_LOAD 已映射区间，用于 trace 关联 mmap 返回值。
    pub fn with_main_ptload(mut self, ranges: Vec<(u64, u64)>) -> Self {
        self.main_ptload_ranges = ranges;
        self
    }

    /// 设置初始堆边界（brk 起始地址和堆区域结尾）。
    pub fn with_allowed_roots(mut self, roots: &[PathBuf]) -> Self {
        self.allowed_roots = roots
            .iter()
            .map(|root| super::normalize_path(root))
            .collect();
        self
    }

    pub fn with_brk(mut self, brk: u64, heap_end: u64) -> Self {
        self.heap_start = brk;
        self.current_brk = brk;
        self.heap_end = heap_end;
        self
    }

    fn resolve_guest_path(&self, path: &Path) -> Option<PathBuf> {
        // 相对路径基于当前目录（guest / 语义）解析，绝对路径以根开始。
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else if self.current_dir.as_os_str().is_empty() {
            PathBuf::from("/").join(path)
        } else {
            self.current_dir.join(path)
        };
        let relative = joined.strip_prefix("/").unwrap_or(&joined);
        self.allowed_roots
            .iter()
            .flat_map(|root| {
                let exact = root.join(relative);
                let basename = path.file_name().map(|name| root.join(name));
                basename.into_iter().chain(std::iter::once(exact))
            })
            .find(|candidate| candidate.is_file())
    }

    /// 返回 guest 视角绝对路径下、受控根内的候选宿主路径列表（不校验存在性）。
    fn resolve_sandbox_candidates(&self, path: &Path) -> Vec<PathBuf> {
        let joined = if path.is_absolute() {
            path.to_path_buf()
        } else if self.current_dir.as_os_str().is_empty() {
            PathBuf::from("/").join(path)
        } else {
            self.current_dir.join(path)
        };
        let relative = joined.strip_prefix("/").unwrap_or(&joined);
        self.allowed_roots
            .iter()
            .map(|root| root.join(relative))
            .collect()
    }

    /// 归一化 guest 绝对路径（解析 . 与 ..），用于 getcwd/chdir 维护当前目录。
    fn normalize_guest_absolute(path: &Path) -> PathBuf {
        let mut normalized = PathBuf::from("/");
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                std::path::Component::Normal(seg) => normalized.push(seg),
                _ => {}
            }
        }
        normalized
    }

    /// 设置 TLS locale 地址和 pointer/stack guard 值。
    pub fn with_tls_guards(
        mut self,
        locale: Option<u64>,
        pointer_guard: u64,
        stack_guard: u64,
    ) -> Self {
        self.tls_locale = locale;
        self.pointer_guard = pointer_guard;
        self.stack_guard = stack_guard;
        self
    }
}

impl<S: OutputSink> SyscallHandler for NativeSyscallBridge<S> {
    fn capture_stdout(&mut self, memory: &mut MemoryModel, stdout: u64) -> Result<(), DaotiError> {
        let fields = memory.read(stdout + 0x20, 16)?;
        let write_base = u64::from_le_bytes(fields[..8].try_into().unwrap());
        let write_ptr = u64::from_le_bytes(fields[8..].try_into().unwrap());
        if write_ptr > write_base {
            let length = write_ptr
                .checked_sub(write_base)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| DaotiError::Other("stdout 缓冲区长度溢出".into()))?;
            let data = memory.read(write_base, length as u64)?.to_vec();
            self.sink.write_all(&data)?;
        }
        Ok(())
    }

    fn handle(&mut self, event: &RuntimeSyscallEvent) -> Result<i64, DaotiError> {
        let result = match event.nr {
            SYS_EXIT | SYS_EXIT_GROUP => {
                self.exit_code = Some(event.args[0] as i32);
                Ok(0)
            }
            SYS_RAISE | SYS_TKILL | SYS_TGKILL => {
                let signal = match event.nr {
                    SYS_RAISE => event.args[0],
                    SYS_TKILL => event.args[1],
                    SYS_TGKILL => event.args[2],
                    _ => unreachable!(),
                };
                self.exit_code = Some(128 + signal as i32);
                Ok(0)
            }
            SYS_MPROTECT | SYS_MADVISE => Ok(0),
            SYS_ACCESS => Ok(-2),
            SYS_IOCTL => {
                // 管道捕获的 stdout 不是终端，TCGETS 应返回 ENOTTY，glibc 才会选择文件缓冲策略。
                if event.args[1] == 0x5401 {
                    Ok(-25)
                } else {
                    Ok(0)
                }
            }
            SYS_FUTEX => {
                let operation = event.args[1] & FUTEX_CMD_MASK;
                match operation {
                    FUTEX_WAIT => Ok(-11),
                    FUTEX_WAKE => Ok(0),
                    _ => Err(DaotiError::Unavailable(format!(
                        "未支持的 futex 操作：{}",
                        operation
                    ))),
                }
            }
            SYS_CLOCK_GETTIME | SYS_SCHED_SETAFFINITY | SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK => {
                Ok(0)
            }
            SYS_SCHED_GETAFFINITY => Ok(1),
            SYS_SET_TID_ADDRESS => {
                self.clear_child_tid = Some(event.args[0]);
                Ok(1)
            }
            SYS_SET_ROBUST_LIST | SYS_GET_ROBUST_LIST => Ok(0),
            SYS_RSEQ => Ok(-38),
            SYS_PRLIMIT64 => Ok(0),
            SYS_READLINK => Ok(-2),
            SYS_GETTID | SYS_GETPID => Ok(1),
            SYS_ARCH_PRCTL => {
                if event.args[0] == ARCH_SET_FS {
                    self.fs_base = Some(event.args[1]);
                    Ok(0)
                } else if event.args[0] == ARCH_GET_FS {
                    Err(DaotiError::Unavailable(
                        "arch_prctl GET_FS 需要内存上下文".into(),
                    ))
                } else {
                    Err(DaotiError::Unavailable(format!(
                        "未支持的 arch_prctl 操作：{}",
                        event.args[0]
                    )))
                }
            }
            _ => Err(DaotiError::Unavailable(format!(
                "未支持的 Linux syscall：{}",
                event.nr
            ))),
        };
        if let Some(observer) = self.observer.as_mut() {
            observer(event, &result);
        }
        result
    }

    fn handle_with_memory(
        &mut self,
        event: &RuntimeSyscallEvent,
        memory: &mut MemoryModel,
    ) -> Result<i64, DaotiError> {
        let result = self.handle_with_memory_inner(event, memory);
        if let Some(observer) = self.observer.as_mut() {
            observer(event, &result);
        }
        result
    }

    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    fn fs_base(&self) -> Option<u64> {
        self.fs_base
    }
}

/// 判断 [addr, addr+len) 与任意 region 有交集（部分映射）。
fn memory_range_partially_mapped(memory: &MemoryModel, addr: u64, len: u64) -> bool {
    let end = addr.saturating_add(len);
    memory
        .regions
        .iter()
        .any(|region| addr < region.base + region.bytes.len() as u64 && region.base < end)
}

/// 判断 [addr, addr+len) 是否被 region 完整覆盖（无空洞）。
fn memory_range_fully_mapped(memory: &MemoryModel, addr: u64, len: u64) -> bool {
    let end = addr.saturating_add(len);
    let covered: u64 = memory
        .regions
        .iter()
        .filter(|region| region.base < end && addr < region.base + region.bytes.len() as u64)
        .map(|region| {
            let start = addr.max(region.base);
            let finish = end.min(region.base + region.bytes.len() as u64);
            finish - start
        })
        .sum();
    covered >= len
}

/// Linux munmap/msync 等内存管理调用的宿主地址必须页对齐。
fn is_page_aligned(value: u64) -> bool {
    value.is_multiple_of(4096)
}

impl<S: OutputSink> NativeSyscallBridge<S> {
    fn handle_with_memory_inner(
        &mut self,
        event: &RuntimeSyscallEvent,
        memory: &mut MemoryModel,
    ) -> Result<i64, DaotiError> {
        if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some()
            && matches!(event.nr, SYS_OPENAT | SYS_MMAP | SYS_BRK)
        {
            eprintln!(
                "TRACE runtime syscall={} nr={} args={:x?} brk=0x{:x}/0x{:x}",
                event.name, event.nr, event.args, self.current_brk, self.heap_end
            );
        }
        if event.nr == SYS_ACCESS || event.nr == SYS_FACCESSAT {
            if event.nr == SYS_FACCESSAT {
                // faccessat(dirfd, pathname, mode, flags)：仅支持 AT_FDCWD(-100)
                // 与其他 at 系列一致；flags 仅接受 0，未知 dirfd 返回 -EBADF。
                let dirfd = event.args[0] as i64;
                if dirfd != -100 {
                    return Ok(-9); // -EBADF
                }
                if event.args[3] != 0 {
                    return Ok(-22); // -EINVAL（不支持 AT_EACCESS 等标志）
                }
            }
            let path_ptr = if event.nr == SYS_FACCESSAT {
                event.args[1]
            } else {
                event.args[0]
            };
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(path_ptr + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("access 路径不是 UTF-8".into()))?,
            );
            let Some(candidate) = self.resolve_guest_path(path) else {
                return Ok(-2);
            };
            let mode = if event.nr == SYS_FACCESSAT {
                event.args[2]
            } else {
                event.args[1]
            };
            if mode & 4 != 0 && std::fs::metadata(&candidate).is_err() {
                return Ok(-13);
            }
            if mode & 2 != 0 || mode & 1 != 0 {
                return Ok(-13);
            }
            return Ok(0);
        }
        if event.nr == SYS_OPENAT {
            let dirfd = event.args[0] as i32;
            if dirfd != -100 {
                return Err(DaotiError::Unavailable("openat 仅支持 AT_FDCWD".into()));
            }
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(event.args[1] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("openat 路径不是 UTF-8".into()))?,
            );
            // O_DIRECTORY=0x10000：显式目录打开；否则路径存在时按宿主类型路由。
            let want_dir = event.args[2] & 0x10000 != 0;
            // 优先按文件解析（含 basename 回退，支持 glibc 用绝对路径打开受控根内文件）；
            // 文件解析不中时回落到沙盒候选（目录或尚不存在的路径按目录路由）。
            let candidate = self.resolve_guest_path(path).or_else(|| {
                self.resolve_sandbox_candidates(path)
                    .into_iter()
                    .find(|candidate| candidate.exists())
            });
            let Some(candidate) = candidate else {
                return Ok(-2); // -ENOENT
            };
            if candidate.is_dir() || want_dir {
                if !candidate.is_dir() {
                    return Ok(-20); // -ENOTDIR
                }
                let fd = self.next_fd;
                self.next_fd += 1;
                self.dirs.insert(fd, (candidate, 0));
                return Ok(fd as i64);
            }
            let bytes = std::fs::read(&candidate).map_err(DaotiError::Io)?;
            let fd = self.next_fd;
            self.next_fd += 1;
            self.files.insert(fd, (bytes, 0));
            if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                eprintln!(
                    "TRACE runtime openat-return fd={} path={} ptload_ranges={:x?}",
                    fd,
                    candidate.display(),
                    self.main_ptload_ranges
                );
            }
            return Ok(fd as i64);
        }
        if event.nr == SYS_CLOSE {
            // 关闭 fd：文件内容已被受控桥接器载入内存（mmap 复制语义），
            // 但仍需校验 fd 真实存在（stdin/stdout/stderr 0..2 恒有效），
            // 未知 fd 返回 -EBADF，与 Linux 语义一致。
            let fd = event.args[0] as i32;
            if self.files.contains_key(&fd)
                || self.dirs.contains_key(&fd)
                || self.pipes.contains_key(&fd)
                || self.eventfds.contains_key(&fd)
                || self.timerfds.contains_key(&fd)
                || self.sockets.contains_key(&fd)
                || fd < 3
            {
                return Ok(0);
            }
            return Ok(-9); // -EBADF
        }
        if event.nr == SYS_LSEEK {
            // lseek(fd, offset, whence)：仅维护已打开的文件快照偏移，
            // whence 支持 SEEK_SET=0 / SEEK_CUR=1 / SEEK_END=2，其余报 -EINVAL。
            let fd = event.args[0] as i32;
            let offset = event.args[1] as i64;
            let whence = event.args[2];
            let (bytes, cursor) = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| DaotiError::Other("无效文件描述符".into()))?;
            let base = match whence {
                0 => 0i64,
                1 => *cursor as i64,
                2 => bytes.len() as i64,
                _ => return Ok(-22), // -EINVAL
            };
            let target = base
                .checked_add(offset)
                .ok_or_else(|| DaotiError::Other("lseek 偏移溢出".into()))?;
            if target < 0 {
                return Ok(-22); // -EINVAL：负偏移不可用
            }
            *cursor = target as usize;
            return Ok(target);
        }
        if event.nr == SYS_FCNTL {
            // fcntl(fd, cmd, arg)：只实现该仿真环境需要的最小命令集合，
            // 未知命令明确返回 -EINVAL，不伪装成功。
            let fd = event.args[0] as i32;
            if !self.files.contains_key(&fd) {
                return Ok(-9); // -EBADF
            }
            let cmd = event.args[1];
            match cmd {
                // F_GETFD=1：返回 close-on-exec 位（0 = 未设置）
                1 => return Ok(0),
                // F_GETFL=3：返回文件状态标志（O_RDONLY=0）
                3 => return Ok(0),
                // F_SETFD=2 / F_SETFL=4：接受但不额外维护状态位（快照天生只读）
                2 | 4 => return Ok(0),
                // F_GETLK=5：不应答锁，返回 -EINVAL
                _ => return Ok(-22),
            }
        }
        if event.nr == SYS_DUP || event.nr == SYS_DUP2 || event.nr == SYS_DUP3 {
            // dup(fd) / dup2(oldfd, newfd) / dup3(oldfd, newfd, flags)：
            // 复制 fd 引用。pipes/sockets 经 Arc 共享同一缓冲区（真实语义）；
            // files/eventfds/timerfds/dirs 复制快照值。dup2/dup3 先关闭目标 fd
            // （若已存在），flow 与 Linux 一致。
            let old_fd = event.args[0] as i32;
            let requested_new = if event.nr == SYS_DUP {
                None
            } else {
                Some(event.args[1] as i32)
            };
            if event.nr == SYS_DUP3 {
                // flags 仅接受 0 或 O_CLOEXEC(0x80000)
                if event.args[2] & !0x80000 != 0 {
                    return Ok(-22); // -EINVAL
                }
            }
            if let Some(new_fd) = requested_new {
                // dup2 语义：old==new 时直接返回，不关闭。
                if new_fd == old_fd {
                    if event.nr == SYS_DUP3 && event.args[2] == 0 {
                        return Ok(-22);
                    }
                    return Ok(new_fd as i64);
                }
            }
            // 源 fd 必须存在（stdin/stdout/stderr 恒有效）。
            let source_exists = old_fd < 3
                || self.files.contains_key(&old_fd)
                || self.dirs.contains_key(&old_fd)
                || self.pipes.contains_key(&old_fd)
                || self.eventfds.contains_key(&old_fd)
                || self.timerfds.contains_key(&old_fd)
                || self.sockets.contains_key(&old_fd);
            if !source_exists {
                return Ok(-9); // -EBADF
            }
            let clone_into = |new_fd: i32, bridge: &mut Self| {
                if let Some(entry) = bridge.files.get(&old_fd) {
                    bridge.files.insert(new_fd, entry.clone());
                } else if let Some(entry) = bridge.dirs.get(&old_fd) {
                    bridge.dirs.insert(new_fd, entry.clone());
                } else if let Some(entry) = bridge.pipes.get(&old_fd) {
                    bridge.pipes.insert(new_fd, entry.clone());
                } else if let Some(entry) = bridge.eventfds.get(&old_fd) {
                    bridge.eventfds.insert(new_fd, *entry);
                } else if let Some(entry) = bridge.timerfds.get(&old_fd) {
                    bridge.timerfds.insert(new_fd, *entry);
                } else if let Some(entry) = bridge.sockets.get(&old_fd) {
                    bridge.sockets.insert(new_fd, entry.clone());
                }
            };
            let new_fd = match requested_new {
                Some(new_fd) => {
                    // 关闭目标 fd（若已存在），从所有后端移除。
                    if self.files.contains_key(&new_fd) {
                        self.files.remove(&new_fd);
                    }
                    if self.dirs.contains_key(&new_fd) {
                        self.dirs.remove(&new_fd);
                    }
                    if self.pipes.contains_key(&new_fd) {
                        self.pipes.remove(&new_fd);
                    }
                    if self.eventfds.contains_key(&new_fd) {
                        self.eventfds.remove(&new_fd);
                    }
                    if self.timerfds.contains_key(&new_fd) {
                        self.timerfds.remove(&new_fd);
                    }
                    if self.sockets.contains_key(&new_fd) {
                        self.sockets.remove(&new_fd);
                    }
                    clone_into(new_fd, self);
                    new_fd
                }
                None => {
                    let new_fd = self.next_fd;
                    self.next_fd += 1;
                    clone_into(new_fd, self);
                    new_fd
                }
            };
            return Ok(new_fd as i64);
        }
        if event.nr == SYS_STATFS || event.nr == SYS_FSTATFS {
            // statfs(path, &buf) / fstatfs(fd, &buf)：填充 Linux x86_64
            // struct statfs 前 4 个成员，保证 libc 读取类型与块大小可用。
            let buf_addr = event.args[1];
            let mut statfs = [0u8; 96];
            // f_type=0x794c7630 (daoti)、f_bsize=4096、f_blocks/f_bfree/f_bavail 足够包容。
            statfs[0..8].copy_from_slice(&0x794c7630u64.to_le_bytes());
            statfs[8..16].copy_from_slice(&4096u64.to_le_bytes());
            statfs[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
            statfs[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
            statfs[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
            memory.write(buf_addr, &statfs)?;
            return Ok(0);
        }
        if event.nr == SYS_UNLINKAT {
            // unlinkat(dirfd, pathname, flags)：仅在受控根目录内删除真实文件，
            // AT_FDCWD(-100) 支持，其余 dirfd 报 -EBADF；flags 仅接受 0，否则 -EINVAL。
            let dirfd = event.args[0] as i64;
            if dirfd != -100 {
                return Ok(-9); // -EBADF
            }
            let flags = event.args[2];
            if flags != 0 {
                return Ok(-22); // -EINVAL（不支持 AT_REMOVEDIR）
            }
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(event.args[1] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("unlinkat 路径不是 UTF-8".into()))?,
            );
            let Some(candidate) = self.resolve_guest_path(path) else {
                return Ok(-2); // -ENOENT
            };
            std::fs::remove_file(&candidate).map_err(DaotiError::Io)?;
            return Ok(0);
        }
        if event.nr == SYS_RENAMEAT {
            // renameat(olddirfd, oldpath, newdirfd, newpath)：仅支持两个 AT_FDCWD(-100)，
            // 在受控根内真实搬运；源缺失返回 -ENOENT(-2)，跨越受控根外的解析失败保持真实错误。
            let old_dirfd = event.args[0] as i64;
            let new_dirfd = event.args[2] as i64;
            if old_dirfd != -100 || new_dirfd != -100 {
                return Ok(-9); // -EBADF
            }
            let read_cstr = |ptr: u64| -> Result<Vec<u8>, DaotiError> {
                let mut raw = Vec::new();
                for index in 0..4096u64 {
                    let byte = memory.read(ptr + index, 1)?[0];
                    if byte == 0 {
                        break;
                    }
                    raw.push(byte);
                }
                Ok(raw)
            };
            let old_bytes = read_cstr(event.args[1])?;
            let new_bytes = read_cstr(event.args[3])?;
            let old_guest = Path::new(
                std::str::from_utf8(&old_bytes)
                    .map_err(|_| DaotiError::Other("renameat 源路径不是 UTF-8".into()))?,
            )
            .to_path_buf();
            let new_guest = Path::new(
                std::str::from_utf8(&new_bytes)
                    .map_err(|_| DaotiError::Other("renameat 目标路径不是 UTF-8".into()))?,
            )
            .to_path_buf();
            // 源必须已存在于受控根内；目标可尚不存在，用沙盒候选构造（不校验存在性）。
            let Some(old_path) = self.resolve_guest_path(&old_guest) else {
                return Ok(-2); // -ENOENT：源不存在
            };
            let new_path = self
                .resolve_sandbox_candidates(&new_guest)
                .into_iter()
                .next()
                .unwrap_or_default();
            if new_path.as_os_str().is_empty() {
                return Ok(-2); // -ENOENT：目标不可解析
            }
            std::fs::rename(&old_path, &new_path).map_err(DaotiError::Io)?;
            return Ok(0);
        }
        if matches!(event.nr, SYS_READ | SYS_PREAD64) {
            let fd = event.args[0] as i32;
            if let Some((shared, is_write_end)) = self.pipes.get(&fd) {
                if *is_write_end {
                    return Ok(-9);
                }
                let count = usize::try_from(event.args[2])
                    .map_err(|_| DaotiError::Other("pipe read 长度溢出".into()))?;
                let mut buffer = shared
                    .lock()
                    .map_err(|_| DaotiError::Other("管道锁中毒".into()))?;
                let take = count.min(buffer.len());
                if take == 0 {
                    return Ok(-11); // -EAGAIN：无数据且写端仍存在
                }
                let data: Vec<u8> = buffer.drain(..take).collect();
                memory.write(event.args[1], &data)?;
                return Ok(take as i64);
            }
            if let Some(counter) = self.eventfds.get_mut(&fd) {
                if event.args[2] < 8 {
                    return Ok(-22);
                }
                if *counter == 0 {
                    return Ok(-11);
                }
                memory.write(event.args[1], &counter.to_le_bytes())?;
                *counter = 0;
                return Ok(8);
            }
            if let Some(deadline) = self.timerfds.get_mut(&fd) {
                if event.args[2] < 8 {
                    return Ok(-22);
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?
                    .as_nanos() as u64;
                if deadline.is_none_or(|value| now < value) {
                    return Ok(-11);
                }
                memory.write(event.args[1], &1u64.to_le_bytes())?;
                *deadline = None;
                return Ok(8);
            }
            let (bytes, offset) = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| DaotiError::Other("无效文件描述符".into()))?;
            let count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("read 长度溢出".into()))?;
            let start = if event.nr == SYS_PREAD64 {
                usize::try_from(event.args[3])
                    .map_err(|_| DaotiError::Other("pread64 偏移溢出".into()))?
            } else {
                *offset
            };
            // start 越过 EOF 时返回 0（Linux 语义），避免切片逆序越界。
            if start >= bytes.len() {
                if event.nr == SYS_READ {
                    *offset = bytes.len();
                }
                return Ok(0);
            }
            let end = start.saturating_add(count).min(bytes.len());
            memory.write(event.args[1], &bytes[start..end])?;
            let read = end - start;
            if event.nr == SYS_READ {
                *offset = end;
            }
            return Ok(read as i64);
        }
        if event.nr == SYS_STATX {
            // statx(dirfd, pathname, flags, mask, statxbuf)：仅支持 AT_FDCWD，
            // 在受控根内读取真实元数据；未知扩展字段保持零，mask 只声明已填充字段。
            if event.args[0] as i64 != -100 {
                return Ok(-9); // -EBADF
            }
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(event.args[1] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("statx 路径不是 UTF-8".into()))?,
            );
            let Some(candidate) = self.resolve_guest_path(path) else {
                return Ok(-2); // -ENOENT
            };
            let metadata = std::fs::metadata(&candidate).map_err(DaotiError::Io)?;
            let mut statx = [0u8; 256];
            // struct statx：mask 0、blksize 4、attributes 8、nlink 16、uid 20、gid 24、
            // mode 28；ino 32、size 40、blocks 48；atime 64、mtime 80、ctime 96。
            statx[0..4].copy_from_slice(&0x07ffu32.to_le_bytes());
            statx[4..8].copy_from_slice(&4096u32.to_le_bytes());
            statx[16..20].copy_from_slice(&1u32.to_le_bytes());
            statx[20..24].copy_from_slice(&1000u32.to_le_bytes());
            statx[24..28].copy_from_slice(&1000u32.to_le_bytes());
            let mode = if metadata.is_dir() {
                0o040000u16 | 0o755
            } else {
                0o100000u16 | 0o644
            };
            statx[28..30].copy_from_slice(&mode.to_le_bytes());
            statx[32..40].copy_from_slice(&1u64.to_le_bytes());
            statx[40..48].copy_from_slice(&metadata.len().to_le_bytes());
            statx[48..56].copy_from_slice(&metadata.len().div_ceil(512).to_le_bytes());
            memory.write(event.args[4], &statx)?;
            return Ok(0);
        }
        if event.nr == SYS_FSTAT || event.nr == SYS_NEWFSTATAT {
            let stat_addr = if event.nr == SYS_FSTAT {
                event.args[1]
            } else {
                event.args[2]
            };
            let mut stat = [0u8; 144];
            // Linux x86_64 struct stat 布局（st_dev 0/st_ino 8/st_nlink 16/st_mode 24/
            // st_uid 28/st_gid 32/st_rdev 40/st_size 48/st_blksize 56/st_blocks 64）。
            stat[0..8].copy_from_slice(&1u64.to_le_bytes());
            stat[8..16].copy_from_slice(&1u64.to_le_bytes());
            stat[16..24].copy_from_slice(&1u64.to_le_bytes());
            // 目录句柄返回 S_IFDIR(0o040000) | 0755；普通文件保持 S_IFREG(0o100000)。
            let is_dir_fd = self.dirs.contains_key(&(event.args[0] as i32));
            let mode = if is_dir_fd {
                0o040000u32 | 0o755
            } else {
                0o100000u32 | 0o644
            };
            stat[24..28].copy_from_slice(&mode.to_le_bytes());
            stat[28..32].copy_from_slice(&1000u32.to_le_bytes());
            stat[32..36].copy_from_slice(&1000u32.to_le_bytes());
            if event.nr == SYS_NEWFSTATAT {
                if let Some((bytes, _)) = self.files.get(&(event.args[0] as i32)) {
                    stat[48..56].copy_from_slice(&(bytes.len() as i64).to_le_bytes());
                    stat[64..72]
                        .copy_from_slice(&((bytes.len().div_ceil(512)) as i64).to_le_bytes());
                }
            }
            stat[56..64].copy_from_slice(&4096i64.to_le_bytes());
            memory.write(stat_addr, &stat)?;
            if std::env::var_os("DAOTI_TRACE_STAT").is_some() {
                eprintln!(
                    "TRACE stat fd={} addr=0x{:x} size={} blocks={} mode=0x{:x}",
                    event.args[0],
                    stat_addr,
                    i64::from_le_bytes(stat[48..56].try_into().unwrap()),
                    i64::from_le_bytes(stat[64..72].try_into().unwrap()),
                    u32::from_le_bytes(stat[16..20].try_into().unwrap()),
                );
            }
            return Ok(0);
        }
        if event.nr == SYS_MPROTECT {
            if event.args[1] == 0 {
                return Ok(0);
            }
            let prot = event.args[2];
            if prot & !0x7 != 0 {
                return Err(DaotiError::Other("mprotect 保护标志无效".into()));
            }
            let perm = MemPerm::new(prot & 0x1 != 0, prot & 0x2 != 0, prot & 0x4 != 0);
            return memory
                .mprotect(event.args[0], event.args[1], perm)
                .map(|_| 0);
        }
        if event.nr == SYS_ARCH_PRCTL && event.args[0] == 0x3001 {
            return Ok(0);
        }
        if event.nr == SYS_ARCH_PRCTL && event.args[0] == ARCH_GET_FS {
            let address = event.args[1];
            let fs = self
                .fs_base
                .ok_or_else(|| DaotiError::Unavailable("FS 基址尚未设置".into()))?;
            memory.write(address, &fs.to_le_bytes())?;
            return Ok(0);
        }
        if event.nr == SYS_ARCH_PRCTL && event.args[0] == ARCH_SET_FS {
            let fs = event.args[1];
            // TLS 正方向写区预留：glibc 的 TLS 初始化例程（__libc_early_init
            // 首个 call 的 ctype 加速函数）会写 [fs+0x4000]/[fs+0x5000] 槽位；
            // 真实内核下这些页已被 loader 的 TLS 大分配覆盖。ld 实际请求的
            // TLS block 仅 0x2000，若不补齐，写失败会连锁阻断 brk 使能标志
            // 的写入（__sbrk 由此恒 ENOMEM → malloc corrupted top size）。
            for tls_slot in [0x4000u64, 0x5000u64] {
                let page = (fs + tls_slot) / 4096 * 4096;
                if memory.read(page, 8).is_err() {
                    memory.add_region(MemoryRegion::with_data(
                        page,
                        MemPerm::rw(),
                        vec![0; 0x1000],
                    ))?;
                }
            }
            // 初始化静态 TLS 块（TP 负方向）：把 ELF PT_TLS 初始化镜像复制到
            // fs - align_up(memsz, align)。否则 __ctype_init 读 fs:[-0x90] 为 0，
            // mov rax, fs:[rax]; mov rax,[rax] 会以空指针解引用崩溃。
            if let Some(tls) = &self.elf_tls {
                let tls_off = align_up(tls.memsz, tls.align);
                let block_start = fs.wrapping_sub(tls_off);
                let page = block_start / 4096 * 4096;
                if memory.read(page, 8).is_err() {
                    memory.add_region(MemoryRegion::with_data(
                        page,
                        MemPerm::rw(),
                        vec![0; 0x1000],
                    ))?;
                }
                memory.write(block_start, &tls.image)?;
                if std::env::var_os("DAOTI_TRACE_CTYPE_INIT").is_some() {
                    let value = memory.read(block_start, 8).ok();
                    eprintln!(
                        "TRACE set-fs static-tls block=0x{block_start:x} tls_off=0x{tls_off:x} head={value:02x?}"
                    );
                }
            }
            // 写入 locale 到 FS-0x60
            if let Some(locale) = self.tls_locale {
                memory.write(fs.wrapping_sub(0x60), &locale.to_le_bytes())?;
            }
            // 写入 pointer_guard 到 FS:0x30
            memory.write(fs + 0x30, &self.pointer_guard.to_le_bytes())?;
            // 写入 stack_guard 到 FS:0x28
            memory.write(fs + 0x28, &self.stack_guard.to_le_bytes())?;
            // 写入 TCB 自指针到 FS:0
            memory.write(fs, &fs.to_le_bytes())?;
            if std::env::var_os("DAOTI_TRACE_CTYPE_INIT").is_some() {
                // 探针：确认静态 TLS 块（TP 负方向，如 fs-0x90/fs-0x60）是否已有 region 覆盖。
                let covered_neg = memory.read(fs.wrapping_sub(0x90), 8).is_ok();
                let covered_neg60 = memory.read(fs.wrapping_sub(0x60), 8).is_ok();
                let covered_zero = memory.read(fs, 8).is_ok();
                let covered_pos = memory.read(fs.wrapping_add(0x1000), 8).is_ok();
                eprintln!(
                    "TRACE set-fs fs=0x{fs:x} covered_fs-0x90={covered_neg} covered_fs-0x60={covered_neg60} covered_fs={covered_zero} covered_fs+0x1000={covered_pos}"
                );
            }
            return self.handle(event);
        }
        if event.nr == SYS_FUTEX {
            let operation = event.args[1] & FUTEX_CMD_MASK;
            if operation == FUTEX_WAIT {
                if std::env::var_os("DAOTI_TRACE_FUTEX").is_some() {
                    let value = memory
                        .read(event.args[0], 4)
                        .ok()
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
                    eprintln!(
                        "TRACE futex wait addr=0x{:x} value={value:?} op=0x{:x}",
                        event.args[0], event.args[1]
                    );
                }
                return Ok(-11);
            }
        }
        if event.nr == SYS_MMAP {
            let anonymous_fd = event.args[4] == u64::MAX || event.args[4] == u32::MAX as u64;
            if !anonymous_fd && event.args[5].is_multiple_of(4096) {
                let fd = event.args[4] as i32;
                let (bytes, _) = self
                    .files
                    .get(&fd)
                    .ok_or_else(|| DaotiError::Other("无效 mmap 文件描述符".into()))?;
                let len = usize::try_from(event.args[1])
                    .map_err(|_| DaotiError::Other("mmap 长度溢出".into()))?;
                let offset = usize::try_from(event.args[5])
                    .map_err(|_| DaotiError::Other("mmap 偏移溢出".into()))?;
                let end = offset
                    .checked_add(len)
                    .ok_or_else(|| DaotiError::Other("mmap 文件范围溢出".into()))?;
                let copy_end = end.min(bytes.len());
                let prot = event.args[2];
                if prot & !0x7 != 0 {
                    return Err(DaotiError::Other("mmap 保护标志无效".into()));
                }
                let requested_perm = MemPerm::new(prot & 1 != 0, prot & 2 != 0, prot & 4 != 0);
                let mapped_elf = bytes.starts_with(b"\x7fELF")
                    && bytes.get(4).copied() == Some(2)
                    && bytes.get(5).copied() == Some(1);
                let mapped_len = if mapped_elf {
                    let info = super::parse_elf_from_bytes(bytes)?;
                    let virtual_end = info
                        .segments
                        .iter()
                        .filter(|segment| segment.type_ == 1)
                        .map(|segment| segment.vaddr.saturating_add(segment.memsz))
                        .max()
                        .unwrap_or(event.args[1]);
                    event.args[1].max(virtual_end).saturating_add(4095) / 4096 * 4096
                } else {
                    event.args[1]
                };
                let requested_len = event.args[1]
                    .checked_add(4095)
                    .ok_or_else(|| DaotiError::Other("mmap 长度对齐溢出".into()))?
                    / 4096
                    * 4096;
                let backing_len = if event.args[0] == 0 {
                    mapped_len
                } else {
                    requested_len
                };
                let addr = if event.args[0] != 0 {
                    let requested_addr = event.args[0];
                    memory.mmap_fixed_replace(requested_addr, requested_len, MemPerm::rw())?;
                    requested_addr
                } else {
                    memory.mmap_anonymous_private_topdown(backing_len, MemPerm::rw())?
                };
                if mapped_elf && offset == 0 {
                    let info = super::parse_elf_from_bytes(bytes)?;
                    for segment in info.segments.iter().filter(|segment| segment.type_ == 1) {
                        let segment_start = usize::try_from(segment.offset)
                            .map_err(|_| DaotiError::Other("ELF PT_LOAD 文件偏移过大".into()))?;
                        let segment_end = segment_start
                            .checked_add(usize::try_from(segment.filesz).map_err(|_| {
                                DaotiError::Other("ELF PT_LOAD 文件大小过大".into())
                            })?)
                            .ok_or_else(|| DaotiError::Other("ELF PT_LOAD 文件范围溢出".into()))?;
                        if segment_end > bytes.len() {
                            return Err(DaotiError::Other("ELF PT_LOAD 超出文件边界".into()));
                        }
                        let target = addr.checked_add(segment.vaddr).ok_or_else(|| {
                            DaotiError::Other("ELF PT_LOAD 运行时地址溢出".into())
                        })?;
                        if target < addr
                            || target.saturating_add(segment.filesz)
                                > addr.saturating_add(mapped_len)
                        {
                            return Err(DaotiError::Other("ELF PT_LOAD 超出 mmap 范围".into()));
                        }
                        memory.write(target, &bytes[segment_start..segment_end])?;
                    }
                    // 装载副本后补应用装载期重定位（RELATIVE/GLOB_DAT/JUMP_SLOT 等），
                    // 否则 libc 的 GOT 槽（如 __curbrk）保持 0，__sbrk 读槽崩溃。
                    let relocs = apply_elf_runtime_relocations(memory, bytes, addr)?;
                    // 缓存 PT_TLS 初始化镜像（重定位后含绝对指针），供 ARCH_SET_FS 建静态 TLS 块。
                    if let Some((vaddr, filesz, memsz, align)) = relocs.tls {
                        let image_addr = addr
                            .checked_add(vaddr)
                            .ok_or_else(|| DaotiError::Other("ELF PT_TLS 地址溢出".into()))?;
                        let mut image = memory.read(image_addr, filesz)?.to_vec();
                        let info = super::parse_elf_from_bytes(bytes)?;
                        let load_ranges = info
                            .segments
                            .iter()
                            .filter(|segment| segment.type_ == 1)
                            .map(|segment| {
                                (segment.vaddr, segment.vaddr.saturating_add(segment.memsz))
                            })
                            .collect::<Vec<_>>();
                        relocate_tls_image_internal_pointers(&mut image, addr, &load_ranges);
                        if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                            eprintln!(
                                "TRACE runtime-reloc tls-image addr=0x{image_addr:x} filesz=0x{filesz:x} memsz=0x{memsz:x} align={align} head={:02x?}",
                                &image[..image.len().min(16)]
                            );
                        }
                        self.elf_tls = Some(ElfTlsImage {
                            image,
                            memsz,
                            align,
                        });
                    }
                    // __sbrk 通过 __curbrk 指针保存用户态 brk；fd-mmap 副本没有
                    // 真实内核初始化副作用，因此必须与 bridge 当前 brk 同步初值。
                    if let Some(curbrk) = relocs.curbrk {
                        memory.write(curbrk, &self.current_brk.to_le_bytes())?;
                        if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                            eprintln!(
                                "TRACE runtime-reloc curbrk-init addr=0x{curbrk:x} value=0x{:x}",
                                self.current_brk
                            );
                        }
                    }
                } else if offset < copy_end {
                    memory.write(addr, &bytes[offset..copy_end])?;
                    // MAP_FIXED 分段覆盖会恢复文件中的 raw TLS/GOT 值；分段写入完成后
                    // 重新按同一 load bias 应用重定位，保持后续 glibc 读取到运行时地址。
                    if mapped_elf {
                        let info = super::parse_elf_from_bytes(bytes)?;
                        if let Some(segment) = info
                            .segments
                            .iter()
                            .filter(|segment| segment.type_ == 1)
                            .find(|segment| {
                                segment.offset / 4096 * 4096 == (offset as u64) / 4096 * 4096
                            })
                        {
                            let bias = event.args[0]
                                .checked_sub(segment.vaddr / 4096 * 4096)
                                .ok_or_else(|| {
                                    DaotiError::Other("ELF load bias 反推下溢".into())
                                })?;
                            let relocs = apply_elf_runtime_relocations(memory, bytes, bias)?;
                            if let Some((vaddr, filesz, memsz, align)) = relocs.tls {
                                let image_addr = bias.checked_add(vaddr).ok_or_else(|| {
                                    DaotiError::Other("ELF PT_TLS 地址溢出".into())
                                })?;
                                let mut image = memory.read(image_addr, filesz)?.to_vec();
                                let load_ranges = info
                                    .segments
                                    .iter()
                                    .filter(|segment| segment.type_ == 1)
                                    .map(|segment| {
                                        (segment.vaddr, segment.vaddr.saturating_add(segment.memsz))
                                    })
                                    .collect::<Vec<_>>();
                                relocate_tls_image_internal_pointers(
                                    &mut image,
                                    bias,
                                    &load_ranges,
                                );
                                self.elf_tls = Some(ElfTlsImage {
                                    image,
                                    memsz,
                                    align,
                                });
                            }
                            if let Some(curbrk) = relocs.curbrk {
                                memory.write(curbrk, &self.current_brk.to_le_bytes())?;
                            }
                        }
                    }
                }
                if !mapped_elf && requested_perm != MemPerm::rw() {
                    let protect_len = event.args[1]
                        .checked_add(4095)
                        .ok_or_else(|| DaotiError::Other("mmap 长度对齐溢出".into()))?
                        / 4096
                        * 4096;
                    memory.mprotect(addr, protect_len, requested_perm)?;
                }
                if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                    let within_ptload = self
                        .main_ptload_ranges
                        .iter()
                        .any(|(s, e)| addr >= *s && addr < *e);
                    eprintln!("TRACE runtime mmap-file-return addr=0x{:x} len=0x{:x} fd={} fd_offset=0x{:x} within_main_ptload={} prot=0x{:x}", addr, event.args[1], fd, event.args[5], within_ptload, event.args[2]);
                    if event.args[5] == 0 && event.args[1] >= 0x219bc0 + 16 {
                        let dynamic_addr = addr + 0x219bc0;
                        let dynamic = memory.read(dynamic_addr, 16).ok();
                        let source = bytes.get(0..16);
                        eprintln!("TRACE runtime mmap-dynamic-check addr=0x{dynamic_addr:x} bytes={dynamic:02x?} source_head={source:02x?} source_len=0x{:x} requested_len=0x{:x} copied_len=0x{:x} expected_file_offset=0x218bc0", bytes.len(), event.args[1], copy_end);
                    }
                }
                return Ok(addr as i64);
            }
            if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                eprintln!("TRACE syscall mmap addr=0x{:x} len=0x{:x} prot=0x{:x} flags=0x{:x} fd=0x{:x} off=0x{:x}", event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5]);
            }
            let flags = event.args[3];
            if flags & (MAP_PRIVATE | MAP_ANONYMOUS) != (MAP_PRIVATE | MAP_ANONYMOUS)
                || !anonymous_fd
                || event.args[5] != 0
            {
                return Err(DaotiError::Unavailable(format!(
                    "仅支持匿名私有 mmap 映射：addr=0x{:x}, len=0x{:x}, flags=0x{:x}, fd={}, offset=0x{:x}",
                    event.args[0],
                    event.args[1],
                    flags,
                    event.args[4] as i64,
                    event.args[5],
                )));
            }
            let prot = event.args[2];
            if prot & !0x7 != 0 {
                return Err(DaotiError::Other("mmap 保护标志无效".into()));
            }
            let perm = MemPerm::new(prot & 0x1 != 0, prot & 0x2 != 0, prot & 0x4 != 0);
            let anon_addr = if event.args[0] != 0 {
                let requested_len = event.args[1]
                    .checked_add(4095)
                    .ok_or_else(|| DaotiError::Other("匿名 mmap 长度对齐溢出".into()))?
                    / 4096
                    * 4096;
                memory
                    .mmap_fixed_replace(event.args[0], requested_len, perm)
                    .map(|_| event.args[0])
            } else {
                memory.mmap_anonymous_private_topdown(event.args[1], perm)
            }
                .map(|addr| {
                    if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                        let within_ptload = self.main_ptload_ranges.iter().any(|(s, e)| addr >= *s && addr < *e);
                        eprintln!("TRACE runtime mmap-anon-return addr=0x{:x} len=0x{:x} within_main_ptload={} prot=0x{:x}", addr, event.args[1], within_ptload, event.args[2]);
                    }
                    addr as i64
                })
                .map_err(|error| {
                    eprintln!("动态 ELF mmap 分配失败：{error}");
                    error
                });
            return anon_addr;
        }
        if event.nr == SYS_GETRLIMIT {
            // getrlimit(resource, &rlim)：x86-64 System V ABI 传 rdi=resource, rsi=&rlim。
            // __libc_early_init 先用 RLIMIT_STACK 查询栈限制，结果参与后续
            // 栈保护页大小计算；返回值必须是非零合理值，否则 early_init 的
            // cmov/div 序列会飞出，连锁导致 sbrk 标志被清 0 → malloc corrupted。
            let resource = event.args[0];
            let rlim_addr = event.args[1];
            // 结构：struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; } 共 16 字节
            let mut buf = [0u8; 16];
            let (cur, max): (u64, u64) = match resource {
                // RLIMIT_STACK=3：与 daoti 栈区（8MB）对齐
                3 => (0x800000, 0x800000),
                // RLIMIT_DATA=2 / RLIMIT_AS=9：宽松上限
                2 | 9 => (u64::MAX - 1, u64::MAX - 1),
                _ => {
                    return Err(DaotiError::Unavailable(format!(
                        "未实现的 getrlimit 资源：{}",
                        resource
                    )))
                }
            };
            buf[0..8].copy_from_slice(&cur.to_le_bytes());
            buf[8..16].copy_from_slice(&max.to_le_bytes());
            memory.write(rlim_addr, &buf)?;
            if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                eprintln!(
                    "TRACE bridge getrlimit resource={resource} addr=0x{rlim_addr:x} cur=0x{cur:x} max=0x{max:x}"
                );
            }
            return Ok(0);
        }
        if event.nr == SYS_PRLIMIT64 {
            // prlimit64(pid=0, resource, new_limit, old_limit)：glibc 的 getrlimit
            // 包装（libc+0x11a310）实际发 syscall 302，参数 rdi=0,rsi=resource,
            // rdx=0(仅查询),r10=&old_limit。若不写 old_limit，__libc_early_init
            // 读到的栈限制是垃圾 → cmov/div 序列错乱 → sbrk 标志被清 → corrupted。
            let pid = event.args[0];
            let resource = event.args[1];
            let new_limit = event.args[2];
            let old_limit = event.args[3];
            if pid == 0 && new_limit == 0 {
                let (cur, max): (u64, u64) = match resource {
                    3 => (0x800000, 0x800000),             // RLIMIT_STACK：与 daoti 8MB 栈对齐
                    2 | 9 => (u64::MAX - 1, u64::MAX - 1), // RLIMIT_DATA/RLIMIT_AS
                    _ => {
                        return Err(DaotiError::Unavailable(format!(
                            "未实现的 prlimit64 资源：{}",
                            resource
                        )))
                    }
                };
                let mut buf = [0u8; 16];
                buf[0..8].copy_from_slice(&cur.to_le_bytes());
                buf[8..16].copy_from_slice(&max.to_le_bytes());
                memory.write(old_limit, &buf)?;
                if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                    eprintln!(
                        "TRACE bridge prlimit64 pid={pid} resource={resource} old=0x{old_limit:x} cur=0x{cur:x}"
                    );
                }
                return Ok(0);
            }
            return Ok(0);
        }
        if event.nr == SYS_SELECT {
            // select(nfds, readfds, writefds, exceptfds, timeout)：x86_64 fd_set 为 1024 位。
            let nfds = usize::try_from(event.args[0])
                .map_err(|_| DaotiError::Other("select nfds 超出平台范围".into()))?;
            if nfds > 1024 {
                return Ok(-22); // -EINVAL
            }
            let words = nfds.div_ceil(64);
            let bytes_len = words * 8;
            let read_ptr = event.args[1];
            let write_ptr = event.args[2];
            let mut read_set = if read_ptr != 0 {
                memory.read(read_ptr, bytes_len as u64)?.to_vec()
            } else {
                vec![0; bytes_len]
            };
            let mut write_set = if write_ptr != 0 {
                memory.read(write_ptr, bytes_len as u64)?.to_vec()
            } else {
                vec![0; bytes_len]
            };
            let read_requested = read_set.clone();
            let write_requested = write_set.clone();
            read_set.fill(0);
            write_set.fill(0);
            let mut ready = 0i64;
            for fd in 0..nfds {
                let word = fd / 64;
                let bit = 1u64 << (fd % 64);
                let read_wanted =
                    u64::from_le_bytes(read_requested[word * 8..word * 8 + 8].try_into().unwrap())
                        & bit
                        != 0;
                let write_wanted =
                    u64::from_le_bytes(write_requested[word * 8..word * 8 + 8].try_into().unwrap())
                        & bit
                        != 0;
                let read_ready = self
                    .pipes
                    .get(&(fd as i32))
                    .is_some_and(|(shared, is_write)| {
                        !*is_write
                            && shared
                                .lock()
                                .map(|buffer| !buffer.is_empty())
                                .unwrap_or(false)
                    })
                    || self
                        .eventfds
                        .get(&(fd as i32))
                        .is_some_and(|value| *value > 0)
                    || self.timerfds.get(&(fd as i32)).is_some_and(|deadline| {
                        deadline.is_some_and(|value| {
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|duration| duration.as_nanos() as u64 >= value)
                                .unwrap_or(false)
                        })
                    })
                    || self.sockets.get(&(fd as i32)).is_some_and(|state| {
                        state.shutdown & 0b01 == 0
                            && state.rx.as_ref().is_some_and(|rx| {
                                rx.lock().map(|buffer| !buffer.is_empty()).unwrap_or(false)
                            })
                    });
                let write_ready = fd == 1
                    || self
                        .pipes
                        .get(&(fd as i32))
                        .is_some_and(|(_, is_write)| *is_write)
                    || self
                        .sockets
                        .get(&(fd as i32))
                        .is_some_and(|state| state.shutdown & 0b10 == 0 && state.tx.is_some());
                if read_wanted && read_ready {
                    let value =
                        u64::from_le_bytes(read_set[word * 8..word * 8 + 8].try_into().unwrap())
                            | bit;
                    read_set[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
                    ready += 1;
                }
                if write_wanted && write_ready {
                    let value =
                        u64::from_le_bytes(write_set[word * 8..word * 8 + 8].try_into().unwrap())
                            | bit;
                    write_set[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
                    if !(read_wanted && read_ready) {
                        ready += 1;
                    }
                }
            }
            if read_ptr != 0 {
                memory.write(read_ptr, &read_set)?;
            }
            if write_ptr != 0 {
                memory.write(write_ptr, &write_set)?;
            }
            return Ok(ready);
        }
        if event.nr == SYS_POLL || event.nr == SYS_PPOLL {
            // poll/ppoll(struct pollfd *fds, nfds, [timeout|tmo_p])：pollfd 为 fd(i32)+events(i16)+revents(i16)，共 8 字节。
            // 当前仿真不阻塞：立即根据设备状态计算就绪事件。ppoll 的额外 sigmask 参数被接受但忽略（无信号语义）。
            let count = usize::try_from(event.args[1])
                .map_err(|_| DaotiError::Other("poll 数量超出平台范围".into()))?;
            let mut ready = 0i64;
            for index in 0..count {
                let address = event.args[0]
                    .checked_add((index as u64) * 8)
                    .ok_or_else(|| DaotiError::Other("poll 数组地址溢出".into()))?;
                let raw = memory.read(address, 8)?;
                let fd = i32::from_le_bytes(raw[0..4].try_into().unwrap());
                let events = i16::from_le_bytes(raw[4..6].try_into().unwrap()) as u16;
                let mut revents = 0u16;
                if fd == 1 || fd == 2 {
                    revents |= events & 0x0004; // POLLOUT
                } else if let Some((shared, is_write_end)) = self.pipes.get(&fd) {
                    if *is_write_end {
                        revents |= events & 0x0004;
                    } else if !shared
                        .lock()
                        .map_err(|_| DaotiError::Other("管道锁中毒".into()))?
                        .is_empty()
                    {
                        revents |= events & 0x0001; // POLLIN
                    }
                } else if let Some(counter) = self.eventfds.get(&fd) {
                    if *counter > 0 {
                        revents |= events & 0x0001;
                    }
                } else if let Some(deadline) = self.timerfds.get(&fd) {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?
                        .as_nanos() as u64;
                    if deadline.is_some_and(|value| now >= value) {
                        revents |= events & 0x0001;
                    }
                } else if let Some(state) = self.sockets.get(&fd) {
                    // socket：写方向未关闭即可写（POLLOUT），读缓冲非空即可读（POLLIN）。
                    if state.shutdown & 0b10 == 0 {
                        revents |= events & 0x0004;
                    }
                    let rx_readable = state.rx.as_ref().is_some_and(|rx| {
                        rx.lock().map(|buffer| !buffer.is_empty()).unwrap_or(false)
                    });
                    if state.shutdown & 0b01 == 0 && rx_readable {
                        revents |= events & 0x0001;
                    }
                } else {
                    revents |= events & 0x0001;
                }
                memory.write(address + 6, &revents.to_le_bytes())?;
                if revents != 0 {
                    ready += 1;
                }
            }
            return Ok(ready);
        }
        if event.nr == SYS_EPOLL_CREATE1 {
            if event.args[0] & !0x80000 != 0 {
                return Ok(-22);
            }
            let fd = self.next_fd;
            self.next_fd += 1;
            self.epolls.insert(fd, Vec::new());
            return Ok(fd as i64);
        }
        if event.nr == SYS_EPOLL_CTL {
            let epfd = event.args[0] as i32;
            let operation = event.args[1];
            let target = event.args[2] as i32;
            let registrations = self
                .epolls
                .get_mut(&epfd)
                .ok_or_else(|| DaotiError::Other("无效 epoll fd".into()))?;
            match operation {
                1 | 3 => {
                    let raw = memory.read(event.args[3], 16)?;
                    let events = u32::from_le_bytes(raw[0..4].try_into().unwrap());
                    let data = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                    if operation == 1 {
                        registrations.push((target, events, data));
                    } else if let Some(item) =
                        registrations.iter_mut().find(|item| item.0 == target)
                    {
                        *item = (target, events, data);
                    } else {
                        return Ok(-2);
                    }
                }
                2 => {
                    registrations.retain(|item| item.0 != target);
                }
                _ => return Ok(-22),
            }
            return Ok(0);
        }
        if event.nr == SYS_EPOLL_WAIT || event.nr == SYS_EPOLL_PWAIT {
            // epoll_wait/epoll_pwait(epfd, events, maxevents, [timeout|timeout,sigmask])：
            // 与 poll 同理不阻塞；epoll_pwait 的 sigmask 额外参数被接受但忽略。
            let epfd = event.args[0] as i32;
            let output = event.args[1];
            let maxevents = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("epoll maxevents 溢出".into()))?;
            if maxevents == 0 {
                return Ok(-22);
            }
            let registrations = self
                .epolls
                .get(&epfd)
                .ok_or_else(|| DaotiError::Other("无效 epoll fd".into()))?
                .clone();
            let mut ready = 0i64;
            for (fd, requested, data) in registrations.into_iter().take(maxevents) {
                let is_ready = fd == 1
                    || self.pipes.get(&fd).is_some_and(|(_, write)| *write)
                    || self.eventfds.get(&fd).is_some_and(|value| *value > 0)
                    || self
                        .timerfds
                        .get(&fd)
                        .is_some_and(|deadline| deadline.is_some())
                    || self.sockets.get(&fd).is_some_and(|state| {
                        // 写方向打开即可就绪（可写）；读方向有数据也可就绪。
                        state.shutdown & 0b10 == 0
                            || (state.shutdown & 0b01 == 0
                                && state.rx.as_ref().is_some_and(|rx| {
                                    rx.lock().map(|buffer| !buffer.is_empty()).unwrap_or(false)
                                }))
                    });
                if is_ready {
                    let mut raw = [0u8; 16];
                    raw[0..4].copy_from_slice(&(requested & 0x1f).to_le_bytes());
                    raw[8..16].copy_from_slice(&data.to_le_bytes());
                    memory.write(output + (ready as u64) * 16, &raw)?;
                    ready += 1;
                }
            }
            return Ok(ready);
        }
        if event.nr == SYS_SOCKET {
            // socket(family, type, protocol)：仅保留受控 family/type 组合，未知返回真实 -EAFNOSUPPORT。
            let family = event.args[0];
            let sock_type = event.args[1];
            // AF_UNIX=1 / AF_INET=2；type 取低字节（SOCK_STREAM=1/SOCK_DGRAM=2，可带 CLOEXEC 等高位）。
            if family != 1 && family != 2 {
                return Ok(-97); // -EAFNOSUPPORT
            }
            if !matches!(sock_type & 0x1f, 1 | 2) {
                return Ok(-22); // -EINVAL
            }
            let fd = self.next_fd;
            self.next_fd += 1;
            self.sockets.insert(
                fd,
                SocketState {
                    family: family as u32,
                    sock_type: (sock_type & 0x1f) as u32,
                    rx: None,
                    tx: None,
                    shutdown: 0,
                    options: HashMap::new(),
                    bound_port: None,
                    listening: false,
                    pending: std::collections::VecDeque::new(),
                },
            );
            return Ok(fd as i64);
        }
        if event.nr == SYS_SOCKETPAIR {
            // socketpair(family, type, protocol, sv[2])：只支持 AF_UNIX=1，
            // 建立两条交叉共享缓冲（A写→B读、B写→A读），复用 pipe 的 VecDeque 语义。
            let family = event.args[0];
            if family != 1 {
                return Ok(-97); // -EAFNOSUPPORT：Linux 仅 AF_UNIX 支持 socketpair
            }
            let fd_a = self.next_fd;
            let fd_b = self.next_fd + 1;
            self.next_fd += 2;
            let a_to_b =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
            let b_to_a =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
            self.sockets.insert(
                fd_a,
                SocketState {
                    family: 1,
                    sock_type: 1,
                    rx: Some(b_to_a.clone()),
                    tx: Some(a_to_b.clone()),
                    shutdown: 0,
                    options: HashMap::new(),
                    bound_port: None,
                    listening: false,
                    pending: std::collections::VecDeque::new(),
                },
            );
            self.sockets.insert(
                fd_b,
                SocketState {
                    family: 1,
                    sock_type: 1,
                    rx: Some(a_to_b),
                    tx: Some(b_to_a),
                    shutdown: 0,
                    options: HashMap::new(),
                    bound_port: None,
                    listening: false,
                    pending: std::collections::VecDeque::new(),
                },
            );
            let mut fds = [0u8; 8];
            fds[..4].copy_from_slice(&(fd_a as u32).to_le_bytes());
            fds[4..].copy_from_slice(&(fd_b as u32).to_le_bytes());
            memory.write(event.args[3], &fds)?;
            return Ok(0);
        }
        if event.nr == SYS_SHUTDOWN {
            // shutdown(fd, how)：0=SHUT_RD，1=SHUT_WR，2=SHUT_RDWR。
            let fd = event.args[0] as i32;
            let how = event.args[1];
            let Some(state) = self.sockets.get_mut(&fd) else {
                return Ok(-9); // -EBADF
            };
            let bits = match how {
                0 => 0b01,
                1 => 0b10,
                2 => 0b11,
                _ => return Ok(-22), // -EINVAL
            };
            state.shutdown |= bits;
            return Ok(0);
        }
        match event.nr {
            SYS_BIND => {
                // bind(fd, sockaddr*, addrlen)：解析 sockaddr_in 的 family/port（port 网络字节序大端），
                // 记录绑定端口；端口已占用或 family 不符返回真实错误。
                let fd = event.args[0] as i32;
                let addr_ptr = event.args[1];
                let addrlen = event.args[2];
                if !self.sockets.contains_key(&fd) {
                    return Ok(-9); // -EBADF
                }
                if addrlen < 8 {
                    return Ok(-22); // -EINVAL：sockaddr_in 至少 8 字节
                }
                let raw = memory.read(addr_ptr, 8)?;
                let family = u16::from_le_bytes(raw[0..2].try_into().unwrap());
                let port = u16::from_be_bytes(raw[2..4].try_into().unwrap());
                let state_family = self.sockets.get(&fd).map(|s| s.family).unwrap_or(0);
                if family as u32 != state_family {
                    return Ok(-22); // -EINVAL：family 与创建时不一致
                }
                // 同 family+port 已被其他 listener 绑定 → -EADDRINUSE(-98)
                if self.sockets.iter().any(|(other, candidate)| {
                    *other != fd
                        && candidate.family == state_family
                        && candidate.bound_port == Some(port)
                }) {
                    return Ok(-98);
                }
                self.sockets.get_mut(&fd).unwrap().bound_port = Some(port);
                return Ok(0);
            }
            SYS_LISTEN => {
                // listen(fd, backlog)：进入监听状态；未绑定端口也允许（内核自动绑定，此处保持 None）。
                let fd = event.args[0] as i32;
                let Some(state) = self.sockets.get_mut(&fd) else {
                    return Ok(-9); // -EBADF
                };
                state.listening = true;
                return Ok(0);
            }
            SYS_CONNECT => {
                // connect(fd, sockaddr*, addrlen)：在本 bridge 的 sockets 表内查找
                // family/port 匹配且处于监听状态的 socket（受控回环仿真）；
                // 找到则建立双向共享缓冲并加入其对端队列，返回 0；
                // 否则返回 -ECONNREFUSED(-111)，与"无进程监听该端口"的真实行为一致。
                let fd = event.args[0] as i32;
                let addr_ptr = event.args[1];
                let addrlen = event.args[2];
                if !self.sockets.contains_key(&fd) {
                    return Ok(-9); // -EBADF
                }
                if addrlen < 8 {
                    return Ok(-22); // -EINVAL
                }
                let raw = memory.read(addr_ptr, 8)?;
                let family = u16::from_le_bytes(raw[0..2].try_into().unwrap());
                let port = u16::from_be_bytes(raw[2..4].try_into().unwrap());
                let client_family = self.sockets.get(&fd).map(|s| s.family).unwrap_or(0);
                if family as u32 != client_family {
                    return Ok(-22); // -EINVAL：family 不匹配
                }
                if self.sockets.get(&fd).is_some_and(|s| s.listening) {
                    return Ok(-22); // -EINVAL：监听端不能作为连接发起端
                }
                // 查找监听端（family+port 匹配的 listening socket）。
                let Some(server_fd) = self.sockets.iter().find_map(|(&candidate_fd, candidate)| {
                    (candidate.family == client_family
                        && candidate.listening
                        && candidate.bound_port == Some(port))
                    .then_some(candidate_fd)
                }) else {
                    return Ok(-111); // -ECONNREFUSED
                };
                // 建立两条交叉共享缓冲：client→server（client 写、server 读）、
                // server→client（client 读、server 写）。
                let client_to_server =
                    std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
                let server_to_client =
                    std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
                let client = self.sockets.get_mut(&fd).unwrap();
                client.rx = Some(server_to_client.clone());
                client.tx = Some(client_to_server.clone());
                // 服务端读 client 写来的缓冲；服务端写 client 读的缓冲。
                let client_to_server_clone = client_to_server.clone();
                let server_to_client_clone = server_to_client.clone();
                self.sockets
                    .get_mut(&server_fd)
                    .ok_or_else(|| DaotiError::Other("connect 目标已消失".into()))?
                    .pending
                    .push_back((client_to_server_clone, server_to_client_clone));
                return Ok(0);
            }
            SYS_ACCEPT4 => {
                // accept4(fd, sockaddr*, socklen_t*, flags)：从监听队列弹出一个连接，
                // 新 fd 的 rx=client_to_server、tx=server_to_client；队列空 → -EAGAIN(-11)。
                let fd = event.args[0] as i32;
                let addr_ptr = event.args[1];
                let len_ptr = event.args[2];
                let flags = event.args[3];
                let Some(state) = self.sockets.get_mut(&fd) else {
                    return Ok(-9); // -EBADF
                };
                if !state.listening {
                    return Ok(-22); // -EINVAL：非监听 socket 不可 accept
                }
                if flags & !0x00080000 != 0 {
                    return Ok(-22); // -EINVAL：仅接受 SOCK_CLOEXEC
                }
                let Some((client_to_server, server_to_client)) = state.pending.pop_front() else {
                    return Ok(-11); // -EAGAIN：无待接受连接
                };
                let accepted_family = state.family;
                let accepted_type = state.sock_type;
                let _ = state;
                let accepted = self.next_fd;
                self.next_fd += 1;
                self.sockets.insert(
                    accepted,
                    SocketState {
                        family: accepted_family,
                        sock_type: accepted_type,
                        rx: Some(client_to_server),
                        tx: Some(server_to_client),
                        shutdown: 0,
                        options: HashMap::new(),
                        bound_port: None,
                        listening: false,
                        pending: std::collections::VecDeque::new(),
                    },
                );
                // 回填对端地址：family + 端口 + 长度 = 16。
                if addr_ptr != 0 {
                    let mut raw = [0u8; 16];
                    raw[..2].copy_from_slice(&(accepted_family as u16).to_le_bytes());
                    memory.write(addr_ptr, &raw)?;
                    if len_ptr != 0 {
                        memory.write(len_ptr, &16u32.to_le_bytes())?;
                    }
                }
                return Ok(accepted as i64);
            }
            _ => {}
        }
        if event.nr == SYS_SENDMSG || event.nr == SYS_RECVMSG {
            // sendmsg/recvmsg(fd, msghdr*, flags)：x86_64 msghdr 布局 56 字节：
            //   msg_name(8)+msg_namelen(8)+msg_iov(8)+msg_iovlen(8)+msg_control(8)+msg_controllen(8)+msg_flags(4)
            // sendmsg 将 iov 段聚合后写入发送缓冲；recvmsg 从接收缓冲分散读出并回填长度。
            let fd = event.args[0] as i32;
            let header = event.args[1];
            if !self.sockets.contains_key(&fd) {
                return Ok(-9); // -EBADF
            }
            let raw = memory.read(header, 56)?;
            let iov_base = u64::from_le_bytes(raw[16..24].try_into().unwrap());
            let iov_count = usize::try_from(u64::from_le_bytes(raw[24..32].try_into().unwrap()))
                .map_err(|_| DaotiError::Other("msghdr iovlen 超出平台范围".into()))?;
            if event.nr == SYS_SENDMSG {
                let Some(state) = self.sockets.get_mut(&fd) else {
                    unreachable!("已校验 sockets.contains_key");
                };
                if state.shutdown & 0b10 != 0 {
                    return Ok(-32); // -EPIPE：写方向已关闭
                }
                let Some(tx) = state.tx.clone() else {
                    return Ok(-107); // -ENOTCONN：未连接 socket 无法发送
                };
                let mut total = 0usize;
                for index in 0..iov_count {
                    let entry = iov_base
                        .checked_add((index as u64).saturating_mul(16))
                        .ok_or_else(|| DaotiError::Other("sendmsg iovec 地址溢出".into()))?;
                    let address = u64::from_le_bytes(memory.read(entry, 8)?.try_into().unwrap());
                    let length = usize::try_from(u64::from_le_bytes(
                        memory.read(entry + 8, 8)?.try_into().unwrap(),
                    ))
                    .map_err(|_| DaotiError::Other("sendmsg iov_len 溢出".into()))?;
                    let payload = memory.read(address, length as u64)?;
                    tx.lock()
                        .map_err(|_| DaotiError::Other("socket 发送缓冲锁中毒".into()))?
                        .extend(payload.iter().copied());
                    total += length;
                }
                return Ok(total as i64);
            }
            let Some(state) = self.sockets.get(&fd) else {
                unreachable!("已校验 sockets.contains_key");
            };
            let Some(rx) = state.rx.clone() else {
                return Ok(-11); // -EAGAIN：未连接 socket 无可读数据
            };
            // 先读取 iov 目标地址与容量（锁内不能持有 memory 的可变借用，先收集）。
            let mut targets = Vec::with_capacity(iov_count);
            let mut capacity_total = 0usize;
            for index in 0..iov_count {
                let entry = iov_base
                    .checked_add((index as u64).saturating_mul(16))
                    .ok_or_else(|| DaotiError::Other("recvmsg iovec 地址溢出".into()))?;
                let address = u64::from_le_bytes(memory.read(entry, 8)?.try_into().unwrap());
                let capacity = u64::from_le_bytes(memory.read(entry + 8, 8)?.try_into().unwrap());
                let capacity = usize::try_from(capacity)
                    .map_err(|_| DaotiError::Other("recvmsg iov_len 溢出".into()))?;
                capacity_total = capacity_total.saturating_add(capacity);
                targets.push((address, capacity));
            }
            // 一次性取出最多总容量的数据（超过部分丢弃，符合流语义）。
            let mut rx = rx
                .lock()
                .map_err(|_| DaotiError::Other("socket 接收缓冲锁中毒".into()))?;
            if rx.is_empty() {
                return Ok(-11); // -EAGAIN：空读缓冲
            }
            let take_total = capacity_total.min(rx.len());
            let data: Vec<u8> = rx.drain(..take_total).collect();
            drop(rx);
            let mut offset = 0usize;
            for (address, capacity) in targets {
                if offset >= data.len() {
                    break;
                }
                let take = capacity.min(data.len() - offset);
                memory.write(address, &data[offset..offset + take])?;
                offset += take;
            }
            // 回填 msg_namelen 与 msg_flags 为 0（无对端地址/无标志语义）。
            memory.write(header + 8, &0u64.to_le_bytes())?;
            memory.write(header + 48, &0u32.to_le_bytes())?;
            return Ok(offset as i64);
        }
        if event.nr == SYS_SENDTO || event.nr == SYS_RECVFROM {
            let fd = event.args[0] as i32;
            let buffer = event.args[1];
            let length = event.args[2];
            if !self.sockets.contains_key(&fd) {
                return Ok(-9); // -EBADF
            }
            if event.nr == SYS_SENDTO {
                let Some(state) = self.sockets.get_mut(&fd) else {
                    unreachable!("已校验 sockets.contains_key");
                };
                if state.shutdown & 0b10 != 0 {
                    return Ok(-32); // -EPIPE：写方向已关闭
                }
                let Some(tx) = state.tx.clone() else {
                    return Ok(-107); // -ENOTCONN：未连接 socket 无法发送
                };
                let payload = memory.read(buffer, length)?;
                tx.lock()
                    .map_err(|_| DaotiError::Other("socket 发送缓冲锁中毒".into()))?
                    .extend(payload);
                return Ok(length as i64);
            }
            let Some(state) = self.sockets.get(&fd) else {
                unreachable!("已校验 sockets.contains_key");
            };
            let Some(rx) = state.rx.clone() else {
                return Ok(-11); // -EAGAIN：未连接 socket 无可读数据
            };
            let mut rx = rx
                .lock()
                .map_err(|_| DaotiError::Other("socket 接收缓冲锁中毒".into()))?;
            let take = usize::try_from(length)
                .map_err(|_| DaotiError::Other("socket 接收长度超出平台范围".into()))?
                .min(rx.len());
            if take == 0 {
                return Ok(-11); // -EAGAIN：空读缓冲
            }
            let data: Vec<u8> = rx.drain(..take).collect();
            drop(rx);
            memory.write(buffer, &data)?;
            return Ok(take as i64);
        }
        if event.nr == SYS_GETSOCKNAME || event.nr == SYS_GETPEERNAME {
            // getsockname/getpeername(fd, sockaddr*, socklen_t*)：
            // 回填 16 字节 sockaddr_in（family u16 + port u16 大端 + 其余零），
            // getsockname 报告本机绑定端口（未绑定为 0），长度指针更新为 16。
            let fd = event.args[0] as i32;
            let addr_ptr = event.args[1];
            let len_ptr = event.args[2];
            let Some(state) = self.sockets.get(&fd) else {
                return Ok(-9); // -EBADF
            };
            let mut raw = [0u8; 16];
            raw[..2].copy_from_slice(&(state.family as u16).to_le_bytes());
            if event.nr == SYS_GETSOCKNAME {
                if let Some(port) = state.bound_port {
                    raw[2..4].copy_from_slice(&port.to_be_bytes());
                }
            }
            memory.write(addr_ptr, &raw)?;
            memory.write(len_ptr, &16u32.to_le_bytes())?;
            return Ok(0);
        }
        if event.nr == SYS_SETSOCKOPT || event.nr == SYS_GETSOCKOPT {
            // setsockopt(fd, level, optname, optval, optlen)：
            // 仅存储/回读原始字节，不假装应用任何网络策略（真实语义：选项记录存在）。
            let fd = event.args[0] as i32;
            let level = event.args[1] as u32;
            let optname = event.args[2] as u32;
            let Some(state) = self.sockets.get_mut(&fd) else {
                return Ok(-9); // -EBADF
            };
            if event.nr == SYS_SETSOCKOPT {
                let optlen = usize::try_from(event.args[4])
                    .map_err(|_| DaotiError::Other("setsockopt 选项长度溢出".into()))?;
                let value = memory.read(event.args[3], optlen as u64)?.to_vec();
                state.options.insert((level, optname), value);
            } else {
                // SO_TYPE（SOL_SOCKET=1, optname=3）恒返回创建时的类型，与 Linux 一致。
                let stored = if (level, optname) == (1, 3) && !state.options.contains_key(&(1, 3)) {
                    state.sock_type.to_le_bytes().to_vec()
                } else {
                    state
                        .options
                        .get(&(level, optname))
                        .cloned()
                        .unwrap_or_default()
                };
                let len_ptr = event.args[4];
                let capacity = usize::try_from(u32::from_le_bytes(
                    memory
                        .read(len_ptr, 4)?
                        .try_into()
                        .map_err(|_| DaotiError::Other("getsockopt 长度指针溢出".into()))?,
                ))
                .map_err(|_| DaotiError::Other("getsockopt 选项长度溢出".into()))?;
                let write_len = stored.len().min(capacity);
                memory.write(event.args[3], &stored[..write_len])?;
                memory.write(len_ptr, &(write_len as u32).to_le_bytes())?;
            }
            return Ok(0);
        }
        if event.nr == SYS_PIPE2 {
            if event.args[1] & !0x80000 != 0 {
                return Ok(-22); // -EINVAL，除 O_CLOEXEC 外不接受标志
            }
            let shared =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
            let read_fd = self.next_fd;
            let write_fd = self.next_fd + 1;
            self.next_fd += 2;
            self.pipes.insert(read_fd, (shared.clone(), false));
            self.pipes.insert(write_fd, (shared, true));
            let mut fds = [0u8; 8];
            fds[..4].copy_from_slice(&(read_fd as u32).to_le_bytes());
            fds[4..].copy_from_slice(&(write_fd as u32).to_le_bytes());
            memory.write(event.args[0], &fds)?;
            return Ok(0);
        }
        if event.nr == SYS_EVENTFD2 {
            if event.args[1] & !0x80000 != 0 {
                return Ok(-22); // -EINVAL
            }
            let fd = self.next_fd;
            self.next_fd += 1;
            self.eventfds.insert(fd, event.args[0]);
            return Ok(fd as i64);
        }
        if event.nr == SYS_TIMERFD_CREATE {
            // 仅支持 CLOCK_MONOTONIC=1；timerfd flags 只接受 O_CLOEXEC。
            if event.args[0] != 1 || event.args[1] & !0x80000 != 0 {
                return Ok(-22); // -EINVAL
            }
            let fd = self.next_fd;
            self.next_fd += 1;
            self.timerfds.insert(fd, None);
            return Ok(fd as i64);
        }
        if event.nr == SYS_TIMERFD_SETTIME {
            let fd = event.args[0] as i32;
            if !self.timerfds.contains_key(&fd) {
                return Ok(-9); // -EBADF
            }
            let spec = memory.read(event.args[2], 32)?;
            let sec = u64::from_le_bytes(spec[16..24].try_into().unwrap());
            let nsec = u64::from_le_bytes(spec[24..32].try_into().unwrap());
            if nsec >= 1_000_000_000 {
                return Ok(-22);
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?
                .as_nanos() as u64;
            self.timerfds.insert(
                fd,
                Some(now.saturating_add(sec.saturating_mul(1_000_000_000) + nsec)),
            );
            return Ok(0);
        }
        if event.nr == SYS_TIMERFD_GETTIME {
            let fd = event.args[0] as i32;
            let deadline = match self.timerfds.get(&fd) {
                Some(value) => *value,
                None => return Ok(-9),
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?
                .as_nanos() as u64;
            let remaining = deadline.map(|value| value.saturating_sub(now)).unwrap_or(0);
            let mut spec = [0u8; 32];
            spec[16..24].copy_from_slice(&(remaining / 1_000_000_000).to_le_bytes());
            spec[24..32].copy_from_slice(&(remaining % 1_000_000_000).to_le_bytes());
            memory.write(event.args[1], &spec)?;
            return Ok(0);
        }
        if event.nr == SYS_GETPPID
            || event.nr == SYS_GETUID
            || event.nr == SYS_GETEUID
            || event.nr == SYS_GETGID
            || event.nr == SYS_GETEGID
            || event.nr == SYS_GETPGID
            || event.nr == SYS_GETPGRP
            || event.nr == SYS_SETSID
        {
            // 单进程仿真：pid/tid/ppid/pgid/sid 稳定为 1，uid/gid 稳定为 1000。
            return match event.nr {
                SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => Ok(1000),
                _ => Ok(1),
            };
        }
        if event.nr == SYS_GETRESUID || event.nr == SYS_GETRESGID {
            // getresuid/getresgid 各写 3 个 u32（real/effective/saved）。
            for address in event.args[0..3].iter().take(3) {
                memory.write(*address, &1000u32.to_le_bytes())?;
            }
            return Ok(0);
        }
        if event.nr == SYS_SYSINFO {
            // struct sysinfo x86_64：uptime(0)/loads[3](8)/totalram(32)/freeram(40)/
            // sharedram(48)/bufferram(56)/totalswap(64)/freeswap(72)/procs(80 u16)/
            // mem_unit(104 u32)。
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?
                .as_secs();
            let mut info = [0u8; 112];
            info[0..8].copy_from_slice(&now.to_le_bytes());
            info[32..40].copy_from_slice(&(8u64 << 30).to_le_bytes()); // totalram=8GB
            info[40..48].copy_from_slice(&(4u64 << 30).to_le_bytes()); // freeram=4GB
            info[80..82].copy_from_slice(&1u16.to_le_bytes()); // procs=1
            info[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit=1
            memory.write(event.args[0], &info)?;
            return Ok(0);
        }
        if event.nr == SYS_UMASK {
            // umask(mask)：返回旧值并设置新值。
            let previous = self.umask;
            self.umask = (event.args[0] & 0o777) as u32;
            return Ok(previous as i64);
        }
        if event.nr == SYS_WAIT4 {
            // 单进程仿真无子进程：wait4 恒返回 -ECHILD。
            return Ok(-10);
        }
        if event.nr == SYS_GETCWD {
            // getcwd(buf, bufsiz)：返回 guest 视角当前目录（受控根内相对绝对路径）。
            let buf = event.args[0];
            let bufsiz = usize::try_from(event.args[1])
                .map_err(|_| DaotiError::Other("getcwd 大小超出平台范围".into()))?;
            let absolute = if self.current_dir.as_os_str().is_empty() {
                PathBuf::from("/")
            } else {
                Self::normalize_guest_absolute(&Path::new("/").join(&self.current_dir))
            };
            let bytes = absolute.to_string_lossy().as_bytes().to_vec();
            if bytes.len() + 1 > bufsiz {
                return Ok(-34); // -ERANGE
            }
            memory.write(buf, &bytes)?;
            memory.write(buf + bytes.len() as u64, &[0])?;
            return Ok(bytes.len() as i64);
        }
        if event.nr == SYS_CHDIR {
            // chdir(path)：仅允许进入受控根内真实存在的目录。
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(event.args[0] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("chdir 路径不是 UTF-8".into()))?,
            );
            let candidates = self.resolve_sandbox_candidates(path);
            if !candidates.iter().any(|candidate| candidate.is_dir()) {
                return Ok(-2); // -ENOENT
            }
            let joined = if path.is_absolute() {
                path.to_path_buf()
            } else if self.current_dir.as_os_str().is_empty() {
                PathBuf::from("/").join(path)
            } else {
                self.current_dir.join(path)
            };
            let absolute = Self::normalize_guest_absolute(&joined);
            self.current_dir = absolute
                .strip_prefix("/")
                .unwrap_or(&absolute)
                .to_path_buf();
            return Ok(0);
        }
        if event.nr == SYS_FSYNC {
            // fsync(fd)：快照文件已在内存，无需落盘同步；校验 fd 存在性。
            let fd = event.args[0] as i32;
            if !self.files.contains_key(&fd) {
                return Ok(-9); // -EBADF
            }
            return Ok(0);
        }
        if event.nr == SYS_FTRUNCATE {
            // ftruncate(fd, length)：调整文件快照长度（缩小截断、扩大补零），
            // 并将文件偏移钳制在文件末尾，避免后续 read 越界。
            let fd = event.args[0] as i32;
            let length = event.args[1];
            let (bytes, cursor) = self
                .files
                .get_mut(&fd)
                .ok_or_else(|| DaotiError::Other("无效文件描述符".into()))?;
            let length = usize::try_from(length)
                .map_err(|_| DaotiError::Other("ftruncate 长度超出平台范围".into()))?;
            if length < bytes.len() {
                bytes.truncate(length);
            } else {
                bytes.resize(length, 0);
            }
            if *cursor > length {
                *cursor = length;
            }
            return Ok(0);
        }
        if event.nr == SYS_TRUNCATE {
            // truncate(pathname, length)：按路径在受控根内真实截断文件。
            // 路径缺失返回 -ENOENT(-2)，无法解析的越界路径返回 -ENOENT；
            // 长度非负由 usize 转换保证，截断语义与 ftruncate 一致。
            let length = usize::try_from(event.args[1])
                .map_err(|_| DaotiError::Other("truncate 长度超出平台范围".into()))?;
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(event.args[0] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("truncate 路径不是 UTF-8".into()))?,
            );
            let Some(candidate) = self.resolve_guest_path(path) else {
                return Ok(-2); // -ENOENT：源不存在
            };
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&candidate)
                .map_err(DaotiError::Io)?;
            file.set_len(length as u64).map_err(DaotiError::Io)?;
            return Ok(0);
        }
        if event.nr == SYS_MKDIRAT {
            // mkdirat(dirfd, pathname, mode)：仅 AT_FDCWD，创建受控根内目录（mode 不模拟）。
            let dirfd = event.args[0] as i64;
            if dirfd != -100 {
                return Ok(-9); // -EBADF
            }
            let mode = event.args[2];
            if mode & !0o777 != 0 {
                return Err(DaotiError::Other("mkdirat mode 不是权限位".into()));
            }
            let mut raw = Vec::new();
            for index in 0..4096u64 {
                let byte = memory.read(event.args[1] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                raw.push(byte);
            }
            let path = Path::new(
                std::str::from_utf8(&raw)
                    .map_err(|_| DaotiError::Other("mkdirat 路径不是 UTF-8".into()))?,
            );
            let candidates = self.resolve_sandbox_candidates(path);
            if let Some(candidate) = candidates.first() {
                std::fs::create_dir(candidate).map_err(DaotiError::Io)?;
                return Ok(0);
            }
            return Ok(-2); // -ENOENT：无受控根
        }
        if event.nr == SYS_GETDENTS64 {
            // getdents64(fd, dirp, count)：向缓冲区写 Linux x86_64
            // struct dirent64（d_ino 8 + d_off 8 + d_reclen 2 + d_type 1 + d_name…），
            // 缓冲区不足时保留下次续读；目录读完返回 0。
            const DT_DIR: u8 = 4;
            const DT_REG: u8 = 8;
            let fd = event.args[0] as i32;
            let buf = event.args[1];
            let count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("getdents64 缓冲区大小超出平台范围".into()))?;
            let (dir_path, cursor) = self
                .dirs
                .get_mut(&fd)
                .ok_or_else(|| DaotiError::Other("无效目录文件描述符".into()))?;
            // count 小于最小对齐条目（24，供 "." 项：19 头部 + 1 名称 + 1 NUL，对齐 8）
            // 时返回 -EINVAL；真实内核同样拒绝过小缓冲区。
            if count < 24 {
                return Ok(-22); // -EINVAL
            }
            let mut entries: Vec<(Vec<u8>, u8)> =
                vec![(b".".to_vec(), DT_DIR), (b"..".to_vec(), DT_DIR)];
            let mut children: Vec<(Vec<u8>, u8)> = std::fs::read_dir(dir_path)
                .map_err(DaotiError::Io)?
                .filter_map(Result::ok)
                .map(|entry| {
                    let name = entry.file_name().to_string_lossy().as_bytes().to_vec();
                    let is_dir = entry
                        .file_type()
                        .map(|file_type| file_type.is_dir())
                        .unwrap_or(false);
                    (name, if is_dir { DT_DIR } else { DT_REG })
                })
                .collect();
            children.sort();
            entries.append(&mut children);
            let mut written = 0usize;
            let mut index = *cursor;
            while index < entries.len() {
                let (name, file_type) = &entries[index];
                // 头部 19 字节 + 名称（含 NUL），并按 8 字节对齐得到 d_reclen
                let raw_len = 19 + name.len() + 1;
                let aligned = (raw_len + 7) & !7;
                if written + aligned > count {
                    break;
                }
                let entry_start = written;
                // d_ino：稳定模拟号；d_off：下一项相对起点偏移
                memory.write(
                    buf + entry_start as u64,
                    &(1000u64 + index as u64).to_le_bytes(),
                )?;
                memory.write(
                    buf + entry_start as u64 + 8,
                    &((entry_start + aligned) as u64).to_le_bytes(),
                )?;
                memory.write(
                    buf + entry_start as u64 + 16,
                    &(aligned as u16).to_le_bytes(),
                )?;
                memory.write(buf + entry_start as u64 + 18, &[*file_type])?;
                memory.write(buf + entry_start as u64 + 19, name)?;
                memory.write(buf + entry_start as u64 + 19 + name.len() as u64, &[0])?;
                written += aligned;
                index += 1;
            }
            *cursor = index;
            return Ok(written as i64);
        }
        if event.nr == SYS_MUNMAP {
            // munmap(addr, len)：卸载映射区间，addr/len 必须页对齐。
            let addr = event.args[0];
            let len = event.args[1];
            if !is_page_aligned(addr) || !is_page_aligned(len) {
                return Ok(-22); // -EINVAL
            }
            return memory
                .unmap(addr, len)
                .map(|_| 0)
                .map_err(|_| DaotiError::Other("munmap 失败".into()));
        }
        if event.nr == SYS_MREMAP {
            // mremap(old_addr, old_size, new_size, flags[, new_addr])
            let flags = event.args[3];
            let fixed_addr = if flags & MREMAP_FIXED != 0 {
                Some(event.args[4])
            } else {
                None
            };
            let result = memory.remap(
                event.args[0],
                event.args[1],
                event.args[2],
                flags,
                fixed_addr,
            );
            return match result {
                Ok(address) => Ok(address as i64),
                Err(error) => {
                    let message = format!("{error}");
                    if message.contains("未映射") {
                        Ok(-14) // -EFAULT
                    } else if message.contains("空间不足") {
                        Ok(-12) // -ENOMEM
                    } else {
                        Ok(-22) // -EINVAL
                    }
                }
            };
        }
        if event.nr == SYS_MSYNC {
            // msync(addr, len, flags)：MS_ASYNC=1 / MS_INVALIDATE=2 / MS_SYNC=4。
            // 快照式内存已常驻且无宿主写回需求，映射存在即成功。
            const MS_ASYNC: u64 = 1;
            const MS_INVALIDATE: u64 = 2;
            const MS_SYNC: u64 = 4;
            let addr = event.args[0];
            let len = event.args[1];
            let flags = event.args[2];
            if !is_page_aligned(addr) || !is_page_aligned(len) {
                return Ok(-22); // -EINVAL
            }
            if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 {
                return Ok(-22); // -EINVAL
            }
            if !memory_range_partially_mapped(memory, addr, len) {
                return Ok(-12); // -ENOMEM：范围内无任何映射
            }
            return Ok(0);
        }
        if event.nr == SYS_MINICORE {
            // mincore(addr, len, vec)：每页一个字节，最低位 1 = 驻留。
            let addr = event.args[0];
            let len = event.args[1];
            let vec = event.args[2];
            if !is_page_aligned(addr) {
                return Ok(-22); // -EINVAL
            }
            if !memory_range_fully_mapped(memory, addr, len) {
                return Ok(-12); // -ENOMEM
            }
            let page_count = len.div_ceil(4096);
            memory.write(vec, &vec![0xff; page_count as usize])?;
            return Ok(0);
        }
        if event.nr == SYS_MLOCK || event.nr == SYS_MUNLOCK {
            // mlock/munlock(addr, len)：页对齐 + 范围内必须有映射，否则 -ENOMEM。
            let addr = event.args[0];
            let len = event.args[1];
            if !is_page_aligned(addr) {
                return Ok(-22); // -EINVAL
            }
            if !memory_range_partially_mapped(memory, addr, len) {
                return Ok(-12); // -ENOMEM
            }
            return Ok(0);
        }
        if event.nr == SYS_MLOCKALL {
            // mlockall(flags)：MCL_CURRENT=1 / MCL_FUTURE=2，未知位拒绝。
            let flags = event.args[0];
            if flags & !(1 | 2) != 0 {
                return Ok(-22); // -EINVAL
            }
            return Ok(0);
        }
        if event.nr == SYS_MUNLOCKALL {
            return Ok(0);
        }
        if event.nr == SYS_BRK {
            let raw = self.current_brk;
            let new_brk = event.args[0];
            // brk(0)：仅查询当前程序断点
            if new_brk == 0 {
                if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                    // 栈回溯：确定 brk(0) 调用者（libc __sbrk 还是 ld 静态代码）
                    let rsp = event.args[5]; // 不可靠，改用上一寄存器快照不可得；dump rbp
                    let _ = rsp;
                    eprintln!(
                        "TRACE bridge brk(0) -> 0x{raw:x} heap_end=0x{:x}",
                        self.heap_end
                    );
                }
                return Ok(raw as i64);
            }
            // brk(addr)：内核按页维护映射，但返回值保持请求的程序断点。
            if new_brk > self.heap_end {
                if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                    eprintln!(
                        "TRACE bridge brk(0x{new_brk:x}) REJECT -> 0x{raw:x} (heap_end=0x{:x})",
                        self.heap_end
                    );
                }
                return Ok(self.current_brk as i64);
            }
            self.current_brk = new_brk;
            if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                eprintln!("TRACE bridge brk(0x{new_brk:x}) -> 0x{new_brk:x} (old=0x{raw:x})");
            }
            return Ok(self.current_brk as i64);
        }
        if event.nr == SYS_GETRANDOM {
            let address = event.args[0];
            let length = usize::try_from(event.args[1])
                .map_err(|_| DaotiError::Other("getrandom 长度溢出".into()))?;
            let mut bytes = vec![0u8; length];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (address.wrapping_add(index as u64).wrapping_mul(0x9e37_79b9) >> 24) as u8;
            }
            memory.write(address, &bytes)?;
            return Ok(length as i64);
        }
        if event.nr == SYS_RT_SIGPROCMASK {
            let oldset = event.args[2];
            if oldset != 0 {
                memory.write(oldset, &[0u8; 128])?;
            }
            return Ok(0);
        }
        if event.nr == SYS_CLOCK_GETTIME {
            let address = event.args[1];
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?;
            let sec = now.as_secs().to_le_bytes();
            let nsec = now.subsec_nanos().to_le_bytes();
            let mut value = [0u8; 16];
            value[..8].copy_from_slice(&sec);
            value[8..12].copy_from_slice(&nsec);
            memory.write(address, &value)?;
            return Ok(0);
        }
        if event.nr == SYS_WRITEV {
            // writev(fd, iov, iovcnt)：聚合全部 iovec 段后，按与 write 相同的
            // 后端分派（pipe 写端扩展、eventfd 累加、socket 发送缓冲、stdout/stderr）。
            // 真实语义：未连接的 socket 写返回 -ENOTCONN，方向关闭返回 -EPIPE。
            let fd = event.args[0];
            let fd_i32 = fd as i32;
            let base = event.args[1];
            let count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("writev 数量溢出".into()))?;
            let mut aggregate = Vec::new();
            for i in 0..count {
                let raw = memory.read(base + (i as u64) * 16, 16)?;
                let address = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let length = usize::try_from(u64::from_le_bytes(raw[8..16].try_into().unwrap()))
                    .map_err(|_| DaotiError::Other("writev 长度溢出".into()))?;
                let data = memory.read(address, length as u64)?;
                aggregate.extend_from_slice(data);
            }
            if let Some((shared, is_write_end)) = self.pipes.get(&fd_i32) {
                if !*is_write_end {
                    return Ok(-9);
                }
                let mut buffer = shared
                    .lock()
                    .map_err(|_| DaotiError::Other("管道锁中毒".into()))?;
                buffer.extend(aggregate.iter().copied());
                return Ok(aggregate.len() as i64);
            }
            if let Some(counter) = self.eventfds.get_mut(&fd_i32) {
                if aggregate.len() < 8 {
                    return Ok(-22);
                }
                let value = u64::from_le_bytes(aggregate[0..8].try_into().unwrap());
                *counter = counter.saturating_add(value);
                return Ok(8);
            }
            if let Some(sock) = self.sockets.get_mut(&fd_i32) {
                if sock.shutdown & 0x2 != 0 {
                    return Ok(-32); // -EPIPE：写方向已关闭
                }
                let Some(tx) = &sock.tx else {
                    return Ok(-107); // -ENOTCONN：socketpair 未连接
                };
                let mut buffer = tx
                    .lock()
                    .map_err(|_| DaotiError::Other("socket 缓冲锁中毒".into()))?;
                buffer.extend(aggregate.iter().copied());
                return Ok(aggregate.len() as i64);
            }
            if fd != 1 && fd != 2 {
                return Err(DaotiError::Unavailable(format!(
                    "writev 仅支持 stdout/stderr，fd={fd}"
                )));
            }
            self.sink.write_all(&aggregate)?;
            return Ok(aggregate.len() as i64);
        }
        if event.nr == SYS_READV {
            // readv(fd, iov, iovcnt)：先按 fd 后端读取（pipe 读端 / eventfd /
            // timerfd / files），再按各 iovec 段分散写入 guest 内存。错误语义与
            // read 一致：空缓冲 -EAGAIN、写端 -EBADF、无效 fd -EBADF。
            let fd = event.args[0] as i32;
            let base = event.args[1];
            let count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("readv 数量溢出".into()))?;
            // 读取 iovec 段表，累计总请求长度。
            let mut segments = Vec::with_capacity(count);
            let mut requested = 0usize;
            for i in 0..count {
                let raw = memory.read(base + (i as u64) * 16, 16)?;
                let address = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let length = usize::try_from(u64::from_le_bytes(raw[8..16].try_into().unwrap()))
                    .map_err(|_| DaotiError::Other("readv 长度溢出".into()))?;
                requested = requested.saturating_add(length);
                segments.push((address, length));
            }
            // 从后端单次读取（语义与 read 相同）。
            let data: Vec<u8> = if let Some((shared, is_write_end)) = self.pipes.get(&fd) {
                if *is_write_end {
                    return Ok(-9); // -EBADF：写端不可读
                }
                let mut buffer = shared
                    .lock()
                    .map_err(|_| DaotiError::Other("管道锁中毒".into()))?;
                let take = requested.min(buffer.len());
                if take == 0 {
                    return Ok(-11); // -EAGAIN
                }
                buffer.drain(..take).collect()
            } else if let Some(counter) = self.eventfds.get_mut(&fd) {
                if requested < 8 {
                    return Ok(-22); // -EINVAL
                }
                if *counter == 0 {
                    return Ok(-11); // -EAGAIN
                }
                let value = *counter;
                *counter = 0;
                value.to_le_bytes().to_vec()
            } else if let Some(deadline) = self.timerfds.get_mut(&fd) {
                if requested < 8 {
                    return Ok(-22); // -EINVAL
                }
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| DaotiError::Other(format!("系统时间不可用：{e}")))?
                    .as_nanos() as u64;
                if deadline.is_none_or(|value| now < value) {
                    return Ok(-11); // -EAGAIN：未到期
                }
                *deadline = None;
                1u64.to_le_bytes().to_vec()
            } else if let Some((bytes, offset)) = self.files.get_mut(&fd) {
                let start = *offset;
                let take = requested.min(bytes.len().saturating_sub(start));
                *offset += take;
                bytes[start..start + take].to_vec()
            } else {
                return Ok(-9); // -EBADF：未知 fd
            };
            // 分散写入各 iovec 段。
            let mut cursor = 0usize;
            for (address, length) in segments {
                if cursor >= data.len() {
                    break;
                }
                let end = cursor.saturating_add(length).min(data.len());
                memory.write(address, &data[cursor..end])?;
                cursor = end;
            }
            return Ok(data.len() as i64);
        }
        if event.nr != SYS_WRITE {
            return self.handle(event);
        }
        let fd = event.args[0];
        let fd_i32 = fd as i32;
        if let Some((shared, is_write_end)) = self.pipes.get(&fd_i32) {
            if !*is_write_end {
                return Ok(-9);
            }
            let length = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("pipe write 长度溢出".into()))?;
            let data = memory.read(event.args[1], length as u64)?;
            let mut buffer = shared
                .lock()
                .map_err(|_| DaotiError::Other("管道锁中毒".into()))?;
            buffer.extend(data.iter().copied());
            return Ok(length as i64);
        }
        if let Some(counter) = self.eventfds.get_mut(&fd_i32) {
            if event.args[2] < 8 {
                return Ok(-22);
            }
            let data = memory.read(event.args[1], 8)?;
            let value = u64::from_le_bytes(data.try_into().unwrap());
            *counter = counter.saturating_add(value);
            return Ok(8);
        }
        if fd != 1 && fd != 2 {
            return Err(DaotiError::Unavailable(format!(
                "write 仅支持 stdout/stderr，fd={fd}"
            )));
        }
        let address = event.args[1];
        let length = usize::try_from(event.args[2])
            .map_err(|_| DaotiError::Other("write 长度超出平台 usize".into()))?;
        let data = memory.read(address, length as u64)?;
        self.sink.write_all(data)?;
        Ok(length as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::runtime::{
        ExecutionState, GeneralRegisters, MemPerm, RuntimeContext, X86_64Interpreter,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct BufferSink(Arc<Mutex<Vec<u8>>>);

    impl OutputSink for BufferSink {
        fn write_all(&mut self, data: &[u8]) -> Result<(), DaotiError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(data);
            Ok(())
        }
    }

    fn memory() -> MemoryModel {
        let mut memory = MemoryModel::new(0x1000, 0x3000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rwx(),
                vec![0; 0x1000],
            ))
            .unwrap();
        memory.write(0x1020, b"Hello, World!\n").unwrap();
        memory
    }

    #[test]
    fn write_reads_sandbox_memory() {
        let sink = BufferSink::default();
        let output = sink.0.clone();
        let mut bridge = NativeSyscallBridge::new(sink);
        let event = RuntimeSyscallEvent::enter(SYS_WRITE, "write", [1, 0x1020, 14, 0, 0, 0]);
        let mut memory = memory();
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 14);
        assert_eq!(&*output.lock().unwrap(), b"Hello, World!\n");
    }

    #[test]
    fn exit_requests_interpreter_exit() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let event = RuntimeSyscallEvent::enter(SYS_EXIT, "exit", [7, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle(&event).unwrap(), 0);
        assert_eq!(bridge.exit_code(), Some(7));
    }

    #[test]
    fn mmap_anonymous_private_allocates_zeroed_memory() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let event = RuntimeSyscallEvent::enter(
            SYS_MMAP,
            "mmap",
            [0, 1, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        let address = bridge.handle_with_memory(&event, &mut memory).unwrap();
        // topdown 分配：首次匿名映射取地址空间顶部页
        assert_eq!(address, 0x4000);
        assert_eq!(
            memory.read(address as u64, 4096).unwrap(),
            vec![0; 4096].as_slice()
        );
        assert!(memory.write(address as u64, &[0x5a]).is_ok());
    }

    #[test]
    fn mmap_rejects_non_anonymous_or_shared_mapping() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let event = RuntimeSyscallEvent::enter(SYS_MMAP, "mmap", [0, 4096, 0x3, 0, u64::MAX, 0]);
        assert!(bridge.handle_with_memory(&event, &mut memory).is_err());
    }

    #[test]
    fn brk_preserves_current_value_on_invalid_request() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default()).with_brk(0x2000, 0x4000);
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let query = RuntimeSyscallEvent::enter(SYS_BRK, "brk", [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&query, &mut memory).unwrap(),
            0x2000
        );
        let invalid = RuntimeSyscallEvent::enter(SYS_BRK, "brk", [0x5000, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&invalid, &mut memory).unwrap(),
            0x2000
        );
    }

    #[test]
    fn brk_expansion_makes_extended_heap_range_readable_and_writable() {
        // 堆区 [0x2000, 0x4000) 已按 8MiB 预映射（装载期整体建立，brk 只改断点数字）。
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        memory
            .add_region(MemoryRegion::with_data(
                0x2000,
                MemPerm::rw(),
                vec![0; 0x2000],
            ))
            .unwrap();
        let mut bridge = NativeSyscallBridge::new(BufferSink::default()).with_brk(0x2000, 0x4000);
        let query = RuntimeSyscallEvent::enter(SYS_BRK, "brk", [0, 0, 0, 0, 0, 0]);
        // 初始断点
        assert_eq!(
            bridge.handle_with_memory(&query, &mut memory).unwrap(),
            0x2000
        );
        // brk 扩展到 0x3000：返回新断点
        let extend = RuntimeSyscallEvent::enter(SYS_BRK, "brk", [0x3000, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&extend, &mut memory).unwrap(),
            0x3000
        );
        // 新增区间 [0x2000, 0x3000) 真实可读写（不依赖解释器容错路径）
        assert!(memory.write(0x2ff0, &[0x5a; 16]).is_ok());
        assert_eq!(memory.read(0x2ff0, 16).unwrap(), [0x5a; 16]);
        // 断点查询反映扩展
        assert_eq!(
            bridge.handle_with_memory(&query, &mut memory).unwrap(),
            0x3000
        );
        // 超界拒绝：保持旧断点且超界外不可访问
        let invalid = RuntimeSyscallEvent::enter(SYS_BRK, "brk", [0x5000, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&invalid, &mut memory).unwrap(),
            0x3000
        );
        assert!(memory.write(0x4500, &[1]).is_err());
        assert!(memory.read(0x4500, 1).is_err());
    }

    #[test]
    fn mprotect_changes_memory_permissions() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let map = RuntimeSyscallEvent::enter(
            SYS_MMAP,
            "mmap",
            [0, 4096, 3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        let address = bridge.handle_with_memory(&map, &mut memory).unwrap() as u64;
        let protect =
            RuntimeSyscallEvent::enter(SYS_MPROTECT, "mprotect", [address, 4096, 1, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&protect, &mut memory).unwrap(), 0);
        assert!(memory.write(address, &[1]).is_err());
        assert!(memory.read(address, 1).is_ok());
    }

    #[test]
    fn set_tid_address_records_clear_child_tid_and_returns_stable_tid() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let tid = RuntimeSyscallEvent::enter(SYS_SET_TID_ADDRESS, "set_tid_address", [0x1200; 6]);
        assert_eq!(bridge.handle(&tid).unwrap(), 1);
        assert_eq!(bridge.clear_child_tid, Some(0x1200));
        let tid_update =
            RuntimeSyscallEvent::enter(SYS_SET_TID_ADDRESS, "set_tid_address", [0x2400; 6]);
        assert_eq!(bridge.handle(&tid_update).unwrap(), 1);
        assert_eq!(bridge.clear_child_tid, Some(0x2400));
    }

    #[test]
    fn lseek_updates_file_offset_and_rejects_invalid_whence() {
        let sink = BufferSink::default();
        let mut bridge = NativeSyscallBridge::new(sink);
        bridge.files.insert(9, (b"abcdef".to_vec(), 0));
        let mut memory = memory();
        let seek = RuntimeSyscallEvent::enter(SYS_LSEEK, "lseek", [9, 2, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&seek, &mut memory).unwrap(), 2);
        let read = RuntimeSyscallEvent::enter(SYS_READ, "read", [9, 0x1100, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&read, &mut memory).unwrap(), 2);
        assert_eq!(memory.read(0x1100, 2).unwrap(), b"cd");

        let invalid = RuntimeSyscallEvent::enter(SYS_LSEEK, "lseek", [9, 0, 3, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&invalid, &mut memory).unwrap(),
            -22
        );
    }

    #[test]
    fn fcntl_getfl_returns_read_only_descriptor_flags() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        bridge.files.insert(9, (b"data".to_vec(), 0));
        let mut memory = memory();
        let event = RuntimeSyscallEvent::enter(SYS_FCNTL, "fcntl", [9, 3, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
    }

    #[test]
    fn statfs_and_fstatfs_write_linux_layout() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        bridge.files.insert(9, (b"data".to_vec(), 0));
        let mut memory = memory();
        for (nr, args) in [
            (SYS_STATFS, [0x1020, 0x1200, 0, 0, 0, 0]),
            (SYS_FSTATFS, [9, 0x1300, 0, 0, 0, 0]),
        ] {
            let event = RuntimeSyscallEvent::enter(nr, "statfs", args);
            assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        }
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1200, 8).unwrap().try_into().unwrap()),
            0x794c7630
        );
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1300, 8).unwrap().try_into().unwrap()),
            0x794c7630
        );
    }

    #[test]
    fn unlinkat_removes_only_files_under_allowed_root() {
        let root = std::env::temp_dir().join(format!("daoti-unlink-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("victim");
        std::fs::write(&file, b"x").unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b"victim\0").unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_UNLINKAT,
            "unlinkat",
            [-100i64 as u64, 0x1100, 0, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        assert!(!file.exists());
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn chdir_then_getcwd_reflects_sandbox_relative_dir() {
        let root = std::env::temp_dir().join(format!("daoti-cwd-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b"sub\0").unwrap();
        let chdir = RuntimeSyscallEvent::enter(SYS_CHDIR, "chdir", [0x1100, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&chdir, &mut memory).unwrap(), 0);
        let getcwd = RuntimeSyscallEvent::enter(SYS_GETCWD, "getcwd", [0x1200, 4096, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&getcwd, &mut memory).unwrap(), 4);
        assert_eq!(&memory.read(0x1200, 4).unwrap(), b"/sub");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mkdirat_creates_directory_under_allowed_root() {
        let root = std::env::temp_dir().join(format!("daoti-mkdir-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b"newdir\0").unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_MKDIRAT,
            "mkdirat",
            [-100i64 as u64, 0x1100, 0, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        assert!(root.join("newdir").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn renameat_moves_files_within_allowed_root() {
        let root = std::env::temp_dir().join(format!("daoti-rename-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("source"), b"payload").unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b"source\0").unwrap();
        memory.write(0x1200, b"renamed\0").unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_RENAMEAT,
            "renameat",
            [-100i64 as u64, 0x1100, -100i64 as u64, 0x1200, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        assert!(!root.join("source").exists());
        assert_eq!(std::fs::read(root.join("renamed")).unwrap(), b"payload");
        // 源缺失：renameat 应返回 -ENOENT(-2)
        let missing = RuntimeSyscallEvent::enter(
            SYS_RENAMEAT,
            "renameat",
            [-100i64 as u64, 0x1100, -100i64 as u64, 0x1240, 0, 0],
        );
        memory.write(0x1240, b"other\0").unwrap();
        assert_eq!(
            bridge.handle_with_memory(&missing, &mut memory).unwrap(),
            -2
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dup_shares_pipe_buffer_and_dup2_replaces_target_fd() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let create = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let read_fd = u32::from_le_bytes(memory.read(0x1200, 4).unwrap().try_into().unwrap());
        let write_fd = u32::from_le_bytes(memory.read(0x1204, 4).unwrap().try_into().unwrap());
        // dup(read_fd) → 新 fd 与 read_fd 共享同一管道缓冲
        let dup = RuntimeSyscallEvent::enter(SYS_DUP, "dup", [read_fd as u64, 0, 0, 0, 0, 0]);
        let dup_fd = bridge.handle_with_memory(&dup, &mut memory).unwrap();
        assert!(dup_fd > read_fd as i64);
        // 写入管道，dup 后的读端应能读到数据
        memory.write(0x1100, b"x").unwrap();
        let write =
            RuntimeSyscallEvent::enter(SYS_WRITE, "write", [write_fd as u64, 0x1100, 1, 0, 0, 0]);
        bridge.handle_with_memory(&write, &mut memory).unwrap();
        let read_dup =
            RuntimeSyscallEvent::enter(SYS_READ, "read", [dup_fd as u64, 0x1300, 8, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&read_dup, &mut memory).unwrap(),
            1
        );
        // dup2(read_fd, 9)：9 为新 fd，指向同一缓冲
        let dup2 = RuntimeSyscallEvent::enter(SYS_DUP2, "dup2", [read_fd as u64, 9, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&dup2, &mut memory).unwrap(), 9);
        // dup2 目标已存在：先关闭再复制（对管道 fd 生效）
        let dup2_replace =
            RuntimeSyscallEvent::enter(SYS_DUP2, "dup2", [read_fd as u64, 9, 0, 0, 0, 0]);
        assert_eq!(
            bridge
                .handle_with_memory(&dup2_replace, &mut memory)
                .unwrap(),
            9
        );
        // dup3 flags 非法 → -EINVAL
        let dup3_bad = RuntimeSyscallEvent::enter(
            SYS_DUP3,
            "dup3",
            [read_fd as u64, 10, 0x80000 | 0x1, 0, 0, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&dup3_bad, &mut memory).unwrap(),
            -22
        );
        // 未知 fd → -EBADF
        let dup_bad = RuntimeSyscallEvent::enter(SYS_DUP, "dup", [1234, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&dup_bad, &mut memory).unwrap(),
            -9
        );
    }

    #[test]
    fn readv_and_writev_scatter_gather_pipe() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // pipe2 创建管道
        let create = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let read_fd = u32::from_le_bytes(memory.read(0x1200, 4).unwrap().try_into().unwrap());
        let write_fd = u32::from_le_bytes(memory.read(0x1204, 4).unwrap().try_into().unwrap());
        // writev：两段 iovec 聚合写入管道（"AB" + "CD"）
        memory.write(0x1300, b"AB").unwrap();
        memory.write(0x1310, b"CD").unwrap();
        let iov = 0x1400u64;
        memory.write(iov, &(0x1300u64).to_le_bytes()).unwrap();
        memory.write(iov + 8, &2u64.to_le_bytes()).unwrap();
        memory.write(iov + 16, &(0x1310u64).to_le_bytes()).unwrap();
        memory.write(iov + 24, &2u64.to_le_bytes()).unwrap();
        let writev =
            RuntimeSyscallEvent::enter(SYS_WRITEV, "writev", [write_fd as u64, iov, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&writev, &mut memory).unwrap(), 4);
        // readv：两段 iovec 分散读取（每段 2 字节）
        let seg0 = 0x1500u64;
        let seg1 = 0x1520u64;
        memory.write(0x1500, b"__").unwrap();
        memory.write(0x1520, b"__").unwrap();
        let riov = 0x1410u64;
        memory.write(riov, &seg0.to_le_bytes()).unwrap();
        memory.write(riov + 8, &2u64.to_le_bytes()).unwrap();
        memory.write(riov + 16, &seg1.to_le_bytes()).unwrap();
        memory.write(riov + 24, &2u64.to_le_bytes()).unwrap();
        let readv =
            RuntimeSyscallEvent::enter(SYS_READV, "readv", [read_fd as u64, riov, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&readv, &mut memory).unwrap(), 4);
        assert_eq!(memory.read(0x1500, 2).unwrap(), b"AB");
        assert_eq!(memory.read(0x1520, 2).unwrap(), b"CD");
        // 空管道 readv → -EAGAIN
        let empty =
            RuntimeSyscallEvent::enter(SYS_READV, "readv", [read_fd as u64, riov, 1, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&empty, &mut memory).unwrap(), -11);
        // 写端 readv → -EBADF
        let bad =
            RuntimeSyscallEvent::enter(SYS_READV, "readv", [write_fd as u64, riov, 1, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -9);
    }

    #[test]
    fn truncate_resizes_file_within_allowed_root() {
        let root = std::env::temp_dir().join(format!("daoti-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("target"), b"0123456789").unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b"target\0").unwrap();
        // 截断到 4 字节：应真实缩小文件
        let trunc = RuntimeSyscallEvent::enter(SYS_TRUNCATE, "truncate", [0x1100, 4, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&trunc, &mut memory).unwrap(), 0);
        assert_eq!(std::fs::read(root.join("target")).unwrap(), b"0123");
        // 扩展到 6 字节：应补零
        let extend = RuntimeSyscallEvent::enter(SYS_TRUNCATE, "truncate", [0x1100, 6, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&extend, &mut memory).unwrap(), 0);
        assert_eq!(std::fs::read(root.join("target")).unwrap(), b"0123\0\0");
        // 缺失路径：-ENOENT(-2)
        memory.write(0x1200, b"nope\0").unwrap();
        let missing = RuntimeSyscallEvent::enter(SYS_TRUNCATE, "truncate", [0x1200, 4, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&missing, &mut memory).unwrap(),
            -2
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn statx_reads_real_metadata_within_allowed_root() {
        let root = std::env::temp_dir().join(format!("daoti-statx-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("data"), b"0123456789").unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b"data\0").unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_STATX,
            "statx",
            [-100i64 as u64, 0x1100, 0, 0, 0x1200, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        // size@40 = 10；mode@28 低位 = S_IFREG(0o100000)|0o644
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1228, 8).unwrap().try_into().unwrap()),
            10
        );
        let mode = u16::from_le_bytes(memory.read(0x121c, 2).unwrap().try_into().unwrap());
        assert_eq!(mode, 0o100000u16 | 0o644);
        // 缺失路径：-ENOENT(-2)
        memory.write(0x1100, b"missing\0").unwrap();
        let missing = RuntimeSyscallEvent::enter(
            SYS_STATX,
            "statx",
            [-100i64 as u64, 0x1100, 0, 0, 0x1200, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&missing, &mut memory).unwrap(),
            -2
        );
        // 非法 dirfd：-EBADF(-9)
        let bad = RuntimeSyscallEvent::enter(SYS_STATX, "statx", [7u64, 0x1100, 0, 0, 0x1200, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -9);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fsync_validates_descriptor() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        bridge.files.insert(9, (b"data".to_vec(), 0));
        let mut memory = memory();
        let ok = RuntimeSyscallEvent::enter(SYS_FSYNC, "fsync", [9, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&ok, &mut memory).unwrap(), 0);
        let bad = RuntimeSyscallEvent::enter(SYS_FSYNC, "fsync", [999, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -9);
    }

    #[test]
    fn ftruncate_adjusts_snapshot_size_and_keeps_offset_in_bounds() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        bridge.files.insert(9, (b"abcdef".to_vec(), 5));
        let mut memory = memory();
        let shrink = RuntimeSyscallEvent::enter(SYS_FTRUNCATE, "ftruncate", [9, 3, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&shrink, &mut memory).unwrap(), 0);
        let bytes = &bridge.files.get(&9).unwrap().0;
        assert_eq!(bytes, b"abc");
        assert!(bridge.files.get(&9).unwrap().1 <= 3);
        let grow = RuntimeSyscallEvent::enter(SYS_FTRUNCATE, "ftruncate", [9, 8, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&grow, &mut memory).unwrap(), 0);
        assert_eq!(bridge.files.get(&9).unwrap().0, b"abc\0\0\0\0\0");
    }

    #[test]
    fn getdents64_enumerates_directory_entries_with_linux_layout() {
        let root = std::env::temp_dir().join(format!("daoti-dents-{}", std::process::id()));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        std::fs::write(root.join("b"), b"y").unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        // 打开目录句柄（"." 解析到受控根）
        memory.write(0x1100, b".\0").unwrap();
        let open = RuntimeSyscallEvent::enter(
            SYS_OPENAT,
            "openat",
            [-100i64 as u64, 0x1100, 0x10000, 0, 0, 0],
        );
        let fd = bridge.handle_with_memory(&open, &mut memory).unwrap() as i32;
        assert!(fd >= 3);
        let mut names: Vec<(String, u8)> = Vec::new();
        loop {
            let event = RuntimeSyscallEvent::enter(
                SYS_GETDENTS64,
                "getdents64",
                [fd as u64, 0x1300, 4096, 0, 0, 0],
            );
            let n = bridge.handle_with_memory(&event, &mut memory).unwrap();
            assert!(n >= 0);
            if n == 0 {
                break;
            }
            let mut offset = 0usize;
            while (offset as u64) < (n as u64) {
                let reclen = u16::from_le_bytes(
                    memory
                        .read(0x1300 + offset as u64 + 16, 2)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ) as usize;
                let file_type = memory.read(0x1300 + offset as u64 + 18, 1).unwrap()[0];
                let name_len = reclen.saturating_sub(19);
                let raw = memory
                    .read(0x1300 + offset as u64 + 19, name_len as u64)
                    .unwrap();
                let name = String::from_utf8(raw.to_vec())
                    .unwrap()
                    .trim_end_matches('\0')
                    .to_string();
                names.push((name, file_type));
                offset += reclen;
            }
        }
        let type_of: std::collections::HashMap<&str, u8> = names
            .iter()
            .map(|(name, ty)| (name.as_str(), *ty))
            .collect();
        assert_eq!(type_of.get("."), Some(&4)); // DT_DIR
        assert_eq!(type_of.get(".."), Some(&4));
        assert_eq!(type_of.get("a.txt"), Some(&8)); // DT_REG
        assert_eq!(type_of.get("b"), Some(&8));
        assert_eq!(type_of.get("sub"), Some(&4)); // DT_DIR
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fstat_reports_directory_mode_for_dir_fd() {
        let root = std::env::temp_dir().join(format!("daoti-fstat-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b".\0").unwrap();
        let open =
            RuntimeSyscallEvent::enter(SYS_OPENAT, "openat", [-100i64 as u64, 0x1100, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&open, &mut memory).unwrap() as i32;
        let stat = RuntimeSyscallEvent::enter(SYS_FSTAT, "fstat", [fd as u64, 0x1200, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&stat, &mut memory).unwrap(), 0);
        // struct stat：st_mode 位于偏移 24；S_IFDIR=0o040000
        let mode = u32::from_le_bytes(memory.read(0x1218, 4).unwrap().try_into().unwrap());
        assert_eq!(mode & 0o170000, 0o040000);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn close_returns_ebadf_for_unknown_descriptor() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        bridge.files.insert(9, (b"data".to_vec(), 0));
        let mut memory = memory();
        let known = RuntimeSyscallEvent::enter(SYS_CLOSE, "close", [9, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&known, &mut memory).unwrap(), 0);
        let unknown = RuntimeSyscallEvent::enter(SYS_CLOSE, "close", [1234, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&unknown, &mut memory).unwrap(),
            -9
        );
    }

    #[test]
    fn lseek_past_eof_then_read_returns_zero() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        bridge.files.insert(9, (b"abcdef".to_vec(), 0));
        let mut memory = memory();
        // SEEK_END(2) + 8 → 14，越过 6 字节 EOF
        let seek = RuntimeSyscallEvent::enter(SYS_LSEEK, "lseek", [9, 8, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&seek, &mut memory).unwrap(), 14);
        // EOF 之外 read 返回 0（不报错、不越界写）
        let read = RuntimeSyscallEvent::enter(SYS_READ, "read", [9, 0x1100, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&read, &mut memory).unwrap(), 0);
    }

    #[test]
    fn getdents64_rejects_tiny_buffer() {
        let root = std::env::temp_dir().join(format!("daoti-dents-tiny-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1100, b".\0").unwrap();
        let open = RuntimeSyscallEvent::enter(
            SYS_OPENAT,
            "openat",
            [-100i64 as u64, 0x1100, 0x10000, 0, 0, 0],
        );
        let fd = bridge.handle_with_memory(&open, &mut memory).unwrap() as i32;
        // count 过小（< 最小对齐条目 24）返回 -EINVAL，而不是 0（0 会被误判为读完）
        let tiny = RuntimeSyscallEvent::enter(
            SYS_GETDENTS64,
            "getdents64",
            [fd as u64, 0x1300, 8, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&tiny, &mut memory).unwrap(), -22);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn munmap_releases_region_and_isolates_split() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        let map = RuntimeSyscallEvent::enter(
            SYS_MMAP,
            "mmap",
            [0, 0x3000, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        let base = bridge.handle_with_memory(&map, &mut memory).unwrap() as u64;
        assert!(memory.write(base, &[1]).is_ok());
        assert!(memory.write(base + 0x2000, &[2]).is_ok());
        // 卸载中间页 [base+0x1000, base+0x2000)
        let unmap =
            RuntimeSyscallEvent::enter(SYS_MUNMAP, "munmap", [base + 0x1000, 0x1000, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&unmap, &mut memory).unwrap(), 0);
        // 前缀/后缀仍可访问，中间页已不可访问
        assert!(memory.read(base, 1).is_ok());
        assert!(memory.read(base + 0x2000, 1).is_ok());
        assert!(memory.read(base + 0x1000, 1).is_err());
        assert!(memory.write(base + 0x1000, &[3]).is_err());
    }

    #[test]
    fn munmap_unmapped_range_silently_succeeds() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        // [0x3000, 0x4000) 从未映射：munmap 静默成功返回 0
        let event = RuntimeSyscallEvent::enter(SYS_MUNMAP, "munmap", [0x3000, 0x1000, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        // 非法参数：长度非页对齐 → -EINVAL
        let invalid = RuntimeSyscallEvent::enter(SYS_MUNMAP, "munmap", [0x3000, 0x500, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&invalid, &mut memory).unwrap(),
            -22
        );
    }

    #[test]
    fn msync_accepts_mapped_range_and_validates_flags() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let map = RuntimeSyscallEvent::enter(
            SYS_MMAP,
            "mmap",
            [0, 0x1000, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        let base = bridge.handle_with_memory(&map, &mut memory).unwrap() as u64;
        // MS_ASYNC=1 / MS_SYNC=4 对已映射私有匿名页返回 0
        for flags in [1u64, 4] {
            let event =
                RuntimeSyscallEvent::enter(SYS_MSYNC, "msync", [base, 0x1000, flags, 0, 0, 0]);
            assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        }
        // 非法 flags → -EINVAL
        let bad = RuntimeSyscallEvent::enter(SYS_MSYNC, "msync", [base, 0x1000, 0x100, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -22);
        // 未映射范围 → -ENOMEM
        let missing = RuntimeSyscallEvent::enter(SYS_MSYNC, "msync", [0x3000, 0x1000, 1, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&missing, &mut memory).unwrap(),
            -12
        );
    }

    #[test]
    fn mincore_reports_all_resident_pages() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let map = RuntimeSyscallEvent::enter(
            SYS_MMAP,
            "mmap",
            [0, 0x2000, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        let base = bridge.handle_with_memory(&map, &mut memory).unwrap() as u64;
        // mincore(base, 0x2000, vec)：2 页全部驻留 → vec 两字节最低位均为 1
        let event =
            RuntimeSyscallEvent::enter(SYS_MINICORE, "mincore", [base, 0x2000, 0x1100, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        assert_eq!(memory.read(0x1100, 2).unwrap(), [0xff, 0xff]);
    }

    #[test]
    fn mlock_family_validates_arguments() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let map = RuntimeSyscallEvent::enter(
            SYS_MMAP,
            "mmap",
            [0, 0x1000, 0x3, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        let base = bridge.handle_with_memory(&map, &mut memory).unwrap() as u64;
        // mlock / munlock：已映射页返回 0；未映射页返回 -ENOMEM
        let lock = RuntimeSyscallEvent::enter(SYS_MLOCK, "mlock", [base, 0x1000, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&lock, &mut memory).unwrap(), 0);
        let unlock = RuntimeSyscallEvent::enter(SYS_MUNLOCK, "munlock", [base, 0x1000, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&unlock, &mut memory).unwrap(), 0);
        let missing = RuntimeSyscallEvent::enter(SYS_MLOCK, "mlock", [0x3000, 0x1000, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&missing, &mut memory).unwrap(),
            -12
        );
        // mlockall：MCL_CURRENT(1)|MCL_FUTURE(2) 合法；未知位返回 -EINVAL
        let all = RuntimeSyscallEvent::enter(SYS_MLOCKALL, "mlockall", [3, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&all, &mut memory).unwrap(), 0);
        let bad = RuntimeSyscallEvent::enter(SYS_MLOCKALL, "mlockall", [0x100, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -22);
        let all_clear =
            RuntimeSyscallEvent::enter(SYS_MUNLOCKALL, "munlockall", [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&all_clear, &mut memory).unwrap(),
            0
        );
    }

    #[test]
    fn mremap_grows_in_place_when_space_available() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x2000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        // 原地扩展 [0x2000,0x3000) → [0x2000,0x4000)：上方无 region 且不越界
        let event =
            RuntimeSyscallEvent::enter(SYS_MREMAP, "mremap", [0x2000, 0x1000, 0x2000, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&event, &mut memory).unwrap(),
            0x2000
        );
        assert!(memory.write(0x3000, &[0x5a]).is_ok());
        assert_eq!(memory.read(0x3000, 1).unwrap(), [0x5a]);
    }

    #[test]
    fn mremap_shrinks_in_place_releasing_tail() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x2000,
                MemPerm::rw(),
                vec![0; 0x2000],
            ))
            .unwrap();
        // 收缩 [0x2000,0x4000) → [0x2000,0x3000)：返回原地址，尾部释放
        let event =
            RuntimeSyscallEvent::enter(SYS_MREMAP, "mremap", [0x2000, 0x2000, 0x1000, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&event, &mut memory).unwrap(),
            0x2000
        );
        assert!(memory.read(0x2000, 1).is_ok());
        assert!(memory.read(0x3000, 1).is_err());
    }

    #[test]
    fn mremap_moves_with_maymove_preserving_content() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        // 阻碍原地扩展的占位 region + 待移动 region
        memory
            .add_region(MemoryRegion::with_data(
                0x3000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        memory
            .add_region(MemoryRegion::with_data(0x2000, MemPerm::rw(), {
                let mut bytes = vec![0u8; 0x1000];
                bytes[..7].copy_from_slice(b"payload");
                bytes
            }))
            .unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_MREMAP,
            "mremap",
            [0x2000, 0x1000, 0x2000, MREMAP_MAYMOVE, 0, 0],
        );
        let new_addr = bridge.handle_with_memory(&event, &mut memory).unwrap() as u64;
        assert_ne!(new_addr, 0x2000);
        // 新地址内容保留、旧地址释放
        assert_eq!(memory.read(new_addr, 7).unwrap(), b"payload");
        assert!(memory.read(0x2000, 1).is_err());
    }

    #[test]
    fn mremap_without_maymove_returns_enomem_when_blocked() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x3000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        memory
            .add_region(MemoryRegion::with_data(
                0x2000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        // 无法原地扩展且未指定 MAYMOVE → -ENOMEM
        let event =
            RuntimeSyscallEvent::enter(SYS_MREMAP, "mremap", [0x2000, 0x1000, 0x2000, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), -12);
    }

    #[test]
    fn mremap_fixed_places_at_hint_and_releases_old() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(0x2000, MemPerm::rw(), {
                let mut bytes = vec![0u8; 0x1000];
                bytes[..6].copy_from_slice(b"hello!");
                bytes
            }))
            .unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_MREMAP,
            "mremap",
            [
                0x2000,
                0x1000,
                0x1000,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                0x5000,
                0,
            ],
        );
        assert_eq!(
            bridge.handle_with_memory(&event, &mut memory).unwrap(),
            0x5000
        );
        assert_eq!(memory.read(0x5000, 6).unwrap(), b"hello!");
        assert!(memory.read(0x2000, 1).is_err());
    }

    #[test]
    fn mremap_rejects_invalid_or_unmapped_args() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x2000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        // 非页对齐长度 → -EINVAL
        let unaligned =
            RuntimeSyscallEvent::enter(SYS_MREMAP, "mremap", [0x2000, 0x500, 0x1000, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&unaligned, &mut memory).unwrap(),
            -22
        );
        // 未映射起始地址 → -EFAULT
        let unmapped =
            RuntimeSyscallEvent::enter(SYS_MREMAP, "mremap", [0x6000, 0x1000, 0x1000, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&unmapped, &mut memory).unwrap(),
            -14
        );
    }

    #[test]
    fn process_identity_queries_return_stable_values() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        for (nr, expected) in [
            (SYS_GETPPID, 1),
            (SYS_GETUID, 1000),
            (SYS_GETEUID, 1000),
            (SYS_GETGID, 1000),
            (SYS_GETEGID, 1000),
            (SYS_GETPGID, 1),
            (SYS_GETPGRP, 1),
            (SYS_SETSID, 1),
        ] {
            let event = RuntimeSyscallEvent::enter(nr, "process-query", [0; 6]);
            assert_eq!(
                bridge.handle_with_memory(&event, &mut memory).unwrap(),
                expected,
                "syscall nr={nr}"
            );
        }
    }

    #[test]
    fn getresuid_and_getresgid_write_three_ids() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // getresuid(ruid, euid, suid)
        let event = RuntimeSyscallEvent::enter(
            SYS_GETRESUID,
            "getresuid",
            [0x1100, 0x1110, 0x1120, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        for addr in [0x1100u64, 0x1110, 0x1120] {
            assert_eq!(
                u32::from_le_bytes(memory.read(addr, 4).unwrap().try_into().unwrap()),
                1000
            );
        }
        // getresgid(rgid, egid, sgid)
        let event = RuntimeSyscallEvent::enter(
            SYS_GETRESGID,
            "getresgid",
            [0x1130, 0x1140, 0x1150, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        for addr in [0x1130u64, 0x1140, 0x1150] {
            assert_eq!(
                u32::from_le_bytes(memory.read(addr, 4).unwrap().try_into().unwrap()),
                1000
            );
        }
    }

    #[test]
    fn sysinfo_writes_linux_layout() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let event = RuntimeSyscallEvent::enter(SYS_SYSINFO, "sysinfo", [0x1200, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 0);
        // struct sysinfo x86_64：uptime(0)/loads[3](8)/totalram(32)/freeram(40)/procs(80 u16)/mem_unit(104 u32)
        let uptime = u64::from_le_bytes(memory.read(0x1200, 8).unwrap().try_into().unwrap());
        let totalram = u64::from_le_bytes(memory.read(0x1220, 8).unwrap().try_into().unwrap());
        let procs = u16::from_le_bytes(memory.read(0x1250, 2).unwrap().try_into().unwrap());
        let mem_unit = u32::from_le_bytes(memory.read(0x1268, 4).unwrap().try_into().unwrap());
        assert!(uptime > 0);
        assert!(totalram > 0);
        assert!(procs >= 1);
        assert!(mem_unit >= 1);
    }

    #[test]
    fn umask_sets_and_returns_previous() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // 初始 022
        let query = RuntimeSyscallEvent::enter(SYS_UMASK, "umask", [0o077, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&query, &mut memory).unwrap(),
            0o22
        );
        // 再次设置 0 → 返回上次值 077
        let query = RuntimeSyscallEvent::enter(SYS_UMASK, "umask", [0, 0, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&query, &mut memory).unwrap(),
            0o77
        );
    }

    #[test]
    fn wait4_without_children_returns_echild() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let event = RuntimeSyscallEvent::enter(SYS_WAIT4, "wait4", [0, 0x1100, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), -10);
    }

    #[test]
    fn pipe2_flows_bytes_and_blocks_empty_read() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let create = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&create, &mut memory).unwrap(), 0);
        let fds: [u32; 2] = [
            u32::from_le_bytes(memory.read(0x1200, 4).unwrap().try_into().unwrap()),
            u32::from_le_bytes(memory.read(0x1204, 4).unwrap().try_into().unwrap()),
        ];
        assert_ne!(fds[0], fds[1]);
        // 写端写入
        memory.write(0x1100, b"hello").unwrap();
        let write =
            RuntimeSyscallEvent::enter(SYS_WRITE, "write", [fds[1] as u64, 0x1100, 5, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&write, &mut memory).unwrap(), 5);
        // 读端读出
        let read =
            RuntimeSyscallEvent::enter(SYS_READ, "read", [fds[0] as u64, 0x1120, 16, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&read, &mut memory).unwrap(), 5);
        assert_eq!(&memory.read(0x1120, 5).unwrap(), b"hello");
        // 空管道读 → EAGAIN
        let empty =
            RuntimeSyscallEvent::enter(SYS_READ, "read", [fds[0] as u64, 0x1120, 16, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&empty, &mut memory).unwrap(), -11);
    }

    #[test]
    fn eventfd2_counter_accumulates_and_clears_on_read() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let create = RuntimeSyscallEvent::enter(SYS_EVENTFD2, "eventfd2", [0, 0, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&create, &mut memory).unwrap() as i32;
        assert!(fd >= 3);
        // 写 3 再写 2 → 计数 5
        memory.write(0x1100, &3u64.to_le_bytes()).unwrap();
        let w1 = RuntimeSyscallEvent::enter(SYS_WRITE, "write", [fd as u64, 0x1100, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&w1, &mut memory).unwrap(), 8);
        memory.write(0x1100, &2u64.to_le_bytes()).unwrap();
        let w3 = RuntimeSyscallEvent::enter(SYS_WRITE, "write", [fd as u64, 0x1100, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&w3, &mut memory).unwrap(), 8);
        // 读 → 5 并清零
        let read = RuntimeSyscallEvent::enter(SYS_READ, "read", [fd as u64, 0x1120, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&read, &mut memory).unwrap(), 8);
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1120, 8).unwrap().try_into().unwrap()),
            5
        );
        // 清零后再读 → EAGAIN
        let again = RuntimeSyscallEvent::enter(SYS_READ, "read", [fd as u64, 0x1120, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&again, &mut memory).unwrap(), -11);
    }

    #[test]
    fn timerfd_settime_and_gettime_roundtrip() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let create =
            RuntimeSyscallEvent::enter(SYS_TIMERFD_CREATE, "timerfd_create", [1, 0, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&create, &mut memory).unwrap() as i32;
        assert!(fd >= 3);
        // 设置 10ms 定时（itimerspec：it_interval[0..16] + it_value[16..32]，
        // it_value.tv_sec=[16..24], tv_nsec=[24..32]）
        let mut spec = [0u8; 32];
        spec[24..28].copy_from_slice(&10_000_000u32.to_le_bytes());
        memory.write(0x1300, &spec).unwrap();
        let settime = RuntimeSyscallEvent::enter(
            SYS_TIMERFD_SETTIME,
            "timerfd_settime",
            [fd as u64, 0, 0x1300, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&settime, &mut memory).unwrap(), 0);
        // gettime 查询剩余时间（>=1ns）
        let gettime = RuntimeSyscallEvent::enter(
            SYS_TIMERFD_GETTIME,
            "timerfd_gettime",
            [fd as u64, 0x1400, 0, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&gettime, &mut memory).unwrap(), 0);
        let remaining_ns = u64::from_le_bytes(memory.read(0x1410, 8).unwrap().try_into().unwrap())
            + u64::from_le_bytes(memory.read(0x1418, 8).unwrap().try_into().unwrap());
        assert!(remaining_ns > 0);
    }

    #[test]
    fn poll_reports_pipe_and_stdout_readiness() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let create = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let read_fd = u32::from_le_bytes(memory.read(0x1200, 4).unwrap().try_into().unwrap());
        let write_fd = u32::from_le_bytes(memory.read(0x1204, 4).unwrap().try_into().unwrap());
        memory.write(0x1100, b"x").unwrap();
        let write =
            RuntimeSyscallEvent::enter(SYS_WRITE, "write", [write_fd as u64, 0x1100, 1, 0, 0, 0]);
        bridge.handle_with_memory(&write, &mut memory).unwrap();
        // pollfd：pipe 读端监听 POLLIN，stdout 监听 POLLOUT
        memory
            .write(0x1300, &(read_fd as i32).to_le_bytes())
            .unwrap();
        memory.write(0x1304, &1u16.to_le_bytes()).unwrap();
        memory.write(0x1306, &[0, 0]).unwrap();
        memory.write(0x1308, &1i32.to_le_bytes()).unwrap();
        memory.write(0x130c, &4u16.to_le_bytes()).unwrap();
        memory.write(0x130e, &[0, 0]).unwrap();
        let poll = RuntimeSyscallEvent::enter(SYS_POLL, "poll", [0x1300, 2, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&poll, &mut memory).unwrap(), 2);
        assert_eq!(
            u16::from_le_bytes(memory.read(0x1306, 2).unwrap().try_into().unwrap()),
            1
        );
        assert_eq!(
            u16::from_le_bytes(memory.read(0x130e, 2).unwrap().try_into().unwrap()),
            4
        );
    }

    #[test]
    fn poll_rejects_unreadable_pollfd_array() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x2000);
        let poll = RuntimeSyscallEvent::enter(SYS_POLL, "poll", [0x1800, 1, 0, 0, 0, 0]);
        assert!(bridge.handle_with_memory(&poll, &mut memory).is_err());
    }

    #[test]
    fn select_updates_fd_sets_for_pipe_and_stdout() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let create = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let read_fd = u64::from(u32::from_le_bytes(
            memory.read(0x1200, 4).unwrap().try_into().unwrap(),
        ));
        let write_fd = u64::from(u32::from_le_bytes(
            memory.read(0x1204, 4).unwrap().try_into().unwrap(),
        ));
        memory.write(0x1100, b"x").unwrap();
        let write = RuntimeSyscallEvent::enter(SYS_WRITE, "write", [write_fd, 0x1100, 1, 0, 0, 0]);
        bridge.handle_with_memory(&write, &mut memory).unwrap();
        // fd_set 的第 0 个 64 位 word：pipe 读端和 stdout 写端
        let mut read_set = [0u8; 128];
        let mut write_set = [0u8; 128];
        read_set[(read_fd as usize / 8) * 8..(read_fd as usize / 8 + 1) * 8]
            .copy_from_slice(&(1u64 << (read_fd % 64)).to_le_bytes());
        write_set[0..8].copy_from_slice(&2u64.to_le_bytes()); // stdout fd=1
        memory.write(0x1400, &read_set).unwrap();
        memory.write(0x1480, &write_set).unwrap();
        let event = RuntimeSyscallEvent::enter(
            SYS_SELECT,
            "select",
            [write_fd + 1, 0x1400, 0x1480, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&event, &mut memory).unwrap(), 2);
        assert_ne!(
            u64::from_le_bytes(
                memory
                    .read(0x1400 + (read_fd / 8) * 8, 8)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            0
        );
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1480, 8).unwrap().try_into().unwrap()),
            2
        );
    }

    #[test]
    fn epoll_registers_pipe_write_end_and_returns_event() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let pipe = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&pipe, &mut memory).unwrap();
        let write_fd = u64::from(u32::from_le_bytes(
            memory.read(0x1204, 4).unwrap().try_into().unwrap(),
        ));
        let epfd = bridge
            .handle_with_memory(
                &RuntimeSyscallEvent::enter(SYS_EPOLL_CREATE1, "epoll_create1", [0, 0, 0, 0, 0, 0]),
                &mut memory,
            )
            .unwrap() as i32;
        memory.write(0x1300, &(4u32).to_le_bytes()).unwrap();
        memory.write(0x1308, &0x55u64.to_le_bytes()).unwrap();
        let ctl = RuntimeSyscallEvent::enter(
            SYS_EPOLL_CTL,
            "epoll_ctl",
            [epfd as u64, 1, write_fd, 0x1300, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&ctl, &mut memory).unwrap(), 0);
        let wait = RuntimeSyscallEvent::enter(
            SYS_EPOLL_WAIT,
            "epoll_wait",
            [epfd as u64, 0x1400, 1, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&wait, &mut memory).unwrap(), 1);
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1408, 8).unwrap().try_into().unwrap()),
            0x55
        );
    }

    #[test]
    fn access_returns_enoent_for_unavailable_runtime_probe() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let event = RuntimeSyscallEvent::enter(SYS_ACCESS, "access", [0x1000, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle(&event).unwrap(), -2);
    }

    #[test]
    fn faccessat_reuses_sandbox_access_semantics() {
        let root = std::env::temp_dir().join(format!("daoti-faccessat-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("probe"), b"ok").unwrap();
        let mut bridge =
            NativeSyscallBridge::new(BufferSink::default()).with_allowed_roots(&[root.clone()]);
        let mut memory = memory();
        memory.write(0x1200, b"/probe\0").unwrap();
        let readable = RuntimeSyscallEvent::enter(
            SYS_FACCESSAT,
            "faccessat",
            [u64::MAX - 99, 0x1200, 4, 0, 0, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&readable, &mut memory).unwrap(),
            0
        );
        memory.write(0x1240, b"/missing\0").unwrap();
        let missing = RuntimeSyscallEvent::enter(
            SYS_FACCESSAT,
            "faccessat",
            [u64::MAX - 99, 0x1240, 4, 0, 0, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&missing, &mut memory).unwrap(),
            -2
        );
        let bad_dirfd =
            RuntimeSyscallEvent::enter(SYS_FACCESSAT, "faccessat", [3, 0x1200, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&bad_dirfd, &mut memory).unwrap(),
            -9
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn unsupported_abi_paths_are_rejected_or_real() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let futex = RuntimeSyscallEvent::enter(SYS_FUTEX, "futex", [0, 2, 0, 0, 0, 0]);
        assert!(bridge.handle(&futex).is_err());
        let set_fs = RuntimeSyscallEvent::enter(
            SYS_ARCH_PRCTL,
            "arch_prctl",
            [ARCH_SET_FS, 0x1800, 0, 0, 0, 0],
        );
        assert_eq!(bridge.handle(&set_fs).unwrap(), 0);
        let mut memory = memory();
        let get_fs = RuntimeSyscallEvent::enter(
            SYS_ARCH_PRCTL,
            "arch_prctl",
            [ARCH_GET_FS, 0x1100, 0, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&get_fs, &mut memory).unwrap(), 0);
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1100, 8).unwrap().try_into().unwrap()),
            0x1800
        );
    }

    #[test]
    fn unknown_syscall_is_rejected() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let event = RuntimeSyscallEvent::enter(999, "unknown", [0; 6]);
        assert!(bridge.handle(&event).is_err());
    }

    #[test]
    fn shadow_observer_records_prediction_without_changing_execution() {
        let network = BilateralLadderNetwork::new(
            ndarray::Array2::eye(16),
            ndarray::Array2::eye(16),
            ndarray::Array1::zeros(16),
            0,
        )
        .unwrap();
        let codec = SyscallCodec::new(
            16,
            vec![crate::bilateral::weights::OpEntry {
                nr: SYS_GETPID as i32,
                name: "getpid".into(),
                windows_op: "GetCurrentProcessId".into(),
            }],
        )
        .unwrap();
        let records = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observer = shadow_inference_observer(network, codec, records.clone());
        let mut bridge = NativeSyscallBridge::new(BufferSink::default()).with_observer(observer);
        let event = RuntimeSyscallEvent::enter(SYS_GETPID, "getpid", [0; 6]);
        assert_eq!(bridge.handle(&event).unwrap(), 1);
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].nr, SYS_GETPID);
        assert_eq!(
            records[0].prediction.as_deref(),
            Some("GetCurrentProcessId")
        );
        assert_eq!(records[0].actual_result, Some(1));
        assert!(records[0].actual_success);
        assert!(records[0].actual_error.is_none());
    }

    #[test]
    fn observer_records_failed_actual_result() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = seen.clone();
        let mut bridge = NativeSyscallBridge::new(BufferSink::default()).with_observer(Box::new(
            move |event, result| {
                captured.lock().unwrap().push((event.nr, result.is_err()));
            },
        ));
        let event = RuntimeSyscallEvent::enter(999, "unknown", [0; 6]);
        assert!(bridge.handle(&event).is_err());
        assert_eq!(*seen.lock().unwrap(), vec![(999, true)]);
    }

    #[test]
    fn observer_sees_syscall_without_changing_return_value() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = seen.clone();
        let mut bridge = NativeSyscallBridge::new(BufferSink::default()).with_observer(Box::new(
            move |event, _result| {
                captured.lock().unwrap().push(event.nr);
            },
        ));
        let event = RuntimeSyscallEvent::enter(SYS_GETPID, "getpid", [0; 6]);
        assert_eq!(bridge.handle(&event).unwrap(), 1);
        assert_eq!(*seen.lock().unwrap(), vec![SYS_GETPID]);
    }

    #[test]
    fn socket_allocs_fd_and_rejects_unknown_family() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // AF_INET=2, SOCK_STREAM=1, protocol=0 → 分配新 fd
        let create = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&create, &mut memory).unwrap();
        assert!(fd >= 3);
        // 未知 family → -EAFNOSUPPORT(-97)
        let bad = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [99, 1, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -97);
    }

    #[test]
    fn socketpair_linked_fds_transfer_bytes_both_ways() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, fds[2]@0x1100)
        let create =
            RuntimeSyscallEvent::enter(SYS_SOCKETPAIR, "socketpair", [1, 1, 0, 0x1100, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&create, &mut memory).unwrap(), 0);
        let fd_a = i64::from(u32::from_le_bytes(
            memory.read(0x1100, 4).unwrap().try_into().unwrap(),
        ));
        let fd_b = i64::from(u32::from_le_bytes(
            memory.read(0x1104, 4).unwrap().try_into().unwrap(),
        ));
        assert_ne!(fd_a, fd_b);
        // A 向 B 发送 "hi"：sendto(fd_a, src, 2, flags, NULL, 0)
        memory.write(0x1200, b"hi").unwrap();
        let send =
            RuntimeSyscallEvent::enter(SYS_SENDTO, "sendto", [fd_a as u64, 0x1200, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&send, &mut memory).unwrap(), 2);
        // B 接收：recvfrom(fd_b, dst, 8, 0, NULL, NULL)
        let recv =
            RuntimeSyscallEvent::enter(SYS_RECVFROM, "recvfrom", [fd_b as u64, 0x1300, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&recv, &mut memory).unwrap(), 2);
        assert_eq!(memory.read(0x1300, 2).unwrap(), b"hi");
        // 反向 B→A
        memory.write(0x1200, b"ok").unwrap();
        let send_b =
            RuntimeSyscallEvent::enter(SYS_SENDTO, "sendto", [fd_b as u64, 0x1200, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&send_b, &mut memory).unwrap(), 2);
        let recv_a =
            RuntimeSyscallEvent::enter(SYS_RECVFROM, "recvfrom", [fd_a as u64, 0x1300, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&recv_a, &mut memory).unwrap(), 2);
        assert_eq!(memory.read(0x1300, 2).unwrap(), b"ok");
    }

    #[test]
    fn unconnected_socket_send_returns_real_errors() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let create = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&create, &mut memory).unwrap();
        // 未连接 socket 发送 → -ENOTCONN(-107)
        memory.write(0x1200, b"x").unwrap();
        let send =
            RuntimeSyscallEvent::enter(SYS_SENDTO, "sendto", [fd as u64, 0x1200, 1, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&send, &mut memory).unwrap(), -107);
        // 空读缓冲 → -EAGAIN(-11)
        let recv =
            RuntimeSyscallEvent::enter(SYS_RECVFROM, "recvfrom", [fd as u64, 0x1300, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&recv, &mut memory).unwrap(), -11);
        // 未知 fd → -EBADF(-9)
        let bad = RuntimeSyscallEvent::enter(SYS_RECVFROM, "recvfrom", [1234, 0x1300, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -9);
    }

    #[test]
    fn shutdown_marks_direction_and_blocks_transfer() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let create =
            RuntimeSyscallEvent::enter(SYS_SOCKETPAIR, "socketpair", [1, 1, 0, 0x1100, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let fd_a = i64::from(u32::from_le_bytes(
            memory.read(0x1100, 4).unwrap().try_into().unwrap(),
        ));
        // shutdown(fd_a, SHUT_WR=1) → A 不能再发送
        let shutdown =
            RuntimeSyscallEvent::enter(SYS_SHUTDOWN, "shutdown", [fd_a as u64, 1, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&shutdown, &mut memory).unwrap(),
            0
        );
        memory.write(0x1200, b"x").unwrap();
        let send =
            RuntimeSyscallEvent::enter(SYS_SENDTO, "sendto", [fd_a as u64, 0x1200, 1, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&send, &mut memory).unwrap(), -32); // -EPIPE
                                                                                 // 非法 how → -EINVAL(-22)
        let bad =
            RuntimeSyscallEvent::enter(SYS_SHUTDOWN, "shutdown", [fd_a as u64, 7, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bad, &mut memory).unwrap(), -22);
    }

    #[test]
    fn default_sockaddr_has_unix_family_and_socketpair_shares_linked_state() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let create = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&create, &mut memory).unwrap();
        // getsockname(fd, sockaddr@0x1300, len@0x1400)；sockaddr_in 前 2 字节 family
        memory.write(0x1400, &16u32.to_le_bytes()).unwrap();
        let name = RuntimeSyscallEvent::enter(
            SYS_GETSOCKNAME,
            "getsockname",
            [fd as u64, 0x1300, 0x1400, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&name, &mut memory).unwrap(), 0);
        assert_eq!(
            u16::from_le_bytes(memory.read(0x1300, 2).unwrap().try_into().unwrap()),
            2 // AF_INET 保留真实 family
        );
        assert_eq!(
            u32::from_le_bytes(memory.read(0x1400, 4).unwrap().try_into().unwrap()),
            16
        );
    }

    #[test]
    fn setsockopt_stores_and_getsockopt_reads_back() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let create = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&create, &mut memory).unwrap();
        // setsockopt(fd, SOL_SOCKET=1, SO_REUSEADDR=2, val=1, len=4)
        memory.write(0x1200, &1u32.to_le_bytes()).unwrap();
        let set = RuntimeSyscallEvent::enter(
            SYS_SETSOCKOPT,
            "setsockopt",
            [fd as u64, 1, 2, 0x1200, 4, 0],
        );
        assert_eq!(bridge.handle_with_memory(&set, &mut memory).unwrap(), 0);
        // getsockopt：需要 optlen 指针回填 4
        memory.write(0x1400, &4u32.to_le_bytes()).unwrap();
        let get = RuntimeSyscallEvent::enter(
            SYS_GETSOCKOPT,
            "getsockopt",
            [fd as u64, 1, 2, 0x1300, 0x1400, 0],
        );
        assert_eq!(bridge.handle_with_memory(&get, &mut memory).unwrap(), 0);
        assert_eq!(
            u32::from_le_bytes(memory.read(0x1300, 4).unwrap().try_into().unwrap()),
            1
        );
    }

    #[test]
    fn bind_listen_connect_accept4_establishes_loopback_stream() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // 服务端：socket(AF_INET=2, SOCK_STREAM=1) → bind(端口 8080 大端 0x1f90) → listen
        let listen_sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let server = bridge
            .handle_with_memory(&listen_sock, &mut memory)
            .unwrap();
        // sockaddr_in：family(2 字节小端=2) + port(2 字节大端=8080) + addr(4) + 填充
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes());
        sockaddr[2..4].copy_from_slice(&8080u16.to_be_bytes());
        memory.write(0x1500, &sockaddr).unwrap();
        let bind =
            RuntimeSyscallEvent::enter(SYS_BIND, "bind", [server as u64, 0x1500, 16, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bind, &mut memory).unwrap(), 0);
        let listen =
            RuntimeSyscallEvent::enter(SYS_LISTEN, "listen", [server as u64, 8, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&listen, &mut memory).unwrap(), 0);
        // 客户端：socket + connect 到 8080
        let client_sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let client = bridge
            .handle_with_memory(&client_sock, &mut memory)
            .unwrap();
        let connect = RuntimeSyscallEvent::enter(
            SYS_CONNECT,
            "connect",
            [client as u64, 0x1500, 16, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&connect, &mut memory).unwrap(), 0);
        // accept4 返回连接好的新 fd
        memory.write(0x1600, &16u32.to_le_bytes()).unwrap();
        let accept = RuntimeSyscallEvent::enter(
            SYS_ACCEPT4,
            "accept4",
            [server as u64, 0x1700, 0x1600, 0, 0, 0],
        );
        let conn = bridge.handle_with_memory(&accept, &mut memory).unwrap();
        assert!(conn >= 3);
        assert_eq!(
            u32::from_le_bytes(memory.read(0x1600, 4).unwrap().try_into().unwrap()),
            16
        );
        // 客户端 → 服务端：sendto(client,"hi") → recvfrom(conn)
        memory.write(0x1200, b"hi").unwrap();
        let send =
            RuntimeSyscallEvent::enter(SYS_SENDTO, "sendto", [client as u64, 0x1200, 2, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&send, &mut memory).unwrap(), 2);
        let recv =
            RuntimeSyscallEvent::enter(SYS_RECVFROM, "recvfrom", [conn as u64, 0x1300, 8, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&recv, &mut memory).unwrap(), 2);
        assert_eq!(memory.read(0x1300, 2).unwrap(), b"hi");
        // 服务端 → 客户端：sendto(conn,"ok") → recvfrom(client)
        memory.write(0x1200, b"ok").unwrap();
        let send_back =
            RuntimeSyscallEvent::enter(SYS_SENDTO, "sendto", [conn as u64, 0x1200, 2, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&send_back, &mut memory).unwrap(),
            2
        );
        let recv_back = RuntimeSyscallEvent::enter(
            SYS_RECVFROM,
            "recvfrom",
            [client as u64, 0x1300, 8, 0, 0, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&recv_back, &mut memory).unwrap(),
            2
        );
        assert_eq!(memory.read(0x1300, 2).unwrap(), b"ok");
    }

    #[test]
    fn connect_to_unbound_port_returns_ecnrefused() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let client_sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let client = bridge
            .handle_with_memory(&client_sock, &mut memory)
            .unwrap();
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes());
        sockaddr[2..4].copy_from_slice(&9999u16.to_be_bytes());
        memory.write(0x1500, &sockaddr).unwrap();
        let connect = RuntimeSyscallEvent::enter(
            SYS_CONNECT,
            "connect",
            [client as u64, 0x1500, 16, 0, 0, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&connect, &mut memory).unwrap(),
            -111
        );
    }

    #[test]
    fn bind_rejects_conflict_and_listen_rejects_unknown_fd() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&sock, &mut memory).unwrap();
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes());
        sockaddr[2..4].copy_from_slice(&8888u16.to_be_bytes());
        memory.write(0x1500, &sockaddr).unwrap();
        let bind = RuntimeSyscallEvent::enter(SYS_BIND, "bind", [fd as u64, 0x1500, 16, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bind, &mut memory).unwrap(), 0);
        // 第二个 socket 绑定同一端口 → -EADDRINUSE(-98)
        let sock2 = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd2 = bridge.handle_with_memory(&sock2, &mut memory).unwrap();
        let bind2 = RuntimeSyscallEvent::enter(SYS_BIND, "bind", [fd2 as u64, 0x1500, 16, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&bind2, &mut memory).unwrap(), -98);
        // listen 未知 fd → -EBADF(-9)
        let bad_listen = RuntimeSyscallEvent::enter(SYS_LISTEN, "listen", [1234, 8, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&bad_listen, &mut memory).unwrap(),
            -9
        );
    }

    #[test]
    fn accept4_empty_queue_returns_eagain() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&sock, &mut memory).unwrap();
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes());
        sockaddr[2..4].copy_from_slice(&7777u16.to_be_bytes());
        memory.write(0x1500, &sockaddr).unwrap();
        let bind = RuntimeSyscallEvent::enter(SYS_BIND, "bind", [fd as u64, 0x1500, 16, 0, 0, 0]);
        bridge.handle_with_memory(&bind, &mut memory).unwrap();
        let listen = RuntimeSyscallEvent::enter(SYS_LISTEN, "listen", [fd as u64, 8, 0, 0, 0, 0]);
        bridge.handle_with_memory(&listen, &mut memory).unwrap();
        let accept = RuntimeSyscallEvent::enter(
            SYS_ACCEPT4,
            "accept4",
            [fd as u64, 0x1700, 0x1600, 0, 0, 0],
        );
        assert_eq!(
            bridge.handle_with_memory(&accept, &mut memory).unwrap(),
            -11
        );
    }

    #[test]
    fn getsockname_reports_bound_port() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&sock, &mut memory).unwrap();
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes());
        sockaddr[2..4].copy_from_slice(&2222u16.to_be_bytes());
        memory.write(0x1500, &sockaddr).unwrap();
        let bind = RuntimeSyscallEvent::enter(SYS_BIND, "bind", [fd as u64, 0x1500, 16, 0, 0, 0]);
        bridge.handle_with_memory(&bind, &mut memory).unwrap();
        memory.write(0x1400, &16u32.to_le_bytes()).unwrap();
        let name = RuntimeSyscallEvent::enter(
            SYS_GETSOCKNAME,
            "getsockname",
            [fd as u64, 0x1300, 0x1400, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&name, &mut memory).unwrap(), 0);
        assert_eq!(
            u16::from_be_bytes(memory.read(0x1302, 2).unwrap().try_into().unwrap()),
            2222
        );
    }

    #[test]
    fn ppoll_reports_same_readiness_as_poll() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let create = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let read_fd = u32::from_le_bytes(memory.read(0x1200, 4).unwrap().try_into().unwrap());
        let write_fd = u32::from_le_bytes(memory.read(0x1204, 4).unwrap().try_into().unwrap());
        memory.write(0x1100, b"x").unwrap();
        let write =
            RuntimeSyscallEvent::enter(SYS_WRITE, "write", [write_fd as u64, 0x1100, 1, 0, 0, 0]);
        bridge.handle_with_memory(&write, &mut memory).unwrap();
        // ppoll(pollfd@0x1300, 1, NULL, NULL, 0)：监听 pipe 读端 POLLIN
        memory
            .write(0x1300, &(read_fd as i32).to_le_bytes())
            .unwrap();
        memory.write(0x1304, &1u16.to_le_bytes()).unwrap();
        memory.write(0x1306, &[0, 0]).unwrap();
        let ppoll = RuntimeSyscallEvent::enter(SYS_PPOLL, "ppoll", [0x1300, 1, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&ppoll, &mut memory).unwrap(), 1);
        assert_eq!(
            u16::from_le_bytes(memory.read(0x1306, 2).unwrap().try_into().unwrap()),
            1
        );
    }

    #[test]
    fn epoll_pwait_returns_registered_pipe_event() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let pipe = RuntimeSyscallEvent::enter(SYS_PIPE2, "pipe2", [0x1200, 0, 0, 0, 0, 0]);
        bridge.handle_with_memory(&pipe, &mut memory).unwrap();
        let write_fd = u64::from(u32::from_le_bytes(
            memory.read(0x1204, 4).unwrap().try_into().unwrap(),
        ));
        let epfd = bridge
            .handle_with_memory(
                &RuntimeSyscallEvent::enter(SYS_EPOLL_CREATE1, "epoll_create1", [0, 0, 0, 0, 0, 0]),
                &mut memory,
            )
            .unwrap() as i32;
        memory.write(0x1300, &(4u32).to_le_bytes()).unwrap();
        memory.write(0x1308, &0x42u64.to_le_bytes()).unwrap();
        let ctl = RuntimeSyscallEvent::enter(
            SYS_EPOLL_CTL,
            "epoll_ctl",
            [epfd as u64, 1, write_fd, 0x1300, 0, 0],
        );
        bridge.handle_with_memory(&ctl, &mut memory).unwrap();
        // epoll_pwait(epfd, events@0x1400, 1, -1, NULL, 0)
        let pwait = RuntimeSyscallEvent::enter(
            SYS_EPOLL_PWAIT,
            "epoll_pwait",
            [epfd as u64, 0x1400, 1, 0, 0, 0],
        );
        assert_eq!(bridge.handle_with_memory(&pwait, &mut memory).unwrap(), 1);
        assert_eq!(
            u64::from_le_bytes(memory.read(0x1408, 8).unwrap().try_into().unwrap()),
            0x42
        );
    }

    #[test]
    fn sendmsg_recvmsg_transfers_iovec_payload_over_socketpair() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        // socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, fds@0x1100)
        let create =
            RuntimeSyscallEvent::enter(SYS_SOCKETPAIR, "socketpair", [1, 1, 0, 0x1100, 0, 0]);
        bridge.handle_with_memory(&create, &mut memory).unwrap();
        let fd_a = i64::from(u32::from_le_bytes(
            memory.read(0x1100, 4).unwrap().try_into().unwrap(),
        ));
        let fd_b = i64::from(u32::from_le_bytes(
            memory.read(0x1104, 4).unwrap().try_into().unwrap(),
        ));
        // 载荷分散在两段 iov：0x1200="he"，0x1210="llo"
        memory.write(0x1200, b"he").unwrap();
        memory.write(0x1210, b"llo").unwrap();
        // iovec 数组（16 字节/项）@0x1300：base(8) + len(8)
        memory.write(0x1300, &0x1200u64.to_le_bytes()).unwrap();
        memory.write(0x1308, &2u64.to_le_bytes()).unwrap();
        memory.write(0x1310, &0x1210u64.to_le_bytes()).unwrap();
        memory.write(0x1318, &3u64.to_le_bytes()).unwrap();
        // msghdr（x86_64 56 字节）@0x1400：name(8)+namelen(8)+iov(8)+iovlen(8)+control(8)+controllen(8)+flags(4)
        memory.write(0x1400, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1408, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1410, &0x1300u64.to_le_bytes()).unwrap();
        memory.write(0x1418, &2u64.to_le_bytes()).unwrap();
        memory.write(0x1420, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1428, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1430, &0u32.to_le_bytes()).unwrap();
        // A 用 sendmsg 发送聚合后的 "hello"
        let sendmsg =
            RuntimeSyscallEvent::enter(SYS_SENDMSG, "sendmsg", [fd_a as u64, 0x1400, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&sendmsg, &mut memory).unwrap(), 5);
        // B 用 recvmsg 接收：msghdr@0x1510（name 偏移0, namelen 偏移8, iov 偏移16, iovlen 偏移24），
        // iov 数组@0x1500 指向 0x1600 容量 8。
        memory.write(0x1500, &0x1600u64.to_le_bytes()).unwrap();
        memory.write(0x1508, &8u64.to_le_bytes()).unwrap();
        memory.write(0x1510, &0u64.to_le_bytes()).unwrap(); // msg_name=NULL
        memory.write(0x1518, &0u64.to_le_bytes()).unwrap(); // msg_namelen=0
        memory.write(0x1520, &0x1500u64.to_le_bytes()).unwrap(); // msg_iov=数组
        memory.write(0x1528, &1u64.to_le_bytes()).unwrap(); // msg_iovlen=1
        let recvmsg =
            RuntimeSyscallEvent::enter(SYS_RECVMSG, "recvmsg", [fd_b as u64, 0x1510, 0, 0, 0, 0]);
        assert_eq!(bridge.handle_with_memory(&recvmsg, &mut memory).unwrap(), 5);
        assert_eq!(memory.read(0x1600, 5).unwrap(), b"hello");
    }

    #[test]
    fn sendmsg_on_unconnected_socket_returns_enotconn() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let mut memory = memory();
        let sock = RuntimeSyscallEvent::enter(SYS_SOCKET, "socket", [2, 1, 0, 0, 0, 0]);
        let fd = bridge.handle_with_memory(&sock, &mut memory).unwrap();
        // 空 msghdr（iov=0, iovlen=0）
        memory.write(0x1400, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1408, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1410, &0u64.to_le_bytes()).unwrap();
        memory.write(0x1418, &0u64.to_le_bytes()).unwrap();
        let sendmsg =
            RuntimeSyscallEvent::enter(SYS_SENDMSG, "sendmsg", [fd as u64, 0x1400, 0, 0, 0, 0]);
        assert_eq!(
            bridge.handle_with_memory(&sendmsg, &mut memory).unwrap(),
            -107
        );
    }

    #[test]
    fn interpreter_can_use_bridge() {
        let sink = BufferSink::default();
        let bridge = NativeSyscallBridge::new(sink);
        let mut memory = memory();
        memory
            .add_region(MemoryRegion::with_data(
                0x2000,
                MemPerm::rwx(),
                vec![0; 0x100],
            ))
            .unwrap();
        memory
            .write(0x2000, &[0xb8, SYS_EXIT as u8, 0, 0, 0, 0x0f, 0x05])
            .unwrap();
        let mut context = RuntimeContext::new(0x2000, 0x1080, memory);
        context.registers.general = GeneralRegisters::new(0x2000, 0x1080);
        let mut interpreter =
            X86_64Interpreter::new(context).with_syscall_handler(Box::new(bridge));
        let result = interpreter.run();
        assert!(result.is_ok(), "解释器运行失败：{result:?}");
        assert!(
            matches!(interpreter.context.state, ExecutionState::Exited(0)),
            "实际状态：{:?}",
            interpreter.context.state
        );
    }
}
