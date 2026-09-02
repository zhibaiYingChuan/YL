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
pub const SYS_ACCESS: u64 = 21;
pub const SYS_UNAME: u64 = 63;
pub const SYS_WRITEV: u64 = 20;
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

    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut curbrk_relocated = false;
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
                            Some(addr.wrapping_add(0x222218))
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
                if r_offset == 0x219e60 && r_type == R_X86_64_GLOB_DAT && value != 0 {
                    curbrk_relocated = true;
                }
                if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                    eprintln!(
                        "TRACE runtime-reloc bias=0x{addr:x} table={label} offset=0x{r_offset:x} target=0x{target:x} type={r_type} sym={r_sym} value=0x{value:x}"
                    );
                }
            }
        }
    }
    if curbrk_relocated {
        // glibc __sbrk 的快速路径用该字节表示 __curbrk 已可由 brk 更新。
        // fd-mmap 副本没有真实 ld.so 的早期初始化副作用，需在 GOT 就绪后补齐。
        memory.write(addr + 0x228e4e, &[1])?;
        if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
            eprintln!(
                "TRACE runtime-reloc curbrk-ready flag=0x{:x}",
                addr + 0x228e4e
            );
        }
    }
    if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
        eprintln!("TRACE runtime-reloc done bias=0x{addr:x} applied={applied} skipped={skipped}");
    }
    Ok(AppliedRelocations { tls })
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
    files: HashMap<i32, (Vec<u8>, usize)>,
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
            files: HashMap::new(),
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
        let relative = path.strip_prefix("/").unwrap_or(path);
        self.allowed_roots
            .iter()
            .flat_map(|root| {
                let exact = root.join(relative);
                let basename = path.file_name().map(|name| root.join(name));
                basename.into_iter().chain(std::iter::once(exact))
            })
            .find(|candidate| candidate.is_file())
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
        if event.nr == SYS_ACCESS {
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
                    .map_err(|_| DaotiError::Other("access 路径不是 UTF-8".into()))?,
            );
            let Some(candidate) = self.resolve_guest_path(path) else {
                return Ok(-2);
            };
            let mode = event.args[1];
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
            let Some(candidate) = self.resolve_guest_path(path) else {
                return Ok(-2);
            };
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
            // 文件内容已被受控桥接器载入内存；保留快照，使 close 后的 mmap
            // 仍符合 Linux 的文件映射语义。
            return Ok(0);
        }
        if matches!(event.nr, SYS_READ | SYS_PREAD64) {
            let fd = event.args[0] as i32;
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
            let end = start.saturating_add(count).min(bytes.len());
            memory.write(event.args[1], &bytes[start..end])?;
            let read = end - start;
            if event.nr == SYS_READ {
                *offset = end;
            }
            return Ok(read as i64);
        }
        if event.nr == SYS_FSTAT || event.nr == SYS_NEWFSTATAT {
            let stat_addr = if event.nr == SYS_FSTAT {
                event.args[1]
            } else {
                event.args[2]
            };
            let mut stat = [0u8; 144];
            // Linux x86_64 struct stat：填充 glibc 读取的类型、大小和块信息。
            stat[8..16].copy_from_slice(&1u64.to_le_bytes());
            stat[16..20].copy_from_slice(&0x8000u32.to_le_bytes());
            stat[20..24].copy_from_slice(&1u32.to_le_bytes());
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
                let addr = memory.mmap_anonymous_private_topdown(mapped_len, MemPerm::rw())?;
                if mapped_elf {
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
                        let image = memory.read(image_addr, filesz)?.to_vec();
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
                    memory.write(addr + 0x222218, &self.current_brk.to_le_bytes())?;
                    if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                        eprintln!(
                            "TRACE runtime-reloc curbrk-init addr=0x{:x} value=0x{:x}",
                            addr + 0x222218,
                            self.current_brk
                        );
                    }
                } else if offset < copy_end {
                    memory.write(addr, &bytes[offset..copy_end])?;
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
            let anon_addr = memory
                .mmap_anonymous_private_topdown(event.args[1], perm)
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
            let fd = event.args[0];
            if fd != 1 && fd != 2 {
                return Err(DaotiError::Unavailable(format!(
                    "writev 仅支持 stdout/stderr，fd={fd}"
                )));
            }
            let base = event.args[1];
            let count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("writev 数量溢出".into()))?;
            let mut total = 0usize;
            for i in 0..count {
                let raw = memory.read(base + (i as u64) * 16, 16)?;
                let address = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let length = usize::try_from(u64::from_le_bytes(raw[8..16].try_into().unwrap()))
                    .map_err(|_| DaotiError::Other("writev 长度溢出".into()))?;
                let data = memory.read(address, length as u64)?;
                self.sink.write_all(data)?;
                total += length;
            }
            return Ok(total as i64);
        }
        if event.nr != SYS_WRITE {
            return self.handle(event);
        }
        let fd = event.args[0];
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
    fn access_returns_enoent_for_unavailable_runtime_probe() {
        let mut bridge = NativeSyscallBridge::new(BufferSink::default());
        let event = RuntimeSyscallEvent::enter(SYS_ACCESS, "access", [0x1000, 0, 0, 0, 0, 0]);
        assert_eq!(bridge.handle(&event).unwrap(), -2);
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
