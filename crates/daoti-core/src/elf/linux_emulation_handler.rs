use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use daoti_common::DaotiError;

use super::runtime::{GeneralRegisters, MemoryModel, RuntimeSyscallEvent, SyscallHandler};
use super::syscall_bridge::{BufferSink, NativeSyscallBridge};
use crate::injector::{AuditBuffer, Injector, LinuxEmulationInjector};

pub struct LinuxEmulationHandler {
    injector: LinuxEmulationInjector,
    native_bridge: NativeSyscallBridge<BufferSink>,
    exit_code: Option<i32>,
    captured: Arc<Mutex<Vec<u8>>>,
    diagnostic_rtld_global: Option<u64>,
    diagnostic_main_map: Option<u64>,
    /// 诊断钩子保存的最近一次 syscall 入口寄存器快照，仅诊断用。
    last_registers: Option<GeneralRegisters>,
    /// 仅诊断用的最近指令历史。
    last_instruction_history: Vec<(u64, Vec<u8>, GeneralRegisters)>,
}

impl LinuxEmulationHandler {
    pub fn new(audit: AuditBuffer) -> Self {
        Self {
            injector: LinuxEmulationInjector::new(audit),
            native_bridge: NativeSyscallBridge::new(BufferSink::default()),
            exit_code: None,
            captured: Arc::new(Mutex::new(Vec::new())),
            diagnostic_rtld_global: None,
            diagnostic_main_map: None,
            last_registers: None,
            last_instruction_history: Vec::new(),
        }
    }

    pub fn with_allowed_roots(mut self, roots: &[PathBuf]) -> Self {
        self.native_bridge = self.native_bridge.with_allowed_roots(roots);
        self
    }

    /// 把 loader 布局的真实堆断点同步给 native bridge；
    /// 否则 brk(0) 走 injector 默认堆顶 0x2000_0000（未映射区域），
    /// malloc 初始化写 top chunk 失败后读回 0，报 "malloc(): corrupted top size"。
    pub fn with_brk(mut self, brk: u64, heap_end: u64) -> Self {
        self.native_bridge = self.native_bridge.with_brk(brk, heap_end);
        self
    }

    pub fn with_link_map_diagnostics(mut self, rtld_global: u64, main_map: u64) -> Self {
        self.diagnostic_rtld_global = Some(rtld_global);
        self.diagnostic_main_map = Some(main_map);
        self
    }

    pub fn captured_stdout_shared(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.captured)
    }

    fn emit_write(&mut self, operation: &str, fd: u64, bytes: Vec<u8>) -> Result<i64, DaotiError> {
        if operation == "write" && fd == 2 && std::env::var_os("DAOTI_TRACE_LD_DEBUG").is_some() {
            let path = std::env::var_os("DAOTI_LD_DEBUG_LOG")
                .unwrap_or_else(|| "glibc-ld-debug.log".into());
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                use std::io::Write;
                let _ = writeln!(file, "fd=2 bytes={:?}", String::from_utf8_lossy(&bytes));
            }
        }
        self.captured
            .lock()
            .expect("输出缓冲区锁不应中毒")
            .extend_from_slice(&bytes);
        let args = vec![String::from_utf8_lossy(&bytes).into_owned()];
        let target =
            crate::interceptor::TargetSyscall::new(operation, "Linux 写入仿真").with_args(&args);
        Ok(self.injector.inject(&target)?.ret_value.unwrap_or(0))
    }

    fn diagnose_link_map(&self, memory: &MemoryModel) {
        let Some(rtld_global) = self.diagnostic_rtld_global else {
            eprintln!("TRACE inconsistency-link-map exact address unavailable");
            return;
        };
        let Some(main_map) = self.diagnostic_main_map else {
            eprintln!("TRACE inconsistency-link-map stored main_map unavailable");
            return;
        };
        // ns0 的链头在 rtld_global+0x00（过去误用 +0xa30 读到 namespace 1，导致 ns_loaded 恒为 0）。
        let ns_loaded_addr = rtld_global;
        let ns_loaded = read_u64_lossy(memory, ns_loaded_addr);
        let ns_next = ns_loaded.and_then(|addr| read_u64_lossy(memory, addr + 0x18));
        let ns_prev = ns_loaded.and_then(|addr| read_u64_lossy(memory, addr + 0x20));
        let main_next = read_u64_lossy(memory, main_map + 0x18);
        let main_prev = read_u64_lossy(memory, main_map + 0x20);
        eprintln!(
            "TRACE inconsistency-link-map exact rtld_global=0x{rtld_global:x} ns_loaded_addr=0x{ns_loaded_addr:x} ns_loaded={ns_loaded:?} stored_main_map=0x{main_map:x} equal={} ns_l_next={ns_next:?} ns_l_prev={ns_prev:?} stored_l_next={main_next:?} stored_l_prev={main_prev:?}",
            ns_loaded == Some(main_map)
        );
    }

    /// malloc(): corrupted top size 现场取证。
    /// DAOTI_DIAGNOSE_CURBRK 指定扫描范围（hex: start-end），在范围内查找
    /// 值 0x2864000（brk(0) 的返回值）以定位 __curbrk 是否被写入。
    fn diagnose_corrupted_top(&self, memory: &MemoryModel) {
        let Some(range) = std::env::var("DAOTI_DIAGNOSE_CURBRK").ok() else {
            return;
        };
        // 格式：<scan_start>-<scan_end>[,<arena_addr>]，如 0x880000-0x92E000,0x7045C80
        let mut segs = range.split(',');
        let scan_range = segs.next().unwrap_or("");
        let arena_override = segs
            .next()
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());
        let parts: Vec<&str> = scan_range.split('-').collect();
        if parts.len() != 2 {
            return;
        }
        let (Ok(start), Ok(end)) = (
            u64::from_str_radix(parts[0].trim_start_matches("0x"), 16),
            u64::from_str_radix(parts[1].trim_start_matches("0x"), 16),
        ) else {
            return;
        };
        let regs = self.last_registers;
        eprintln!(
            "TRACE corrupted-top scan 0x{start:x}-0x{end:x} rip=0x{:x} rsp=0x{:x}",
            regs.map(|r| r.rip).unwrap_or(0),
            regs.map(|r| r.rsp).unwrap_or(0),
        );
        // 指令历史：writev 前 10 条 rip+bytes，定位 corrupted 检查代码
        for (rip, bytes, _regs) in self.last_instruction_history.iter().rev().take(10) {
            eprintln!("TRACE corrupted-top insn rip=0x{rip:x} bytes={bytes:02x?}");
        }
        let target = 0x2864000u64;
        let mut hits = Vec::new();
        let mut addr = start & !7;
        while addr < end {
            if read_u64_lossy(memory, addr) == Some(target) {
                hits.push(addr);
            }
            addr += 8;
        }
        eprintln!(
            "TRACE corrupted-top brk-value hits={:?}",
            hits.iter().map(|a| format!("0x{a:x}")).collect::<Vec<_>>()
        );
        // 扫描 main_arena：特征 attached_threads(u32@+8)==1；不要求 top 非零——
        // ptmalloc_init 未执行时 top 恒 0，这正是要验证的状态
        let mut arenas = Vec::new();
        let mut a = start & !7;
        while a + 0x88 <= end {
            if read_u64_lossy(memory, a + 8) == Some(1) {
                if let Some(top) = read_u64_lossy(memory, a + 0x60) {
                    arenas.push((a, top));
                }
            }
            a += 8;
        }
        for (arena, top) in arenas.iter().take(4) {
            let top_size = read_u64_lossy(memory, top.wrapping_add(8));
            let sysmem = read_u64_lossy(memory, arena + 0x888);
            eprintln!(
                "TRACE corrupted-top arena=0x{arena:x} top=0x{top:x} top_size={top_size:?} system_mem={sysmem:?}"
            );
        }
        // malloc 慢路径 lea rbx 实参确认的 main_arena（libc 基址随 topdown 布局变化）
        let arena = arena_override.unwrap_or(0x91FC80);
        let vals: Vec<Option<u64>> = [
            0x0,   // mutex/flags
            0x8,   // attached_threads
            0x60,  // top
            0x68,  // last_remainder
            0x870, // next（应自引用 0x91FC80）
            0x888, // system_mem
            0x890, // max_system_mem
        ]
        .iter()
        .map(|off| read_u64_lossy(memory, arena + off))
        .collect();
        eprintln!("TRACE corrupted-top main_arena@0x{arena:x} = {vals:?}");
        // brk 使能标志（__sbrk 入口 cmp byte [libc+0x228E4E],0），
        // 相对 main_arena(+0x21A2C8) 偏移 0xEB86，读 8 字节对齐窗口
        let flag_win = read_u64_lossy(memory, arena + 0xEB80);
        eprintln!(
            "TRACE corrupted-top brk-flag@0x{:x} window={flag_win:?} (byte@+6 即标志)",
            arena + 0xEB80
        );
        // dump main_arena.top 周边精确视图：top-0x10（prev_size）..top+0x10
        if let Some(top) = vals[2] {
            let head: Vec<Option<u64>> = (-2..=2)
                .map(|i| read_u64_lossy(memory, (top as i64 + i * 8) as u64))
                .collect();
            eprintln!("TRACE corrupted-top top@0x{top:x} head[-2..2]={head:?}");
        }
    }

    /// 检测到 Inconsistency detected 时输出完整诊断：寄存器、RSP 栈顶、搜索区域、_rtld_global 固定字段。
    fn diagnose_inconsistency(&self, memory: &MemoryModel) {
        // 输出 syscall 入口寄存器（RAX 为 syscall nr，RDI/RSI/RDX/RCX/R8/R9 为参数）
        if let Some(regs) = &self.last_registers {
            eprintln!(
                "TRACE inconsistency-registers RAX=0x{:x} RDI=0x{:x} RSI=0x{:x} RDX=0x{:x} RCX=0x{:x} R8=0x{:x} R9=0x{:x}",
                regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9
            );
            // RSP 顶部 64 字节，并在其中搜索目标地址。
            match memory.read(regs.rsp, 64) {
                Ok(rsp_bytes) => {
                    let hex: String = rsp_bytes
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let stack_words = rsp_bytes
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|word| u64::from_le_bytes(*word))
                        .collect::<Vec<_>>();
                    eprintln!(
                        "TRACE inconsistency-rsp-top64 stack=0x{:x} bytes=[{}]",
                        regs.rsp, hex
                    );
                    eprintln!(
                        "TRACE inconsistency-search-values location=stack values={:?}",
                        search_values(&stack_words)
                    );
                }
                Err(_) => {
                    eprintln!(
                        "TRACE inconsistency-rsp-top64 stack=0x{:x} <不可读>",
                        regs.rsp
                    );
                }
            }
            let register_values = [
                ("RAX", regs.rax),
                ("RDI", regs.rdi),
                ("RSI", regs.rsi),
                ("RDX", regs.rdx),
                ("RCX", regs.rcx),
                ("R8", regs.r8),
                ("R9", regs.r9),
            ];
            eprintln!(
                "TRACE inconsistency-search-values location=registers values={:?}",
                register_values
                    .iter()
                    .filter(|(_, value)| *value == 0x275a000 || *value == 0x2700000)
                    .collect::<Vec<_>>()
            );
        } else {
            eprintln!("TRACE inconsistency-registers <无寄存器快照>");
        }

        // 读取目标地址周边 64 字节，便于发现指针是否落在相关区域。
        for &addr in &[0x275a000u64, 0x2700000u64] {
            match memory.read(addr, 64) {
                Ok(bytes) => {
                    let words = bytes
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|word| u64::from_le_bytes(*word))
                        .collect::<Vec<_>>();
                    eprintln!(
                        "TRACE inconsistency-search-region addr=0x{addr:x} values={:?}",
                        search_values(&words)
                    );
                }
                Err(_) => {
                    eprintln!("TRACE inconsistency-search-region addr=0x{addr:x} <未映射>");
                }
            }
        }

        // 读取 diagnostic_rtld_global 周边若干 u64 字段。
        if let Some(rtld_global) = self.diagnostic_rtld_global {
            let fields = (0..8)
                .map(|index| {
                    let address = rtld_global + index * 8;
                    (address, read_u64_lossy(memory, address))
                })
                .collect::<Vec<_>>();
            eprintln!(
                "TRACE inconsistency-diagnostic-rtld-global addr=0x{rtld_global:x} fields={fields:x?}"
            );
        } else {
            eprintln!("TRACE inconsistency-diagnostic-rtld-global <未配置>");
        }

        if std::env::var_os("DAOTI_TRACE_INSN_HISTORY").is_some() {
            let start = self.last_instruction_history.len().saturating_sub(10);
            eprintln!(
                "TRACE inconsistency-instruction-history total={} last={}",
                self.last_instruction_history.len(),
                self.last_instruction_history.len().saturating_sub(start)
            );
            for (rip, bytes, regs) in self.last_instruction_history.iter().skip(start) {
                eprintln!("TRACE insn RIP=0x{rip:x} BYTES={bytes:02x?} RAX=0x{:x} RBX=0x{:x} RCX=0x{:x} RDX=0x{:x} RDI=0x{:x} RSI=0x{:x} RBP=0x{:x} RSP=0x{:x} RAX_SOURCE={}", regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rdi, regs.rsi, regs.rbp, regs.rsp, rax_assignment_source(bytes));
            }
        }

        // 同时输出现有 link_map 诊断
        self.diagnose_link_map(memory);

        // dl-mutex.c __rtld_mutex_init 断言失败专项诊断
        if std::env::var_os("DAOTI_TRACE_RTLD_MUTEX").is_some() {
            self.diagnose_rtld_mutex(memory);
        }
    }

    /// __rtld_mutex_init（sysdeps/nptl/dl-mutex.c:44）断言 sym!=NULL 失败时，
    /// dump libc_map 与 l_info 全貌，定位 _dl_lookup_direct 返回 NULL 的原因。
    ///
    /// 输出内容：
    /// - libc_map = GL(dl_ns)[0].libc_map，位于 rtld_global+0x20（经验值）
    /// - libc_map 关键字段：l_name / l_ld / l_phdr / l_phnum / l_info
    /// - 从 l_ld 重扫动态段，列出关心的 tag 及其运行时地址（bias + value）
    /// - l_info 数组全部非空槽位，版本槽位指向内容抽样
    fn diagnose_rtld_mutex(&self, memory: &MemoryModel) {
        let Some(rtld_global) = self.diagnostic_rtld_global else {
            eprintln!("TRACE rtld-mutex <rtld_global 未配置>");
            return;
        };
        let libc_map = read_u64_lossy(memory, rtld_global + 0x20);
        eprintln!(
            "TRACE rtld-mutex rtld_global=0x{rtld_global:x} libc_map(rtld+0x20)={libc_map:#x?}"
        );
        let Some(libc_map) = libc_map else {
            eprintln!("TRACE rtld-mutex <libc_map 为空，断言必然失败>");
            return;
        };
        let read_word = |address: u64| read_u64_lossy(memory, address);
        let l_addr = read_word(libc_map).unwrap_or(0);
        let l_name_ptr = read_word(libc_map + 0x08);
        let l_name = l_name_ptr.and_then(|ptr| read_c_string_lossy(memory, ptr, 256));
        let l_ld = read_word(libc_map + 0x10);
        let l_phdr = read_word(libc_map + 0x30);
        let l_phnum = read_word(libc_map + 0x38);
        let l_info = read_word(libc_map + 0x68); // glibc 2.35 l_info 内联数组起点是 map+0x40，此处 +0x68 只是 l_info[DT_STRTAB] 槽内容（动态条目指针），保留作对照
        eprintln!(
            "TRACE rtld-mutex map=0x{libc_map:x} l_addr=0x{l_addr:x} l_name={l_name:?} l_ld=0x{l_ld:x?} l_phdr=0x{l_phdr:x?} l_phnum=0x{l_phnum:x?} l_info_via_0x68=0x{l_info:x?}"
        );
        // dump map+0x20..+0x50 原始字段（l_ld 之上），识别预建 map 的字段污染。
        {
            let raw: Vec<u64> = (0x20u64..=0x58)
                .step_by(8)
                .filter_map(|off| read_word(libc_map + off))
                .collect();
            eprintln!("TRACE rtld-mutex map-fields[0x20..0x58]={raw:x?}");
        }
        // 从 l_ld 重扫动态段：glibc 的 elf_get_dynamic_info 已把含地址/指针的
        // value 字段原地绝对化（d_ptr += l_addr），因此 value 本身就是运行时
        // 地址，不可再叠加 l_addr。tag 字段不被改写。
        if let Some(l_ld) = l_ld {
            let mut cursor = l_ld;
            let mut found = Vec::new();
            for _ in 0..512 {
                let Some(bytes) = memory.read(cursor, 16).ok() else {
                    eprintln!("TRACE rtld-mutex dyn scan stopped unreadable at 0x{cursor:x}");
                    break;
                };
                let tag = i64::from_le_bytes(bytes[..8].try_into().unwrap());
                let value = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                if tag == 0 {
                    break;
                }
                found.push((tag, value));
                cursor = cursor.saturating_add(16);
            }
            eprintln!("TRACE rtld-mutex dyn total_entries={}", found.len());
            // 原文 dump 前若干条目，确认绝对化后的动态段与文件差异。
            let head = found.iter().take(8).copied().collect::<Vec<_>>();
            eprintln!("TRACE rtld-mutex dyn head={head:x?}");
            let interesting = [
                4i64,       // DT_HASH
                5,          // DT_STRTAB
                6,          // DT_SYMTAB
                0x6ffffef5, // DT_GNU_HASH
                0x6ffffff0, // DT_VERSYM
                0x6ffffffc, // DT_VERDEF
                0x6ffffffd, // DT_VERNEED
                0x6ffffffe, // DT_VERNEEDNUM
                0x6fffffff, // DT_VERDEFNUM
            ];
            for tag in interesting {
                let hit = found.iter().find(|(t, _)| *t == tag);
                match hit {
                    Some((_, value)) => {
                        // value 已绝对化：直接作为运行时地址验证可读性；
                        // file_value = value - l_addr 还原文件相对值。
                        let file_value = value.wrapping_sub(l_addr);
                        let readable = memory.read(*value, 8).is_ok();
                        eprintln!(
                            "TRACE rtld-mutex dyn tag=0x{tag:x} value(runtime)=0x{value:x} file_value=0x{file_value:x} readable={readable}"
                        );
                        if tag == 0x6ffffef5 {
                            // GNU hash 表头：nbuckets / nchains / bitmask_nwords / bloom_size
                            match memory.read(*value, 32) {
                                Ok(bytes) => {
                                    eprintln!("TRACE rtld-mutex gnu-hash-head bytes={bytes:02x?}")
                                }
                                Err(_) => eprintln!("TRACE rtld-mutex gnu-hash-head <不可读>"),
                            }
                        }
                    }
                    None => eprintln!("TRACE rtld-mutex dyn tag=0x{tag:x} <未找到>"),
                }
            }
        } else {
            eprintln!("TRACE rtld-mutex <l_ld 为空>");
        }
        // 正确的 l_info 读取：glibc 2.35 中 l_info 是 map+0x40 起的内联数组，
        // 槽索引 = DT_tag，每个槽值是指向动态段中该条目 ElfW(Dyn)* 的指针，
        // 槽值本身是地址（= l_ld + 条目偏移），解引用才能得到 (tag, value)。
        {
            let base = libc_map + 0x40;
            let mut slots = Vec::new();
            for index in 0..66usize {
                let Some(word) = read_word(base + (index as u64) * 8) else {
                    continue;
                };
                if word != 0 {
                    slots.push((index, word));
                }
            }
            eprintln!("TRACE rtld-mutex l_info_inline base=0x{base:x} non_null_slots={slots:x?}");
            // 检查关键槽位指向的动态条目内容是否与动态段扫描一致。
            for &(index, entry_ptr) in slots.iter().take(40) {
                match memory.read(entry_ptr, 16) {
                    Ok(bytes) => {
                        let t = i64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
                        let v = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                        eprintln!(
                            "TRACE rtld-mutex l_info[{index}] ptr=0x{entry_ptr:x} -> (tag=0x{t:x}, value=0x{v:x})"
                        );
                    }
                    Err(_) => eprintln!(
                        "TRACE rtld-mutex l_info[{index}] ptr=0x{entry_ptr:x} <条目不可读>"
                    ),
                }
            }
        }
        // link_map 尾部字段 raw dump：l_phdr/l_entry/l_phnum/l_searchlist/l_loader/
        // l_versions/l_nversions/l_nbuckets/l_gnu_shift/l_gnu_buckets/l_gnu_chain_zero/
        // l_gnu_bitmask/l_versyms。偏移按 glibc 2.35 include/link.h（l_info[66] 内联，
        // 0x250 起为 l_phdr）推算，直接打印原始值便于对照 glibc 运行时是否已填充。
        for label in ["self=libc_map", "l_real"] {
            let base = if label == "l_real" {
                read_word(libc_map + 0x28).unwrap_or(libc_map)
            } else {
                libc_map
            };
            eprintln!("TRACE rtld-mutex tail-dump label={label} base=0x{base:x}");
            let mut cursor = base + 0x240;
            for _ in 0..8 {
                let Ok(bytes) = memory.read(cursor, 16) else {
                    eprintln!("TRACE rtld-mutex tail-dump  0x{cursor:x} <不可读>");
                    break;
                };
                eprintln!(
                    "TRACE rtld-mutex tail-dump  0x{cursor:x}: {}",
                    bytes
                        .chunks(8)
                        .map(|c| format!("0x{}", u64::from_le_bytes(c.try_into().unwrap())))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
                cursor += 16;
            }
        }
    }

    fn syscall_name(nr: u64) -> &'static str {
        match nr {
            1 => "write",
            8 => "lseek",
            21 => "access",
            63 => "uname",
            257 => "openat",
            262 => "newfstatat",
            72 => "fcntl",
            137 => "statfs",
            138 => "fstatfs",
            263 => "unlinkat",
            79 => "getcwd",
            80 => "chdir",
            74 => "fsync",
            77 => "ftruncate",
            258 => "mkdirat",
            3 => "close",
            0 => "read",
            20 => "writev",
            9 => "mmap",
            10 => "mprotect",
            12 => "brk",
            158 => "arch_prctl",
            60 => "exit",
            231 => "exit_group",
            273 => "set_robust_list",
            274 => "get_robust_list",
            334 => "rseq",
            302 => "prlimit64",
            318 => "getrandom",
            163 => "getrlimit",
            5 => "fstat",
            13 => "rt_sigaction",
            14 => "rt_sigprocmask",
            16 => "ioctl",
            39 => "getpid",
            89 => "readlink",
            117 => "raise",
            267 => "readlinkat",
            186 => "gettid",
            200 => "tkill",
            203 => "sched_setaffinity",
            204 => "sched_getaffinity",
            228 => "clock_gettime",
            234 => "tgkill",
            _ => "unknown",
        }
    }
}

impl SyscallHandler for LinuxEmulationHandler {
    fn fs_base(&self) -> Option<u64> {
        // 关键转发：ARCH_SET_FS 由 native_bridge 的 handle_with_memory 处理并缓存在
        // bridge.fs_base；若不转发，runtime 的 fs 段译码恒用预置 tls_base，
        // 导致 __ctype_init 之类访问 [fs-0x90] 落在 daoti 空 TLS 区域而读 0 崩溃。
        <NativeSyscallBridge<BufferSink> as SyscallHandler>::fs_base(&self.native_bridge)
    }

    fn diagnose_instruction_history(&mut self, history: &[(u64, Vec<u8>, GeneralRegisters)]) {
        self.last_instruction_history.clear();
        self.last_instruction_history.extend_from_slice(history);
    }

    fn diagnose_syscall_context(&mut self, registers: &GeneralRegisters, _memory: &MemoryModel) {
        if std::env::var_os("DAOTI_DIAGNOSE_INCONSISTENCY").is_some() {
            eprintln!(
                "TRACE syscall-context nr={} RAX=0x{:x} RDI=0x{:x} RSI=0x{:x} RDX=0x{:x} RCX=0x{:x} R8=0x{:x} R9=0x{:x} RSP=0x{:x}",
                registers.rax,
                registers.rax,
                registers.rdi,
                registers.rsi,
                registers.rdx,
                registers.rcx,
                registers.r8,
                registers.r9,
                registers.rsp
            );
        }
        self.last_registers = Some(*registers);
    }

    fn handle(&mut self, event: &RuntimeSyscallEvent) -> Result<i64, DaotiError> {
        if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
            eprintln!(
                "TRACE linux-emulation-syscall enter nr={} name={} args=[0x{:x},0x{:x},0x{:x},0x{:x},0x{:x},0x{:x}]",
                event.nr,
                Self::syscall_name(event.nr),
                event.args[0],
                event.args[1],
                event.args[2],
                event.args[3],
                event.args[4],
                event.args[5]
            );
        }
        if event.nr == 231 && std::env::var_os("DAOTI_TRACE_EXIT_GROUP").is_some() {
            eprintln!(
                "TRACE exit-group code={} rip=0x{:x} recent_instructions={:?}",
                event.args[0] as i32,
                self.last_registers
                    .map(|registers| registers.rip)
                    .unwrap_or(0),
                self.last_instruction_history
                    .iter()
                    .rev()
                    .take(10)
                    .map(|(rip, bytes, registers)| (*rip, bytes.clone(), registers))
                    .collect::<Vec<_>>()
            );
        }
        let name = Self::syscall_name(event.nr);
        if name == "unknown" {
            return Err(DaotiError::Unavailable(format!(
                "Linux 仿真器尚未实现 syscall nr={}",
                event.nr
            )));
        }
        if event.nr == 60 || event.nr == 231 {
            if event.nr == 231 && std::env::var_os("DAOTI_TRACE_EXIT_GROUP").is_some() {
                eprintln!(
                    "TRACE exit-group code={} rip=0x{:x} recent_instructions={:?}",
                    event.args[0] as i32,
                    self.last_registers
                        .map(|registers| registers.rip)
                        .unwrap_or(0),
                    self.last_instruction_history
                        .iter()
                        .rev()
                        .take(10)
                        .map(|(rip, bytes, _)| (*rip, bytes.clone()))
                        .collect::<Vec<_>>()
                );
            }
            self.exit_code = Some(event.args[0] as i32);
            return Ok(0);
        }
        let args = match event.nr {
            9 => vec![event.args[1].to_string()],
            10 => vec![
                format!("0x{:x}", event.args[0]),
                event.args[1].to_string(),
                permissions(event.args[2]),
            ],
            12 => {
                if event.args[0] == 0 {
                    Vec::new()
                } else {
                    vec![format!("0x{:x}", event.args[0])]
                }
            }
            _ => event.args.iter().map(|arg| format!("0x{arg:x}")).collect(),
        };
        let target =
            crate::interceptor::TargetSyscall::new(name, "Linux 仿真 syscall").with_args(&args);
        let result = self.injector.inject(&target)?;
        let ret = result.ret_value.unwrap_or(0);
        if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
            eprintln!(
                "TRACE linux-emulation-syscall exit nr={} ret={ret}",
                event.nr
            );
        }
        Ok(ret)
    }

    fn handle_with_memory(
        &mut self,
        event: &RuntimeSyscallEvent,
        memory: &mut MemoryModel,
    ) -> Result<i64, DaotiError> {
        if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
            eprintln!(
                "TRACE linux-emulation-syscall memory nr={} name={} args={:?}",
                event.nr,
                Self::syscall_name(event.nr),
                event.args
            );
        }
        if event.nr == 63 {
            let address = event.args[0];
            let mut utsname = [0u8; 390];
            for (offset, value) in [
                (0, b"Linux\0".as_slice()),
                (65, b"daoti\0".as_slice()),
                (130, b"6.1.0-daoti\0".as_slice()),
                (195, b"#1 SMP\0".as_slice()),
                (260, b"x86_64\0".as_slice()),
                (325, b"\0".as_slice()),
            ] {
                utsname[offset..offset + value.len()].copy_from_slice(value);
            }
            memory.write(address, &utsname)?;
            return Ok(0);
        }
        if event.nr == 1 {
            let address = event.args[1];
            let _length = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("write 长度超出平台范围".into()))?;
            let bytes = memory.read(address, event.args[2])?.to_vec();
            if std::env::var_os("DAOTI_DIAGNOSE_CURBRK").is_some() {
                eprintln!(
                    "TRACE write-event fd={} addr=0x{address:x} len={} head={:?}",
                    event.args[0],
                    bytes.len(),
                    String::from_utf8_lossy(&bytes[..bytes.len().min(48)])
                );
            }
            if bytes
                .windows("Inconsistency detected".len())
                .any(|window| window == b"Inconsistency detected")
            {
                self.diagnose_inconsistency(memory);
            }
            if bytes
                .windows(b"corrupted top size".len())
                .any(|w| w == b"corrupted top size")
            {
                // malloc(): corrupted top size 现场取证：__curbrk 由
                // DAOTI_DIAGNOSE_CURBRK=<addr> 传入（libc 基址 + __curbrk 偏移）。
                if let Some(curbrk_addr) = std::env::var("DAOTI_DIAGNOSE_CURBRK")
                    .ok()
                    .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
                {
                    let curbrk = read_u64_lossy(memory, curbrk_addr);
                    let regs = self.last_registers;
                    eprintln!(
                        "TRACE corrupted-top curbrk_addr=0x{curbrk_addr:x} curbrk={curbrk:?} nr_regs={:?} rip=0x{:x} rdi=0x{:x} rsi=0x{:x}",
                        regs.is_some(),
                        regs.map(|r| r.rip).unwrap_or(0),
                        regs.map(|r| r.rdi).unwrap_or(0),
                        regs.map(|r| r.rsi).unwrap_or(0),
                    );
                    // dump __curbrk 指向的堆头部 64 字节（top chunk 元数据区）
                    if let Some(cb) = curbrk {
                        let mut dump = Vec::new();
                        for i in 0..8 {
                            dump.push(read_u64_lossy(memory, cb.wrapping_add(i * 8)));
                        }
                        eprintln!("TRACE corrupted-top heap_dump @curbrk={dump:?}");
                    }
                }
            }
            let ret = self.emit_write("write", event.args[0], bytes)?;
            if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                eprintln!("TRACE linux-emulation-syscall exit nr=1 ret={ret}");
            }
            return Ok(ret);
        }
        if event.nr == 267 {
            // readlinkat(dirfd, pathname, buf, bufsiz)
            // glibc 早期用 readlinkat(AT_FDCWD, "/proc/self/exe", ...) 定位 rtld 目录；
            // 返回失败时 glibc 有官方 fallback（_rtld_global_ro+0x2c0 字符串），
            // 因此宿主无法解析时返回 -ENOENT 属于真实内核语义，不违反契约。
            if event.args[0] as i64 != -100 {
                return Ok(-9); // -EBADF：仅支持 AT_FDCWD（glibc 启动只使用该形式）
            }
            let path_addr = event.args[1];
            let buf_addr = event.args[2];
            let bufsiz = usize::try_from(event.args[3])
                .map_err(|_| DaotiError::Other("readlinkat bufsiz 超出平台范围".into()))?;
            let Some(path) = read_c_string_lossy(memory, path_addr, 4096) else {
                return Ok(-14); // -EFAULT：guest 路径不可读
            };
            match std::fs::read_link(&path) {
                Ok(target) => {
                    let bytes = target.to_string_lossy().as_bytes().to_vec();
                    let n = bytes.len().min(bufsiz);
                    memory.write(buf_addr, &bytes[..n])?;
                    if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                        eprintln!(
                            "TRACE linux-emulation-syscall readlinkat path={path:?} -> {:?} n={n}",
                            target.to_string_lossy()
                        );
                    }
                    return Ok(n as i64);
                }
                Err(host_err) => {
                    if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                        eprintln!(
                            "TRACE linux-emulation-syscall readlinkat path={path:?} host_err={host_err} ret=-ENOENT"
                        );
                    }
                    return Ok(-2); // -ENOENT：宿主 FS 不可解析（如 /proc 在 Windows 宿主缺失）
                }
            }
        }
        if event.nr == 231 && std::env::var_os("DAOTI_TRACE_EXIT_GROUP").is_some() {
            eprintln!(
                "TRACE exit-group code={} rip=0x{:x} recent_instructions={:?}",
                event.args[0] as i32,
                self.last_registers
                    .map(|registers| registers.rip)
                    .unwrap_or(0),
                self.last_instruction_history
                    .iter()
                    .rev()
                    .take(10)
                    .map(|(rip, bytes, registers)| (*rip, bytes.clone(), registers))
                    .collect::<Vec<_>>()
            );
        }
        if matches!(
            event.nr,
            0 | 3
                | 5
                | 8
                | 9
                | 10
                | 72
                | 137
                | 138
                | 263
                | 74
                | 77
                | 79
                | 80
                | 258
                | 12
                | 13
                | 14
                | 16
                | 17
                | 21
                | 28
                | 39
                | 89
                | 117
                | 158
                | 163
                | 186
                | 200
                | 202
                | 203
                | 204
                | 218
                | 228
                | 234
                | 257
                | 262
                | 273
                | 274
                | 302
                | 318
                | 334
        ) {
            return self.native_bridge.handle_with_memory(event, memory);
        }
        if event.nr == 20 {
            let iovec_base = event.args[1];
            let iovec_count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("writev iovec 数量超出平台范围".into()))?;
            let mut payload = Vec::new();
            for index in 0..iovec_count {
                let entry = iovec_base
                    .checked_add((index as u64).saturating_mul(16))
                    .ok_or_else(|| DaotiError::Other("writev iovec 地址溢出".into()))?;
                let address = read_u64(memory, entry)?;
                let length = read_u64(memory, entry + 8)?;
                payload.extend_from_slice(memory.read(address, length)?);
            }
            if payload
                .windows("Inconsistency detected".len())
                .any(|window| window == b"Inconsistency detected")
            {
                self.diagnose_inconsistency(memory);
            }
            if payload
                .windows(b"corrupted top size".len())
                .any(|w| w == b"corrupted top size")
            {
                self.diagnose_corrupted_top(memory);
            }
            let ret = self.emit_write("writev", event.args[0], payload)?;
            if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                eprintln!("TRACE linux-emulation-syscall exit nr=20 ret={ret}");
            }
            return Ok(ret);
        }
        self.handle(event)
    }

    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    fn captured_stdout(&self) -> Vec<u8> {
        self.captured.lock().expect("输出缓冲区锁不应中毒").clone()
    }
}

fn rax_assignment_source(bytes: &[u8]) -> &'static str {
    match bytes {
        [0x48, 0x8b, ..] | [0x49, 0x8b, ..] => "mov rax, [memory]（候选）",
        [0x48, 0x89, ..] | [0x49, 0x89, ..] => "mov [memory], rax（写入）",
        [0x48, 0x8d, ..] | [0x49, 0x8d, ..] => "lea（可能生成地址）",
        [0xb8..=0xbf, ..] => "mov rax, immediate/register（候选）",
        [0x31, ..] | [0x33, ..] => "xor（可能清零/合并）",
        _ => "未识别为 RAX 赋值",
    }
}

fn search_values(values: &[u64]) -> Vec<(usize, u64)> {
    values
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, value)| *value == 0x275a000 || *value == 0x2700000)
        .collect()
}

fn read_u64_lossy(memory: &MemoryModel, address: u64) -> Option<u64> {
    memory
        .read(address, 8)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
}

/// 读取以 NUL 结尾的 C 字符串（最多 max_len 字节），不可读或超长时返回 None。
fn read_c_string_lossy(memory: &MemoryModel, address: u64, max_len: usize) -> Option<String> {
    let mut bytes = Vec::new();
    let mut cursor = address;
    for _ in 0..max_len {
        let Ok(byte) = memory.read(cursor, 1) else {
            return None;
        };
        if byte[0] == 0 {
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.push(byte[0]);
        cursor = cursor.wrapping_add(1);
    }
    None
}

fn read_u64(memory: &MemoryModel, address: u64) -> Result<u64, DaotiError> {
    let bytes = memory.read(address, 8)?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| DaotiError::Other("writev iovec 字段长度错误".into()))?;
    Ok(u64::from_le_bytes(bytes))
}

fn permissions(prot: u64) -> String {
    let mut value = String::new();
    if prot & 1 != 0 {
        value.push('r');
    }
    if prot & 2 != 0 {
        value.push('w');
    }
    if prot & 4 != 0 {
        value.push('x');
    }
    if value.is_empty() {
        value.push('-');
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::runtime::{MemPerm, MemoryRegion};

    #[test]
    fn brk_zero_queries_current_heap_without_resetting_it() {
        let audit = AuditBuffer::new();
        let mut handler = LinuxEmulationHandler::new(audit.clone())
            // brk 现由 native bridge 按真实堆布局记账（见 load_and_run 的 with_brk）
            .with_brk(0x2759000, 0x2F59000);
        let mut memory = MemoryModel::new(0x1000, 0x2000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .expect("测试内存段应映射");

        let event = RuntimeSyscallEvent::enter(12, "syscall", [0, 0, 0, 0, 0, 0]);
        let result = handler
            .handle_with_memory(&event, &mut memory)
            .expect("brk(0) 查询应成功");

        assert_eq!(result, 0x2759000);
        // bridge 记账不产生 injector 审计记录
        assert!(audit.records().is_empty());
    }

    #[test]
    fn writev_reads_iovecs_and_concatenates_audit_output() {
        let audit = AuditBuffer::new();
        let mut handler = LinuxEmulationHandler::new(audit.clone());
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        let mut bytes = vec![0; 0x1000];
        bytes[0x100..0x106].copy_from_slice(b"Hello ");
        bytes[0x200..0x20a].copy_from_slice(b"from libc!");
        bytes[0x300..0x308].copy_from_slice(&0x1100u64.to_le_bytes());
        bytes[0x308..0x310].copy_from_slice(&6u64.to_le_bytes());
        bytes[0x310..0x318].copy_from_slice(&0x1200u64.to_le_bytes());
        bytes[0x318..0x320].copy_from_slice(&10u64.to_le_bytes());
        memory
            .add_region(MemoryRegion::with_data(0x1000, MemPerm::rw(), bytes))
            .expect("测试内存段应映射");

        let event = RuntimeSyscallEvent::enter(20, "syscall", [1, 0x1300, 2, 0, 0, 0]);
        let result = handler
            .handle_with_memory(&event, &mut memory)
            .expect("writev 仿真应成功");

        assert_eq!(result, 16);
        assert_eq!(handler.captured_stdout(), b"Hello from libc!");
        assert_eq!(audit.records(), vec!["write:Hello from libc!".to_string()]);
    }
}
