//! 最小 ELF 运行时模型（daoti-core::elf::runtime）

use daoti_common::DaotiError;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// 将一次 main_map 来源现场追加到用户目录中的证据 JSONL。
pub fn append_source_evidence_to_jsonl(evidence: &MainMapSourceEvidence) {
    let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) else {
        eprintln!("WARN 无法确定用户目录，跳过 main_map 来源证据持久化");
        return;
    };
    let path = std::path::PathBuf::from(home)
        .join(".daoti")
        .join("main_map_source")
        .join("evidence.jsonl");
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("WARN 创建 main_map 来源证据目录失败：{error}");
            return;
        }
    }
    let Ok(mut line) = serde_json::to_string(evidence) else {
        eprintln!("WARN 序列化 main_map 来源证据失败");
        return;
    };
    line.push('\n');
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut file) => {
            if let Err(error) = file.write_all(line.as_bytes()) {
                eprintln!("WARN 写入 main_map 来源证据失败：{error}");
            }
        }
        Err(error) => eprintln!("WARN 打开 main_map 来源证据文件失败：{error}"),
    }
}

static LAST_INTERPRETER_RIP: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RAX: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RBX: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RCX: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RDX: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RSI: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RDI: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RBP: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_RSP: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_R12: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_R13: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_R14: AtomicU64 = AtomicU64::new(0);
static LAST_INTERPRETER_R15: AtomicU64 = AtomicU64::new(0);
/// 最近执行的指令序列（rip+bytes），仅在 DAOTI_TRACE_INSN_HISTORY=1 时维护，
/// 供 find_region 内存访问失败时回溯「真实失败指令」（LAST_INTERPRETER_RIP 只是
/// 探针区末尾的滞留值，不是崩溃指令）。容量 100（与主循环 instruction_history 同步）。
static LAST_INSN_HISTORY: Mutex<VecDeque<(u64, Vec<u8>)>> = Mutex::new(VecDeque::new());
static WATCH_RELA_ADDR: AtomicU64 = AtomicU64::new(0);
static WATCH_RELA_SIZE: AtomicU64 = AtomicU64::new(0);
/// 记录最近一次执行深度只读探针（reloc-callsite-deep）的 map，避免每轮循环重复打印。
static LAST_DEEP_MAP: AtomicU64 = AtomicU64::new(0);
/// 最近一次探针窗口看到的动态段基址（l_ld），供 MemoryModel::write 监视动态段改写。
static TRACE_DYN_BASE: AtomicU64 = AtomicU64::new(0);
/// 探针自身读取 rela 表时置位，让 MemoryModel::read 跳过监视打印，避免自读污染日志。
static RELOC_PROBE_READING: AtomicBool = AtomicBool::new(false);

/// 探针读取辅助：读取期间置位 RELOC_PROBE_READING，使 rela-read 监视不记录探针自读。
fn probe_read(memory: &MemoryModel, addr: u64, len: u64) -> Result<&[u8], DaotiError> {
    RELOC_PROBE_READING.store(true, Ordering::Relaxed);
    let result = memory.read(addr, len);
    RELOC_PROBE_READING.store(false, Ordering::Relaxed);
    result
}
/// 被 `MemoryModel::read` 在 `e_ehsize` 地址读取时置位，激活 `run()` 循环中的 cmp/jcc 细粒度追踪。
static E_EHSIZE_READ_ARM: AtomicBool = AtomicBool::new(false);
type WrittenAuxv = Option<(u64, Vec<u8>)>;
static WRITTEN_AUXV: OnceLock<Mutex<WrittenAuxv>> = OnceLock::new();

fn ensure_l_info(memory: &mut MemoryModel, map_addr: u64) -> Result<(), DaotiError> {
    let read_u64 = |offset: u64| {
        memory
            .read(map_addr + offset, 8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .unwrap_or(0)
    };
    // ld.so 在 _dl_setup_hash 真正执行前，link_map 的 l_gnu_*/l_versions 全为零；
    // 而 l_info 可能已被写入半成品指针（观察值 = l_ld + 0x60，垃圾值），因此若仅以
    // l_info == 0 判定就会短路、永远越过 hash 补齐。这里改为检查哈希/版本关键字段
    // 是否真实可用：GNU 路径要求 l_gnu_bitmask(+0x300)/buckets(+0x308)/chain(+0x310)
    // 三者非零且 bitmask 可读；SysV 路径要求 bitmask 为 0 且 buckets(+0x310) 有效；
    // 版本校验要求 l_versions(+0x2e8) 非零可读。任何一项缺失即触发初始化补齐。
    let l_gnu_bitmask = read_u64(0x300);
    let l_gnu_buckets = read_u64(0x308);
    let l_gnu_chain_zero = read_u64(0x310);
    let l_versions = read_u64(0x2e8);
    let bitmask_readable = l_gnu_bitmask != 0 && memory.read(l_gnu_bitmask, 8).is_ok();
    let gnu_valid =
        l_gnu_bitmask != 0 && l_gnu_buckets != 0 && l_gnu_chain_zero != 0 && bitmask_readable;
    let sysv_valid =
        l_gnu_bitmask == 0 && l_gnu_chain_zero != 0 && memory.read(l_gnu_chain_zero, 4).is_ok();
    let versions_valid = l_versions != 0 && memory.read(l_versions, 8).is_ok();
    if !(gnu_valid || sysv_valid) || !versions_valid {
        super::dynamic_loader::initialize_link_map_info(memory, map_addr)?;
    }
    Ok(())
}

pub(crate) fn record_auxv_snapshot(memory: &MemoryModel, start: u64) {
    if let Some(bytes) = memory.read(start, 19 * 16).ok().map(|bytes| bytes.to_vec()) {
        *WRITTEN_AUXV
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap() = Some((start, bytes));
    }
}

/// 根据 64 位 XOR 运算结果计算逻辑运算标志位（0x31 / XOR）。
fn update_flags_logic(result: u64, width: u8) -> u64 {
    let mask = match width {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    };
    let value = result & mask;
    let mut f = 0u64;
    if value == 0 {
        f |= 0x40;
    }
    if (value & (1u64 << (width as u32 * 8 - 1))) != 0 {
        f |= 0x80;
    }
    if (value & 0xff).count_ones().is_multiple_of(2) {
        f |= 0x04;
    }
    f
}

fn update_flags_xor64(result: u64) -> u64 {
    update_flags_logic(result, 8)
}

/// 根据 64 位算术运算结果计算 rflags。
fn update_flags_arith_width(result: u64, lhs: u64, rhs: u64, is_sub: bool, width: u8) -> u64 {
    let mask = match width {
        1 => 0xff,
        2 => 0xffff,
        4 => 0xffff_ffff,
        _ => u64::MAX,
    };
    let sign = 1u64 << (width as u32 * 8 - 1);
    let result = result & mask;
    let lhs = lhs & mask;
    let rhs = rhs & mask;
    let mut f = 0u64;
    if result == 0 {
        f |= 0x40;
    }
    if result & sign != 0 {
        f |= 0x80;
    }
    if is_sub {
        if lhs < rhs {
            f |= 0x01;
        }
    } else if result < lhs {
        f |= 0x01;
    }
    if is_sub {
        if ((lhs & sign) != 0) != ((rhs & sign) != 0)
            && ((result & sign) != 0) == ((rhs & sign) != 0)
        {
            f |= 0x800;
        }
    } else if ((lhs & sign) != 0) == ((rhs & sign) != 0)
        && ((result & sign) != 0) != ((lhs & sign) != 0)
    {
        f |= 0x800;
    }
    if (result & 0xff).count_ones().is_multiple_of(2) {
        f |= 0x04;
    }
    f
}

fn update_flags_arith64(result: u64, lhs: u64, rhs: u64, is_sub: bool) -> u64 {
    update_flags_arith_width(result, lhs, rhs, is_sub, 8)
}

/// 解码 x86-64 条件跳转条件。
fn parse_jcc(op: u8, rflags: u64) -> bool {
    let zf = rflags & 0x40 != 0;
    let sf = rflags & 0x80 != 0;
    let of = rflags & 0x800 != 0;
    let cf = rflags & 0x1 != 0;
    let pf = rflags & 0x4 != 0;
    match op & 0x0f {
        0x0 => of,
        0x1 => !of,
        0x2 => cf,
        0x3 => !cf,
        0x4 => zf,
        0x5 => !zf,
        0x6 => cf | zf,
        0x7 => !cf & !zf,
        0x8 => sf,
        0x9 => !sf,
        0xa => pf,
        0xb => !pf,
        0xc => sf ^ of,
        0xd => !(sf ^ of),
        0xe => zf | (sf ^ of),
        0xf => !zf & !(sf ^ of),
        _ => false,
    }
}

/// 内存权限。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemPerm {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MemPerm {
    pub const fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }
    pub const fn r() -> Self {
        Self::new(true, false, false)
    }
    pub const fn rw() -> Self {
        Self::new(true, true, false)
    }
    pub const fn rx() -> Self {
        Self::new(true, false, true)
    }
    pub const fn rwx() -> Self {
        Self::new(true, true, true)
    }
}

/// 内存段。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub perm: MemPerm,
    pub bytes: Vec<u8>,
}

impl MemoryRegion {
    pub fn with_data(base: u64, perm: MemPerm, bytes: Vec<u8>) -> Self {
        Self { base, perm, bytes }
    }
    fn end(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }
}

/// 简单内存模型。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryModel {
    pub min_addr: u64,
    pub max_addr: u64,
    pub regions: Vec<MemoryRegion>,
    /// 调试用：主对象可写 PT_LOAD 的运行时范围。
    pub trace_writable_pt_load: Vec<(u64, u64)>,
    /// 可选的 namespace 链表头写入修正目标，仅由 loader 在显式启用时配置。
    pub ns_loaded_write_fix: Option<(u64, u64)>,
    /// 运行时首次创建主 map 后写入的 namespace 根地址。
    pub namespace_root_addr: Option<u64>,
}

impl MemoryModel {
    pub fn new(min_addr: u64, max_addr: u64) -> Self {
        assert!(
            min_addr <= max_addr,
            "max_addr 必须是不小于 min_addr 的绝对地址上界"
        );
        Self {
            min_addr,
            max_addr,
            regions: Vec::new(),
            trace_writable_pt_load: Vec::new(),
            ns_loaded_write_fix: None,
            namespace_root_addr: None,
        }
    }

    pub fn add_region(&mut self, region: MemoryRegion) -> Result<(), DaotiError> {
        if region.base < self.min_addr || region.end() > self.max_addr {
            return Err(DaotiError::Other("内存段越界".into()));
        }
        if self
            .regions
            .iter()
            .any(|existing| region.base < existing.end() && existing.base < region.end())
        {
            return Err(DaotiError::Other("内存段重叠".into()));
        }
        self.regions.push(region);
        self.regions.sort_by_key(|r| r.base);
        Ok(())
    }

    pub fn mprotect(&mut self, addr: u64, len: u64, perm: MemPerm) -> Result<(), DaotiError> {
        if len == 0 || !addr.is_multiple_of(4096) {
            return Err(DaotiError::Other("mprotect 地址或长度无效".into()));
        }
        let end = addr
            .checked_add(len)
            .ok_or_else(|| DaotiError::Other("mprotect 范围溢出".into()))?;
        let index = self
            .regions
            .iter()
            .position(|region| addr >= region.base && end <= region.end())
            .ok_or_else(|| DaotiError::Other(format!("地址不可访问：0x{addr:x}")))?;
        let region = self.regions.remove(index);
        let offset_start = (addr - region.base) as usize;
        let offset_end = (end - region.base) as usize;
        let mut parts = Vec::new();
        if offset_start > 0 {
            parts.push(MemoryRegion::with_data(
                region.base,
                region.perm,
                region.bytes[..offset_start].to_vec(),
            ));
        }
        parts.push(MemoryRegion::with_data(
            addr,
            perm,
            region.bytes[offset_start..offset_end].to_vec(),
        ));
        if offset_end < region.bytes.len() {
            parts.push(MemoryRegion::with_data(
                end,
                region.perm,
                region.bytes[offset_end..].to_vec(),
            ));
        }
        self.regions.splice(index..index, parts);
        Ok(())
    }

    pub fn mmap_anonymous_private(&mut self, len: u64, perm: MemPerm) -> Result<u64, DaotiError> {
        if len == 0 {
            return Err(DaotiError::Other("mmap 长度不能为 0".into()));
        }
        let size = len
            .checked_add(4095)
            .ok_or_else(|| DaotiError::Other("mmap 长度溢出".into()))?
            / 4096
            * 4096;
        let mut base = self.min_addr.div_ceil(4096) * 4096;
        for region in &self.regions {
            if base.checked_add(size).is_some_and(|end| end <= region.base) {
                self.add_region(MemoryRegion::with_data(base, perm, vec![0; size as usize]))?;
                return Ok(base);
            }
            base = region.end().div_ceil(4096) * 4096;
        }
        if base
            .checked_add(size)
            .is_some_and(|end| end <= self.max_addr)
        {
            self.add_region(MemoryRegion::with_data(base, perm, vec![0; size as usize]))?;
            return Ok(base);
        }
        Err(DaotiError::Other("mmap 地址空间不足".into()))
    }

    /// Linux mmap 语义：匿名映射自 mmap_base 向低地址生长（top-down），
    /// 返回地址远高于 brk 段。glibc malloc 的 sysmalloc 依赖该语义判断堆段
    /// 连续性——若 mmap 区落在 brk 段下方，它会把 top.size 写成
    /// `brk(0) - top`，触发 "malloc(): corrupted top size"。
    pub fn mmap_anonymous_private_topdown(
        &mut self,
        len: u64,
        perm: MemPerm,
    ) -> Result<u64, DaotiError> {
        if len == 0 {
            return Err(DaotiError::Other("mmap 长度不能为 0".into()));
        }
        let size = len
            .checked_add(4095)
            .ok_or_else(|| DaotiError::Other("mmap 长度溢出".into()))?
            / 4096
            * 4096;
        // 从地址空间顶部逐页向下搜索；每个候选区间都必须与已有 region 不重叠。
        let mut base = self.max_addr.saturating_sub(size) & !0xFFF_u64;
        loop {
            let end = base.saturating_add(size);
            if base < self.min_addr {
                break;
            }
            let overlaps = self
                .regions
                .iter()
                .any(|region| base < region.end() && region.base < end);
            if !overlaps {
                self.add_region(MemoryRegion::with_data(base, perm, vec![0; size as usize]))?;
                return Ok(base);
            }
            if base < 4096 {
                break;
            }
            base -= 4096;
        }
        Err(DaotiError::Other("mmap 地址空间不足（topdown）".into()))
    }

    /// 静默检查 addr..addr+len 是否完整落在某个可读 region 内。
    /// 纯查询语义：不打印任何失败诊断，也不走 find_region 的探针路径，
    /// 专供工具代码（如 dynamic_loader 的 absolutize）对地址形态做探测。
    pub(crate) fn probe_read(&self, addr: u64, len: u64) -> bool {
        let end = addr.saturating_add(len);
        self.regions
            .iter()
            .any(|r| addr >= r.base && end <= r.end() && r.perm.read)
    }

    fn find_region(&self, addr: u64, len: u64) -> Result<&MemoryRegion, DaotiError> {
        let end = addr.saturating_add(len);
        self.regions
            .iter()
            .find(|r| addr >= r.base && end <= r.end())
            .ok_or_else(|| {
                let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
                eprintln!(
                    "动态 ELF 内存访问失败：rip=0x{rip:x} addr=0x{addr:x} len={len} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x}",
                    LAST_INTERPRETER_RAX.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RBX.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RCX.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RDX.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RSI.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RDI.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RBP.load(Ordering::Relaxed),
                    LAST_INTERPRETER_RSP.load(Ordering::Relaxed),
                    LAST_INTERPRETER_R12.load(Ordering::Relaxed),
                    LAST_INTERPRETER_R13.load(Ordering::Relaxed),
                    LAST_INTERPRETER_R14.load(Ordering::Relaxed),
                    LAST_INTERPRETER_R15.load(Ordering::Relaxed),
                );
                // 回放最近 12 条已执行指令（rip+字节），定位真实失败指令：
                // LAST_INTERPRETER_RIP 是探针区末尾滞留值，不是崩溃指令本尊。
                if std::env::var_os("DAOTI_TRACE_INSN_HISTORY").is_some() {
                    if let Ok(hist) = LAST_INSN_HISTORY.lock() {
                        let skip = hist.len().saturating_sub(12);
                        eprintln!(
                            "TRACE insn-history-before-fault total={} last={}",
                            hist.len(),
                            hist.len() - skip
                        );
                        for (hrip, hbytes) in hist.iter().skip(skip) {
                            eprintln!("TRACE insn RIP=0x{hrip:x} BYTES={hbytes:02x?}");
                        }
                    }
                }
                if addr == 0x28 && std::env::var_os("DAOTI_TRACE_VERSION_MAP").is_some() {
                    let map = LAST_INTERPRETER_RAX.load(Ordering::Relaxed);
                    let l_real = self
                        .regions
                        .iter()
                        .find(|region| map.saturating_add(0x28) >= region.base && map.saturating_add(0x30) <= region.end())
                        .map(|region| {
                            let offset = (map + 0x28 - region.base) as usize;
                            u64::from_le_bytes(region.bytes[offset..offset + 8].try_into().unwrap())
                        });
                    let l_ld = self
                        .regions
                        .iter()
                        .find(|region| map.saturating_add(0x10) >= region.base && map.saturating_add(0x18) <= region.end())
                        .map(|region| {
                            let offset = (map + 0x10 - region.base) as usize;
                            u64::from_le_bytes(region.bytes[offset..offset + 8].try_into().unwrap())
                        });
                    eprintln!(
                        "TRACE version-map-probe-failure rip=0x{rip:x} fault_addr=0x{addr:x} rax_map=0x{map:x} l_real={l_real:#x?} l_ld={l_ld:#x?}"
                    );
                }
                if addr <= 0x2000 && std::env::var_os("DAOTI_TRACE_LOW_ADDR").is_some() {
                    eprintln!("TRACE low-address-access rip=0x{rip:x} addr=0x{addr:x} len={len}");
                }
                DaotiError::Other(format!("地址不可访问：0x{addr:x}"))
            })
    }

    fn find_region_mut(&mut self, addr: u64, len: u64) -> Result<&mut MemoryRegion, DaotiError> {
        let end = addr.saturating_add(len);
        self.regions
            .iter_mut()
            .find(|r| addr >= r.base && end <= r.end())
            .ok_or_else(|| DaotiError::Other(format!("地址不可访问：0x{addr:x}")))
    }

    pub fn read(&self, addr: u64, len: u64) -> Result<&[u8], DaotiError> {
        if std::env::var_os("DAOTI_TRACE_RELA_READS").is_some()
            && !RELOC_PROBE_READING.load(Ordering::Relaxed)
        {
            let watched = WATCH_RELA_ADDR.load(Ordering::Relaxed);
            let size = WATCH_RELA_SIZE.load(Ordering::Relaxed);
            if watched != 0
                && addr < watched.saturating_add(size)
                && addr.saturating_add(len) > watched
            {
                let bytes = self.find_region(addr, len).ok().and_then(|region| {
                    let start = (addr - region.base) as usize;
                    let end = start.checked_add(len as usize)?;
                    region.bytes.get(start..end)
                });
                let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
                eprintln!(
                    "TRACE rela-read rip=0x{rip:x} addr=0x{addr:x} len={len} watch=0x{watched:x} size=0x{size:x} bytes={bytes:02x?}"
                );
            }
        }
        let cmp_trace_on = std::env::var_os("DAOTI_TRACE_CMP").is_some();
        if (std::env::var_os("DAOTI_TRACE_MEM_ACCESS").is_some() || cmp_trace_on)
            && addr == 0x270003a
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            let bytes = self.find_region(addr, len).ok().and_then(|region| {
                let start = (addr - region.base) as usize;
                let end = start.checked_add(len as usize)?;
                region.bytes.get(start..end)
            });
            eprintln!(
                "TRACE e_ehsize-read rip=0x{rip:x} addr=0x{addr:x} len={len} bytes={bytes:02x?} call_chain=unavailable-at-memory-layer"
            );
            // 置位 cmp/jcc 细粒度追踪：断言前最后一次 e_ehsize 读取触发。
            if cmp_trace_on {
                E_EHSIZE_READ_ARM.store(true, Ordering::Relaxed);
            }
        }
        // ld-linux 自举阶段把 l_addr 当作 _dl_rtld_map 基址；将其三个
        // 链表字段访问重定向到实际的 _rtld_global 存储区。
        let addr = match addr {
            0x2400018 => 0x2433038,
            0x2400020 => 0x2433040,
            0x2400028 => 0x2433048,
            _ => addr,
        };
        // 临时诊断：监视对 libc link_map l_nbuckets（map+0x2f4 = 0x273bdd4）的读取，
        // 定位 _dl_lookup_direct 的 div ecx 除数为 0 前谁把这个字段读成 0。
        if std::env::var_os("DAOTI_TRACE_NBUCKETS_READ").is_some()
            && addr < 0x273bdd8
            && addr.saturating_add(len) > 0x273bdd4
        {
            let bytes = self.find_region(addr, len).ok().and_then(|region| {
                let start = (addr - region.base) as usize;
                let end = start.checked_add(len as usize)?;
                region.bytes.get(start..end)
            });
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE nbuckets-read rip=0x{rip:x} addr=0x{addr:x} len={len} bytes={bytes:02x?}"
            );
        }
        let region = self.find_region(addr, len).map_err(|error| {
            if std::env::var_os("DAOTI_TRACE_MEM_ACCESS").is_some()
                && (addr == 0 || addr == 0x270003a)
            {
                let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
                let instruction = self.find_region(rip, 15).ok().and_then(|region| {
                    let start = (rip - region.base) as usize;
                    region.bytes.get(start..start + 15).map(|bytes| bytes.to_vec())
                });
                eprintln!(
                    "TRACE memory-read-fault rip=0x{rip:x} addr=0x{addr:x} len={len} instruction={instruction:?} error={error}"
                );
            }
            error
        })?;
        if !region.perm.read {
            return Err(DaotiError::Other(format!("地址不可读：0x{addr:x}")));
        }
        let start = (addr - region.base) as usize;
        let end = start + len as usize;
        let value = &region.bytes[start..end];
        Ok(value)
    }

    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), DaotiError> {
        // 与读取路径保持一致：ld-linux 自举阶段访问 _dl_rtld_map 的链表字段
        // 必须统一落到 _rtld_global 的实际存储区，不能一半写入 ELF 头。
        let addr = match addr {
            0x2400018 => 0x2433038,
            0x2400020 => 0x2433040,
            0x2400028 => 0x2433048,
            _ => addr,
        };
        // 临时诊断：监视对 libc link_map l_nbuckets（map+0x2f4 = 0x273bdd4）的写入，
        // 定位 div ecx 前谁把这个字段覆写成 0。
        if std::env::var_os("DAOTI_TRACE_NBUCKETS_READ").is_some()
            && addr < 0x273bdd8
            && addr.saturating_add(data.len() as u64) > 0x273bdd4
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE nbuckets-write rip=0x{rip:x} addr=0x{addr:x} len={} data={data:02x?}",
                data.len()
            );
        }
        // l_relocated 写监视：0x273ae0c = load_bias(0x2700000) + 0x3ae0c，
        // 即 GL(dl_rtld_map).l_relocated（bit2）。若自举 OR 指令执行，应出现 0x04 写入。
        if std::env::var_os("DAOTI_TRACE_LRELOCATED").is_some() && addr == 0x273ae0c {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE lreloc-write rip=0x{rip:x} addr=0x{addr:x} len={} data={data:02x?}",
                data.len()
            );
        }
        // 只读诊断：监视对已识别动态段（l_ld 基址附近 0x400 字节）的写入，
        // 以便定位"把 d_val 加 load_bias（绝对化）"的写入者。仅记录，不拦截。
        if std::env::var_os("DAOTI_TRACE_DYNSEG_WRITES").is_some() {
            let base = TRACE_DYN_BASE.load(Ordering::Relaxed);
            // 监视范围：TRACE_DYN_BASE 记录的动态段，或硬编码的 libc 动态段（0x91ebc0..0x91f000）。
            let tracked = (base != 0 && addr >= base && addr < base + 0x400)
                || (0x91ebc0..0x91f000).contains(&addr);
            if tracked {
                let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
                eprintln!(
                    "TRACE dynseg-write rip=0x{rip:x} base=0x{base:x} addr=0x{addr:x} len={} data={data:02x?}",
                    data.len()
                );
            }
        }
        // 只读诊断：监视对 guest ld.so 跳转表（0x272c120..+0x9c，vaddr 0x2c120）的写入，
        // 定位把槽1（R_X86_64_64 应为 -0x1abe3→0x1153d）改写为 bad_type 前序的写入者。
        if std::env::var_os("DAOTI_TRACE_JUMPTABLE_WRITES").is_some()
            && addr < 0x272c1bc
            && addr.saturating_add(data.len() as u64) > 0x272c120
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE jumptable-write rip=0x{rip:x} addr=0x{addr:x} len={} data={data:02x?}",
                data.len()
            );
        }
        if std::env::var_os("DAOTI_TRACE_ELF_HEADER_WRITES").is_some()
            && addr < 0x2700040
            && addr.saturating_add(data.len() as u64) > 0x2700000
        {
            let value = data
                .iter()
                .take(8)
                .enumerate()
                .fold(0u64, |acc, (index, byte)| {
                    acc | ((*byte as u64) << (index * 8))
                });
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!("TRACE elf-header-write rip=0x{rip:x} addr=0x{addr:x} len={} value=0x{value:x} data={data:02x?}", data.len());
        }
        if std::env::var_os("DAOTI_TRACE_WRITABLE_PT_LOAD").is_some() {
            let in_range = self
                .trace_writable_pt_load
                .iter()
                .any(|(range_start, range_end)| {
                    addr < *range_end && addr.saturating_add(data.len() as u64) > *range_start
                });
            if in_range {
                let value = data
                    .iter()
                    .take(8)
                    .enumerate()
                    .fold(0u64, |acc, (index, byte)| {
                        acc | ((*byte as u64) << (index * 8))
                    });
                if value != 0 {
                    let readable = self.read(addr, data.len() as u64).is_ok();
                    eprintln!("TRACE writable-pt-load-write addr=0x{addr:x} len={} value=0x{value:x} readable={readable}", data.len());
                }
            }
        }
        if std::env::var_os("DAOTI_TRACE_LINK_MAP_WRITE").is_some()
            && (0x273b230..0x273b240).contains(&addr)
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE link-map-write rip=0x{rip:x} addr=0x{addr:x} len={} bytes={data:02x?}",
                data.len()
            );
        }
        if std::env::var_os("DAOTI_TRACE_L_INFO_WRITE").is_some()
            && addr < 0x273bae0 + 0x68 + 8
            && addr.saturating_add(data.len() as u64) > 0x273bae0 + 0x68
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            let before = self
                .read(0x273bae0 + 0x68, 8)
                .ok()
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
            let incoming = data
                .iter()
                .take(8)
                .enumerate()
                .fold(0u64, |value, (index, byte)| {
                    value | ((*byte as u64) << (index * 8))
                });
            eprintln!(
                "TRACE l-info-write-watch rip=0x{rip:x} map=0x273bae0 field_addr=0x273bb48 offset=0x68 len={} before={before:#x?} incoming=0x{incoming:x} bytes={data:02x?}",
                data.len()
            );
        }
        if std::env::var_os("DAOTI_TRACE_MAIN_MAP_WRITE").is_some()
            && addr < 0x2762000
            && addr.saturating_add(data.len() as u64) > 0x2761000
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            let before = self
                .read(addr, data.len() as u64)
                .ok()
                .map(|bytes| bytes.to_vec());
            let value = data
                .iter()
                .take(8)
                .enumerate()
                .fold(0u64, |value, (index, byte)| {
                    value | ((*byte as u64) << (index * 8))
                });
            let field = if addr == 0x2761000 {
                "l_addr(+0x00)"
            } else if addr == 0x2761010 {
                "l_ld(+0x10)"
            } else if addr == 0x2761028 {
                "l_real(+0x28)"
            } else {
                "other"
            };
            eprintln!(
                "TRACE main-map-write rip=0x{rip:x} addr=0x{addr:x} offset=0x{:x} field={field} len={} value=0x{value:x} before={before:02x?} bytes={data:02x?}",
                addr - 0x2761000,
                data.len()
            );
        }
        if (std::env::var_os("DAOTI_TRACE_RTLD_GLOBAL_WRITE").is_some()
            || std::env::var_os("DAOTI_TRACE_NS_LOADED_WRITE").is_some())
            && (addr == 0x273a040 || addr == 0x273aa70 || (0x2733020..0x2733028).contains(&addr))
        {
            let before = self
                .read(addr, 8)
                .ok()
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
            let after = data
                .iter()
                .take(8)
                .enumerate()
                .fold(0u64, |value, (index, byte)| {
                    value | ((*byte as u64) << (index * 8))
                });
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE rtld-global-write rip=0x{rip:x} addr=0x{addr:x} len={} before={before:#x?} incoming=0x{after:x} bytes={data:02x?}",
                data.len()
            );
        }
        let mut corrected = data.to_vec();
        if std::env::var_os("DAOTI_FIX_NS_LOADED_WRITE").is_some()
            && data.len() >= 8
            && self
                .ns_loaded_write_fix
                .is_some_and(|(ns_loaded_addr, _)| addr == ns_loaded_addr)
        {
            let (_, main_map_addr) = self.ns_loaded_write_fix.unwrap();
            let before = self.read(addr, 8).ok();
            corrected[..8].copy_from_slice(&main_map_addr.to_le_bytes());
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE ns-loaded-write-fix rip=0x{rip:x} addr=0x{addr:x} before={before:02x?} incoming={data:02x?} corrected=0x{main_map_addr:x}"
            );
        }
        // 写修正已撤销：0x270ac00 处的 l_next=main_map 写入与 dl_main 的
        // _dl_add_to_namespace_list 是 glibc 合法链构建。此前按旧诊断把它们
        // 强制改为 0/0x275b000，反而破坏链导致 rtld.c:1720 断言失败。
        // 镜像初始垃圾（0x1ab70）改由 zero_rtld_map_l_next_if_nonzero 在
        // 运行前修正（dynamic_loader.rs），此处不再拦截运行时写入。
        if std::env::var_os("DAOTI_TRACE_HIGH_WRITES").is_some()
            && (0x4000000..0x5000000).contains(&addr)
        {
            let rip = LAST_INTERPRETER_RIP.load(Ordering::Relaxed);
            eprintln!(
                "TRACE high-write rip=0x{rip:x} addr=0x{addr:x} len={} data={corrected:02x?}",
                corrected.len()
            );
        }
        let region = self.find_region_mut(addr, corrected.len() as u64)?;
        if !region.perm.write {
            return Err(DaotiError::Other(format!("地址不可写：0x{addr:x}")));
        }
        let start = (addr - region.base) as usize;
        let end = start + corrected.len();
        if std::env::var_os("DAOTI_TRACE_STDOUT_WRITES").is_some()
            && (0x4a4320..0x4a43f0).contains(&addr)
        {
            eprintln!(
                "TRACE stdout-memory-write addr=0x{addr:x} len={} data={:02x?}",
                data.len(),
                data
            );
        }
        if std::env::var_os("DAOTI_TRACE_VTABLE_WRITES").is_some()
            && addr < 0x4a43e8
            && addr.saturating_add(data.len() as u64) > 0x4a43e0
        {
            eprintln!(
                "TRACE stdout-memory-write addr=0x{addr:x} len={} data={:02x?}",
                data.len(),
                data
            );
        }
        region.bytes[start..end].copy_from_slice(&corrected);
        Ok(())
    }

    pub fn is_executable(&self, addr: u64) -> bool {
        self.regions
            .iter()
            .any(|r| addr >= r.base && addr < r.end() && r.perm.execute)
    }
}

#[cfg(test)]
mod memory_model_tests {
    use super::{MemPerm, MemoryModel, MemoryRegion};

    fn writable_memory() -> MemoryModel {
        let mut memory = MemoryModel::new(0x2700000, 0x2760000);
        memory
            .add_region(MemoryRegion::with_data(
                0x2700000,
                MemPerm {
                    read: true,
                    write: true,
                    execute: false,
                },
                vec![0; 0x60000],
            ))
            .unwrap();
        memory
    }

    #[test]
    fn xchg_eax_ecx_swaps_low_words_and_clears_high_words() {
        let mut memory = MemoryModel::new(0x1000, 0x3000);
        memory
            .add_region(MemoryRegion::with_data(0x1000, MemPerm::rwx(), {
                let mut bytes = vec![0x91, 0xf4];
                bytes.resize(0x100, 0x90);
                bytes
            }))
            .unwrap();
        let mut context = super::RuntimeContext::new(0x1000, 0x2000, memory);
        context.registers.general.rax = 0xaaaa_aaaa_1234_5678;
        context.registers.general.rcx = 0xbbbb_bbbb_9abc_def0;
        let mut interpreter = super::X86_64Interpreter::new(context);
        assert_eq!(interpreter.run().unwrap(), super::ExecutionState::Faulted);
        assert_eq!(interpreter.context.registers.general.rax, 0x9abc_def0);
        assert_eq!(interpreter.context.registers.general.rcx, 0x1234_5678);
        assert_eq!(interpreter.context.registers.general.rip, 0x1001);
    }

    #[test]
    fn cmp_with_operand_size_prefix_uses_16_bit_flags() {
        let mut memory = MemoryModel::new(0x1000, 0x3000);
        memory
            .add_region(MemoryRegion::with_data(0x1000, MemPerm::rwx(), {
                let mut bytes = vec![0x66, 0x83, 0xf8, 0x40, 0xf4];
                bytes.resize(0x100, 0x90);
                bytes
            }))
            .unwrap();
        let mut context = super::RuntimeContext::new(0x1000, 0x2000, memory);
        context.registers.general.rax = 0x0000_0000_0000_0040;
        let mut interpreter = super::X86_64Interpreter::new(context);
        assert_eq!(interpreter.run().unwrap(), super::ExecutionState::Faulted);
        assert_ne!(interpreter.context.registers.general.rflags & 0x40, 0);
    }

    #[test]
    fn allows_rtld_legitimate_link_chain_writes() {
        // 调整后的期望值：0x270ac00 处 ld.so 把 _dl_rtld_map.l_next 写成
        // main_map（0x275a000）是合法链构建，写路径不得拦截改写。
        let mut memory = writable_memory();
        memory
            .write(0x2700018, &0x275a000u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(memory.read(0x2700018, 8).unwrap().try_into().unwrap()),
            0x275a000
        );

        // dl_main 的 _dl_add_to_namespace_list 会把 main_map.l_next 写成
        // 旧链头（ld.so_map 0x2700000），同样应原样保留。
        memory
            .write(0x275a018, &0x2700000u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(memory.read(0x275a018, 8).unwrap().try_into().unwrap()),
            0x2700000
        );
    }

    #[test]
    fn tls_get_addr_breakpoint_resolves_and_returns_like_glibc() {
        // 功能型断点端到端验证：rip 命中 __tls_get_addr 时，解释器按
        // System V AMD64 ABI 读取 tls_index（rdi → [module_id, offset]），
        // 经 TlsContext.get_addr 解析出 TLS 变量地址写入 rax，并模拟 ret。
        use super::super::relocation::{TlsContext, TlsSymbolLocation};
        use super::{ExecutionState, RuntimeBreakpoint, RuntimeContext, X86_64Interpreter};

        let mut memory = MemoryModel::new(0x1000, 0x2000);
        memory
            .add_region(MemoryRegion::with_data(0x1000, MemPerm::rwx(), {
                let mut bytes = vec![0u8; 0x1000];
                // 返回地址 0x1200 处放 hlt（0xf4），断点模拟 ret 后停机。
                bytes[0x200] = 0xf4;
                bytes
            }))
            .unwrap();
        // tls_index 结构：[0x1500]=ti_module_id(u32)=2、[0x1508]=ti_offset(u64)=0x10。
        memory.write(0x1500, &2u32.to_le_bytes()).unwrap();
        memory.write(0x1508, &0x10u64.to_le_bytes()).unwrap();
        // 栈上返回地址：rsp=0x1FF8 处存 0x1200。
        memory.write(0x1FF8, &0x1200u64.to_le_bytes()).unwrap();

        let mut context = RuntimeContext::new(0x1100, 0x1FF8, memory);
        context.registers.general.rdi = 0x1500;

        let mut tls = TlsContext::new(0x1000);
        tls.insert(
            "tls_var",
            TlsSymbolLocation {
                module_id: 2,
                block_start: 0x1800,
                offset: 0x10,
            },
        );

        let mut interpreter = X86_64Interpreter::new(context)
            .with_breakpoints(vec![RuntimeBreakpoint {
                name: "__tls_get_addr".into(),
                addr: 0x1100,
            }])
            .with_tls_context(tls);
        // 断点命中 → rax=block_start+offset=0x1810，模拟 ret 后 rip=0x1200 的 hlt → Faulted。
        assert_eq!(interpreter.run().unwrap(), ExecutionState::Faulted);
        assert_eq!(interpreter.context.registers.general.rax, 0x1810);
        assert_eq!(interpreter.context.registers.general.rip, 0x1200);
        assert_eq!(interpreter.context.registers.general.rsp, 0x2000);
    }
}

/// 执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionState {
    NotStarted,
    Running,
    Paused,
    Exited(i32),
    Faulted,
}

impl ExecutionState {
    pub fn exit(code: i32) -> Self {
        Self::Exited(code)
    }
}

/// 通用寄存器。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl GeneralRegisters {
    pub const fn zeroed() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
        }
    }
    pub fn new(rip: u64, rsp: u64) -> Self {
        Self {
            rip,
            rsp,
            ..Self::zeroed()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFile {
    pub general: GeneralRegisters,
}

impl RegisterFile {
    pub fn new(entry: u64, rsp: u64) -> Self {
        Self {
            general: GeneralRegisters::new(entry, rsp),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeContext {
    pub entry: u64,
    pub stack_ptr: u64,
    pub registers: RegisterFile,
    pub state: ExecutionState,
    pub memory: MemoryModel,
    pub tls_base: u64,
    /// 初始程序断点（brk 起始地址），用于 glibc sbrk/brk 系统调用
    pub heap_brk: u64,
    /// 堆区域结尾地址
    pub heap_end: u64,
}

impl RuntimeContext {
    pub fn new(entry: u64, rsp: u64, memory: MemoryModel) -> Self {
        Self {
            entry,
            stack_ptr: rsp,
            registers: RegisterFile::new(entry, rsp),
            state: ExecutionState::NotStarted,
            memory,
            tls_base: 0,
            heap_brk: 0,
            heap_end: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSyscallEvent {
    pub nr: u64,
    pub name: &'static str,
    pub args: [u64; 6],
}

impl RuntimeSyscallEvent {
    pub fn enter(nr: u64, name: &'static str, args: [u64; 6]) -> Self {
        Self { nr, name, args }
    }

    /// 转换为上层 B1/B2 使用的事件；编号溢出时拒绝转换，不猜测。
    pub fn to_syscall_event(
        &self,
        tid: u64,
    ) -> Result<crate::interceptor::SyscallEvent, DaotiError> {
        let nr = i32::try_from(self.nr)
            .map_err(|_| DaotiError::Other(format!("syscall 编号超出 i32 范围：{}", self.nr)))?;
        Ok(crate::interceptor::SyscallEvent::new(
            nr,
            self.name,
            self.args.iter().map(|arg| format!("0x{arg:x}")).collect(),
            tid,
        ))
    }
}

pub trait SyscallHandler {
    fn handle(&mut self, event: &RuntimeSyscallEvent) -> Result<i64, DaotiError>;
    fn handle_with_memory(
        &mut self,
        event: &RuntimeSyscallEvent,
        _memory: &mut MemoryModel,
    ) -> Result<i64, DaotiError> {
        self.handle(event)
    }
    /// 可选 syscall 上下文诊断钩子：在 handle_with_memory 前传入当前寄存器与内存现场。
    /// 默认实现为空，不产生任何副作用；仅诊断，不修改业务逻辑。
    fn diagnose_syscall_context(&mut self, _registers: &GeneralRegisters, _memory: &MemoryModel) {}
    fn diagnose_instruction_history(&mut self, _history: &[(u64, Vec<u8>, GeneralRegisters)]) {}
    fn exit_code(&self) -> Option<i32> {
        None
    }
    fn fs_base(&self) -> Option<u64> {
        None
    }
    fn capture_stdout(
        &mut self,
        _memory: &mut MemoryModel,
        _stdout_addr: u64,
    ) -> Result<(), DaotiError> {
        Ok(())
    }
    fn captured_stdout(&self) -> Vec<u8> {
        Vec::new()
    }
}

/// 动态 ELF 阶段化道体决策的划分。
///
/// 阶段 0：解释器入口之前（装载管线，设置初始 _rtld_global/link_map）。
/// 阶段 1：_dl_new_object 返回后（main_map 已创建）。
/// 阶段 2：依赖映射完成后。
/// 阶段 3：重定位完成后。
/// 阶段 4：dl_main 返回前 / 断言前。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseId {
    Zero,
    One,
    Two,
    Three,
    Four,
}

impl PhaseId {
    pub fn label(self) -> &'static str {
        match self {
            PhaseId::Zero => "phase_0_interpreter_entry",
            PhaseId::One => "phase_1_new_object_returned",
            PhaseId::Two => "phase_2_dependencies_mapped",
            PhaseId::Three => "phase_3_relocations_done",
            PhaseId::Four => "phase_4_before_assertion",
        }
    }
}

/// 执行断点：命中时按 x86_64 ABI 记录参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBreakpoint {
    pub name: String,
    pub addr: u64,
}

/// 断点命中后记录的结构化 ABI 参数证据（x86_64 System V：rdi/rsi/rdx/rcx/r8/r9）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHit {
    pub name: String,
    pub addr: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub r8: u64,
    pub r9: u64,
}

pub type PhaseHandler<'a> =
    Box<dyn FnMut(&mut RuntimeContext, PhaseId) -> Result<(), DaotiError> + 'a>;

pub type LinkMapInitializer<'a> =
    Box<dyn FnMut(&mut MemoryModel) -> Result<usize, DaotiError> + 'a>;
pub type LinkMapObjectInitializer<'a> =
    Box<dyn FnMut(&mut MemoryModel, u64) -> Result<(), DaotiError> + 'a>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainMapSourceEvidence {
    pub rip: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rax: u64,
    pub rdi: u64,
    pub rbp_slot: Option<u64>,
    pub rsp_slot: Option<u64>,
    pub rax_l_next: Option<u64>,
    pub rdi_value: Option<u64>,
    pub ns_loaded: Option<u64>,
}

pub struct X86_64Interpreter<'a> {
    pub context: RuntimeContext,
    /// 当前解释器映像的运行时 load bias；未设置时禁止动态 ELF 监控。
    pub load_bias: Option<u64>,
    phase_handler: Option<PhaseHandler<'a>>,
    /// 断言前采集的 main_map 来源证据，不参与状态写入。
    pub main_map_source_evidence: Vec<MainMapSourceEvidence>,
    syscall_handler: Option<Box<dyn SyscallHandler + 'a>>,
    xmm: [u128; 16],
    /// SSE/SSE2 控制状态（MXCSR）；x86 复位值为 0x1F80。
    mxcsr: u32,
    /// TLS/FS 段基址
    fs_base: u64,
    /// 当前指令是否有 FS 段覆盖前缀
    fs_override: bool,
    /// 哨兵返回模式：为 true 时 RIP 归零表示函数调用结束（用于 IFUNC 解析）
    sentinel_mode: bool,
    stdout_cleanup_addr: Option<u64>,
    stdout_addr: Option<u64>,
    stdout_captured: bool,
    /// 已设置的执行断点：rip 命中时记录 ABI 参数
    breakpoints: Vec<RuntimeBreakpoint>,
    /// 跨对象 TLS 上下文：装载期构建，供功能型断点 `__tls_get_addr` 查询 TLS 变量地址。
    tls_context: Option<super::relocation::TlsContext>,
    /// ld.so 创建主程序 map 后，接入预留 libc map 的一次性诊断/执行钩子。
    libc_link_map_patch: Option<(u64, u64, u64)>,
    user_entry: Option<u64>,
    pending_l_info_init: bool,
    link_map_initializer: Option<LinkMapInitializer<'a>>,
    link_map_object_initializer: Option<LinkMapObjectInitializer<'a>>,
}

impl<'a> X86_64Interpreter<'a> {
    pub fn new(context: RuntimeContext) -> Self {
        let fs_base = context.tls_base;
        Self {
            load_bias: None,
            context,
            phase_handler: None,
            main_map_source_evidence: Vec::new(),
            syscall_handler: None,
            xmm: [0u128; 16],
            mxcsr: 0x1F80,
            fs_base,
            fs_override: false,
            sentinel_mode: false,
            stdout_cleanup_addr: None,
            stdout_addr: None,
            stdout_captured: false,
            breakpoints: Vec::new(),
            tls_context: None,
            libc_link_map_patch: None,
            user_entry: None,
            pending_l_info_init: false,
            link_map_initializer: None,
            link_map_object_initializer: None,
        }
    }

    pub fn with_load_bias(mut self, load_bias: u64) -> Self {
        self.load_bias = Some(load_bias);
        self
    }

    pub fn with_user_entry(mut self, user_entry: u64) -> Self {
        self.user_entry = Some(user_entry);
        self
    }

    pub fn with_link_map_initializer(mut self, initializer: LinkMapInitializer<'a>) -> Self {
        self.link_map_initializer = Some(initializer);
        self
    }

    pub fn with_link_map_object_initializer(
        mut self,
        initializer: LinkMapObjectInitializer<'a>,
    ) -> Self {
        self.link_map_object_initializer = Some(initializer);
        self
    }

    pub fn with_delayed_link_map_init(mut self, dl_start: u64) -> Self {
        self.breakpoints.push(RuntimeBreakpoint {
            name: "_dl_start".into(),
            addr: dl_start,
        });
        self
    }

    pub fn with_namespace_root_addr(mut self, ns_loaded_addr: u64) -> Self {
        self.context.memory.namespace_root_addr = Some(ns_loaded_addr);
        self
    }

    /// 将解释器 ELF 内偏移转换为当前实例的运行时地址。
    /// 未提供 load bias 时不返回地址，禁止回退到历史绝对地址。
    fn monitor_addr(&self, offset: u64) -> Option<u64> {
        self.load_bias?.checked_add(offset)
    }

    fn monitor_hit(&self, rip: u64, offset: u64) -> bool {
        self.monitor_addr(offset) == Some(rip)
    }

    /// 只读追踪 `e_ehsize` 读取后的 cmp/test/jcc 指令：RIP、原始字节、
    /// rflags（ZF/SF/OF/CF/PF）与相关寄存器。不修改任何执行状态。
    fn trace_cmp_instruction(&self, rip: u64, steps: u64) -> bool {
        let Ok(bytes) = self.context.memory.read(rip, 15) else {
            return false;
        };
        // 跳过 REX 前缀与 66 操作数前缀。
        let mut idx = 0usize;
        while idx < bytes.len() && matches!(bytes[idx], 0x40..=0x4f | 0x66) {
            idx += 1;
        }
        let Some(&op) = bytes.get(idx) else {
            return false;
        };
        let g = &self.context.registers.general;
        let flags = g.rflags;
        let zf = flags & 0x40 != 0;
        let sf = flags & 0x80 != 0;
        let of = flags & 0x800 != 0;
        let cf = flags & 0x1 != 0;
        let pf = flags & 0x4 != 0;
        let reg_hex = format!(
            "rax=0x{:016x} rbx=0x{:016x} rcx=0x{:016x} rdx=0x{:016x} rsi=0x{:016x} rdi=0x{:016x} rbp=0x{:016x} rsp=0x{:016x}",
            g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp
        );
        let mut extra = String::new();

        // 条件跳转：打印条件、判定结果与目标。
        if (0x70..=0x7f).contains(&op) {
            let Some(&rel_b) = bytes.get(idx + 1) else {
                return false;
            };
            let rel = rel_b as i8 as i64;
            let taken = parse_jcc(op, flags);
            let target = (rip + (idx as u64 + 2)).wrapping_add_signed(rel);
            extra = format!(
                " kind=jcc_rel8 cond=0x{:02x} taken={taken} target=0x{target:016x}",
                op & 0x0f
            );
        } else if op == 0x0f {
            if let Some(&op2) = bytes.get(idx + 1) {
                if (0x80..=0x8f).contains(&op2) && idx + 6 <= bytes.len() {
                    let rel =
                        i32::from_le_bytes(bytes[idx + 2..idx + 6].try_into().unwrap()) as i64;
                    let taken = parse_jcc(op2, flags);
                    let target = (rip + (idx as u64 + 6)).wrapping_add_signed(rel);
                    extra = format!(
                        " kind=jcc_rel32 cond=0x{:02x} taken={taken} target=0x{target:016x}",
                        op2 & 0x0f
                    );
                }
            }
        } else if op == 0x3c {
            // cmp al, imm8
            if let Some(&imm) = bytes.get(idx + 1) {
                extra = format!(
                    " kind=cmp_al_imm8 lhs=0x{:02x} rhs=0x{imm:02x}",
                    g.rax & 0xff
                );
            }
        } else if op == 0x3d {
            // cmp eax/rax, imm32
            let width = if bytes[..idx].iter().any(|b| b & 0x08 != 0) {
                8
            } else {
                4
            };
            if idx + 5 <= bytes.len() {
                let raw = i32::from_le_bytes(bytes[idx + 1..idx + 5].try_into().unwrap());
                let imm = if width == 8 {
                    raw as i64 as u64
                } else {
                    raw as u32 as u64
                };
                let lhs = if width == 8 {
                    g.rax
                } else {
                    g.rax & 0xffff_ffff
                };
                extra = format!(" kind=cmp_imm32 width={width} lhs=0x{lhs:x} rhs=0x{imm:x}");
            }
        } else {
            // 通用 cmp / test / Grp1(/7)：打印 ModRM 供手工解析操作数。
            let kind = match op {
                0x38..=0x3b => "cmp",
                0x84 | 0x85 => "test",
                0x80 | 0x81 | 0x83
                    if bytes
                        .get(idx + 1)
                        .is_some_and(|modrm| (modrm >> 3) & 7 == 7) =>
                {
                    "cmp"
                }
                _ => return false, // 非追踪目标指令：跳过
            };
            let modrm = bytes.get(idx + 1).copied().unwrap_or(0);
            if matches!(op, 0x80 | 0x81 | 0x83) && (modrm >> 3) & 7 == 7 && modrm & 0xc7 == 0x05 {
                let imm_len = if op == 0x81 { 4 } else { 1 };
                let disp = bytes
                    .get(idx + 2..idx + 6)
                    .and_then(|raw| raw.try_into().ok())
                    .map(i32::from_le_bytes);
                let address = disp.map(|disp| {
                    (rip + (idx as u64 + 6 + imm_len as u64)).wrapping_add_signed(disp as i64)
                });
                let width: u64 = if op == 0x80 {
                    1
                } else if bytes[..idx].contains(&0x66) {
                    2
                } else if bytes[..idx].iter().any(|prefix| prefix & 0x08 != 0) {
                    8
                } else {
                    4
                };
                let lhs = address.and_then(|address| {
                    self.context.memory.read(address, width).ok().map(|raw| {
                        raw.iter().enumerate().fold(0u64, |value, (shift, byte)| {
                            value | ((*byte as u64) << (shift * 8))
                        })
                    })
                });
                let rhs = bytes.get(idx + 6).copied().map(|value| {
                    if op == 0x83 {
                        (value as i8 as i64) as u64
                    } else {
                        value as u64
                    }
                });
                extra = format!(
                    " kind=cmp_mem_imm width={width} address={address:#x?} lhs={lhs:#x?} rhs={rhs:#x?}"
                );
            } else {
                extra = format!(" kind={kind} modrm=0x{modrm:02x}");
            }
        }
        eprintln!(
            "TRACE cmp-detail step={steps} rip=0x{rip:016x} bytes={bytes:02x?} rflags=0x{flags:016x} ZF={zf} SF={sf} OF={of} CF={cf} PF={pf} {reg_hex}{extra}"
        );
        true
    }

    fn record_main_map_source_evidence(
        &mut self,
        rbp: u64,
        rsp: u64,
        rax: u64,
        rdi: u64,
        ns_loaded_addr: Option<u64>,
    ) {
        let read_u64 = |address: u64| {
            self.context
                .memory
                .read(address, 8)
                .ok()
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let evidence = MainMapSourceEvidence {
            rip: self.context.registers.general.rip,
            rbp,
            rsp,
            rax,
            rdi,
            rbp_slot: read_u64(rbp),
            rsp_slot: read_u64(rsp),
            rax_l_next: read_u64(rax.wrapping_add(0x18)),
            rdi_value: read_u64(rdi),
            ns_loaded: ns_loaded_addr.and_then(read_u64),
        };
        if std::env::var_os("DAOTI_TRACE_MAIN_MAP_SOURCE").is_some() {
            append_source_evidence_to_jsonl(&evidence);
        }
        self.main_map_source_evidence.push(evidence);
    }

    pub fn with_phase_handler(mut self, handler: PhaseHandler<'a>) -> Self {
        self.phase_handler = Some(handler);
        self
    }

    pub fn with_syscall_handler(mut self, handler: Box<dyn SyscallHandler + 'a>) -> Self {
        self.syscall_handler = Some(handler);
        self
    }

    /// 注册执行断点：rip 命中时记录 x86_64 ABI 参数（rdi/rsi/rdx/rcx/r8/r9）。
    pub fn with_libc_link_map_patch(
        mut self,
        ns_loaded_addr: u64,
        libc_map_addr: u64,
        patch_rip: u64,
    ) -> Self {
        self.libc_link_map_patch = Some((ns_loaded_addr, libc_map_addr, patch_rip));
        self
    }

    pub fn with_breakpoints(mut self, breakpoints: Vec<RuntimeBreakpoint>) -> Self {
        if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
            for bp in &breakpoints {
                eprintln!(
                    "TRACE runtime breakpoint set name={} addr=0x{:x}",
                    bp.name, bp.addr
                );
            }
        }
        self.breakpoints = breakpoints;
        self
    }

    /// 注入跨对象 TLS 上下文：使功能型断点 `__tls_get_addr` 能在执行期
    /// 按 (module_id, offset) 查询 TLS 变量地址并模拟返回。
    pub fn with_tls_context(mut self, tls_context: super::relocation::TlsContext) -> Self {
        self.tls_context = Some(tls_context);
        self
    }

    pub fn captured_stdout(&self) -> Vec<u8> {
        self.syscall_handler
            .as_ref()
            .map(|handler| handler.captured_stdout())
            .unwrap_or_default()
    }

    pub fn with_stdout_capture(
        mut self,
        cleanup_addr: Option<u64>,
        stdout_addr: Option<u64>,
    ) -> Self {
        self.stdout_cleanup_addr = cleanup_addr;
        self.stdout_addr = stdout_addr;
        self
    }

    /// 真实 x86_64 解释器主循环。
    pub fn run(&mut self) -> Result<ExecutionState, DaotiError> {
        self.context.state = ExecutionState::Running;
        let mut steps: u64 = 0;
        let mut trace_dlmain_steps = 0u64;
        let mut trace_dlmain_active = false;
        let trace_insn_enabled = std::env::var_os("DAOTI_TRACE_INSN").is_some();
        let mut trace_after_brk = 0u64;
        let mut instruction_history: VecDeque<(u64, Vec<u8>, GeneralRegisters)> =
            VecDeque::with_capacity(100);
        let mut trace_insn_log = if trace_insn_enabled {
            Some(
                std::fs::File::create("trae-insn-trace.log")
                    .map_err(|error| DaotiError::Other(format!("无法创建指令追踪日志：{error}")))?,
            )
        } else {
            None
        };
        let mut dlmain_args_logged = false;
        let mut entry_zero_addrs = Vec::new();
        let mut previous_rdi = self.context.registers.general.rdi;
        let mut previous_rip = self.context.registers.general.rip;
        let mut previous_opcode = 0u8;
        let mut previous_rdi_trace = false;
        let mut previous_r12 = self.context.registers.general.r12;
        let mut previous_r12_trace = false;
        // `e_ehsize` 读取触发后的 cmp/test/jcc 细粒度追踪剩余条数（0 = 未激活）。
        let mut cmp_trace_remaining = 0u64;
        const DLMAIN_TRACE_START_OFFSET: u64 = 0x1bfc0;
        const ASSERTION_OFFSET: u64 = 0x2571e;
        const RTLD_GLOBAL_OFFSET: u64 = 0x3a040;
        const NS_LOADED_OFFSET: u64 = 0xa30;
        // _dl_lookup_direct（glibc 2.35 elf/dl-lookup-direct.c）函数入口偏移。
        const LOOKUP_DIRECT_OFFSET: u64 = 0xd0b0;
        const DLMAIN_TRACE_MAX_STEPS: u64 = 10_000;
        let dlmain_trace_start = self.monitor_addr(DLMAIN_TRACE_START_OFFSET);
        let rtld_global_addr = self.monitor_addr(RTLD_GLOBAL_OFFSET);
        let ns_loaded_addr = self.monitor_addr(NS_LOADED_OFFSET);
        let mut call_chain_active = false;
        // (调用来源、目标、返回地址、是否写入解释器全局可写段)
        let mut dlmain_calls: Vec<(u64, u64, u64, bool)> = Vec::new();
        let call_chain_trace = std::env::var_os("DAOTI_TRACE_CALL_CHAIN").is_some();
        let mut call_chain_frames: Vec<(u64, u64, u64)> = Vec::new();
        let mut link_map_calls: Vec<(u64, u64, u64)> = Vec::new();
        let mut dl_start_calls: Vec<(u64, u64, u64)> = Vec::new();
        let mut delayed_l_info_initialized = false;
        let mut dlmain_trace = std::env::var_os("DAOTI_TRACE_DLMAIN")
            .map(|_| {
                std::fs::File::create("daoti-dlmain-trace.log").map_err(|e| {
                    DaotiError::Other(format!("无法创建 DAOTI_TRACE_DLMAIN 日志文件：{e}"))
                })
            })
            .transpose()?;
        loop {
            if self.context.state != ExecutionState::Running {
                return Ok(self.context.state);
            }

            if self.pending_l_info_init {
                if let Some(initializer) = self.link_map_initializer.as_mut() {
                    let initialized = initializer(&mut self.context.memory)?;
                    if std::env::var_os("DAOTI_TRACE_LOOKUP_HOOK").is_some() {
                        eprintln!(
                            "TRACE pending-l-info-init-observed rip=0x{:x} initialized={initialized}",
                            self.context.registers.general.rip
                        );
                    }
                } else if std::env::var_os("DAOTI_TRACE_LOOKUP_HOOK").is_some() {
                    eprintln!(
                        "TRACE pending-l-info-init-missing-handler rip=0x{:x}",
                        self.context.registers.general.rip
                    );
                }
                self.pending_l_info_init = false;
            }

            steps += 1;
            if steps > 10_000_000 {
                return Err(DaotiError::Other("解释器达到执行步数上限 (10M)".into()));
            }
            let rip = self.context.registers.general.rip;
            // glibc 早期 dl_main 会调用 __rtld_mutex_init（dl-mutex.c:44），其中
            // 通过 _dl_lookup_direct 查询 ld.so 自身 map 的符号。此刻 ld.so 尚未执行
            // 真正的 _dl_setup_hash，link_map 的 l_gnu_*/l_versions 字段全为零，
            // 导致查找返回 NULL、断言 sym != NULL 失败。因此在 _dl_lookup_direct
            // 入口对 rdi（link_map*）幂等补齐：l_info 已存在则直接跳过。
            if let Some(lookup_bias) = self.load_bias {
                if rip == lookup_bias + LOOKUP_DIRECT_OFFSET {
                    let map_arg = self.context.registers.general.rdi;
                    if std::env::var_os("DAOTI_TRACE_LOOKUP_HOOK").is_some() {
                        use std::sync::atomic::{AtomicBool, Ordering};
                        static LOOKUP_HOOK_PRINTED: AtomicBool = AtomicBool::new(false);
                        if !LOOKUP_HOOK_PRINTED.swap(true, Ordering::Relaxed) {
                            let field = |offset: u64| {
                                self.context
                                    .memory
                                    .read(map_arg + offset, 8)
                                    .ok()
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                                    .unwrap_or(0)
                            };
                            // 识别命中 map 的身份与链位置：l_name/l_real/l_next/l_prev
                            // 用于核对 __rtld_mutex_init 的 _ns_loaded（链头）与 hook 的
                            // rdi（libc 链尾）是否错位。
                            let name_ptr = field(0x8);
                            let mut name_bytes = Vec::new();
                            if name_ptr != 0 {
                                for i in 0..128u64 {
                                    let Ok([b]) = self.context.memory.read(name_ptr + i, 1) else {
                                        break;
                                    };
                                    if *b == 0 {
                                        break;
                                    }
                                    name_bytes.push(*b);
                                }
                            }
                            let l_name = String::from_utf8_lossy(&name_bytes);
                            // 读取 l_info[5]=DT_STRTAB 槽指向的 Elf64_Dyn(tag,d_ptr)
                            let linfo5 = field(0x68);
                            let linfo5_dyn = |off: u64| {
                                self.context
                                    .memory
                                    .read(linfo5.wrapping_add(off), 8)
                                    .ok()
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                                    .unwrap_or(0)
                            };
                            eprintln!(
                                "TRACE lookup-direct-entry rip=0x{rip:x} map=0x{map_arg:x} l_addr=0x{:x} l_name={l_name:?} l_real=0x{:x} l_next=0x{:x} l_prev=0x{:x} l_ld=0x{:x} l_info=0x{:x} l_nbuckets=0x{:x} l_gnu_bitmask=0x{:x} l_gnu_buckets=0x{:x} l_gnu_chain_zero=0x{:x} l_versions=0x{:x} l_versyms=0x{:x}",
                                field(0),
                                field(0x28),
                                field(0x30),
                                field(0x38),
                                field(0x10),
                                field(0x68),
                                field(0x2f4),
                                field(0x300),
                                field(0x308),
                                field(0x310),
                                field(0x2e8),
                                field(0x348)
                            );
                            // 补充：直接打印 l_info[DT_STRTAB] 槽位指向的 Dyn 内容，
                            // 确认 strtab 基址是否被错误保持为文件内偏移 0x1fd08。
                            eprintln!(
                                "TRACE lookup-direct-strtab linfo5=0x{linfo5:x} tag=0x{:x} d_ptr=0x{:x}",
                                linfo5_dyn(0),
                                linfo5_dyn(8)
                            );
                        }
                    }
                    // 关键字段可能是"可读但语义错误"的半成品（如 l_gnu_bitmask 恰好指向
                    // 文件内偏移），_dl_lookup_direct 据此走 GNU 路径返回 NULL 导致断言
                    // 失败。因此每次查找入口都无条件执行幂等初始化：从动态段重扫并覆盖
                    // 全部 hash/版本字段，确保指向真实 mmap 数据。
                    if map_arg != 0 && self.context.memory.read(map_arg, 8).is_ok() {
                        if let Err(error) = super::dynamic_loader::initialize_link_map_info(
                            &mut self.context.memory,
                            map_arg,
                        ) {
                            eprintln!(
                                "WARN initialize_link_map_info@lookup_direct map=0x{map_arg:x}: {error}"
                            );
                        }
                        // 临时诊断：初始化返回后立即回读关键 hash 字段，验证写入持久性。
                        if std::env::var_os("DAOTI_TRACE_NBUCKETS_READ").is_some() {
                            let verify = |offset: u64| {
                                self.context
                                    .memory
                                    .read(map_arg + offset, 8)
                                    .ok()
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                                    .unwrap_or(0)
                            };
                            eprintln!(
                                "TRACE hook-after-init map=0x{map_arg:x} nbuckets=0x{:x} shift=0x{:x} bitmask=0x{:x} buckets=0x{:x} chain_zero=0x{:x}",
                                verify(0x2f4),
                                verify(0x2f8),
                                verify(0x300),
                                verify(0x308),
                                verify(0x310)
                            );
                        }
                    }
                }
            }
            // IRELATIVE trampoline 区域逐指令跟踪：捕获 r12 从 0x705000 被破坏的精确指令
            if std::env::var_os("DAOTI_TRACE_IREL_RET").is_some()
                && (0x2710e00..=0x2711f00).contains(&rip)
            {
                let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                let g = &self.context.registers.general;
                eprintln!(
                    "TRACE irel-step step={steps} rip=0x{rip:x} bytes={bytes:02x?} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x}",
                    g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp, g.r12, g.r13, g.r14, g.r15
                );
            }
            // _dl_lookup_direct 主体逐指令追踪：定位 GNU 查找的精确失败点
            // （bucket 定位→chain 比对→版本匹配→返回 NULL/命中符号索引）。
            if std::env::var_os("DAOTI_TRACE_LOOKUP_BODY").is_some()
                && self
                    .load_bias
                    .is_some_and(|bias| (bias + 0xd0b8..bias + 0xd220).contains(&rip))
            {
                let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                let g = &self.context.registers.general;
                eprintln!(
                    "TRACE lookup-body step={steps} rip=0x{rip:x} bytes={bytes:02x?} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} r8=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x}",
                    g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.r8, g.r12, g.r13, g.r14, g.r15
                );
            }
            if std::env::var_os("DAOTI_TRACE_ASSERT_WINDOW").is_some()
                && self
                    .load_bias
                    .is_some_and(|bias| (bias + 0x25700..bias + 0x2571e).contains(&rip))
            {
                let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                let g = &self.context.registers.general;
                eprintln!(
                    "TRACE assert-window step={steps} rip=0x{rip:x} bytes={bytes:02x?} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rdi=0x{:x} rsi=0x{:x} rbp=0x{:x} rsp=0x{:x} rflags=0x{:x}",
                    g.rax, g.rbx, g.rcx, g.rdx, g.rdi, g.rsi, g.rbp, g.rsp, g.rflags
                );
            }
            // __ctype_init（libc + 0x3a3c0）诊断：由当前 RIP 反推 libc 基址，
            // 避免把旧运行的绝对地址误用于随机 load bias。
            let ctype_bytes = self.context.memory.read(rip, 7).ok();
            if std::env::var_os("DAOTI_TRACE_CTYPE_INIT").is_some()
                && ctype_bytes
                    .as_ref()
                    .is_some_and(|bytes| bytes == &[0x48, 0x8b, 0x05, 0xa5, 0xfb, 0x1d, 0x00])
            {
                let g = &self.context.registers.general;
                let libc_base = rip.wrapping_sub(0x3a3c4);
                let fs_addr = self.fs_base.wrapping_add(g.rax);
                let tls_low = self.fs_base.wrapping_sub(0x4000);
                let tls_high = self.fs_base.wrapping_add(0x4000);
                let covered_low = self.context.memory.read(tls_low, 8).is_ok();
                let covered_fs = self.context.memory.read(self.fs_base, 8).is_ok();
                let covered_high = self.context.memory.read(tls_high, 8).is_ok();
                let rip_slot = libc_base.wrapping_add(0x219f70);
                let rip_slot_value = self
                    .context
                    .memory
                    .read(rip_slot, 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE ctype-init step={steps} rip=0x{rip:x} libc_base=0x{libc_base:x} fs_base=0x{:x} rax=0x{:x} fs_addr=0x{fs_addr:x} [fs_addr]=0x{:?} tls_low=0x{tls_low:x} covered_low={covered_low} covered_fs={covered_fs} covered_high={covered_high} rip_slot=0x{rip_slot:x} rip_slot_value=0x{rip_slot_value:?}",
                    self.fs_base,
                    g.rax,
                    self.context.memory.read(fs_addr, 8).ok().map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                );
            }
            if std::env::var_os("DAOTI_TRACE_DLMAIN_R15").is_some()
                && self.monitor_addr(0x22243) == Some(rip)
            {
                let bytes = self.context.memory.read(rip, 8).unwrap_or_default();
                let g = &self.context.registers.general;
                eprintln!(
                    "TRACE dl-main-r15-assign step={steps} rip=0x{rip:x} bytes={bytes:02x?} rax_return=0x{:x} r15_before=0x{:x} rbp=0x{:x} rsp=0x{:x}",
                    g.rax, g.r15, g.rbp, g.rsp
                );
            }
            if std::env::var_os("DAOTI_TRACE_NAMESPACE_ENTRY").is_some()
                && self
                    .load_bias
                    .is_some_and(|bias| (bias + 0xd920..bias + 0xd940).contains(&rip))
            {
                let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                let g = &self.context.registers.general;
                let namespace_slot = g
                    .r12
                    .wrapping_sub(0xa30)
                    .wrapping_add(g.rbx.wrapping_mul(5).wrapping_mul(0x20));
                let slot_value = self
                    .context
                    .memory
                    .read(namespace_slot, 8)
                    .ok()
                    .map(|value| u64::from_le_bytes(value.try_into().unwrap()));
                eprintln!(
                    "TRACE namespace-entry step={steps} rip=0x{rip:x} bytes={bytes:02x?} map_arg_rbp=0x{:x} namespace_id_rbx=0x{:x} namespace_base_r12=0x{:x} rtld_global_rdx=0x{:x} namespace_arg_rcx=0x{:x} namespace_slot=0x{namespace_slot:x} slot_value={slot_value:#x?}",
                    g.rbp, g.rbx, g.r12, g.rdx, g.rcx
                );
                if std::env::var_os("DAOTI_FIX_L_INFO").is_some() && g.rbp != 0 {
                    if let Err(error) = ensure_l_info(&mut self.context.memory, g.rbp) {
                        eprintln!("WARN ensure_l_info failed map=0x{:x}: {error}", g.rbp);
                    } else {
                        let l_info = self
                            .context
                            .memory
                            .read(g.rbp + 0x68, 8)
                            .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
                            .unwrap_or(0);
                        eprintln!(
                            "TRACE ensure-l-info map=0x{:x} l_info=0x{:x}",
                            g.rbp, l_info
                        );
                    }
                }
            }
            // l_relocated 调试：写入点 0x21510（or byte [rip+0x198f5],4 → 0x3ae0c）
            // 与断言读取点 0x2281b（test byte [rip+0x185ea],4）。仅观测，不修改状态。
            if std::env::var_os("DAOTI_TRACE_LRELOCATED").is_some() {
                let g = &self.context.registers.general;
                if self.monitor_addr(0x21510) == Some(rip) {
                    let bytes = self.context.memory.read(rip, 8).unwrap_or_default();
                    let lreloc_addr = self.monitor_addr(0x3ae0c);
                    let value = lreloc_addr.and_then(|address| {
                        self.context.memory.read(address, 1).ok().map(|v| v[0])
                    });
                    eprintln!(
                        "TRACE lreloc-write-hit step={steps} rip=0x{rip:x} bytes={bytes:02x?} dst=0x{:x} before={value:?} rax=0x{:x} rbx=0x{:x}",
                        lreloc_addr.unwrap_or(0),
                        g.rax,
                        g.rbx
                    );
                }
                if self.monitor_addr(0x2281b) == Some(rip) {
                    let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                    let lreloc_addr = self.monitor_addr(0x3ae0c);
                    let value = lreloc_addr.and_then(|address| {
                        self.context.memory.read(address, 1).ok().map(|v| v[0])
                    });
                    eprintln!(
                        "TRACE lreloc-assert-read step={steps} rip=0x{rip:x} bytes={bytes:02x?} src=0x{:x} value={value:?} rflags=0x{:x}",
                        lreloc_addr.unwrap_or(0),
                        g.rflags
                    );
                }
            }
            if std::env::var_os("DAOTI_TRACE_ASSERT_COMPARE").is_some()
                && self.monitor_addr(0x22287) == Some(rip)
            {
                let bytes = self.context.memory.read(rip, 8).unwrap_or_default();
                let g = &self.context.registers.general;
                let rtld_addr = self.monitor_addr(0x3a040);
                let rtld_value = rtld_addr.and_then(|address| {
                    self.context
                        .memory
                        .read(address, 8)
                        .ok()
                        .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
                });
                eprintln!(
                    "TRACE assert-compare step={steps} rip=0x{rip:x} bytes={bytes:02x?} main_map_r15=0x{:x} rtld_global_addr={:#x?} rtld_global_value={:#x?} rax=0x{:x} rbp=0x{:x} rsp=0x{:x}",
                    g.r15,
                    rtld_addr,
                    rtld_value,
                    g.rax,
                    g.rbp,
                    g.rsp
                );
            }
            // `e_ehsize` 读取完成 → 激活接下来的 200 条指令内的 cmp/test/jcc 追踪。
            if cmp_trace_remaining == 0 && E_EHSIZE_READ_ARM.swap(false, Ordering::Relaxed) {
                cmp_trace_remaining = 50;
                eprintln!("TRACE cmp-mode ARMED window=50 step={steps} rip=0x{rip:016x}");
            }
            if cmp_trace_remaining > 0 {
                cmp_trace_remaining -= 1;
                self.trace_cmp_instruction(rip, steps);
            }
            if std::env::var_os("DAOTI_TRACE_INSN_HISTORY").is_some() {
                let bytes = self
                    .context
                    .memory
                    .read(rip, 8)
                    .unwrap_or_default()
                    .to_vec();
                if instruction_history.len() == 100 {
                    instruction_history.pop_front();
                }
                instruction_history.push_back((rip, bytes.clone(), self.context.registers.general));
                if let Ok(mut global_hist) = LAST_INSN_HISTORY.lock() {
                    if global_hist.len() == 100 {
                        global_hist.pop_front();
                    }
                    global_hist.push_back((rip, bytes));
                }
            }
            if std::env::var_os("DAOTI_TRACE_NAMESPACE").is_some()
                && self
                    .load_bias
                    .is_some_and(|base| (base + 0xd8f0..base + 0xd990).contains(&rip))
            {
                let g = &self.context.registers.general;
                eprintln!(
                    "TRACE namespace-step rip=0x{rip:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} rbp=0x{:x} r12=0x{:x} ns_loaded={:#x?}",
                    g.rdi,
                    g.rsi,
                    g.rdx,
                    g.rbp,
                    g.r12,
                    ns_loaded_addr.and_then(|address| self.context.memory.read(address, 8).ok())
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                );
            }
            trace_after_brk = trace_after_brk.saturating_sub(1);
            if let Some(file) = trace_insn_log.as_mut() {
                let sample = trace_after_brk > 0 || steps.is_multiple_of(1000);
                if sample {
                    use std::io::Write;
                    let g = &self.context.registers.general;
                    let op_hex = self
                        .context
                        .memory
                        .read(rip, 8)
                        .map(|bytes| {
                            bytes
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_else(|_| "MEM?".into());
                    let _ = writeln!(file, "STEP={steps} RIP=0x{rip:016x} BYTES=[{op_hex}] RAX=0x{:x} RSP=0x{:x} RBP=0x{:x}", g.rax, g.rsp, g.rbp);
                }
            }
            if std::env::var_os("DAOTI_TRACE_RTLD_PHDR").is_some()
                && self
                    .load_bias
                    .is_some_and(|bias| (bias + 0x20c0..bias + 0x2300).contains(&rip))
            {
                let g = &self.context.registers.general;
                let bytes = self.context.memory.read(rip, 16).unwrap_or_default();
                eprintln!(
                    "TRACE rtld-phdr-step rip=0x{rip:x} bytes={bytes:02x?} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rdi=0x{:x} rsi=0x{:x} rsp=0x{:x}",
                    g.rax, g.rbx, g.rcx, g.rdx, g.rdi, g.rsi, g.rsp
                );
            }
            if previous_r12_trace && previous_r12 != self.context.registers.general.r12 {
                eprintln!(
                    "TRACE r12-change rip=0x{previous_rip:x} opcode=0x{previous_opcode:02x} old=0x{previous_r12:x} new=0x{:x}",
                    self.context.registers.general.r12
                );
            }
            if previous_rdi_trace
                && previous_rdi != self.context.registers.general.rdi
                && !self.monitor_hit(previous_rip, ASSERTION_OFFSET)
            {
                eprintln!(
                    "TRACE rdi-change rip=0x{previous_rip:x} opcode=0x{previous_opcode:02x} old=0x{previous_rdi:x} new=0x{:x}",
                    self.context.registers.general.rdi
                );
            }
            previous_rdi = self.context.registers.general.rdi;
            previous_r12 = self.context.registers.general.r12;
            previous_rip = rip;
            previous_opcode = self
                .context
                .memory
                .read(rip, 1)
                .ok()
                .map(|b| b[0])
                .unwrap_or(0);
            previous_rdi_trace = trace_dlmain_active && !self.monitor_hit(rip, ASSERTION_OFFSET);
            previous_r12_trace = trace_dlmain_active && !self.monitor_hit(rip, ASSERTION_OFFSET);
            if dlmain_trace.is_some()
                && (self.monitor_hit(rip, 0x1ab70) || dlmain_trace_start == Some(rip))
            {
                if let Some(rtld_global) = rtld_global_addr {
                    if let Ok(bytes) = self.context.memory.read(rtld_global, 8) {
                        let value = u64::from_le_bytes(bytes.try_into().unwrap());
                        let label = if self.monitor_hit(rip, 0x1ab70) {
                            "_dl_start"
                        } else {
                            "dl_main"
                        };
                        eprintln!("TRACE {label}-entry _rtld_global.l_addr=0x{value:x}");
                    }
                }
                if dlmain_trace_start == Some(rip) {
                    entry_zero_addrs.clear();
                    if let Some(rtld_global) = rtld_global_addr {
                        for address in (rtld_global..rtld_global.saturating_add(0x2000)).step_by(8)
                        {
                            if self
                                .context
                                .memory
                                .read(address, 8)
                                .ok()
                                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                                == Some(0)
                            {
                                entry_zero_addrs.push(address);
                            }
                        }
                    }
                    let g = &self.context.registers.general;
                    let read_u64 = |addr: u64| -> Option<u64> {
                        self.context
                            .memory
                            .read(addr, 8)
                            .ok()
                            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    };
                    eprintln!(
                        "TRACE rtld-global-entry-zero-count={}",
                        entry_zero_addrs.len()
                    );
                    eprintln!(
                        "DL_MAIN_ENTRY: rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} rcx=0x{:x} l_addr={:#x?} ns_loaded={:#x?}",
                        g.rdi, g.rsi, g.rdx, g.rcx,
                        rtld_global_addr.and_then(read_u64), ns_loaded_addr.and_then(read_u64)
                    );
                }
            }
            if self.monitor_hit(rip, ASSERTION_OFFSET) {
                let (rax, rdi, rbp, rsp) = {
                    let g = &self.context.registers.general;
                    (g.rax, g.rdi, g.rbp, g.rsp)
                };
                self.record_main_map_source_evidence(rbp, rsp, rax, rdi, ns_loaded_addr);
                if std::env::var_os("DAOTI_TRACE_MAIN_MAP_SOURCE").is_some() {
                    eprintln!(
                        "TRACE main-map-source phase={} rbp=0x{:x} rsp=0x{:x} rax=0x{:x} rdi=0x{:x}",
                        PhaseId::Four.label(), rbp, rsp, rax, rdi
                    );
                }
                if let Some(handler) = self.phase_handler.as_mut() {
                    handler(&mut self.context, PhaseId::Four)?;
                }
            }
            if dlmain_trace.is_some() && dlmain_trace_start == Some(rip) {
                trace_dlmain_active = true;
                trace_dlmain_steps = 0;
                if !dlmain_args_logged {
                    let g = &self.context.registers.general;
                    eprintln!(
                        "TRACE dl-main-abi phdr=0x{:x} phnum=0x{:x} user_entry=0x{:x} auxv=0x{:x}",
                        g.rdi, g.rsi, g.rdx, g.rcx
                    );
                    dlmain_args_logged = true;
                }
            }
            if trace_dlmain_active {
                if self.monitor_hit(rip, ASSERTION_OFFSET)
                    || trace_dlmain_steps >= DLMAIN_TRACE_MAX_STEPS
                {
                    trace_dlmain_active = false;
                } else {
                    trace_dlmain_steps += 1;
                }
            }
            if std::env::var_os("DAOTI_TRACE_STARTUP").is_some() && steps < 3 {
                let rsp = self.context.registers.general.rsp;
                let words = self.context.memory.read(rsp, 512).ok();
                eprintln!(
                    "动态 ELF 启动状态：rip=0x{rip:x} rsp=0x{rsp:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} rcx=0x{:x} fs=0x{:x} stack={words:02x?}",
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rdx,
                    self.context.registers.general.rcx,
                    self.fs_base
                );
                if let Ok(auxv) = self.context.memory.read(rsp + 24, 19 * 16) {
                    eprintln!("TRACE startup-auxv rsp=0x{rsp:x} bytes={auxv:02x?}");
                }
                if let Ok(phdr) = self
                    .context
                    .memory
                    .read(self.context.registers.general.rsi, 56)
                {
                    eprintln!(
                        "TRACE startup-phdr addr=0x{:x} bytes={phdr:02x?}",
                        self.context.registers.general.rsi
                    );
                }
            }
            if std::env::var_os("DAOTI_TRACE_VERSION_ENTRY").is_some()
                && self.monitor_addr(0x15f30) == Some(rip)
            {
                let g = &self.context.registers.general;
                if std::env::var_os("DAOTI_TRACE_RIP_2715F30").is_some() {
                    let read_rax_field = |offset: u64| {
                        self.context
                            .memory
                            .read(g.rax.wrapping_add(offset), 8)
                            .ok()
                            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    };
                    let l_name = read_rax_field(0x08);
                    let l_name_bytes = l_name.and_then(|address| {
                        self.context.memory.read(address, 64).ok().map(|bytes| {
                            bytes
                                .iter()
                                .copied()
                                .take(64)
                                .take_while(|byte| *byte != 0)
                                .collect::<Vec<_>>()
                        })
                    });
                    eprintln!(
                        "TRACE rip-2715f30 step={steps} rip=0x{rip:x} rax=0x{:x} rax_l_name_ptr={l_name:#x?} rax_l_addr={:#x?} rax_l_ld={:#x?} rax_l_next={:#x?} rax_l_real={:#x?} rax_l_info={:#x?} l_name_bytes={l_name_bytes:?} rbp=0x{:x} rbx=0x{:x} r12=0x{:x} r15=0x{:x}",
                        g.rax,
                        read_rax_field(0x00),
                        read_rax_field(0x10),
                        read_rax_field(0x18),
                        read_rax_field(0x28),
                        read_rax_field(0x68),
                        g.rbp,
                        g.rbx,
                        g.r12,
                        g.r15
                    );
                }
                let read_field = |offset: u64| {
                    self.context
                        .memory
                        .read(g.rbp.wrapping_add(offset), 8)
                        .ok()
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                };
                let l_info = read_field(0x68);
                let version_slots = l_info.map(|info| {
                    [
                        ("DT_VERSYM", 50u64),
                        ("DT_VERDEF", 38u64),
                        ("DT_VERDEFNUM", 37u64),
                        ("DT_VERNEED", 36u64),
                        ("DT_VERNEEDNUM", 35u64),
                    ]
                    .into_iter()
                    .map(|(name, index)| {
                        let address = info + index * 8;
                        let value = self
                            .context
                            .memory
                            .read(address, 8)
                            .ok()
                            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                        (name, address, value)
                    })
                    .collect::<Vec<_>>()
                });
                eprintln!(
                    "TRACE version-entry step={steps} rip=0x{rip:x} rbp_map=0x{:x} l_addr={:#x?} l_ld={:#x?} l_real={:#x?} l_info={l_info:#x?} version_slots={version_slots:?} rax=0x{:x} rbx=0x{:x} r12=0x{:x} r15=0x{:x}",
                    g.rbp,
                    read_field(0x00),
                    read_field(0x10),
                    read_field(0x28),
                    g.rax,
                    g.rbx,
                    g.r12,
                    g.r15
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP_WINDOW_2715F00").is_some()
                && self
                    .load_bias
                    .is_some_and(|bias| (bias + 0x15f00..=bias + 0x15f30).contains(&rip))
            {
                let g = &self.context.registers.general;
                let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                eprintln!(
                    "TRACE rip-window-2715f00 step={steps} rip=0x{rip:x} rax=0x{:x} rbp=0x{:x} bytes={bytes:02x?}",
                    g.rax, g.rbp
                );
            }
            if std::env::var_os("DAOTI_TRACE_EXCEPTION_INTERNAL").is_some()
                && self
                    .load_bias
                    .is_some_and(|bias| (bias + 0x4ba0..bias + 0x4d00).contains(&rip))
            {
                let g = &self.context.registers.general;
                let bytes = self.context.memory.read(rip, 15).unwrap_or_default();
                let stack = self.context.memory.read(g.rsp, 32).ok();
                let return_target = (bytes.first() == Some(&0xc3))
                    .then(|| self.context.memory.read(g.rsp, 8).ok())
                    .flatten()
                    .map(|value| u64::from_le_bytes(value.try_into().unwrap()));
                eprintln!(
                    "TRACE exception-internal step={steps} rip=0x{rip:x} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x} r8=0x{:x} r9=0x{:x} rflags=0x{:x} return_target={return_target:#x?} stack={stack:02x?} bytes={bytes:02x?}",
                    g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp, g.r8, g.r9, g.rflags
                );
            }
            let g = &self.context.registers.general;
            if std::env::var_os("DAOTI_TRACE_RELOC_CALLSITE").is_some()
                && (0x2715ee2..=0x2715f4b).contains(&rip)
            {
                let read_u64 = |address: u64| {
                    self.context
                        .memory
                        .read(address, 8)
                        .ok()
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                };
                // 上一轮 0xe2a270 rela-read 是探针自读（2144-2148 行读取 rela_first_entry 时
                // 命中自己刚设置的 WATCH_RELA_ADDR）。现在改用 probe_read 屏蔽自读。
                let map = if (0x2715f02..=0x2715f4b).contains(&rip) {
                    g.rax
                } else {
                    0
                };
                let l_addr = (map != 0).then(|| read_u64(map)).flatten();
                let l_ld = (map != 0).then(|| read_u64(map + 0x10)).flatten();
                // 第五轮日志的 slot_scan 证实：link_map 中 l_info[] 内联数组起点是 map+0x40，
                // 槽索引 = DT_tag（此前用 map+0x68 只读到 l_info[5] 槽内容，系统性错位）。
                // l_info[tag] 槽位保存动态条目指针 ElfW(Dyn)*，需再解引用一次取 (d_tag, d_un.d_ptr)。
                let l_info = if map != 0 { Some(map + 0x40) } else { None };
                let read_dyn = |entry: u64| (read_u64(entry), read_u64(entry + 8));
                let rela_dyn_entry = l_info.and_then(|base| read_u64(base + 7 * 8));
                let (rela_tag, rela_raw) = rela_dyn_entry.map(read_dyn).unwrap_or((None, None));
                let relasz_dyn_entry = l_info.and_then(|base| read_u64(base + 8 * 8));
                let (relasz_tag, relasz_raw) =
                    relasz_dyn_entry.map(read_dyn).unwrap_or((None, None));
                let runtime_rela = rela_raw.zip(l_addr).map(|(v, base)| base.wrapping_add(v));
                // dump 重定位表首条目 24 字节：r_offset(8) + r_info(8) + r_addend(8)
                let rela_first_entry = runtime_rela
                    .and_then(|address| probe_read(&self.context.memory, address, 24).ok())
                    .map(|bytes| bytes.to_vec());
                let first_r_offset = rela_first_entry
                    .as_ref()
                    .map(|b| u64::from_le_bytes(b[0..8].try_into().unwrap()));
                let first_r_info = rela_first_entry
                    .as_ref()
                    .map(|b| u64::from_le_bytes(b[8..16].try_into().unwrap()));
                let first_r_addend = rela_first_entry
                    .as_ref()
                    .map(|b| u64::from_le_bytes(b[16..24].try_into().unwrap()));
                let first_type_low32 = first_r_info.map(|info| (info & 0xffff_ffff) as u32);
                let dynamic_rela = l_ld.and_then(|base| {
                    (0..256u64).find_map(|index| {
                        let entry = base + index * 16;
                        (read_u64(entry) == Some(7))
                            .then(|| read_u64(entry + 8))
                            .flatten()
                    })
                });
                // 详细 dump：仅在 0x2715f02（每轮循环进入处）输出，避免日志爆炸
                let mut dyn_dump = Vec::new();
                let mut info_dump = Vec::new();
                let mut rela_content = None;
                if rip == 0x2715f02 {
                    if let Some(base) = l_ld {
                        for index in 0..12u64 {
                            let entry = base + index * 16;
                            let (tag, value) = (read_u64(entry), read_u64(entry + 8));
                            if tag == Some(0) {
                                dyn_dump.push("(0,0)@END".to_string());
                                break;
                            }
                            dyn_dump.push(format!("({tag:?},{value:?})"));
                        }
                    }
                    if let Some(base) = l_info {
                        for index in 0..16u64 {
                            info_dump.push(format!("[{index}]={:?}", read_u64(base + index * 8)));
                        }
                    }
                    // 按 guest 动态段语义（d_ptr 已是绝对运行时地址）读取 rela 表首条目内容
                    rela_content = dynamic_rela.and_then(|address| {
                        probe_read(&self.context.memory, address, 24)
                            .ok()
                            .map(|b| b.to_vec())
                    });
                    // 深度只读探针：仅当切换到新 map 时打印一次，验证 l_info 内联布局与
                    // glibc D_PTR（d_val + l_addr）双重加偏置假设，不改任何执行状态。
                    // 同时把当前 map 的动态段基址记录到全局原子，供 MemoryModel::write 监视。
                    if let Some(base) = l_ld {
                        TRACE_DYN_BASE.store(base, Ordering::Relaxed);
                    }
                    let prev_deep = LAST_DEEP_MAP.swap(map, Ordering::Relaxed);
                    if prev_deep != map && map != 0 {
                        let name_ptr = read_u64(map + 0x08);
                        let name_bytes = name_ptr.and_then(|ptr| {
                            if ptr == 0 {
                                None
                            } else {
                                self.context.memory.read(ptr, 24).ok().map(|b| {
                                    b.iter()
                                        .take_while(|byte| **byte != 0)
                                        .map(|byte| *byte as char)
                                        .collect::<String>()
                                })
                            }
                        });
                        let inline_slot = |tag: u64| read_u64(map + 0x40 + tag * 8);
                        // 找出 l_info 数组真实起点：扫描 map+0x40..map+0xa0 的槽，
                        // 并尝试把非零槽值解引用为动态条目 (d_tag, d_val)。
                        let mut slot_scan = Vec::new();
                        for off in (0x40u64..0xa0).step_by(8) {
                            let slot_value = read_u64(map + off);
                            let resolved = slot_value.and_then(|value| {
                                if value == 0 {
                                    None
                                } else {
                                    read_u64(value).zip(read_u64(value + 8))
                                }
                            });
                            slot_scan.push(format!("map+0x{off:x}={slot_value:#x?}->{resolved:?}"));
                        }
                        // 打印动态段逐项 (index, d_tag, d_val) 以便与文件 .dynamic dump 对比，
                        // 验证哪些 d_val 被加过 load_bias（绝对化）。
                        let mut dyn_vals = Vec::new();
                        if let Some(base) = l_ld {
                            for index in 0..40u64 {
                                if let Some(tag) = read_u64(base + index * 16) {
                                    if tag == 0 {
                                        dyn_vals.push(format!("[{index}]=tag=0,val=0@END"));
                                        break;
                                    }
                                    let val = read_u64(base + index * 16 + 8).unwrap_or(u64::MAX);
                                    dyn_vals.push(format!("[{index}]=tag=0x{tag:x},val=0x{val:x}"));
                                } else {
                                    break;
                                }
                            }
                        }
                        // 验证 l_info 数组中所有非零槽解引用后的 (tag,value) 是否为合法动态条目。
                        // 起点为 map+0x40（真实 l_info 内联数组基址）。
                        let mut info_resolved = Vec::new();
                        for slot_index in 0..64u64 {
                            let slot_ptr = read_u64(map + 0x40 + slot_index * 8);
                            if let Some(ptr) = slot_ptr {
                                if ptr != 0 {
                                    let decoded = read_u64(ptr).zip(read_u64(ptr + 8));
                                    info_resolved.push(format!(
                                        "l_info[{slot_index}]=0x{ptr:x}->{decoded:?}"
                                    ));
                                } else {
                                    info_resolved.push(format!("l_info[{slot_index}]=NULL"));
                                }
                            } else {
                                info_resolved.push(format!("l_info[{slot_index}]=UNREADABLE"));
                            }
                        }
                        let rela_plus_bias = l_addr
                            .zip(dynamic_rela)
                            .map(|(base, value)| base.wrapping_add(value));
                        let rela_plus_bias_content = rela_plus_bias.and_then(|address| {
                            probe_read(&self.context.memory, address, 24)
                                .ok()
                                .map(|b| b.to_vec())
                        });
                        let strtab_dval = l_ld.and_then(|base| {
                            (0..256u64).find_map(|index| {
                                let entry = base + index * 16;
                                (read_u64(entry) == Some(5))
                                    .then(|| read_u64(entry + 8))
                                    .flatten()
                            })
                        });
                        let strtab_file_vaddr = strtab_dval
                            .zip(l_addr)
                            .map(|(value, base)| value.wrapping_sub(base));
                        eprintln!(
                            "TRACE reloc-callsite-deep map=0x{map:x} name={name_bytes:?} l_name_ptr={name_ptr:#x?} l_addr={l_addr:#x?} l_ld={l_ld:#x?} l_info_field={l_info:#x?} inline[7]={:?} inline[8]={:?} inline[23]={:?} rela_dval={dynamic_rela:#x?} rela_plus_bias={rela_plus_bias:#x?} rela_plus_bias_content={rela_plus_bias_content:02x?} strtab_dval={strtab_dval:#x?} strtab_file_vaddr={strtab_file_vaddr:#x?}",
                            inline_slot(7),
                            inline_slot(8),
                            inline_slot(23)
                        );
                        eprintln!(
                            "TRACE reloc-callsite-deep2 map=0x{map:x} slot_scan={slot_scan:?}"
                        );
                        eprintln!("TRACE reloc-callsite-deep3 map=0x{map:x} dyn_vals={dyn_vals:?}");
                        eprintln!(
                            "TRACE reloc-callsite-deep4 map=0x{map:x} info_resolved={info_resolved:?}"
                        );
                    }
                }
                // 顺带激活 DT_RELA 读取监视（仅诊断标记，不改变执行状态）
                if std::env::var_os("DAOTI_TRACE_RELA_READS").is_some() {
                    if let Some(address) = runtime_rela {
                        WATCH_RELA_ADDR.store(address, Ordering::Relaxed);
                    }
                    if let Some(size) = relasz_raw {
                        WATCH_RELA_SIZE.store(size, Ordering::Relaxed);
                    }
                }
                eprintln!(
                    "TRACE reloc-callsite rip=0x{rip:x} regs=[rax=0x{:x},rbx=0x{:x},rcx=0x{:x},rdx=0x{:x},rsi=0x{:x},rdi=0x{:x},rbp=0x{:x}] map=0x{map:x} l_addr={l_addr:#x?} l_ld={l_ld:#x?} l_info={l_info:#x?} rela_dyn_entry={rela_dyn_entry:#x?} rela_tag={rela_tag:#x?} rela_raw={rela_raw:#x?} runtime_rela={runtime_rela:#x?} relasz_dyn_entry={relasz_dyn_entry:#x?} relasz_tag={relasz_tag:#x?} relasz_raw={relasz_raw:#x?} first_entry={rela_first_entry:02x?} first_r_offset={first_r_offset:#x?} first_r_info={first_r_info:#x?} first_type_low32={first_type_low32:#x?} first_r_addend={first_r_addend:#x?} dynamic_rela={dynamic_rela:#x?} dyn_dump={dyn_dump:?} info_dump={info_dump:?} rela_content={rela_content:02x?}",
                    g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp
                );
            }
            // _dl_reloc_bad_type 入口（ld.so 文件偏移 0x10c90，guest base=0x2700000）。
            // 该函数打印 "unexpected reloc type 0x%x"（_dl_reloc_bad_type 内部不用 plt 参数
            // 区分消息，4 个调用点都打同一文本）。命中后 dump 参数与返回地址，即可
            // 区分调用点（0x2711ab8/0x2712518 是 rela switch default；0x27126ce/0x271c16f 是
            // 跳转表+mask 路径）并锁定 type=0x01 的寄存器来源。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2710c90 {
                let read_u64 = |address: u64| {
                    self.context
                        .memory
                        .read(address, 8)
                        .ok()
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                };
                let map = g.rdi;
                let r_type = (g.rsi & 0xffff_ffff) as u32;
                let name = read_u64(map.wrapping_add(0x08)).and_then(|ptr| {
                    if ptr == 0 {
                        None
                    } else {
                        self.context.memory.read(ptr, 32).ok().map(|b| {
                            b.iter()
                                .take_while(|byte| **byte != 0)
                                .map(|byte| *byte as char)
                                .collect::<String>()
                        })
                    }
                });
                let return_addr = self
                    .context
                    .memory
                    .read(g.rsp, 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                // rbx 在 libc rela 区间（DT_RELA=0x725270..+0x7860）内应指向当前 rela 条目。
                // dump 24 字节：r_offset(8)+r_info(8)+r_addend(8)，并解出 type/symndx。
                let rela_entry = self.context.memory.read(g.rbx, 24).ok().map(|b| b.to_vec());
                let (rela_r_offset, rela_r_info, rela_r_addend) = rela_entry
                    .as_ref()
                    .map(|b| {
                        (
                            u64::from_le_bytes(b[0..8].try_into().unwrap()),
                            u64::from_le_bytes(b[8..16].try_into().unwrap()),
                            u64::from_le_bytes(b[16..24].try_into().unwrap()),
                        )
                    })
                    .unwrap_or((0, 0, 0));
                let rela_type = (rela_r_info & 0xffff_ffff) as u32;
                let rela_symndx = rela_r_info >> 32;
                // [_dl_relocate_object 的 default 判定关键] 跳转表检查：
                // cmp edi, [r15+0x418]（or edi, r9d 后）。dump map+0x418 的 4 字节 mask。
                let mask_418 = read_u64(map.wrapping_add(0x418));
                eprintln!(
                    "TRACE reloc-bad-type rip=0x{rip:x} map=0x{map:x} name={name:?} r_type=0x{r_type:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} r14=0x{:x} r15=0x{:x} r12=0x{:x} rbx=0x{:x} rax=0x{:x} return_addr={return_addr:#x?} rela_entry={rela_entry:02x?} rela_r_offset={rela_r_offset:#x} rela_r_info={rela_r_info:#x} rela_type=0x{rela_type:x} rela_symndx={rela_symndx:#x} rela_r_addend={rela_r_addend:#x} map419={mask_418:#x?}",
                    g.rdi, g.rsi, g.rdx, g.r14, g.r15, g.r12, g.rbx, g.rax
                );
                // 关键验证：dump guest 内存中的 ld.so 跳转表（vaddr 0x2c120 → guest
                // 0x272c120，39 槽 x 4B disp32，0x11532 处 notrack jmp rax 的取表地址）。
                // 文件验证 slot=1(disp=-0x1abe3) → 0x1153d（R_X86_64_64 handler 正确）；
                // 若 guest 槽1 被改写成 -0x1a670（指向 0x11ab0 bad_type 前序），即证明
                // 跳转表在加载/运行期被错误写入破坏 —— 这正是 r12=0x1 却走到
                // return_addr=0x2711abd 的唯一可能（r12≤0x25 时 0x1151e/0x11aa5 均不跳转）。
                {
                    static DUMPED_JUMPTABLE: AtomicBool = AtomicBool::new(false);
                    if !DUMPED_JUMPTABLE.load(Ordering::Relaxed) {
                        DUMPED_JUMPTABLE.store(true, Ordering::Relaxed);
                        let jt_base = 0x272c120u64;
                        if let Ok(jb) = self.context.memory.read(jt_base, 39 * 4) {
                            let mut line =
                                format!("TRACE reloc-bad-type jumptable_guest base=0x{jt_base:x}:");
                            for (i, chunk) in jb.chunks_exact(4).enumerate() {
                                let disp = i32::from_le_bytes(chunk.try_into().unwrap());
                                let target = (jt_base as i64 + disp as i64) as u64;
                                line.push_str(&format!(
                                    " [{}]=0x{:x}->0x{:x}",
                                    i, disp as u32, target
                                ));
                            }
                            eprintln!("{line}");
                        }
                    }
                }
            }
            // 探针 1：0x271151a（cmp r12, 0x25 处）——打印实际用于判断的 r12。
            // 若此处 r12>0x25，说明 r12 在 0x113c7~0x1151a 之间被符号查找/IRELATIVE/
            // 版本处理路径修改；若 r12=0x1 则走跳转表（与 return_addr=0x2711abd 矛盾，
            // 需结合探针 2 判定）。限 libc rela 区间或 r12>0x25 时打印。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x271151a {
                let is_libc_rela = g.rbx >= 0x72c000 && g.rbx < 0x72cad0;
                if is_libc_rela || g.r12 > 0x25 {
                    eprintln!(
                        "TRACE cmp-r12 rip=0x{rip:x} r12=0x{:x} r14=0x{:x} rbx=0x{:x} rdx=0x{:x} r15=0x{:x}",
                        g.r12, g.r14, g.rbx, g.rdx, g.r15
                    );
                }
            }
            // 探针 2：0x2711532（notrack jmp rax 前）——打印 r12（表索引）、rax（跳转目标）、
            // 槽原始 disp。若 r12=1 且 rax=0x271153d → 跳转表正确，bad_type 来自其他路径；
            // 若 r12=1 且 rax=0x2711ab0 → 运行时槽1 内容异常；若从不触发 → 走了 ja 路径。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2711532 {
                let is_bad_target = (0x2711a80..0x2711ad0).contains(&g.rax);
                let is_libc_rela = g.rbx >= 0x72c000 && g.rbx < 0x72cad0;
                if is_bad_target || is_libc_rela {
                    // 顺带读当前槽原始 disp32（guest 0x272c120 + r12*4），r12 可能越界，
                    // read 失败返回 None。
                    let slot_addr = 0x272c120u64.wrapping_add(g.r12.wrapping_mul(4));
                    let slot_disp = self
                        .context
                        .memory
                        .read(slot_addr, 4)
                        .ok()
                        .map(|b| i32::from_le_bytes(b.try_into().unwrap()));
                    eprintln!(
                        "TRACE jmptable-dispatch rip=0x{rip:x} r12=0x{:x} rax=0x{:x} rbx=0x{:x} rdx=0x{:x} r15=0x{:x} slot_addr=0x{slot_addr:x} slot_disp={slot_disp:?}",
                        g.r12, g.rax, g.rbx, g.rdx, g.r15
                    );
                }
            }
            // 探针 2a：0x271152b（movsxd rax, [rdi + r12*4] 前）——锁定 rdi（表 base）与
            // r12（表索引）。dispatch 探针 rax=0x2711ab0 反推 base≠0x272c120，需确认
            // lea 结果 rdi 及指令编码是否被改写。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x271152b {
                let is_libc_rela = g.rbx >= 0x72c000 && g.rbx < 0x72cad0;
                if is_libc_rela {
                    // 抓 guest 0x2711524 处的 lea 指令字节（应为 48 8d 3d f5 ab 01 00，
                    // LEA rdi,[rip+0x1abf5]），排除 .text 被改写。
                    let lea_bytes = self
                        .context
                        .memory
                        .read(0x2711524, 7)
                        .ok()
                        .map(|b| b.to_vec());
                    // movsxd 指令字节 0x271152b..0x2711535（应为 48 63 04 a7 | 48 01 f8 | 3e ff e0）。
                    let dispatch_bytes = self
                        .context
                        .memory
                        .read(0x271152b, 11)
                        .ok()
                        .map(|b| b.to_vec());
                    eprintln!(
                        "TRACE movsxd-rdi rip=0x{rip:x} rdi=0x{:x} r12=0x{:x} r15=0x{:x} rbx=0x{:x} lea_bytes={lea_bytes:02x?} dispatch_bytes={dispatch_bytes:02x?}",
                        g.rdi, g.r12, g.r15, g.rbx
                    );
                }
            }
            // 探针 D：0x2710fc1（mov r12, [rsi] 前，rsi=[rbp-0xc8] 指向的结构）——
            // `_dl_relocate_object` 处理 rela 的入口，打印结构 4 字段：
            //   f0=rela 起点（应 = bias+0x2cxxx，若 ≈0x2d 则 DT_RELA d_ptr 未绝对化/缺失）
            //   f1=rela 终点增量（rcx 会 +r12）、f2=?, f3=flags(esi)
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2710fc1 {
                // 探针 D（增强）：结构数组起点 [rbp-0x70]，每组 0x20，end=[rbp-0xe8]。
                // 打印当前结构指针 sp=[[rbp-0xc8]]、三个结构槽的 f0/f1、当前结构 4 字段，
                // 以及关键寄存器。注意：r14 在 0x11086（IRELATIVE 特判循环）会被改写为
                // rela 条目的 r_offset（垃圾），重入路径时不是 map；真 map 在 r11。
                let rd = |a: u64, n: usize| {
                    self.context
                        .memory
                        .read(a, n as u64)
                        .ok()
                        .map(|b| b.to_vec())
                };
                let u64_at = |a: u64| -> u64 {
                    rd(a, 8)
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        .unwrap_or(0)
                };
                let u32_at = |a: u64| -> u32 {
                    rd(a, 4)
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                        .unwrap_or(0)
                };
                let end = u64_at(g.rbp.wrapping_sub(0xe8));
                let sp = u64_at(g.rbp.wrapping_sub(0xc8));
                // 三个结构槽（在栈上时）的 f0/f1
                let s0 = u64_at(g.rbp.wrapping_sub(0x70));
                let s1 = u64_at(g.rbp.wrapping_sub(0x68));
                let s2 = u64_at(g.rbp.wrapping_sub(0x50));
                let s3 = u64_at(g.rbp.wrapping_sub(0x48));
                let s4 = u64_at(g.rbp.wrapping_sub(0x30));
                let s5 = u64_at(g.rbp.wrapping_sub(0x28));
                eprintln!(
                    "TRACE rela-entry rip=0x{rip:x} sp=0x{sp:x} end=0x{end:x} slot0x70=0x{s0:x}/0x{s1:x} slot0x50=0x{s2:x}/0x{s3:x} slot0x30=0x{s4:x}/0x{s5:x} cur_f0=0x{:x} cur_f1=0x{:x} cur_f2=0x{:x} cur_f3=0x{:x} r11=0x{:x} r14=0x{:x} r10=0x{:x} rbx=0x{:x} rbp=0x{:x}",
                    u64_at(sp),
                    u64_at(sp + 8),
                    u64_at(sp + 0x10),
                    u32_at(sp + 0x18),
                    g.r11,
                    g.r14,
                    g.r10,
                    g.rbx,
                    g.rbp
                );
            }
            // 探针 E：0x2711036（mov rsi, [r12+8] 前）——崩溃现场：r12 为 rela 游标
            // （+0x18 步长），若 r12/r10 都是 ~0x2d 级别 → rela 段地址几乎为 0，
            // 证实 DT_RELA d_ptr 错误；r15=link_map 可判断是哪个对象。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2711036 {
                eprintln!(
                    "TRACE rela-loop rip=0x{rip:x} r12=0x{:x} r10=0x{:x} r15=0x{:x} r14=0x{:x} r13=0x{:x} r11=0x{:x} rbx=0x{:x} rsi=0x{:x} rbp=0x{:x}",
                    g.r12, g.r10, g.r15, g.r14, g.r13, g.r11, g.rbx, g.rsi, g.rbp
                );
            }
            // 探针 F：0x2710fa2（mov [rbp-0xc8], rax 前）——结构数组重建点：
            // rax=lea[rbp-0x70]（新起点），每次到这里都会重置 [rbp-0xc8]。
            // 标记第几次重建、此时 r14/r11 的值。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2710fa2 {
                let old = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xc8), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE rela-rebuild rip=0x{rip:x} new_sp(rax)=0x{:x} old_sp=0x{old:x?} r11=0x{:x} r14=0x{:x} r10=0x{:x} r15=0x{:x} r13=0x{:x} rbx=0x{:x}",
                    g.rax, g.r11, g.r14, g.r10, g.r15, g.r13, g.rbx
                );
            }
            // 探针 G：0x27110a5（add [rbp-0xc8], 0x20 前）——内层数组迭代步进点：
            // 打印 [rbp-0xc8] 旧值、r14/r11，确认每次步进后结构指针变化。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x27110a5 {
                let cur = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xc8), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                let end = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xe8), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE rela-step rip=0x{rip:x} sp_before=0x{cur:x?} end=0x{end:x?} r11=0x{:x} r14=0x{:x} r10=0x{:x} r15=0x{:x} rbx=0x{:x} r12=0x{:x}",
                    g.r11, g.r14, g.r10, g.r15, g.rbx, g.r12
                );
            }
            // 探针 H：0x27110bb（jne 0x11c00 前）——数组边界判定。
            // rax=[rbp-0xc8]（步进后新游标）、[rbp-0xe8]=终点（=rbp-0x30）。
            // taken=true→数组还有槽，跳 0x11c00 重入下一槽；false→本帧 rela 阶段收尾。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x27110bb {
                let end = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xe8), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                let next = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xc8), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                let taken = next != end;
                eprintln!(
                    "TRACE rela-bnd rip=0x{rip:x} rbp=0x{:x} next_sp=0x{next:x?} end=0x{end:x?} taken={taken} r11=0x{:x} r14=0x{:x} r10=0x{:x} r15=0x{:x}",
                    g.rbp, g.r11, g.r14, g.r10, g.r15
                );
            }
            // 探针 J：0x27110c1（数组完毕后的恢复点）——标记该帧 rela 阶段结束，
            // 打印 [rbp-0xd0]（flags 恢复值）与 [rbp-0xf0]（下一处理段指针）。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x27110c1 {
                let d0 = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xd0), 4)
                    .ok()
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                let f0 = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xf0), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE rela-done rip=0x{rip:x} rbp=0x{:x} [rbp-0xd0]=0x{d0:x?} [rbp-0xf0]=0x{f0:x?} r11=0x{:x} r14=0x{:x} r15=0x{:x} rbx=0x{:x}",
                    g.rbp, g.r11, g.r14, g.r15, g.rbx
                );
            }
            // 探针 P：0x27110f5（mov rax,[r14+0x478] 前）——rela-tail 判定：
            // 0x478 非 0 → 走 0x11db0 TEXTREL/间隙路径；0 → 直接 epilogue ret。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x27110f5 {
                let v = self
                    .context
                    .memory
                    .read(g.r14.wrapping_add(0x478), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE rela-tail rip=0x{rip:x} rbp=0x{:x} [r14+0x478]=0x{v:x?} r14=0x{:x} r11=0x{:x} r15=0x{:x} rbx=0x{:x}",
                    g.rbp, g.r14, g.r11, g.r15, g.rbx
                );
            }
            // 探针 K：0x27111113（ret）——打印被弹回的返回地址（读 [rsp]）与该帧 map。
            // 返回地址可精确指认函数调用者；配合 rbp 可识别新的嵌套帧。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2711113 {
                let ret_addr = self
                    .context
                    .memory
                    .read(g.rsp, 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE rela-ret rip=0x{rip:x} rbp=0x{:x} rsp=0x{:x} ret_addr=0x{ret_addr:x?} r14=0x{:x} r11=0x{:x} r15=0x{:x} rbx=0x{:x}",
                    g.rbp, g.rsp, g.r14, g.r11, g.r15, g.rbx
                );
            }
            // 探针 L：0x2711091（IRELATIVE 解析器 call rax 前）——打印 call 目标与 rela 条目
            // 位置（rbx）。若解析器本身是 guest 代码，其执行会改变 rbp → 是第三次进入的源头候选。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2711091 {
                eprintln!(
                    "TRACE irel-call rip=0x{rip:x} rbp=0x{:x} rax=0x{:x}(callee) rbx=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x}",
                    g.rbp, g.rax, g.rbx, g.r12, g.r13, g.r14, g.r15
                );
            }
            // 探针 M：0x2710f92（lea rax,[rbp-0x70] 前）与 0x2710fba（mov rsi,[rbp-0xc8] 后）——
            // 验证解释器对「lea + disp8(0x90=-112)」与「mov [rbp-0xc8]」的地址计算是否一致：
            // rsi 应 = rbp-0x70 = rbp-112；若 rsi≠rbp-112 → 解释器 SIB/disp bug 把
            // [rbp-0xc8] 解析到 0x72cac0（libc rela 区内）→ f0=0x25 垃圾 → 崩溃 0x2d。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2710fba {
                let expect = g.rbp.wrapping_sub(0x70);
                let stack_val = self
                    .context
                    .memory
                    .read(g.rbp.wrapping_sub(0xc8_u64), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                if g.rsi != expect || stack_val != Some(expect) {
                    eprintln!(
                        "TRACE probe-m rip=0x{rip:x} rbp=0x{:x} rsi=0x{:x} expect(rbp-0x70)=0x{expect:x} [rbp-0xc8]=0x{stack_val:x?} r14=0x{:x} r11=0x{:x}",
                        g.rbp, g.rsi, g.r14, g.r11
                    );
                }
            }
            // 探针 I：0x2711c00（mov r10,[r11]; jmp 0x10fba）——数组重入点。
            // 0x110bb jne 命中这里时取 [r11] 到 r10，再跳回 0x10fba 重入下一槽。
            // 第三次 rela-entry 的 rbp 已从 0x2759b80 变 0x2759b00，记录每次重入时
            // r11/r10/[r11]/rbp/游标，定位「重入时结构指针被污染」的精确转换点。
            if std::env::var_os("DAOTI_TRACE_RELOC_BAD_TYPE").is_some() && rip == 0x2711c00 {
                let ind = self
                    .context
                    .memory
                    .read(g.r11, 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                eprintln!(
                    "TRACE rela-reenter rip=0x{rip:x} rbp=0x{:x} r11=0x{:x} [r11]=0x{ind:x?} r10=0x{:x} r15=0x{:x} rbx=0x{:x} r12=0x{:x} r14=0x{:x}",
                    g.rbp, g.r11, g.r10, g.r15, g.rbx, g.r12, g.r14
                );
            }
            LAST_INTERPRETER_RIP.store(rip, Ordering::Relaxed);
            LAST_INTERPRETER_RAX.store(g.rax, Ordering::Relaxed);
            LAST_INTERPRETER_RBX.store(g.rbx, Ordering::Relaxed);
            LAST_INTERPRETER_RCX.store(g.rcx, Ordering::Relaxed);
            LAST_INTERPRETER_RDX.store(g.rdx, Ordering::Relaxed);
            LAST_INTERPRETER_RSI.store(g.rsi, Ordering::Relaxed);
            LAST_INTERPRETER_RDI.store(g.rdi, Ordering::Relaxed);
            LAST_INTERPRETER_RBP.store(g.rbp, Ordering::Relaxed);
            LAST_INTERPRETER_RSP.store(g.rsp, Ordering::Relaxed);
            LAST_INTERPRETER_R12.store(g.r12, Ordering::Relaxed);
            LAST_INTERPRETER_R13.store(g.r13, Ordering::Relaxed);
            LAST_INTERPRETER_R14.store(g.r14, Ordering::Relaxed);
            LAST_INTERPRETER_R15.store(g.r15, Ordering::Relaxed);
            if std::env::var_os("DAOTI_FIX_NAMESPACE_ROOT").is_some()
                && rip == self.monitor_addr(0x22243).unwrap_or(0)
            {
                if let Some(ns_loaded_addr) = self.context.memory.namespace_root_addr {
                    let root = self.context.registers.general.rax;
                    self.context
                        .memory
                        .write(ns_loaded_addr, &root.to_le_bytes())?;
                    eprintln!(
                        "TRACE namespace-root-fix rip=0x{rip:x} addr=0x{ns_loaded_addr:x} root=0x{root:x}"
                    );
                    self.context.memory.namespace_root_addr = None;
                }
            }
            if let Some((ns_loaded_addr, libc_map_addr, patch_rip)) = self.libc_link_map_patch {
                if rip == patch_rip {
                    let main_map_addr = u64::from_le_bytes(
                        self.context
                            .memory
                            .read(ns_loaded_addr, 8)?
                            .try_into()
                            .unwrap(),
                    );
                    self.context
                        .memory
                        .write(main_map_addr + 0x18, &libc_map_addr.to_le_bytes())?;
                    self.context
                        .memory
                        .write(libc_map_addr + 0x18, &0u64.to_le_bytes())?;
                    self.context
                        .memory
                        .write(libc_map_addr + 0x20, &main_map_addr.to_le_bytes())?;
                    self.libc_link_map_patch = None;
                }
            }
            if std::env::var_os("DAOTI_TRACE_NEW_OBJECT_RETURN").is_some()
                && self.monitor_addr(0x15f30) == Some(rip)
            {
                let map_addr = self.context.registers.general.rax;
                let l_real = self
                    .context
                    .memory
                    .read(map_addr.wrapping_add(0x28), 8)
                    .ok()
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                eprintln!(
                    "TRACE new-object-return-probe rip=0x{rip:x} map=0x{map_addr:x} l_real={l_real:#x?}"
                );
            }
            if std::env::var_os("DAOTI_TRACE_VERSION_MAP").is_some()
                && self.monitor_addr(0x15f30) == Some(rip)
            {
                let rax = self.context.registers.general.rax;
                let l_real = self
                    .context
                    .memory
                    .read(rax.wrapping_add(0x28), 8)
                    .ok()
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                eprintln!(
                    "TRACE version-map-probe rip=0x{rip:x} rax=0x{rax:x} l_real={l_real:#x?}"
                );
            }
            if let Some(bp) = self.breakpoints.iter().find(|bp| bp.addr == rip) {
                if bp.name == "__tls_get_addr" {
                    // 功能型断点：模拟 glibc `__tls_get_addr`（System V AMD64 TLS ABI）。
                    // ABI：rdi = tls_index*（GOT 中的槽对：[rdi]=u32 ti_module_id、
                    // [rdi+8]=u64 ti_offset）；返回值 rax = 该 TLS 变量的运行时地址。
                    // 找不到模块时返回 0（可诊断，不 panic）。
                    let ti = self.context.registers.general.rdi;
                    let module_id = self
                        .context
                        .memory
                        .read(ti, 4)
                        .ok()
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
                        .unwrap_or(0);
                    let offset = self
                        .context
                        .memory
                        .read(ti + 8, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        .unwrap_or(0);
                    let addr = self
                        .tls_context
                        .as_ref()
                        .and_then(|ctx| ctx.get_addr(module_id, offset as i64))
                        .unwrap_or(0);
                    self.context.registers.general.rax = addr;
                    if std::env::var_os("DAOTI_TRACE_TLS").is_some() {
                        eprintln!(
                            "TRACE tls-get_addr hit rip=0x{rip:x} tls_index=0x{ti:x} module_id={module_id} offset=0x{offset:x} rax=0x{addr:x}"
                        );
                    }
                    // 模拟 ret：弹出调用方压入的返回地址。
                    let rsp = self.context.registers.general.rsp;
                    let return_rip =
                        u64::from_le_bytes(self.context.memory.read(rsp, 8)?.try_into().unwrap());
                    self.context.registers.general.rsp = rsp
                        .checked_add(8)
                        .ok_or_else(|| DaotiError::Other("__tls_get_addr 返回时栈溢出".into()))?;
                    self.context.registers.general.rip = return_rip;
                    continue;
                }
                let g = &self.context.registers.general;
                if let Some(name) = bp.name.strip_prefix("gen:") {
                    // 通用验证探针：命中打印 System V ABI 参数、[rsp] 返回地址现场；
                    // 名字带 " watch=0x<addr>" 时额外读取该地址 8 字节
                    let watch_addr = name
                        .find(" watch=0x")
                        .and_then(|pos| u64::from_str_radix(name[pos + 9..].trim(), 16).ok());
                    let watch_val = watch_addr.and_then(|w| {
                        self.context
                            .memory
                            .read(w, 8)
                            .ok()
                            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    });
                    let ret_addr = self
                        .context
                        .memory
                        .read(g.rsp, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                    let deref_rax = self
                        .context
                        .memory
                        .read(g.rax, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                    let deref_rdi = self
                        .context
                        .memory
                        .read(g.rdi, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                    // early_init_w：rax = &__libc_single_threaded（libc+0x2224B8），
                    // brk 标志 = libc+0x228E4E，相对偏移 +0x6996
                    let early_flag = if name == "early_init_w" {
                        self.context
                            .memory
                            .read(g.rax.wrapping_add(0x6996), 1)
                            .ok()
                            .map(|b| b[0])
                    } else {
                        None
                    };
                    if name == "int_malloc_corrupted" {
                        let read_u64 = |addr: u64| {
                            self.context
                                .memory
                                .read(addr, 8)
                                .ok()
                                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        };
                        eprintln!(
                            "TRACE int-malloc-corrupted rbx=0x{:x} r11=0x{:x} rax=0x{:x} rdx=0x{:x} rbx_top={:?} rbx_top_size={:?} rbx_system_mem={:?} r11_top={:?} r11_top_size={:?} r11_system_mem={:?}",
                            g.rbx,
                            g.r11,
                            g.rax,
                            g.rdx,
                            read_u64(g.rbx + 0x60),
                            read_u64(read_u64(g.rbx + 0x60).unwrap_or(0) + 8),
                            read_u64(g.rbx + 0x888),
                            read_u64(g.r11 + 0x60),
                            read_u64(read_u64(g.r11 + 0x60).unwrap_or(0) + 8),
                            read_u64(g.r11 + 0x888),
                        );
                    }
                    if name == "malloc_arena" {
                        let arena = g.r12;
                        let read_u64 = |addr: u64| {
                            self.context
                                .memory
                                .read(addr, 8)
                                .ok()
                                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        };
                        eprintln!(
                            "TRACE malloc-arena r12=0x{arena:x} top={:?} top_size={:?} system_mem={:?} next={:?} curbrk={:?}",
                            read_u64(arena + 0x60),
                            read_u64(read_u64(arena + 0x60).unwrap_or(0).wrapping_add(8)),
                            read_u64(arena + 0x888),
                            read_u64(arena + 0x870),
                            read_u64(g.rip.wrapping_add(0x11a869)),
                        );
                    }
                    // 下一刀（2026-08-31）：读取 rbx/r12/rflags，验证 __sbrk 的
                    // add rbx,r12(0x11a8fb) 后 jae(0x11a901) 是否因 CF 误置位而跳过
                    // brk 扩展。rflags 分解 CF=bit0/PF=bit2/ZF=bit6/SF=bit7/OF=bit11。
                    let rflags = g.rflags;
                    let (cf, zf, sf, of) = (
                        rflags & 0x1 != 0,
                        rflags & 0x40 != 0,
                        rflags & 0x80 != 0,
                        rflags & 0x800 != 0,
                    );
                    match watch_val {
                        Some(wv) => eprintln!(
                            "TRACE bp-hit {name} rip=0x{rip:x} rdi=0x{:x} rbx=0x{:x} r12=0x{:x} rflags=0x{:x} CF={cf} ZF={zf} SF={sf} OF={of} rsi=0x{:x} rax=0x{:x} r11=0x{:x} ret=0x{:x} watch={wv:#x}",
                            g.rdi,
                            g.rbx,
                            g.r12,
                            rflags,
                            g.rsi,
                            g.rax,
                            g.r11,
                            ret_addr.unwrap_or(0)
                        ),
                        None => eprintln!(
                            "TRACE bp-hit {name} rip=0x{rip:x} rdi={:#x} [rdi]={deref_rdi:?} rbx={:#x} r12={:#x} rflags=0x{:x} CF={cf} ZF={zf} SF={sf} OF={of} rsi={:#x} rdx={:#x} rax={:#x} [rax]={deref_rax:?} r11={:#x} ret={:#x} early_flag={early_flag:?}",
                            g.rdi,
                            g.rbx,
                            g.r12,
                            rflags,
                            g.rsi,
                            g.rdx,
                            g.rax,
                            g.r11,
                            ret_addr.unwrap_or(0)
                        ),
                    }
                }
                if bp.name == "__libc_early_init" {
                    // 通用验证探针：命中即证明 ld 调用了 libc 早期初始化；
                    // System V ABI：rdi=main_map, rsi=argc, rdx=argv
                    eprintln!(
                        "TRACE early-init HIT rip=0x{rip:x} main_map=0x{:x} argc={} argv=0x{:x}",
                        g.rdi, g.rsi, g.rdx
                    );
                }
                if bp.name == "_dl_start" {
                    if let Ok(bytes) = self.context.memory.read(g.rsp, 8) {
                        let return_rip = u64::from_le_bytes(bytes.try_into().unwrap());
                        dl_start_calls.push((rip, return_rip, rip));
                    }
                }
                if bp.name == "call_chain_start" {
                    call_chain_active = true;
                }
                if bp.name == "_dl_relocate_object"
                    && std::env::var_os("DAOTI_TRACE_RELA_READS").is_some()
                {
                    let read_u64 = |address: u64| {
                        self.context
                            .memory
                            .read(address, 8)
                            .ok()
                            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    };
                    let map = g.rdi;
                    let l_addr = read_u64(map);
                    let l_ld = read_u64(map.wrapping_add(0x10));
                    let mut rela = None;
                    let mut relasz = None;
                    if let Some(dynamic) = l_ld {
                        for index in 0..256u64 {
                            let entry = dynamic.wrapping_add(index * 16);
                            let tag = read_u64(entry);
                            let value = read_u64(entry.wrapping_add(8));
                            match tag {
                                Some(0) => break,
                                Some(7) => rela = value,
                                Some(8) => relasz = value,
                                _ => {}
                            }
                        }
                    }
                    let runtime_rela = rela
                        .zip(l_addr)
                        .map(|(address, base)| address.wrapping_add(base));
                    if let (Some(address), Some(size)) = (runtime_rela, relasz) {
                        WATCH_RELA_ADDR.store(address, Ordering::Relaxed);
                        WATCH_RELA_SIZE.store(size, Ordering::Relaxed);
                    }
                    eprintln!(
                        "TRACE dl-relocate-object map=0x{map:x} l_addr={l_addr:#x?} l_ld={l_ld:#x?} dt_rela={rela:#x?} dt_relasz={relasz:#x?} runtime_rela={runtime_rela:#x?}"
                    );
                }
                if bp.name == "_dl_exception_create_format" {
                    let readable =
                        |addr: u64, len: u64| self.context.memory.read(addr, len).is_ok();
                    let read_bytes = |addr: u64, len: u64| {
                        self.context
                            .memory
                            .read(addr, len)
                            .ok()
                            .map(|bytes| bytes.to_vec())
                    };
                    let read_string = |addr: u64| {
                        read_bytes(addr, 256).map(|bytes| {
                            bytes
                                .into_iter()
                                .take_while(|byte| *byte != 0)
                                .map(|byte| {
                                    if byte.is_ascii_graphic() || byte == b' ' {
                                        byte as char
                                    } else {
                                        '.'
                                    }
                                })
                                .collect::<String>()
                        })
                    };
                    eprintln!(
                        "TRACE exception-create-format-entry rip=0x{rip:x} args=[rdi=0x{:x},rsi=0x{:x},rdx=0x{:x},rcx=0x{:x},r8=0x{:x},r9=0x{:x}] readable=[rdi={},rsi={},rdx={},rcx={},r8={},r9={}] arg_bytes=[rdi={:?},rsi={:?},rdx={:?},rcx={:?},r8={:?}] fs=0x{:x} rsp=0x{:x} tsd_fs0={:?} tsd_fs8={:?} tsd_fs28={:?}",
                        g.rdi, g.rsi, g.rdx, g.rcx, g.r8, g.r9,
                        readable(g.rdi, 8), readable(g.rsi, 8), readable(g.rdx, 8),
                        readable(g.rcx, 8), readable(g.r8, 8), readable(g.r9, 8),
                        read_bytes(g.rdi, 32), read_bytes(g.rsi, 32), read_bytes(g.rdx, 32),
                        read_bytes(g.rcx, 32), read_bytes(g.r8, 32), self.fs_base, g.rsp,
                        read_bytes(self.fs_base, 8), read_bytes(self.fs_base + 8, 8),
                        read_bytes(self.fs_base + 0x28, 8)
                    );
                    eprintln!(
                        "TRACE exception-create-format-strings rdi={:?} rsi={:?} rdx={:?}",
                        read_string(g.rdi),
                        read_string(g.rsi),
                        read_string(g.rdx)
                    );
                }
                if bp.name == "dl_main"
                    || bp.name == "candidate_0x2423aa0"
                    || bp.name == "call_chain_candidate"
                {
                    let prologue = self.context.memory.read(rip, 16).ok();
                    let readable =
                        |addr: u64, len: u64| self.context.memory.read(addr, len).is_ok();
                    eprintln!(
                        "TRACE entry-observe name={} rip=0x{:x} prologue={:02x?} regs=[rdi=0x{:x},rsi=0x{:x},rdx=0x{:x},rcx=0x{:x}] readable=[rdi={},rsi={},rdx={},rcx={}]",
                        bp.name, rip, prologue, g.rdi, g.rsi, g.rdx, g.rcx,
                        readable(g.rdi, 8), readable(g.rsi, 8), readable(g.rdx, 8), readable(g.rcx, 8)
                    );
                    let args = self.context.memory.read(g.rdi, 64).ok();
                    if let Some(data) = args {
                        let read_u64 = |offset: usize| {
                            u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
                        };
                        let phdr_ptr = read_u64(0);
                        let phnum = u32::from_le_bytes(data[8..12].try_into().unwrap());
                        let user_entry = read_u64(16);
                        let auxv_ptr = read_u64(24);
                        eprintln!(
                            "TRACE dl_main-args base=0x{:x} phdr=0x{:x} phnum={} user_entry=0x{:x} auxv=0x{:x} raw={:02x?}",
                            g.rdi, phdr_ptr, phnum, user_entry, auxv_ptr, data
                        );
                        let phdr = self.context.memory.read(phdr_ptr, 56).ok();
                        let auxv = self.context.memory.read(auxv_ptr, 16 * 16).ok();
                        eprintln!("TRACE dl_main-memory phdr={phdr:02x?} auxv={auxv:02x?}");
                    } else {
                        eprintln!("TRACE dl_main-args unreadable base=0x{:x}", g.rdi);
                    }
                }
                if bp.name == "calloc_entry" {
                    let got_val = self
                        .context
                        .memory
                        .read(0x2432a28u64, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                    eprintln!(
                        "TRACE calloc_entry nmemb=0x{:x} size=0x{:x} GOT[0x2432a28]={:02x?}",
                        g.rdi, g.rsi, got_val
                    );
                }
                if bp.name == "allocator_call" {
                    let got_val = self
                        .context
                        .memory
                        .read(0x2432a28u64, 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                    eprintln!("TRACE allocator_call GOT[0x2432a28]={:02x?}", got_val);
                }
            }
            if std::env::var_os("DAOTI_TRACE_ASSERT_STATE").is_some()
                && self.monitor_hit(rip, ASSERTION_OFFSET)
            {
                if let Some(base) = rtld_global_addr {
                    for address in (base..=base.saturating_add(0x80)).step_by(8) {
                        let value = self
                            .context
                            .memory
                            .read(address, 8)
                            .ok()
                            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                        eprintln!("TRACE namespace-state addr=0x{address:x} value={value:?}");
                    }
                }
            }
            if std::env::var_os("DAOTI_TRACE_ASSERT_STATE").is_some()
                && (rip == 0x2420e30 || rip == 0x2420e4f)
            {
                let rsp = self.context.registers.general.rsp;
                let stack = self.context.memory.read(rsp, 64).ok();
                if std::env::var_os("DAOTI_TRACE_WRITABLE_PT_LOAD").is_some() {
                    let candidates =
                        self.context
                            .memory
                            .trace_writable_pt_load
                            .iter()
                            .flat_map(|(start, end)| (*start..*end).step_by(8))
                            .filter_map(|addr| {
                                let value =
                                    self.context.memory.read(addr, 8).ok().map(|bytes| {
                                        u64::from_le_bytes(bytes.try_into().unwrap())
                                    })?;
                                (value != 0).then_some((addr, value))
                            })
                            .take(16)
                            .collect::<Vec<_>>();
                    eprintln!("TRACE assertion-writable-candidates rip=0x{rip:x} candidates={candidates:?}");
                }
                eprintln!(
                    "TRACE assertion-state rip=0x{rip:x} rsp=0x{rsp:x} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} fs=0x{:x} stack={stack:02x?}",
                    self.context.registers.general.rax,
                    self.context.registers.general.rbx,
                    self.context.registers.general.rcx,
                    self.context.registers.general.rdx,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rdi,
                    self.fs_base,
                );
            }
            if !self.stdout_captured && self.stdout_cleanup_addr == Some(rip) {
                if let Some(stdout) = self.stdout_addr {
                    if let Some(handler) = self.syscall_handler.as_mut() {
                        handler.capture_stdout(&mut self.context.memory, stdout)?;
                    }
                }
                self.stdout_captured = true;
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some()
                && ((0x2715f02..0x2715f42).contains(&rip)
                    || (0x2715ee0..0x2715f50).contains(&rip)
                    || (0x2708e80..0x2708ed0).contains(&rip)
                    || (0x2420d80..0x2420f20).contains(&rip)
                    || (0x240c6d0..0x240c710).contains(&rip)
                    || (0x241bf00..0x241c100).contains(&rip)
                    || (0x42a140..0x42a1c0).contains(&rip)
                    || (0x401530..0x401554).contains(&rip)
                    || (0x4087b0..0x408a35).contains(&rip)
                    || (0x433700..0x433c00).contains(&rip)
                    || (0x401650..0x401690).contains(&rip)
                    || (0x410820..0x410a20).contains(&rip)
                    || (0x40ccf0..0x40ce00).contains(&rip)
                    || (0x40ff80..0x410020).contains(&rip)
                    || (0x40ef30..0x40f100).contains(&rip)
                    || (0x40f020..0x40f0a0).contains(&rip)
                    || (0x411b30..0x411d20).contains(&rip)
                    || (0x4105a0..0x410820).contains(&rip)
                    || (0x40ed20..0x40edf0).contains(&rip)
                    || (0x40e660..0x40e6a0).contains(&rip)
                    || (0x40ca80..0x40cac0).contains(&rip)
                    || (0x40dc80..0x40dd20).contains(&rip)
                    || (0x4308a0..0x430940).contains(&rip)
                    || (0x40ed20..0x40eff0).contains(&rip)
                    || (0x4422b0..0x442320).contains(&rip))
            {
                let trace_bytes = self.context.memory.read(rip, 15).ok();
                eprintln!(
                    "TRACE rip=0x{rip:x} bytes={trace_bytes:02x?} p? rbp=0x{:x} rsp=0x{:x} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rdi=0x{:x} rsi=0x{:x}",
                    self.context.registers.general.rbp,
                    self.context.registers.general.rsp,
                    self.context.registers.general.rax,
                    self.context.registers.general.rbx,
                    self.context.registers.general.rcx,
                    self.context.registers.general.rdx,
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some()
                && matches!(rip, 0x40ff90 | 0x40ffca | 0x40ffd1 | 0x40ffe0 | 0x41001e)
            {
                let file = self.context.registers.general.rdi;
                let vtable = self
                    .context
                    .memory
                    .read(file.wrapping_add(0xd8), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                let slot = vtable.and_then(|table| {
                    self.context
                        .memory
                        .read(table.wrapping_add(0x60), 8)
                        .ok()
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                });
                eprintln!(
                    "TRACE file-write-path rip=0x{rip:x} file=0x{file:x} flags={:?} write_base={:?} write_ptr={:?} write_end={:?} lock={:?} mode={:?} vtable={vtable:?} slot60={slot:?} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rsp=0x{:x}",
                    self.context.memory.read(file, 4).ok(),
                    self.context.memory.read(file + 0x20, 8).ok(),
                    self.context.memory.read(file + 0x28, 8).ok(),
                    self.context.memory.read(file + 0x30, 8).ok(),
                    self.context.memory.read(file + 0x88, 8).ok(),
                    self.context.memory.read(file + 0xc0, 4).ok(),
                    self.context.registers.general.rax,
                    self.context.registers.general.rbx,
                    self.context.registers.general.rcx,
                    self.context.registers.general.rdx,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rsp
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && matches!(rip, 0x410820 | 0x4109d9) {
                let rbx = self.context.registers.general.rbx;
                let field = self
                    .context
                    .memory
                    .read(rbx.wrapping_add(0xc0), 4)
                    .ok()
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                let snapshot = self.context.memory.read(rbx, 0x100).ok();
                eprintln!(
                    "TRACE cleanup-state rip=0x{rip:x} rbx=0x{rbx:x} field_c0={field:?} snapshot={snapshot:02x?}"
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some()
                && matches!(
                    rip,
                    0x402f60
                        | 0x402f6a
                        | 0x402f70
                        | 0x402f74
                        | 0x402f90
                        | 0x402f9c
                        | 0x402fa7
                        | 0x402fb7
                        | 0x4088a0
                )
            {
                let rsp = self.context.registers.general.rsp;
                let stack50 = self
                    .context
                    .memory
                    .read(rsp.wrapping_add(0x50), 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!(
                    "TRACE fini-register rip=0x{rip:x} rsp=0x{rsp:x} rax=0x{:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} stack+50=0x{stack50:x}",
                    self.context.registers.general.rax,
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rdx
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && rip == 0x4089f8 {
                let entry = self.context.registers.general.rax;
                let raw = self.context.memory.read(entry, 0x100)?;
                eprintln!("TRACE node entry=0x{entry:x} raw={:02x?}", raw);
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some()
                && matches!(
                    rip,
                    0x408a08 | 0x408a0b | 0x408a0d | 0x408a11 | 0x408a1b | 0x408a28
                )
            {
                eprintln!(
                    "TRACE exit rip=0x{rip:x} rax=0x{:x} rdx=0x{:x} r8=0x{:x} rdi=0x{:x} rsi=0x{:x}",
                    self.context.registers.general.rax,
                    self.context.registers.general.rdx,
                    self.context.registers.general.r8,
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && rip == 0x408a11 {
                let guard_addr = self.fs_base.wrapping_add(0x30);
                let guard = self.context.memory.read(guard_addr, 8)?;
                eprintln!(
                    "TRACE decode rip=0x{rip:x} fs=0x{:x} guard=0x{:x} rax=0x{:x} rdi=0x{:x} rsi=0x{:x}",
                    self.fs_base,
                    u64::from_le_bytes(guard.try_into().unwrap()),
                    self.context.registers.general.rax,
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && rip == 0x442317 {
                let entry = self.context.registers.general.rdi;
                let raw = self.context.memory.read(entry, 0x20)?;
                eprintln!(
                    "TRACE encode entry=0x{entry:x} rbp=0x{:x} raw={:02x?}",
                    self.context.registers.general.rbp, raw
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && rip == 0x42a160 {
                let rsp = self.context.registers.general.rsp;
                let ret = self
                    .context
                    .memory
                    .read(rsp, 8)
                    .ok()
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!(
                    "TRACE strcpy-entry ret=0x{ret:x} rsp=0x{rsp:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x}",
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rdx
                );
            }
            if std::env::var_os("DAOTI_TRACE_ABORT").is_some() && rip == 0x401119 {
                let rsp = self.context.registers.general.rsp;
                let mut chain = Vec::new();
                for off in 0..12u64 {
                    if let Ok(b) = self.context.memory.read(rsp + off * 8, 8) {
                        chain.push(u64::from_le_bytes(b.try_into().unwrap()));
                    }
                }
                eprintln!("TRACE abort-entry rsp=0x{rsp:x} stack={chain:x?}");
            }
            if std::env::var_os("DAOTI_TRACE_ABORT").is_some()
                && (0x403e00..0x403e40).contains(&rip)
            {
                let rdi = self.context.registers.general.rdi;
                let rsi = self.context.registers.general.rsi;
                let rdx = self.context.registers.general.rdx;
                let rcx = self.context.registers.general.rcx;
                let ehdr_phentsize = self
                    .context
                    .memory
                    .read(0x400036, 2)
                    .ok()
                    .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                let ehdr_type = self
                    .context
                    .memory
                    .read(0x400000, 2)
                    .ok()
                    .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!("TRACE __assert_fail rip=0x{rip:x} rdi=0x{rdi:x} rsi=0x{rsi:x} rdx=0x{rdx:x} rcx=0x{rcx:x} ehdr_type=0x{ehdr_type:04x} e_phentsize=0x{ehdr_phentsize:04x}");
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && rip == 0x401530 {
                eprintln!(
                    "TRACE start rdx=0x{:x} r8=0x{:x} r9=0x{:x} rsp=0x{:x}",
                    self.context.registers.general.rdx,
                    self.context.registers.general.r8,
                    self.context.registers.general.r9,
                    self.context.registers.general.rsp
                );
            }
            if std::env::var_os("DAOTI_TRACE_RIP").is_some() && rip == 0x4027f0 {
                eprintln!(
                    "TRACE libc-start args rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} rcx=0x{:x} r8=0x{:x} r9=0x{:x}",
                    self.context.registers.general.rdi,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rdx,
                    self.context.registers.general.rcx,
                    self.context.registers.general.r8,
                    self.context.registers.general.r9
                );
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x40ef30 {
                let file = self.context.registers.general.rdi;
                for offset in [0x20u64, 0x28, 0x30, 0x38, 0x70, 0x74, 0x80, 0x88, 0x90] {
                    if let Ok(bytes) = self.context.memory.read(file + offset, 8) {
                        eprintln!(
                            "TRACE file field+0x{offset:x}=0x{:x}",
                            u64::from_le_bytes(bytes.try_into().unwrap())
                        );
                    }
                }
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x40efa7 {
                let file = self.context.registers.general.rdi;
                let target = self
                    .context
                    .memory
                    .read(file.wrapping_add(0x80), 8)
                    .ok()
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!(
                    "TRACE file-write-dispatch file=0x{file:x} target=0x{target:x} rdx=0x{:x}",
                    self.context.registers.general.rdx
                );
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x40ffca {
                let r13 = self.context.registers.general.r13;
                let target = self
                    .context
                    .memory
                    .read(r13.wrapping_add(0x60), 8)
                    .ok()
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!("TRACE nested-write-dispatch r13=0x{r13:x} target=0x{target:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x}", self.context.registers.general.rdi, self.context.registers.general.rsi, self.context.registers.general.rdx);
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x4109dd {
                let r15 = self.context.registers.general.r15;
                let target = self
                    .context
                    .memory
                    .read(r15.wrapping_add(0x58), 8)
                    .ok()
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!("TRACE stdout-write-callback r15=0x{r15:x} target=0x{target:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x}", self.context.registers.general.rdi, self.context.registers.general.rsi, self.context.registers.general.rdx);
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x4089e0 {
                let table = self.context.registers.general.rbx;
                let target = self
                    .context
                    .memory
                    .read(table, 8)
                    .ok()
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!(
                    "TRACE cleanup-dispatch table=0x{table:x} target=0x{target:x} rdi=0x{:x}",
                    self.context.registers.general.rdi
                );
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x4088b0 {
                for (address, name) in [
                    (0x4a4120u64, "io_list_all"),
                    (0x4a4320u64, "stdout"),
                    (0x4a6d20u64, "exit_node"),
                ] {
                    if let Ok(bytes) = self.context.memory.read(address, 0x80) {
                        eprintln!("TRACE {name} address=0x{address:x} bytes={bytes:02x?}");
                    }
                }
            }
            if std::env::var_os("DAOTI_TRACE_STDOUT").is_some() && rip == 0x401668 {
                let stdout = 0x4a4320u64;
                let fields = self.context.memory.read(stdout, 72).unwrap_or_default();
                eprintln!("TRACE stdout fields={fields:02x?}");
                for (offset, name) in [
                    (0, "flags"),
                    (32, "write_base"),
                    (40, "write_ptr"),
                    (48, "write_end"),
                    (56, "buf_base"),
                    (64, "buf_end"),
                ] {
                    if let Ok(bytes) = self.context.memory.read(stdout + offset, 8) {
                        eprintln!(
                            "TRACE stdout {name}=0x{:x}",
                            u64::from_le_bytes(bytes.try_into().unwrap())
                        );
                    }
                }
            }
            if std::env::var_os("DAOTI_TRACE_FATAL").is_some() && rip == 0x401289 {
                let instruction = self.context.memory.read(rip, 16).unwrap_or_default();
                eprintln!(
                    "TRACE fatal rip=0x{rip:x} bytes={instruction:02x?} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x} r8=0x{:x} r9=0x{:x} r10=0x{:x} r11=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x} rflags=0x{:x}",
                    self.context.registers.general.rax,
                    self.context.registers.general.rbx,
                    self.context.registers.general.rcx,
                    self.context.registers.general.rdx,
                    self.context.registers.general.rsi,
                    self.context.registers.general.rdi,
                    self.context.registers.general.rbp,
                    self.context.registers.general.rsp,
                    self.context.registers.general.r8,
                    self.context.registers.general.r9,
                    self.context.registers.general.r10,
                    self.context.registers.general.r11,
                    self.context.registers.general.r12,
                    self.context.registers.general.r13,
                    self.context.registers.general.r14,
                    self.context.registers.general.r15,
                    self.context.registers.general.rflags,
                );
            }
            if std::env::var_os("DAOTI_TRACE_DLMAIN").is_some() && call_chain_active {
                if let Ok(bytes) = self.context.memory.read(rip, 15) {
                    let mut opcode_index = 0usize;
                    while opcode_index < bytes.len()
                        && matches!(bytes[opcode_index], 0x40..=0x4f | 0x66)
                    {
                        opcode_index += 1;
                    }
                    let opcode = bytes.get(opcode_index).copied().unwrap_or(0);
                    let is_compare = matches!(
                        opcode,
                        0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d | 0x84 | 0x85
                    ) || (opcode == 0x0f
                        && bytes
                            .get(opcode_index + 1)
                            .copied()
                            .is_some_and(|op2| (0x80..=0x8f).contains(&op2)));
                    if is_compare {
                        let g = &self.context.registers.general;
                        if let Some(ref mut file) = dlmain_trace {
                            use std::io::Write;
                            let stack = self.context.memory.read(g.rsp, 0x40).ok();
                            let operand = if opcode == 0x39
                                && bytes.get(opcode_index + 1).copied() == Some(0x1d)
                                && bytes.len() >= opcode_index + 6
                            {
                                let disp = i32::from_le_bytes(
                                    bytes[opcode_index + 2..opcode_index + 6]
                                        .try_into()
                                        .unwrap(),
                                ) as i64;
                                let address =
                                    (rip + opcode_index as u64 + 6).wrapping_add_signed(disp);
                                let value = self
                                    .context
                                    .memory
                                    .read(address, 8)
                                    .ok()
                                    .map(|raw| u64::from_le_bytes(raw.try_into().unwrap()));
                                format!(" mem_addr=0x{address:016x} mem_value={value:?} rhs_rbx=0x{:016x}", g.rbx)
                            } else {
                                String::new()
                            };
                            let _ = writeln!(
                                file,
                                "COMPARE rip=0x{rip:016x} bytes={bytes:02x?} opcode=0x{opcode:02x} rax=0x{:016x} rbx=0x{:016x} rcx=0x{:016x} rdx=0x{:016x} rsi=0x{:016x} rdi=0x{:016x} rbp=0x{:016x} rsp=0x{:016x} r8=0x{:016x} r9=0x{:016x} rflags=0x{:016x} stack={stack:02x?}{operand}",
                                g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp,
                                g.r8, g.r9, g.rflags
                            );
                        }
                    }
                }
            }
            if std::env::var_os("DAOTI_TRACE_DLMAIN").is_some() && rip == 0 {
                if std::env::var_os("DAOTI_TRACE_RIP").is_some() {
                    eprintln!(
                        "TRACE rip-zero rsp=0x{:x} rax=0x{:x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x}",
                        self.context.registers.general.rsp,
                        self.context.registers.general.rax,
                        self.context.registers.general.rdi,
                        self.context.registers.general.rsi,
                        self.context.registers.general.rdx
                    );
                }
                if self.sentinel_mode {
                    // IFUNC 解析已完成，函数返回
                    return Ok(self.context.state);
                }
                return Err(DaotiError::Other("RIP 归零，无法继续执行".into()));
            }
            let bytes = match self.context.memory.read(rip, 15) {
                Ok(bytes) => bytes.to_vec(),
                Err(error) => {
                    eprintln!(
                        "动态 ELF 内存访问失败：rip=0x{rip:x} addr=0x{rip:x} fs=0x{:x} rsp=0x{:x} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} r8=0x{:x} r9=0x{:x} r10=0x{:x} r11=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x}; error={error}",
                        self.fs_base,
                        self.context.registers.general.rsp,
                        self.context.registers.general.rax,
                        self.context.registers.general.rbx,
                        self.context.registers.general.rcx,
                        self.context.registers.general.rdx,
                        self.context.registers.general.rsi,
                        self.context.registers.general.rdi,
                        self.context.registers.general.r8,
                        self.context.registers.general.r9,
                        self.context.registers.general.r10,
                        self.context.registers.general.r11,
                        self.context.registers.general.r12,
                        self.context.registers.general.r13,
                        self.context.registers.general.r14,
                        self.context.registers.general.r15,
                    );
                    return Err(error);
                }
            };
            if std::env::var_os("DAOTI_TRACE_RANGE").is_some()
                && (0x240abb0..=0x240ac00).contains(&rip)
            {
                let g = &self.context.registers.general;
                let op_hex = bytes
                    .iter()
                    .take(15)
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                eprintln!("TRACE_RANGE rip=0x{rip:x} bytes=[{op_hex}] rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x} r8=0x{:x} r9=0x{:x} r10=0x{:x} r11=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x}", g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp, g.r8, g.r9, g.r10, g.r11, g.r12, g.r13, g.r14, g.r15);
            }
            // DLMAIN 指令级轨迹：记录 RIP、opcode、关键寄存器与栈顶内存访问。
            if let Some(ref mut file) = dlmain_trace {
                use std::io::Write;
                if trace_dlmain_active {
                    let g = &self.context.registers.general;
                    let op_hex = bytes
                        .iter()
                        .take(15)
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let stack_top = self
                        .context
                        .memory
                        .read(g.rsp, 8)
                        .map(|b| {
                            format!("0x{:016x}", u64::from_le_bytes(b[..8].try_into().unwrap()))
                        })
                        .unwrap_or_else(|_| "MEM? ".to_string());
                    let _ = writeln!(
                        file,
                        "STEP={steps} rip=0x{rip:016x} bytes=[{op_hex}] rax=0x{:016x} rbx=0x{:016x} rcx=0x{:016x} rdx=0x{:016x} rdi=0x{:016x} rsi=0x{:016x} rbp=0x{:016x} rsp=0x{:016x} r8=0x{:016x} r9=0x{:016x} r10=0x{:016x} r11=0x{:016x} stack[0]={stack_top}",
                        g.rax, g.rbx, g.rcx, g.rdx, g.rdi, g.rsi, g.rbp, g.rsp,
                        g.r8, g.r9, g.r10, g.r11,
                    );
                }
            }
            if self.monitor_hit(rip, ASSERTION_OFFSET) && call_chain_trace {
                eprintln!(
                    "TRACE call-chain-at-assertion depth={} frames={:?}",
                    call_chain_frames.len(),
                    call_chain_frames
                );
            }
            let mut p = 0usize;
            let mut rex = 0u8;
            let mut opsz16 = false; // 66 前缀
            let mut rep = 0u8; // f2/f3 前缀
            self.fs_override = false;
            // 跳过各类前缀，REX 须在最后
            while p < bytes.len() {
                let b = bytes[p];
                match b {
                    0x66 => {
                        opsz16 = true;
                        p += 1;
                    }
                    0xf2 | 0xf3 => {
                        rep = b;
                        p += 1;
                    }
                    0x64 | 0x65 => {
                        self.fs_override = true;
                        p += 1;
                    }
                    0x67 | 0x2e | 0x36 | 0x3e | 0x26 | 0xf0 => {
                        p += 1;
                    }
                    _ if b & 0xf0 == 0x40 => {
                        rex = b;
                        p += 1;
                    }
                    _ => break,
                }
            }
            let op = *bytes
                .get(p)
                .ok_or_else(|| DaotiError::Other("指令截断".into()))?;
            p += 1;
            match op {
                0xf7 => {
                    // Grp3 r/m64：test/not/neg/mul/imul/div/idiv
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xf7 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    let dst_reg = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                    if ext_op == 0 {
                        // test r/m64, imm32
                        let (_r, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        if p + 4 > bytes.len() {
                            return Err(DaotiError::Other("0xf7 imm32 截断".into()));
                        }
                        let imm =
                            i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64;
                        p += 4;
                        let lhs = match addr {
                            Some(a) => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                            None => *self.reg(dst_reg),
                        };
                        self.context.registers.general.rflags = update_flags_xor64(lhs & imm);
                    } else if mod_ == 0xc0 {
                        let val = *self.reg(dst_reg);
                        let result = match ext_op {
                            2 => !val,               // NOT
                            3 => val.wrapping_neg(), // NEG
                            4 | 5 => {
                                // MUL/IMUL rdx:rax = rax * r/m64
                                let l = if ext_op == 5 {
                                    ((self.context.registers.general.rax as i64) as i128)
                                        * ((val as i64) as i128)
                                } else {
                                    ((self.context.registers.general.rax as u128) * (val as u128))
                                        as i128
                                };
                                self.context.registers.general.rax = l as u64;
                                self.context.registers.general.rdx = (l >> 64) as u64;
                                l as u64
                            }
                            6 | 7 => {
                                // div/idiv rdx:rax, r/m64
                                let divisor = if val == 0 {
                                    let g = &self.context.registers.general;
                                    let nbucket_mem = self
                                        .context
                                        .memory
                                        .read(g.rdi + 0x2f4, 4)
                                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                                        .unwrap_or(0xffff_ffff);
                                    return Err(DaotiError::Other(format!(
                                        "除法除数为 0（0xf7 寄存器形式, rip=0x{:x}, rm={rm}, ext={ext_op}, rcx=0x{:x}, rdi=0x{:x}, rdx=0x{:x}, rax=0x{:x}, mem[rdi+0x2f4]={nbucket_mem:#x}, bytes={:02x?}）",
                                        g.rip, g.rcx, g.rdi, g.rdx, g.rax, bytes
                                    )));
                                } else {
                                    val
                                };
                                let dividend = self.context.registers.general.rax;
                                let q = dividend / divisor;
                                let rem = dividend % divisor;
                                self.context.registers.general.rax = q;
                                self.context.registers.general.rdx = rem;
                                q
                            }
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0xf7 不支持的扩展操作：/{}",
                                    ext_op
                                )))
                            }
                        };
                        if ext_op == 2 || ext_op == 3 {
                            *self.reg_mut(dst_reg) = result;
                        }
                    } else {
                        let (_r, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0xf7 需要内存地址".into()))?;
                        let width = if opsz16 {
                            2
                        } else if rex & 0x08 != 0 {
                            8
                        } else {
                            4
                        };
                        let raw = self.context.memory.read(addr, width as u64)?;
                        let val = match width {
                            2 => u16::from_le_bytes(raw.try_into().unwrap()) as u64,
                            4 => u32::from_le_bytes(raw.try_into().unwrap()) as u64,
                            _ => u64::from_le_bytes(raw.try_into().unwrap()),
                        };
                        let result = match ext_op {
                            2 => !val,
                            3 => val.wrapping_neg(),
                            6 => {
                                if val == 0 {
                                    return Err(DaotiError::Other(format!(
                                        "除法除数为 0（0xf7 内存形式, rip=0x{:x}, addr=0x{addr:x}, rax=0x{:x}）",
                                        self.context.registers.general.rip,
                                        self.context.registers.general.rax
                                    )));
                                }
                                self.context.registers.general.rax /= val;
                                self.context.registers.general.rdx %= val;
                                val
                            }
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0xf7 内存形式不支持扩展操作：/{}",
                                    ext_op
                                )))
                            }
                        };
                        if ext_op == 2 || ext_op == 3 {
                            self.context
                                .memory
                                .write(addr, &result.to_le_bytes()[..width as usize])?;
                        }
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xf6 => {
                    // Grp3 r/m8：test/not/neg/mul/div 等
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xf6 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    if ext_op == 0 {
                        // test r/m8, imm8
                        let (_r, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr = addr.map(|address| {
                            if mod_ == 0 && rm == 5 {
                                address.wrapping_add(1)
                            } else {
                                address
                            }
                        });
                        if p + 1 > bytes.len() {
                            return Err(DaotiError::Other("0xf6 imm8 截断".into()));
                        }
                        let imm = bytes[p];
                        p += 1;
                        let lhs = match addr {
                            Some(a) => self.context.memory.read(a, 1)?[0] as u64,
                            None => self.rd8(rm, rex, false) as u64,
                        };
                        self.context.registers.general.rflags =
                            update_flags_xor64(lhs & imm as u64);
                    } else if mod_ == 0xc0 {
                        let val = self.rd8(rm, rex, false);
                        match ext_op {
                            2 => self.wr8(rm, rex, false, !val),
                            3 => self.wr8(rm, rex, false, val.wrapping_neg()),
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0xf6 不支持的扩展操作：/{}",
                                    ext_op
                                )))
                            }
                        }
                    } else {
                        return Err(DaotiError::Other(format!(
                            "0xf6 内存形式扩展操作：/{}",
                            ext_op
                        )));
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xff => {
                    // Grp5：inc/dec/call/jmp/push r/m64
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xff 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    let mut get_val = |interp: &X86_64Interpreter| -> Result<u64, DaotiError> {
                        if mod_ == 0xc0 {
                            Ok(*interp.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 }))
                        } else {
                            let (_r, addr) = interp.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                            let addr =
                                addr.ok_or_else(|| DaotiError::Other("0xff 需要内存地址".into()))?;
                            let raw = interp.context.memory.read(addr, 8).inspect_err(|_| {
                                if std::env::var_os("DAOTI_TRACE_INDIRECT").is_some() {
                                    eprintln!("TRACE indirect-read rip=0x{:x} addr=0x{addr:x} ext={ext_op}", interp.context.registers.general.rip);
                                }
                            })?;
                            if std::env::var_os("DAOTI_TRACE_INDIRECT").is_some() {
                                eprintln!(
                                    "TRACE indirect-slot rip=0x{:x} addr=0x{addr:x} raw={raw:02x?}",
                                    interp.context.registers.general.rip
                                );
                            }
                            let v = u64::from_le_bytes(raw.try_into().unwrap());
                            Ok(v)
                        }
                    };
                    match ext_op {
                        0 | 1 => {
                            // inc / dec r/m16/r/m32/r/m64；不修改 CF
                            let width = if opsz16 {
                                2
                            } else if rex & 0x08 != 0 {
                                8
                            } else {
                                4
                            };
                            let mask = match width {
                                2 => 0xffff,
                                4 => 0xffff_ffff,
                                _ => u64::MAX,
                            };
                            let memory_addr = if mod_ == 0xc0 {
                                None
                            } else {
                                let (_r, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                Some(
                                    addr.ok_or_else(|| {
                                        DaotiError::Other("0xff 需要内存地址".into())
                                    })?,
                                )
                            };
                            let old = match memory_addr {
                                Some(addr) => {
                                    let raw = self.context.memory.read(addr, width as u64)?;
                                    match width {
                                        2 => u16::from_le_bytes(raw.try_into().unwrap()) as u64,
                                        4 => u32::from_le_bytes(raw.try_into().unwrap()) as u64,
                                        _ => u64::from_le_bytes(raw.try_into().unwrap()),
                                    }
                                }
                                None => {
                                    *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 }) & mask
                                }
                            };
                            let result = if ext_op == 1 {
                                old.wrapping_sub(1) & mask
                            } else {
                                old.wrapping_add(1) & mask
                            };
                            if mod_ == 0xc0 {
                                let dst_reg = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                                if width == 2 {
                                    *self.reg_mut(dst_reg) =
                                        (*self.reg(dst_reg) & !0xffff) | result;
                                } else if width == 4 {
                                    *self.reg_mut(dst_reg) = result as u32 as u64;
                                } else {
                                    *self.reg_mut(dst_reg) = result;
                                }
                            } else {
                                let addr = memory_addr.expect("0xff 内存地址已解析");
                                self.context
                                    .memory
                                    .write(addr, &result.to_le_bytes()[..width as usize])?;
                            }
                            let carry = self.context.registers.general.rflags & 1;
                            self.context.registers.general.rflags =
                                update_flags_arith_width(result, old, 1, ext_op == 1, width)
                                    | carry;
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        2 | 4 => {
                            // call / jmp r/m64
                            let target = get_val(self)?;
                            if std::env::var_os("DAOTI_TRACE_INDIRECT").is_some() {
                                eprintln!(
                                    "TRACE indirect-control rip=0x{rip:x} ext={ext_op} target=0x{target:x} rbx=0x{:x} rbp=0x{:x} rsp=0x{:x} bytes={:02x?}",
                                    self.context.registers.general.rbx,
                                    self.context.registers.general.rbp,
                                    self.context.registers.general.rsp,
                                    self.context.memory.read(rip, 8).unwrap_or_default(),
                                );
                            }
                            if call_chain_active && target >= 0x241b770 {
                                if let Some(ref mut file) = dlmain_trace {
                                    use std::io::Write;
                                    let g = &self.context.registers.general;
                                    let _ = writeln!(file, "INDIRECT_CONTROL from=0x{rip:016x} kind={} target=0x{target:016x} rdi=0x{:016x} rsi=0x{:016x} rdx=0x{:016x} rcx=0x{:016x}", if ext_op == 2 { "call" } else { "jmp" }, g.rdi, g.rsi, g.rdx, g.rcx);
                                    if !self.breakpoints.iter().any(|bp| bp.addr == target) {
                                        self.breakpoints.push(RuntimeBreakpoint {
                                            name: "call_chain_candidate".into(),
                                            addr: target,
                                        });
                                        let _ = writeln!(
                                            file,
                                            "AUTO_BREAKPOINT target=0x{target:016x}"
                                        );
                                    }
                                }
                            }
                            if ext_op == 2 {
                                let return_rip = rip + p as u64;
                                // IRELATIVE resolver 调用探针：抓取 call 前寄存器实况
                                if std::env::var_os("DAOTI_TRACE_IREL_RET").is_some()
                                    && (0x7a0000..=0x7d0000).contains(&target)
                                {
                                    let g = &self.context.registers.general;
                                    eprintln!("TRACE irel-call from=0x{rip:x} target=0x{target:x} return=0x{return_rip:x} rbp=0x{:x} rsp=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} r15=0x{:x} rbx=0x{:x} rax=0x{:x}",
                                        g.rbp, g.rsp, g.r12, g.r13, g.r14, g.r15, g.rbx, g.rax);
                                }
                                if self
                                    .breakpoints
                                    .iter()
                                    .any(|bp| bp.name == "_dl_new_object" && bp.addr == target)
                                {
                                    link_map_calls.push((target, return_rip, rip));
                                    if std::env::var_os("DAOTI_TRACE_NEW_OBJECT_CALL").is_some() {
                                        eprintln!("TRACE new-object-call kind=indirect from=0x{rip:x} target=0x{target:x} return=0x{return_rip:x}");
                                    }
                                }
                                if self
                                    .breakpoints
                                    .iter()
                                    .any(|bp| bp.name == "_dl_start" && bp.addr == target)
                                {
                                    dl_start_calls.push((target, return_rip, rip));
                                }
                                if trace_dlmain_active {
                                    let prologue = self.context.memory.read(target, 16).ok();
                                    if let Some(ref mut file) = dlmain_trace {
                                        use std::io::Write;
                                        let g = &self.context.registers.general;
                                        let _ = writeln!(file, "DLMAIN_CALL kind=indirect from=0x{rip:016x} target=0x{target:016x} return=0x{return_rip:016x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} rcx=0x{:x} r8=0x{:x} prologue={prologue:02x?}", g.rdi, g.rsi, g.rdx, g.rcx, g.r8);
                                    }
                                    dlmain_calls.push((rip, target, return_rip, false));
                                }
                                let rsp = self.context.registers.general.rsp;
                                let new_rsp = rsp
                                    .checked_sub(8)
                                    .ok_or_else(|| DaotiError::Other("call 栈下溢".into()))?;
                                self.context
                                    .memory
                                    .write(new_rsp, &return_rip.to_le_bytes())?;
                                self.context.registers.general.rsp = new_rsp;
                            }
                            self.context.registers.general.rip = target;
                            continue;
                        }
                        6 => {
                            // push r/m64
                            let value = get_val(self)?;
                            let rsp = self.context.registers.general.rsp;
                            let new_rsp = rsp
                                .checked_sub(8)
                                .ok_or_else(|| DaotiError::Other("push 栈下溢".into()))?;
                            self.context.memory.write(new_rsp, &value.to_le_bytes())?;
                            self.context.registers.general.rsp = new_rsp;
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "0xff 不支持的扩展操作：/{}",
                                ext_op
                            )))
                        }
                    }
                }
                0xf4 => {
                    self.context.state = ExecutionState::Faulted;
                    return Ok(self.context.state);
                }
                0xc9 => {
                    // leave：rsp = rbp；随后从新 rsp 弹出旧 rbp 到 rbp 寄存器。
                    // x86-64 语义：先 mov rsp, rbp，再 pop rbp。
                    let cur_rbp = self.context.registers.general.rbp;
                    let saved_rbp = u64::from_le_bytes(
                        self.context.memory.read(cur_rbp, 8)?.try_into().unwrap(),
                    );
                    if std::env::var_os("DAOTI_TRACE_IREL_RET").is_some() {
                        eprintln!(
                            "TRACE leave rip=0x{rip:x} rbp_before=0x{cur_rbp:x} rsp_before=0x{:x} saved_rbp=0x{saved_rbp:x}",
                            self.context.registers.general.rsp
                        );
                    }
                    self.context.registers.general.rsp = cur_rbp.wrapping_add(8);
                    self.context.registers.general.rbp = saved_rbp;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xc3 => {
                    let rsp = self.context.registers.general.rsp;
                    let target =
                        u64::from_le_bytes(self.context.memory.read(rsp, 8)?.try_into().unwrap());
                    if std::env::var_os("DAOTI_TRACE_IREL_RET").is_some()
                        && (0x2711080..=0x27110c0).contains(&target)
                    {
                        eprintln!(
                            "TRACE irel-return rip=0x{rip:x} ret_to=0x{target:x} rbp=0x{:x} rsp=0x{:x} rbx=0x{:x} r12=0x{:x} r13=0x{:x} r14=0x{:x} rax=0x{:x}",
                            self.context.registers.general.rbp,
                            self.context.registers.general.rsp,
                            self.context.registers.general.rbx,
                            self.context.registers.general.r12,
                            self.context.registers.general.r13,
                            self.context.registers.general.r14,
                            self.context.registers.general.rax
                        );
                        // 首次命中时 dump resolver epilogue 与 trampoline 字节码，避免刷屏
                        use std::sync::atomic::{AtomicBool, Ordering};
                        static DUMPED: AtomicBool = AtomicBool::new(false);
                        if !DUMPED.swap(true, Ordering::Relaxed) {
                            // dump 返回指令前的 epilogue 字节，确认 resolver 真实退栈序列
                            let epi_base = rip.wrapping_sub(0x30);
                            if let Ok(b) = self.context.memory.read(epi_base, 0x40) {
                                eprintln!("TRACE irel-epilogue-dump base=0x{epi_base:x} ret_at=0x{rip:x} bytes={b:02x?}");
                            }
                            // dump IRELATIVE trampoline 区域字节码，确认解析器真实退栈序列
                            let dump_base = 0x2711000u64;
                            if let Ok(b) = self.context.memory.read(dump_base, 0x140) {
                                eprintln!(
                                    "TRACE irel-tramp-dump base=0x{dump_base:x} bytes={b:02x?}"
                                );
                            }
                            // 栈上 call 返回地址下方 0x30 字节，观察调用前栈布局
                            let stack_dump = rsp.wrapping_sub(0x38);
                            if let Ok(s) = self.context.memory.read(stack_dump, 0x40) {
                                eprintln!(
                                    "TRACE irel-stack-dump base=0x{stack_dump:x} bytes={s:02x?}"
                                );
                            }
                        }
                    }
                    if target == 0 && self.sentinel_mode {
                        return Ok(self.context.state);
                    }
                    if let Some(position) = dl_start_calls
                        .iter()
                        .rposition(|(_, ret, _)| *ret == target)
                    {
                        dl_start_calls.remove(position);
                        if !delayed_l_info_initialized {
                            self.pending_l_info_init = true;
                            delayed_l_info_initialized = true;
                        }
                    }
                    self.context.registers.general.rsp = rsp.wrapping_add(8);
                    if std::env::var_os("DAOTI_TRACE_NEW_OBJECT_CALL").is_some()
                        && !link_map_calls.is_empty()
                    {
                        eprintln!(
                            "TRACE new-object-ret target=0x{target:x} frames={link_map_calls:?}"
                        );
                    }
                    if let Some(position) = link_map_calls
                        .iter()
                        .rposition(|(_, ret, _)| *ret == target)
                    {
                        let (_, _, call_rip) = link_map_calls.remove(position);
                        let map_addr = self.context.registers.general.rax;
                        if let Some(initializer) = self.link_map_object_initializer.as_mut() {
                            initializer(&mut self.context.memory, map_addr)?;
                            eprintln!("TRACE new-object-link-map-init map=0x{map_addr:x}");
                        }
                        if std::env::var_os("DAOTI_TRACE_NEW_OBJECT_RETURN").is_some() {
                            let l_real = self
                                .context
                                .memory
                                .read(map_addr.wrapping_add(0x28), 8)
                                .ok()
                                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                            eprintln!(
                                "TRACE new-object-return map=0x{map_addr:x} l_real={l_real:#x?} call=0x{call_rip:x} ret=0x{target:x}"
                            );
                        }
                        if map_addr != 0
                            && self.context.memory.read(map_addr, 0x70).is_ok()
                            && self
                                .context
                                .memory
                                .read(map_addr + 0x28, 8)
                                .ok()
                                .is_some_and(|bytes| {
                                    u64::from_le_bytes(bytes.try_into().unwrap()) == map_addr
                                })
                        {
                            if std::env::var_os("DAOTI_TRACE_NEW_OBJECT_RETURN").is_some() {
                                eprintln!("TRACE new-object-return call=0x{call_rip:x} ret=0x{target:x} map=0x{map_addr:x}");
                            }
                            if let Some(handler) = self.phase_handler.as_mut() {
                                handler(&mut self.context, PhaseId::One)?;
                            }
                        }
                    }
                    let g = &self.context.registers.general;
                    if !dlmain_calls.is_empty() {
                        if let Some(pos) = dlmain_calls
                            .iter()
                            .rposition(|&(_, _, ret, _)| ret == target)
                        {
                            let (from_rip, call_target, _ret, wrote_global) =
                                dlmain_calls.remove(pos);
                            if let Some(ref mut file) = dlmain_trace {
                                use std::io::Write;
                                let _ = writeln!(
                                    file,
                                    "DLMAIN_RETURN from_entry=0x{from_rip:016x} target=0x{call_target:016x} ret_to=0x{target:016x} rax=0x{:016x} rax_zero={} wrote_global={}",
                                    g.rax, g.rax == 0, wrote_global
                                );
                            }
                            eprintln!(
                                "TRACE dlmain-return target=0x{call_target:x} rax=0x{:x} rax_zero={} wrote_global={}",
                                g.rax, g.rax == 0, wrote_global
                            );
                        }
                    }
                    if call_chain_trace {
                        eprintln!("TRACE RET from=0x{rip:x} target=0x{target:x}");
                        if let Some(pos) = call_chain_frames
                            .iter()
                            .rposition(|&(_, _, ret)| ret == target)
                        {
                            call_chain_frames.truncate(pos);
                        }
                    }
                    if call_chain_active && std::env::var_os("DAOTI_TRACE_DLMAIN").is_some() {
                        if let Some(ref mut file) = dlmain_trace {
                            use std::io::Write;
                            let _ = writeln!(
                                file,
                                "RETURN from=0x{rip:016x} target=0x{target:016x} rax=0x{:016x} rsp=0x{:016x}",
                                g.rax, g.rsp
                            );
                        }
                        eprintln!(
                            "TRACE return rip=0x{rip:x} target=0x{target:x} rax=0x{:x}",
                            g.rax
                        );
                    }
                    self.context.registers.general.rip = target;
                    continue;
                }
                0xd0 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xd0 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let original = match dst_addr {
                        Some(addr) => self.context.memory.read(addr, 1)?[0],
                        None => self.rd8(rm, rex, false),
                    };
                    let result = match ext_op {
                        4 => original.wrapping_shl(1),
                        5 => original.wrapping_shr(1),
                        6 => original.rotate_left(1),
                        7 => original.rotate_right(1),
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "0xd0 不支持的扩展操作：/{}",
                                ext_op
                            )))
                        }
                    };
                    match dst_addr {
                        Some(addr) => self.context.memory.write(addr, &[result])?,
                        None => self.wr8(rm, rex, false, result),
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xd1 => {
                    // Grp2：r/m16/r/m32/r/m64 按 1 位移位
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xd1 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    let width = if opsz16 {
                        2
                    } else if rex & 8 != 0 {
                        8
                    } else {
                        4
                    };
                    let mask = match width {
                        2 => 0xffff,
                        4 => 0xffff_ffff,
                        _ => u64::MAX,
                    };
                    let value = if mod_ == 0xc0 {
                        *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 }) & mask
                    } else {
                        let (_, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let raw = self.context.memory.read(
                            addr.ok_or_else(|| DaotiError::Other("0xd1 需要内存地址".into()))?,
                            width as u64,
                        )?;
                        match width {
                            2 => u16::from_le_bytes(raw.try_into().unwrap()) as u64,
                            4 => u32::from_le_bytes(raw.try_into().unwrap()) as u64,
                            _ => u64::from_le_bytes(raw.try_into().unwrap()),
                        }
                    };
                    let result = match ext_op {
                        0 | 4 | 6 => value.wrapping_shl(1) & mask,
                        1 | 5 => value >> 1,
                        7 => ((value | (!mask)) as i64 >> 1) as u64 & mask,
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "0xd1 不支持的扩展操作：0x{ext_op:x}"
                            )))
                        }
                    };
                    if mod_ == 0xc0 {
                        let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        if width == 2 {
                            *self.reg_mut(dst) = (*self.reg(dst) & !0xffff) | result;
                        } else if width == 4 {
                            *self.reg_mut(dst) = result as u32 as u64;
                        } else {
                            *self.reg_mut(dst) = result;
                        }
                    } else {
                        let (_, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        self.context.memory.write(
                            addr.ok_or_else(|| DaotiError::Other("0xd1 需要内存地址".into()))?,
                            &result.to_le_bytes()[..width as usize],
                        )?;
                    }
                    self.context.registers.general.rflags = update_flags_logic(result, width);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xd3 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xd3 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    if mod_ != 0xc0 {
                        return Err(DaotiError::Other("0xd3 暂不支持内存形式".into()));
                    }
                    let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                    let count = (self.context.registers.general.rcx & 0x3f) as u32;
                    let value = *self.reg(dst);
                    *self.reg_mut(dst) = match ext_op {
                        0 | 4 | 6 => value.wrapping_shl(count),
                        1 | 5 => value.wrapping_shr(count),
                        7 => ((value as i64) >> count.min(63)) as u64,
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "0xd3 不支持的扩展操作：0x{ext_op:x}"
                            )))
                        }
                    };
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xc0 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xc0 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("0xc0 imm8 截断".into()));
                    }
                    let count = (bytes[p] & 0x1f) as u32;
                    p += 1;
                    let original = match dst_addr {
                        Some(addr) => self.context.memory.read(addr, 1)?[0],
                        None => self.rd8(rm, rex, false),
                    };
                    let result = match ext_op {
                        4 => original.wrapping_shl(count),
                        5 => original.wrapping_shr(count),
                        6 => original.rotate_left(count),
                        7 => original.rotate_right(count),
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "0xc0 不支持的扩展操作：/{}",
                                ext_op
                            )))
                        }
                    };
                    match dst_addr {
                        Some(addr) => self.context.memory.write(addr, &[result])?,
                        None => self.wr8(rm, rex, false, result),
                    }
                    self.context.registers.general.rflags = update_flags_logic(result as u64, 1);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xc1 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xc1 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("0xc1 imm8 截断".into()));
                    }
                    let imm = bytes[p] as u32;
                    p += 1;
                    if mod_ == 0xc0 {
                        let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        let val = *self.reg(dst);
                        *self.reg_mut(dst) = match ext_op {
                            0 => val.rotate_left(imm & 63),
                            4 | 6 => val.wrapping_shl(imm),
                            1 => val.rotate_right(imm & 63),
                            5 => val.wrapping_shr(imm),
                            7 => ((val as i64) >> imm.min(63)) as u64,
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0xc1 不支持的扩展操作：0x{ext_op:x}"
                                )))
                            }
                        };
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0xc1 需要内存地址".into()))?;
                        let val = u64::from_le_bytes(
                            self.context.memory.read(addr, 8)?.try_into().unwrap(),
                        );
                        let result = match ext_op {
                            0 => val.rotate_left(imm & 63),
                            4 | 6 => val.wrapping_shl(imm),
                            1 => val.rotate_right(imm & 63),
                            5 => val.wrapping_shr(imm),
                            7 => ((val as i64) >> imm.min(63)) as u64,
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0xc1 不支持的扩展操作：0x{ext_op:x}"
                                )))
                            }
                        };
                        self.context.memory.write(addr, &result.to_le_bytes())?;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xc2 => {
                    if p + 2 > bytes.len() {
                        return Err(DaotiError::Other("ret imm16 指令截断".into()));
                    }
                    let adjust = u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap()) as u64;
                    let rsp = self.context.registers.general.rsp;
                    let target =
                        u64::from_le_bytes(self.context.memory.read(rsp, 8)?.try_into().unwrap());
                    self.context.registers.general.rsp = rsp.wrapping_add(8).wrapping_add(adjust);
                    self.context.registers.general.rip = target;
                    continue;
                }
                0x90 => {
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x91 => {
                    let eax = self.context.registers.general.rax as u32;
                    let ecx = self.context.registers.general.rcx as u32;
                    self.context.registers.general.rax = ecx as u64;
                    self.context.registers.general.rcx = eax as u64;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x9c => {
                    let rsp = self
                        .context
                        .registers
                        .general
                        .rsp
                        .checked_sub(8)
                        .ok_or_else(|| DaotiError::Other("pushfq 栈下溢".into()))?;
                    self.context
                        .memory
                        .write(rsp, &self.context.registers.general.rflags.to_le_bytes())?;
                    self.context.registers.general.rsp = rsp;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x9d => {
                    let rsp = self.context.registers.general.rsp;
                    let flags =
                        u64::from_le_bytes(self.context.memory.read(rsp, 8)?.try_into().unwrap());
                    self.context.registers.general.rflags = flags;
                    self.context.registers.general.rsp = rsp.wrapping_add(8);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x98 => {
                    // cbw/cwde/cdqe：按操作数宽度符号扩展累加器
                    if opsz16 {
                        let value = (self.context.registers.general.rax as u8 as i8) as i16 as u16;
                        self.context.registers.general.rax =
                            (self.context.registers.general.rax & !0xffff) | value as u64;
                    } else if rex & 0x08 != 0 {
                        self.context.registers.general.rax =
                            (self.context.registers.general.rax as u32 as i32 as i64) as u64;
                    } else {
                        self.context.registers.general.rax =
                            (self.context.registers.general.rax as u16 as i16 as i32) as u32 as u64;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x70..=0x7f => {
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("条件跳转 rel8 截断".into()));
                    }
                    let rel = bytes[p] as i8 as i64;
                    p += 1;
                    if parse_jcc(op, self.context.registers.general.rflags) {
                        self.context.registers.general.rip = ((rip + p as u64) as i64 + rel) as u64;
                    } else {
                        self.context.registers.general.rip = rip + p as u64;
                    }
                    continue;
                }
                0xeb => {
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("jmp rel8 截断".into()));
                    }
                    let rel = bytes[p] as i8 as i64;
                    p += 1;
                    self.context.registers.general.rip = ((rip + p as u64) as i64 + rel) as u64;
                    continue;
                }
                0xe9 => {
                    if p + 4 > bytes.len() {
                        return Err(DaotiError::Other("jmp rel32 截断".into()));
                    }
                    let rel = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                    p += 4;
                    self.context.registers.general.rip =
                        ((rip + p as u64) as i64 + rel as i64) as u64;
                    continue;
                }
                0x68 => {
                    if p + 4 > bytes.len() {
                        return Err(DaotiError::Other("push imm32 指令截断".into()));
                    }
                    let value =
                        i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64;
                    p += 4;
                    let rsp = self.context.registers.general.rsp;
                    let new_rsp = rsp
                        .checked_sub(8)
                        .ok_or_else(|| DaotiError::Other("push 栈下溢".into()))?;
                    self.context.memory.write(new_rsp, &value.to_le_bytes())?;
                    self.context.registers.general.rsp = new_rsp;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x6a => {
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("push imm8 指令截断".into()));
                    }
                    let value = (bytes[p] as i8 as i64) as u64;
                    p += 1;
                    let rsp = self.context.registers.general.rsp;
                    let new_rsp = rsp
                        .checked_sub(8)
                        .ok_or_else(|| DaotiError::Other("push 栈下溢".into()))?;
                    self.context.memory.write(new_rsp, &value.to_le_bytes())?;
                    self.context.registers.general.rsp = new_rsp;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x50..=0x57 => {
                    let rd = ((op - 0x50) as usize) | if rex & 1 != 0 { 8 } else { 0 };
                    let val = *self.reg(rd);
                    let rsp = self.context.registers.general.rsp;
                    let new_rsp = rsp
                        .checked_sub(8)
                        .ok_or_else(|| DaotiError::Other("push 栈下溢".into()))?;
                    self.context.memory.write(new_rsp, &val.to_le_bytes())?;
                    self.context.registers.general.rsp = new_rsp;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x58..=0x5f => {
                    let rd = ((op - 0x58) as usize) | if rex & 1 != 0 { 8 } else { 0 };
                    let rsp = self.context.registers.general.rsp;
                    let val =
                        u64::from_le_bytes(self.context.memory.read(rsp, 8)?.try_into().unwrap());
                    *self.reg_mut(rd) = val;
                    self.context.registers.general.rsp = rsp.wrapping_add(8);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xab => {
                    let width = if rex & 0x08 != 0 { 8 } else { 4 };
                    let repeat = rep == 0xf3;
                    let count = if repeat {
                        self.context.registers.general.rcx
                    } else {
                        1
                    };
                    let decrement = self.context.registers.general.rflags & 0x400 != 0;
                    let step = if decrement {
                        -(width as i64)
                    } else {
                        width as i64
                    };
                    let value = self.context.registers.general.rax.to_le_bytes();
                    let mut address = self.context.registers.general.rdi;
                    for _ in 0..count {
                        self.context.memory.write(address, &value[..width])?;
                        address = address.wrapping_add_signed(step);
                    }
                    self.context.registers.general.rdi = address;
                    if repeat {
                        self.context.registers.general.rcx = 0;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xa8 => {
                    // test al, imm8
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("test al, imm8 截断".into()));
                    }
                    let imm = bytes[p] as u64;
                    p += 1;
                    let result = (self.context.registers.general.rax & 0xff) & imm;
                    self.context.registers.general.rflags = update_flags_logic(result, 1);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xa9 => {
                    // test eax/rax, imm32
                    if p + 4 > bytes.len() {
                        return Err(DaotiError::Other("test eax/rax, imm32 截断".into()));
                    }
                    let width = if rex & 0x08 != 0 { 8 } else { 4 };
                    let imm = if width == 8 {
                        i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64
                    } else {
                        u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as u64
                    };
                    p += 4;
                    let lhs = self.context.registers.general.rax;
                    self.context.registers.general.rflags = update_flags_logic(lhs & imm, width);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xb8..=0xbf => {
                    let rd = ((op - 0xb8) as usize) | if rex & 1 != 0 { 8 } else { 0 };
                    if rex & 0x08 != 0 {
                        if p + 8 > bytes.len() {
                            return Err(DaotiError::Other("movabs 指令截断".into()));
                        }
                        let mut imm_buf = [0u8; 8];
                        imm_buf.copy_from_slice(&bytes[p..p + 8]);
                        p += 8;
                        *self.reg_mut(rd) = u64::from_le_bytes(imm_buf);
                    } else {
                        if p + 4 > bytes.len() {
                            return Err(DaotiError::Other("mov imm32 指令截断".into()));
                        }
                        let imm = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                        p += 4;
                        *self.reg_mut(rd) = imm as u64;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xc6 => {
                    // mov r/m8, imm8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xc6 指令截断".into()))?;
                    p += 1;
                    let ext_op = (m >> 3) & 7;
                    if ext_op != 0 {
                        return Err(DaotiError::Other(format!(
                            "0xc6 不支持的扩展操作：/{}",
                            ext_op
                        )));
                    }
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("0xc6 imm8 截断".into()));
                    }
                    let v = bytes[p];
                    p += 1;
                    if mod_ == 0xc0 {
                        self.wr8(rm, rex, false, v);
                    } else {
                        let addr = dst_addr
                            .ok_or_else(|| DaotiError::Other("0xc6 需要内存地址".into()))?;
                        if trace_dlmain_active {
                            eprintln!("TRACE dl_main-memory-write step={} rip=0x{rip:x} opcode=c6 addr=0x{addr:x} width=1 value=0x{v:x} ns_loaded_target={} main_map_candidate=false rdi_target={}", trace_dlmain_steps, Some(addr) == ns_loaded_addr, addr == self.context.registers.general.rdi);
                            if rtld_global_addr.is_some_and(|base| {
                                (base..base.saturating_add(0x2000)).contains(&addr)
                            }) {
                                if let Some(frame) = dlmain_calls.last_mut() {
                                    frame.3 = true;
                                }
                            }
                        }
                        self.context.memory.write(addr, &[v])?;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xc7 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0xc7 指令截断".into()))?;
                    p += 1;
                    let ext_op = (m >> 3) & 7;
                    if ext_op != 0 {
                        return Err(DaotiError::Other(format!(
                            "不支持的 mov imm32 扩展操作：/{}",
                            ext_op
                        )));
                    }
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let dst_addr = dst_addr.map(|addr| {
                        if mod_ == 0 && rm == 5 {
                            addr.wrapping_add(if opsz16 { 2 } else { 4 })
                        } else {
                            addr
                        }
                    });
                    let immediate_len = if opsz16 { 2 } else { 4 };
                    if p + immediate_len > bytes.len() {
                        return Err(DaotiError::Other("mov 立即数截断".into()));
                    }
                    let v = if opsz16 {
                        u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap()) as u64
                    } else {
                        i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64
                    };
                    p += immediate_len;
                    let width64 = rex & 0x08 != 0 && !opsz16;
                    match dst_addr {
                        Some(addr) => {
                            let bytes = if width64 {
                                &v.to_le_bytes()[..]
                            } else if opsz16 {
                                &v.to_le_bytes()[..2]
                            } else {
                                &v.to_le_bytes()[..4]
                            };
                            if trace_dlmain_active {
                                eprintln!("TRACE dl_main-memory-write step={} rip=0x{rip:x} opcode=c7 addr=0x{addr:x} width={} value=0x{:x} ns_loaded_target={} main_map_candidate=false rdi_target={}", trace_dlmain_steps, bytes.len(), v, Some(addr) == ns_loaded_addr, addr == self.context.registers.general.rdi);
                                if rtld_global_addr.is_some_and(|base| {
                                    (base..base.saturating_add(0x2000)).contains(&addr)
                                }) {
                                    if let Some(frame) = dlmain_calls.last_mut() {
                                        frame.3 = true;
                                    }
                                }
                            }
                            self.context.memory.write(addr, bytes)?;
                        }
                        None => {
                            *self.reg_mut(dst_reg) = if width64 { v } else { v as u32 as u64 };
                        }
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x8d => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("lea 指令截断".into()))?;
                    p += 1;
                    let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let addr = if mod_ == 0 && rm == 5 {
                        if p + 4 > bytes.len() {
                            return Err(DaotiError::Other("lea disp32 截断".into()));
                        }
                        let d = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                        p += 4;
                        (rip + p as u64).wrapping_add(d as i64 as u64)
                    } else if rm == 4 {
                        let sib = *bytes
                            .get(p)
                            .ok_or_else(|| DaotiError::Other("lea SIB 截断".into()))?;
                        p += 1;
                        let disp: i64 = match mod_ {
                            0 => {
                                if sib & 7 == 5 {
                                    if p + 4 > bytes.len() {
                                        return Err(DaotiError::Other(
                                            "lea SIB 无基址 disp32 截断".into(),
                                        ));
                                    }
                                    let d = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                                    p += 4;
                                    d as i64
                                } else {
                                    0
                                }
                            }
                            0x40 => {
                                let d = *bytes
                                    .get(p)
                                    .ok_or_else(|| DaotiError::Other("lea disp8 截断".into()))?
                                    as i8 as i64;
                                p += 1;
                                d
                            }
                            0x80 => {
                                if p + 4 > bytes.len() {
                                    return Err(DaotiError::Other("lea SIB disp32 截断".into()));
                                }
                                let d = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                                p += 4;
                                d as i64
                            }
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "lea 不支持 SIB mod：0x{m:02x}"
                                )))
                            }
                        };
                        let scale_shift = ((sib >> 6) & 3) as u32;
                        let index_field = (sib >> 3) & 7;
                        let index = if index_field == 4 {
                            0
                        } else {
                            let index_reg = index_field as usize | if rex & 2 != 0 { 8 } else { 0 };
                            self.reg(index_reg).wrapping_shl(scale_shift)
                        };
                        let base_field = sib & 7;
                        let base = if mod_ == 0 && base_field == 5 {
                            0
                        } else {
                            let base_reg = base_field as usize | if rex & 1 != 0 { 8 } else { 0 };
                            *self.reg(base_reg)
                        };
                        base.wrapping_add(index).wrapping_add(disp as u64)
                    } else {
                        let base = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        if mod_ == 0 {
                            *self.reg(base)
                        } else {
                            let disp: i64 = if mod_ == 0x40 {
                                let d = *bytes
                                    .get(p)
                                    .ok_or_else(|| DaotiError::Other("lea disp8 截断".into()))?
                                    as i8 as i64;
                                p += 1;
                                d
                            } else if mod_ == 0x80 {
                                if p + 4 > bytes.len() {
                                    return Err(DaotiError::Other("lea disp32 截断".into()));
                                }
                                let d = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                                p += 4;
                                d as i64
                            } else {
                                return Err(DaotiError::Other(format!(
                                    "lea 不支持的寻址模式：0x{m:02x}"
                                )));
                            };
                            self.reg(base).wrapping_add_signed(disp)
                        }
                    };
                    *self.reg_mut(dst) = self.seg_addr(addr);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x63 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x63 指令截断".into()))?;
                    p += 1;
                    let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let value = if mod_ == 0xc0 {
                        let src = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        (*self.reg(src) & 0xffffffff) as i32 as i64 as u64
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("movsxd 需要内存地址".into()))?;
                        let raw = self.context.memory.read(addr, 4)?;
                        i32::from_le_bytes(raw.try_into().unwrap()) as i64 as u64
                    };
                    *self.reg_mut(dst) = value;
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x08 => {
                    // or r/m8, r8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x08 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let rhs = self.rd8((m >> 3) & 7, rex, true);
                    let lhs = match dst_addr {
                        Some(addr) => self.context.memory.read(addr, 1)?[0] as u64,
                        None => self.rd8(rm, rex, false) as u64,
                    };
                    let result = lhs | rhs as u64;
                    self.context.registers.general.rflags = update_flags_logic(result, 1);
                    match dst_addr {
                        Some(addr) => self.context.memory.write(addr, &[result as u8])?,
                        None => self.wr8(rm, rex, false, result as u8),
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x03 | 0x09 | 0x0b | 0x19 | 0x1b | 0x21 | 0x23 | 0x29 | 0x2b => {
                    // add/sub/or/and/sbb r/m64, r64 或 r64, r/m64
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("算术 r,r 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let reg_idx = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let is_sbb = op == 0x19 || op == 0x1b;
                    let is_sub = op == 0x29 || op == 0x2b || is_sbb;
                    let is_or = op == 0x09 || op == 0x0b;
                    let is_and = op == 0x21 || op == 0x23;
                    let is_reverse =
                        op == 0x03 || op == 0x0b || op == 0x1b || op == 0x23 || op == 0x2b;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let (lhs, rhs) = if is_reverse {
                        (
                            *self.reg(reg_idx),
                            match dst_addr {
                                Some(a) => u64::from_le_bytes(
                                    self.context.memory.read(a, 8)?.try_into().unwrap(),
                                ),
                                None => *self.reg(dst_reg),
                            },
                        )
                    } else {
                        (
                            match dst_addr {
                                Some(a) => u64::from_le_bytes(
                                    self.context.memory.read(a, 8)?.try_into().unwrap(),
                                ),
                                None => *self.reg(dst_reg),
                            },
                            *self.reg(reg_idx),
                        )
                    };
                    let carry = u64::from(self.context.registers.general.rflags & 1 != 0);
                    let result = if is_sbb {
                        lhs.wrapping_sub(rhs).wrapping_sub(carry)
                    } else if is_sub {
                        lhs.wrapping_sub(rhs)
                    } else if is_or {
                        lhs | rhs
                    } else if is_and {
                        lhs & rhs
                    } else {
                        lhs.wrapping_add(rhs)
                    };
                    if is_or || is_and {
                        self.context.registers.general.rflags = update_flags_xor64(result);
                    } else {
                        self.context.registers.general.rflags = update_flags_arith64(
                            result,
                            lhs,
                            rhs.wrapping_add(if is_sbb { carry } else { 0 }),
                            is_sub,
                        );
                    }
                    if is_reverse {
                        *self.reg_mut(reg_idx) = result;
                    } else {
                        match dst_addr {
                            Some(a) => self.context.memory.write(a, &result.to_le_bytes())?,
                            None => *self.reg_mut(dst_reg) = result,
                        }
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x00 => {
                    // add r/m8, r8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x00 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let rhs = self.rd8((m >> 3) & 7, rex, true);
                    if let Some(addr) = dst_addr {
                        let lhs = self.context.memory.read(addr, 1)?[0];
                        let result = lhs.wrapping_add(rhs);
                        self.context.memory.write(addr, &[result])?;
                        self.context.registers.general.rflags =
                            update_flags_arith64(result as u64, lhs as u64, rhs as u64, false);
                    } else {
                        let lhs = self.rd8(rm, rex, false);
                        let result = lhs.wrapping_add(rhs);
                        self.wr8(rm, rex, false, result);
                        self.context.registers.general.rflags =
                            update_flags_arith64(result as u64, lhs as u64, rhs as u64, false);
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x20 => {
                    // and r/m8, r8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x20 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let rhs = self.rd8((m >> 3) & 7, rex, true);
                    let result = if let Some(addr) = dst_addr {
                        let lhs = self.context.memory.read(addr, 1)?[0];
                        let result = lhs & rhs;
                        self.context.memory.write(addr, &[result])?;
                        result
                    } else {
                        let lhs = self.rd8(rm, rex, false);
                        let result = lhs & rhs;
                        self.wr8(rm, rex, false, result);
                        result
                    };
                    self.context.registers.general.rflags = update_flags_logic(result as u64, 1);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x28 => {
                    // sub r/m8, r8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x28 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let rhs = self.rd8((m >> 3) & 7, rex, true);
                    if let Some(addr) = dst_addr {
                        let lhs = self.context.memory.read(addr, 1)?[0];
                        let result = lhs.wrapping_sub(rhs);
                        self.context.memory.write(addr, &[result])?;
                        self.context.registers.general.rflags =
                            update_flags_arith64(result as u64, lhs as u64, rhs as u64, true);
                    } else {
                        let lhs = self.rd8(rm, rex, false);
                        let result = lhs.wrapping_sub(rhs);
                        self.wr8(rm, rex, false, result);
                        self.context.registers.general.rflags =
                            update_flags_arith64(result as u64, lhs as u64, rhs as u64, true);
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c => {
                    // 8 位累加器立即数运算：add/or/adc/sbb/and/sub/xor/cmp al, imm8
                    let lhs = (self.context.registers.general.rax & 0xff) as u8;
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("8 位累加器 imm8 截断".into()));
                    }
                    let imm = bytes[p];
                    p += 1;
                    if op == 0x14 || op == 0x1c {
                        return Err(DaotiError::Other("adc/sbb 暂不支持".into()));
                    }
                    let result = match op {
                        0x04 => lhs.wrapping_add(imm),
                        0x0c => lhs | imm,
                        0x24 => lhs & imm,
                        0x2c => lhs.wrapping_sub(imm),
                        0x34 => lhs ^ imm,
                        _ => 0, // cmp 不写回
                    };
                    if op == 0x3c {
                        // cmp：只置标志，不写回
                        self.context.registers.general.rflags = update_flags_arith64(
                            lhs.wrapping_sub(imm) as u64,
                            lhs as u64,
                            imm as u64,
                            true,
                        );
                    } else {
                        self.context.registers.general.rax =
                            (self.context.registers.general.rax & !0xff) | result as u64;
                        if op == 0x34 || op == 0x0c || op == 0x24 {
                            self.context.registers.general.rflags =
                                update_flags_xor64(result as u64);
                        } else {
                            self.context.registers.general.rflags = update_flags_arith64(
                                result as u64,
                                lhs as u64,
                                imm as u64,
                                op == 0x2c,
                            );
                        }
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x38 => {
                    // cmp r/m8, r8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x38 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let lhs = match dst_addr {
                        Some(a) => self.context.memory.read(a, 1)?[0] as u64,
                        None => self.rd8(rm, rex, false) as u64,
                    };
                    let rhs = self.rd8((m >> 3) & 7, rex, true) as u64;
                    self.context.registers.general.rflags =
                        update_flags_arith_width(lhs.wrapping_sub(rhs), lhs, rhs, true, 1);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x3a => {
                    // cmp r8, r/m8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x3a 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (_src_reg, src_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let lhs = self.rd8((m >> 3) & 7, rex, true) as u64;
                    let rhs = match src_addr {
                        Some(a) => self.context.memory.read(a, 1)?[0] as u64,
                        None => self.rd8(rm, rex, false) as u64,
                    };
                    self.context.registers.general.rflags =
                        update_flags_arith_width(lhs.wrapping_sub(rhs), lhs, rhs, true, 1);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x39 => {
                    // cmp r/m64, r64
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x39 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let lhs = match dst_addr {
                        Some(a) => match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(a, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(a, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                        },
                        None => match width {
                            2 => *self.reg(dst_reg) & 0xffff,
                            4 => *self.reg(dst_reg) & 0xffff_ffff,
                            _ => *self.reg(dst_reg),
                        },
                    };
                    let rhs = match width {
                        2 => *self.reg(src) & 0xffff,
                        4 => *self.reg(src) & 0xffff_ffff,
                        _ => *self.reg(src),
                    };
                    self.context.registers.general.rflags = update_flags_arith_width(
                        lhs.wrapping_sub(rhs),
                        lhs,
                        rhs,
                        true,
                        width as u8,
                    );
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x01 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x01 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let mask = match width {
                        2 => 0xffff,
                        4 => 0xffff_ffff,
                        _ => u64::MAX,
                    };
                    let value = *self.reg(src) & mask;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let old = match dst_addr {
                        Some(a) => match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(a, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(a, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                        },
                        None => *self.reg(dst_reg) & mask,
                    };
                    let result = old.wrapping_add(value) & mask;
                    match dst_addr {
                        Some(a) => self
                            .context
                            .memory
                            .write(a, &result.to_le_bytes()[..width as usize])?,
                        None => {
                            *self.reg_mut(dst_reg) = if width == 2 {
                                (*self.reg(dst_reg) & !0xffff) | result
                            } else if width == 4 {
                                result as u32 as u64
                            } else {
                                result
                            };
                        }
                    }
                    self.context.registers.general.rflags =
                        update_flags_arith_width(result, old, value, false, width);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x3b => {
                    // cmp r64, r/m64
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x3b 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (src_reg, src_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let lhs = match width {
                        2 => *self.reg(dst) & 0xffff,
                        4 => *self.reg(dst) & 0xffff_ffff,
                        _ => *self.reg(dst),
                    };
                    let rhs = match src_addr {
                        Some(a) => match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(a, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(a, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                        },
                        None => match width {
                            2 => *self.reg(src_reg) & 0xffff,
                            4 => *self.reg(src_reg) & 0xffff_ffff,
                            _ => *self.reg(src_reg),
                        },
                    };
                    self.context.registers.general.rflags = update_flags_arith_width(
                        lhs.wrapping_sub(rhs),
                        lhs,
                        rhs,
                        true,
                        width as u8,
                    );
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 => {
                    // 累加器立即数运算：add/or/adc/sbb/and/sub/xor eax/rax, imm32
                    let is_64 = rex & 0x08 != 0;
                    let lhs = if is_64 {
                        self.context.registers.general.rax
                    } else {
                        self.context.registers.general.rax & 0xffff_ffff
                    };
                    if p + 4 > bytes.len() {
                        return Err(DaotiError::Other("累加器 imm32 截断".into()));
                    }
                    let imm = if is_64 {
                        i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64
                    } else {
                        u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as u64
                    };
                    p += 4;
                    if op == 0x15 || op == 0x1d {
                        return Err(DaotiError::Other("adc/sbb 暂不支持".into()));
                    }
                    let result = match op {
                        0x05 => lhs.wrapping_add(imm),
                        0x0d => lhs | imm,
                        0x25 => lhs & imm,
                        0x2d => lhs.wrapping_sub(imm),
                        0x35 => lhs ^ imm,
                        _ => unreachable!(),
                    };
                    self.context.registers.general.rax = result;
                    if op == 0x35 || op == 0x0d || op == 0x25 {
                        self.context.registers.general.rflags = update_flags_xor64(result);
                    } else {
                        self.context.registers.general.rflags =
                            update_flags_arith64(result, lhs, imm, op == 0x2d);
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x3d => {
                    // cmp rax/eax, imm32
                    let width = if rex & 0x08 != 0 { 8 } else { 4 };
                    let lhs = if width == 8 {
                        self.context.registers.general.rax
                    } else {
                        self.context.registers.general.rax & 0xffff_ffff
                    };
                    if p + 4 > bytes.len() {
                        return Err(DaotiError::Other("cmp imm32 截断".into()));
                    }
                    let imm = if width == 8 {
                        i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64
                    } else {
                        u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as u64
                    };
                    p += 4;
                    self.context.registers.general.rflags =
                        update_flags_arith_width(lhs.wrapping_sub(imm), lhs, imm, true, width);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x84 => {
                    // test r/m8, r8（AND 后不写回，仅置标志）
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x84 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let src = self.rd8((m >> 3) & 7, rex, true);
                    let lhs = if mod_ == 0xc0 {
                        self.rd8(rm, rex, false) as u64
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x84 需要内存地址".into()))?;
                        self.context.memory.read(addr, 1)?[0] as u64
                    };
                    let result = lhs & src as u64;
                    self.context.registers.general.rflags = update_flags_xor64(result);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x85 => {
                    // test r/m64, r64（AND 后不写回，仅置标志）
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x85 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let lhs = match dst_addr {
                        Some(a) => match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(a, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(a, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                        },
                        None => match width {
                            2 => *self.reg(dst_reg) & 0xffff,
                            4 => *self.reg(dst_reg) & 0xffff_ffff,
                            _ => *self.reg(dst_reg),
                        },
                    };
                    let rhs = match width {
                        2 => *self.reg(src) & 0xffff,
                        4 => *self.reg(src) & 0xffff_ffff,
                        _ => *self.reg(src),
                    };
                    let result = lhs & rhs;
                    self.context.registers.general.rflags = update_flags_logic(result, width as u8);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x33 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x33 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let value = if mod_ == 0xc0 {
                        let value = *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 });
                        match width {
                            2 => value & 0xffff,
                            4 => value & 0xffff_ffff,
                            _ => value,
                        }
                    } else {
                        let (_, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x33 需要内存地址".into()))?;
                        match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(addr, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(addr, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(addr, 8)?.try_into().unwrap(),
                            ),
                        }
                    };
                    let old = *self.reg(src);
                    let result = match width {
                        2 => (old & 0xffff) ^ value,
                        4 => ((old as u32) ^ (value as u32)) as u64,
                        _ => old ^ value,
                    };
                    *self.reg_mut(src) = if width == 2 {
                        (old & !0xffff) | result
                    } else {
                        result
                    };
                    self.context.registers.general.rflags = update_flags_logic(result, width as u8);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x30 => {
                    // xor r/m8, r8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x30 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let src = self.rd8((m >> 3) & 7, rex, true);
                    if mod_ == 0xc0 {
                        let old = self.rd8(rm, rex, false);
                        self.wr8(rm, rex, false, old ^ src);
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x30 需要内存地址".into()))?;
                        let old = self.context.memory.read(addr, 1)?[0];
                        self.context.memory.write(addr, &[old ^ src])?;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x31 => {
                    // xor r/m16/r/m32/r/m64, r16/r32/r64
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x31 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let source = match width {
                        2 => *self.reg(src) & 0xffff,
                        4 => *self.reg(src) & 0xffff_ffff,
                        _ => *self.reg(src),
                    };
                    let mut memory_addr = None;
                    let destination = if mod_ == 0xc0 {
                        let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        match width {
                            2 => *self.reg(dst) & 0xffff,
                            4 => *self.reg(dst) & 0xffff_ffff,
                            _ => *self.reg(dst),
                        }
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x31 需要内存地址".into()))?;
                        memory_addr = Some(addr);
                        match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(addr, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(addr, 4).map_err(|error| {
                                    if std::env::var_os("DAOTI_TRACE_ERRORS").is_some() {
                                        eprintln!("TRACE 0x8b rip=0x{rip:x} addr=0x{addr:x} width={width} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} r8=0x{:x} r9=0x{:x}: {error}", self.context.registers.general.rax, self.context.registers.general.rbx, self.context.registers.general.rcx, self.context.registers.general.rdx, self.context.registers.general.rsi, self.context.registers.general.rdi, self.context.registers.general.rbp, self.context.registers.general.r8, self.context.registers.general.r9);
                                    }
                                    error
                                })?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(addr, 8).map_err(|error| {
                                    if std::env::var_os("DAOTI_TRACE_ERRORS").is_some() {
                                        eprintln!("TRACE 0x8b rip=0x{rip:x} addr=0x{addr:x} width={width} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} r8=0x{:x} r9=0x{:x}: {error}", self.context.registers.general.rax, self.context.registers.general.rbx, self.context.registers.general.rcx, self.context.registers.general.rdx, self.context.registers.general.rsi, self.context.registers.general.rdi, self.context.registers.general.rbp, self.context.registers.general.r8, self.context.registers.general.r9);
                                    }
                                    error
                                })?.try_into().unwrap(),
                            ),
                        }
                    };
                    let result = destination ^ source;
                    if mod_ == 0xc0 {
                        let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        if opsz16 {
                            *self.reg_mut(dst) = (*self.reg(dst) & !0xffff) | (result & 0xffff);
                        } else if rex & 0x08 != 0 {
                            *self.reg_mut(dst) = result;
                        } else {
                            *self.reg_mut(dst) = result as u32 as u64;
                        }
                    } else {
                        let addr = memory_addr.expect("0x31 内存地址已解析");
                        let result_bytes = result.to_le_bytes();
                        self.context.memory.write(addr, &result_bytes[..width])?;
                    }
                    self.context.registers.general.rflags = update_flags_logic(result, width as u8);
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x88 | 0x8a => {
                    // mov r8, r/m8 (0x8a) 或 mov r/m8, r8 (0x88)
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x8a/0x88 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let is_store = op == 0x88;
                    if mod_ == 0xc0 {
                        if is_store {
                            let src_val = self.rd8((m >> 3) & 7, rex, true);
                            self.wr8(rm, rex, false, src_val);
                        } else {
                            let src_val = self.rd8(rm, rex, false);
                            self.wr8((m >> 3) & 7, rex, true, src_val);
                        }
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x8a/0x88 需要内存地址".into()))?;
                        if is_store {
                            let val = self.rd8((m >> 3) & 7, rex, true);
                            self.context.memory.write(addr, &[val])?;
                        } else {
                            let raw = self.context.memory.read(addr, 1)?[0];
                            self.wr8((m >> 3) & 7, rex, true, raw);
                        }
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x8b => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x8b 指令截断".into()))?;
                    p += 1;
                    let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    if mod_ == 0xc0 {
                        let value = *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 });
                        *self.reg_mut(dst) = if opsz16 {
                            (*self.reg(dst) & !0xffff) | (value & 0xffff)
                        } else if rex & 0x08 != 0 {
                            value
                        } else {
                            value as u32 as u64
                        };
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x8b 需要内存地址".into()))?;
                        if std::env::var_os("DAOTI_TRACE_FS_8B").is_some()
                            && (rip.wrapping_sub(0x6e3d000) == 0xa509d
                                || rip.wrapping_sub(0x6e3d000) == 0xa50a4)
                        {
                            eprintln!(
                                "TRACE fs-8b rip=0x{rip:x} bytes={bytes:02x?} fs_override={} fs_base=0x{:x} addr=0x{addr:x} modrm=0x{m:02x} p={p}",
                                self.fs_override,
                                self.fs_base,
                            );
                        }
                        // 注意 resolve_dst 已应用 seg_addr
                        let width = if opsz16 {
                            2
                        } else if rex & 0x08 != 0 {
                            8
                        } else {
                            4
                        };
                        if trace_dlmain_active {
                            eprintln!("TRACE dl_main-memory-read step={} rip=0x{rip:x} addr=0x{addr:x} width={width}", trace_dlmain_steps);
                        }
                        if rip == 0x270abf3
                            && std::env::var_os("DAOTI_TRACE_LNEXT_SOURCE").is_some()
                        {
                            let g = &self.context.registers.general;
                            eprintln!(
                                "TRACE lnext-source-failure rip=0x{rip:x} bytes={bytes:02x?} addr=0x{addr:x} base_rax=0x{:x} dst_reg={} modrm=0x{m:02x}",
                                g.rax, dst
                            );
                            for (history_rip, history_bytes, history_regs) in
                                instruction_history.iter().rev().take(10).rev()
                            {
                                eprintln!(
                                    "TRACE lnext-history RIP=0x{history_rip:x} BYTES={history_bytes:02x?} RAX=0x{:x} RBX=0x{:x} RCX=0x{:x} RDX=0x{:x} RDI=0x{:x} RSI=0x{:x} RBP=0x{:x} RSP=0x{:x}",
                                    history_regs.rax,
                                    history_regs.rbx,
                                    history_regs.rcx,
                                    history_regs.rdx,
                                    history_regs.rdi,
                                    history_regs.rsi,
                                    history_regs.rbp,
                                    history_regs.rsp
                                );
                            }
                            eprintln!(
                                "TRACE lnext-source-values rax=0x{:x} rax_plus_0x18={:?} rbx_plus_0x18={:?} rcx_plus_0x18={:?} rdx_plus_0x18={:?} rbp_plus_0x18={:?}",
                                g.rax,
                                self.context.memory.read(g.rax.wrapping_add(0x18), 8).ok(),
                                self.context.memory.read(g.rbx.wrapping_add(0x18), 8).ok(),
                                self.context.memory.read(g.rcx.wrapping_add(0x18), 8).ok(),
                                self.context.memory.read(g.rdx.wrapping_add(0x18), 8).ok(),
                                self.context.memory.read(g.rbp.wrapping_add(0x18), 8).ok()
                            );
                        }
                        let value = match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(addr, 2).map_err(|error| {
                                    if std::env::var_os("DAOTI_TRACE_ERRORS").is_some() {
                                        eprintln!("TRACE 0x8b rip=0x{rip:x} bytes={bytes:02x?} addr=0x{addr:x} width={width} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x}: {error}", self.context.registers.general.rax, self.context.registers.general.rbx, self.context.registers.general.rcx, self.context.registers.general.rdx, self.context.registers.general.rsi, self.context.registers.general.rdi, self.context.registers.general.rbp, self.context.registers.general.rsp);
                                    }
                                    error
                                })?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(addr, 4).map_err(|error| {
                                    if std::env::var_os("DAOTI_TRACE_ERRORS").is_some() {
                                        eprintln!("TRACE 0x8b rip=0x{rip:x} bytes={bytes:02x?} addr=0x{addr:x} width={width} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x}: {error}", self.context.registers.general.rax, self.context.registers.general.rbx, self.context.registers.general.rcx, self.context.registers.general.rdx, self.context.registers.general.rsi, self.context.registers.general.rdi, self.context.registers.general.rbp, self.context.registers.general.rsp);
                                    }
                                    error
                                })?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(addr, 8).map_err(|error| {
                                    if std::env::var_os("DAOTI_TRACE_ERRORS").is_some() {
                                        eprintln!("TRACE 0x8b rip=0x{rip:x} bytes={bytes:02x?} addr=0x{addr:x} width={width} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x} rsi=0x{:x} rdi=0x{:x} rbp=0x{:x} rsp=0x{:x}: {error}", self.context.registers.general.rax, self.context.registers.general.rbx, self.context.registers.general.rcx, self.context.registers.general.rdx, self.context.registers.general.rsi, self.context.registers.general.rdi, self.context.registers.general.rbp, self.context.registers.general.rsp);
                                    }
                                    error
                                })?.try_into().unwrap(),
                            ),
                        };
                        if opsz16 {
                            *self.reg_mut(dst) = (*self.reg(dst) & !0xffff) | (value & 0xffff);
                        } else {
                            *self.reg_mut(dst) = value;
                        }
                        if trace_dlmain_active && dst == 7 {
                            eprintln!(
                                "TRACE rdi-load rip=0x{rip:x} opcode=0x8b source=0x{addr:x} width={width} value=0x{value:x}"
                            );
                        }
                        if self
                            .load_bias
                            .is_some_and(|base| (base + 0xd690..base + 0xd6f1).contains(&rip))
                            && std::env::var_os("DAOTI_TRACE_NAMESPACE").is_some()
                        {
                            eprintln!(
                                "TRACE name-match-load rip=0x{rip:x} source=0x{addr:x} width={width} dst={dst} value=0x{value:x} rbx=0x{:x} rsi=0x{:x}",
                                self.context.registers.general.rbx,
                                self.context.registers.general.rsi,
                            );
                        }
                        if trace_dlmain_active && dst == 12 {
                            eprintln!(
                                "TRACE r12-load rip=0x{rip:x} opcode=0x8b source=0x{addr:x} width={width} value=0x{value:x}"
                            );
                        }
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x87 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x87 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let reg_idx = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    if mod_ == 0xc0 {
                        let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        let a = *self.reg(dst);
                        let b = *self.reg(reg_idx);
                        *self.reg_mut(dst) = b;
                        *self.reg_mut(reg_idx) = a;
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x87 需要内存地址".into()))?;
                        let width = if opsz16 {
                            2
                        } else if rex & 0x08 != 0 {
                            8
                        } else {
                            4
                        };
                        let mem_val = match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(addr, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(addr, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(addr, 8)?.try_into().unwrap(),
                            ),
                        };
                        let reg_val = *self.reg(reg_idx);
                        let bytes = reg_val.to_le_bytes();
                        if std::env::var_os("DAOTI_TRACE_XCHG").is_some() && addr == self.fs_base {
                            eprintln!("TRACE xchg rip=0x{rip:x} addr=0x{addr:x} old=0x{mem_val:x} new=0x{reg_val:x} width={width}");
                        }
                        self.context.memory.write(addr, &bytes[..width])?;
                        *self.reg_mut(reg_idx) = mem_val;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x89 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x89 指令截断".into()))?;
                    p += 1;
                    let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let val = *self.reg(src);
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    if mod_ == 0xc0 {
                        let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                        if opsz16 {
                            *self.reg_mut(dst) = (*self.reg(dst) & !0xffff) | (val & 0xffff);
                        } else if rex & 0x08 != 0 {
                            *self.reg_mut(dst) = val;
                        } else {
                            *self.reg_mut(dst) = val as u32 as u64;
                        }
                    } else {
                        let (_reg, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                        let addr =
                            addr.ok_or_else(|| DaotiError::Other("0x89 需要内存地址".into()))?;
                        // resolve_dst 已应用 seg_addr
                        let bytes = val.to_le_bytes();
                        if trace_dlmain_active {
                            let rip_relative = (m & 0xc7) == 0x05;
                            let global_candidate = (0x2400000..0x2440000).contains(&addr);
                            let main_map_candidate = global_candidate && rip_relative;
                            eprintln!("TRACE dl_main-memory-write step={} rip=0x{rip:x} opcode=89 addr=0x{addr:x} width={width} value=0x{:x} rip_relative={} global_candidate={} main_map_candidate={}", trace_dlmain_steps, val, rip_relative, global_candidate, main_map_candidate);
                            if global_candidate {
                                if let Some(frame) = dlmain_calls.last_mut() {
                                    frame.3 = true;
                                }
                            }
                        }
                        self.context.memory.write(addr, &bytes[..width])?;
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x81 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x81 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let ext_op = (m >> 3) & 7;
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let immediate_len = if opsz16 { 2 } else { 4 };
                    if p + immediate_len > bytes.len() {
                        return Err(DaotiError::Other("0x81 立即数截断".into()));
                    }
                    let imm = if opsz16 {
                        u16::from_le_bytes(bytes[p..p + 2].try_into().unwrap()) as u64
                    } else if width == 8 {
                        i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as i64 as u64
                    } else {
                        u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as u64
                    };
                    p += immediate_len;
                    let orig = match dst_addr {
                        Some(a) => match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(a, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(a, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                        },
                        None => {
                            let raw = *self.reg(dst_reg);
                            match width {
                                2 => raw & 0xffff,
                                4 => raw & 0xffff_ffff,
                                _ => raw,
                            }
                        }
                    };

                    let carry = u64::from(self.context.registers.general.rflags & 1 != 0);
                    let result = match ext_op {
                        0 => orig.wrapping_add(imm),
                        1 => orig | imm,
                        2 => orig.wrapping_add(imm).wrapping_add(carry),
                        3 => orig.wrapping_sub(imm).wrapping_sub(carry),
                        4 => orig & imm,
                        5 => orig.wrapping_sub(imm),
                        6 => orig ^ imm,
                        7 => orig.wrapping_sub(imm),
                        _ => unreachable!(),
                    };
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let width64 = width == 8;
                    if ext_op != 7 {
                        match dst_addr {
                            Some(a) => {
                                let bytes = result.to_le_bytes();
                                self.context.memory.write(a, &bytes[..width as usize])?;
                            }
                            None => {
                                *self.reg_mut(dst_reg) = if width64 {
                                    result
                                } else {
                                    result as u32 as u64
                                };
                            }
                        }
                    }
                    self.context.registers.general.rflags = update_flags_arith_width(
                        result,
                        orig,
                        imm,
                        ext_op == 5 || ext_op == 7,
                        width,
                    );
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x80 => {
                    // Grp1 r/m8, imm8
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x80 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let ext_op = (m >> 3) & 7;
                    let (_dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let dst_addr = dst_addr.map(|addr| {
                        if mod_ == 0 && rm == 5 {
                            addr.wrapping_add(1)
                        } else {
                            addr
                        }
                    });
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("0x80 imm8 截断".into()));
                    }
                    let imm = bytes[p] as u8;
                    p += 1;
                    if mod_ == 0xc0 {
                        let orig = self.rd8(rm, rex, false);
                        let result = match ext_op {
                            0 => orig.wrapping_add(imm),
                            4 => orig & imm,
                            5 | 7 => orig.wrapping_sub(imm),
                            6 => orig ^ imm,
                            1 => orig | imm,
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0x80 不支持的扩展操作：/{}",
                                    ext_op
                                )))
                            }
                        };
                        if ext_op != 7 {
                            self.wr8(rm, rex, false, result);
                        }
                        self.context.registers.general.rflags = update_flags_arith_width(
                            result as u64,
                            orig as u64,
                            imm as u64,
                            ext_op == 5 || ext_op == 7,
                            1,
                        );
                    } else {
                        let addr = dst_addr
                            .ok_or_else(|| DaotiError::Other("0x80 需要内存地址".into()))?;
                        let orig = self.context.memory.read(addr, 1)?[0];
                        let result = match ext_op {
                            0 => orig.wrapping_add(imm),
                            4 => orig & imm,
                            5 | 7 => orig.wrapping_sub(imm),
                            6 => orig ^ imm,
                            1 => orig | imm,
                            2 => orig.wrapping_add(imm),
                            _ => {
                                return Err(DaotiError::Other(format!(
                                    "0x80 不支持的扩展操作：/{}",
                                    ext_op
                                )))
                            }
                        };
                        if ext_op != 7 {
                            self.context.memory.write(addr, &[result])?;
                        }
                        self.context.registers.general.rflags = update_flags_arith_width(
                            result as u64,
                            orig as u64,
                            imm as u64,
                            ext_op == 5 || ext_op == 7,
                            1,
                        );
                    }
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0x83 => {
                    let m = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x83 指令截断".into()))?;
                    p += 1;
                    let mod_ = m & 0xc0;
                    let rm = m & 7;
                    let (dst_reg, dst_addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                    let ext_op = (m >> 3) & 7;
                    let dst_addr = dst_addr.map(|addr| {
                        if mod_ == 0 && rm == 5 {
                            addr.wrapping_add(1)
                        } else {
                            addr
                        }
                    });
                    if p + 1 > bytes.len() {
                        return Err(DaotiError::Other("0x83 imm8 截断".into()));
                    }
                    let imm = bytes[p] as i8 as i64 as u64;
                    p += 1;
                    let width = if opsz16 {
                        2
                    } else if rex & 0x08 != 0 {
                        8
                    } else {
                        4
                    };
                    let width64 = width == 8;
                    let orig = match dst_addr {
                        Some(a) => match width {
                            2 => u16::from_le_bytes(
                                self.context.memory.read(a, 2)?.try_into().unwrap(),
                            ) as u64,
                            4 => u32::from_le_bytes(
                                self.context.memory.read(a, 4)?.try_into().unwrap(),
                            ) as u64,
                            _ => u64::from_le_bytes(
                                self.context.memory.read(a, 8)?.try_into().unwrap(),
                            ),
                        },
                        None => {
                            let value = *self.reg(dst_reg);
                            match width {
                                2 => value & 0xffff,
                                4 => value & 0xffff_ffff,
                                _ => value,
                            }
                        }
                    };
                    let carry = u64::from(self.context.registers.general.rflags & 1 != 0);
                    let result = match ext_op {
                        0 => orig.wrapping_add(imm),
                        1 => orig.wrapping_add(imm).wrapping_add(carry),
                        4 => orig & imm,
                        5 => orig.wrapping_sub(imm),
                        6 => orig ^ imm,
                        7 => orig.wrapping_sub(imm),
                        3 => orig.wrapping_sub(imm).wrapping_sub(carry),
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "不支持的 0x83 扩展操作：/{}",
                                ext_op
                            )))
                        }
                    };
                    if ext_op != 7 {
                        match dst_addr {
                            Some(a) => {
                                let bytes = result.to_le_bytes();
                                self.context.memory.write(a, &bytes[..width as usize])?;
                            }
                            None => {
                                *self.reg_mut(dst_reg) = if width64 {
                                    result
                                } else {
                                    result as u32 as u64
                                };
                            }
                        }
                    }
                    self.context.registers.general.rflags = update_flags_arith_width(
                        result,
                        orig,
                        imm,
                        ext_op == 5 || ext_op == 7,
                        if width64 { 8 } else { 4 },
                    );
                    self.context.registers.general.rip = rip + p as u64;
                    continue;
                }
                0xe8 => {
                    if p + 4 > bytes.len() {
                        return Err(DaotiError::Other("call rel32 指令截断".into()));
                    }
                    let rel = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                    p += 4;
                    let return_rip = rip + p as u64;
                    let rsp = self.context.registers.general.rsp;
                    let new_rsp = rsp
                        .checked_sub(8)
                        .ok_or_else(|| DaotiError::Other("call 栈下溢".into()))?;
                    self.context
                        .memory
                        .write(new_rsp, &return_rip.to_le_bytes())?;
                    self.context.registers.general.rsp = new_rsp;
                    let target = (return_rip as i64 + rel as i64) as u64;
                    if self
                        .breakpoints
                        .iter()
                        .any(|bp| bp.name == "_dl_new_object" && bp.addr == target)
                    {
                        link_map_calls.push((target, return_rip, rip));
                        if std::env::var_os("DAOTI_TRACE_NEW_OBJECT_CALL").is_some() {
                            eprintln!("TRACE new-object-call kind=rel32 from=0x{rip:x} target=0x{target:x} return=0x{return_rip:x}");
                        }
                    }
                    if trace_dlmain_active {
                        let prologue = self.context.memory.read(target, 16).ok();
                        let g = &self.context.registers.general;
                        if let Some(ref mut file) = dlmain_trace {
                            use std::io::Write;
                            let _ = writeln!(file, "DLMAIN_CALL kind=rel32 from=0x{rip:016x} target=0x{target:016x} return=0x{return_rip:016x} rdi=0x{:x} rsi=0x{:x} rdx=0x{:x} rcx=0x{:x} prologue={prologue:02x?}", g.rdi, g.rsi, g.rdx, g.rcx);
                        }
                        dlmain_calls.push((rip, target, return_rip, false));
                    }
                    if call_chain_trace {
                        eprintln!(
                            "TRACE CALL from=0x{rip:x} target=0x{target:x} return=0x{return_rip:x}"
                        );
                        call_chain_frames.push((rip, target, return_rip));
                    }
                    if call_chain_active {
                        if let Some(ref mut file) = dlmain_trace {
                            use std::io::Write;
                            let g = &self.context.registers.general;
                            let _ = writeln!(
                            file,
                            "CALL_REL32 from=0x{rip:016x} next=0x{return_rip:016x} rel={rel} target=0x{target:016x} rdi=0x{:016x} rsi=0x{:016x} rdx=0x{:016x} rcx=0x{:016x} r8=0x{:016x} r9=0x{:016x}",
                            g.rdi, g.rsi, g.rdx, g.rcx, g.r8, g.r9
                        );
                            if target >= 0x241b770 {
                                let _ = writeln!(
                                file,
                                "CANDIDATE_ENTRY target=0x{target:016x} args=[0x{:016x},0x{:016x},0x{:016x},0x{:016x}]",
                                g.rdi, g.rsi, g.rdx, g.rcx
                            );
                                if target != 0x241b770
                                    && !self.breakpoints.iter().any(|bp| bp.addr == target)
                                {
                                    self.breakpoints.push(RuntimeBreakpoint {
                                        name: "call_chain_candidate".into(),
                                        addr: target,
                                    });
                                    let _ =
                                        writeln!(file, "AUTO_BREAKPOINT target=0x{target:016x}");
                                }
                            }
                        }
                    }
                    self.context.registers.general.rip = target;
                    continue;
                }
                0x0f => {
                    let op2 = *bytes
                        .get(p)
                        .ok_or_else(|| DaotiError::Other("0x0f 指令截断".into()))?;
                    p += 1;
                    match op2 {
                        0x1e => {
                            let modrm = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("endbr64 指令截断".into()))?;
                            p += 1;
                            if modrm != 0xfa {
                                return Err(DaotiError::Other("不支持的 0x0f 0x1e 扩展".into()));
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0x31 => {
                            // RDTSC：返回 0（不依赖真实时间戳）
                            self.context.registers.general.rax = 0;
                            self.context.registers.general.rdx = 0;
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xa2 => {
                            // CPUID：提供 glibc CPU 特性探测所需的稳定 x86-64 能力集。
                            let leaf = self.context.registers.general.rax as u32;
                            let subleaf = self.context.registers.general.rcx as u32;
                            let (eax, ebx, ecx, edx): (u32, u32, u32, u32) = match leaf {
                                0 => (1, 0x756e_6547, 0x6c65_746e, 0x4965_6e69),
                                1 => (0x0003_06a9, 0x0000_0000, 0x0000_0000, 0x178b_fbff),
                                7 if subleaf == 0 => (0, 0, 0, 0),
                                0x8000_0000 => (0x8000_0001, 0, 0, 0),
                                0x8000_0001 => (0, 0, 0x0000_0100, 0x2c10_0800),
                                _ => (0, 0, 0, 0),
                            };
                            self.context.registers.general.rax = eax as u64;
                            self.context.registers.general.rbx = ebx as u64;
                            self.context.registers.general.rcx = ecx as u64;
                            self.context.registers.general.rdx = edx as u64;
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0x05 => {
                            let nr = self.context.registers.general.rax;
                            let args = [
                                self.context.registers.general.rdi,
                                self.context.registers.general.rsi,
                                self.context.registers.general.rdx,
                                self.context.registers.general.r10,
                                self.context.registers.general.r8,
                                self.context.registers.general.r9,
                            ];
                            const SYS_RAISE: u64 = 117;
                            const SYS_TKILL: u64 = 200;
                            const SYS_TGKILL: u64 = 234;
                            if std::env::var_os("DAOTI_TRACE_ABORT").is_some()
                                && (nr == SYS_RAISE || nr == SYS_TKILL || nr == SYS_TGKILL)
                            {
                                let rsp = self.context.registers.general.rsp;
                                let ret_addr = if rsp >= 0x400000 {
                                    self.context
                                        .memory
                                        .read(rsp, 8)
                                        .ok()
                                        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                                } else {
                                    None
                                };
                                eprintln!("TRACE abort-sig nr={nr} rip=0x{rip:x} args={:x?} rsp=0x{rsp:x} ret=0x{:x}",
                                    args, ret_addr.unwrap_or(0));
                            }
                            if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                                eprintln!("TRACE syscall nr={nr} args={args:x?} rip=0x{rip:x}");
                            }
                            let name = match nr {
                                21 => "access",
                                89 => "readlink",
                                257 => "openat",
                                262 => "newfstatat",
                                _ => "syscall",
                            };
                            let event = RuntimeSyscallEvent::enter(nr, name, args);
                            // x86-64 syscall 硬件语义：进入时 rcx = 返回地址、
                            // r11 = 旧 rflags。glibc 的 __libc_early_init 依赖
                            // syscall 后 r11 非 0（rflags 残留）来使能 brk 路径，
                            // 缺失该语义会把标志写成 0，导致 "malloc(): corrupted
                            // top size"。
                            let saved_rflags = self.context.registers.general.rflags;
                            let syscall_return_rip = rip + p as u64;
                            let ret = if let Some(handler) = self.syscall_handler.as_mut() {
                                if std::env::var_os("DAOTI_TRACE_INSN_HISTORY").is_some() {
                                    handler.diagnose_instruction_history(
                                        &instruction_history.iter().cloned().collect::<Vec<_>>(),
                                    );
                                }
                                handler.diagnose_syscall_context(
                                    &self.context.registers.general,
                                    &self.context.memory,
                                );
                                handler.handle_with_memory(&event, &mut self.context.memory)?
                            } else {
                                return Err(DaotiError::Unavailable(format!(
                                    "无 syscall 处理器：nr={nr}"
                                )));
                            };
                            self.context.registers.general.rax = ret as u64;
                            // fd-mmap 的 ELF 副本才是 ld.so 后续实际执行的 libc 实例。
                            // mmap 返回值就是该副本的 load bias，按此地址动态补入早期初始化探针。
                            if nr == 9
                                && std::env::var_os("DAOTI_TRACE_EARLY_INIT").is_some()
                                && ret > 0
                                && event.args[4] != u64::MAX
                                && event.args[4] != u32::MAX as u64
                                && event.args[5] == 0
                            {
                                let base = ret as u64;
                                for (name, offset) in [
                                    ("__libc_early_init", 0x175ba0u64),
                                    ("gen:early_init_w", 0x175bcfu64),
                                    ("gen:early_init_div", 0x175c29u64),
                                    ("gen:early_init_malloc_init", 0x974a0u64),
                                    ("gen:sbrk", 0x11a8a0u64),
                                    ("gen:sbrk_flag_test", 0x11a8a6u64),
                                    ("gen:sbrk_curbrk_load", 0x11a8b9u64),
                                    ("gen:sbrk_positive_branch", 0x11a8f4u64),
                                    ("gen:sbrk_after_flag_branch", 0x11a8e0u64),
                                    ("gen:sbrk_after_curbrk_load", 0x11a8bfu64),
                                    ("gen:sbrk_add", 0x11a8fbu64),
                                    ("gen:sbrk_jae", 0x11a901u64),
                                    ("gen:sbrk_before_brk", 0x11a92fu64),
                                    ("gen:sbrk_after_brk", 0x11a934u64),
                                    ("gen:sbrk", 0x11a860u64),
                                    ("gen:brk", 0x11a860u64),
                                    ("gen:malloc_tls_read", 0xa509du64),
                                    ("gen:malloc_arena", 0xa50d5u64),
                                    ("gen:malloc_tls_null", 0xa50a4u64),
                                    ("gen:int_malloc_corrupted", 0xa46a6u64),
                                    ("gen:sysmalloc", 0x9f8a0u64),
                                    ("gen:__sbrk", 0x11a8a0u64),
                                    ("gen:__brk", 0x11a860u64),
                                ] {
                                    let addr = base + offset;
                                    if !self.breakpoints.iter().any(|bp| bp.addr == addr) {
                                        // brk 使能标志（__sbrk 入口 cmp byte [libc+0x228E4E],0）
                                        // 与 early_init_w 的写目标同一地址；sbrk_flag_test 命中
                                        // 时读该字节确认标志实际值（0=走 ENOMEM 快路径，1=走 add/jae）。
                                        let name = match name {
                                            "gen:early_init_w" | "gen:sbrk_flag_test" => {
                                                format!("{name} watch=0x{:x}", base + 0x228e4e)
                                            }
                                            _ => name.to_string(),
                                        };
                                        self.breakpoints.push(RuntimeBreakpoint { name, addr });
                                        eprintln!(
                                            "TRACE dynamic-file-mmap-early-init base=0x{base:x} addr=0x{addr:x}"
                                        );
                                    }
                                }
                            }
                            // 补全 syscall 的 rcx/r11 内核语义（见上方 saved_rflags 注释）
                            self.context.registers.general.rcx = syscall_return_rip;
                            self.context.registers.general.r11 = saved_rflags;
                            self.context.registers.general.rip = rip + p as u64;
                            if nr == 12 && trace_insn_enabled {
                                trace_after_brk = 10_000;
                                if let Some(file) = trace_insn_log.as_mut() {
                                    use std::io::Write;
                                    let _ = writeln!(file, "BRK_RETURN STEP={steps} RIP=0x{:016x} NEXT_RIP=0x{:016x} RET=0x{:x}", rip, self.context.registers.general.rip, ret as u64);
                                }
                            }
                            if let Some(handler) = self.syscall_handler.as_mut() {
                                if let Some(base) = handler.fs_base() {
                                    self.fs_base = base;
                                    self.context.tls_base = base;
                                    if std::env::var_os("DAOTI_TRACE_SYSCALLS").is_some() {
                                        eprintln!("TRACE fs_base=0x{base:x}");
                                    }
                                }
                                if let Some(code) = handler.exit_code() {
                                    self.context.state = ExecutionState::Exited(code);
                                    return Ok(self.context.state);
                                }
                            }
                            continue;
                        }
                        0x1f => {
                            let m = *bytes.get(p).ok_or_else(|| {
                                DaotiError::Other("多字节 NOP ModR/M 截断".into())
                            })?;
                            p += 1;
                            let mod_ = m >> 6;
                            let rm = m & 7;
                            if mod_ != 3 {
                                if rm == 4 {
                                    let _sib = *bytes.get(p).ok_or_else(|| {
                                        DaotiError::Other("多字节 NOP SIB 截断".into())
                                    })?;
                                    p += 1;
                                    if mod_ == 0 && _sib & 7 == 5 {
                                        p += 4;
                                    } else if mod_ == 1 {
                                        p += 1;
                                    } else if mod_ == 2 {
                                        p += 4;
                                    }
                                } else if mod_ == 0 && rm == 5 {
                                    p += 4;
                                } else if mod_ == 1 {
                                    p += 1;
                                } else if mod_ == 2 {
                                    p += 4;
                                }
                            }
                            if p > bytes.len() {
                                return Err(DaotiError::Other("多字节 NOP 指令截断".into()));
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0x90..=0x9f => {
                            // setcc r/m8
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("setcc ModR/M 截断".into()))?;
                            p += 1;
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let val = if parse_jcc(op2, self.context.registers.general.rflags) {
                                1u8
                            } else {
                                0u8
                            };
                            if mod_ == 0xc0 {
                                if rex == 0 && (4..=7).contains(&rm) {
                                    let dst = (rm - 4) as usize;
                                    let shift = 8;
                                    let mask = 0xffu64 << shift;
                                    *self.reg_mut(dst) =
                                        (*self.reg(dst) & !mask) | ((val as u64) << shift);
                                } else {
                                    let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                                    *self.reg_mut(dst) = (*self.reg(dst) & !0xff) | val as u64;
                                }
                            } else {
                                let (_reg, addr) =
                                    self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                let addr = addr.ok_or_else(|| {
                                    DaotiError::Other("setcc 需要内存地址".into())
                                })?;
                                self.context.memory.write(addr, &[val])?;
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        // 条件移动（cmovcc r64, r/m64）
                        0x40..=0x46 | 0x48..=0x4f => {
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("cmov ModR/M 截断".into()))?;
                            p += 1;
                            let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let value = if mod_ == 0xc0 {
                                *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 })
                            } else {
                                let (_, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                let addr = addr
                                    .ok_or_else(|| DaotiError::Other("cmov 需要内存地址".into()))?;
                                u64::from_le_bytes(
                                    self.context.memory.read(addr, 8)?.try_into().unwrap(),
                                )
                            };
                            if parse_jcc(op2, self.context.registers.general.rflags) {
                                *self.reg_mut(dst) = value;
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        // 近条件跳转（0f 82..0f 8f，rel32）
                        0x80..=0x8f => {
                            if p + 4 > bytes.len() {
                                return Err(DaotiError::Other("近条件跳转 rel32 截断".into()));
                            }
                            let rel = i32::from_le_bytes(bytes[p..p + 4].try_into().unwrap());
                            p += 4;
                            if parse_jcc(op2, self.context.registers.general.rflags) {
                                self.context.registers.general.rip =
                                    ((rip + p as u64) as i64 + rel as i64) as u64;
                            } else {
                                self.context.registers.general.rip = rip + p as u64;
                            }
                            continue;
                        }
                        0x47 => {
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("cmova ModR/M 截断".into()))?;
                            p += 1;
                            let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let value = if mod_ == 0xc0 {
                                *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 })
                            } else {
                                let (_, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                u64::from_le_bytes(
                                    self.context
                                        .memory
                                        .read(
                                            addr.ok_or_else(|| {
                                                DaotiError::Other("cmova 需要内存地址".into())
                                            })?,
                                            8,
                                        )?
                                        .try_into()
                                        .unwrap(),
                                )
                            };
                            if self.context.registers.general.rflags & 0x1 == 0 {
                                *self.reg_mut(dst) = value;
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xaf => {
                            // imul r16/r32/r64, r/m16/r/m32/r/m64
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("imul ModR/M 截断".into()))?;
                            p += 1;
                            let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let width = if opsz16 {
                                2
                            } else if rex & 0x08 != 0 {
                                8
                            } else {
                                4
                            };
                            let mask = match width {
                                2 => 0xffff,
                                4 => 0xffff_ffff,
                                _ => u64::MAX,
                            };
                            let source = if mod_ == 0xc0 {
                                *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 }) & mask
                            } else {
                                let (_reg, addr) =
                                    self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                let addr = addr
                                    .ok_or_else(|| DaotiError::Other("imul 需要内存地址".into()))?;
                                let raw = self.context.memory.read(addr, width as u64)?;
                                match width {
                                    2 => u16::from_le_bytes(raw.try_into().unwrap()) as u64,
                                    4 => u32::from_le_bytes(raw.try_into().unwrap()) as u64,
                                    _ => u64::from_le_bytes(raw.try_into().unwrap()),
                                }
                            };
                            let lhs = *self.reg(dst) & mask;
                            let result = lhs.wrapping_mul(source) & mask;
                            if width == 2 {
                                *self.reg_mut(dst) = (*self.reg(dst) & !0xffff) | result;
                            } else if width == 4 {
                                *self.reg_mut(dst) = result as u32 as u64;
                            } else {
                                *self.reg_mut(dst) = result;
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xb1 => {
                            // cmpxchg r/m16/r/m32/r/m64, r16/r32/r64
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("cmpxchg ModR/M 截断".into()))?;
                            p += 1;
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let src = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let width = if opsz16 {
                                2
                            } else if rex & 0x08 != 0 {
                                8
                            } else {
                                4
                            };
                            let mask = match width {
                                2 => 0xffff,
                                4 => 0xffff_ffff,
                                _ => u64::MAX,
                            };
                            let acc = *self.reg(0) & mask;
                            let source = *self.reg(src) & mask;
                            let mut memory_addr = None;
                            let old = if mod_ == 0xc0 {
                                let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                                *self.reg(dst) & mask
                            } else {
                                let (_reg, addr) =
                                    self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                let addr = addr.ok_or_else(|| {
                                    DaotiError::Other("cmpxchg 需要内存地址".into())
                                })?;
                                memory_addr = Some(addr);
                                let raw = self.context.memory.read(addr, width as u64)?;
                                match width {
                                    2 => u16::from_le_bytes(raw.try_into().unwrap()) as u64,
                                    4 => u32::from_le_bytes(raw.try_into().unwrap()) as u64,
                                    _ => u64::from_le_bytes(raw.try_into().unwrap()),
                                }
                            };
                            let equal = old == acc;
                            self.context.registers.general.rflags = update_flags_arith_width(
                                old.wrapping_sub(acc),
                                old,
                                acc,
                                true,
                                width,
                            );
                            if equal {
                                if mod_ == 0xc0 {
                                    let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                                    if width == 2 {
                                        *self.reg_mut(dst) = (*self.reg(dst) & !0xffff) | source;
                                    } else if width == 4 {
                                        *self.reg_mut(dst) = source as u32 as u64;
                                    } else {
                                        *self.reg_mut(dst) = source;
                                    }
                                } else {
                                    let addr = memory_addr.expect("cmpxchg 内存地址已解析");
                                    self.context
                                        .memory
                                        .write(addr, &source.to_le_bytes()[..width as usize])?;
                                }
                                self.context.registers.general.rflags |= 0x40;
                            } else if width == 2 {
                                *self.reg_mut(0) = (*self.reg(0) & !0xffff) | old;
                            } else if width == 4 {
                                *self.reg_mut(0) = old as u32 as u64;
                            } else {
                                *self.reg_mut(0) = old;
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xb6 | 0xb7 | 0xbe => {
                            // movzx r64, r/m8/r/m16 或 movsx r64, r/m8
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("movzx ModR/M 截断".into()))?;
                            p += 1;
                            let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let value = if mod_ == 0xc0 {
                                let src = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                                if op2 == 0xb6 {
                                    (*self.reg(src) & 0xff) as u64
                                } else if op2 == 0xbe {
                                    (*self.reg(src) as u8 as i8) as i64 as u64
                                } else {
                                    (*self.reg(src) & 0xffff) as u64
                                }
                            } else {
                                let addr =
                                    self.resolve_sse_mem(mod_, rm, rex, &bytes, &mut p, rip)?;
                                if op2 == 0xb6 {
                                    let raw = self.context.memory.read(addr, 1)?;
                                    raw[0] as u64
                                } else if op2 == 0xbe {
                                    let raw = self.context.memory.read(addr, 1)?;
                                    (raw[0] as i8) as i64 as u64
                                } else {
                                    let raw = self.context.memory.read(addr, 2)?;
                                    u16::from_le_bytes(raw.try_into().unwrap()) as u64
                                }
                            };
                            *self.reg_mut(dst) = if op2 == 0xbe && rex & 0x08 == 0 {
                                value as i32 as u32 as u64
                            } else {
                                value
                            };
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xa3 => {
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("bt ModR/M 截断".into()))?;
                            p += 1;
                            // 位索引来自 ModR/M 的 reg 字段（Intel 语法 bt r/m, r，第二操作数为位索引）
                            let bit_reg =
                                ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let bit = *self.reg(bit_reg);
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            // 操作数宽度：REX.W=1 时 64 位（位索引模 64），否则 32 位（模 32）
                            let width_mask: u64 = if rex & 0x08 != 0 { 63 } else { 31 };
                            let bit_set = if mod_ == 0xc0 {
                                let source =
                                    *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 });
                                ((source >> (bit & width_mask)) & 1) != 0
                            } else {
                                let (_, base_addr) =
                                    self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                // 读取包含目标位所在的 8 字节对齐窗口
                                let address = base_addr
                                    .ok_or_else(|| DaotiError::Other("bt 需要内存地址".into()))?
                                    .wrapping_add((bit / 64).wrapping_mul(8));
                                let source = u64::from_le_bytes(
                                    self.context.memory.read(address, 8)?.try_into().unwrap(),
                                );
                                ((source >> (bit & 63)) & 1) != 0
                            };
                            if bit_set {
                                self.context.registers.general.rflags |= 1;
                            } else {
                                self.context.registers.general.rflags &= !1;
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xae => {
                            // 0F AE 组：fxsave/fxrstor/ldmxcsr/stmxcsr/xsave/xsaveopt/xrstor/clflush。
                            // glibc 用 stmxcsr/ldmxcsr 围绕 call 保存恢复 MXCSR；
                            // fxsave/xsave 系在无 x87/SSE 控制状态跟踪下按复位值填充。
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("0f ae ModR/M 截断".into()))?;
                            p += 1;
                            if m & 0xc0 == 0xc0 {
                                return Err(DaotiError::Other("0f ae 组要求内存操作数".into()));
                            }
                            let (_, addr) =
                                self.resolve_dst(m & 0xc0, m & 7, rex, &bytes, &mut p)?;
                            let addr = addr.ok_or_else(|| {
                                DaotiError::Other("0f ae 需要有效内存地址".into())
                            })?;
                            match (m >> 3) & 7 {
                                0 => {
                                    // fxsave：512 字节 x87+SSE 状态，按复位值填充
                                    let mut state = [0u8; 512];
                                    state[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
                                    state[16..20].copy_from_slice(&self.mxcsr.to_le_bytes());
                                    self.context.memory.write(addr, &state)?;
                                }
                                1 => {
                                    // fxrstor：模拟器不跟踪 x87/SSE 控制状态，读出忽略
                                    let _ = self.context.memory.read(addr, 32);
                                }
                                2 => {
                                    // ldmxcsr m32
                                    let raw = u32::from_le_bytes(
                                        self.context.memory.read(addr, 4)?.try_into().unwrap(),
                                    );
                                    self.mxcsr = raw;
                                }
                                3 => {
                                    // stmxcsr m32
                                    self.context.memory.write(addr, &self.mxcsr.to_le_bytes())?;
                                }
                                4 | 6 => {
                                    // xsave/xsaveopt：无扩展状态，写出基本控制区
                                    let mut state = [0u8; 576];
                                    state[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
                                    state[16..20].copy_from_slice(&self.mxcsr.to_le_bytes());
                                    self.context.memory.write(addr, &state)?;
                                }
                                5 => {
                                    // xrstor：忽略恢复
                                    let _ = self.context.memory.read(addr, 64);
                                }
                                7 => {
                                    // clflush：无副作用，仅推进 rip
                                }
                                _ => {
                                    return Err(DaotiError::Other(format!(
                                        "0f ae 不支持的组扩展：{}",
                                        (m >> 3) & 7
                                    )))
                                }
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xd7 => {
                            // pmovmskb r32, xmm
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("pmovmskb ModR/M 截断".into()))?;
                            p += 1;
                            if m & 0xc0 != 0xc0 {
                                return Err(DaotiError::Other("pmovmskb 不支持内存形式".into()));
                            }
                            let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let src = (m & 7) as usize | if rex & 1 != 0 { 8 } else { 0 };
                            let xmm = self.xmm[src].to_le_bytes();
                            let mut mask = 0u16;
                            for (i, byte) in xmm.iter().enumerate() {
                                if byte & 0x80 != 0 {
                                    mask |= 1 << i;
                                }
                            }
                            *self.reg_mut(dst) = mask as u64;
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        0xbc | 0xbd => {
                            // bsf/bsr r64, r/m64
                            let m = *bytes
                                .get(p)
                                .ok_or_else(|| DaotiError::Other("bsf/bsr ModR/M 截断".into()))?;
                            p += 1;
                            let dst = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
                            let mod_ = m & 0xc0;
                            let rm = m & 7;
                            let src_val = if mod_ == 0xc0 {
                                *self.reg(rm as usize | if rex & 1 != 0 { 8 } else { 0 })
                            } else {
                                let (_r, addr) = self.resolve_dst(mod_, rm, rex, &bytes, &mut p)?;
                                let addr = addr.ok_or_else(|| {
                                    DaotiError::Other("bsf/bsr 需要内存地址".into())
                                })?;
                                u64::from_le_bytes(
                                    self.context.memory.read(addr, 8)?.try_into().unwrap(),
                                )
                            };
                            if src_val == 0 {
                                self.context.registers.general.rflags |= 0x40; // ZF=1
                            } else {
                                self.context.registers.general.rflags &= !0x40; // ZF=0
                                *self.reg_mut(dst) = if op2 == 0xbc {
                                    src_val.trailing_zeros() as u64
                                } else {
                                    63 - src_val.leading_zeros() as u64
                                };
                            }
                            self.context.registers.general.rip = rip + p as u64;
                            continue;
                        }
                        // SSE 指令
                        0x10 | 0x11 | 0x12 | 0x16 | 0x28 | 0x29 | 0x57 | 0x58 | 0x59 | 0x60
                        | 0x61 | 0x62 | 0x6a | 0x6c | 0x6e | 0x6f | 0x70 | 0x76 | 0xdb | 0xd6
                        | 0xda | 0xeb | 0x7e | 0x73 | 0x7f | 0x74 | 0xef | 0xf8 | 0xc6 => {
                            let next_rip =
                                self.exec_sse(op2, opsz16, rep, rex, &bytes, &mut p, rip)?;
                            self.context.registers.general.rip = next_rip;
                            continue;
                        }
                        _ => {
                            return Err(DaotiError::Other(format!(
                                "不支持的 x86_64 指令：rip=0x{rip:x} 0x{op:02x} 0x{op2:02x}"
                            )))
                        }
                    }
                }
                _ => {
                    return Err(DaotiError::Other(format!(
                        "不支持的 x86_64 指令：rip=0x{rip:x} 0x{op:02x}"
                    )))
                }
            }
        }
    }

    /// 解析 `.rela.plt` 中的 IRELATIVE 重定位并运行解析器（IFUNC）。
    /// 对于静态 ET_EXEC，`resolver` 即 `addend` 的绝对地址。
    pub fn resolve_irelative_relocs(
        &mut self,
        data: &[u8],
        load_bias: u64,
    ) -> Result<(), DaotiError> {
        // 读取 ELF 节表，找到 `.rela.plt`
        if data.len() < 0x40 {
            return Ok(());
        }
        let e_shoff = u64::from_le_bytes(data[0x28..0x30].try_into().unwrap());
        let e_shentsize = u16::from_le_bytes(data[0x3a..0x3c].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(data[0x3c..0x3e].try_into().unwrap()) as usize;
        let shstr_idx = u16::from_le_bytes(data[0x3e..0x40].try_into().unwrap()) as usize;
        if e_shentsize < 0x40 || shstr_idx >= e_shnum {
            return Ok(());
        }
        let shstr_off = e_shoff + shstr_idx as u64 * e_shentsize as u64;
        let shstr_addr =
            u64::from_le_bytes(data[shstr_off as usize..][0x18..0x20].try_into().unwrap()) as usize;
        let shstr_table = data.get(shstr_addr..).unwrap_or(&[]);
        let str_name = |off: usize| -> String {
            let s = &shstr_table[off..];
            let end = s.iter().position(|&b| b == 0).unwrap_or(0);
            String::from_utf8_lossy(&s[..end]).into_owned()
        };
        let mut relocs: Vec<(u64, u64)> = Vec::new();
        for i in 0..e_shnum {
            let sh = (e_shoff + i as u64 * e_shentsize as u64) as usize;
            if sh + 0x40 > data.len() {
                continue;
            }
            let name_off = u32::from_le_bytes(data[sh..sh + 4].try_into().unwrap()) as usize;
            let name = str_name(name_off);
            if name != ".rela.plt" {
                continue;
            }
            let sh_offset = u64::from_le_bytes(data[sh + 0x18..sh + 0x20].try_into().unwrap());
            let sh_size = u64::from_le_bytes(data[sh + 0x20..sh + 0x28].try_into().unwrap());
            let sh_entsize = u64::from_le_bytes(data[sh + 0x38..sh + 0x40].try_into().unwrap());
            if sh_entsize == 0 {
                break;
            }
            let mut off = sh_offset as usize;
            let end = (sh_offset + sh_size) as usize;
            while off + 24 <= end && off + 24 <= data.len() {
                let r_offset = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
                let r_info = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
                let r_addend = i64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
                let r_type = (r_info & 0xffffffff) as u32;
                // R_X86_64_IRELATIVE = 37
                if r_type == 37 {
                    let resolver = if load_bias == 0 {
                        r_addend as u64
                    } else {
                        load_bias.checked_add_signed(r_addend).ok_or_else(|| {
                            DaotiError::Other("IRELATIVE resolver 地址溢出".into())
                        })?
                    };
                    let slot = load_bias
                        .checked_add(r_offset)
                        .ok_or_else(|| DaotiError::Other("IRELATIVE 槽位地址溢出".into()))?;
                    relocs.push((slot, resolver));
                }
                off += sh_entsize as usize;
            }
            break;
        }
        if relocs.is_empty() {
            return Ok(());
        }
        // 运行每个解析器，把返回值写入 GOT 槽位
        let entry_rip = self.context.registers.general.rip;
        let entry_rsp = self.context.registers.general.rsp;
        self.context.state = ExecutionState::Running;
        self.sentinel_mode = true;
        for (slot, resolver) in relocs {
            let saved_registers = self.context.registers.general;
            self.context.registers.general.rsp = entry_rsp;
            let rsp = self.context.registers.general.rsp;
            let new_rsp = rsp
                .checked_sub(8)
                .ok_or_else(|| DaotiError::Other("IFUNC 栈下溢".into()))?;
            self.context.memory.write(new_rsp, &0u64.to_le_bytes())?;
            self.context.registers.general.rsp = new_rsp;
            self.context.registers.general.rip = resolver;
            let result = self.run();
            let value = self.context.registers.general.rax;
            self.context.registers.general = saved_registers;
            result?;
            self.context.memory.write(slot, &value.to_le_bytes())?;
        }
        self.sentinel_mode = false;
        self.context.registers.general.rip = entry_rip;
        self.context.registers.general.rsp = entry_rsp;
        self.context.state = ExecutionState::NotStarted;
        Ok(())
    }

    /// 执行 SSE 指令（0f 10/11/28/29/57/58/59/6f/7f/ef）。
    #[allow(clippy::too_many_arguments)]
    fn exec_sse(
        &mut self,
        op2: u8,
        opsz16: bool,
        rep: u8,
        rex: u8,
        bytes: &[u8],
        p: &mut usize,
        rip: u64,
    ) -> Result<u64, DaotiError> {
        let m = *bytes
            .get(*p)
            .ok_or_else(|| DaotiError::Other("SSE 指令截断".into()))?;
        *p += 1;
        let reg_field = ((m >> 3) & 7) as usize | if rex & 4 != 0 { 8 } else { 0 };
        let mod_ = m >> 6;
        let rm = m & 7;
        // 将 mod_ 转为 0xc0/0x40/0x80/0x00 格式
        let mod_val = mod_ << 6;
        let () = match op2 {
            0x73 => {
                let count = *bytes
                    .get(*p)
                    .ok_or_else(|| DaotiError::Other("pslldq/psrldq 立即数截断".into()))?;
                *p += 1;
                if mod_ != 3 {
                    return Err(DaotiError::Other("pslldq/psrldq 暂不支持内存目标".into()));
                }
                let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                let value = self.xmm[dst].to_le_bytes();
                let mut result = [0u8; 16];
                let extension = m & 0x38;
                if extension == 0x38 {
                    if count < 16 {
                        result[count as usize..].copy_from_slice(&value[..16 - count as usize]);
                    }
                } else if extension == 0x18 {
                    if count < 16 {
                        result[..16 - count as usize].copy_from_slice(&value[count as usize..]);
                    }
                } else if extension == 0x30 || extension == 0x10 {
                    let mut lanes = [
                        u64::from_le_bytes(value[..8].try_into().unwrap()),
                        u64::from_le_bytes(value[8..].try_into().unwrap()),
                    ];
                    for lane in &mut lanes {
                        *lane = if count >= 64 {
                            0
                        } else if extension == 0x30 {
                            lane.wrapping_shl(count as u32)
                        } else {
                            lane.wrapping_shr(count as u32)
                        };
                    }
                    result[..8].copy_from_slice(&lanes[0].to_le_bytes());
                    result[8..].copy_from_slice(&lanes[1].to_le_bytes());
                } else {
                    return Err(DaotiError::Other("0x0f 0x73 不支持的扩展操作".into()));
                }
                self.xmm[dst] = u128::from_le_bytes(result);
            }
            0x62 => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("punpckldq 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }].to_le_bytes();
                let dst = self.xmm[reg_field].to_le_bytes();
                let mut value = [0u8; 16];
                for i in 0..2 {
                    value[i * 8..i * 8 + 4].copy_from_slice(&dst[i * 4..i * 4 + 4]);
                    value[i * 8 + 4..i * 8 + 8].copy_from_slice(&src[i * 4..i * 4 + 4]);
                }
                self.xmm[reg_field] = u128::from_le_bytes(value);
            }
            0x61 => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("punpcklwd 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }].to_le_bytes();
                let dst = self.xmm[reg_field].to_le_bytes();
                let mut value = [0u8; 16];
                for i in 0..4 {
                    value[i * 4..i * 4 + 2].copy_from_slice(&dst[i * 2..i * 2 + 2]);
                    value[i * 4 + 2..i * 4 + 4].copy_from_slice(&src[i * 2..i * 2 + 2]);
                }
                self.xmm[reg_field] = u128::from_le_bytes(value);
            }
            0x60 => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("punpcklbw 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }].to_le_bytes();
                let dst = self.xmm[reg_field].to_le_bytes();
                let mut value = [0u8; 16];
                for i in 0..8 {
                    value[i * 2] = dst[i];
                    value[i * 2 + 1] = src[i];
                }
                self.xmm[reg_field] = u128::from_le_bytes(value);
            }
            0xeb => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("por 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }];
                self.xmm[reg_field] |= src;
            }
            0x76 => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("pcmpeqd 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }];
                let dst = self.xmm[reg_field];
                self.xmm[reg_field] = if dst == src { u128::MAX } else { 0 };
            }
            0x6a => {
                let src = if mod_ == 3 {
                    self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }]
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    let raw = self.context.memory.read(addr, 16)?;
                    u128::from_le_bytes(raw.try_into().unwrap())
                };
                let mut dst_bytes = self.xmm[reg_field].to_le_bytes();
                let src_bytes = src.to_le_bytes();
                for index in 0..16 {
                    dst_bytes[index] = dst_bytes[index].min(src_bytes[index]);
                }
                self.xmm[reg_field] = u128::from_le_bytes(dst_bytes);
            }
            0x70 => {
                let imm = *bytes
                    .get(*p)
                    .ok_or_else(|| DaotiError::Other("pshufd immediate 截断".into()))?;
                *p += 1;
                if mod_ != 3 {
                    return Err(DaotiError::Other("pshufd 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }].to_le_bytes();
                let mut value = [0u8; 16];
                for i in 0..4 {
                    let lane = ((imm >> (i * 2)) & 3) as usize;
                    value[i * 4..i * 4 + 4].copy_from_slice(&src[lane * 4..lane * 4 + 4]);
                }
                self.xmm[reg_field] = u128::from_le_bytes(value);
            }
            0xc6 => {
                // SHUFPS (无前缀) / SHUFPD (66 前缀)。imm8 从目的/源两个 XMM
                // 中各选元素组合写回目的寄存器。元素宽度由 opsz16 决定。
                let opsz_64 = opsz16;
                let elem = if opsz_64 { 8usize } else { 4usize };
                let lanes = 16 / elem;
                let imm = *bytes
                    .get(*p)
                    .ok_or_else(|| DaotiError::Other("shufps immediate 截断".into()))?;
                *p += 1;
                let src = if mod_ == 3 {
                    self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }].to_le_bytes()
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    let raw = self.context.memory.read(addr, 16)?;
                    raw.try_into().unwrap()
                };
                let dst = self.xmm[reg_field].to_le_bytes();
                let mut value = [0u8; 16];
                if opsz_64 {
                    // SHUFPD：imm[0] 选目的元素，imm[1] 选源元素
                    let sel = [(imm & 1) as usize, ((imm >> 1) & 1) as usize];
                    value[0..8].copy_from_slice(&dst[sel[0] * 8..sel[0] * 8 + 8]);
                    value[8..16].copy_from_slice(&src[sel[1] * 8..sel[1] * 8 + 8]);
                } else {
                    // SHUFPS：imm bits[1:0]→结果[0]、[3:2]→[1]（都来自 dest），
                    // bits[5:4]→[2]、[7:6]→[3]（都来自 source）
                    for i in 0..lanes {
                        let lane = ((imm >> (i * 2)) & 3) as usize;
                        let from = if i < 2 { &dst } else { &src };
                        value[i * elem..i * elem + elem]
                            .copy_from_slice(&from[lane * elem..lane * elem + elem]);
                    }
                }
                self.xmm[reg_field] = u128::from_le_bytes(value);
            }
            0x6e => {
                // REX.W 优先决定 0f 6e 为 movq；无 REX.W 时按 movd 处理。
                let is_qword = rex & 0x08 != 0;
                let value = if mod_ == 3 {
                    let src = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                    if is_qword {
                        *self.reg(src)
                    } else {
                        *self.reg(src) & 0xffff_ffff
                    }
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    let size = if is_qword { 8 } else { 4 };
                    let raw = self.context.memory.read(addr, size)?;
                    if is_qword {
                        u64::from_le_bytes(raw.try_into().unwrap())
                    } else {
                        u32::from_le_bytes(raw.try_into().unwrap()) as u64
                    }
                };
                // MOVD/MOVQ 写入 XMM 时，整个寄存器先被清零；MOVQ 仅保留低 64 位。
                self.xmm[reg_field] = if is_qword {
                    value as u128
                } else {
                    (value as u32) as u128
                };
            }
            0x6c => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("punpcklqdq 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }];
                let dst_low = self.xmm[reg_field] as u64;
                let src_low = src as u64;
                self.xmm[reg_field] = (dst_low as u128) | ((src_low as u128) << 64);
            }
            0xdb => {
                if mod_ != 3 {
                    return Err(DaotiError::Other("pand 暂不支持内存源".into()));
                }
                let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }];
                self.xmm[reg_field] &= src;
            }
            0xda => {
                let src = if mod_ == 3 {
                    self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }]
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    let raw = self.context.memory.read(addr, 16)?;
                    u128::from_le_bytes(raw.try_into().unwrap())
                };
                let mut value = self.xmm[reg_field].to_le_bytes();
                let source = src.to_le_bytes();
                for lane in 0..16 {
                    value[lane] = value[lane].min(source[lane]);
                }
                self.xmm[reg_field] = u128::from_le_bytes(value);
            }
            0xd6 => {
                let value = self.xmm[reg_field].to_le_bytes();
                if mod_ == 3 {
                    let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                    *self.reg_mut(dst) = u64::from_le_bytes(value[0..8].try_into().unwrap());
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    self.context.memory.write(addr, &value[..8])?;
                }
            }
            0x7e => {
                let value = self.xmm[reg_field].to_le_bytes();
                // REX.W 或 F3 前缀表示 movq；否则为 movd。
                let is_qword = rex & 0x08 != 0 || rep == 0xf3;
                if mod_ == 3 {
                    let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                    *self.reg_mut(dst) = if is_qword {
                        u64::from_le_bytes(value[0..8].try_into().unwrap())
                    } else {
                        u32::from_le_bytes(value[0..4].try_into().unwrap()) as u64
                    };
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    let size = if is_qword { 8 } else { 4 };
                    self.context.memory.write(addr, &value[..size])?;
                }
            }
            0x10 | 0x12 | 0x16 | 0x28 | 0x6f | 0x57 | 0x58 | 0x59 | 0x74 | 0xef | 0xf8 => {
                // 加载/算术类：reg 字段是目标，rm 是源（reg 或内存）
                let pcmpeqb = |dst: u128, src: u128| -> u128 {
                    let mut result = [0u8; 16];
                    let d = dst.to_le_bytes();
                    let s = src.to_le_bytes();
                    for i in 0..16 {
                        result[i] = if d[i] == s[i] { 0xff } else { 0x00 };
                    }
                    u128::from_le_bytes(result)
                };
                if mod_ == 3 {
                    // 寄存器形式
                    let src = self.xmm[rm as usize | if rex & 1 != 0 { 8 } else { 0 }];
                    self.xmm[reg_field] = match op2 {
                        0x57 | 0xef => self.xmm[reg_field] ^ src,
                        0x58 | 0x59 => {
                            // 0f 58/59 是 addps/mulps；F3 前缀切换为只处理低位 lane 的 addss/mulss。
                            let dst = self.xmm[reg_field].to_le_bytes();
                            let src = src.to_le_bytes();
                            let lanes = if rep == 0xf3 { 1 } else { 4 };
                            let mut out = dst;
                            for lane in 0..lanes {
                                let a = f32::from_le_bytes(
                                    dst[lane * 4..lane * 4 + 4].try_into().unwrap(),
                                );
                                let b = f32::from_le_bytes(
                                    src[lane * 4..lane * 4 + 4].try_into().unwrap(),
                                );
                                let value = if op2 == 0x58 { a + b } else { a * b };
                                out[lane * 4..lane * 4 + 4].copy_from_slice(&value.to_le_bytes());
                            }
                            u128::from_le_bytes(out)
                        }
                        0x74 => pcmpeqb(self.xmm[reg_field], src),
                        0x7e => {
                            let value = self.xmm[reg_field].to_le_bytes();
                            let dst = reg_field;
                            *self.reg_mut(dst) =
                                u32::from_le_bytes(value[0..4].try_into().unwrap()) as u64;
                            self.xmm[reg_field]
                        }
                        0xf8 => {
                            // psubb：按 16 个无符号 8 位 lane 做模 256 减法。
                            let mut value = self.xmm[reg_field].to_le_bytes();
                            let source = src.to_le_bytes();
                            for lane in 0..16 {
                                value[lane] = value[lane].wrapping_sub(source[lane]);
                            }
                            u128::from_le_bytes(value)
                        }
                        0x16 => {
                            let mut value = self.xmm[reg_field].to_le_bytes();
                            let source = src.to_le_bytes();
                            value[8..16].copy_from_slice(&source[0..8]);
                            u128::from_le_bytes(value)
                        }
                        _ => src,
                    };
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    // movq 使用 F2，movdqu 使用 F3，二者都不能把 F3 误当成 4 字节 movd。
                    let size = if op2 == 0x6f && rep == 0xf3 {
                        16
                    } else if rep == 0xf2 {
                        8
                    } else {
                        16
                    };
                    let raw = self.context.memory.read(addr, size)?;
                    let mut buf = [0u8; 16];
                    buf[..size as usize].copy_from_slice(raw);
                    let src = u128::from_le_bytes(buf);
                    self.xmm[reg_field] = match op2 {
                        0x57 | 0xef => self.xmm[reg_field] ^ src,
                        0x58 | 0x59 => {
                            // 内存形式的 addps/mulps，以及 F3 前缀的 addss/mulss。
                            let dst = self.xmm[reg_field].to_le_bytes();
                            let src = src.to_le_bytes();
                            let lanes = if rep == 0xf3 { 1 } else { 4 };
                            let mut out = dst;
                            for lane in 0..lanes {
                                let a = f32::from_le_bytes(
                                    dst[lane * 4..lane * 4 + 4].try_into().unwrap(),
                                );
                                let b = f32::from_le_bytes(
                                    src[lane * 4..lane * 4 + 4].try_into().unwrap(),
                                );
                                let value = if op2 == 0x58 { a + b } else { a * b };
                                out[lane * 4..lane * 4 + 4].copy_from_slice(&value.to_le_bytes());
                            }
                            u128::from_le_bytes(out)
                        }
                        0x74 => pcmpeqb(self.xmm[reg_field], src),
                        0xf8 => {
                            // psubb：按 16 个无符号 8 位 lane 做模 256 减法。
                            let mut value = self.xmm[reg_field].to_le_bytes();
                            let source = src.to_le_bytes();
                            for lane in 0..16 {
                                value[lane] = value[lane].wrapping_sub(source[lane]);
                            }
                            u128::from_le_bytes(value)
                        }
                        _ => src,
                    };
                }
            }
            0x11 | 0x29 | 0x7f => {
                // 存储类：reg 字段是源，rm 是目标（reg 或内存）
                let val = self.xmm[reg_field];
                if mod_ == 3 {
                    let dst = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
                    self.xmm[dst] = val;
                } else {
                    let addr = self.resolve_sse_mem(mod_val, rm, rex, bytes, p, rip)?;
                    let size = match op2 {
                        // 标量 movss/movsd 与 movdqu 的存储宽度不同。
                        0x11 if rep == 0xf3 => 4,
                        0x11 if rep == 0xf2 => 8,
                        0x11 => 16,
                        0x29 | 0x7f => 16,
                        _ => 16,
                    };
                    self.context
                        .memory
                        .write(addr, &val.to_le_bytes()[..size])?;
                }
            }
            _ => {}
        };
        Ok(rip + *p as u64)
    }

    /// 解析 SSE ModR/M 的内存地址（mod_ != 3 时调用）。
    fn resolve_sse_mem(
        &self,
        mod_val: u8,
        rm: u8,
        rex: u8,
        bytes: &[u8],
        p: &mut usize,
        rip: u64,
    ) -> Result<u64, DaotiError> {
        if mod_val == 0 && rm == 5 {
            if *p + 4 > bytes.len() {
                return Err(DaotiError::Other("SSE rip 相对 disp32 截断".into()));
            }
            let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
            *p += 4;
            let addr = (rip + *p as u64).wrapping_add(d as i64 as u64);
            Ok(self.seg_addr(addr))
        } else if rm == 4 {
            let sib = *bytes
                .get(*p)
                .ok_or_else(|| DaotiError::Other("SSE SIB 截断".into()))?;
            *p += 1;
            let disp: i64 = match mod_val {
                0x40 => {
                    let d = *bytes
                        .get(*p)
                        .ok_or_else(|| DaotiError::Other("SSE disp8 截断".into()))?
                        as i8 as i64;
                    *p += 1;
                    d
                }
                0x80 => {
                    if *p + 4 > bytes.len() {
                        return Err(DaotiError::Other("SSE disp32 截断".into()));
                    }
                    let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
                    *p += 4;
                    d as i64
                }
                _ => 0,
            };
            let base_field = sib & 7;
            let addr = if mod_val == 0 && base_field == 5 {
                disp as u64
            } else {
                self.sib_addr(sib, rex, disp)?
            };
            Ok(self.seg_addr(addr))
        } else {
            let base = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
            let base_val = *self.reg(base);
            let addr = match mod_val {
                0x40 => {
                    let d = *bytes
                        .get(*p)
                        .ok_or_else(|| DaotiError::Other("SSE disp8 截断".into()))?
                        as i8 as i64;
                    *p += 1;
                    base_val.wrapping_add_signed(d)
                }
                0x80 => {
                    if *p + 4 > bytes.len() {
                        return Err(DaotiError::Other("SSE disp32 截断".into()));
                    }
                    let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
                    *p += 4;
                    base_val.wrapping_add(d as i64 as u64)
                }
                _ => base_val,
            };
            Ok(self.seg_addr(addr))
        }
    }

    /// 应用 FS/GS 段基址到地址。
    fn seg_addr(&self, addr: u64) -> u64 {
        if self.fs_override {
            addr.wrapping_add(self.fs_base)
        } else {
            addr
        }
    }

    /// 根据 ModR/M 的 mod/rm 字段解析目标：寄存器编号（无地址）或内存地址。
    fn resolve_dst(
        &self,
        mod_: u8,
        rm: u8,
        rex: u8,
        bytes: &[u8],
        p: &mut usize,
    ) -> Result<(usize, Option<u64>), DaotiError> {
        if mod_ == 0xc0 {
            return Ok((rm as usize | if rex & 1 != 0 { 8 } else { 0 }, None));
        }
        if mod_ == 0 && rm == 5 {
            if *p + 4 > bytes.len() {
                return Err(DaotiError::Other("rip 相对 disp32 截断".into()));
            }
            let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
            *p += 4;
            let next_rip = self.context.registers.general.rip + *p as u64;
            let addr = next_rip.wrapping_add(d as i64 as u64);
            let addr = self.seg_addr(addr);
            if std::env::var_os("DAOTI_TRACE_SBRK_RIPREL").is_some()
                && self.load_bias.is_some_and(|bias| {
                    (bias + 0x11a8a0..bias + 0x11a950).contains(&self.context.registers.general.rip)
                })
            {
                eprintln!(
                    "TRACE sbrk-riprel rip=0x{:x} p={} disp=0x{:x} next=0x{next_rip:x} addr=0x{addr:x} fs_override={} fs=0x{:x}",
                    self.context.registers.general.rip,
                    *p,
                    d as u32,
                    self.fs_override,
                    self.fs_base
                );
            }
            // 探针：__ctype_init（libc 0x3a3c0）窗口内的 RIP-relative 地址计算，
            // 验证 disp/next_rip 解析是否正确（崩溃指令 0x73f3d6 的前置 mov 曾算出 -0x90）。
            if std::env::var_os("DAOTI_TRACE_RIPREL").is_some()
                && (0x73f3c0..0x73f410).contains(&self.context.registers.general.rip)
            {
                eprintln!(
                    "TRACE riprel-dst rip=0x{:x} modrm=0x{:x} p={} disp=0x{:x} next_rip=0x{next_rip:x} addr=0x{addr:x} fs_override={} fs_base=0x{:x}",
                    self.context.registers.general.rip,
                    (mod_ | rm),
                    *p,
                    d as u32,
                    self.fs_override,
                    self.fs_base
                );
            }
            if addr < 0x100000 && std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                eprintln!(
                    "TRACE low-memory-operand rip=0x{:x} modrm=0x{:x} p={} disp={} next=0x{:x} addr=0x{:x} rsp=0x{:x} rax=0x{:x} rbx=0x{:x} rcx=0x{:x} rdx=0x{:x}",
                    self.context.registers.general.rip,
                    (mod_ | rm),
                    *p,
                    d,
                    next_rip,
                    addr,
                    self.context.registers.general.rsp,
                    self.context.registers.general.rax,
                    self.context.registers.general.rbx,
                    self.context.registers.general.rcx,
                    self.context.registers.general.rdx
                );
            }
            return Ok((0, Some(addr)));
        }
        if rm == 4 {
            let sib = *bytes
                .get(*p)
                .ok_or_else(|| DaotiError::Other("SIB 字节截断".into()))?;
            *p += 1;
            let disp: i64 = match mod_ {
                0 => {
                    if sib & 7 == 5 {
                        if *p + 4 > bytes.len() {
                            return Err(DaotiError::Other("SIB 无基址 disp32 截断".into()));
                        }
                        let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
                        *p += 4;
                        d as i64
                    } else {
                        0
                    }
                }
                0x40 => {
                    let d = *bytes
                        .get(*p)
                        .ok_or_else(|| DaotiError::Other("disp8 截断".into()))?
                        as i8 as i64;
                    *p += 1;
                    d
                }
                0x80 => {
                    if *p + 4 > bytes.len() {
                        return Err(DaotiError::Other("SIB disp32 截断".into()));
                    }
                    let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
                    *p += 4;
                    d as i64
                }
                _ => return Err(DaotiError::Other(format!("不支持的 SIB mod：0x{mod_:02x}"))),
            };
            let addr = if mod_ == 0 && sib & 7 == 5 {
                let scale_shift = ((sib >> 6) & 3) as u32;
                let index_field = (sib >> 3) & 7;
                let index = if index_field == 4 {
                    0
                } else {
                    let index_reg = index_field as usize | if rex & 2 != 0 { 8 } else { 0 };
                    self.reg(index_reg).wrapping_shl(scale_shift)
                };
                index.wrapping_add(disp as u64)
            } else {
                self.sib_addr(sib, rex, disp)?
            };
            return Ok((0, Some(self.seg_addr(addr))));
        }
        let base = rm as usize | if rex & 1 != 0 { 8 } else { 0 };
        let base_val = *self.reg(base);
        let addr = match mod_ {
            0 => base_val,
            0x40 => {
                let d = *bytes
                    .get(*p)
                    .ok_or_else(|| DaotiError::Other("disp8 截断".into()))?
                    as i8 as i64;
                *p += 1;
                base_val.wrapping_add_signed(d)
            }
            0x80 => {
                if *p + 4 > bytes.len() {
                    return Err(DaotiError::Other("disp32 截断".into()));
                }
                let d = i32::from_le_bytes(bytes[*p..*p + 4].try_into().unwrap());
                *p += 4;
                base_val.wrapping_add(d as i64 as u64)
            }
            _ => {
                return Err(DaotiError::Other(format!(
                    "不支持的寻址模式 mod：0x{mod_:02x}"
                )))
            }
        };
        Ok((base, Some(self.seg_addr(addr))))
    }

    /// 计算 SIB 有效地址：base + index*scale + disp。
    fn sib_addr(&self, sib: u8, rex: u8, disp: i64) -> Result<u64, DaotiError> {
        let scale_shift = match (sib >> 6) & 3 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 3,
        };
        let base_field = sib & 7;
        let base = base_field as usize | if rex & 1 != 0 { 8 } else { 0 };
        let index_field = (sib >> 3) & 7;
        // x86-64 SIB：index=100 且 REX.X=0 → no index；REX.X=1 → index=r12。
        // 旧代码无条件把 index==4 当作 no index，导致 4a 63 04 a7（REX.X=1）
        // 的 [rdi+r12*4] 被误算成 [rdi]，跳转表错取槽0 → 误入 bad_type。
        let index_val = if index_field == 4 && (rex & 2) == 0 {
            0
        } else {
            let idx = index_field as usize | if rex & 2 != 0 { 8 } else { 0 };
            (*self.reg(idx)).wrapping_shl(scale_shift as u32)
        };
        let base_val = *self.reg(base);
        Ok(base_val.wrapping_add(index_val).wrapping_add(disp as u64))
    }

    #[allow(dead_code)]
    fn reg(&self, n: usize) -> &u64 {
        match n {
            0 => &self.context.registers.general.rax,
            1 => &self.context.registers.general.rcx,
            2 => &self.context.registers.general.rdx,
            3 => &self.context.registers.general.rbx,
            4 => &self.context.registers.general.rsp,
            5 => &self.context.registers.general.rbp,
            6 => &self.context.registers.general.rsi,
            7 => &self.context.registers.general.rdi,
            8 => &self.context.registers.general.r8,
            9 => &self.context.registers.general.r9,
            10 => &self.context.registers.general.r10,
            11 => &self.context.registers.general.r11,
            12 => &self.context.registers.general.r12,
            13 => &self.context.registers.general.r13,
            14 => &self.context.registers.general.r14,
            15 => &self.context.registers.general.r15,
            _ => panic!("无效寄存器编号：{n}"),
        }
    }

    fn reg_mut(&mut self, n: usize) -> &mut u64 {
        match n {
            0 => &mut self.context.registers.general.rax,
            1 => &mut self.context.registers.general.rcx,
            2 => &mut self.context.registers.general.rdx,
            3 => &mut self.context.registers.general.rbx,
            4 => &mut self.context.registers.general.rsp,
            5 => &mut self.context.registers.general.rbp,
            6 => &mut self.context.registers.general.rsi,
            7 => &mut self.context.registers.general.rdi,
            8 => &mut self.context.registers.general.r8,
            9 => &mut self.context.registers.general.r9,
            10 => &mut self.context.registers.general.r10,
            11 => &mut self.context.registers.general.r11,
            12 => &mut self.context.registers.general.r12,
            13 => &mut self.context.registers.general.r13,
            14 => &mut self.context.registers.general.r14,
            15 => &mut self.context.registers.general.r15,
            _ => panic!("无效寄存器编号：{n}"),
        }
    }

    /// 读取 ModRM 中 8 位寄存器字段的值（code = reg/rm 3 位字段 0..=7）。
    ///
    /// x86-64 编码关键点：**无 REX 前缀**时，字段值 4..=7 并不映射到
    /// spl/bpl/sil/dil（rsp/rbp/rsi/rdi 的低字节），而是映射到
    /// ah/ch/dh/bh——即 rax/rcx/rdx/rbx 的**第 2 字节（bit8..15）**。
    /// 只有存在 REX 前缀时才使用低字节，且 reg 字段用 REX.R(0x4) 扩展、
    /// r/m 字段用 REX.B(0x1) 扩展。
    ///
    /// `is_reg_field=true` 表示该字段是 ModRM.reg（REX.R 扩展），
    /// `false` 表示是 ModRM.r/m（REX.B 扩展）。
    fn rd8(&self, code: u8, rex: u8, is_reg_field: bool) -> u8 {
        if rex == 0 && (4..=7).contains(&code) {
            // ah/ch/dh/bh → rax/rcx/rdx/rbx 的第 2 字节
            let base = (code - 4) as usize;
            ((*self.reg(base) >> 8) & 0xff) as u8
        } else {
            let idx = code as usize
                | if is_reg_field {
                    if rex & 4 != 0 {
                        8
                    } else {
                        0
                    }
                } else {
                    if rex & 1 != 0 {
                        8
                    } else {
                        0
                    }
                };
            (*self.reg(idx) & 0xff) as u8
        }
    }

    /// 写入 ModRM 中 8 位寄存器字段的值，编码规则同 [`Self::rd8`]。
    fn wr8(&mut self, code: u8, rex: u8, is_reg_field: bool, val: u8) {
        if rex == 0 && (4..=7).contains(&code) {
            // ah/ch/dh/bh → rax/rcx/rdx/rbx 的第 2 字节
            let base = (code - 4) as usize;
            let r = self.reg_mut(base);
            *r = (*r & !(0xffu64 << 8)) | ((val as u64) << 8);
        } else {
            let idx = code as usize
                | if is_reg_field {
                    if rex & 4 != 0 {
                        8
                    } else {
                        0
                    }
                } else {
                    if rex & 1 != 0 {
                        8
                    } else {
                        0
                    }
                };
            let r = self.reg_mut(idx);
            *r = (*r & !0xff) | val as u64;
        }
    }
}
