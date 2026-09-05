//! ELF 结构解析器（L0 本地重映射基础设施）
//!
//! 提供 ELF 文件头、段表（Program Headers）、架构、入口点等信息的纯逻辑解析。
//! 不涉及进程创建、内存加载或 syscall 拦截——这些是 L0 后续步骤。
//!
//! 解析结果的消费者：`L0::ElfLoader`（加载 ELF 到内存沙箱）、`L0::Interceptor`（拦截桩）。

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use daoti_common::DaotiError;

use runtime::{
    ExecutionState, MemPerm, MemoryModel, MemoryRegion, RuntimeContext, X86_64Interpreter,
};
use syscall_bridge::{NativeSyscallBridge, OutputSink, StdoutSink};

pub use syscall_bridge::BufferSink;

struct EmptyDynamicResolver;

impl relocation::SymbolResolver for EmptyDynamicResolver {
    fn resolve(&self, _symbol: u32) -> Option<u64> {
        None
    }
}

/// ELF 常量：64 位 ELF header 固定大小
const ELF64_EHSIZE: usize = 64;
/// ELF 常量：64 位 Program Header 固定大小
const ELF64_PHENTSIZE: usize = 56;

/// 段类型：PT_NULL
#[allow(dead_code)]
const PT_NULL: u32 = 0;
/// 段类型：PT_LOAD（可加载段）
#[allow(dead_code)]
const PT_LOAD: u32 = 1;
/// 段类型：PT_TLS（线程本地存储）
const PT_TLS: u32 = 7;

/// 段标志：PF_X（可执行）
#[allow(dead_code)]
const PF_X: u32 = 1;
/// 段标志：PF_W（可写）
#[allow(dead_code)]
const PF_W: u32 = 2;
/// 段标志：PF_R（可读）
#[allow(dead_code)]
const PF_R: u32 = 4;

pub mod dynamic_loader;
pub mod layout;
mod linux_emulation_handler;
pub mod relocation;
pub mod runtime;
pub mod syscall_bridge;
pub use dynamic_loader::{DynamicElfLoader, DynamicExecutionResult, DynamicLoadResult};
pub use layout::{align_down, align_up, plan_segments, MemoryLayout, SegmentMapping, PAGE_SIZE};

/// L0 最小 ELF 加载器：基于 `MemoryLayout` 构造沙箱镜像，不执行宿主进程指令。
#[derive(Debug, Clone, PartialEq)]
pub struct ElfLoader {
    /// 解析后的 ELF 信息
    pub info: ElfInfo,
    /// 规划后的内存布局
    pub layout: MemoryLayout,
}

/// 沙箱内的段镜像。
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxedSegment {
    /// 段在沙箱内的偏移
    pub offset_in_sandbox: u64,
    /// 段原始虚拟地址
    pub vaddr: u64,
    /// 段标志
    pub flags: u32,
    /// 段数据（含 BSS 零填充）
    pub bytes: Vec<u8>,
}

/// 沙箱装载结果。
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxImage {
    /// 入口点
    pub entry: u64,
    /// 镜像基址
    pub base: u64,
    /// 装载后的段
    pub segments: Vec<SandboxedSegment>,
}

/// 使用泛型 sink 在受限 x86_64 解释器中执行 ELF 字节数据。
///
/// 仅允许 x86_64、静态 ET_EXEC 且存在非零入口点的 ELF；不会接入 CLI 或启动宿主进程。
/// `sink` 参数决定 syscall write 的输出目标（如 `StdoutSink`、`BufferSink`）。
pub fn execute_elf_with_sink<S: OutputSink>(
    data: &[u8],
    stack_size: u64,
    sink: S,
) -> Result<ExecutionState, DaotiError> {
    let info = parse_elf_from_bytes(data)?;
    if info.arch != "x86_64" {
        return Err(DaotiError::Unavailable(format!(
            "本地 ELF 执行仅支持 x86_64，实际架构：{}",
            info.arch
        )));
    }
    if info.file_type != "ET_EXEC（可执行文件）" {
        return Err(DaotiError::Unavailable(format!(
            "本地 ELF 执行仅支持静态 ET_EXEC，实际类型：{}",
            info.file_type
        )));
    }
    if info.entry == 0 {
        return Err(DaotiError::Other("ELF 缺失有效入口点".into()));
    }

    let context = ElfLoader::build_runtime_context_from_bytes(data, stack_size)?;
    let heap_brk = context.heap_brk;
    let heap_end = context.heap_end;
    // 与初始栈 AT_RANDOM 一致：前 8 字节为 stack_guard，后 8 字节为 pointer_guard。
    let stack_guard = u64::from_le_bytes([0x6d, 0x31, 0x92, 0xa7, 0x44, 0x18, 0x5f, 0xc3]) & !0xff;
    let pointer_guard = u64::from_le_bytes([0x28, 0xe6, 0x70, 0x0b, 0x9d, 0x52, 0xf1, 0x86]);
    let bridge = NativeSyscallBridge::new(sink)
        .with_brk(heap_brk, heap_end)
        .with_tls_guards(
            find_elf_symbol(data, "_nl_global_locale")?,
            pointer_guard,
            stack_guard,
        );
    let cleanup_addr = find_elf_symbol(data, "_IO_cleanup")?;
    let stdout_addr = find_elf_symbol(data, "_IO_2_1_stdout_")?;
    let mut interpreter = X86_64Interpreter::new(context)
        .with_syscall_handler(Box::new(bridge))
        .with_stdout_capture(cleanup_addr, stdout_addr);
    // 解析 IFUNC（IRELATIVE）重定位，填充 GOT.plt 表项
    interpreter.resolve_irelative_relocs(data, 0)?;
    interpreter.run()
}

/// 从 ELF 文件装载并在受限 x86_64 解释器中执行（Stdout 输出）。
///
/// 这是 CLI 的便捷入口，内部委托给 `execute_elf_with_sink`。
/// 仅允许 x86_64、静态 ET_EXEC 且存在非零入口点的 ELF；不会接入 CLI 或启动宿主进程。
pub fn execute_elf_file(path: &str, stack_size: u64) -> Result<ExecutionState, DaotiError> {
    let mut file = File::open(path)
        .map_err(|e| DaotiError::Other(format!("无法打开 ELF 文件 {path}：{e}")))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| DaotiError::Other(format!("读取 ELF 文件 {path} 失败：{e}")))?;
    execute_elf_with_sink(&data, stack_size, StdoutSink)
}

/// 在受控 runtime 根目录内执行动态 ELF 及其依赖，不调用宿主动态链接器。
pub fn execute_dynamic_elf_file(
    path: &str,
    runtime_root: &Path,
    stack_size: u64,
) -> Result<ExecutionState, DaotiError> {
    let loader = dynamic_loader::DynamicElfLoader::new(EmptyDynamicResolver, 0x700000, stack_size)?;
    let allowed_roots = vec![normalize_path(runtime_root)];
    loader.execute_combined(Path::new(path), &allowed_roots)
}

impl ElfLoader {
    /// 从 ELF 解析结果创建加载器。
    pub fn new(info: ElfInfo) -> Result<Self, DaotiError> {
        let layout = plan_segments(&info.segments)?;
        Ok(Self { info, layout })
    }

    /// 构造沙箱镜像，复制 PT_LOAD 段并补齐 BSS。
    pub fn build_image(&self, data: &[u8]) -> Result<SandboxImage, DaotiError> {
        let mut segments = Vec::with_capacity(self.info.segments.len());
        for mapping in &self.layout.mappings {
            let source = self
                .info
                .segments
                .iter()
                .find(|seg| seg.vaddr == mapping.vaddr)
                .ok_or_else(|| {
                    DaotiError::Other(format!("找不到段 vaddr=0x{:x}", mapping.vaddr))
                })?;
            let start = source.offset as usize;
            let end = start.saturating_add(source.filesz as usize);
            if start > data.len() {
                return Err(DaotiError::Other(format!(
                    "段起点超出文件边界 vaddr=0x{:x}",
                    source.vaddr
                )));
            }
            let copy_end = end.min(data.len());
            let mut bytes = data[start..copy_end].to_vec();
            if bytes.len() < source.filesz as usize {
                bytes.resize(source.filesz as usize, 0);
            }
            if source.memsz > source.filesz {
                bytes.extend(std::iter::repeat_n(
                    0u8,
                    (source.memsz - source.filesz) as usize,
                ));
            }
            segments.push(SandboxedSegment {
                offset_in_sandbox: mapping.offset_in_sandbox,
                vaddr: mapping.vaddr,
                flags: mapping.flags,
                bytes,
            });
        }
        Ok(SandboxImage {
            entry: self.info.entry,
            base: self.layout.base,
            segments,
        })
    }

    /// 从 ELF 字节构造已装载的运行时上下文。
    pub fn build_runtime_context_from_bytes(
        data: &[u8],
        stack_size: u64,
    ) -> Result<RuntimeContext, DaotiError> {
        let info = parse_elf_from_bytes(data)?;
        let loader = Self::new(info)?;
        loader.build_runtime_context(data, stack_size)
    }

    /// 从 ELF 文件构造已装载的运行时上下文。
    pub fn build_runtime_context_from_file(
        path: &str,
        stack_size: u64,
    ) -> Result<RuntimeContext, DaotiError> {
        let mut file = File::open(path)
            .map_err(|e| DaotiError::Other(format!("无法打开 ELF 文件 {path}：{e}")))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| DaotiError::Other(format!("读取 ELF 文件 {path} 失败：{e}")))?;
        Self::build_runtime_context_from_bytes(&data, stack_size)
    }

    /// 将镜像段和安全栈注册到运行时内存模型。
    pub fn build_runtime_context(
        &self,
        data: &[u8],
        stack_size: u64,
    ) -> Result<RuntimeContext, DaotiError> {
        if stack_size == 0 {
            return Err(DaotiError::Other("安全栈大小不能为 0".into()));
        }
        let image = self.build_image(data)?;
        let stack_base = image
            .base
            .checked_add(self.layout.total_size)
            .ok_or_else(|| DaotiError::Other("安全栈地址溢出".into()))?;
        let stack_size = align_up(stack_size, PAGE_SIZE);
        let stack_region_size = stack_size
            .checked_add(PAGE_SIZE)
            .ok_or_else(|| DaotiError::Other("安全栈范围溢出".into()))?;
        let stack_end = stack_base
            .checked_add(stack_region_size)
            .ok_or_else(|| DaotiError::Other("安全栈范围溢出".into()))?;
        // 栈顶为初始进程栈数据（argc/argv/envp/auxv）保留一页空间
        const STACK_DATA_PAGE: u64 = 0x1000;
        let stack_ptr = stack_end
            .checked_sub(STACK_DATA_PAGE)
            .ok_or_else(|| DaotiError::Other("安全栈指针下溢".into()))?;
        let mut memory = MemoryModel::new(
            self.layout.base,
            stack_end
                .checked_add(PAGE_SIZE * 3 + 0x50000000)
                .ok_or_else(|| DaotiError::Other("内存范围溢出".into()))?,
        );
        for segment in &image.segments {
            // 非执行段（数据/RELRO）映射为可读写，模拟内核在 RELRO 保护前的状态
            let write = segment.flags & PF_W != 0 || segment.flags & PF_X == 0;
            let perm = MemPerm {
                read: segment.flags & PF_R != 0,
                write,
                execute: segment.flags & PF_X != 0,
            };
            let base = align_down(segment.vaddr, PAGE_SIZE);
            let prefix = (segment.vaddr - base) as usize;
            let mut bytes = vec![0; prefix];
            bytes.extend_from_slice(&segment.bytes);
            let size = align_up(bytes.len() as u64, PAGE_SIZE);
            bytes.resize(size as usize, 0);
            memory.add_region(MemoryRegion::with_data(base, perm, bytes))?;
        }
        memory.add_region(MemoryRegion::with_data(
            stack_base,
            MemPerm::rw(),
            vec![0; stack_region_size as usize],
        ))?;
        // 布置初始进程栈：argc=1, argv[0]=程序名, envp=[0], auxv 提供必要信息
        let program_name = b"daoti-elf";
        let name_addr = stack_end - program_name.len() as u64;
        let random_addr = name_addr - 16;
        let mut stack_data = Vec::new();
        // Linux x86_64 初始栈布局（从 rsp 向上）：
        //   [rsp]     = argc
        //   [rsp+8]   = argv[0], ..., argv[argc], NULL
        //   [after]   = envp[0], ..., envp[envc], NULL
        //   [after]   = auxv[0].tag, auxv[0].val, ...
        //                    ..., auxv[n].tag, auxv[n].val (AT_NULL,0)
        // 从 ELF 头读取程序头表地址等
        let e_phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
        let e_phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as u64;
        let entry = u64::from_le_bytes(data[0x18..0x20].try_into().unwrap());
        let phdr_vaddr = self
            .info
            .segments
            .iter()
            .find(|segment| e_phoff >= segment.offset && e_phoff < segment.offset + segment.filesz)
            .map(|segment| segment.vaddr + (e_phoff - segment.offset))
            .unwrap_or(e_phoff);
        stack_data.extend_from_slice(&1u64.to_le_bytes()); // argc
        stack_data.extend_from_slice(&name_addr.to_le_bytes()); // argv[0]
        stack_data.extend_from_slice(&0u64.to_le_bytes()); // argv[1] NULL
        stack_data.extend_from_slice(&0u64.to_le_bytes()); // envp[0] NULL
                                                           // auxv 条目：按 tag, value 交替
                                                           // AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_PAGESZ=6, AT_ENTRY=9
        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_SECURE: u64 = 23;
        const AT_RANDOM: u64 = 25;
        const AT_NULL: u64 = 0;
        const PAGE_SIZE: u64 = 4096;
        stack_data.extend_from_slice(&AT_PHDR.to_le_bytes());
        stack_data.extend_from_slice(&phdr_vaddr.to_le_bytes());
        stack_data.extend_from_slice(&AT_PHENT.to_le_bytes());
        stack_data.extend_from_slice(&56u64.to_le_bytes()); // sizeof(Elf64_Phdr)
        stack_data.extend_from_slice(&AT_PHNUM.to_le_bytes());
        stack_data.extend_from_slice(&e_phnum.to_le_bytes());
        stack_data.extend_from_slice(&AT_PAGESZ.to_le_bytes());
        stack_data.extend_from_slice(&PAGE_SIZE.to_le_bytes());
        stack_data.extend_from_slice(&AT_ENTRY.to_le_bytes());
        stack_data.extend_from_slice(&entry.to_le_bytes());
        stack_data.extend_from_slice(&AT_UID.to_le_bytes());
        stack_data.extend_from_slice(&0u64.to_le_bytes());
        stack_data.extend_from_slice(&AT_EUID.to_le_bytes());
        stack_data.extend_from_slice(&0u64.to_le_bytes());
        stack_data.extend_from_slice(&AT_GID.to_le_bytes());
        stack_data.extend_from_slice(&0u64.to_le_bytes());
        stack_data.extend_from_slice(&AT_EGID.to_le_bytes());
        stack_data.extend_from_slice(&0u64.to_le_bytes());
        stack_data.extend_from_slice(&AT_SECURE.to_le_bytes());
        stack_data.extend_from_slice(&0u64.to_le_bytes());
        stack_data.extend_from_slice(&AT_RANDOM.to_le_bytes());
        stack_data.extend_from_slice(&random_addr.to_le_bytes());
        stack_data.extend_from_slice(&AT_NULL.to_le_bytes());
        stack_data.extend_from_slice(&0u64.to_le_bytes());
        while (stack_data.len() as u64) + (program_name.len() as u64) < STACK_DATA_PAGE {
            stack_data.push(0);
        }
        stack_data.extend_from_slice(program_name);
        memory.write(stack_ptr, &stack_data)?;
        memory.write(
            random_addr,
            &[
                0x6d, 0x31, 0x92, 0xa7, 0x44, 0x18, 0x5f, 0xc3, 0x28, 0xe6, 0x70, 0x0b, 0x9d, 0x52,
                0xf1, 0x86,
            ],
        )?;
        // TLS 页：分配给线程局部存储（FS 段基址，单线程静态 ELF 用）
        let tls_addr = stack_end + PAGE_SIZE;
        let tls_size = PAGE_SIZE * 2;
        let tls_base = tls_addr + PAGE_SIZE + 0x800; // 为静态 TLS 的负偏移访问保留 TCB 空间
        let _lock_addr = tls_base;
        let tcb_addr = tls_base + 0x100;
        let _dtv_addr = tls_addr + tls_size - 0x100;
        let e_phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;
        let has_tls = (0..e_phnum).any(|i| {
            let off = e_phoff as usize + i * e_phentsize;
            off + 4 <= data.len() && u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) == 7
        });
        if has_tls {
            memory.add_region(MemoryRegion::with_data(
                tls_addr - 0x1000,
                MemPerm::rw(),
                vec![0; (tls_size + 0x1000) as usize],
            ))?;
            // 静态链接 glibc 使用该字节选择单线程快速路径；按 ELF 符号定位，避免固定虚拟地址。
            if let Some(address) = find_elf_symbol(data, "__libc_single_threaded")? {
                memory.write(address, &[1])?;
            }
            if let Some(address) = find_elf_symbol(data, "_dl_random")? {
                memory.write(address, &random_addr.to_le_bytes())?;
            }
            if let Some(address) = find_elf_symbol(data, "lock")? {
                memory.write(address, &0u32.to_le_bytes())?;
            }
            for symbol in ["__libc_lock_lock", "__libc_lock_recursive_lock"] {
                if let Some(address) = find_elf_symbol(data, symbol)? {
                    memory.write(address, &0u32.to_le_bytes())?;
                }
            }
            // TCB 字段由 glibc 在运行时初始化，loader 写入的地址与 glibc 实际选择的
            // FS base 不一致，因此不在 loader 中写入 TCB 字段。
            // locale 和 pointer_guard 在 ARCH_SET_FS 后写入正确地址。
        }

        // 解析 PT_TLS 并复制初始化映像到 TLS 块
        struct Phdr {
            p_type: u32,
            p_offset: u64,
            p_filesz: u64,
            p_memsz: u64,
            p_align: u64,
        }
        let e_phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
        let e_phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap()) as usize;
        let e_phnum = u16::from_le_bytes(data[0x38..0x3a].try_into().unwrap()) as usize;
        for i in 0..e_phnum {
            let off = e_phoff as usize + i * e_phentsize;
            if off + 56 > data.len() {
                break;
            }
            let phdr = Phdr {
                p_type: u32::from_le_bytes(data[off..off + 4].try_into().unwrap()),
                p_offset: u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()),
                p_filesz: u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap()),
                p_memsz: u64::from_le_bytes(data[off + 40..off + 48].try_into().unwrap()),
                p_align: u64::from_le_bytes(data[off + 48..off + 56].try_into().unwrap()),
            };
            if phdr.p_type == 7 {
                // TLS_TCB_AT_TP：TLS 块起始于 tls_base - roundup(p_memsz, p_align)
                let tls_memsz = align_up(phdr.p_memsz, phdr.p_align);
                let tls_block_start = tls_base.wrapping_sub(tls_memsz);
                // 复制初始化映像
                if phdr.p_filesz > 0 {
                    let init_start = phdr.p_offset as usize;
                    let init_end = init_start + phdr.p_filesz as usize;
                    if init_end <= data.len() {
                        memory.write(tls_block_start, &data[init_start..init_end])?;
                    }
                }
                // 读取时已零填充，无需显式零填充 BSS 部分
                break;
            }
        }
        if has_tls {
            // TCB 字段由 glibc 在运行时初始化，不在 loader 中写入。
        }
        // 预分配堆区域（8 MB），用于 glibc 的 brk/sbrk 堆管理
        const HEAP_SIZE: u64 = 8 * 1024 * 1024;
        let heap_addr = tls_addr + tls_size;
        let heap_end = heap_addr + HEAP_SIZE;
        memory.add_region(MemoryRegion::with_data(
            heap_addr,
            MemPerm::rw(),
            vec![0; HEAP_SIZE as usize],
        ))?;
        let mut context = RuntimeContext::new(image.entry, stack_ptr, memory);
        context.tls_base = tcb_addr;
        context.heap_brk = heap_addr;
        context.heap_end = heap_end;
        if std::env::var_os("DAOTI_TRACE_TLS").is_some() {
            let value = context
                .memory
                .read(tls_base, 4)
                .ok()
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()));
            eprintln!("TRACE tls_base=0x{tls_base:x} initial_word={value:?}");
        }
        Ok(context)
    }
}

#[cfg(test)]
fn find_elf_symbol(data: &[u8], wanted: &str) -> Result<Option<u64>, DaotiError> {
    find_elf_symbol_impl(data, wanted)
}

#[cfg(not(test))]
fn find_elf_symbol(data: &[u8], wanted: &str) -> Result<Option<u64>, DaotiError> {
    find_elf_symbol_impl(data, wanted)
}

fn find_elf_symbol_impl(data: &[u8], wanted: &str) -> Result<Option<u64>, DaotiError> {
    if data.len() < ELF64_EHSIZE || data[4] != 2 {
        return Ok(None);
    }
    let section_offset = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let section_size = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let section_count = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
    if section_size < 64
        || section_offset
            .checked_add(
                section_size
                    .checked_mul(section_count)
                    .ok_or_else(|| DaotiError::Other("ELF 节表大小溢出".into()))?,
            )
            .is_none()
    {
        return Ok(None);
    }
    let section_table_end = section_offset + section_size * section_count;
    if section_table_end > data.len() {
        return Ok(None);
    }
    for index in 0..section_count {
        let offset = section_offset + index * section_size;
        let section_type = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap());
        if section_type != 2 && section_type != 11 {
            continue;
        }
        let symbol_offset =
            u64::from_le_bytes(data[offset + 24..offset + 32].try_into().unwrap()) as usize;
        let symbol_size =
            u64::from_le_bytes(data[offset + 32..offset + 40].try_into().unwrap()) as usize;
        let symbol_entry_size =
            u64::from_le_bytes(data[offset + 56..offset + 64].try_into().unwrap()) as usize;
        let string_table_index =
            u32::from_le_bytes(data[offset + 40..offset + 44].try_into().unwrap()) as usize;
        if symbol_entry_size < 24
            || !symbol_size.is_multiple_of(symbol_entry_size)
            || string_table_index >= section_count
        {
            continue;
        }
        let string_section = section_offset + string_table_index * section_size;
        let string_offset = u64::from_le_bytes(
            data[string_section + 24..string_section + 32]
                .try_into()
                .unwrap(),
        ) as usize;
        let string_size = u64::from_le_bytes(
            data[string_section + 32..string_section + 40]
                .try_into()
                .unwrap(),
        ) as usize;
        let Some(symbol_end) = symbol_offset.checked_add(symbol_size) else {
            continue;
        };
        let Some(string_end) = string_offset.checked_add(string_size) else {
            continue;
        };
        if symbol_end > data.len() || string_end > data.len() {
            continue;
        }
        for symbol in (symbol_offset..symbol_end).step_by(symbol_entry_size) {
            let name_offset =
                u32::from_le_bytes(data[symbol..symbol + 4].try_into().unwrap()) as usize;
            if name_offset >= string_size {
                continue;
            }
            let name_end = data[string_offset + name_offset..string_end]
                .iter()
                .position(|byte| *byte == 0)
                .map_or(string_end, |end| string_offset + name_offset + end);
            if &data[string_offset + name_offset..name_end] == wanted.as_bytes() {
                return Ok(Some(u64::from_le_bytes(
                    data[symbol + 8..symbol + 16].try_into().unwrap(),
                )));
            }
        }
    }
    Ok(None)
}

/// 纯解析的 ELF 重定位条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationEntry {
    pub offset: u64,
    pub info: u64,
    pub addend: Option<i64>,
    pub symbol: u32,
    pub symbol_name: Option<String>,
    pub symbol_size: u64,
    pub relocation_type: X86_64RelocationType,
}

/// x86_64 ELF 重定位类型（未知值保留，避免解析阶段丢失信息）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86_64RelocationType {
    None,
    Type64,
    Relative,
    GlobDat,
    JumpSlot,
    DtpMod64,
    DtpOff64,
    TpOff64,
    Copy,
    IRelative,
    Unknown(u32),
}

impl X86_64RelocationType {
    fn decode(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Type64,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JumpSlot,
            8 => Self::Relative,
            // x86-64 ABI：DTPMOD64=16、DTPOFF64=17、TPOFF64=18。
            // 旧表把 10/16 误标为 DTPMOD64/DTPOFF64，会让真实 libc 的 TLS
            // 重定位被错误分类，这里按 System V AMD64 ABI 修正。
            16 => Self::DtpMod64,
            17 => Self::DtpOff64,
            18 => Self::TpOff64,
            37 => Self::IRelative,
            other => Self::Unknown(other),
        }
    }
}

/// 读取 PT_DYNAMIC 中声明的 DT_RELA/DT_REL 实际条目；仅解析，不执行重定位。
pub fn read_dynamic_relocations(
    data: &[u8],
    info: &ElfInfo,
    plan: &DynamicLoadPlan,
) -> Result<Vec<RelocationEntry>, DaotiError> {
    read_dynamic_relocations_with_plt(data, info, plan, true)
}

/// 读取动态重定位；解释器自重定位阶段不应提前解析其懒绑定 PLT。
/// ld.so 的 DT_JMPREL 由自身初始化流程处理，提前写入会破坏其启动状态。
pub fn read_dynamic_relocations_with_plt(
    data: &[u8],
    info: &ElfInfo,
    plan: &DynamicLoadPlan,
    include_plt: bool,
) -> Result<Vec<RelocationEntry>, DaotiError> {
    let mut result = Vec::new();
    if let Some((address, entry_size, count)) = plan.rela {
        if entry_size != 24 {
            return Err(DaotiError::Other("x86_64 DT_RELA 条目大小错误".into()));
        }
        read_relocation_table(
            data,
            info,
            plan,
            address,
            entry_size,
            count,
            true,
            &mut result,
        )?;
    }
    if include_plt {
        if let Some((address, entry_size, count, rela)) = plan.jmprel {
            if (rela && entry_size != 24) || (!rela && entry_size != 16) {
                return Err(DaotiError::Other("x86_64 DT_JMPREL 条目大小错误".into()));
            }
            read_relocation_table(
                data,
                info,
                plan,
                address,
                entry_size,
                count,
                rela,
                &mut result,
            )?;
        }
    }
    if let Some((address, entry_size, count)) = plan.rel {
        if entry_size != 16 {
            return Err(DaotiError::Other("x86_64 DT_REL 条目大小错误".into()));
        }
        read_relocation_table(
            data,
            info,
            plan,
            address,
            entry_size,
            count,
            false,
            &mut result,
        )?;
    }
    if let Some((address, entry_size, count)) = plan.relr {
        if entry_size != 8 {
            return Err(DaotiError::Other("x86_64 DT_RELR 条目大小错误".into()));
        }
        let mut slot = 0u64;
        for index in 0..count {
            let file = vaddr_to_file(data, &info.segments, address + index * 8)?;
            let word = u64::from_le_bytes(data[file..file + 8].try_into().unwrap());
            if word & 1 == 0 {
                slot = word;
                result.push(RelocationEntry {
                    offset: slot,
                    info: 0,
                    addend: None,
                    symbol: 0,
                    symbol_name: None,
                    symbol_size: 0,
                    relocation_type: X86_64RelocationType::Relative,
                });
                slot += 8;
            } else {
                for bit in 1..64 {
                    if word & (1u64 << bit) != 0 {
                        result.push(RelocationEntry {
                            offset: slot + (bit - 1) * 8,
                            info: 0,
                            addend: None,
                            symbol: 0,
                            symbol_name: None,
                            symbol_size: 0,
                            relocation_type: X86_64RelocationType::Relative,
                        });
                    }
                }
                slot += 63 * 8;
            }
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn read_relocation_table(
    data: &[u8],
    info: &ElfInfo,
    plan: &DynamicLoadPlan,
    address: u64,
    entry_size: u64,
    count: u64,
    rela: bool,
    out: &mut Vec<RelocationEntry>,
) -> Result<(), DaotiError> {
    let start = vaddr_to_file(data, &info.segments, address)?;
    let bytes = usize::try_from(
        entry_size
            .checked_mul(count)
            .ok_or_else(|| DaotiError::Other("重定位表大小溢出".into()))?,
    )
    .map_err(|_| DaotiError::Other("重定位表大小过大".into()))?;
    let end = start
        .checked_add(bytes)
        .ok_or_else(|| DaotiError::Other("重定位表边界溢出".into()))?;
    if end > data.len() {
        return Err(DaotiError::Other("重定位表超出文件边界".into()));
    }
    for chunk in data[start..end].chunks_exact(entry_size as usize) {
        let offset = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let info_value = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        let addend = if rela {
            Some(i64::from_le_bytes(chunk[16..24].try_into().unwrap()))
        } else {
            None
        };
        out.push(RelocationEntry {
            offset,
            info: info_value,
            addend,
            symbol: (info_value >> 32) as u32,
            symbol_name: dynamic_symbol_name(data, info, plan, (info_value >> 32) as u32)?,
            symbol_size: dynamic_symbol_size(data, info, plan, (info_value >> 32) as u32)?,
            relocation_type: X86_64RelocationType::decode(info_value as u32),
        });
    }
    Ok(())
}

fn dynamic_symbol_name(
    data: &[u8],
    info: &ElfInfo,
    plan: &DynamicLoadPlan,
    index: u32,
) -> Result<Option<String>, DaotiError> {
    let (Some(symtab), Some(strtab)) = (plan.symtab, plan.strtab) else {
        return Ok(None);
    };
    let sym_addr = symtab
        .checked_add(index as u64 * 24)
        .ok_or_else(|| DaotiError::Other("动态符号地址溢出".into()))?;
    let sym = vaddr_to_file(data, &info.segments, sym_addr)?;
    if sym + 4 > data.len() {
        return Ok(None);
    }
    let name_offset = u32::from_le_bytes(data[sym..sym + 4].try_into().unwrap()) as u64;
    let name_addr = strtab
        .checked_add(name_offset)
        .ok_or_else(|| DaotiError::Other("动态符号名地址溢出".into()))?;
    let start = vaddr_to_file(data, &info.segments, name_addr)?;
    let end = data[start..]
        .iter()
        .position(|b| *b == 0)
        .map_or(data.len(), |n| start + n);
    Ok(Some(String::from_utf8(data[start..end].to_vec()).map_err(
        |_| DaotiError::Other("动态符号名不是有效 UTF-8".into()),
    )?))
}

fn dynamic_symbol_size(
    data: &[u8],
    info: &ElfInfo,
    plan: &DynamicLoadPlan,
    index: u32,
) -> Result<u64, DaotiError> {
    let (Some(symtab), _) = (plan.symtab, plan.strtab) else {
        return Ok(0);
    };
    let sym_addr = symtab
        .checked_add(index as u64 * 24)
        .ok_or_else(|| DaotiError::Other("动态符号地址溢出".into()))?;
    let sym = vaddr_to_file(data, &info.segments, sym_addr)?;
    if sym + 24 > data.len() {
        return Ok(0);
    }
    Ok(u64::from_le_bytes(
        data[sym + 16..sym + 24].try_into().unwrap(),
    ))
}

/// 动态符号读取结果：名称 + 已装载地址（load_bias + st_value）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedDynamicSymbol {
    pub name: String,
    pub loaded_address: u64,
    pub defined: bool,
    /// st_info 低 4 位为符号类型（STT_*），STT_TLS=6 表示线程局部符号。
    pub symbol_type: u8,
    /// 原始 st_value：对 STT_TLS 符号而言是相对 PT_TLS 起始的块内偏移，
    /// 非 TLS 符号为 load_bias 未叠加的链接期值。
    pub raw_value: u64,
}

/// 读取对象 DT_SYMTAB/DT_STRTAB，生成全部符号的已装载地址表。
pub fn read_loaded_dynamic_symbols(
    data: &[u8],
    plan: &DynamicLoadPlan,
) -> Result<Vec<LoadedDynamicSymbol>, DaotiError> {
    let (symtab, strtab) = match (plan.symtab, plan.strtab) {
        (Some(s), Some(t)) => (s, t),
        _ => return Ok(Vec::new()),
    };
    let info = parse_elf_from_bytes(data)?;
    let entry_size = plan
        .entries
        .iter()
        .find(|entry| entry.tag == 11)
        .map(|entry| entry.value)
        .unwrap_or(24);
    if entry_size != 24 {
        return Err(DaotiError::Other("x86_64 动态符号条目大小错误".into()));
    }
    let count = if let Some(hash) = plan.entries.iter().find(|entry| entry.tag == 4) {
        let file = vaddr_to_file(data, &info.segments, hash.value)?;
        if file + 8 > data.len() {
            return Err(DaotiError::Other("DT_HASH 超出文件边界".into()));
        }
        u32::from_le_bytes(data[file + 4..file + 8].try_into().unwrap()) as usize
    } else if let Some(hash) = plan.entries.iter().find(|entry| entry.tag == 0x6ffffef5) {
        // glibc 通常只提供 GNU hash。动态符号索引不能从 DT_GNU_HASH 的
        // nbuckets 直接推导，必须扫描被 bucket 指向的 chain，直到链尾。
        let file = vaddr_to_file(data, &info.segments, hash.value)?;
        let read_u32 = |offset: usize| -> Result<u32, DaotiError> {
            let end = offset
                .checked_add(4)
                .ok_or_else(|| DaotiError::Other("DT_GNU_HASH 偏移溢出".into()))?;
            if end > data.len() {
                return Err(DaotiError::Other("DT_GNU_HASH 超出文件边界".into()));
            }
            Ok(u32::from_le_bytes(data[offset..end].try_into().unwrap()))
        };
        let buckets = read_u32(file)? as usize;
        let symoffset = read_u32(file + 4)? as usize;
        let bloom_size = read_u32(file + 8)? as usize;
        let buckets_file = file
            .checked_add(
                16 + bloom_size
                    .checked_mul(8)
                    .ok_or_else(|| DaotiError::Other("DT_GNU_HASH bloom 溢出".into()))?,
            )
            .ok_or_else(|| DaotiError::Other("DT_GNU_HASH bucket 偏移溢出".into()))?;
        let mut count = symoffset;
        for bucket in 0..buckets {
            let index = read_u32(
                buckets_file
                    .checked_add(bucket * 4)
                    .ok_or_else(|| DaotiError::Other("DT_GNU_HASH bucket 溢出".into()))?,
            )? as usize;
            if index < symoffset {
                continue;
            }
            let mut current = index;
            loop {
                let chain_offset = buckets_file
                    .checked_add(buckets * 4)
                    .and_then(|base| base.checked_add((current - symoffset) * 4))
                    .ok_or_else(|| DaotiError::Other("DT_GNU_HASH chain 偏移溢出".into()))?;
                let chain = read_u32(chain_offset)?;
                count = count.max(current + 1);
                if chain & 1 != 0 {
                    break;
                }
                current += 1;
            }
        }
        count
    } else {
        0
    };
    let mut symbols = Vec::with_capacity(count.clamp(1, 65536));
    for index in 0..count {
        let sym_addr = symtab
            .checked_add(index as u64 * entry_size)
            .ok_or_else(|| DaotiError::Other("动态符号地址溢出".into()))?;
        let sym_file = vaddr_to_file(data, &info.segments, sym_addr)?;
        if sym_file + 24 > data.len() {
            return Err(DaotiError::Other("动态符号超出文件边界".into()));
        }
        let name_offset = u32::from_le_bytes(data[sym_file..sym_file + 4].try_into().unwrap());
        // st_info（字节 4）低 4 位为符号类型，STT_TLS=6；st_other 在字节 5。
        let st_info = data[sym_file + 4];
        let st_shndx = u16::from_le_bytes(data[sym_file + 6..sym_file + 8].try_into().unwrap());
        let st_value = u64::from_le_bytes(data[sym_file + 8..sym_file + 16].try_into().unwrap());
        if name_offset == 0 {
            continue;
        }
        let name_addr = strtab
            .checked_add(name_offset as u64)
            .ok_or_else(|| DaotiError::Other("动态符号名地址溢出".into()))?;
        let start = vaddr_to_file(data, &info.segments, name_addr)?;
        let end = data[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map_or(data.len(), |n| start + n);
        let name = String::from_utf8(data[start..end].to_vec())
            .map_err(|_| DaotiError::Other("动态符号名不是有效 UTF-8".into()))?;
        symbols.push(LoadedDynamicSymbol {
            name,
            loaded_address: plan
                .load_bias
                .checked_add(st_value)
                .ok_or_else(|| DaotiError::Other("动态符号已装载地址溢出".into()))?,
            defined: st_shndx != 0,
            symbol_type: st_info & 0x0f,
            raw_value: st_value,
        });
    }
    Ok(symbols)
}

/// 从 ELF 文件数据中读取完整符号表（.symtab）中的符号。
///
/// 与 `read_loaded_dynamic_symbols` 不同，该函数读取的是完整符号表（SHT_SYMTAB），
/// 而非仅动态符号表（DT_SYMTAB/.dynsym）。这对于查找 ld-linux 内部隐藏符号
/// （如 _dl_map_object/_dl_new_object）是必要的，因为它们不在 .dynsym 中导出。
/// 返回（符号名, st_value）对，st_value 为原始未重定位地址。
pub fn read_full_symtab_symbols(data: &[u8]) -> Result<Vec<(String, u64)>, DaotiError> {
    if data.len() < 64 {
        return Ok(Vec::new());
    }
    let is_64 = data[4] == 2;
    if !is_64 {
        return Ok(Vec::new());
    }
    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap());
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap());
    // e_shstrndx
    let _e_shstrndx = u16::from_le_bytes(data[62..64].try_into().unwrap());

    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
        return Ok(Vec::new());
    }

    // 1. 读取所有 section header，找到 .symtab 和其关联的 .strtab
    let shoff = e_shoff as usize;
    let shentsize = e_shentsize as usize;
    let mut sections: Vec<(u32, u32, u64, u64, u32)> = Vec::new(); // (type, link, offset, size, entsize)
    for i in 0..e_shnum as usize {
        let base = shoff + i * shentsize;
        if base + 64 > data.len() {
            break;
        }
        let sh_type = u32::from_le_bytes(data[base + 4..base + 8].try_into().unwrap());
        let sh_offset = u64::from_le_bytes(data[base + 24..base + 32].try_into().unwrap());
        let sh_size = u64::from_le_bytes(data[base + 32..base + 40].try_into().unwrap());
        let sh_link = u32::from_le_bytes(data[base + 40..base + 44].try_into().unwrap());
        let sh_entsize = u64::from_le_bytes(data[base + 56..base + 64].try_into().unwrap());
        sections.push((sh_type, sh_link, sh_offset, sh_size, sh_entsize as u32));
    }

    // 2. 找到 SHT_SYMTAB（type=2）及其关联的 SHT_STRTAB（type=3）
    let mut symtab_info = None;
    let mut strtab_info = None;
    for &(sh_type, sh_link, sh_offset, sh_size, sh_entsize) in sections.iter() {
        if sh_type == 2 {
            // SHT_SYMTAB: sh_link points to the associated .strtab
            let strtab_idx = sh_link as usize;
            if strtab_idx < sections.len() {
                let (st_type, _, st_off, st_sz, _) = sections[strtab_idx];
                if st_type == 3 {
                    strtab_info = Some((st_off, st_sz));
                }
            }
            symtab_info = Some((sh_offset, sh_size, sh_entsize));
        }
        if sh_type == 3 && strtab_info.is_none() {
            // SHT_STRTAB: could be a standalone strtab linked via sh_info
            strtab_info = Some((sh_offset, sh_size));
        }
    }

    let (symtab_offset, symtab_size, symtab_entsize) = match symtab_info {
        Some(info) => info,
        None => return Ok(Vec::new()),
    };
    let (strtab_offset, strtab_size) = match strtab_info {
        Some(info) => info,
        None => return Ok(Vec::new()),
    };

    let entsize = if symtab_entsize > 0 {
        symtab_entsize as usize
    } else {
        24 // 默认 ELF64 符号条目大小
    };

    let symtab_off = symtab_offset as usize;
    let symtab_len = symtab_size as usize;
    if symtab_off + symtab_len > data.len() {
        return Ok(Vec::new());
    }
    let strtab_off = strtab_offset as usize;
    let strtab_len = strtab_size as usize;
    if strtab_off + strtab_len > data.len() {
        return Ok(Vec::new());
    }

    let symtab_bytes = &data[symtab_off..symtab_off + symtab_len];
    let strtab_bytes = &data[strtab_off..strtab_off + strtab_len];

    let n = symtab_len / entsize;
    let mut symbols = Vec::new();
    for i in 0..n {
        let entry = &symtab_bytes[i * entsize..(i + 1) * entsize];
        let st_name = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        // st_info at byte 4, st_other at byte 5, st_shndx at byte 6..8
        let st_value = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        // st_size at byte 16..24
        if st_name == 0 {
            continue;
        }
        let name_end = strtab_bytes[st_name as usize..]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(strtab_len - st_name as usize);
        let name =
            String::from_utf8(strtab_bytes[st_name as usize..st_name as usize + name_end].to_vec())
                .unwrap_or_default();
        if !name.is_empty() {
            symbols.push((name, st_value));
        }
    }
    Ok(symbols)
}

fn vaddr_to_file(data: &[u8], segments: &[ElfSegment], address: u64) -> Result<usize, DaotiError> {
    let segment = segments
        .iter()
        .find(|s| {
            s.type_ == PT_LOAD
                && address >= s.vaddr
                && address
                    .checked_sub(s.vaddr)
                    .and_then(|d| d.checked_add(1))
                    .is_some_and(|d| d <= s.filesz)
        })
        .ok_or_else(|| DaotiError::Other("重定位表不在可加载文件段内".into()))?;
    let offset = segment
        .offset
        .checked_add(address - segment.vaddr)
        .ok_or_else(|| DaotiError::Other("重定位表文件偏移溢出".into()))?;
    let index =
        usize::try_from(offset).map_err(|_| DaotiError::Other("重定位表文件偏移过大".into()))?;
    if index > data.len() {
        return Err(DaotiError::Other("重定位表文件偏移越界".into()));
    }
    Ok(index)
}

/// ELF 动态段条目（DT_*）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ElfDynamicEntry {
    /// 动态标签。
    pub tag: i64,
    /// 标签对应的数值或文件内偏移。
    pub value: u64,
}

/// 动态 ELF 的结构化验收 metadata；仅描述解析/规划结果，不代表入口已执行。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DynamicElfMetadata {
    pub file_type: String,
    pub architecture: String,
    pub entry: u64,
    pub load_bias: u64,
    pub relocated_entry: u64,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub load_segments: Vec<DynamicLoadSegment>,
    pub dynamic_entries: Vec<ElfDynamicEntry>,
    pub rela_count: u64,
    pub rel_count: u64,
    pub execution_verified: bool,
}

impl DynamicElfMetadata {
    pub fn from_plan(info: &ElfInfo, plan: &DynamicLoadPlan) -> Self {
        Self {
            file_type: info.file_type.clone(),
            architecture: info.arch.clone(),
            entry: info.entry,
            load_bias: plan.load_bias,
            relocated_entry: plan.relocated_entry,
            interpreter: plan.interpreter.clone(),
            needed: plan.needed.clone(),
            load_segments: plan.load_segments.clone(),
            dynamic_entries: plan.entries.clone(),
            rela_count: plan.rela.map_or(0, |(_, _, count)| count),
            rel_count: plan.rel.map_or(0, |(_, _, count)| count),
            execution_verified: false,
        }
    }
}

/// 结构化的 PT_LOAD 映射规划。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicLoadSegment {
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub mapped_start: u64,
    pub mapped_end: u64,
    pub flags: u32,
}

/// 动态依赖图中的一条边。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
}

/// PT_TLS 元数据。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsMetadata {
    pub vaddr: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

/// 动态 ELF 的基础装载规划。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicLoadPlan {
    /// 使最低 PT_LOAD 虚拟地址对齐到该地址后的装载偏移。
    pub load_bias: u64,
    /// 加载偏移应用到 ELF 入口点后的地址；仅表示规划结果，不执行。
    pub relocated_entry: u64,
    /// 结构化的 PT_LOAD 映射信息。
    pub load_segments: Vec<DynamicLoadSegment>,
    /// PT_TLS 元数据。
    pub tls: Option<TlsMetadata>,
    /// DT_NEEDED 声明形成的依赖边（当前节点到依赖库）。
    pub dependency_graph: Vec<DependencyEdge>,
    /// PT_INTERP 指定的动态链接器路径。
    pub interpreter: Option<String>,
    /// 动态段原始条目。
    pub entries: Vec<ElfDynamicEntry>,
    /// DT_NEEDED 声明的依赖库名称，按声明顺序去重。
    pub needed: Vec<String>,
    /// 动态字符串表虚拟地址。
    pub strtab: Option<u64>,
    /// 动态符号表虚拟地址。
    pub symtab: Option<u64>,
    /// RELA 表虚拟地址、条目大小和条目数量。
    pub rela: Option<(u64, u64, u64)>,
    /// REL 表虚拟地址、条目大小和条目数量。
    pub rel: Option<(u64, u64, u64)>,
    /// RELR 压缩相对重定位表虚拟地址、条目大小和条目数量。
    pub relr: Option<(u64, u64, u64)>,
    /// PLT 重定位表虚拟地址、条目大小和条目数量（DT_JMPREL/DT_PLTRELSZ）。
    pub jmprel: Option<(u64, u64, u64, bool)>,
}

pub fn plan_dynamic_load(data: &[u8], preferred_base: u64) -> Result<DynamicLoadPlan, DaotiError> {
    let info = parse_elf_from_bytes(data)?;
    if !info.is_64 || info.arch != "x86_64" || info.file_type != "ET_DYN（共享库/动态可执行）"
    {
        return Err(DaotiError::Unavailable(
            "动态装载第一阶段仅支持 x86_64 ET_DYN".into(),
        ));
    }
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(data[56..58].try_into().unwrap()) as usize;
    let mut lowest = u64::MAX;
    let mut dynamic = None;
    let mut interpreter = None;
    let mut tls = None;
    for index in 0..phnum {
        let off = phoff
            .checked_add(
                index
                    .checked_mul(ELF64_PHENTSIZE)
                    .ok_or_else(|| DaotiError::Other("Program header 偏移溢出".into()))?,
            )
            .ok_or_else(|| DaotiError::Other("Program header 偏移溢出".into()))?;
        let end = off
            .checked_add(ELF64_PHENTSIZE)
            .ok_or_else(|| DaotiError::Other("Program header 边界溢出".into()))?;
        if end > data.len() {
            return Err(DaotiError::Other("Program header 超出文件边界".into()));
        }
        let tag = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let offset = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
        let vaddr = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
        let filesz = u64::from_le_bytes(data[off + 32..off + 40].try_into().unwrap());
        let memsz = u64::from_le_bytes(data[off + 40..off + 48].try_into().unwrap());
        let align = u64::from_le_bytes(data[off + 48..off + 56].try_into().unwrap());
        match tag {
            PT_LOAD => lowest = lowest.min(vaddr),
            PT_TLS => {
                tls = Some(TlsMetadata {
                    vaddr,
                    file_offset: offset,
                    file_size: filesz,
                    memory_size: memsz,
                    align,
                })
            }
            2 => dynamic = Some((offset, filesz)),
            3 => {
                let end = offset
                    .checked_add(filesz)
                    .ok_or_else(|| DaotiError::Other("PT_INTERP 边界溢出".into()))?
                    as usize;
                if end > data.len() {
                    return Err(DaotiError::Other("PT_INTERP 超出文件边界".into()));
                }
                let raw = &data[offset as usize..end];
                let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
                interpreter = Some(
                    String::from_utf8(raw[..length].to_vec())
                        .map_err(|_| DaotiError::Other("PT_INTERP 不是有效 UTF-8".into()))?,
                );
            }
            _ => {}
        }
    }
    if lowest == u64::MAX {
        return Err(DaotiError::Unavailable("ET_DYN 缺少 PT_LOAD".into()));
    }
    let (offset, size) =
        dynamic.ok_or_else(|| DaotiError::Unavailable("ET_DYN 缺少 PT_DYNAMIC".into()))?;
    if size % 16 != 0
        || offset
            .checked_add(size)
            .ok_or_else(|| DaotiError::Other("PT_DYNAMIC 边界溢出".into()))? as usize
            > data.len()
    {
        return Err(DaotiError::Other("PT_DYNAMIC 超出文件边界".into()));
    }
    let load_bias = preferred_base
        .checked_sub(lowest & !(PAGE_SIZE - 1))
        .ok_or_else(|| DaotiError::Other("动态 ELF load bias 下溢".into()))?;
    let relocated_entry = info
        .entry
        .checked_add(load_bias)
        .ok_or_else(|| DaotiError::Other("动态 ELF 重定位入口地址溢出".into()))?;
    let load_segments = info
        .segments
        .iter()
        .filter(|segment| segment.type_ == PT_LOAD)
        .map(|segment| {
            let raw_start = segment
                .vaddr
                .checked_add(load_bias)
                .ok_or_else(|| DaotiError::Other("PT_LOAD 映射起点溢出".into()))?;
            let mapped_start = align_down(raw_start, PAGE_SIZE);
            let raw_end = raw_start
                .checked_add(segment.memsz)
                .ok_or_else(|| DaotiError::Other("PT_LOAD 映射终点溢出".into()))?;
            let mapped_end = align_up(raw_end, PAGE_SIZE);
            Ok(DynamicLoadSegment {
                vaddr: segment.vaddr,
                file_offset: segment.offset,
                file_size: segment.filesz,
                memory_size: segment.memsz,
                mapped_start,
                mapped_end,
                flags: segment.flags,
            })
        })
        .collect::<Result<Vec<_>, DaotiError>>()?;
    let mut entries = Vec::new();
    for bytes in data[offset as usize..(offset + size) as usize]
        .as_chunks::<16>()
        .0
    {
        let tag = i64::from_le_bytes(bytes[..8].try_into().unwrap());
        let value = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        entries.push(ElfDynamicEntry { tag, value });
        if tag == 0 {
            break;
        }
    }
    let value_for = |tag: i64| {
        entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    };
    let strtab = value_for(5);
    let symtab = value_for(6);
    let rela_addr = value_for(7);
    let rela_size = value_for(8).unwrap_or(0);
    let rela_ent = value_for(9).unwrap_or(24);
    let rel_addr = value_for(17);
    let rel_size = value_for(18).unwrap_or(0);
    let rel_ent = value_for(19).unwrap_or(16);
    let relr_addr = value_for(36);
    let relr_size = value_for(35).unwrap_or(0);
    let relr_ent = value_for(37).unwrap_or(8);
    let plt_addr = value_for(23);
    let plt_size = value_for(2).unwrap_or(0);
    let plt_kind = value_for(20).unwrap_or(7);
    let plt_rela = match plt_kind {
        7 => true,
        17 => false,
        other => {
            return Err(DaotiError::Unavailable(format!(
                "不支持的 DT_PLTREL 类型：{other}"
            )))
        }
    };
    let jmprel = if let Some(address) = plt_addr {
        let entry_size = if plt_rela { rela_ent } else { rel_ent };
        if plt_size % entry_size != 0 {
            return Err(DaotiError::Other(
                "DT_PLTRELSZ 大小不是条目大小的整数倍".into(),
            ));
        }
        Some((address, entry_size, plt_size / entry_size, plt_rela))
    } else {
        None
    };
    let rela = if let Some(address) = rela_addr {
        if rela_ent != 24 {
            return Err(DaotiError::Other("x86_64 DT_RELA 条目大小错误".into()));
        }
        if rela_size % rela_ent != 0 {
            return Err(DaotiError::Other("DT_RELA 大小不是条目大小的整数倍".into()));
        }
        let count = rela_size / rela_ent;
        if count > usize::MAX as u64 {
            return Err(DaotiError::Other("DT_RELA 条目数量过大".into()));
        }
        Some((address, rela_ent, count))
    } else {
        None
    };
    let rel = if let Some(address) = rel_addr {
        if rel_ent != 16 {
            return Err(DaotiError::Other("x86_64 DT_REL 条目大小错误".into()));
        }
        if rel_size % rel_ent != 0 {
            return Err(DaotiError::Other("DT_REL 大小不是条目大小的整数倍".into()));
        }
        Some((address, rel_ent, rel_size / rel_ent))
    } else {
        None
    };
    let relr = relr_addr
        .map(|address| {
            if relr_ent != 8 || relr_size % relr_ent != 0 {
                return Err(DaotiError::Other("x86_64 DT_RELR 大小错误".into()));
            }
            Ok((address, relr_ent, relr_size / relr_ent))
        })
        .transpose()?;
    let mut needed = Vec::new();
    if let Some(strtab_addr) = strtab {
        for entry in entries.iter().filter(|entry| entry.tag == 1) {
            let name = read_dynamic_string(data, &info.segments, strtab_addr, entry.value)?;
            if !needed.iter().any(|item| item == &name) {
                needed.push(name);
            }
        }
    }
    let dependency_graph = needed
        .iter()
        .cloned()
        .map(|to| DependencyEdge {
            from: "<main>".to_string(),
            to,
        })
        .collect();
    Ok(DynamicLoadPlan {
        load_bias,
        relocated_entry,
        load_segments,
        tls,
        dependency_graph,
        interpreter,
        entries,
        needed,
        strtab,
        symtab,
        rela,
        rel,
        relr,
        jmprel,
    })
}

/// 受控动态依赖来源；实现只负责读取字节，不执行 ELF。
pub trait DynamicDependencySource {
    fn read(&self, path: &Path) -> Result<Vec<u8>, DaotiError>;
}

pub struct FileDynamicDependencySource;

impl DynamicDependencySource for FileDynamicDependencySource {
    fn read(&self, path: &Path) -> Result<Vec<u8>, DaotiError> {
        let mut file = File::open(path)
            .map_err(|e| DaotiError::Other(format!("无法打开依赖 {}：{e}", path.display())))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| DaotiError::Other(format!("读取依赖 {} 失败：{e}", path.display())))?;
        Ok(bytes)
    }
}

/// 以显式根目录解析 DT_NEEDED 的递归依赖图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicDependencyGraph {
    pub root: PathBuf,
    pub nodes: Vec<PathBuf>,
    pub edges: Vec<DependencyEdge>,
}

pub fn plan_dynamic_dependency_graph<S: DynamicDependencySource>(
    root: impl AsRef<Path>,
    allowed_roots: &[PathBuf],
    source: &S,
) -> Result<DynamicDependencyGraph, DaotiError> {
    let root = root.as_ref().to_path_buf();
    let allowed: Vec<PathBuf> = allowed_roots.iter().map(|p| normalize_path(p)).collect();
    let root = normalize_path(&root);
    if !allowed.iter().any(|base| root.starts_with(base)) {
        return Err(DaotiError::Unavailable(format!(
            "依赖根文件不在白名单路径内：{}",
            root.display()
        )));
    }
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    let mut stack = Vec::new();
    visit_dependency(
        &root,
        &allowed,
        source,
        &mut nodes,
        &mut edges,
        &mut visiting,
        &mut visited,
        &mut stack,
    )?;
    Ok(DynamicDependencyGraph { root, nodes, edges })
}

#[allow(clippy::too_many_arguments)]
fn visit_dependency<S: DynamicDependencySource>(
    path: &Path,
    allowed: &[PathBuf],
    source: &S,
    nodes: &mut Vec<PathBuf>,
    edges: &mut Vec<DependencyEdge>,
    visiting: &mut HashSet<PathBuf>,
    visited: &mut HashSet<PathBuf>,
    stack: &mut Vec<PathBuf>,
) -> Result<(), DaotiError> {
    let path = normalize_path(path);
    if !allowed.iter().any(|base| path.starts_with(base)) {
        return Err(DaotiError::Unavailable(format!(
            "依赖路径不在白名单内：{}",
            path.display()
        )));
    }
    if visiting.contains(&path) {
        stack.push(path.clone());
        return Err(DaotiError::Other(format!(
            "检测到 DT_NEEDED 循环依赖：{}",
            stack
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" -> ")
        )));
    }
    if !visited.insert(path.clone()) {
        return Ok(());
    }
    visiting.insert(path.clone());
    stack.push(path.clone());
    let bytes = source.read(&path).map_err(|e| {
        DaotiError::Other(format!(
            "DT_NEEDED 依赖 {}（父对象 {}）读取失败：{e}",
            path.display(),
            stack
                .get(stack.len().saturating_sub(2))
                .map_or_else(|| "未知".to_string(), |parent| parent.display().to_string())
        ))
    })?;
    let info = parse_elf_from_bytes(&bytes)
        .map_err(|e| DaotiError::Other(format!("解析依赖 {} 失败：{e}", path.display())))?;
    let lowest = info
        .segments
        .iter()
        .filter(|segment| segment.type_ == PT_LOAD)
        .map(|segment| segment.vaddr)
        .min()
        .ok_or_else(|| DaotiError::Other(format!("依赖 {} 缺少 PT_LOAD", path.display())))?;
    let plan = plan_dynamic_load(&bytes, lowest & !(PAGE_SIZE - 1))
        .map_err(|e| DaotiError::Other(format!("解析依赖 {} 失败：{e}", path.display())))?;
    nodes.push(path.clone());
    for name in plan.needed {
        let child = normalize_path(&path.parent().unwrap_or_else(|| Path::new(".")).join(&name));
        edges.push(DependencyEdge {
            from: path.display().to_string(),
            to: child.display().to_string(),
        });
        visit_dependency(
            &child, allowed, source, nodes, edges, visiting, visited, stack,
        )?;
    }
    stack.pop();
    visiting.remove(&path);
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn read_dynamic_string(
    data: &[u8],
    segments: &[ElfSegment],
    strtab_addr: u64,
    string_offset: u64,
) -> Result<String, DaotiError> {
    let virtual_address = strtab_addr
        .checked_add(string_offset)
        .ok_or_else(|| DaotiError::Other("动态字符串地址溢出".into()))?;
    let segment = segments
        .iter()
        .find(|segment| {
            segment.type_ == PT_LOAD
                && virtual_address >= segment.vaddr
                && virtual_address < segment.vaddr.saturating_add(segment.filesz)
        })
        .ok_or_else(|| DaotiError::Other("动态字符串不在可加载文件段内".into()))?;
    let file_offset = segment
        .offset
        .checked_add(virtual_address - segment.vaddr)
        .ok_or_else(|| DaotiError::Other("动态字符串文件偏移溢出".into()))?
        as usize;
    if file_offset >= data.len() {
        return Err(DaotiError::Other("动态字符串超出文件边界".into()));
    }
    let end = data[file_offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| file_offset + index)
        .unwrap_or(data.len());
    String::from_utf8(data[file_offset..end].to_vec())
        .map_err(|_| DaotiError::Other("动态字符串不是有效 UTF-8".into()))
}

/// ELF 加载段（Program Header 中的可加载段，`p_type == PT_LOAD`）
#[derive(Debug, Clone, PartialEq)]
pub struct ElfSegment {
    /// 段类型
    pub type_: u32,
    /// 段在文件中的偏移
    pub offset: u64,
    /// 加载到内存的虚拟地址
    pub vaddr: u64,
    /// 物理地址
    pub paddr: u64,
    /// 文件中的大小
    pub filesz: u64,
    /// 内存中的大小
    pub memsz: u64,
    /// 标志（PF_R=4, PF_W=2, PF_X=1）
    pub flags: u32,
    /// 对齐
    pub align: u64,
}

/// ELF 文件解析结果
#[derive(Debug, Clone, PartialEq)]
pub struct ElfInfo {
    /// 架构名称（如 "x86_64", "AArch64", "RISC-V"）
    pub arch: String,
    /// ELF 文件类型（可执行、共享库、可重定位目标文件）
    pub file_type: String,
    /// 入口点虚拟地址
    pub entry: u64,
    /// 程序头（段）数量
    pub ph_num: u16,
    /// 节头数量
    pub sh_num: u16,
    /// ABI 名称
    pub abi: String,
    /// 是否可执行文件（ET_EXEC 或 ET_DYN 且含 PT_LOAD 段）
    pub executable: bool,
    /// 64 位（true）或 32 位（false）
    pub is_64: bool,
    /// 加载段列表（仅 PT_LOAD 段）
    pub segments: Vec<ElfSegment>,
}

/// 从字节数据解析 ELF 文件
///
/// 纯函数，不读取文件系统。适合测试或从内存加载的 ELF。
pub fn parse_elf_from_bytes(data: &[u8]) -> Result<ElfInfo, DaotiError> {
    if data.len() < 16 {
        return Err(DaotiError::Other("数据太短，不足 ELF 标识头".into()));
    }

    // 校验魔数
    if data[0..4] != [0x7F, 0x45, 0x4C, 0x46] {
        return Err(DaotiError::Other("非 ELF 格式：魔数不匹配".into()));
    }

    let class = data[4]; // 1=32-bit, 2=64-bit
    let byte_order = data[5]; // 1=little-endian, 2=big-endian
    let abi_num = data[7];

    if class != 1 && class != 2 {
        return Err(DaotiError::Other(format!(
            "不支持的 ELF 类别：{}（应为 1=32-bit 或 2=64-bit）",
            class
        )));
    }

    if byte_order != 1 {
        return Err(DaotiError::Other(format!(
            "仅支持小端序（little-endian），当前字节序：{}",
            byte_order
        )));
    }

    let is_64 = class == 2;
    let (phoff, phnum, shnum, entry, e_type, e_machine) = if is_64 {
        if data.len() < ELF64_EHSIZE {
            return Err(DaotiError::Other("数据太短，不足 64 位 ELF header".into()));
        }
        let e_type_val = u16::from_le_bytes([data[16], data[17]]);
        let e_machine_val = u16::from_le_bytes([data[18], data[19]]);
        let entry_val = u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
        let phoff_val = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);
        let phnum_val = u16::from_le_bytes([data[56], data[57]]);
        let shnum_val = u16::from_le_bytes([data[60], data[61]]);
        (
            phoff_val,
            phnum_val,
            shnum_val,
            entry_val,
            e_type_val,
            e_machine_val,
        )
    } else {
        // 32-bit: 52 bytes header
        if data.len() < 52 {
            return Err(DaotiError::Other("数据太短，不足 32 位 ELF header".into()));
        }
        let e_type_val = u16::from_le_bytes([data[16], data[17]]);
        let e_machine_val = u16::from_le_bytes([data[18], data[19]]);
        let entry_val = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64;
        let phoff_val = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as u64;
        let phnum_val = u16::from_le_bytes([data[44], data[45]]);
        let shnum_val = u16::from_le_bytes([data[48], data[49]]);
        (
            phoff_val,
            phnum_val,
            shnum_val,
            entry_val,
            e_type_val,
            e_machine_val,
        )
    };

    let arch = match e_machine {
        0x00 => "无特定架构",
        0x02 => "SPARC",
        0x03 => "i386 (x86)",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC (64-bit)",
        0x28 => "ARM",
        0x2A => "SuperH",
        0x32 => "IA-64",
        0x3E => "x86_64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        _ => "未知架构",
    }
    .to_string();

    let file_type = match e_type {
        0 => "ET_NONE（无类型）",
        1 => "ET_REL（可重定位目标文件）",
        2 => "ET_EXEC（可执行文件）",
        3 => "ET_DYN（共享库/动态可执行）",
        4 => "ET_CORE（核心转储）",
        _ => "未知类型",
    }
    .to_string();

    let abi = match abi_num {
        0 => "UNIX System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        7 => "AIX",
        9 => "FreeBSD",
        10 => "Tru64",
        12 => "OpenBSD",
        13 => "OpenVMS",
        97 => "ARM EABI",
        255 => "Standalone",
        _ => "未知 ABI",
    }
    .to_string();

    let executable = e_type == 2 || (e_type == 3 && phnum > 0);

    // 解析 Program Headers（段表）
    let segments = if phnum > 0 && phoff > 0 {
        let ph_entry_size = if is_64 { ELF64_PHENTSIZE } else { 32usize };
        let ph_start = phoff as usize;
        let ph_end = ph_start + (phnum as usize) * ph_entry_size;
        if ph_end > data.len() {
            return Err(DaotiError::Other(format!(
                "Program header 表超出数据边界：偏移 {}，大小 {}，数据长度 {}",
                ph_start,
                phnum as usize * ph_entry_size,
                data.len()
            )));
        }
        let mut segs = Vec::with_capacity(phnum as usize);
        for i in 0..phnum as usize {
            let off = ph_start + i * ph_entry_size;
            if is_64 {
                let p_type =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                let p_flags = u32::from_le_bytes([
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                ]);
                let p_offset = u64::from_le_bytes([
                    data[off + 8],
                    data[off + 9],
                    data[off + 10],
                    data[off + 11],
                    data[off + 12],
                    data[off + 13],
                    data[off + 14],
                    data[off + 15],
                ]);
                let p_vaddr = u64::from_le_bytes([
                    data[off + 16],
                    data[off + 17],
                    data[off + 18],
                    data[off + 19],
                    data[off + 20],
                    data[off + 21],
                    data[off + 22],
                    data[off + 23],
                ]);
                let p_paddr = u64::from_le_bytes([
                    data[off + 24],
                    data[off + 25],
                    data[off + 26],
                    data[off + 27],
                    data[off + 28],
                    data[off + 29],
                    data[off + 30],
                    data[off + 31],
                ]);
                let p_filesz = u64::from_le_bytes([
                    data[off + 32],
                    data[off + 33],
                    data[off + 34],
                    data[off + 35],
                    data[off + 36],
                    data[off + 37],
                    data[off + 38],
                    data[off + 39],
                ]);
                let p_memsz = u64::from_le_bytes([
                    data[off + 40],
                    data[off + 41],
                    data[off + 42],
                    data[off + 43],
                    data[off + 44],
                    data[off + 45],
                    data[off + 46],
                    data[off + 47],
                ]);
                let p_align = u64::from_le_bytes([
                    data[off + 48],
                    data[off + 49],
                    data[off + 50],
                    data[off + 51],
                    data[off + 52],
                    data[off + 53],
                    data[off + 54],
                    data[off + 55],
                ]);
                segs.push(ElfSegment {
                    type_: p_type,
                    offset: p_offset,
                    vaddr: p_vaddr,
                    paddr: p_paddr,
                    filesz: p_filesz,
                    memsz: p_memsz,
                    flags: p_flags,
                    align: p_align,
                });
            } else {
                // 32-bit program header: 32 bytes
                let p_type =
                    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                let p_offset = u32::from_le_bytes([
                    data[off + 4],
                    data[off + 5],
                    data[off + 6],
                    data[off + 7],
                ]) as u64;
                let p_vaddr = u32::from_le_bytes([
                    data[off + 8],
                    data[off + 9],
                    data[off + 10],
                    data[off + 11],
                ]) as u64;
                let p_paddr = u32::from_le_bytes([
                    data[off + 12],
                    data[off + 13],
                    data[off + 14],
                    data[off + 15],
                ]) as u64;
                let p_filesz = u32::from_le_bytes([
                    data[off + 16],
                    data[off + 17],
                    data[off + 18],
                    data[off + 19],
                ]) as u64;
                let p_memsz = u32::from_le_bytes([
                    data[off + 20],
                    data[off + 21],
                    data[off + 22],
                    data[off + 23],
                ]) as u64;
                let p_flags = u32::from_le_bytes([
                    data[off + 24],
                    data[off + 25],
                    data[off + 26],
                    data[off + 27],
                ]);
                let p_align = u32::from_le_bytes([
                    data[off + 28],
                    data[off + 29],
                    data[off + 30],
                    data[off + 31],
                ]) as u64;
                segs.push(ElfSegment {
                    type_: p_type,
                    offset: p_offset,
                    vaddr: p_vaddr,
                    paddr: p_paddr,
                    filesz: p_filesz,
                    memsz: p_memsz,
                    flags: p_flags,
                    align: p_align,
                });
            }
        }
        segs
    } else {
        Vec::new()
    };

    Ok(ElfInfo {
        arch,
        file_type,
        entry,
        ph_num: phnum,
        sh_num: shnum,
        abi,
        executable,
        is_64,
        segments,
    })
}

/// 从文件路径解析 ELF 文件
///
/// 读取文件后委托 `parse_elf_from_bytes`。  
/// 错误：文件不存在、权限不足、非 ELF 格式。
pub fn parse_elf(path: &str) -> Result<ElfInfo, DaotiError> {
    let mut file =
        File::open(path).map_err(|e| DaotiError::Other(format!("无法打开文件 {path}：{e}")))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| DaotiError::Other(format!("读取文件 {path} 失败：{e}")))?;
    parse_elf_from_bytes(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── 构造最小 ELF 64-bit x86_64 可执行文件 ────────────────
    //
    // ELF header (64 bytes) + 1 个 PT_LOAD program header (56 bytes) = 120 bytes
    fn make_minimal_elf64() -> Vec<u8> {
        let mut buf = Vec::with_capacity(120);

        // e_ident[0..16]
        buf.extend_from_slice(&[0x7F, 0x45, 0x4C, 0x46]); // magic
        buf.push(2); // class: 64-bit
        buf.push(1); // data: little-endian
        buf.push(1); // version
        buf.push(0); // OS/ABI: UNIX System V
        buf.extend_from_slice(&[0u8; 8]); // padding

        // e_type: 2 = ET_EXEC
        buf.extend_from_slice(&2u16.to_le_bytes());
        // e_machine: 0x3E = x86_64
        buf.extend_from_slice(&0x003Eu16.to_le_bytes());
        // e_version: 1
        buf.extend_from_slice(&1u32.to_le_bytes());
        // e_entry: 0x400000
        buf.extend_from_slice(&0x400000u64.to_le_bytes());
        // e_phoff: 64 (header 之后紧跟 program header)
        buf.extend_from_slice(&64u64.to_le_bytes());
        // e_shoff: 0 (无 section header)
        buf.extend_from_slice(&0u64.to_le_bytes());
        // e_flags: 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // e_ehsize: 64
        buf.extend_from_slice(&64u16.to_le_bytes());
        // e_phentsize: 56
        buf.extend_from_slice(&56u16.to_le_bytes());
        // e_phnum: 1
        buf.extend_from_slice(&1u16.to_le_bytes());
        // e_shentsize: 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // e_shnum: 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // e_shstrndx: 0
        buf.extend_from_slice(&0u16.to_le_bytes());

        // 至此 64 bytes ELF header 完成

        // Program header: PT_LOAD
        buf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        buf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
        buf.extend_from_slice(&0u64.to_le_bytes()); // p_offset: 0
        buf.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
        buf.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
        buf.extend_from_slice(&4096u64.to_le_bytes()); // p_filesz
        buf.extend_from_slice(&4096u64.to_le_bytes()); // p_memsz
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

        buf
    }

    // ─── 构造最小 ELF 32-bit x86 可执行文件 ────────────────
    //
    // ELF header (52 bytes) + 1 个 PT_LOAD program header (32 bytes) = 84 bytes
    fn make_minimal_elf32() -> Vec<u8> {
        let mut buf = Vec::with_capacity(84);

        // e_ident[0..16]
        buf.extend_from_slice(&[0x7F, 0x45, 0x4C, 0x46]); // magic
        buf.push(1); // class: 32-bit
        buf.push(1); // data: little-endian
        buf.push(1); // version
        buf.push(0); // OS/ABI: UNIX System V
        buf.extend_from_slice(&[0u8; 8]); // padding

        // e_type: 2 = ET_EXEC
        buf.extend_from_slice(&2u16.to_le_bytes());
        // e_machine: 0x03 = i386
        buf.extend_from_slice(&0x0003u16.to_le_bytes());
        // e_version: 1
        buf.extend_from_slice(&1u32.to_le_bytes());
        // e_entry: 0x08048000
        buf.extend_from_slice(&0x08048000u32.to_le_bytes());
        // e_phoff: 52 (header 之后紧跟 program header)
        buf.extend_from_slice(&52u32.to_le_bytes());
        // e_shoff: 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // e_flags: 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // e_ehsize: 52
        buf.extend_from_slice(&52u16.to_le_bytes());
        // e_phentsize: 32
        buf.extend_from_slice(&32u16.to_le_bytes());
        // e_phnum: 1
        buf.extend_from_slice(&1u16.to_le_bytes());
        // e_shentsize: 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // e_shnum: 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        // e_shstrndx: 0
        buf.extend_from_slice(&0u16.to_le_bytes());

        // 52 bytes ELF header 完成

        // Program header: PT_LOAD 32-bit (32 bytes)
        buf.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
        buf.extend_from_slice(&0u32.to_le_bytes()); // p_offset: 0
        buf.extend_from_slice(&0x08048000u32.to_le_bytes()); // p_vaddr
        buf.extend_from_slice(&0x08048000u32.to_le_bytes()); // p_paddr
        buf.extend_from_slice(&4096u32.to_le_bytes()); // p_filesz
        buf.extend_from_slice(&4096u32.to_le_bytes()); // p_memsz
        buf.extend_from_slice(&5u32.to_le_bytes()); // p_flags: PF_R | PF_X
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align

        buf
    }

    // ─── 测试 ───

    fn write_temp_elf(name: &str, data: &[u8]) -> String {
        let path = std::env::temp_dir().join(format!("daoti_{name}_{}.elf", std::process::id()));
        std::fs::write(&path, data).unwrap_or_else(|e| panic!("写入临时 ELF 失败：{e}"));
        path.to_string_lossy().into_owned()
    }

    fn remove_temp_elf(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    fn make_runnable_elf64() -> Vec<u8> {
        let mut data = make_minimal_elf64();
        data[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        data[64 + 8..64 + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        data[64 + 32..64 + 40].copy_from_slice(&12u64.to_le_bytes());
        data[64 + 40..64 + 48].copy_from_slice(&12u64.to_le_bytes());
        data.resize(0x100c, 0);
        data[0x1000..0x100c]
            .copy_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, 0x90, 0x90, 0x90]);
        data
    }

    #[test]
    fn test_execute_elf_file_runs_static_x86_64() {
        let path = write_temp_elf("runnable", &make_runnable_elf64());
        let state = execute_elf_file(&path, 4096).unwrap_or_else(|e| panic!("执行失败：{e}"));
        remove_temp_elf(&path);
        assert_eq!(state, ExecutionState::Exited(0));
    }

    #[test]
    fn test_execute_elf_file_rejects_dynamic() {
        let mut data = make_runnable_elf64();
        data[16..18].copy_from_slice(&3u16.to_le_bytes());
        let path = write_temp_elf("dynamic", &data);
        let err = execute_elf_file(&path, 4096).unwrap_err();
        remove_temp_elf(&path);
        assert!(format!("{err}").contains("静态 ET_EXEC"));
    }

    #[test]
    fn test_execute_elf_file_rejects_non_x86_64() {
        let mut data = make_runnable_elf64();
        data[18..20].copy_from_slice(&0xb7u16.to_le_bytes());
        let path = write_temp_elf("aarch64", &data);
        let err = execute_elf_file(&path, 4096).unwrap_err();
        remove_temp_elf(&path);
        assert!(format!("{err}").contains("仅支持 x86_64"));
    }

    #[test]
    fn test_execute_elf_file_rejects_missing_entry() {
        let mut data = make_runnable_elf64();
        data[24..32].fill(0);
        let path = write_temp_elf("no_entry", &data);
        let err = execute_elf_file(&path, 4096).unwrap_err();
        remove_temp_elf(&path);
        assert!(format!("{err}").contains("缺失有效入口点"));
    }

    #[test]
    fn test_parse_elf64_x86_64() {
        let data = make_minimal_elf64();
        let info = parse_elf_from_bytes(&data).unwrap_or_else(|e| panic!("解析失败：{e}"));
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.entry, 0x400000);
        assert!(info.is_64);
        assert!(info.executable);
        assert_eq!(info.ph_num, 1);
        assert_eq!(info.sh_num, 0);
        assert_eq!(info.abi, "UNIX System V");
        assert_eq!(info.file_type, "ET_EXEC（可执行文件）");
        assert_eq!(info.segments.len(), 1);
        assert_eq!(info.segments[0].type_, PT_LOAD);
        assert_eq!(info.segments[0].vaddr, 0x400000);
        assert_eq!(info.segments[0].flags, PF_R | PF_X);
    }

    #[test]
    fn test_parse_elf32_i386() {
        let data = make_minimal_elf32();
        let info = parse_elf_from_bytes(&data).unwrap_or_else(|e| panic!("解析失败：{e}"));
        assert_eq!(info.arch, "i386 (x86)");
        assert_eq!(info.entry, 0x08048000);
        assert!(!info.is_64);
        assert!(info.executable);
        assert_eq!(info.ph_num, 1);
        assert_eq!(info.sh_num, 0);
        assert_eq!(info.abi, "UNIX System V");
        assert_eq!(info.segments.len(), 1);
        assert_eq!(info.segments[0].type_, PT_LOAD);
    }

    #[test]
    fn test_reject_non_elf_magic() {
        // 16 字节但魔数不匹配
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // 魔数错误（应为 7F 45 4C 46）
            0x02, 0x01, 0x01, 0x00, // class, data, version, ABI
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
        ];
        let err = parse_elf_from_bytes(&data).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("非 ELF 格式"),
            "错误信息应指示非 ELF 格式，得到：{msg}"
        );
    }

    #[test]
    fn test_reject_short_data() {
        let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02]; // 只有 5 bytes
        let err = parse_elf_from_bytes(&data).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("太短"), "应提示数据太短，得到：{msg}");
    }

    #[test]
    fn test_reject_unsupported_class() {
        let mut data = vec![0x7F, 0x45, 0x4C, 0x46];
        data.push(0xFF); // class: 255 (不支持)
        data.push(1); // little-endian
        data.push(1); // version
        data.push(0); // ABI
        data.extend_from_slice(&[0u8; 8]); // padding
        let err = parse_elf_from_bytes(&data).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("不支持"), "应提示不支持的类别，得到：{msg}");
    }

    #[test]
    fn test_parse_elf_shared_library() {
        // 构造 ET_DYN (type=3) 的 ELF64
        let mut buf: Vec<u8> = make_minimal_elf64();
        // e_type 在偏移 16-17
        buf[16] = 3; // ET_DYN
        buf[17] = 0;
        // 保留 phnum=1，所以 executable 应为 true
        let info = parse_elf_from_bytes(&buf).unwrap_or_else(|e| panic!("解析失败：{e}"));
        assert_eq!(info.file_type, "ET_DYN（共享库/动态可执行）");
        assert!(info.executable, "ET_DYN 含 PT_LOAD 段应视为可执行");
    }

    #[test]
    fn test_parse_elf_with_big_endian_rejected() {
        let mut data = vec![0x7F, 0x45, 0x4C, 0x46];
        data.push(2); // class: 64-bit
        data.push(2); // data: big-endian（不支持）
        data.push(1); // version
        data.push(0); // ABI
        data.extend_from_slice(&[0u8; 8]); // padding
        let err = parse_elf_from_bytes(&data).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("小端序"), "应提示仅支持小端序，得到：{msg}");
    }

    #[test]
    fn test_parse_elf_aarch64() {
        // 构造 AArch64 ET_EXEC
        let mut buf = make_minimal_elf64();
        // e_machine 在偏移 18-19
        buf[18] = 0xB7; // EM_AARCH64
        buf[19] = 0x00;
        let info = parse_elf_from_bytes(&buf).unwrap_or_else(|e| panic!("解析失败：{e}"));
        assert_eq!(info.arch, "AArch64");
    }

    #[test]
    fn test_parse_elf_riscv() {
        let mut buf = make_minimal_elf64();
        buf[18] = 0xF3; // EM_RISCV
        buf[19] = 0x00;
        let info = parse_elf_from_bytes(&buf).unwrap_or_else(|e| panic!("解析失败：{e}"));
        assert_eq!(info.arch, "RISC-V");
    }

    #[test]
    fn test_parse_elf_file_not_found() {
        let err = parse_elf("/tmp/__nonexistent_elf_file__").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("无法打开"), "应提示无法打开文件，得到：{msg}");
    }

    #[test]
    fn test_parse_elf_from_file_roundtrip() {
        // 使用 tempfile 测试文件路径解析
        let dir = std::env::temp_dir();
        let path = dir.join("test_elf_roundtrip.bin");
        let data = make_minimal_elf64();
        std::fs::write(&path, &data).unwrap_or_else(|e| panic!("写入临时文件失败：{e}"));
        let info =
            parse_elf(&path.to_string_lossy()).unwrap_or_else(|e| panic!("文件解析失败：{e}"));
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.entry, 0x400000);
        // 清理
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_elf_loader_builds_image() {
        let data = make_minimal_elf64();
        let info = parse_elf_from_bytes(&data).unwrap_or_else(|e| panic!("解析失败：{e}"));
        let loader = ElfLoader::new(info).unwrap_or_else(|e| panic!("创建加载器失败：{e}"));
        let image = loader
            .build_image(&data)
            .unwrap_or_else(|e| panic!("构建镜像失败：{e}"));
        assert_eq!(image.entry, 0x400000);
        assert_eq!(image.base, 0x400000);
        assert_eq!(image.segments.len(), 1);
        assert_eq!(image.segments[0].bytes.len(), 4096);
    }

    #[test]
    fn test_elf_loader_builds_runtime_context() {
        let data = make_minimal_elf64();
        let context = ElfLoader::build_runtime_context_from_bytes(&data, 8192)
            .unwrap_or_else(|e| panic!("构造运行时失败：{e}"));
        assert_eq!(context.entry, 0x400000);
        assert_eq!(context.registers.general.rip, 0x400000);
        assert_eq!(context.stack_ptr, 0x403000);
        // 3 个区域：代码段 + 栈 + 堆
        assert_eq!(context.memory.regions.len(), 3);
        assert_eq!(context.memory.regions[0].perm, MemPerm::rx());
        assert_eq!(context.memory.regions[1].perm, MemPerm::rw());
        assert_eq!(
            context.memory.read(0x400000, 4).unwrap(),
            &[0x7f, 0x45, 0x4c, 0x46]
        );
        assert!(context.memory.is_executable(0x400000));
        assert!(!context.memory.is_executable(context.stack_ptr - 1));
        assert_eq!(context.memory.read(context.stack_ptr - 1, 1).unwrap(), &[0]);
    }

    #[test]
    fn test_elf_loader_rejects_zero_sized_stack() {
        let data = make_minimal_elf64();
        let err = ElfLoader::build_runtime_context_from_bytes(&data, 0).unwrap_err();
        assert!(format!("{err}").contains("安全栈大小"));
    }

    #[test]
    fn test_elf_loader_pads_bss() {
        let mut data = make_minimal_elf64();
        // 将程序头里的文件大小改小于内存大小，触发 BSS 填充
        let ph_filesz_offset = 64 + 32;
        let ph_memsz_offset = 64 + 40;
        data[ph_filesz_offset..ph_filesz_offset + 8].copy_from_slice(&16u64.to_le_bytes());
        data[ph_memsz_offset..ph_memsz_offset + 8].copy_from_slice(&32u64.to_le_bytes());
        let info = parse_elf_from_bytes(&data).unwrap_or_else(|e| panic!("解析失败：{e}"));
        let loader = ElfLoader::new(info).unwrap_or_else(|e| panic!("创建加载器失败：{e}"));
        let image = loader
            .build_image(&data)
            .unwrap_or_else(|e| panic!("构建镜像失败：{e}"));
        assert_eq!(image.segments[0].bytes.len(), 32);
        assert!(image.segments[0].bytes[16..].iter().all(|b| *b == 0));
    }

    // ─── 真实 x86_64 ELF 构造与执行测试 ──────────────────────
    //
    // 构造一个真实的 x86_64 ELF 可执行文件，使用 mov/lea/mov/syscall 实现
    // write(1, "Hello World\n", 13) + exit_group(0)。

    use std::sync::{Arc, Mutex};

    /// 内存缓冲区输出接收器，用于捕获 write syscall 的输出。
    #[derive(Clone, Default)]
    struct BufferSink(Arc<Mutex<Vec<u8>>>);

    impl super::syscall_bridge::OutputSink for BufferSink {
        fn write_all(&mut self, data: &[u8]) -> Result<(), daoti_common::DaotiError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(data);
            Ok(())
        }
    }

    /// 构造一个输出"Hello World\n"并退出码 0 的真实 x86_64 ELF。
    ///
    /// 汇编指令序列（Intel 语法）：
    /// ```asm
    /// mov rdi, 1        ; fd = stdout
    /// lea rsi, [rip + 0x20] ; buf = "Hello World\n" 的地址
    /// mov rdx, 13       ; count
    /// mov rax, 1        ; SYS_write
    /// syscall
    /// mov rdi, 0        ; exit_code
    /// mov rax, 231      ; SYS_exit_group
    /// syscall
    /// ; 偏移 0x2e 处："Hello World\n"
    /// ```
    fn make_hello_elf64() -> Vec<u8> {
        // x86_64 机器码：mov rdi, 1 → 48 c7 c7 01 00 00 00
        // lea rsi, [rip + 0x20] → 48 8d 35 20 00 00 00
        // mov rdx, 12 → 48 c7 c2 0c 00 00 00
        // mov rax, 1 (SYS_write) → 48 c7 c0 01 00 00 00
        // syscall → 0f 05
        // mov rdi, 0 → 48 c7 c7 00 00 00 00
        // mov rax, 231 (SYS_exit_group) → 48 c7 c0 e7 00 00 00
        // syscall → 0f 05
        let code: [u8; 46] = [
            0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
            0x48, 0x8d, 0x35, 0x20, 0x00, 0x00, 0x00, // lea rsi, [rip + 0x20]
            0x48, 0xc7, 0xc2, 0x0c, 0x00, 0x00, 0x00, // mov rdx, 12
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (SYS_write)
            0x0f, 0x05, // syscall
            0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00, // mov rdi, 0
            0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // mov rax, 231 (SYS_exit_group)
            0x0f, 0x05, // syscall
        ];
        let msg = b"Hello World\n";
        let payload_len = code.len() + msg.len(); // 46 + 13 = 59

        let mut data = make_minimal_elf64();
        // p_offset = 0x1000（代码和数据放在文件偏移 0x1000 处）
        data[64 + 8..64 + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        // p_filesz = 实际载荷大小（不含零填充）
        data[64 + 32..64 + 40].copy_from_slice(&(payload_len as u64).to_le_bytes());
        // p_memsz = 一页（4096），剩余部分为零填充（BSS）
        data[64 + 40..64 + 48].copy_from_slice(&0x1000u64.to_le_bytes());

        data.resize(0x1000 + payload_len, 0);
        data[0x1000..0x1000 + code.len()].copy_from_slice(&code);
        data[0x1000 + code.len()..0x1000 + payload_len].copy_from_slice(msg);

        data
    }

    fn make_dynamic_fixture(needed: &[&str], rela_count: usize) -> Vec<u8> {
        let mut data = make_minimal_elf64();
        data[16..18].copy_from_slice(&3u16.to_le_bytes());
        data[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        data[56..58].copy_from_slice(&2u16.to_le_bytes());
        data[64 + 32..64 + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        data.resize(64 + 2 * 56, 0);
        let ph = 64 + 56;
        data[ph..ph + 4].copy_from_slice(&2u32.to_le_bytes());
        data[ph + 8..ph + 16].copy_from_slice(&0x200u64.to_le_bytes());
        data[ph + 16..ph + 24].copy_from_slice(&0x400200u64.to_le_bytes());
        data[ph + 32..ph + 40].copy_from_slice(&0x100u64.to_le_bytes());
        data[ph + 40..ph + 48].copy_from_slice(&0x100u64.to_le_bytes());
        data.extend(std::iter::repeat_n(
            0,
            0x1000usize.saturating_sub(data.len()),
        ));
        let mut strings = vec![0u8];
        let mut offsets = Vec::new();
        for name in needed {
            offsets.push(strings.len() as u64);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let strtab = 0x300usize;
        data.resize(0x1000, 0);
        data[strtab..strtab + strings.len()].copy_from_slice(&strings);
        let dynamic = 0x200usize;
        let mut entries = vec![
            (5i64, 0x400300u64),
            (7, 0x400380),
            (8, (rela_count * 24) as u64),
            (9, 24),
        ];
        entries.extend(offsets.into_iter().map(|offset| (1, offset)));
        entries.push((0, 0));
        for (index, (tag, value)) in entries.into_iter().enumerate() {
            let at = dynamic + index * 16;
            data[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            data[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        let rela = 0x380usize;
        for index in 0..rela_count {
            let at = rela + index * 24;
            data[at..at + 8].copy_from_slice(&(0x5000 + index as u64 * 8).to_le_bytes());
            data[at + 8..at + 16].copy_from_slice(&((8u64 << 32) | 8).to_le_bytes());
            data[at + 16..at + 24].copy_from_slice(&(index as i64 - 1).to_le_bytes());
        }
        data
    }

    #[test]
    fn test_dynamic_plan_reads_needed_and_rela_metadata() {
        let plan = plan_dynamic_load(
            &make_dynamic_fixture(&["liba.so", "libb.so", "liba.so"], 2),
            0x500000,
        )
        .unwrap();
        assert_eq!(plan.needed, ["liba.so", "libb.so"]);
        assert_eq!(plan.rela, Some((0x400380, 24, 2)));
    }

    #[test]
    fn test_dynamic_rela_entries_decode_addends() {
        let data = make_dynamic_fixture(&[], 2);
        let info = parse_elf_from_bytes(&data).unwrap();
        let plan = plan_dynamic_load(&data, 0x500000).unwrap();
        let entries = read_dynamic_relocations(&data, &info, &plan).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].addend, Some(-1));
        assert_eq!(entries[1].addend, Some(0));
    }

    #[test]
    fn test_dynamic_rela_zero_count_is_empty() {
        assert!(read_dynamic_relocations(
            &make_dynamic_fixture(&[], 0),
            &parse_elf_from_bytes(&make_dynamic_fixture(&[], 0)).unwrap(),
            &plan_dynamic_load(&make_dynamic_fixture(&[], 0), 0x500000).unwrap()
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn test_dynamic_needed_order_is_preserved() {
        let p = plan_dynamic_load(&make_dynamic_fixture(&["z.so", "a.so"], 0), 0x500000).unwrap();
        assert_eq!(p.needed, ["z.so", "a.so"]);
    }

    #[test]
    fn test_dynamic_rela_bad_entry_size_rejected() {
        let mut d = make_dynamic_fixture(&[], 1);
        d[0x230 + 8..0x230 + 16].copy_from_slice(&16u64.to_le_bytes());
        let e = plan_dynamic_load(&d, 0x500000)
            .and_then(|p| read_dynamic_relocations(&d, &parse_elf_from_bytes(&d)?, &p))
            .unwrap_err();
        assert!(format!("{e}").contains("条目大小"));
    }

    #[test]
    fn test_dynamic_rela_file_boundary_rejected() {
        let mut d = make_dynamic_fixture(&[], 1);
        d[0x210 + 8..0x210 + 16].copy_from_slice(&0x400ff0u64.to_le_bytes());
        let e = plan_dynamic_load(&d, 0x500000)
            .and_then(|p| read_dynamic_relocations(&d, &parse_elf_from_bytes(&d)?, &p))
            .unwrap_err();
        assert!(format!("{e}").contains("文件边界"), "实际错误：{e}");
    }

    #[test]
    fn test_dynamic_needed_invalid_string_offset_rejected() {
        let mut d = make_dynamic_fixture(&["ok.so"], 0);
        d[0x240 + 8..0x240 + 16].copy_from_slice(&0xffffu64.to_le_bytes());
        assert!(plan_dynamic_load(&d, 0x500000).is_err());
    }

    #[test]
    fn test_dynamic_rela_overflow_count_rejected() {
        let mut d = make_dynamic_fixture(&[], 0);
        d[0x220 + 8..0x220 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(plan_dynamic_load(&d, 0x500000).is_err());
    }

    #[test]
    fn test_dynamic_missing_dynamic_segment_rejected() {
        let mut d = make_minimal_elf64();
        d[16..18].copy_from_slice(&3u16.to_le_bytes());
        assert!(plan_dynamic_load(&d, 0x500000).is_err());
    }

    #[test]
    fn test_dynamic_load_bias_underflow_rejected() {
        // load_bias = preferred_base - lowest_vaddr：当 preferred_base 低于
        // 最低 PT_LOAD 虚拟地址时必须显式报错，不得回绕成超大地址。
        let d = make_dynamic_fixture(&[], 0);
        // make_dynamic_fixture 的 PT_LOAD vaddr 起点为 0x400000。
        let error = plan_dynamic_load(&d, 0x300000).unwrap_err();
        assert!(
            format!("{error}").contains("load bias 下溢"),
            "preferred_base 低于最低段地址时必须报 load bias 下溢：{error}"
        );
    }

    #[test]
    fn test_dynamic_truncated_rela_rejected() {
        let mut d = make_dynamic_fixture(&[], 1);
        d.truncate(0x380 + 23);
        let p = plan_dynamic_load(&d, 0x500000).unwrap();
        let e = read_dynamic_relocations(&d, &parse_elf_from_bytes(&d).unwrap(), &p).unwrap_err();
        assert!(format!("{e}").contains("文件边界"));
    }

    #[test]
    fn test_real_x86_64_elf_hello_world() {
        let elf_data = make_hello_elf64();
        if let Some(path) = std::env::var_os("DAOTI_WRITE_STATIC_ELF_FIXTURE") {
            std::fs::write(path, &elf_data).expect("写入静态 ELF fixture 失败");
        }
        let sink = BufferSink::default();
        let output = sink.0.clone();

        let state = execute_elf_with_sink(&elf_data, 8192, sink)
            .unwrap_or_else(|e| panic!("execute_elf_with_sink 失败：{e}"));

        // 断言退出码为 0
        assert_eq!(
            state,
            ExecutionState::Exited(0),
            "预期退出码 0，实际状态：{state:?}"
        );

        // 断言捕获的输出为 "Hello World\n"
        let captured = output.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            captured.as_slice(),
            b"Hello World\n",
            "预期输出 'Hello World\\n'，实际输出：{:?}",
            String::from_utf8_lossy(captured.as_slice())
        );
    }
}
