//! PE 解析器 (daoti-core::parser::pe)
//!
//! 封装已有 PE 解析能力，输出统一的 `BinaryInfo` 格式。
//! 对应《本地二进制信号重映射主路线施工计划》P0 格式解析。
//!
//! 当前通过魔数检测 + 最小 PE 头部解析提供基本信息。
//! 完整 PE 解析（节表、导入表、导出表等）为后续扩展。

// 格式常量用于文档化 PE 格式规范，编译器不检查死代码
#![allow(dead_code)]

use super::{BinaryInfo, BinaryType, CpuArch, SegmentDesc};
use crate::elf::runtime::{
    ExecutionState, MemPerm, MemoryModel, MemoryRegion, RuntimeContext, RuntimeSyscallEvent,
    SyscallHandler, X86_64Interpreter,
};
use daoti_common::DaotiError;

/// PE32+ 数据目录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

type PeLayout = (usize, usize, Vec<(u32, u32, u32, u32)>, usize);

/// PE32+ 导入项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImport {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
}

/// 解析后的最小 IAT 绑定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeIatBinding {
    pub dll: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
    pub address: u64,
}

/// 由宿主提供的 DLL/符号地址解析器。
pub trait PeImportResolver {
    fn resolve(&self, dll: &str, name: Option<&str>, ordinal: Option<u16>) -> Option<u64>;
}

/// PE 控制台竖切提供的最小 Windows API 地址表。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeApiAddressMap {
    pub write_file: u64,
    pub write_console_a: u64,
    pub write_console_w: u64,
    pub get_std_handle: u64,
    pub get_console_mode: u64,
    pub set_console_mode: u64,
    pub exit_process: u64,
}

impl Default for PeApiAddressMap {
    fn default() -> Self {
        Self {
            write_file: 0x7fff_0000,
            write_console_a: 0x7fff_0010,
            write_console_w: 0x7fff_0018,
            get_std_handle: 0x7fff_0020,
            get_console_mode: 0x7fff_0028,
            set_console_mode: 0x7fff_0030,
            exit_process: 0x7fff_0008,
        }
    }
}

impl PeImportResolver for PeApiAddressMap {
    fn resolve(&self, dll: &str, name: Option<&str>, _ordinal: Option<u16>) -> Option<u64> {
        let dll = normalize_dll_name(dll);
        let name = name?.trim().to_ascii_lowercase();
        match (dll.as_str(), name.as_str()) {
            ("kernel32.dll" | "kernelbase.dll", "writefile") => Some(self.write_file),
            ("kernel32.dll" | "kernelbase.dll", "writeconsolea") => Some(self.write_console_a),
            ("kernel32.dll" | "kernelbase.dll", "writeconsolew") => Some(self.write_console_w),
            ("kernel32.dll" | "kernelbase.dll", "getstdhandle") => Some(self.get_std_handle),
            ("kernel32.dll" | "kernelbase.dll", "getconsolemode") => Some(self.get_console_mode),
            ("kernel32.dll" | "kernelbase.dll", "setconsolemode") => Some(self.set_console_mode),
            ("kernel32.dll" | "kernelbase.dll", "exitprocess") => Some(self.exit_process),
            ("ntdll.dll", "ntwritefile") => Some(self.write_file),
            ("ntdll.dll", "rtlexituserprocess") => Some(self.exit_process),
            _ => None,
        }
    }
}

fn decode_write_console_w(wide: &[u8]) -> Result<Vec<u8>, DaotiError> {
    if !wide.len().is_multiple_of(2) {
        return Err(DaotiError::Other(
            "WriteConsoleW UTF-16 数据长度非法".into(),
        ));
    }
    let units = wide
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map(String::into_bytes)
        .map_err(|_| DaotiError::Other("WriteConsoleW UTF-16 数据非法".into()))
}

fn normalize_dll_name(dll: &str) -> String {
    let trimmed = dll.trim().trim_matches('\0');
    let basename = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed);
    let lower = basename.to_ascii_lowercase();
    if lower.ends_with(".dll") {
        lower
    } else {
        format!("{lower}.dll")
    }
}

/// 将 PE32+ 导入项解析为可写入 IAT 的宿主地址。
pub fn resolve_pe32_plus_imports<R: PeImportResolver>(
    data: &[u8],
    resolver: &R,
) -> Result<Vec<PeIatBinding>, DaotiError> {
    let parsed = parse_pe32_plus(data)?;
    parsed
        .imports
        .into_iter()
        .map(|import| {
            let address = resolver
                .resolve(&import.dll, import.name.as_deref(), import.ordinal)
                .ok_or_else(|| {
                    parse_err(format!(
                        "未解析 PE 导入: {}!{}",
                        import.dll,
                        import.name.as_deref().unwrap_or("<ordinal>")
                    ))
                })?;
            Ok(PeIatBinding {
                dll: import.dll,
                name: import.name,
                ordinal: import.ordinal,
                iat_rva: import.iat_rva,
                address,
            })
        })
        .collect()
}

/// PE32+ 基址重定位项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeRelocation {
    pub page_rva: u32,
    pub offset: u16,
    pub kind: u16,
}

/// PE32+ 纯解析模型（不包含执行器）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pe32Plus {
    pub image_base: u64,
    pub data_directories: Vec<PeDataDirectory>,
    pub imports: Vec<PeImport>,
    pub relocations: Vec<PeRelocation>,
}

/// PE32+ 的纯逻辑装载计划，不分配内存、不复制字节、不执行入口点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pe32PlusImageLoadPlan {
    pub image_base: u64,
    pub load_base: u64,
    pub size_of_image: u32,
    pub entry_rva: u32,
    pub entry_address: u64,
    pub sections: Vec<Pe32PlusSectionMapping>,
    pub relocations: Vec<Pe32PlusRelocationPatch>,
}

/// 一个节从文件映射到镜像地址空间的描述。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pe32PlusSectionMapping {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub file_offset: u32,
    pub file_size: u32,
}

/// 一项需要由真正装载器应用的 DIR64 重定位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pe32PlusRelocationPatch {
    pub rva: u32,
    pub kind: u16,
    pub delta: i64,
}

/// 根据已解析的 PE32+ 头部生成纯逻辑 image load plan。
/// 该函数只校验和计算地址，不执行 PE，也不触碰可执行内存。
pub fn plan_pe32_plus_image_load(
    data: &[u8],
    load_base: Option<u64>,
) -> Result<Pe32PlusImageLoadPlan, DaotiError> {
    let (pe, opt, sections, opt_size) = pe_layout(data)?;
    if u16_at(data, opt)? != PE32_PLUS_MAGIC || opt_size < 112 {
        return Err(parse_err("不是完整 PE32+"));
    }
    let image_base = u64_at(data, opt + 24)?;
    let entry_rva = u32_at(data, opt + 16)?;
    let size_of_image = u32_at(data, opt + 56)?;
    if size_of_image == 0 || entry_rva >= size_of_image {
        return Err(parse_err("入口点或镜像大小非法"));
    }
    let load_base = load_base.unwrap_or(image_base);
    let delta = load_base as i128 - image_base as i128;
    if delta < i64::MIN as i128 || delta > i64::MAX as i128 {
        return Err(parse_err("重定位差值溢出"));
    }
    let mut mappings = Vec::with_capacity(sections.len());
    for (index, &(virtual_size, rva, raw_size, raw_ptr)) in sections.iter().enumerate() {
        let end = (rva as u64)
            .checked_add(virtual_size.max(raw_size) as u64)
            .ok_or_else(|| parse_err("节地址溢出"))?;
        if end > size_of_image as u64 || raw_size > 0 {
            range(data, raw_ptr as usize, raw_size as usize)?;
        }
        let name_at = opt + opt_size + index * 40;
        let name_bytes = range(data, name_at, 8)?;
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_len]).into_owned();
        mappings.push(Pe32PlusSectionMapping {
            name,
            rva,
            virtual_size,
            file_offset: raw_ptr,
            file_size: raw_size,
        });
    }
    let parsed = parse_pe32_plus(data)?;
    let relocations = parsed
        .relocations
        .into_iter()
        .map(|r| {
            Ok(Pe32PlusRelocationPatch {
                rva: r
                    .page_rva
                    .checked_add(r.offset as u32)
                    .ok_or_else(|| parse_err("重定位 RVA 溢出"))?,
                kind: r.kind,
                delta: delta as i64,
            })
        })
        .collect::<Result<Vec<_>, DaotiError>>()?;
    let _ = pe;
    Ok(Pe32PlusImageLoadPlan {
        image_base,
        load_base,
        size_of_image,
        entry_rva,
        entry_address: load_base
            .checked_add(entry_rva as u64)
            .ok_or_else(|| parse_err("入口地址溢出"))?,
        sections: mappings,
        relocations,
    })
}

/// 解析 PE32+ 的数据目录、导入表和基址重定位。
pub fn parse_pe32_plus(data: &[u8]) -> Result<Pe32Plus, DaotiError> {
    let (pe, opt, sections, size) = pe_layout(data)?;
    if u16_at(data, opt)? != PE32_PLUS_MAGIC || size < 112 {
        return Err(parse_err("不是完整 PE32+"));
    }
    let image_base = u64_at(data, opt + 24)?;
    let dir_count = u32_at(data, opt + 108)? as usize;
    if dir_count > 16
        || opt
            .checked_add(112)
            .and_then(|v| v.checked_add(dir_count.checked_mul(8)?))
            .is_none_or(|e| e > opt + size)
    {
        return Err(parse_err("数据目录超出可选头"));
    }
    let mut dirs = Vec::with_capacity(dir_count);
    for i in 0..dir_count {
        let p = opt + 112 + i * 8;
        dirs.push(PeDataDirectory {
            virtual_address: u32_at(data, p)?,
            size: u32_at(data, p + 4)?,
        });
    }
    let imports = parse_imports(data, dirs.get(1).copied(), &sections)?;
    let relocations = parse_relocations(data, dirs.get(5).copied(), &sections)?;
    let _ = pe;
    Ok(Pe32Plus {
        image_base,
        data_directories: dirs,
        imports,
        relocations,
    })
}

fn parse_err(s: impl Into<String>) -> DaotiError {
    DaotiError::ParseError(s.into())
}
fn range(data: &[u8], at: usize, len: usize) -> Result<&[u8], DaotiError> {
    let end = at.checked_add(len).ok_or_else(|| parse_err("偏移溢出"))?;
    data.get(at..end)
        .ok_or_else(|| parse_err("结构超出文件范围"))
}
fn u16_at(d: &[u8], p: usize) -> Result<u16, DaotiError> {
    Ok(u16::from_le_bytes(range(d, p, 2)?.try_into().unwrap()))
}
fn u32_at(d: &[u8], p: usize) -> Result<u32, DaotiError> {
    Ok(u32::from_le_bytes(range(d, p, 4)?.try_into().unwrap()))
}
fn u64_at(d: &[u8], p: usize) -> Result<u64, DaotiError> {
    Ok(u64::from_le_bytes(range(d, p, 8)?.try_into().unwrap()))
}
fn pe_layout(d: &[u8]) -> Result<PeLayout, DaotiError> {
    if d.len() < 0x40 || &d[..2] != b"MZ" {
        return Err(parse_err("非 PE 文件"));
    }
    let pe = u32_at(d, 0x3c)? as usize;
    range(d, pe, 24)?;
    if u32_at(d, pe)? != PE_MAGIC {
        return Err(parse_err("PE signature 不匹配"));
    }
    let n = u16_at(d, pe + 6)? as usize;
    let opt = pe.checked_add(24).ok_or_else(|| parse_err("偏移溢出"))?;
    let size = u16_at(d, pe + 20)? as usize;
    range(d, opt, size)?;
    let mut s = Vec::new();
    let base = opt.checked_add(size).ok_or_else(|| parse_err("偏移溢出"))?;
    for i in 0..n {
        let p = base
            .checked_add(i.checked_mul(40).ok_or_else(|| parse_err("偏移溢出"))?)
            .ok_or_else(|| parse_err("偏移溢出"))?;
        range(d, p, 40)?;
        s.push((
            u32_at(d, p + 8)?,
            u32_at(d, p + 12)?,
            u32_at(d, p + 16)?,
            u32_at(d, p + 20)?,
        ));
    }
    Ok((pe, opt, s, size))
}
fn rva_file(
    d: &[u8],
    rva: u32,
    len: usize,
    s: &[(u32, u32, u32, u32)],
) -> Result<usize, DaotiError> {
    for &(vs, va, raw, ptr) in s {
        let span = vs.max(raw);
        if rva >= va && (rva - va) as u64 + len as u64 <= span as u64 {
            let p = (ptr as usize)
                .checked_add((rva - va) as usize)
                .ok_or_else(|| parse_err("文件偏移溢出"))?;
            range(d, p, len)?;
            return Ok(p);
        }
    }
    Err(parse_err("RVA 无对应文件范围"))
}
fn cstr(d: &[u8], p: usize) -> Result<String, DaotiError> {
    let end = d[p..]
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| parse_err("字符串未终止"))?;
    String::from_utf8(d[p..p + end].to_vec()).map_err(|_| parse_err("字符串不是 UTF-8"))
}
fn parse_imports(
    d: &[u8],
    dir: Option<PeDataDirectory>,
    s: &[(u32, u32, u32, u32)],
) -> Result<Vec<PeImport>, DaotiError> {
    let Some(x) = dir else { return Ok(Vec::new()) };
    if x.virtual_address == 0 || x.size == 0 {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut p = rva_file(d, x.virtual_address, 20, s)?;
    let dir_end = p
        .checked_add(x.size as usize)
        .ok_or_else(|| parse_err("导入表大小溢出"))?;
    range(d, p, x.size as usize)?;
    loop {
        if p.checked_add(20).is_none_or(|end| end > dir_end) {
            return Err(parse_err("导入表缺少终止项"));
        }
        let b = range(d, p, 20)?;
        if b.iter().all(|&v| v == 0) {
            break;
        }
        let oft = u32::from_le_bytes(b[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(b[12..16].try_into().unwrap());
        let ft = u32::from_le_bytes(b[16..20].try_into().unwrap());
        let dll = cstr(d, rva_file(d, name_rva, 1, s)?)?;
        let thunk = if oft != 0 { oft } else { ft };
        let mut q = rva_file(d, thunk, 8, s)?;
        loop {
            let v = u64_at(d, q)?;
            if v == 0 {
                break;
            }
            if v >> 63 != 0 {
                out.push(PeImport {
                    dll: dll.clone(),
                    name: None,
                    ordinal: Some(v as u16),
                    iat_rva: ft + (q - rva_file(d, thunk, 8, s)?) as u32,
                });
            } else {
                let n = cstr(d, rva_file(d, v as u32 + 2, 1, s)?)?;
                out.push(PeImport {
                    dll: dll.clone(),
                    name: Some(n),
                    ordinal: None,
                    iat_rva: ft + (q - rva_file(d, thunk, 8, s)?) as u32,
                });
            }
            q = q
                .checked_add(8)
                .ok_or_else(|| parse_err("导入 thunk 偏移溢出"))?;
        }
        p = p
            .checked_add(20)
            .ok_or_else(|| parse_err("导入表偏移溢出"))?;
        if p >= d.len() {
            return Err(parse_err("导入表缺少终止项"));
        }
    }
    Ok(out)
}
fn parse_relocations(
    d: &[u8],
    dir: Option<PeDataDirectory>,
    s: &[(u32, u32, u32, u32)],
) -> Result<Vec<PeRelocation>, DaotiError> {
    let Some(x) = dir else { return Ok(Vec::new()) };
    if x.virtual_address == 0 || x.size == 0 {
        return Ok(Vec::new());
    };
    let mut p = rva_file(d, x.virtual_address, 8, s)?;
    let end = p
        .checked_add(x.size as usize)
        .ok_or_else(|| parse_err("重定位大小溢出"))?;
    range(d, p, x.size as usize)?;
    let mut o = Vec::new();
    while p < end {
        let page = u32_at(d, p)?;
        let sz = u16_at(d, p + 4)? as usize;
        if sz < 8 || p + sz > end {
            return Err(parse_err("重定位块非法"));
        }
        for i in 0..(sz - 8) / 2 {
            let v = u16_at(d, p + 8 + i * 2)?;
            if v >> 12 != 0 {
                o.push(PeRelocation {
                    page_rva: page,
                    offset: v & 0xfff,
                    kind: v >> 12,
                });
            }
        }
        p += sz;
    }
    Ok(o)
}

/// PE 常量
const PE_MAGIC: u32 = 0x00004550; // "PE\0\0"
const PE32_PLUS_MAGIC: u16 = 0x20B; // PE32+
const PE32_MAGIC: u16 = 0x10B; // PE32

/// 从字节流解析 PE 并转为统一 BinaryInfo
/// 控制台竖切执行结果。仅支持解释器已实现的 x86_64 指令和最小退出/stdout shim。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeConsoleExecution {
    pub state: ExecutionState,
    pub stdout: Vec<u8>,
}

struct PeConsoleShim {
    stdout: Vec<u8>,
    exit_code: Option<i32>,
}

impl SyscallHandler for PeConsoleShim {
    fn handle(&mut self, event: &RuntimeSyscallEvent) -> Result<i64, DaotiError> {
        if event.nr == 1 {
            return Ok(event.args[2] as i64);
        }
        if matches!(event.nr, 0x100..=0x104) {
            return Ok(0);
        }
        if event.nr != 60 {
            return Err(DaotiError::Other(format!(
                "PE 控制台 shim 未支持 syscall/API: {}",
                event.name
            )));
        }
        self.exit_code = Some(event.args[0] as i32);
        Ok(0)
    }

    fn handle_with_memory(
        &mut self,
        event: &RuntimeSyscallEvent,
        memory: &mut MemoryModel,
    ) -> Result<i64, DaotiError> {
        if matches!(event.nr, 0x100..=0x104) {
            if event.nr == 0x100 || event.nr == 0x101 {
                let count = usize::try_from(event.args[2])
                    .map_err(|_| DaotiError::Other("控制台输出长度超出平台范围".into()))?;
                let bytes = if event.nr == 0x100 {
                    memory.read(event.args[1], count as u64)?.to_vec()
                } else {
                    let byte_len = count
                        .checked_mul(2)
                        .ok_or_else(|| DaotiError::Other("WriteConsoleW 长度溢出".into()))?;
                    let wide = memory.read(event.args[1], byte_len as u64)?;
                    decode_write_console_w(wide)?
                };
                self.stdout.extend_from_slice(&bytes);
                return Ok(count as i64);
            }
            return Ok(0);
        }
        if event.nr == 1 {
            let count = usize::try_from(event.args[2])
                .map_err(|_| DaotiError::Other("stdout 长度超出平台范围".into()))?;
            let bytes = memory.read(event.args[1], count as u64)?;
            self.stdout.extend_from_slice(bytes);
            // Windows WriteFile ABI：除返回 TRUE 外，还需把实际写入字节数写回
            // lpNumberOfBytesWritten（位于 r9 = Linux syscall 的 args[5]，stub 未改动）。
            let written_ptr = event.args[5];
            if written_ptr != 0 {
                memory.write(written_ptr, &(count as u32).to_le_bytes())?;
            }
            return Ok(count as i64);
        }
        self.handle(event)
    }

    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    fn captured_stdout(&self) -> Vec<u8> {
        self.stdout.clone()
    }

    fn capture_stdout(
        &mut self,
        memory: &mut MemoryModel,
        stdout_addr: u64,
    ) -> Result<(), DaotiError> {
        let mut addr = stdout_addr;
        for _ in 0..1_048_576 {
            let byte = memory.read(addr, 1)?[0];
            if byte == 0 {
                break;
            }
            self.stdout.push(byte);
            addr = addr
                .checked_add(1)
                .ok_or_else(|| DaotiError::Other("stdout 地址溢出".into()))?;
        }
        Ok(())
    }
}

/// 按 PE32+ load plan 映射镜像并运行控制台最小竖切。
/// 导入表仅被解析；除退出和 stdout 外的 Windows API 均明确不支持。
pub fn execute_pe32_plus_console(
    data: &[u8],
    load_base: Option<u64>,
) -> Result<PeConsoleExecution, DaotiError> {
    let plan = plan_pe32_plus_image_load(data, load_base)?;
    let parsed = parse_pe32_plus(data)?;
    let unsupported: Vec<String> = parsed
        .imports
        .iter()
        .filter_map(|import| import.name.clone())
        .filter(|name| {
            !matches!(
                name.as_str(),
                "WriteFile"
                    | "WriteConsoleA"
                    | "WriteConsoleW"
                    | "GetStdHandle"
                    | "GetConsoleMode"
                    | "SetConsoleMode"
                    | "ExitProcess"
            )
        })
        .collect();
    if !unsupported.is_empty() {
        return Err(DaotiError::Unavailable(format!(
            "PE 控制台执行不支持的 CRT/API：{}；解析成功不等于执行成功",
            unsupported.join(", ")
        )));
    }
    let mut memory = MemoryModel::new(
        plan.load_base,
        plan.load_base
            .checked_add(plan.size_of_image as u64 + 0x30000)
            .ok_or_else(|| DaotiError::Other("PE 地址空间溢出".into()))?,
    );
    for section in &plan.sections {
        let size = section.virtual_size.max(section.file_size).max(0x1000) as usize;
        if size == 0 {
            continue;
        }
        let mut bytes = vec![0u8; size];
        if section.file_size != 0 {
            let raw = range(
                data,
                section.file_offset as usize,
                section.file_size as usize,
            )?;
            bytes[..raw.len()].copy_from_slice(raw);
        }
        let perm = if section.name == ".text" {
            MemPerm::rx()
        } else if section.name == ".data" || section.name == ".rdata" {
            MemPerm::rw()
        } else {
            MemPerm::rwx()
        };
        memory.add_region(MemoryRegion::with_data(
            plan.load_base + section.rva as u64,
            perm,
            bytes,
        ))?;
    }
    let shim_base = plan
        .load_base
        .checked_add(plan.size_of_image as u64)
        .and_then(|value| value.checked_add(0x1000 - 1))
        .map(|value| value & !(0x1000 - 1))
        .ok_or_else(|| DaotiError::Other("PE shim 地址溢出".into()))?;
    let api_map = PeApiAddressMap {
        write_file: shim_base,
        write_console_a: shim_base + 0x1000,
        write_console_w: shim_base + 0x2000,
        get_std_handle: shim_base + 0x3000,
        get_console_mode: shim_base + 0x4000,
        set_console_mode: shim_base + 0x5000,
        exit_process: shim_base + 0x6000,
    };
    for binding in resolve_pe32_plus_imports(data, &api_map)? {
        memory.write(
            plan.load_base + binding.iat_rva as u64,
            &binding.address.to_le_bytes(),
        )?;
    }
    for patch in &plan.relocations {
        if patch.kind != 10 {
            return Err(DaotiError::Unavailable(format!(
                "PE32+ 不支持的重定位类型: {}",
                patch.kind
            )));
        }
        let address = plan
            .load_base
            .checked_add(patch.rva as u64)
            .ok_or_else(|| DaotiError::Other("重定位地址溢出".into()))?;
        let current = u64::from_le_bytes(memory.read(address, 8)?.try_into().unwrap());
        let relocated = (current as i128)
            .checked_add(patch.delta as i128)
            .filter(|value| (0..=u64::MAX as i128).contains(value))
            .ok_or_else(|| DaotiError::Other("重定位值溢出".into()))?
            as u64;
        memory.write(address, &relocated.to_le_bytes())?;
    }
    // 每个 API shim 占用完整一页并间隔一页：解释器单次取指窗口为若干字节，
    // 若 stub 区域过短，执行到 stub 尾部时取指会越过区域边界而失败。
    let one_page_stub = |mut stub: Vec<u8>| {
        stub.resize(0x1000, 0x90); // 0x90 = nop
        stub
    };
    let write_file_stub = vec![
        0xb8, 1, 0, 0, 0, 0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6, 0x4c, 0x89, 0xc2, 0x0f, 0x05, 0xc3,
    ];
    memory.add_region(MemoryRegion::with_data(
        api_map.write_file,
        MemPerm::rwx(),
        one_page_stub(write_file_stub),
    ))?;
    for (address, nr) in [
        (api_map.write_console_a, 0x100u32),
        (api_map.write_console_w, 0x101),
        (api_map.get_std_handle, 0x102),
        (api_map.get_console_mode, 0x103),
        (api_map.set_console_mode, 0x104),
    ] {
        let mut stub = vec![0xb8];
        stub.extend_from_slice(&nr.to_le_bytes());
        stub.extend_from_slice(&[0x0f, 0x05, 0xc3]);
        memory.add_region(MemoryRegion::with_data(
            address,
            MemPerm::rwx(),
            one_page_stub(stub),
        ))?;
    }
    memory.add_region(MemoryRegion::with_data(
        api_map.exit_process,
        MemPerm::rwx(),
        one_page_stub(vec![0xb8, 60, 0, 0, 0, 0x89, 0xcf, 0x0f, 0x05, 0xc3]),
    ))?;
    let stack = memory.mmap_anonymous_private(0x10000, MemPerm::rw())?;
    // 与 ELF 路径一致：初始 RSP 上方保留一页 headroom。
    // Windows x64 入口代码会按正偏移（shadow space/返回地址槽/参数区）访问栈，
    // 若把 RSP 顶到区域上界，[rsp+0x40] 等访问会越过栈区而失败。
    let stack_pointer = stack
        .checked_add(0x10000 - 0x1000)
        .ok_or_else(|| DaotiError::Other("PE 栈地址溢出".into()))?;
    let context = RuntimeContext::new(plan.entry_address, stack_pointer, memory);
    let mut interpreter =
        X86_64Interpreter::new(context).with_syscall_handler(Box::new(PeConsoleShim {
            stdout: Vec::new(),
            exit_code: None,
        }));
    let state = interpreter.run()?;
    let stdout = interpreter.captured_stdout();
    Ok(PeConsoleExecution { state, stdout })
}

pub fn parse_pe(data: &[u8]) -> Result<BinaryInfo, DaotiError> {
    if data.len() < 256 {
        return Err(DaotiError::ParseError("PE 文件过短".into()));
    }

    // DOS header: e_magic at [0..2] should be "MZ"
    if data[0] != b'M' || data[1] != b'Z' {
        return Err(DaotiError::ParseError("非 PE 格式：DOS 魔数不匹配".into()));
    }

    // e_lfanew at [0x3C..0x40] = 偏移到 PE signature
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
    let pe_offset = e_lfanew as usize;
    if pe_offset + 24 > data.len() {
        return Err(DaotiError::ParseError(
            "PE signature 偏移超出文件范围".into(),
        ));
    }

    // PE signature: "PE\0\0"
    let sig = u32::from_le_bytes([
        data[pe_offset],
        data[pe_offset + 1],
        data[pe_offset + 2],
        data[pe_offset + 3],
    ]);
    if sig != PE_MAGIC {
        return Err(DaotiError::ParseError(
            "非 PE 格式：PE signature 不匹配".into(),
        ));
    }

    // COFF header (20 bytes)
    let coff = pe_offset + 4;
    let machine = u16::from_le_bytes([data[coff], data[coff + 1]]);
    let num_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]);
    let characteristics = u16::from_le_bytes([data[coff + 18], data[coff + 19]]);

    // Optional header (紧随 COFF header)
    let opt_offset = coff + 20;
    if opt_offset + 2 > data.len() {
        return Err(DaotiError::ParseError(
            "PE optional header 超出文件范围".into(),
        ));
    }
    let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let is_pe32_plus = opt_magic == PE32_PLUS_MAGIC;

    // 架构
    let arch = match machine {
        0x8664 => CpuArch::X86_64,
        0x14C => CpuArch::X86,
        0xAA64 => CpuArch::Arm64,
        _ => CpuArch::Unknown(machine as u32),
    };

    // 入口点
    let entry_point = if is_pe32_plus {
        if opt_offset + 24 + 8 > data.len() {
            return Err(DaotiError::ParseError(
                "PE32+ optional header 不完整".into(),
            ));
        }
        // PE32+: AddressOfEntryPoint at opt_offset + 24 (跳过 magic+2, major+1, minor+1, size+4, entry+4, entry+4)
        // PE32+ struct: 16 bytes fields, then AddressOfEntryPoint at offset 24
        u64::from(u32::from_le_bytes([
            data[opt_offset + 24],
            data[opt_offset + 25],
            data[opt_offset + 26],
            data[opt_offset + 27],
        ]))
    } else {
        if opt_offset + 16 + 8 > data.len() {
            return Err(DaotiError::ParseError("PE32 optional header 不完整".into()));
        }
        // PE32: AddressOfEntryPoint at opt_offset + 16
        u64::from(u32::from_le_bytes([
            data[opt_offset + 16],
            data[opt_offset + 17],
            data[opt_offset + 18],
            data[opt_offset + 19],
        ]))
    };

    // 判断是否为 DLL
    // characteristics bit 0x2000 = IMAGE_FILE_DLL
    let is_dll = (characteristics & 0x2000) != 0;
    // characteristics bit 0x2002 = IMAGE_FILE_EXECUTABLE_IMAGE
    let is_executable = (characteristics & 0x0002) != 0;

    let mut info = BinaryInfo::new(BinaryType::Pe, arch, entry_point);
    info.is_dynamic = is_dll || is_executable;

    // 解析节表（Section Table）
    // Section table 紧跟在 optional header 之后
    let opt_header_size = if is_pe32_plus {
        // PE32+ 标准大小：112 bytes (16+68+28)
        // 实际大小由 SizeOfOptionalHeader 字段决定
        112usize
    } else {
        // PE32 标准大小：96 bytes (16+68+12)
        96usize
    };

    let section_offset = opt_offset + opt_header_size;
    let section_entry_size = 40usize; // IMAGE_SECTION_HEADER

    for i in 0..num_sections as usize {
        let so = section_offset + i * section_entry_size;
        if so + 40 > data.len() {
            break;
        }

        // 节名称（8 字节，不足补 0）
        let name_end = so + 8;
        let name_bytes = &data[so..name_end];
        let name = String::from_utf8_lossy(
            &name_bytes[..name_bytes.iter().position(|&b| b == 0).unwrap_or(8)],
        )
        .to_string();

        // 虚拟大小 + 虚拟地址
        let virtual_size =
            u32::from_le_bytes([data[so + 8], data[so + 9], data[so + 10], data[so + 11]]);
        let virtual_address =
            u32::from_le_bytes([data[so + 12], data[so + 13], data[so + 14], data[so + 15]]);
        // 原始数据大小 + 原始数据偏移
        let size_of_raw =
            u32::from_le_bytes([data[so + 16], data[so + 17], data[so + 18], data[so + 19]]);
        let pointer_to_raw =
            u32::from_le_bytes([data[so + 20], data[so + 21], data[so + 22], data[so + 23]]);
        // 特征
        let characteristics_flags =
            u32::from_le_bytes([data[so + 36], data[so + 37], data[so + 38], data[so + 39]]);

        let seg = SegmentDesc {
            name: name.clone(),
            vaddr: virtual_address as u64,
            file_offset: pointer_to_raw as u64,
            file_size: size_of_raw as u64,
            mem_size: virtual_size as u64,
            flags: characteristics_flags,
        };
        info.segments.push(seg);
    }

    info.header_bytes = data[..pe_offset + 4].to_vec();

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_console_w_decodes_utf16_and_rejects_errors() {
        assert_eq!(
            decode_write_console_w(&[0x48, 0x00, 0x69, 0x00]).unwrap(),
            b"Hi"
        );
        assert!(decode_write_console_w(&[0x00]).is_err());
        assert!(decode_write_console_w(&[0x00, 0xd8]).is_err());
    }

    #[test]
    fn test_minimal_windows_api_map() {
        let map = PeApiAddressMap::default();
        assert_eq!(
            map.resolve("KERNEL32.DLL", Some("WriteFile"), None),
            Some(map.write_file)
        );
        assert_eq!(
            map.resolve("ntdll.dll", Some("RtlExitUserProcess"), None),
            Some(map.exit_process)
        );
        assert_eq!(map.resolve("user32.dll", Some("MessageBoxA"), None), None);
    }

    #[test]
    fn test_reject_non_pe() {
        let result = parse_pe(b"\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(result.is_err(), "非 PE 数据应被拒绝");
    }

    #[test]
    fn test_reject_short_data() {
        let result = parse_pe(b"MZ");
        assert!(result.is_err(), "过短数据应被拒绝");
    }

    #[test]
    fn test_pe32_plus_rejects_truncated_directory() {
        let mut data = vec![0u8; 256];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        data[134..136].copy_from_slice(&0u16.to_le_bytes());
        data[148..150].copy_from_slice(&112u16.to_le_bytes());
        data[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
        data[256 - 1] = 16;
        assert!(parse_pe32_plus(&data).is_err(), "截断的数据目录应被拒绝");
    }

    #[test]
    fn test_minimal_pe_structure() {
        // 构造一个最小 PE 文件结构（仅用于测试解析器，不可执行）
        let data = create_minimal_pe();
        let info = parse_pe(&data).expect("最小 PE 应可解析");
        assert_eq!(info.binary_type, BinaryType::Pe);
        // PE 总是可执行或 DLL，所以 is_dynamic 应为 true
        assert!(info.is_dynamic);
    }

    #[test]
    fn test_execute_self_contained_pe_fixture() {
        let data = create_self_contained_pe_fixture();
        let result = execute_pe32_plus_console(&data, None).expect("自包含 PE 必须通过解释器执行");
        assert_eq!(result.stdout, b"Hello, PE!\n");
        assert_eq!(result.state, ExecutionState::Exited(0));
    }

    fn create_self_contained_pe_fixture() -> Vec<u8> {
        let image_base = 0x1400_0000_0u64;
        let pe_offset = 0x80usize;
        let section_raw = 0x200usize;
        let section_rva = 0x1000u32;
        let mut data = vec![0u8; section_raw + 0x700];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        data[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

        let coff = pe_offset + 4;
        data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&0xf0u16.to_le_bytes());
        data[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        data[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        data[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        data[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        data[opt + 60..opt + 64].copy_from_slice(&(section_raw as u32).to_le_bytes());
        data[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        data[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        // IMAGE_DIRECTORY_ENTRY_IMPORT
        data[opt + 112 + 8..opt + 112 + 12].copy_from_slice(&0x1200u32.to_le_bytes());
        data[opt + 112 + 12..opt + 112 + 16].copy_from_slice(&0x40u32.to_le_bytes());

        let section = opt + 0xf0;
        data[section..section + 8].copy_from_slice(b".peall\0\0");
        data[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section + 12..section + 16].copy_from_slice(&section_rva.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0x600u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&(section_raw as u32).to_le_bytes());
        data[section + 36..section + 40].copy_from_slice(&0xe0000020u32.to_le_bytes());

        let at = |rva: usize| section_raw + (rva - section_rva as usize);
        let mut code = vec![
            0x48, 0x83, 0xec, 0x28, // sub rsp, 40h
            0xb9, 0xf5, 0xff, 0xff, 0xff, // mov ecx, STD_OUTPUT_HANDLE
            0xff, 0x15, 0, 0, 0, 0, // call [GetStdHandle]
            0x48, 0x89, 0xc1, // mov rcx, rax
            0x48, 0x8d, 0x15, 0, 0, 0, 0, // lea rdx, message
            0x41, 0xb8, 11, 0, 0, 0, // mov r8d, 11
            0x4c, 0x8d, 0x0d, 0, 0, 0, 0, // lea r9, written
            0xff, 0x15, 0, 0, 0, 0, // call [WriteFile]
            0x31, 0xc9, // xor ecx, ecx
            0xff, 0x15, 0, 0, 0, 0, // call [ExitProcess]
            0xcc,
        ];
        let next = |offset: usize| 0x1000u32 + offset as u32;
        let patch_call = |bytes: &mut [u8], offset: usize, target_rva: u32| {
            let next_rip = next(offset + 6);
            bytes[offset + 2..offset + 6]
                .copy_from_slice(&((target_rva as i64 - next_rip as i64) as i32).to_le_bytes());
        };
        patch_call(&mut code, 9, 0x1280);
        let lea_msg_offset = 18usize;
        code[lea_msg_offset + 3..lea_msg_offset + 7].copy_from_slice(
            &((0x11c0i64 - i64::from(next(lea_msg_offset + 7))) as i32).to_le_bytes(),
        );
        let lea_written_offset = 31usize;
        code[lea_written_offset + 3..lea_written_offset + 7].copy_from_slice(
            &((0x11cci64 - i64::from(next(lea_written_offset + 7))) as i32).to_le_bytes(),
        );
        patch_call(&mut code, 38, 0x1288);
        patch_call(&mut code, 46, 0x1290);
        data[at(0x1000)..at(0x1000) + code.len()].copy_from_slice(&code);

        data[at(0x1200)..at(0x1200) + 4].copy_from_slice(&0x1240u32.to_le_bytes());
        data[at(0x1200) + 12..at(0x1200) + 16].copy_from_slice(&0x1260u32.to_le_bytes());
        data[at(0x1200) + 16..at(0x1200) + 20].copy_from_slice(&0x1280u32.to_le_bytes());
        for rva in [0x1240usize, 0x1280usize] {
            let entries = [0x12b0u64, 0x1270u64, 0x12a0u64, 0];
            for (index, entry) in entries.iter().enumerate() {
                let target = rva + index * 8;
                data[at(target)..at(target) + 8].copy_from_slice(&entry.to_le_bytes());
            }
        }
        data[at(0x1260)..at(0x1260) + 13].copy_from_slice(b"kernel32.dll\0");
        // IMAGE_IMPORT_BY_NAME：Hint(2 字节) + 名称 + 终止符。
        let mut write_import_name = |rva: usize, name: &[u8]| {
            let base = at(rva);
            data[base..base + 2].copy_from_slice(&0u16.to_le_bytes());
            let body = name.strip_suffix(b"\0").unwrap_or(name);
            data[base + 2..base + 2 + body.len()].copy_from_slice(body);
        };
        write_import_name(0x1270, b"WriteFile\0");
        write_import_name(0x12a0, b"ExitProcess\0");
        write_import_name(0x12b0, b"GetStdHandle\0");
        data[at(0x11c0)..at(0x11c0) + 11].copy_from_slice(b"Hello, PE!\n");
        data[at(0x11cc)..at(0x11cc) + 4].copy_from_slice(&0u32.to_le_bytes());
        data
    }

    fn create_minimal_pe() -> Vec<u8> {
        // DOS header: 64 bytes
        let mut buf = vec![0u8; 256];
        buf[0] = b'M';
        buf[1] = b'Z';

        // e_lfanew at 0x3C
        let pe_offset: u32 = 128; // PE signature 在偏移 128 处
        buf[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature at offset 128
        let pe_start = 128usize;
        buf[pe_start..pe_start + 4].copy_from_slice(b"PE\0\0");

        // COFF header at offset 132
        let coff = pe_start + 4;
        // machine: x86_64 (0x8664)
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        // number of sections: 1
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        // time date stamp: 0
        buf[coff + 4..coff + 8].copy_from_slice(&0u32.to_le_bytes());
        // pointer to symbol table: 0
        buf[coff + 8..coff + 12].copy_from_slice(&0u32.to_le_bytes());
        // number of symbols: 0
        buf[coff + 12..coff + 16].copy_from_slice(&0u32.to_le_bytes());
        // size of optional header: 0 (最小)
        buf[coff + 16..coff + 18].copy_from_slice(&0u16.to_le_bytes());
        // characteristics: executable (0x0002)
        buf[coff + 18..coff + 20].copy_from_slice(&0x0002u16.to_le_bytes());

        buf
    }
}
