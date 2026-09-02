//! Mach-O 解析器 (daoti-core::parser::macho)
//!
//! Mach-O 完整格式解析：支持 fat/universal header、32/64 位 Mach-O、
//! 所有主要 load commands、动态库依赖、代码签名。
//! 对应《本地二进制信号重映射主路线施工计划》P0 格式解析。

// 格式常量用于文档化 Mach-O 格式规范，编译器不检查死代码
#![allow(dead_code)]

use crate::parser::{BinaryInfo, BinaryType, CpuArch, DynLibDependency, SegmentDesc};

use daoti_common::DaotiError;

// ─── Mach-O 常量 ───────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_CIGAM: u32 = 0xBEBAFECA;

// CPU 类型
const CPU_TYPE_X86: i32 = 7;
const CPU_TYPE_X86_64: i32 = 7 | 0x01000000;
const CPU_TYPE_ARM64: i32 = 12 | 0x01000000;

// 文件类型
#[allow(dead_code)]
const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
#[allow(dead_code)]
const MH_FVMLIB: u32 = 0x3;
const MH_DYLIB: u32 = 0x6;
#[allow(dead_code)]
const MH_DYLINKER: u32 = 0x7;
#[allow(dead_code)]
const MH_BUNDLE: u32 = 0x8;
const MH_DSYM: u32 = 0xA;

// Load commands
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xB;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_ID_DYLIB: u32 = 0xD;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1B;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
const LC_REEXPORT_DYLIB: u32 = 0x1F | 0x80000000;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x22 | 0x80000000;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | 0x80000000;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DYLD_ENVIRONMENT: u32 = 0x27;
const LC_MAIN: u32 = 0x28 | 0x80000000;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_SOURCE_VERSION: u32 = 0x2A;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const LC_LINKER_OPTION: u32 = 0x2D;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
const LC_VERSION_MIN_TVOS: u32 = 0x2F;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_NOTE: u32 = 0x31;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | 0x80000000;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | 0x80000000;

// 段标志
const SG_HIGHVL: u32 = 0x20000000;
const SG_LOWVL: u32 = 0x40000000;
const SG_PROTECTED_VERSION_1: u32 = 0x80000000;
const SG_READ_ONLY: u32 = 0x10000;

// ─── 辅助函数 ──────────────────────────────────────────────────

/// 读取 u32（小端序）
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// 读取 u64（小端序）
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// 读取 u16（小端序）
fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// 解析 CPU 类型为 CpuArch
fn cpu_type_to_arch(cpu_type: i32) -> CpuArch {
    match cpu_type {
        CPU_TYPE_X86_64 => CpuArch::X86_64,
        CPU_TYPE_X86 => CpuArch::X86,
        CPU_TYPE_ARM64 => CpuArch::Arm64,
        other => CpuArch::Unknown(other as u32),
    }
}

/// 解析 load command 中的动态库依赖（LC_LOAD_DYLIB / LC_ID_DYLIB 等）
fn parse_dylib_command(data: &[u8], cmd_offset: usize) -> Result<DynLibDependency, DaotiError> {
    // dylib 结构 (offset from cmd_offset):
    //   cmdsize: u32 (offset 4)
    //   dylib: {
    //     offset: u32 (offset 8) - 偏移到字符串
    //     current_version: u32 (offset 12)
    //     compat_version: u32 (offset 16)
    //   }
    //   字符串: 从 offset 8 + dylib.offset 开始

    let dylib_offset = cmd_offset + 8;
    let str_offset = read_u32(data, dylib_offset); // 相对于 dylib 结构的偏移
    let current_version_raw = read_u32(data, dylib_offset + 4);
    let compat_version_raw = read_u32(data, dylib_offset + 8);

    // 字符串位置
    let name_start = cmd_offset + 8 + str_offset as usize;
    let name = read_cstring(data, name_start).unwrap_or("".into());

    let current_version = if current_version_raw != 0 {
        Some(format!(
            "{}.{}.{}",
            (current_version_raw >> 16) & 0xFFFF,
            (current_version_raw >> 8) & 0xFF,
            current_version_raw & 0xFF
        ))
    } else {
        None
    };

    let compat_version = if compat_version_raw != 0 {
        Some(format!(
            "{}.{}.{}",
            (compat_version_raw >> 16) & 0xFFFF,
            (compat_version_raw >> 8) & 0xFF,
            compat_version_raw & 0xFF
        ))
    } else {
        None
    };

    Ok(DynLibDependency {
        name,
        current_version,
        compat_version,
    })
}

/// 读取以 null 结尾的 C 字符串
fn read_cstring(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|pos| offset + pos)
        .unwrap_or(data.len());
    if end <= offset {
        return None;
    }
    String::from_utf8(data[offset..end].to_vec()).ok()
}

/// 读取 UTF-8 字符串（固定长度，不足补 0）
fn read_fixed_string(data: &[u8], offset: usize, len: usize) -> String {
    let end = (offset + len).min(data.len());
    let bytes = &data[offset..end];
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..null_pos]).to_string()
}

/// 按指定字节序读取 u32（用于 fat 头支持大小端反转）
fn read_u32_endian(data: &[u8], offset: usize, reversed: bool) -> u32 {
    if reversed {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    } else {
        read_u32(data, offset)
    }
}

/// 将 LC_MAIN 的入口文件偏移换算为虚拟地址。
///
/// Mach-O 的 `entry_point_command.entryoff` 是入口点在文件中的偏移（通常落在
/// `__TEXT` 段内），并非虚拟地址。为与 ELF(`entry`) 和 PE(`AddressOfEntryPoint`)
/// 的地址语义保持一致，需借助包含该偏移的段做 `vaddr + (entryoff - file_offset)`
/// 换算。找不到承载段时返回 `None`，由调用方决定回退策略。
fn resolve_entry_address(segments: &[SegmentDesc], fileoff: u64) -> Option<u64> {
    segments
        .iter()
        .find(|seg| {
            seg.file_size > 0
                && fileoff >= seg.file_offset
                && fileoff < seg.file_offset + seg.file_size
        })
        .map(|seg| seg.vaddr + (fileoff - seg.file_offset))
}

// ─── 公共解析函数 ──────────────────────────────────────────────

/// 解析 32 位 Mach-O
pub fn parse_macho32(data: &[u8]) -> Result<BinaryInfo, DaotiError> {
    parse_macho_inner(data, false)
}

/// 解析 64 位 Mach-O
pub fn parse_macho64(data: &[u8]) -> Result<BinaryInfo, DaotiError> {
    parse_macho_inner(data, true)
}

/// 解析 fat/universal Mach-O 二进制
pub fn parse_fat_macho(data: &[u8]) -> Result<BinaryInfo, DaotiError> {
    parse_fat_macho_inner(data, false)
}

/// 解析反转字节序的 fat/universal Mach-O 二进制
pub fn parse_fat_macho_reverse(data: &[u8]) -> Result<BinaryInfo, DaotiError> {
    parse_fat_macho_inner(data, true)
}

// ─── 内部解析实现 ──────────────────────────────────────────────

/// 解析 32/64 位 Mach-O 的共用逻辑
fn parse_macho_inner(data: &[u8], is_64: bool) -> Result<BinaryInfo, DaotiError> {
    let header_size = if is_64 { 32usize } else { 28usize };

    if data.len() < header_size {
        return Err(DaotiError::ParseError(format!(
            "Mach-O 文件过短：{} 字节 < 最小头部 {} 字节",
            data.len(),
            header_size
        )));
    }

    let magic = read_u32(data, 0);
    let is_64_bit = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;

    // 对于 32 位 Mach-O 确认头部大小
    let header_size_actual = if is_64_bit { 32 } else { 28 };

    // 文件类型
    let file_type = read_u32(data, 12);
    // load commands 数量
    let _ncmds = read_u32(data, 16);
    // load commands 总大小
    let sizeofcmds = read_u32(data, 20);
    // flags
    let _flags = read_u32(data, 24);

    // CPU 类型
    let cpu_type = read_u32(data, 4) as i32;
    let arch = cpu_type_to_arch(cpu_type);

    // 入口点：先置 0，待解析 load commands 时从 LC_MAIN 获取并换算为虚拟地址
    let entry_point = 0u64;

    let mut info = BinaryInfo::new(BinaryType::MachO, arch, entry_point);

    // 判断文件类型
    info.is_dynamic = file_type == MH_DYLIB;
    // MH_DSYM 是调试符号文件，不参与执行
    if file_type == MH_DSYM {
        info.is_pic = true;
    }

    // 解析 load commands
    let mut cmd_offset = header_size_actual;
    let cmds_end = header_size_actual + sizeofcmds as usize;
    let cmds_end = cmds_end.min(data.len());

    // 临时存储 LC_MAIN 入口点
    let mut lc_main_entry: Option<u64> = None;

    while cmd_offset + 8 <= cmds_end {
        let cmd = read_u32(data, cmd_offset);
        let cmdsize = read_u32(data, cmd_offset + 4) as usize;

        if cmdsize < 8 || cmd_offset + cmdsize > cmds_end {
            break;
        }

        match cmd {
            LC_SEGMENT_64 => {
                // segment_command_64: 72 bytes + sections
                if is_64_bit && cmd_offset + 72 <= data.len() {
                    let segname = read_fixed_string(data, cmd_offset + 8, 16);
                    let vmaddr = read_u64(data, cmd_offset + 24);
                    let vmsize = read_u64(data, cmd_offset + 32);
                    let fileoff = read_u64(data, cmd_offset + 40);
                    let filesize = read_u64(data, cmd_offset + 48);
                    let maxprot = read_u32(data, cmd_offset + 56);
                    let initprot = read_u32(data, cmd_offset + 60);
                    let nsects = read_u32(data, cmd_offset + 64);
                    let _flags = read_u32(data, cmd_offset + 68);

                    // 段信息
                    let seg = SegmentDesc {
                        name: segname,
                        vaddr: vmaddr,
                        file_offset: fileoff,
                        file_size: filesize,
                        mem_size: vmsize,
                        flags: initprot | (if maxprot != 0 { maxprot << 8 } else { 0 }),
                    };
                    info.segments.push(seg);

                    // 解析 sections（每个 section_64 80 bytes）
                    let sections_offset = cmd_offset + 72;
                    for i in 0..nsects as usize {
                        let so = sections_offset + i * 80;
                        if so + 80 > data.len() {
                            break;
                        }
                        // section name (16 bytes)
                        // We don't add sections to BinaryInfo currently
                        // as BinaryInfo uses segments for the unified representation
                    }
                }
            }
            LC_SEGMENT => {
                // segment_command: 56 bytes + sections (32-bit)
                if !is_64_bit && cmd_offset + 56 <= data.len() {
                    let segname = read_fixed_string(data, cmd_offset + 8, 16);
                    let vmaddr = read_u32(data, cmd_offset + 24) as u64;
                    let vmsize = read_u32(data, cmd_offset + 28) as u64;
                    let fileoff = read_u32(data, cmd_offset + 32) as u64;
                    let filesize = read_u32(data, cmd_offset + 36) as u64;
                    let maxprot = read_u32(data, cmd_offset + 40);
                    let initprot = read_u32(data, cmd_offset + 44);
                    let _nsects = read_u32(data, cmd_offset + 48);
                    let _flags = read_u32(data, cmd_offset + 52);

                    let seg = SegmentDesc {
                        name: segname,
                        vaddr: vmaddr,
                        file_offset: fileoff,
                        file_size: filesize,
                        mem_size: vmsize,
                        flags: initprot | (if maxprot != 0 { maxprot << 8 } else { 0 }),
                    };
                    info.segments.push(seg);
                }
            }
            LC_UUID => {
                if cmd_offset + 24 <= data.len() {
                    // UUID 16 bytes at cmd_offset + 8
                    // 信息性，不存储到 BinaryInfo
                }
            }
            LC_MAIN => {
                // entry_point_command: 24 bytes
                if cmd_offset + 24 <= data.len() {
                    let entryoff = read_u64(data, cmd_offset + 8);
                    let _stacksize = read_u64(data, cmd_offset + 16);
                    lc_main_entry = Some(entryoff);
                }
            }
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                if cmd_offset + 8 + 16 <= data.len() {
                    if let Ok(dep) = parse_dylib_command(data, cmd_offset) {
                        info.dyn_libs.push(dep);
                        if cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB {
                            info.is_dynamic = true;
                        }
                    }
                }
            }
            LC_CODE_SIGNATURE => {
                // linkedit_data_command: 16 bytes
                if cmd_offset + 16 <= data.len() {
                    let _dataoff = read_u32(data, cmd_offset + 8);
                    let _datasize = read_u32(data, cmd_offset + 12);
                    // 代码签名信息，不存储内容
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                // dyld_info_command: 48 bytes
                if cmd_offset + 48 <= data.len() {
                    let _rebase_off = read_u32(data, cmd_offset + 8);
                    let _rebase_size = read_u32(data, cmd_offset + 12);
                    let _bind_off = read_u32(data, cmd_offset + 16);
                    let _bind_size = read_u32(data, cmd_offset + 20);
                    let _weak_bind_off = read_u32(data, cmd_offset + 24);
                    let _weak_bind_size = read_u32(data, cmd_offset + 28);
                    let _lazy_bind_off = read_u32(data, cmd_offset + 32);
                    let _lazy_bind_size = read_u32(data, cmd_offset + 36);
                    let _export_off = read_u32(data, cmd_offset + 40);
                    let _export_size = read_u32(data, cmd_offset + 44);
                    // 存在 dyld info 说明是动态链接
                    info.is_dynamic = true;
                }
            }
            LC_SYMTAB => {
                // symtab_command: 24 bytes
                if cmd_offset + 24 <= data.len() {
                    let _symoff = read_u32(data, cmd_offset + 8);
                    let _nsyms = read_u32(data, cmd_offset + 12);
                    let _stroff = read_u32(data, cmd_offset + 16);
                    let _strsize = read_u32(data, cmd_offset + 20);
                }
            }
            LC_DYSYMTAB => {
                // dysymtab_command: 80 bytes
                if cmd_offset + 80 <= data.len() {
                    // 动态符号表信息
                }
            }
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => {
                // version_min_command: 16 bytes
                if cmd_offset + 16 <= data.len() {
                    let _version = read_u32(data, cmd_offset + 8);
                    let _sdk = read_u32(data, cmd_offset + 12);
                }
            }
            LC_BUILD_VERSION => {
                // build_version_command: 24 bytes + tools
                if cmd_offset + 24 <= data.len() {
                    let _platform = read_u32(data, cmd_offset + 8);
                    let _minos = read_u32(data, cmd_offset + 12);
                    let _sdk = read_u32(data, cmd_offset + 16);
                    let _ntools = read_u32(data, cmd_offset + 20);
                }
            }
            LC_SOURCE_VERSION => {
                // source_version_command: 16 bytes
                if cmd_offset + 16 <= data.len() {
                    let _version = read_u64(data, cmd_offset + 8);
                }
            }
            LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLIB_CODE_SIGN_DRS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_SEGMENT_SPLIT_INFO => {
                // linkedit_data_command: 16 bytes
                if cmd_offset + 16 <= data.len() {
                    let _dataoff = read_u32(data, cmd_offset + 8);
                    let _datasize = read_u32(data, cmd_offset + 12);
                }
            }
            LC_DYLD_ENVIRONMENT => {
                // 环境变量字符串
                if cmd_offset + 8 < data.len() {
                    let _env = read_cstring(data, cmd_offset + 8);
                }
            }
            LC_LINKER_OPTION => {
                // linker_option_command: 可变长度
                if cmd_offset + 12 <= data.len() {
                    let _count = read_u32(data, cmd_offset + 8);
                }
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 if cmd_offset + 20 <= data.len() => {
                // encryption_info_command: 20 bytes
                let _cryptoff = read_u32(data, cmd_offset + 8);
                let _cryptsize = read_u32(data, cmd_offset + 12);
                let _cryptid = read_u32(data, cmd_offset + 16);
            }
            _ => {
                // 未知 load command，跳过
            }
        }

        cmd_offset += cmdsize;
    }

    // 设置入口点：LC_MAIN 的 entryoff 是文件偏移，需换算为虚拟地址
    if let Some(entryoff) = lc_main_entry {
        info.entry_point = resolve_entry_address(&info.segments, entryoff).unwrap_or(entryoff);
    }

    // 保留头部字节
    info.header_bytes = data[..header_size_actual.min(data.len())].to_vec();

    Ok(info)
}

/// 解析 fat/universal Mach-O 二进制
fn parse_fat_macho_inner(data: &[u8], reversed: bool) -> Result<BinaryInfo, DaotiError> {
    if data.len() < 8 {
        return Err(DaotiError::ParseError("Fat Mach-O 文件过短".into()));
    }

    let _magic = read_u32(data, 0);
    // fat 头字段按文件字节序存储：reversed 时为大端
    let nfat_arch = read_u32_endian(data, 4, reversed) as usize;

    // 防御：nfat_arch 过大时乘法可能溢出 usize
    let arch_table_bytes = nfat_arch
        .checked_mul(20)
        .ok_or_else(|| DaotiError::ParseError("Fat Mach-O 架构列表大小溢出".into()))?;
    let arch_table_end = 8usize
        .checked_add(arch_table_bytes)
        .ok_or_else(|| DaotiError::ParseError("Fat Mach-O 架构列表偏移溢出".into()))?;
    if data.len() < arch_table_end {
        return Err(DaotiError::ParseError(
            "Fat Mach-O 架构列表超出文件范围".into(),
        ));
    }

    // 优先选择 x86_64 架构，其次是 arm64，最后是第一个
    let mut best_offset: Option<u64> = None;
    let mut best_size: Option<u64> = None;
    let mut fallback_offset: Option<u64> = None;
    let mut fallback_size: Option<u64> = None;

    for i in 0..nfat_arch {
        let entry_offset = 8 + i * 20;
        if entry_offset + 20 > data.len() {
            break;
        }
        // fat_arch 中除 magic 外字段均按文件字节序存储
        let cpu_type = read_u32_endian(data, entry_offset, reversed) as i32;
        let _cpu_subtype = read_u32_endian(data, entry_offset + 4, reversed);
        let arch_offset = read_u32_endian(data, entry_offset + 8, reversed) as u64;
        let arch_size = read_u32_endian(data, entry_offset + 12, reversed) as u64;
        let _align = read_u32_endian(data, entry_offset + 16, reversed);

        // 跳过明显越界/为空的切片，避免把坏条目选为「最优」
        let in_bounds = arch_size > 0
            && arch_offset
                .checked_add(arch_size)
                .is_some_and(|end| end <= data.len() as u64);

        // 记录第一个有效切片作为回退
        if fallback_offset.is_none() && in_bounds {
            fallback_offset = Some(arch_offset);
            fallback_size = Some(arch_size);
        }

        // 优先选择 x86_64
        if cpu_type == CPU_TYPE_X86_64 && in_bounds {
            best_offset = Some(arch_offset);
            best_size = Some(arch_size);
            break;
        }
        // 其次是 arm64
        if cpu_type == CPU_TYPE_ARM64 && in_bounds && best_offset.is_none() {
            best_offset = Some(arch_offset);
            best_size = Some(arch_size);
        }
    }

    let (slice_offset, slice_size) = match (best_offset, best_size) {
        (Some(off), Some(sz)) => (off as usize, sz as usize),
        (Some(_), None) => (0usize, 0usize),
        (None, _) => match (fallback_offset, fallback_size) {
            (Some(off), Some(sz)) => (off as usize, sz as usize),
            _ => return Err(DaotiError::ParseError("Fat Mach-O 无可用架构".into())),
        },
    };

    // 防御性边界校验：切片必须完全落在文件字节范围内
    if slice_size == 0
        || slice_offset
            .checked_add(slice_size)
            .is_none_or(|end| end > data.len())
    {
        return Err(DaotiError::ParseError(
            "Fat Mach-O 架构切片为空或超出文件范围".into(),
        ));
    }

    let slice_data = &data[slice_offset..slice_offset + slice_size];
    let slice_magic = read_u32(slice_data, 0);

    // 解析选中的架构切片
    let mut info = match slice_magic {
        MH_MAGIC_64 | MH_CIGAM_64 => parse_macho_inner(slice_data, true)?,
        MH_MAGIC | MH_CIGAM => parse_macho_inner(slice_data, false)?,
        _ => {
            return Err(DaotiError::ParseError("Fat Mach-O 切片魔数无效".into()));
        }
    };

    info.binary_type = BinaryType::FatMachO;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_empty_data() {
        assert!(parse_macho64(&[]).is_err());
        assert!(parse_macho32(&[]).is_err());
    }

    #[test]
    fn test_reject_short_data() {
        assert!(parse_macho64(&[0xFE, 0xED, 0xFA, 0xCF]).is_err());
    }

    #[test]
    fn test_minimal_macho64_header() {
        // 构造最小 64 位 Mach-O header
        let data = create_minimal_macho64();
        let info = parse_macho64(&data).expect("最小 Mach-O 64 应可解析");
        assert_eq!(info.binary_type, BinaryType::MachO);
        assert_eq!(info.segments.len(), 1);
    }

    #[test]
    fn test_minimal_macho32_header() {
        let data = create_minimal_macho32();
        let info = parse_macho32(&data).expect("最小 Mach-O 32 应可解析");
        assert_eq!(info.binary_type, BinaryType::MachO);
    }

    #[test]
    fn test_parse_fat_header() {
        let data = create_minimal_fat_macho();
        let info = parse_fat_macho(&data).expect("最小 Fat Mach-O 应可解析");
        // 应为 Fat Mach-O 类型
        assert_eq!(info.binary_type, BinaryType::FatMachO);
    }

    #[test]
    fn test_parse_distinguishes_64_vs_32() {
        let data64 = create_minimal_macho64();
        let info64 = parse_macho64(&data64).unwrap();
        // 64-bit 的 CPU 类型是 x86_64
        assert_eq!(info64.arch, CpuArch::X86_64);

        let data32 = create_minimal_macho32();
        let info32 = parse_macho32(&data32).unwrap();
        // 32-bit 默认是 x86
        assert_eq!(info32.arch, CpuArch::X86);
    }

    #[test]
    fn test_entry_point_zero_without_lc_main() {
        // 无 LC_MAIN 时可执行文件入口应为 0
        let data = create_minimal_macho64();
        let info = parse_macho64(&data).unwrap();
        assert_eq!(info.entry_point, 0);
    }

    #[test]
    fn test_lc_main_entry_resolved_to_vaddr() {
        // __TEXT: vmaddr=0x100000000, fileoff=0, filesize=0x1000
        // LC_MAIN.entryoff=0x3A0（落在段内）→ 期望入口虚拟地址 = 0x100000000 + 0x3A0
        let data = create_macho64_with_lc_main(0x3A0);
        let info = parse_macho64(&data).expect("含 LC_MAIN 的 Mach-O 64 应可解析");
        assert_eq!(info.entry_point, 0x100000000 + 0x3A0);
    }

    #[test]
    fn test_lc_main_entry_fallbacks_to_fileoff_when_no_segment() {
        // 构造一个 entryoff 落在任何段之外的可执行文件，验证回退保留原始偏移
        let data = create_macho64_with_lc_main_out_of_segment(0x9000);
        let info = parse_macho64(&data).unwrap();
        // 找不到承载段时回退为原始文件偏移
        assert_eq!(info.entry_point, 0x9000);
    }

    #[test]
    fn test_lc_main_entry_resolution_zero_segment_file() {
        // 当段 file_size 为 0 时不应参与入口换算（避免除零/越界）
        let data = create_macho64_with_lc_main_zero_segment(0x3A50);
        let info = parse_macho64(&data).unwrap();
        // 段 file_size=0，无法承载入口，回退为原始偏移
        assert_eq!(info.entry_point, 0x3A50);
    }

    #[test]
    fn test_fat_slice_out_of_bounds_rejected() {
        // 构造 fat：切片 offset+size 超出文件长度，应返回错误而非 panic 越界
        let data = create_fat_with_slice(0, 0x4000);
        assert!(parse_fat_macho(&data).is_err(), "越界切片应被拒绝");
    }

    #[test]
    fn test_fat_slice_zero_size_rejected() {
        // 切片 size 为 0 应被拒绝
        let data = create_fat_with_slice(28, 0);
        assert!(parse_fat_macho(&data).is_err(), "零大小切片应被拒绝");
    }

    #[test]
    fn test_fat_empty_arch_table_overflow_rejected() {
        // nfat_arch 极大但文件很短 → 乘法溢出防御
        let mut buf = Vec::new();
        buf.extend(&FAT_MAGIC.to_le_bytes());
        buf.extend(&0xFFFFFFu32.to_le_bytes()); // nfat_arch
        assert!(parse_fat_macho(&buf).is_err(), "超大架构列表应被拒绝");
    }

    #[test]
    fn test_fat_no_valid_slice_falls_back_to_error() {
        // fat 头声称有切片，但所有切片都越界/为空 → 应返回「无可用架构」
        let data = create_fat_with_slice(0xFFFF, 0x100);
        assert!(parse_fat_macho(&data).is_err(), "无有效切片应被拒绝");
    }

    #[test]
    fn test_fat_reversed_header_parses_slice() {
        // 反转字节序的 fat（FAT_CIGAM），验证 fat 头按大端读取可正确定位切片
        let data = create_reverse_fat_macho();
        let info = parse_fat_macho_reverse(&data).expect("反转 fat 应可解析");
        assert_eq!(info.binary_type, BinaryType::FatMachO);
    }

    // ─── 测试数据生成 ──────────────────────────────────────────

    fn create_minimal_macho64() -> Vec<u8> {
        // Mach-O 64 header (32 bytes) + 一个空的 LC_SEGMENT_64
        let mut buf = Vec::new();

        // header
        buf.extend(&MH_MAGIC_64.to_le_bytes()); // magic
        buf.extend(&CPU_TYPE_X86_64.to_le_bytes() as &[u8]); // cputype (8 bytes as i32)
        buf.extend(&0u32.to_le_bytes()); // cpusubtype
        buf.extend(&MH_EXECUTE.to_le_bytes()); // filetype
        buf.extend(&1u32.to_le_bytes()); // ncmds
        buf.extend(&72u32.to_le_bytes()); // sizeofcmds (one LC_SEGMENT_64 = 72 bytes)
        buf.extend(&0u32.to_le_bytes()); // flags
        buf.extend(&0u32.to_le_bytes()); // reserved (64-bit only)

        // LC_SEGMENT_64 (72 bytes)
        buf.extend(&LC_SEGMENT_64.to_le_bytes()); // cmd
        buf.extend(&72u32.to_le_bytes()); // cmdsize
                                          // segname (16 bytes)
        buf.extend(b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        // vmaddr
        buf.extend(&0x100000000u64.to_le_bytes());
        // vmsize
        buf.extend(&0x1000u64.to_le_bytes());
        // fileoff
        buf.extend(&0u64.to_le_bytes());
        // filesize
        buf.extend(&0x1000u64.to_le_bytes());
        // maxprot
        buf.extend(&7u32.to_le_bytes());
        // initprot
        buf.extend(&7u32.to_le_bytes());
        // nsects
        buf.extend(&0u32.to_le_bytes());
        // flags
        buf.extend(&0u32.to_le_bytes());

        buf
    }

    fn create_minimal_macho32() -> Vec<u8> {
        // Mach-O 32 header (28 bytes) + 一个空的 LC_SEGMENT
        let mut buf = Vec::new();

        // header
        buf.extend(&MH_MAGIC.to_le_bytes()); // magic
        buf.extend(&CPU_TYPE_X86.to_le_bytes() as &[u8]); // cputype
        buf.extend(&0u32.to_le_bytes()); // cpusubtype
        buf.extend(&MH_EXECUTE.to_le_bytes()); // filetype
        buf.extend(&1u32.to_le_bytes()); // ncmds
        buf.extend(&56u32.to_le_bytes()); // sizeofcmds
        buf.extend(&0u32.to_le_bytes()); // flags

        // LC_SEGMENT (56 bytes)
        buf.extend(&LC_SEGMENT.to_le_bytes()); // cmd
        buf.extend(&56u32.to_le_bytes()); // cmdsize
                                          // segname (16 bytes)
        buf.extend(b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        // vmaddr (32-bit)
        buf.extend(&0x1000u32.to_le_bytes());
        // vmsize (32-bit)
        buf.extend(&0x1000u32.to_le_bytes());
        // fileoff (32-bit)
        buf.extend(&0u32.to_le_bytes());
        // filesize (32-bit)
        buf.extend(&0x1000u32.to_le_bytes());
        // maxprot
        buf.extend(&7u32.to_le_bytes());
        // initprot
        buf.extend(&7u32.to_le_bytes());
        // nsects
        buf.extend(&0u32.to_le_bytes());
        // flags
        buf.extend(&0u32.to_le_bytes());

        buf
    }

    fn create_minimal_fat_macho() -> Vec<u8> {
        // Fat header (8 bytes) + 一个 fat_arch 条目 (20 bytes) + 内嵌 64-bit Mach-O
        let macho_data = create_minimal_macho64();
        let macho_offset = 8 + 20; // 28 bytes

        let mut buf = Vec::new();

        // Fat header
        buf.extend(&FAT_MAGIC.to_le_bytes()); // magic
        buf.extend(&1u32.to_le_bytes()); // nfat_arch

        // Fat arch entry
        buf.extend(&CPU_TYPE_X86_64.to_le_bytes() as &[u8]); // cputype
        buf.extend(&0u32.to_le_bytes()); // cpusubtype
        buf.extend(&(macho_offset as u32).to_le_bytes()); // offset
        buf.extend(&(macho_data.len() as u32).to_le_bytes()); // size
        buf.extend(&12u32.to_le_bytes()); // align (2^12 = 4096)

        // 内嵌 Mach-O
        buf.extend(&macho_data);

        buf
    }

    /// 构造含 LC_MAIN 的 64 位 Mach-O：header + LC_SEGMENT_64(__TEXT) + LC_MAIN
    ///
    /// __TEXT: vmaddr=0x100000000, fileoff=0, filesize=0x1000
    /// LC_MAIN.entryoff 作为参数传入。
    fn create_macho64_with_lc_main(entryoff: u64) -> Vec<u8> {
        let unit_size = 72usize; // LC_SEGMENT_64
        let lc_main_size = 24usize;
        let mut buf = Vec::new();

        // header (32 bytes)
        buf.extend(&MH_MAGIC_64.to_le_bytes());
        buf.extend(&CPU_TYPE_X86_64.to_le_bytes() as &[u8]);
        buf.extend(&0u32.to_le_bytes());
        buf.extend(&MH_EXECUTE.to_le_bytes());
        buf.extend(&2u32.to_le_bytes()); // ncmds
        buf.extend(&((unit_size + lc_main_size) as u32).to_le_bytes()); // sizeofcmds
        buf.extend(&0u32.to_le_bytes()); // flags
        buf.extend(&0u32.to_le_bytes()); // reserved

        // LC_SEGMENT_64 (72 bytes)
        buf.extend(&LC_SEGMENT_64.to_le_bytes());
        buf.extend(&(unit_size as u32).to_le_bytes());
        buf.extend(b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        buf.extend(&0x100000000u64.to_le_bytes()); // vmaddr
        buf.extend(&0x1000u64.to_le_bytes()); // vmsize
        buf.extend(&0u64.to_le_bytes()); // fileoff
        buf.extend(&0x1000u64.to_le_bytes()); // filesize
        buf.extend(&7u32.to_le_bytes()); // maxprot
        buf.extend(&7u32.to_le_bytes()); // initprot
        buf.extend(&0u32.to_le_bytes()); // nsects
        buf.extend(&0u32.to_le_bytes()); // flags

        // LC_MAIN (24 bytes)
        buf.extend(&LC_MAIN.to_le_bytes());
        buf.extend(&(lc_main_size as u32).to_le_bytes());
        buf.extend(&entryoff.to_le_bytes()); // entryoff
        buf.extend(&0x1000u64.to_le_bytes()); // stacksize

        buf
    }

    /// 构造 entryoff 落在 __TEXT 段之外的可执行文件
    fn create_macho64_with_lc_main_out_of_segment(entryoff: u64) -> Vec<u8> {
        // 复用 create_macho64_with_lc_main，但 __TEXT 的 filesize 仅 0x1000，
        // 若 entryoff 超出该范围即无法定位承载段
        create_macho64_with_lc_main(entryoff)
    }

    /// 构造 __TEXT 段 file_size 为 0 的可执行文件（不应参与入口换算）
    fn create_macho64_with_lc_main_zero_segment(entryoff: u64) -> Vec<u8> {
        let mut data = create_macho64_with_lc_main(entryoff);
        // 将 __TEXT 段的 filesize 修改为 0
        // 段位于 offset 32，filesize 字段偏移 32+48=80
        let filesize_off = 32 + 48;
        data[filesize_off..filesize_off + 8].copy_from_slice(&0u64.to_le_bytes());
        data
    }

    /// 构造自定义切片的 fat：offset/size 由参数指定（便于构造越界/为空的切片）
    fn create_fat_with_slice(offset: u32, size: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(&FAT_MAGIC.to_le_bytes());
        buf.extend(&1u32.to_le_bytes()); // nfat_arch
        buf.extend(&CPU_TYPE_X86_64.to_le_bytes() as &[u8]); // cputype
        buf.extend(&0u32.to_le_bytes()); // cpusubtype
        buf.extend(&offset.to_le_bytes());
        buf.extend(&size.to_le_bytes());
        buf.extend(&12u32.to_le_bytes()); // align
        buf
    }

    /// 构造大端字节序的 fat（FAT_CIGAM），验证反转解析能正确定位切片
    fn create_reverse_fat_macho() -> Vec<u8> {
        let macho_data = create_minimal_macho64();
        let macho_offset = 8 + 20; // 28 bytes

        let mut buf = Vec::new();
        // magic（FAT_CIGAM = 0xBEBAFECA，按大端写入为 BE BA FE CA）
        buf.extend([0xBE, 0xBA, 0xFE, 0xCA]);
        // nfat_arch=1（大端）
        buf.extend(&1u32.to_be_bytes());
        // fat_arch 条目（全大端）
        buf.extend(&(CPU_TYPE_X86_64 as u32).to_be_bytes());
        buf.extend(&0u32.to_be_bytes());
        buf.extend(&(macho_offset as u32).to_be_bytes());
        buf.extend(&(macho_data.len() as u32).to_be_bytes());
        buf.extend(&12u32.to_be_bytes());
        // 内嵌 Mach-O（内嵌切片本身仍为小端）
        buf.extend(&macho_data);
        buf
    }
}
