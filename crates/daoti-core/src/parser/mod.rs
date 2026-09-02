//! 格式解析器 (daoti-core::parser)
//!
//! 统一二进制格式解析入口。支持 ELF / PE / Mach-O 三种格式的完整解析，
//! 输出与平台无关的 `BinaryInfo` 结构化描述。
//!
//! 对应《本地二进制信号重映射主路线施工计划》能力层 1：格式识别与解析。

pub mod elf;
pub mod macho;
pub mod pe;

use std::path::Path;

use daoti_common::DaotiError;
use serde::{Deserialize, Serialize};

/// 二进制文件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryType {
    /// ELF (Linux)
    Elf,
    /// PE (Windows)
    Pe,
    /// Mach-O (macOS)
    MachO,
    /// Fat 通用二进制 (macOS)
    FatMachO,
}

/// 架构类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuArch {
    X86,
    X86_64,
    Arm64,
    Unknown(u32),
}

/// 段描述
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SegmentDesc {
    /// 段名称
    pub name: String,
    /// 虚拟地址
    pub vaddr: u64,
    /// 文件偏移
    pub file_offset: u64,
    /// 文件大小
    pub file_size: u64,
    /// 内存大小
    pub mem_size: u64,
    /// 段标志（权限等）
    pub flags: u32,
}

/// 节描述
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionDesc {
    /// 节名称
    pub name: String,
    /// 虚拟地址
    pub vaddr: u64,
    /// 文件偏移
    pub file_offset: u64,
    /// 大小
    pub size: u64,
}

/// 动态库依赖
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DynLibDependency {
    /// 库路径/名称
    pub name: String,
    /// 当前版本
    pub current_version: Option<String>,
    /// 兼容版本
    pub compat_version: Option<String>,
}

/// 统一二进制信息（所有格式的公共表示）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// 文件类型
    pub binary_type: BinaryType,
    /// 目标架构
    pub arch: CpuArch,
    /// 入口点地址
    pub entry_point: u64,
    /// 基地址
    pub base_address: u64,
    /// 段列表
    pub segments: Vec<SegmentDesc>,
    /// 节列表（可选，部分格式不区分段/节）
    pub sections: Vec<SectionDesc>,
    /// 动态库依赖列表
    pub dyn_libs: Vec<DynLibDependency>,
    /// 是否为动态链接
    pub is_dynamic: bool,
    /// 是否为位置无关
    pub is_pic: bool,
    /// 原始文件头字节（用于调试/校验）
    pub header_bytes: Vec<u8>,
}

impl BinaryInfo {
    /// 创建空的 BinaryInfo（作为解析的基础）
    pub(crate) fn new(binary_type: BinaryType, arch: CpuArch, entry_point: u64) -> Self {
        BinaryInfo {
            binary_type,
            arch,
            entry_point,
            base_address: 0,
            segments: Vec::new(),
            sections: Vec::new(),
            dyn_libs: Vec::new(),
            is_dynamic: false,
            is_pic: false,
            header_bytes: Vec::new(),
        }
    }
}

/// 统一解析入口：检测格式并调用对应解析器
///
/// 接收二进制文件路径，返回 `BinaryInfo` 结构化描述。
/// 格式自动检测基于魔数（magic bytes），不依赖文件扩展名。
pub fn parse_binary(path: &Path) -> Result<BinaryInfo, DaotiError> {
    let data = std::fs::read(path)
        .map_err(|e| DaotiError::FileNotFound(format!("读取二进制文件失败: {e}")))?;

    if data.len() < 16 {
        return Err(DaotiError::ParseError("文件过短，无法识别格式".into()));
    }

    // 检测魔数
    let magic = &data[..4];
    match magic {
        // ELF: \x7f ELF
        b"\x7fELF" => elf::parse_elf(&data),
        // PE: MZ
        b"MZ\x90\x00" | b"MZ" => pe::parse_pe(&data),
        // Mach-O 32-bit: FE ED FA CE
        b"\xfe\xed\xfa\xce" => macho::parse_macho32(&data),
        // Mach-O 64-bit: FE ED FA CF
        b"\xfe\xed\xfa\xcf" => macho::parse_macho64(&data),
        // Fat binary: CA FE BA BE
        b"\xca\xfe\xba\xbe" => macho::parse_fat_macho(&data),
        // Fat binary reverse: BE BA FE CA
        b"\xbe\xba\xfe\xca" => {
            // 字节序反转的 fat binary
            macho::parse_fat_macho_reverse(&data)
        }
        _ => Err(DaotiError::ParseError(format!(
            "无法识别的二进制格式: 魔数 {:02x?}",
            magic
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[allow(dead_code)]
    fn test_data_dir() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("tests");
        p.push("data");
        p
    }

    #[test]
    fn test_reject_non_binary() {
        let result = parse_binary(Path::new("Cargo.toml"));
        assert!(result.is_err(), "文本文件应被拒绝");
    }

    #[test]
    fn test_reject_short_data() {
        let result = parse_binary(Path::new("src/lib.rs"));
        assert!(result.is_err(), "过短文件应被拒绝");
    }

    #[test]
    fn test_binary_info_new() {
        let info = BinaryInfo::new(BinaryType::Elf, CpuArch::X86_64, 0x400000);
        assert_eq!(info.binary_type, BinaryType::Elf);
        assert_eq!(info.arch, CpuArch::X86_64);
        assert_eq!(info.entry_point, 0x400000);
        assert!(info.segments.is_empty());
        assert!(info.dyn_libs.is_empty());
    }
}
