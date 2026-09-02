//! ELF 解析器 (daoti-core::parser::elf)
//!
//! 封装已有 `crate::elf` 解析能力，输出统一的 `BinaryInfo` 格式。
//! 对应《本地二进制信号重映射主路线施工计划》P0 格式解析。

use crate::elf::parse_elf_from_bytes;
use crate::parser::{BinaryInfo, BinaryType, CpuArch, SegmentDesc};

use daoti_common::DaotiError;

/// 从字节流解析 ELF 并转为统一 BinaryInfo
pub fn parse_elf(data: &[u8]) -> Result<BinaryInfo, DaotiError> {
    let elf_info = parse_elf_from_bytes(data)?;

    let arch = match elf_info.arch.as_str() {
        "x86_64" | "AMD64" => CpuArch::X86_64,
        "i386" | "i686" | "x86" => CpuArch::X86,
        "AArch64" | "ARM64" => CpuArch::Arm64,
        other => CpuArch::Unknown(other.len() as u32),
    };

    let mut info = BinaryInfo::new(BinaryType::Elf, arch, elf_info.entry);

    // 转换段（Program Headers）→ SegmentDesc
    for ph in &elf_info.segments {
        let seg = SegmentDesc {
            name: format!("LOAD_{}", info.segments.len()),
            vaddr: ph.vaddr,
            file_offset: ph.offset,
            file_size: ph.filesz,
            mem_size: ph.memsz,
            flags: ph.flags,
        };
        info.segments.push(seg);
    }

    // 动态链接检测：file_type 含 "DYN" 即为共享库/动态链接
    info.is_dynamic = elf_info.file_type.contains("DYN");
    // 位置无关检测：ET_DYN (共享目标文件) 或 ET_REL (可重定位文件)
    info.is_pic = info.is_dynamic || elf_info.file_type.contains("REL");

    // 保留头部字节
    info.header_bytes = data[..64.min(data.len())].to_vec();

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_elf64_binary_info() {
        // 最小 ELF64 可执行文件魔数+头部
        let data = create_minimal_elf64();
        let info = parse_elf(&data).expect("解析 ELF64 应成功");
        assert_eq!(info.binary_type, BinaryType::Elf);
        assert_eq!(info.segments.len(), 1);
        assert!(!info.is_dynamic);
    }

    #[test]
    fn test_parse_elf_rejects_short_data() {
        let result = parse_elf(&[0x7f, 0x45, 0x4c, 0x46]);
        assert!(result.is_err(), "过短数据应被拒绝");
    }

    fn create_minimal_elf64() -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // ELF header (64 bytes)
        buf.extend(b"\x7fELF"); // magic
        buf.extend(b"\x02"); // 64-bit
        buf.extend(b"\x01"); // little endian
        buf.extend(b"\x01"); // ELF version
        buf.extend(b"\x00"); // OS/ABI
        buf.extend([0u8; 8]); // padding
        buf.extend(&2u16.to_le_bytes()); // ET_EXEC
        buf.extend(&0x3e_u16.to_le_bytes()); // x86_64
        buf.extend(&1u32.to_le_bytes()); // ELF version
        buf.extend(&0x400000u64.to_le_bytes()); // entry
        buf.extend(&64u64.to_le_bytes()); // phoff
        buf.extend(&0u64.to_le_bytes()); // shoff
        buf.extend(&0u32.to_le_bytes()); // flags
        buf.extend(&64u16.to_le_bytes()); // ehsize
        buf.extend(&56u16.to_le_bytes()); // phentsize
        buf.extend(&1u16.to_le_bytes()); // phnum
        buf.extend(&64u16.to_le_bytes()); // shentsize
        buf.extend(&0u16.to_le_bytes()); // shnum
        buf.extend(&0u16.to_le_bytes()); // shstrndx

        // Program Header (56 bytes) - PT_LOAD
        buf.extend(&1u32.to_le_bytes()); // PT_LOAD
        buf.extend(&0u32.to_le_bytes()); // flags (PF_R)
        buf.extend(&0u64.to_le_bytes()); // offset
        buf.extend(&0x400000u64.to_le_bytes()); // vaddr
        buf.extend(&0x400000u64.to_le_bytes()); // paddr
        buf.extend(&0x1000u64.to_le_bytes()); // filesz
        buf.extend(&0x1000u64.to_le_bytes()); // memsz
        buf.extend(&0x1000u64.to_le_bytes()); // align

        buf
    }
}
