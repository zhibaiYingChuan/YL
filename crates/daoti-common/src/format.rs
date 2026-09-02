//! 二进制格式检测 (daoti-common::format)
//!
//! 模式B 基础能力：通过魔数（magic bytes）识别 ELF/PE/Mach-O 格式，
//! 供 CLI agent 和 daemon 共享使用。

use crate::DaotiError;

/// ELF 装载类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfKind {
    Static,
    Dynamic,
}

/// 二进制文件格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// Linux ELF（Executable and Linkable Format）
    Elf,
    /// Windows PE（Portable Executable）
    Pe,
    /// macOS Mach-O（B2 阶段支持）
    MachO,
}

/// 检测二进制文件的格式。
///
/// 读取文件头魔数判断：
/// - `0x7F ELF` → Linux ELF
/// - `MZ` → Windows PE
/// - `0xFE ED FA CE/CF` → macOS Mach-O
/// - 其他 → `DaotiError::UnrecognizedFormat`
pub fn detect_elf_kind(path: &str) -> Result<ElfKind, DaotiError> {
    let data = std::fs::read(path).map_err(|e| DaotiError::FileNotFound(format!("{path}: {e}")))?;
    if data.len() < 46 || data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(DaotiError::UnrecognizedFormat(format!(
            "{path} 不是 ELF 文件"
        )));
    }
    let class = data[4];
    let endian = data[5];
    if endian != 1 {
        return Err(DaotiError::Unavailable("仅支持小端 ELF 调度探测".into()));
    }
    let (phoff, phentsize, phnum) = if class == 2 {
        (
            u64::from_le_bytes(data[32..40].try_into().unwrap()),
            u16::from_le_bytes(data[54..56].try_into().unwrap()) as u64,
            u16::from_le_bytes(data[56..58].try_into().unwrap()) as u64,
        )
    } else if class == 1 {
        (
            u32::from_le_bytes(data[28..32].try_into().unwrap()) as u64,
            u16::from_le_bytes(data[42..44].try_into().unwrap()) as u64,
            u16::from_le_bytes(data[44..46].try_into().unwrap()) as u64,
        )
    } else {
        return Err(DaotiError::UnrecognizedFormat(format!(
            "{path} ELF class 无效"
        )));
    };
    // 优先检查 ELF 头 e_type（offset 16，2 字节）：3 = ET_DYN（动态可执行）
    let e_type = u16::from_le_bytes(data[16..18].try_into().unwrap());
    let has_dynamic_header = e_type == 3
        || (0..phnum).any(|i| {
            let off = phoff.saturating_add(i.saturating_mul(phentsize)) as usize;
            off.checked_add(4).is_some_and(|end| end <= data.len())
                // PT_DYNAMIC (2) 或 PT_INTERP (3) 均表示需要动态链接
                && matches!(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()), 2 | 3)
        });
    Ok(if has_dynamic_header {
        ElfKind::Dynamic
    } else {
        ElfKind::Static
    })
}

pub fn detect_binary_format(path: &str) -> Result<BinaryFormat, DaotiError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return Err(DaotiError::FileNotFound(format!("{path}: {e}"))),
    };
    if !meta.is_file() {
        return Err(DaotiError::UnrecognizedFormat(format!(
            "{path} 不是常规文件"
        )));
    }

    let mut buf = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
        .map_err(|e| DaotiError::FileNotFound(format!("{path}: {e}")))?;

    match buf {
        // ELF: 0x7F 0x45('E') 0x4C('L') 0x46('F')
        [0x7F, 0x45, 0x4C, 0x46] => Ok(BinaryFormat::Elf),
        // PE/DOS: 0x4D('M') 0x5A('Z')
        [0x4D, 0x5A, _, _] => Ok(BinaryFormat::Pe),
        // Mach-O 32-bit / 64-bit，以及 Universal/Fat Mach-O
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCF, 0xFA, 0xED, 0xFE]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xCA, 0xFE, 0xBA, 0xBE]
        | [0xBE, 0xBA, 0xFE, 0xCA] => Ok(BinaryFormat::MachO),
        _ => Err(DaotiError::UnrecognizedFormat(format!(
            "{path}（魔数 {buf:02X?}）"
        ))),
    }
}

impl BinaryFormat {
    /// 格式的中文名称（供判词输出）
    pub fn label(&self) -> &'static str {
        match self {
            BinaryFormat::Elf => "Linux 之躯",
            BinaryFormat::Pe => "Windows 之体",
            BinaryFormat::MachO => "macOS 之形",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_elf_from_magic_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.elf");
        std::fs::write(&path, [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00]).unwrap();
        assert_eq!(
            detect_binary_format(&path.to_string_lossy()).unwrap(),
            BinaryFormat::Elf
        );
    }

    #[test]
    fn detect_pe_from_magic_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.exe");
        std::fs::write(&path, [0x4D, 0x5A, 0x90, 0x00]).unwrap();
        assert_eq!(
            detect_binary_format(&path.to_string_lossy()).unwrap(),
            BinaryFormat::Pe
        );
    }

    #[test]
    fn detect_macho_from_magic_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.macho");
        std::fs::write(&path, [0xFE, 0xED, 0xFA, 0xCE]).unwrap();
        assert_eq!(
            detect_binary_format(&path.to_string_lossy()).unwrap(),
            BinaryFormat::MachO
        );
    }

    #[test]
    fn detect_unrecognized_on_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("script.sh");
        std::fs::write(&path, b"#!/bin/bash\necho hello").unwrap();
        let err = detect_binary_format(&path.to_string_lossy()).unwrap_err();
        assert!(matches!(err, DaotiError::UnrecognizedFormat(_)));
    }

    #[test]
    fn detect_file_not_found() {
        let err = detect_binary_format("__no_such_file__").unwrap_err();
        assert!(matches!(err, DaotiError::FileNotFound(_)));
    }

    #[test]
    fn label_returns_chinese() {
        assert_eq!(BinaryFormat::Elf.label(), "Linux 之躯");
        assert_eq!(BinaryFormat::Pe.label(), "Windows 之体");
        assert_eq!(BinaryFormat::MachO.label(), "macOS 之形");
    }

    /// 构造一个 x86_64 小端 ELF 头，可指定 e_type（16..18）。
    fn elf_with_e_type(e_type: u16) -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2; // ELF64
        data[5] = 1; // 小端
        data[16..18].copy_from_slice(&e_type.to_le_bytes());
        data
    }

    #[test]
    fn detect_elf_kind_distinguishes_static_exec_from_dynamic_et_dyn() {
        let dir = tempfile::tempdir().unwrap();
        // ET_EXEC (2) → Static
        let exec = dir.path().join("exec.elf");
        std::fs::write(&exec, elf_with_e_type(2)).unwrap();
        assert_eq!(
            detect_elf_kind(&exec.to_string_lossy()).unwrap(),
            ElfKind::Static
        );
        // ET_DYN (3) → Dynamic（关键修复：e_type 直接判定）
        let dyn_ = dir.path().join("dyn.elf");
        std::fs::write(&dyn_, elf_with_e_type(3)).unwrap();
        assert_eq!(
            detect_elf_kind(&dyn_.to_string_lossy()).unwrap(),
            ElfKind::Dynamic
        );
    }

    #[test]
    fn detect_elf_kind_falls_back_to_program_header_pt_dynamic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("via_ph.elf");
        // e_type=0（ET_NONE），但程序头含 PT_DYNAMIC (2)，仍需判定为 Dynamic
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        data[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        data[56..58].copy_from_slice(&1u16.to_le_bytes()); //  e_phnum
        data[64..68].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        std::fs::write(&path, data).unwrap();
        assert_eq!(
            detect_elf_kind(&path.to_string_lossy()).unwrap(),
            ElfKind::Dynamic
        );
    }
}
