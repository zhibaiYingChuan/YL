//! Win32 → Linux 反向映射表
//!
//! 对应《本地二进制信号重映射主路线施工计划》P3 映射器扩展。
//! 由正向映射表（linux_to_win）对称派生，确保两方向一致性。
//! 用于 PE→ELF 方向（在 Linux 上运行 Windows PE 文件时使用）。

use std::collections::HashMap;

use super::linux_to_win::MAPPINGS;

/// 反向映射条目
#[derive(Debug, Clone)]
pub struct ReverseEntry {
    /// Windows 操作名
    pub windows_op: &'static str,
    /// Linux syscall 名称
    pub linux_name: &'static str,
    /// Linux syscall 编号
    pub nr: i32,
    /// 操作说明
    pub description: &'static str,
}

/// 反向映射器：Windows 操作 → Linux syscall
#[derive(Debug, Default)]
pub struct ReverseMapper {
    /// 查找表（windows_op → ReverseEntry）
    entries: HashMap<&'static str, ReverseEntry>,
}

impl ReverseMapper {
    /// 从正向映射表构建反向映射器
    pub fn new() -> Self {
        let mut entries = HashMap::new();
        for entry in &MAPPINGS {
            entries.insert(
                entry.windows_op,
                ReverseEntry {
                    windows_op: entry.windows_op,
                    linux_name: entry.name,
                    nr: entry.nr,
                    description: entry.description,
                },
            );
        }
        ReverseMapper { entries }
    }

    /// 按 Windows 操作名反向查找 Linux syscall
    pub fn map(&self, windows_op: &str) -> Option<&ReverseEntry> {
        self.entries.get(windows_op)
    }

    /// 获取反向映射数量
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// 获取所有反向映射条目
    pub fn all(&self) -> Vec<&ReverseEntry> {
        self.entries.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_mapper_has_all_entries() {
        let mapper = ReverseMapper::new();
        // 正向有 50 条，但部分 windows_op 可能重复（如 ExitProcess 对应 exit 和 exit_group）
        // 反向映射以 windows_op 为 key，重复的会被覆盖
        // 50 条映射中有 6 个重复操作，所以至少应有 44 个唯一
        assert!(
            mapper.count() >= 44,
            "反向映射应有至少 44 个唯一 Windows 操作（当前：{}）",
            mapper.count()
        );
    }

    #[test]
    fn test_reverse_mapper_readfile() {
        let mapper = ReverseMapper::new();
        let entry = mapper.map("ReadFile");
        assert!(entry.is_some(), "ReadFile 应能被反向映射");
        assert_eq!(entry.unwrap().nr, 0);
        assert_eq!(entry.unwrap().linux_name, "read");
    }

    #[test]
    fn test_reverse_mapper_createfilew() {
        let mapper = ReverseMapper::new();
        let entry = mapper.map("CreateFileW");
        assert!(entry.is_some(), "CreateFileW 应能被反向映射");
        assert_eq!(entry.unwrap().nr, 2);
        assert_eq!(entry.unwrap().linux_name, "open");
    }

    #[test]
    fn test_reverse_mapper_unknown_returns_none() {
        let mapper = ReverseMapper::new();
        let entry = mapper.map("NonExistentOp");
        assert!(entry.is_none(), "未知操作应返回 None");
    }

    #[test]
    fn test_reverse_mapper_symmetry() {
        // 验证正向映射的每个条目都能反向映射回来
        let mapper = ReverseMapper::new();
        for entry in &MAPPINGS {
            let rev = mapper.map(entry.windows_op);
            assert!(
                rev.is_some(),
                "正向映射 {} ({}) 的反向映射缺失",
                entry.name,
                entry.windows_op
            );
        }
    }

    #[test]
    fn test_reverse_mapper_roundtrip() {
        // 验证经过正向映射再反向映射后，linux name 一致
        let mapper = ReverseMapper::new();
        // 选择一个 unique 的 windows_op 验证往返
        if let Some(rev) = mapper.map("CreatePipe") {
            assert_eq!(rev.linux_name, "pipe");
        } else {
            panic!("CreatePipe 反向映射缺失");
        }
    }
}
