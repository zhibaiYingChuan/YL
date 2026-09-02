//! 系统调用语义映射器 (daoti-core::mapper)
//!
//! 对应《本地二进制信号重映射主路线施工计划》能力层 3：系统调用语义映射。
//! 提供 Linux ↔ Win32 双向确定性映射表 + 参数转换规则。
//!
//! 与 `interceptor::SyscallMapper` 的区别：
//! - `interceptor::SyscallMapper` 是 B1 阶段的轻量映射（20→30 条，无参数转换）
//! - `mapper` 模块是主路线的完整映射（50 条 + 参数转换 + 反向映射）
//! - 两者共享相同的 Linux x86_64 ABI 编号，但 `mapper` 更完整

pub mod linux_to_win;
pub mod param_convert;
pub mod win_to_linux;

use std::collections::HashMap;

use daoti_common::DaotiError;

use crate::interceptor::{SyscallEvent, TargetSyscall};

/// 单条映射项（含参数转换规则）
#[derive(Debug, Clone)]
pub struct MappingEntry {
    /// Linux syscall 编号
    pub nr: i32,
    /// Linux syscall 名称
    pub name: &'static str,
    /// 映射后的 Windows 操作名
    pub windows_op: &'static str,
    /// 操作说明
    pub description: &'static str,
    /// 是否需要参数转换
    pub needs_param_convert: bool,
    /// 是否可直通（true=无需降级）
    pub direct: bool,
}

/// 映射器 trait：统一的 syscall 映射接口
pub trait Mapper: Send + Sync {
    /// 映射一条 Linux syscall 到 Windows 操作
    fn map(&self, event: &SyscallEvent) -> Result<Option<TargetSyscall>, DaotiError>;

    /// 获取支持的 syscall 数量
    fn supported_count(&self) -> usize;

    /// 获取所有映射条目
    fn all_entries(&self) -> &[MappingEntry];
}

/// 确定性映射器：基于静态映射表的实现
#[derive(Debug, Default)]
pub struct DeterministicMapper {
    /// 映射表（Linux nr → MappingEntry 的快速查找）
    entries: HashMap<i32, MappingEntry>,
    /// 有序条目列表（用于迭代和报告）
    ordered: Vec<MappingEntry>,
}

impl DeterministicMapper {
    /// 构建完整的映射器（包含 50 条 Linux→Win32 映射）
    pub fn new() -> Self {
        let ordered = linux_to_win::MAPPINGS.to_vec();
        let entries: HashMap<i32, MappingEntry> =
            ordered.iter().map(|e| (e.nr, e.clone())).collect();
        DeterministicMapper { entries, ordered }
    }

    /// 按 Windows 操作名反向查找 Linux syscall 编号
    pub fn reverse_map(&self, windows_op: &str) -> Option<&MappingEntry> {
        self.ordered.iter().find(|e| e.windows_op == windows_op)
    }

    /// 按 syscall 名称查找
    pub fn map_by_name(&self, name: &str) -> Option<&MappingEntry> {
        self.ordered.iter().find(|e| e.name == name)
    }
}

impl Mapper for DeterministicMapper {
    fn map(&self, event: &SyscallEvent) -> Result<Option<TargetSyscall>, DaotiError> {
        Ok(self.entries.get(&event.nr).map(|entry| {
            let mut target =
                TargetSyscall::new(entry.windows_op, entry.description).with_args(&event.args);

            // 如果条目需要参数转换，应用转换规则
            if entry.needs_param_convert {
                if let Ok(converted) =
                    param_convert::convert_args(entry.name, entry.windows_op, &event.args)
                {
                    target = TargetSyscall::new(entry.windows_op, entry.description)
                        .with_args(&converted);
                }
            }

            target
        }))
    }

    fn supported_count(&self) -> usize {
        self.ordered.len()
    }

    fn all_entries(&self) -> &[MappingEntry] {
        &self.ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapper_has_50_entries() {
        let mapper = DeterministicMapper::new();
        assert_eq!(mapper.supported_count(), 50, "映射表应有 50 条条目");
    }

    #[test]
    fn test_mapper_maps_core_syscalls() {
        let mapper = DeterministicMapper::new();
        // read (nr=0)
        let ev = SyscallEvent::new(
            0,
            "read",
            vec!["3".into(), "0x7fff".into(), "1024".into()],
            1,
        );
        let result = mapper.map(&ev).expect("映射应成功");
        assert!(result.is_some());
        assert_eq!(result.unwrap().operation, "ReadFile");

        // write (nr=1)
        let ev = SyscallEvent::new(1, "write", vec![], 1);
        let result = mapper.map(&ev).expect("映射应成功");
        assert!(result.is_some());
        assert_eq!(result.unwrap().operation, "WriteFile");
    }

    #[test]
    fn test_mapper_unknown_syscall_returns_none() {
        let mapper = DeterministicMapper::new();
        let ev = SyscallEvent::new(9999, "unknown", vec![], 1);
        let result = mapper.map(&ev).expect("未知 syscall 不应抛错");
        assert!(result.is_none());
    }

    #[test]
    fn test_mapper_reverse_map() {
        let mapper = DeterministicMapper::new();
        let entry = mapper.reverse_map("ReadFile");
        assert!(entry.is_some(), "ReadFile 应能被反向映射");
        assert_eq!(entry.unwrap().nr, 0);
    }

    #[test]
    fn test_mapper_map_by_name() {
        let mapper = DeterministicMapper::new();
        let entry = mapper.map_by_name("open");
        assert!(entry.is_some(), "open 应能被名称查找");
        assert_eq!(entry.unwrap().windows_op, "CreateFileW");
    }

    #[test]
    fn test_mapper_all_entries_are_unique() {
        let mapper = DeterministicMapper::new();
        let mut nrs = std::collections::HashSet::new();
        for entry in mapper.all_entries() {
            assert!(nrs.insert(entry.nr), "syscall nr {} 重复", entry.nr);
        }
        assert_eq!(nrs.len(), 50);
    }
}
