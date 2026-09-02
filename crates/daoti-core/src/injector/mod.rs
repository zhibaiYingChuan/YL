//! 系统调用注入与回填 (daoti-core::injector)
//!
//! 对应《本地二进制信号重映射主路线施工计划》能力层 4：系统调用注入与回填。
//! 将映射后的目标平台 syscall 注入到目标进程中执行，并回填结果。
//!
//! 与 `interceptor::Injector` 的关系：
//! - `interceptor::Injector` 是 B1 阶段的轻量契约（纯查表注入）
//! - `injector` 模块是主路线的完整实现（真实进程注入 + 寄存器回填 + 内存读写）

pub mod linux;
pub mod windows;

pub use linux_emulation::{AuditBuffer, LinuxEmulationInjector};

mod linux_emulation;

use std::collections::HashMap;

use daoti_common::DaotiError;

use crate::interceptor::{InjectResult, TargetSyscall};

/// 注入结果（包含寄存器状态快照）
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// 执行结果
    pub result: InjectResult,
    /// 返回值（如果适用）
    pub ret_value: Option<i64>,
    /// 执行后的寄存器状态快照（平台相关）
    pub register_snapshot: Vec<u8>,
}

/// 注入器 trait：统一的 syscall 注入接口
pub trait Injector: Send + Sync {
    /// 注入一条目标操作并执行
    fn inject(&self, target: &TargetSyscall) -> Result<InjectionResult, DaotiError>;

    /// 批量注入（默认实现为逐个调用）
    fn inject_batch(&self, targets: &[TargetSyscall]) -> Result<Vec<InjectionResult>, DaotiError> {
        targets.iter().map(|t| self.inject(t)).collect()
    }

    /// 获取支持的注入操作列表
    fn supported_operations(&self) -> Vec<&str>;
}

/// 模拟注入器：基于本地模拟的实现（不涉及真实进程注入）
///
/// 用于测试和开发阶段，验证注入逻辑正确性而不依赖真实调试 API。
#[derive(Debug, Default)]
pub struct MockInjector {
    /// 预设的返回值映射表（operation → 返回值）
    results: HashMap<String, InjectionResult>,
}

impl MockInjector {
    /// 创建模拟注入器
    pub fn new() -> Self {
        MockInjector {
            results: HashMap::new(),
        }
    }

    /// 预设某个操作的成功返回值
    pub fn with_ok(mut self, operation: &str, ret_value: i64) -> Self {
        self.results.insert(
            operation.to_string(),
            InjectionResult {
                result: InjectResult::new(operation, true, "模拟注入成功"),
                ret_value: Some(ret_value),
                register_snapshot: vec![],
            },
        );
        self
    }

    /// 预设某个操作的失败返回值
    pub fn with_fail(mut self, operation: &str, detail: &str) -> Self {
        self.results.insert(
            operation.to_string(),
            InjectionResult {
                result: InjectResult::new(operation, false, detail),
                ret_value: None,
                register_snapshot: vec![],
            },
        );
        self
    }
}

impl Injector for MockInjector {
    fn inject(&self, target: &TargetSyscall) -> Result<InjectionResult, DaotiError> {
        if let Some(result) = self.results.get(&target.operation) {
            Ok(result.clone())
        } else {
            // 默认返回成功
            Ok(InjectionResult {
                result: InjectResult::new(&target.operation, true, "模拟注入（无预设）"),
                ret_value: Some(0),
                register_snapshot: vec![],
            })
        }
    }

    fn supported_operations(&self) -> Vec<&str> {
        self.results.keys().map(|k| k.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_injector_default_ok() {
        let injector = MockInjector::new();
        let target = TargetSyscall::new("ReadFile", "读文件");
        let result = injector.inject(&target).expect("注入应成功");
        assert!(result.result.success);
        assert_eq!(result.ret_value, Some(0));
    }

    #[test]
    fn test_mock_injector_with_ok() {
        let injector = MockInjector::new().with_ok("ReadFile", 42);
        let target = TargetSyscall::new("ReadFile", "读文件");
        let result = injector.inject(&target).expect("注入应成功");
        assert!(result.result.success);
        assert_eq!(result.ret_value, Some(42));
    }

    #[test]
    fn test_mock_injector_with_fail() {
        let injector = MockInjector::new().with_fail("WriteFile", "磁盘已满");
        let target = TargetSyscall::new("WriteFile", "写文件");
        let result = injector.inject(&target).expect("注入应成功");
        assert!(!result.result.success);
        assert_eq!(result.result.detail, "磁盘已满");
    }

    #[test]
    fn test_mock_injector_batch() {
        let injector = MockInjector::new()
            .with_ok("ReadFile", 100)
            .with_ok("WriteFile", 200);
        let targets = vec![
            TargetSyscall::new("ReadFile", "读文件"),
            TargetSyscall::new("WriteFile", "写文件"),
        ];
        let results = injector.inject_batch(&targets).expect("批量注入应成功");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ret_value, Some(100));
        assert_eq!(results[1].ret_value, Some(200));
    }
}
