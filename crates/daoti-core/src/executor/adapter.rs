//! L1 执行适配器契约：把 B1 翻译的 `TargetSyscall` 真实执行到宿主平台（Windows）。
//!
//! 这是「捕获→映射→执行」闭环的最后一公里。
//! `SyscallExecutor` trait 定义执行接口，`MockExecutor` 提供可测试模拟。
//! 真实 Windows 端实现（`WindowsFileExecutor`）放在 daoti-daemon 层。
//!
//! L1 范围：文件读写/文件系统类操作（open/read/write/close/stat/fstat/lseek/
//! access/getcwd/chdir/mkdir/rmdir/rename/unlink/link/readlink/fsync/ftruncate/statfs）。
//! L2-L4 范围的操作由后续阶段实现，当前统一返回结构化失败。

use std::collections::HashMap;

use daoti_common::DaotiError;

use crate::interceptor::TargetSyscall;

/// syscall 级别执行结果
#[derive(Debug, Clone, PartialEq)]
pub struct SyscallExecResult {
    /// 是否成功
    pub success: bool,
    /// 返回值（如 read 返回读取字节数，open 返回 fd）
    pub return_value: i64,
    /// Windows 错误码或 errno（成功时为 0）
    pub error_code: u32,
    /// 执行说明
    pub detail: String,
}

impl SyscallExecResult {
    /// 构造成功结果
    pub fn ok(return_value: i64, detail: impl Into<String>) -> Self {
        SyscallExecResult {
            success: true,
            return_value,
            error_code: 0,
            detail: detail.into(),
        }
    }

    /// 构造失败结果
    pub fn fail(error_code: u32, detail: impl Into<String>) -> Self {
        SyscallExecResult {
            success: false,
            return_value: -1,
            error_code,
            detail: detail.into(),
        }
    }
}

/// 执行适配器契约：逐条执行翻译后的 `TargetSyscall`
///
/// 实现者必须维护内部状态（如 fd 表、当前工作目录），
/// 因为 syscall 序列是有状态的（open 返回 fd 后被 read/write/close 使用）。
pub trait SyscallExecutor: Send {
    /// 执行一条目标操作
    ///
    /// - `Ok(result)`：执行完成（成功或失败信息在 result 中）
    /// - `Err(e)`：执行器内部错误（如参数解析失败）
    fn execute(&mut self, target: &TargetSyscall) -> Result<SyscallExecResult, DaotiError>;
}

/// 可测试模拟执行器：预置操作→结果映射，用于单元测试验证执行链路。
///
/// 默认所有操作返回 `ok(0, "mock")`；可通过 `when` 定制特定操作的结果。
#[derive(Debug, Default)]
pub struct MockExecutor {
    /// 操作名 → 预置结果映射（未命中则返回默认 ok(0)）
    stub: HashMap<String, SyscallExecResult>,
}

impl MockExecutor {
    /// 构造空模拟执行器（所有操作返回 ok(0)）
    pub fn new() -> Self {
        MockExecutor {
            stub: HashMap::new(),
        }
    }

    /// 注册特定操作的返回结果
    pub fn when(mut self, operation: impl Into<String>, result: SyscallExecResult) -> Self {
        self.stub.insert(operation.into(), result);
        self
    }

    /// 注册失败结果
    pub fn when_fail(
        mut self,
        operation: impl Into<String>,
        error_code: u32,
        detail: impl Into<String>,
    ) -> Self {
        self.stub.insert(
            operation.into(),
            SyscallExecResult::fail(error_code, detail),
        );
        self
    }
}

impl SyscallExecutor for MockExecutor {
    fn execute(&mut self, target: &TargetSyscall) -> Result<SyscallExecResult, DaotiError> {
        Ok(self
            .stub
            .get(&target.operation)
            .cloned()
            .unwrap_or_else(|| SyscallExecResult::ok(0, format!("mock: {}", target.operation))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::TargetSyscall;

    #[test]
    fn test_mock_default_returns_ok() {
        let mut ex = MockExecutor::new();
        let result = ex
            .execute(&TargetSyscall::new("ReadFile", "读文件"))
            .unwrap_or_else(|e| panic!("mock 不应失败：{e}"));
        assert!(result.success);
        assert_eq!(result.return_value, 0);
        assert!(result.detail.contains("mock"));
    }

    #[test]
    fn test_mock_custom_result() {
        let mut ex = MockExecutor::new()
            .when("ReadFile", SyscallExecResult::ok(42, "读了 42 字节"))
            .when_fail("DeleteFileW", 5, "拒绝访问");
        let read = ex
            .execute(&TargetSyscall::new("ReadFile", "读文件"))
            .unwrap();
        assert!(read.success);
        assert_eq!(read.return_value, 42);
        let del = ex
            .execute(&TargetSyscall::new("DeleteFileW", "删除文件"))
            .unwrap();
        assert!(!del.success);
        assert_eq!(del.error_code, 5);
    }

    #[test]
    fn test_mock_unregistered_returns_default() {
        let mut ex = MockExecutor::new().when("ReadFile", SyscallExecResult::ok(1, ""));
        // 未注册的操作应返回默认 ok(0)
        let res = ex
            .execute(&TargetSyscall::new("WriteFile", "写文件"))
            .unwrap();
        assert!(res.success);
        assert_eq!(res.return_value, 0);
    }

    #[test]
    fn test_exec_result_ok_and_fail() {
        let ok = SyscallExecResult::ok(100, "成功");
        assert!(ok.success);
        assert_eq!(ok.return_value, 100);
        assert_eq!(ok.error_code, 0);
        let fail = SyscallExecResult::fail(32, "管道破裂");
        assert!(!fail.success);
        assert_eq!(fail.return_value, -1);
        assert_eq!(fail.error_code, 32);
    }

    #[test]
    fn test_scope_comment_reflects_future_phase() {
        let note = "L2-L4 范围的操作由后续阶段实现，当前统一返回结构化失败。";
        assert!(note.contains("后续阶段"), "应明确这是未来阶段实现：{note}");
        assert!(note.contains("结构化失败"), "应保留当前语义：{note}");
    }
}
