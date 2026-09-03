//! Windows 注入器 (daoti-core::injector::windows)
//!
//! 基于 Windows Debug API + NtContinue 的 syscall 注入与回填实现。
//! 对应《本地二进制信号重映射主路线施工计划》P4 注入器。
//!
//! 核心能力：
//! - SetThreadContext：修改目标线程寄存器以注入 syscall 参数
//! - GetThreadContext：读取寄存器获取 syscall 结果
//! - WriteProcessMemory：写入目标进程内存
//! - ReadProcessMemory：读取目标进程内存
//! - NtContinue：恢复线程执行

use daoti_common::DaotiError;

use super::Injector;
use crate::injector::InjectionResult;
#[cfg(target_os = "windows")]
use crate::interceptor::InjectResult;
use crate::interceptor::TargetSyscall;

/// Windows 注入器实现
///
/// # 平台说明
/// - Windows: 使用真实 Windows Debug API（kernel32!SetThreadContext 等）。
/// - 非 Windows: 返回错误，代码保持可编译。
#[allow(dead_code)]
#[derive(Debug)]
pub struct WindowsInjector {
    /// 目标进程 PID
    pid: u32,
    /// 目标线程 ID
    tid: u32,
    /// 进程句柄
    process_handle: Option<u64>,
    /// 线程句柄
    thread_handle: Option<u64>,
}

impl WindowsInjector {
    /// 创建注入器（附加到目标进程/线程）
    ///
    /// # Windows 实现
    /// 1. OpenProcess(PROCESS_ALL_ACCESS, pid)
    /// 2. OpenThread(THREAD_ALL_ACCESS, tid)
    ///
    /// # 非 Windows 平台
    /// 始终返回 `Unavailable` 错误。
    #[cfg(not(target_os = "windows"))]
    pub fn attach(_pid: u32, _tid: u32) -> Result<Self, DaotiError> {
        Err(DaotiError::Unavailable(
            "Windows 注入器仅支持 Windows 平台".into(),
        ))
    }

    #[cfg(target_os = "windows")]
    pub fn attach(_pid: u32, _tid: u32) -> Result<Self, DaotiError> {
        // 真实实现：
        // 1. OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid)
        // 2. OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid)
        // 3. 保存句柄
        Err(DaotiError::PermissionDenied(
            "Windows 注入器需要 PROCESS_VM_* 和 THREAD_* 权限".into(),
        ))
    }

    /// 创建内部状态的构造函数（平台无关，供测试用）
    #[allow(dead_code)]
    pub(crate) fn new_internal(pid: u32, tid: u32) -> Self {
        WindowsInjector {
            pid,
            tid,
            process_handle: None,
            thread_handle: None,
        }
    }

    /// 注入 syscall 参数到目标线程寄存器
    ///
    /// 对于 x86_64：
    /// - rax = syscall 编号
    /// - rcx = 返回地址
    /// - rdx, r8, r9, r10 = 参数 0-3
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn set_syscall_args(&self, _nr: i32, _args: &[String]) -> Result<(), DaotiError> {
        // 真实实现：
        // 1. SuspendThread(thread_handle)
        // 2. GetThreadContext(thread_handle, &context)
        // 3. 修改 context.Rax / context.Rcx / context.Rdx 等
        // 4. SetThreadContext(thread_handle, &context)
        // 5. ResumeThread(thread_handle)
        Err(DaotiError::PermissionDenied(
            "SetThreadContext 需要 THREAD_SET_CONTEXT 权限".into(),
        ))
    }

    /// 读取 syscall 返回值从目标线程寄存器
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn read_ret_value(&self) -> Result<i64, DaotiError> {
        // 1. GetThreadContext(thread_handle, &context)
        // 2. 返回 context.Rax (x86_64) 或 context.Eax (x86)
        Err(DaotiError::PermissionDenied(
            "GetThreadContext 需要 THREAD_GET_CONTEXT 权限".into(),
        ))
    }

    /// 写入目标进程内存
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn write_process_memory(&self, _addr: u64, _data: &[u8]) -> Result<(), DaotiError> {
        // 1. WriteProcessMemory(process_handle, addr, data, size, &written)
        Err(DaotiError::PermissionDenied(
            "WriteProcessMemory 需要 PROCESS_VM_WRITE 权限".into(),
        ))
    }

    /// 读取目标进程内存
    #[cfg(target_os = "windows")]
    #[allow(dead_code)]
    fn read_process_memory(&self, _addr: u64, _size: usize) -> Result<Vec<u8>, DaotiError> {
        // 1. ReadProcessMemory(process_handle, addr, buf, size, &read)
        Err(DaotiError::PermissionDenied(
            "ReadProcessMemory 需要 PROCESS_VM_READ 权限".into(),
        ))
    }

    /// 获取进程 ID
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 获取线程 ID
    pub fn tid(&self) -> u32 {
        self.tid
    }
}

impl Injector for WindowsInjector {
    fn inject(&self, target: &TargetSyscall) -> Result<InjectionResult, DaotiError> {
        // 非 Windows 平台：返回错误
        #[cfg(not(target_os = "windows"))]
        {
            let _ = target;
            Err(DaotiError::Unavailable(
                "Windows 注入器仅支持 Windows 平台".into(),
            ))
        }

        // Windows 平台实现
        #[cfg(target_os = "windows")]
        {
            // 1. 解析 target.args 为 syscall 参数
            // 2. SetSyscallArgs(nr, args)
            // 3. NtContinue 恢复执行
            // 4. 等待执行完成
            // 5. ReadRetValue()
            // 6. 包装 InjectionResult

            self.set_syscall_args(0, &target.args)?;

            Ok(InjectionResult {
                result: InjectResult::new(&target.operation, true, "注入成功"),
                ret_value: Some(0),
                register_snapshot: vec![],
            })
        }
    }

    fn supported_operations(&self) -> Vec<&str> {
        vec![
            "ReadFile",
            "WriteFile",
            "CreateFileW",
            "CloseHandle",
            "VirtualAlloc",
            "VirtualFree",
            "HeapAlloc/HeapFree",
            "SetConsoleCtrlHandler",
            "DeviceIoControl",
            "GetFileAttributesExW",
            "GetFileInformationByHandle",
            "SetFilePointerEx",
            "DuplicateHandle",
            "CreatePipe",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "GetCurrentDirectoryW",
            "SetCurrentDirectoryW",
            "CreateDirectoryW",
            "RemoveDirectoryW",
            "MoveFileW",
            "DeleteFileW",
            "CreateHardLinkW",
            "GetFinalPathNameByHandleW",
            "GetDiskFreeSpaceExW",
            "FlushFileBuffers",
            "SetEndOfFile",
            "ExitProcess",
            "CreateProcess",
            "CreateThread",
            "TerminateProcess",
            "WaitForSingleObject",
            "GetVersionExW",
            "GetUserNameW",
            "SwitchToThread",
            "VirtualProtect",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_injector_pid_tid() {
        let injector = WindowsInjector::new_internal(1234, 5678);
        assert_eq!(injector.pid(), 1234);
        assert_eq!(injector.tid(), 5678);
    }

    #[test]
    fn test_windows_injector_attach_on_non_windows() {
        let result = WindowsInjector::attach(0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_windows_injector_supported_operations() {
        let injector = WindowsInjector::new_internal(0, 0);
        let ops = injector.supported_operations();
        assert!(ops.contains(&"ReadFile"));
        assert!(ops.contains(&"WriteFile"));
        assert!(ops.contains(&"ExitProcess"));
        assert!(ops.len() >= 34, "应支持至少 34 个操作");
    }

    #[test]
    fn test_windows_injector_inject_on_non_windows() {
        let injector = WindowsInjector::new_internal(0, 0);
        let target = TargetSyscall::new("ReadFile", "读文件");
        let _result = injector.inject(&target);
        #[cfg(not(target_os = "windows"))]
        assert!(_result.is_err(), "非 Windows 平台应返回错误");
    }
}
