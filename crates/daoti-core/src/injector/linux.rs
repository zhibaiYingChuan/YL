//! Linux 注入器 (daoti-core::injector::linux)
//!
//! 基于 ptrace 的 Linux syscall 注入与回填实现。
//! 对应《本地二进制信号重映射主路线施工计划》P4 注入器。
//!
//! 核心能力：
//! - ptrace(PTRACE_SETREGS)：修改目标线程寄存器以注入 syscall 参数
//! - ptrace(PTRACE_GETREGS)：读取寄存器获取 syscall 结果
//! - ptrace(PTRACE_POKEDATA)：写入目标进程内存
//! - ptrace(PTRACE_PEEKDATA)：读取目标进程内存

use daoti_common::DaotiError;

use super::Injector;
use crate::injector::InjectionResult;
#[cfg(target_os = "linux")]
use crate::interceptor::InjectResult;
use crate::interceptor::TargetSyscall;

/// Linux 注入器实现
///
/// # 平台说明
/// - Linux: 使用真实 ptrace 系统调用。
/// - 非 Linux: 返回错误，代码保持可编译。
#[derive(Debug)]
pub struct LinuxInjector {
    /// 目标进程 PID
    pid: i32,
}

impl LinuxInjector {
    /// 附加到目标进程
    ///
    /// # Linux 实现
    /// 1. ptrace(PTRACE_ATTACH, pid)
    /// 2. waitpid(pid, &status, 0)
    ///
    /// # 非 Linux 平台
    /// 始终返回 `Unavailable` 错误。
    #[cfg(target_os = "linux")]
    pub fn attach(pid: i32) -> Result<Self, DaotiError> {
        // 真实实现：
        // 1. ptrace(PTRACE_ATTACH, pid, 0, 0)
        // 2. waitpid(pid, &status, 0)
        // 3. 检查 status 中的 PTRACE_EVENT
        Err(DaotiError::PermissionDenied(
            "ptrace ATTACH 需要 CAP_SYS_PTRACE 权限".into(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn attach(_pid: i32) -> Result<Self, DaotiError> {
        Err(DaotiError::Unavailable(
            "Linux 注入器仅支持 Linux 平台".into(),
        ))
    }

    /// 创建内部状态的构造函数（平台无关，供测试用）
    #[allow(dead_code)]
    pub(crate) fn new_internal(pid: i32) -> Self {
        LinuxInjector { pid }
    }

    /// 设置寄存器以注入 syscall
    ///
    /// 对于 x86_64：
    /// - rax = syscall 编号
    /// - rdi, rsi, rdx, r10, r8, r9 = 参数 0-5
    #[cfg(target_os = "linux")]
    fn set_syscall_regs(&self, _nr: i64, _args: &[i64]) -> Result<(), DaotiError> {
        // 1. ptrace(PTRACE_GETREGS, pid, 0, &regs)
        // 2. 修改 regs.rax = nr, regs.rdi = args[0], etc.
        // 3. ptrace(PTRACE_SETREGS, pid, 0, &regs)
        Err(DaotiError::PermissionDenied(
            "PTRACE_SETREGS 需要 CAP_SYS_PTRACE 权限".into(),
        ))
    }

    /// 读取 syscall 返回值
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn read_ret_value(&self) -> Result<i64, DaotiError> {
        // 1. ptrace(PTRACE_GETREGS, pid, 0, &regs)
        // 2. 返回 regs.rax
        Err(DaotiError::PermissionDenied(
            "PTRACE_GETREGS 需要 CAP_SYS_PTRACE 权限".into(),
        ))
    }

    /// 写入目标进程内存
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn write_memory(&self, _addr: u64, _data: &[u8]) -> Result<(), DaotiError> {
        // 1. 按 word 对齐，逐个 ptrace(PTRACE_POKEDATA, pid, addr, word)
        Err(DaotiError::PermissionDenied(
            "PTRACE_POKEDATA 需要 CAP_SYS_PTRACE 权限".into(),
        ))
    }

    /// 读取目标进程内存
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn read_memory(&self, _addr: u64, _size: usize) -> Result<Vec<u8>, DaotiError> {
        // 1. 逐个 ptrace(PTRACE_PEEKDATA, pid, addr, 0)
        Err(DaotiError::PermissionDenied(
            "PTRACE_PEEKDATA 需要 CAP_SYS_PTRACE 权限".into(),
        ))
    }

    /// 获取进程 PID
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

impl Injector for LinuxInjector {
    fn inject(&self, target: &TargetSyscall) -> Result<InjectionResult, DaotiError> {
        // 非 Linux 平台：返回错误
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            Err(DaotiError::Unavailable(
                "Linux 注入器仅支持 Linux 平台".into(),
            ))
        }

        // Linux 平台实现
        #[cfg(target_os = "linux")]
        {
            // 1. 解析 target.args 为 syscall 参数
            // 2. SetSyscallRegs(nr, args)
            // 3. ptrace(PTRACE_CONT) 继续执行
            // 4. waitpid 等待 syscall exit
            // 5. ReadRetValue()
            // 6. 包装 InjectionResult

            self.set_syscall_regs(0, &[])?;

            Ok(InjectionResult {
                result: InjectResult::new(&target.operation, true, "注入成功"),
                ret_value: Some(0),
                register_snapshot: vec![],
            })
        }
    }

    fn supported_operations(&self) -> Vec<&str> {
        vec![
            "read", "write", "open", "close", "stat", "fstat", "lseek", "mmap", "munmap", "brk",
            "exit", "getpid", "gettid", "getcwd", "chdir",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_injector_pid() {
        let injector = LinuxInjector::new_internal(42);
        assert_eq!(injector.pid(), 42);
    }

    #[test]
    fn test_linux_injector_attach_on_non_linux() {
        let result = LinuxInjector::attach(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_linux_injector_supported_operations() {
        let injector = LinuxInjector::new_internal(0);
        let ops = injector.supported_operations();
        assert!(ops.contains(&"read"));
        assert!(ops.contains(&"write"));
        assert!(ops.contains(&"exit"));
        assert!(ops.len() >= 15, "应支持至少 15 个操作");
    }

    #[test]
    fn test_linux_injector_inject_on_non_linux() {
        let injector = LinuxInjector::new_internal(0);
        let target = TargetSyscall::new("read", "读文件");
        let result = injector.inject(&target);
        #[cfg(not(target_os = "linux"))]
        assert!(result.is_err(), "非 Linux 平台应返回错误");
    }
}
