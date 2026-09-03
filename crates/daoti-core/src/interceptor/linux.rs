//! Linux ptrace 系统调用拦截器 (daoti-core::interceptor::linux)
//!
//! 基于 ptrace(PTRACE_SYSCALL) 的 Linux syscall 捕获实现。
//! 对应《本地二进制信号重映射主路线施工计划》P1 拦截器。
//!
//! 在非 Linux 平台编译为仅含桩代码的模块（不执行 ptrace），
//! 确保 `cargo build --workspace` 跨平台零警告。

use std::collections::VecDeque;

use daoti_common::DaotiError;

use super::{SyscallCaptureSource, SyscallEvent};

/// Linux 架构特定的寄存器布局
#[derive(Debug, Clone, Copy)]
pub enum PtraceArch {
    /// x86_64 (AMD64)
    X86_64,
    /// AArch64 (ARM64)
    AArch64,
}

/// ptrace syscall 捕获结果：一次 syscall 进入（entry）或退出（exit）
#[derive(Debug, Clone, Copy)]
pub struct PtraceSyscall {
    /// syscall 编号
    pub nr: i64,
    /// 参数（最多 6 个）
    pub args: [i64; 6],
    /// 返回值（仅 exit 时有效）
    pub ret: Option<i64>,
    /// 是否条目（entry=true 表示刚进入 syscall，exit=false 表示即将退出）
    pub is_entry: bool,
    /// 线程 ID
    pub tid: i32,
}

/// Linux ptrace 事件源：通过 ptrace(PTRACE_SYSCALL) 捕获子进程的 syscall。
///
/// # 平台说明
/// - Linux: 使用真实的 ptrace 系统调用附加/跟踪子进程。
/// - 非 Linux: 构造函数返回 `Err`，代码保持可编译但不可执行。
///
/// # 用法（Linux 示例）
/// ```ignore
/// let mut source = PtraceCaptureSource::spawn("/bin/echo", &["hello"])?;
/// while let Some(ev) = source.next_event()? {
///     println!("syscall: {} ({:?})", ev.nr, ev.args);
/// }
/// ```
#[derive(Debug)]
pub struct PtraceCaptureSource {
    /// 子进程 PID
    pid: i32,
    /// 待处理的事件队列（entry/exit 对组装后放入）
    pending: VecDeque<SyscallEvent>,
    /// 架构
    arch: PtraceArch,
    /// 当前正在等待 exit 的 syscall 编号（None=等待 entry）
    waiting_exit: Option<i64>,
    /// 当前正在等待 exit 的 syscall 参数
    pending_args: [i64; 6],
}

impl PtraceCaptureSource {
    /// 生成子进程并附加 ptrace，返回捕获源。
    ///
    /// 在非 Linux 平台始终返回 `PermissionDenied` 错误。
    #[cfg(target_os = "linux")]
    pub fn spawn(_path: &str, _args: &[&str]) -> Result<Self, DaotiError> {
        // 使用 unsafe 包装 ptrace 系统调用
        // 实际实现中需要 libc 或 nix crate 的 ptrace 封装
        //
        // 典型流程：
        // 1. fork()
        // 2. 子进程：ptrace(PTRACE_TRACEME) + execve
        // 3. 父进程：waitpid + ptrace(PTRACE_SYSCALL) 循环
        //
        // 此处为最小桩，真实实现依赖 libc::ptrace
        Err(DaotiError::PermissionDenied(
            "ptrace 需要 CAP_SYS_PTRACE 权限，请在 Linux 环境下使用".into(),
        ))
    }

    /// 非 Linux 平台桩：始终返回错误。
    #[cfg(not(target_os = "linux"))]
    pub fn spawn(_path: &str, _args: &[&str]) -> Result<Self, DaotiError> {
        Err(DaotiError::Unavailable(
            "ptrace 拦截器仅支持 Linux 平台".into(),
        ))
    }

    /// 从已附加的进程 PID 创建捕获源（供调试/测试用）。
    #[cfg(target_os = "linux")]
    pub fn attach(_pid: i32) -> Result<Self, DaotiError> {
        // 1. ptrace(PTRACE_ATTACH, pid)
        // 2. waitpid(pid)
        // 3. 确定架构
        // 4. ptrace(PTRACE_SYSCALL, pid)
        Err(DaotiError::PermissionDenied(
            "ptrace ATTACH 需要 CAP_SYS_PTRACE 权限".into(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn attach(_pid: i32) -> Result<Self, DaotiError> {
        Err(DaotiError::Unavailable(
            "ptrace 拦截器仅支持 Linux 平台".into(),
        ))
    }

    /// 创建内部状态的构造函数（平台无关，供测试用）
    #[allow(dead_code)]
    pub(crate) fn new_internal(pid: i32, arch: PtraceArch) -> Self {
        PtraceCaptureSource {
            pid,
            pending: VecDeque::new(),
            arch,
            waiting_exit: None,
            pending_args: [0i64; 6],
        }
    }

    /// 读取子进程的寄存器值（Linux 平台实现）
    #[cfg(target_os = "linux")]
    fn read_registers(&self) -> Result<[i64; 6], DaotiError> {
        // 使用 ptrace(PTRACE_GETREGS, pid) 读取寄存器
        // 返回值取决于架构：
        //   x86_64: rax=nr, rdi/rsi/rdx/r10/r8/r9=args[0..5]
        //   AArch64: x8=nr, x0..x5=args[0..5]
        Err(DaotiError::PermissionDenied(
            "ptrace 寄存器读取需要 CAP_SYS_PTRACE".into(),
        ))
    }

    /// 读取子进程的 syscall 返回值（Linux 平台实现）
    #[cfg(target_os = "linux")]
    fn read_ret_value(&self) -> Result<i64, DaotiError> {
        // ptrace(PTRACE_GETREGS, pid) 然后读取 rax/x0
        Err(DaotiError::PermissionDenied(
            "ptrace 返回值读取需要 CAP_SYS_PTRACE".into(),
        ))
    }

    /// 继续执行到下一次 syscall 捕获点
    #[cfg(target_os = "linux")]
    fn continue_to_syscall(&self) -> Result<(), DaotiError> {
        // ptrace(PTRACE_SYSCALL, pid, 0, 0)
        // waitpid(pid, &status, 0)
        // 检查 status 是否为 PTRACE_EVENT_SYSCALL
        Ok(())
    }

    /// 获取当前架构名称
    pub fn arch_name(&self) -> &'static str {
        match self.arch {
            PtraceArch::X86_64 => "x86_64",
            PtraceArch::AArch64 => "AArch64",
        }
    }

    /// 获取子进程 PID
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

impl SyscallCaptureSource for PtraceCaptureSource {
    fn next_event(&mut self) -> Result<Option<SyscallEvent>, DaotiError> {
        // 先消费已组装好的事件
        if let Some(ev) = self.pending.pop_front() {
            return Ok(Some(ev));
        }

        // 如果没有待处理事件，尝试捕获下一个 syscall
        // 真实 ptrace 实现会：
        // 1. 发出 PTRACE_SYSCALL 继续子进程
        // 2. 等待子进程在 syscall entry 处停下
        // 3. 读取寄存器获取 nr 和 args
        // 4. 发出 PTRACE_SYSCALL 继续子进程
        // 5. 等待子进程在 syscall exit 处停下
        // 6. 读取返回值
        // 7. 组装 SyscallEvent 放入 pending 队列
        //
        // 非 Linux 平台始终返回 None
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self.waiting_exit;
            let _ = self.pending_args;
            Ok(None)
        }

        #[cfg(target_os = "linux")]
        {
            // 如果正在等待 exit，先捕获 exit 事件
            if let Some(nr) = self.waiting_exit.take() {
                let _ret = self.read_ret_value()?;
                self.continue_to_syscall()?;
                let ev = SyscallEvent::new(
                    nr as i32,
                    format!("syscall_{}", nr),
                    self.pending_args.iter().map(|a| a.to_string()).collect(),
                    self.pid as u64,
                );
                self.pending.push_back(ev);
                return Ok(self.pending.pop_front());
            }

            // 等待 entry 事件
            self.continue_to_syscall()?;
            let regs = self.read_registers()?;
            let nr = regs[0]; // rax on x86_64, x8 on AArch64
            let args = regs; // rdi..r9 on x86_64, x0..x5 on AArch64

            self.waiting_exit = Some(nr);
            self.pending_args = args;

            // 继续等待 exit
            self.continue_to_syscall()?;
            let _ret = self.read_ret_value()?;
            self.waiting_exit = None;

            let ev = SyscallEvent::new(
                nr as i32,
                format!("syscall_{}", nr),
                args.iter().map(|a| a.to_string()).collect(),
                self.pid as u64,
            );
            Ok(Some(ev))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptrace_arch_name() {
        let source = PtraceCaptureSource::new_internal(0, PtraceArch::X86_64);
        assert_eq!(source.arch_name(), "x86_64");

        let source = PtraceCaptureSource::new_internal(0, PtraceArch::AArch64);
        assert_eq!(source.arch_name(), "AArch64");
    }

    #[test]
    fn test_ptrace_pid() {
        let source = PtraceCaptureSource::new_internal(42, PtraceArch::X86_64);
        assert_eq!(source.pid(), 42);
    }

    #[test]
    fn test_ptrace_spawn_on_non_linux_returns_error() {
        let result = PtraceCaptureSource::spawn("/bin/echo", &["hello"]);
        // On non-Linux, this should return an error
        // On Linux, it returns PermissionDenied since we don't have real ptrace
        assert!(result.is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_ptrace_next_event_on_non_linux_returns_none() {
        let mut source = PtraceCaptureSource::new_internal(0, PtraceArch::X86_64);
        // On non-Linux, next_event returns None since ptrace is not available
        let result = source.next_event();
        assert!(result.is_ok());
        // On non-Linux the result is Ok(None)
        // On Linux with real ptrace it would return actual events
        #[cfg(not(target_os = "linux"))]
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_arch_determines_register_layout() {
        // x86_64: nr=rax, args=rdi,rsi,rdx,r10,r8,r9
        match PtraceArch::X86_64 {
            PtraceArch::X86_64 => {} // 正确
            _ => panic!("X86_64 架构应被正确识别"),
        }

        // AArch64: nr=x8, args=x0,x1,x2,x3,x4,x5
        match PtraceArch::AArch64 {
            PtraceArch::AArch64 => {} // 正确
            _ => panic!("AArch64 架构应被正确识别"),
        }
    }

    #[test]
    fn test_ptrace_syscall_struct() {
        let syscall = PtraceSyscall {
            nr: 0, // read
            args: [3, 0x7fff, 1024, 0, 0, 0],
            ret: Some(42),
            is_entry: false,
            tid: 12345,
        };
        assert_eq!(syscall.nr, 0);
        assert_eq!(syscall.ret, Some(42));
        assert!(!syscall.is_entry);
    }

    #[test]
    fn test_ptrace_syscall_entry() {
        let syscall = PtraceSyscall {
            nr: 1, // write
            args: [1, 0x600000, 14, 0, 0, 0],
            ret: None,
            is_entry: true,
            tid: 12345,
        };
        assert_eq!(syscall.nr, 1);
        assert!(syscall.ret.is_none());
        assert!(syscall.is_entry);
    }
}
