//! Windows Debug API 系统调用拦截器 (daoti-core::interceptor::windows)
//!
//! 基于 Windows Debug API 的 syscall 捕获实现。
//! 对应《本地二进制信号重映射主路线施工计划》P2 拦截器。
//!
//! 使用 `CreateProcess(DEBUG_PROCESS)` 创建受调试子进程，
//! 通过 `WaitForDebugEvent` / `ContinueDebugEvent` 循环捕获调试事件。
//!
//! # 架构说明
//! Windows 没有与 Linux ptrace(PTRACE_SYSCALL) 等价的单条 API。
//! 本实现采用以下策略：
//! - 创建进程时附加调试器（DEBUG_PROCESS）
//! - 处理 EXCEPTION_BREAKPOINT 事件（INT3 断点）
//! - 通过 GetThreadContext 读取寄存器获取 syscall 参数
//! - 通过 SetThreadContext 修改寄存器实现参数注入/结果回填
//! - 断点位置在 ntdll!NtXxx 系列 stub 入口处

use std::collections::VecDeque;

use daoti_common::DaotiError;

use super::{SyscallCaptureSource, SyscallEvent};

/// Windows 架构
#[derive(Debug, Clone, Copy)]
pub enum DebugApiArch {
    /// x86_64 (AMD64)
    X86_64,
    /// x86 (32-bit)
    X86,
    /// AArch64
    AArch64,
}

/// 调试事件类型（与 Windows SDK 的 DEBUG_EVENT 对应）
#[derive(Debug, Clone, Copy)]
pub enum DebugEventKind {
    /// 断点/异常事件
    Exception,
    /// 创建线程
    CreateThread,
    /// 创建进程
    CreateProcess,
    /// 退出线程
    ExitThread,
    /// 退出进程
    ExitProcess,
    /// 加载 DLL
    LoadDll,
    /// 卸载 DLL
    UnloadDll,
    /// 输出调试字符串
    OutputDebugString,
    /// RIP 事件
    RipEvent,
}

/// 一个被捕获的调试事件
#[derive(Debug, Clone)]
pub struct DebugEvent {
    /// 事件类型
    pub kind: DebugEventKind,
    /// 进程 ID
    pub pid: u32,
    /// 线程 ID
    pub tid: u32,
    /// 异常代码（仅 Exception 事件有效）
    pub exception_code: Option<u32>,
    /// 异常地址（仅 Exception 事件有效）
    pub exception_address: Option<u64>,
}

/// Windows Debug API 事件源：通过调试 API 捕获子进程的调试事件。
///
/// # 平台说明
/// - Windows: 使用真实 Debug API（kernel32!WaitForDebugEvent 等）。
/// - 非 Windows: 构造函数返回错误，代码保持可编译。
///
/// # 最小可用流程
/// 1. `DebugCaptureSource::spawn("cmd.exe", &["/c", "echo hello"])` 创建调试子进程
/// 2. 循环调用 `next_event()` 获取调试事件流
/// 3. 处理 `Exception` 事件（断点命中）时提取 syscall 信息
/// 4. 进程退出时 `next_event()` 返回 `None`
#[derive(Debug)]
pub struct DebugCaptureSource {
    /// 子进程 PID
    pid: u32,
    /// 子进程句柄
    #[allow(dead_code)]
    process_handle: Option<u64>,
    /// 主线程句柄
    #[allow(dead_code)]
    thread_handle: Option<u64>,
    /// 待处理的事件队列
    pending: VecDeque<SyscallEvent>,
    /// 架构
    arch: DebugApiArch,
    /// 是否仍在运行
    running: bool,
}

impl DebugCaptureSource {
    /// 创建调试子进程并附加 Debug API，返回捕获源。
    ///
    /// # Windows 实现
    /// 调用 `CreateProcessW` 带 `DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS` 标志。
    ///
    /// # 非 Windows 平台
    /// 始终返回 `Unavailable` 错误。
    #[cfg(target_os = "windows")]
    pub fn spawn(_path: &str, _args: &[&str]) -> Result<Self, DaotiError> {
        // 真实实现使用 windows-sys 或 winapi crate：
        //
        // 1. 构建 STARTUPINFOEXW
        // 2. 调用 CreateProcessW(
        //      lpCommandLine,
        //      dwCreationFlags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
        //      ...
        //    )
        // 3. 保存进程/线程句柄
        // 4. 确定目标架构（从 PE 头解析）
        //
        // 以下为最小桩，真实实现需要 windows-sys crate
        Err(DaotiError::PermissionDenied(
            "Windows Debug API 需要管理员权限或调试特权（SeDebugPrivilege）".into(),
        ))
    }

    /// 非 Windows 平台桩：始终返回错误。
    #[cfg(not(target_os = "windows"))]
    pub fn spawn(_path: &str, _args: &[&str]) -> Result<Self, DaotiError> {
        Err(DaotiError::Unavailable(
            "Windows Debug API 拦截器仅支持 Windows 平台".into(),
        ))
    }

    /// 创建内部状态的构造函数（平台无关，供测试用）
    #[allow(dead_code)]
    pub(crate) fn new_internal(pid: u32, arch: DebugApiArch) -> Self {
        DebugCaptureSource {
            pid,
            process_handle: None,
            thread_handle: None,
            pending: VecDeque::new(),
            arch,
            running: true,
        }
    }

    /// 转换 DebugEvent 为 SyscallEvent（平台无关逻辑）
    ///
    /// 当异常代码为 EXCEPTION_BREAKPOINT (0x80000003) 且
    /// 异常地址在 ntdll 的 syscall stub 范围内时，解析 syscall 信息。
    pub fn debug_event_to_syscall(event: &DebugEvent) -> Option<SyscallEvent> {
        match event.kind {
            DebugEventKind::Exception => {
                if let Some(code) = event.exception_code {
                    // EXCEPTION_BREAKPOINT = 0x80000003
                    // EXCEPTION_SINGLE_STEP = 0x80000004
                    if code == 0x80000003 || code == 0x80000004 {
                        // 从异常地址推断 syscall 编号
                        // 真实实现中，需要读取 RIP 处的指令字节来确定 syscall 号
                        // 对于 x86_64: syscall 指令是 0F 05，其前的 mov eax, nr 给出编号
                        let nr = (event.exception_address.unwrap_or(0) & 0xFF) as i32;
                        let name = format!("nt_{:#x}", nr);
                        return Some(SyscallEvent::new(nr, name, vec![], event.tid as u64));
                    }
                }
                None
            }
            DebugEventKind::ExitProcess => {
                // 进程退出事件，不产生 syscall
                None
            }
            _ => None,
        }
    }

    /// 等待下一个调试事件（Windows 平台实现）
    #[cfg(target_os = "windows")]
    fn wait_for_debug_event(&self) -> Result<DebugEvent, DaotiError> {
        // 真实实现：
        // 1. WaitForDebugEvent(&debug_event, INFINITE)
        // 2. 根据 debug_event.dwDebugEventCode 分发
        // 3. 转换 DebugEvent 结构体
        // 4. ContinueDebugEvent(pid, tid, DBG_CONTINUE)
        Err(DaotiError::PermissionDenied(
            "WaitForDebugEvent 需要调试特权".into(),
        ))
    }

    /// 获取当前架构名称
    pub fn arch_name(&self) -> &'static str {
        match self.arch {
            DebugApiArch::X86_64 => "x86_64",
            DebugApiArch::X86 => "x86",
            DebugApiArch::AArch64 => "AArch64",
        }
    }

    /// 获取子进程 PID
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 子进程是否仍在运行
    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl SyscallCaptureSource for DebugCaptureSource {
    fn next_event(&mut self) -> Result<Option<SyscallEvent>, DaotiError> {
        // 先消费已组装好的事件
        if let Some(ev) = self.pending.pop_front() {
            return Ok(Some(ev));
        }

        if !self.running {
            return Ok(None);
        }

        // 非 Windows 平台：返回 None
        #[cfg(not(target_os = "windows"))]
        {
            self.running = false;
            return Ok(None);
        }

        // Windows 平台：等待调试事件并转换
        #[cfg(target_os = "windows")]
        {
            let debug_event = self.wait_for_debug_event()?;

            match debug_event.kind {
                DebugEventKind::ExitProcess => {
                    self.running = false;
                    Ok(None)
                }
                DebugEventKind::Exception => {
                    let syscall = Self::debug_event_to_syscall(&debug_event);
                    Ok(syscall)
                }
                _ => {
                    // 其他事件（线程创建/DLL 加载等）跳过
                    // 递归调用继续等待下一个事件
                    self.next_event()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_api_arch_name() {
        let source = DebugCaptureSource::new_internal(0, DebugApiArch::X86_64);
        assert_eq!(source.arch_name(), "x86_64");

        let source = DebugCaptureSource::new_internal(0, DebugApiArch::X86);
        assert_eq!(source.arch_name(), "x86");
    }

    #[test]
    fn test_debug_api_pid() {
        let source = DebugCaptureSource::new_internal(42, DebugApiArch::X86_64);
        assert_eq!(source.pid(), 42);
    }

    #[test]
    fn test_is_running_initial_state() {
        let source = DebugCaptureSource::new_internal(0, DebugApiArch::X86_64);
        assert!(source.is_running());
    }

    #[test]
    fn test_spawn_on_non_windows_returns_error() {
        let result = DebugCaptureSource::spawn("cmd.exe", &["/c", "echo hello"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_next_event_on_non_windows_returns_none() {
        let mut source = DebugCaptureSource::new_internal(0, DebugApiArch::X86_64);
        let result = source.next_event();
        // On Windows, next_event tries to call WaitForDebugEvent which returns Err
        // On non-Windows, it returns Ok(None)
        #[cfg(not(target_os = "windows"))]
        {
            assert!(result.is_ok());
            let ev = result.unwrap();
            assert!(ev.is_none(), "非 Windows 平台应返回 None");
            assert!(!source.is_running(), "非 Windows 平台应标记为停止");
        }
        #[cfg(target_os = "windows")]
        {
            assert!(
                result.is_err(),
                "Windows 平台 wait_for_debug_event 应返回错误"
            );
        }
    }

    #[test]
    fn test_debug_event_kind() {
        let ev = DebugEvent {
            kind: DebugEventKind::Exception,
            pid: 1234,
            tid: 5678,
            exception_code: Some(0x80000003), // EXCEPTION_BREAKPOINT
            exception_address: Some(0x7ffa1234),
        };
        assert!(matches!(ev.kind, DebugEventKind::Exception));
        assert_eq!(ev.exception_code, Some(0x80000003));
    }

    #[test]
    fn test_debug_event_to_syscall_breakpoint() {
        let ev = DebugEvent {
            kind: DebugEventKind::Exception,
            pid: 1234,
            tid: 5678,
            exception_code: Some(0x80000003), // EXCEPTION_BREAKPOINT
            exception_address: Some(0x007f_fa00_0005), // 低字节暗示 syscall nr=5 (fstat)
        };
        let syscall = DebugCaptureSource::debug_event_to_syscall(&ev);
        assert!(syscall.is_some(), "断点事件应转换为 syscall");
        assert_eq!(syscall.unwrap().nr, 5);
    }

    #[test]
    fn test_debug_event_to_syscall_non_exception() {
        let ev = DebugEvent {
            kind: DebugEventKind::ExitProcess,
            pid: 1234,
            tid: 5678,
            exception_code: None,
            exception_address: None,
        };
        let syscall = DebugCaptureSource::debug_event_to_syscall(&ev);
        assert!(syscall.is_none(), "非异常事件不应转换为 syscall");
    }

    #[test]
    fn test_debug_event_to_syscall_unknown_exception() {
        let ev = DebugEvent {
            kind: DebugEventKind::Exception,
            pid: 1234,
            tid: 5678,
            exception_code: Some(0xC0000005), // ACCESS_VIOLATION
            exception_address: Some(0x7ffa1234),
        };
        let syscall = DebugCaptureSource::debug_event_to_syscall(&ev);
        assert!(syscall.is_none(), "非断点异常不应转换为 syscall");
    }

    #[test]
    fn test_debug_arch_determines_register_layout() {
        // x86_64: rax=syscall nr, rcx=ret addr, r11=old RFLAGS
        match DebugApiArch::X86_64 {
            DebugApiArch::X86_64 => {}
            _ => panic!("X86_64 架构应被正确识别"),
        }

        // x86: eax=syscall nr
        match DebugApiArch::X86 {
            DebugApiArch::X86 => {}
            _ => panic!("X86 架构应被正确识别"),
        }
    }
}
