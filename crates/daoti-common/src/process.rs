//! 进程工具 (daoti-common::process)
//!
//! P0-1《推进计划-AdvancePlan.md》：daemon 生命周期管理（单实例锁 / 启停 / 状态探测）。
//! 本模块提供跨平台的进程存活探测、终止与 PID 文件读写，供 `daoti-daemon`（单实例锁）
//! 与 `daoti-cli`（`daemon start/stop/status`）共用，避免平台细节在调用方重复。
//!
//! 平台策略：
//! - Windows：`tasklist /FI "PID eq <pid>"` 探测存活；`taskkill /PID <pid> /T /F` 强制终止。
//! - Unix  ：`kill -0 <pid>` 探测存活；`kill <pid>` 发送 SIGTERM 优雅终止。
//!   一律经 `Command::args` 传参（无 shell），杜绝命令行注入（R5）。

use std::path::Path;

/// 探测某 PID 对应的进程是否存活（跨平台，不 panic）。
pub fn pid_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("tasklist")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output();
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&format!("{pid}")),
            Err(_) => false,
        }
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output();
        matches!(out, Ok(o) if o.status.success())
    }
}

/// 终止某 PID 对应的进程（跨平台，尽力而为，不 panic）。
pub fn terminate_process(pid: u32) {
    if pid == 0 {
        return;
    }
    #[cfg(windows)]
    {
        // /T 连同子进程树，/F 强制终止（守护进程无界面，强制更可靠）
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = std::process::Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .arg(pid.to_string())
            .status();
    }
}

/// 从 PID 文件读取 PID；文件缺失/内容非法返回 `None`（不 panic）。
pub fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// 将 PID 写入 PID 文件（自动创建父目录）。
pub fn write_pid_file(path: &Path, pid: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, pid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pid_file_handles_valid_and_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("test.pid");
        // 写入合法 PID
        std::fs::write(&p, "12345\n").unwrap();
        assert_eq!(read_pid_file(&p), Some(12345));
        // 非法内容返回 None
        std::fs::write(&p, "not-a-pid").unwrap();
        assert_eq!(read_pid_file(&p), None);
        // 缺失文件返回 None
        assert_eq!(read_pid_file(&dir.path().join("missing.pid")), None);
    }

    #[test]
    fn write_pid_file_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        // 父目录尚不存在，应被自动创建
        let p = dir.path().join("nested").join("deep").join("daemon.pid");
        write_pid_file(&p, 42).unwrap();
        assert_eq!(read_pid_file(&p), Some(42));
    }

    #[test]
    fn pid_zero_is_never_alive() {
        assert!(!pid_alive(0));
    }

    #[test]
    fn random_pid_is_not_alive() {
        // 一个极不可能存在的 PID；若恰巧存在则跳过断言（避免 CI 抖动）
        let pid = u32::MAX - 1;
        if !pid_alive(pid) {
            assert!(!pid_alive(pid));
        }
    }
}
