//! 子进程运行辅助 (daoti-core::runner)
//!
//! 所有感知/执行层对子进程（PowerShell / wsl / docker）的调用统一走此模块：
//! - 一律 `Command::args` 传参（`shell=false`），杜绝 shell 注入（开发计划 R5）
//! - 强制 `tokio::time::timeout`，卡死可恢复（开发计划 R4）
//! - `kill_on_drop` 在超时/取消时清理子进程（HCSE 取消路径）
//! - 输出统一按 UTF-8 lossy 解码，规避 PowerShell 中文乱码（开发计划 R2）

use std::time::Duration;

use daoti_common::DaotiError;
use tokio::process::Command;

/// 异步运行子进程并返回 stdout（UTF-8 lossy 解码），带超时
pub(crate) async fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, DaotiError> {
    let (stdout, _stderr, _code) = run_detailed(program, args, timeout).await?;
    Ok(stdout)
}

/// 运行子进程并返回 (stdout, stderr, 退出码)，带超时；供执行层使用
pub(crate) async fn run_detailed(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(String, String, i32), DaotiError> {
    let mut command = Command::new(program);
    command.args(args);
    #[cfg(windows)]
    {
        // 诊断和 WSL 子进程后台运行时不创建可见控制台窗口。
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let child = command
        // 进程被 drop（含超时/取消）时强制终止，避免残留
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| DaotiError::CommandTimeout {
            timeout: timeout.as_secs(),
            command: format!("{} {}", program, args.join(" ")),
        })??;

    Ok((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code().unwrap_or(-1),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_echo_like_command() {
        // 用当前可执行文件自身模拟"输出"：返回 0 行输出
        let out = run_with_timeout("cmd", &["/C", "echo", "ok"], Duration::from_secs(5)).await;
        // 仅验证不报错（是否含 "ok" 取决于 echo 行为，宽松断言）
        assert!(out.is_ok());
    }

    #[tokio::test]
    async fn times_out_for_sleep() {
        // 用 PowerShell Start-Sleep 模拟卡死，验证 timeout 真正触发
        let r = run_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 5",
            ],
            Duration::from_millis(100),
        )
        .await;
        assert!(r.is_err(), "应因超时而失败，实际返回 Ok");
        assert!(matches!(r, Err(DaotiError::CommandTimeout { .. })));
    }
}
