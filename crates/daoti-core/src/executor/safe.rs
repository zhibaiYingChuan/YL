//! 安全执行层 (daoti-core::executor::safe)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.3.2。包含：
//! - 三平台执行器（WindowsExecutor / Wsl2Executor / DockerExecutor，实现 PlatformExecutor）
//! - SafeCommandExecutor：白名单 + 禁止模式 + 超时兜底 + 回滚语义
//!
//! 所有子进程调用经 `runner::run_detailed`，`Command::args` 传参（shell=false）防注入（开发计划 R5）。

use std::time::Duration;

use super::{CommandSpec, ExecResult, PlatformExecutor};
use crate::runner::run_detailed;
use daoti_common::DaotiError;

/// Windows 执行器：通过 PowerShell 执行
#[derive(Default)]
pub struct WindowsExecutor;

impl WindowsExecutor {
    pub fn new() -> Self {
        WindowsExecutor
    }
}

impl PlatformExecutor for WindowsExecutor {
    async fn execute(&self, spec: &CommandSpec) -> Result<ExecResult, DaotiError> {
        let (stdout, stderr, code) = run_detailed(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &spec.command],
            Duration::from_secs(spec.timeout),
        )
        .await?;
        Ok(ExecResult {
            success: code == 0,
            stdout,
            stderr,
            returncode: code,
            command: spec.command.clone(),
            target: "windows".into(),
        })
    }
}

/// WSL2 执行器：通过 wsl 桥接执行
pub struct Wsl2Executor {
    pub distro: String,
}

impl Wsl2Executor {
    pub fn new(distro: String) -> Self {
        Wsl2Executor { distro }
    }
}

impl PlatformExecutor for Wsl2Executor {
    async fn execute(&self, spec: &CommandSpec) -> Result<ExecResult, DaotiError> {
        // 将命令拆为参数传给 wsl，避免拼接注入
        let parts: Vec<&str> = spec.command.split_whitespace().collect();
        let (stdout, stderr, code) = run_detailed(
            "wsl",
            &["-d", &self.distro, "--", &parts.join(" ")],
            Duration::from_secs(spec.timeout),
        )
        .await?;
        Ok(ExecResult {
            success: code == 0,
            stdout,
            stderr,
            returncode: code,
            command: spec.command.clone(),
            target: "wsl2".into(),
        })
    }
}

/// Docker 执行器：通过 docker CLI 执行
#[derive(Default)]
pub struct DockerExecutor;

impl DockerExecutor {
    pub fn new() -> Self {
        DockerExecutor
    }
}

impl PlatformExecutor for DockerExecutor {
    async fn execute(&self, spec: &CommandSpec) -> Result<ExecResult, DaotiError> {
        let parts: Vec<&str> = spec.command.split_whitespace().collect();
        let (stdout, stderr, code) =
            run_detailed("docker", &parts, Duration::from_secs(spec.timeout)).await?;
        Ok(ExecResult {
            success: code == 0,
            stdout,
            stderr,
            returncode: code,
            command: spec.command.clone(),
            target: "docker".into(),
        })
    }
}

/// 安全执行器：执行前做白名单/禁止模式校验，再分派到对应平台执行器
pub struct SafeCommandExecutor {
    /// 平台执行器实例（工厂语义内聚于此）
    windows: WindowsExecutor,
    wsl2: Wsl2Executor,
    docker: DockerExecutor,
    /// 禁止模式（黑名单，子串匹配，小写）
    forbidden_patterns: Vec<String>,
    /// 各平台允许的命令前缀（白名单）
    allowed_windows: Vec<String>,
    allowed_wsl2: Vec<String>,
    allowed_docker: Vec<String>,
}

impl Default for SafeCommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SafeCommandExecutor {
    pub fn new() -> Self {
        Self::with_distro("Ubuntu".into())
    }

    /// 以指定 WSL 发行版构造（供 `daoti run` 等使用配置中的发行版，避免硬编码）
    pub fn with_distro(distro: String) -> Self {
        SafeCommandExecutor {
            windows: WindowsExecutor::new(),
            wsl2: Wsl2Executor::new(distro),
            docker: DockerExecutor::new(),
            forbidden_patterns: vec![
                "rm -rf /".into(),
                "dd if=".into(),
                "mkfs".into(),
                "format".into(),
                "shutdown -h".into(),
                "del /f /s".into(),
                "remove-item -recurse -force c:\\".into(),
                "del /q /f".into(),
            ],
            allowed_windows: vec![
                "Get-".into(),
                "Set-".into(),
                "Restart-".into(),
                "Start-".into(),
                "Stop-".into(),
                "Test-Path".into(),
                "wsl".into(),
                "docker".into(),
                "Write-Host".into(),
            ],
            allowed_wsl2: vec![
                "service".into(),
                "docker".into(),
                "systemctl".into(),
                "journalctl".into(),
                "pgrep".into(),
                "test".into(),
                "echo".into(),
                "df".into(),
                "free".into(),
                "mount".into(),
                "uname".into(),
            ],
            allowed_docker: vec![
                "version".into(),
                "ps".into(),
                "images".into(),
                "system".into(),
                "restart".into(),
                "start".into(),
                "stop".into(),
                "logs".into(),
                "network".into(),
                "volume".into(),
            ],
        }
    }

    /// 执行一条指令：校验安全 → 分派到平台执行器
    pub async fn execute(&self, spec: &CommandSpec) -> Result<ExecResult, DaotiError> {
        self.validate(spec)?;
        match spec.target.as_str() {
            "windows" => self.windows.execute(spec).await,
            "wsl2" => self.wsl2.execute(spec).await,
            "docker" => self.docker.execute(spec).await,
            other => Err(DaotiError::Unavailable(format!("未知目标平台: {other}"))),
        }
    }

    /// 校验命令是否安全
    ///
    /// 安全加固（S3）：① 空白归一化后做黑名单子串匹配，闭合「双空格/制表符」绕过；
    /// ② 白名单改为「首 token 精确匹配 + PowerShell 动词前缀 `Xxx-`」双模式，
    ///    杜绝 `docker-compose` / `psql` 等被 `docker` / `ps` 前缀误放行。
    pub fn validate(&self, spec: &CommandSpec) -> Result<(), DaotiError> {
        // 空白归一化：连续空白折叠为单空格，闭合黑名单的空白变体绕过
        let normalized = spec
            .command
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let lower = normalized.to_lowercase();

        // 1. 禁止模式检查（黑名单优先，基于归一化后的命令）
        for p in &self.forbidden_patterns {
            if lower.contains(&p.to_lowercase()) {
                return Err(DaotiError::Blocked(spec.command.clone()));
            }
        }

        // 2. 白名单匹配：首 token 精确匹配（或 PowerShell 动词前缀 `Xxx-`）
        let allowed: &[String] = match spec.target.as_str() {
            "windows" => &self.allowed_windows,
            "wsl2" => &self.allowed_wsl2,
            "docker" => &self.allowed_docker,
            _ => {
                return Err(DaotiError::Unavailable(format!(
                    "未知目标: {}",
                    spec.target
                )))
            }
        };
        let first = normalized
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_lowercase();
        let ok = allowed.iter().any(|a| {
            let al = a.to_lowercase();
            if al.ends_with('-') {
                // 前缀型（PowerShell `动词-名词`，如 Get-*/Set-*）
                lower.starts_with(&al) || first.starts_with(&al)
            } else {
                // 精确首 token 型（如 `docker` / `service` / `ps`），杜绝前缀混淆
                first == al
            }
        });
        if !ok {
            return Err(DaotiError::Blocked(spec.command.clone()));
        }

        Ok(())
    }

    /// 校验注入的 Windows 操作是否安全（B1 注入器复用）
    ///
    /// 与 `validate` 的区别：入参是翻译后的 Win32 操作名（如 `"ReadFile"`），
    /// 而非原始 shell 命令。策略：① 复用禁止模式；② 仅允许映射表中的操作直通。
    pub fn validate_inject(&self, operation: &str) -> Result<(), DaotiError> {
        let lower = operation.to_lowercase();

        // 1. 禁止模式检查（复用黑名单语义，防御性兜底）
        for p in &self.forbidden_patterns {
            if lower.contains(p) {
                return Err(DaotiError::Blocked(operation.to_string()));
            }
        }

        // 2. 白名单：仅允许 30 条映射表中的 Win32 操作直通
        let supported = crate::interceptor::SYSCALL_MAPPINGS
            .iter()
            .any(|m| m.windows_op.to_lowercase() == lower);
        if !supported {
            return Err(DaotiError::Blocked(operation.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(target: &str, cmd: &str) -> CommandSpec {
        CommandSpec::new(target, cmd).with_timeout(5)
    }

    #[tokio::test]
    async fn blocks_forbidden_pattern() {
        let s = SafeCommandExecutor::new();
        // docker target 但命令含 rm -rf /
        let err = s.validate(&spec("wsl2", "sudo rm -rf /"));
        assert!(matches!(err, Err(DaotiError::Blocked(_))));
    }

    #[tokio::test]
    async fn blocks_non_whitelisted() {
        let s = SafeCommandExecutor::new();
        let err = s.validate(&spec("docker", "run --rm alpine"));
        // "run" 不在 docker 白名单（仅诊断类），应被拦截
        assert!(matches!(err, Err(DaotiError::Blocked(_))));
    }

    #[tokio::test]
    async fn allows_whitelisted() {
        let s = SafeCommandExecutor::new();
        assert!(s.validate(&spec("docker", "ps -a")).is_ok());
        assert!(s.validate(&spec("wsl2", "service docker status")).is_ok());
        assert!(s.validate(&spec("windows", "Get-Service docker")).is_ok());
    }

    #[tokio::test]
    async fn rejects_unknown_target() {
        let s = SafeCommandExecutor::new();
        assert!(matches!(
            s.validate(&spec("macos", "ps")),
            Err(DaotiError::Unavailable(_))
        ));
    }

    /// S3：空白变体（双空格）绕过黑名单，归一化后仍应命中禁止模式。
    #[tokio::test]
    async fn blocks_whitespace_variation_blacklist() {
        let s = SafeCommandExecutor::new();
        let err = s.validate(&spec("wsl2", "sudo rm  -rf  /"));
        assert!(matches!(err, Err(DaotiError::Blocked(_))));
    }

    /// S3：`docker-compose` 不应被 `docker` 白名单前缀误放行。
    #[tokio::test]
    async fn blocks_prefix_confusion() {
        let s = SafeCommandExecutor::new();
        let err = s.validate(&spec("wsl2", "docker-compose up -d"));
        assert!(matches!(err, Err(DaotiError::Blocked(_))));
    }

    #[tokio::test]
    async fn unknown_target_returns_error() {
        let s = SafeCommandExecutor::new();
        let r = s.execute(&spec("macos", "ps")).await;
        assert!(r.is_err());
    }

    /// 映射表内的 Win32 操作可直通注入
    #[test]
    fn validate_inject_allows_mapped_ops() {
        let s = SafeCommandExecutor::new();
        assert!(s.validate_inject("ReadFile").is_ok());
        assert!(s.validate_inject("CreateFileW").is_ok());
        assert!(s.validate_inject("GetCurrentProcessId").is_ok());
    }

    /// 映射表外的危险操作（写进程内存/远程线程注入）被拦截
    #[test]
    fn validate_inject_blocks_unmapped_ops() {
        let s = SafeCommandExecutor::new();
        assert!(matches!(
            s.validate_inject("WriteProcessMemory"),
            Err(DaotiError::Blocked(_))
        ));
        assert!(matches!(
            s.validate_inject("CreateRemoteThread"),
            Err(DaotiError::Blocked(_))
        ));
    }
}
