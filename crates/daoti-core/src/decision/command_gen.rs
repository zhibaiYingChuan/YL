//! 平台指令生成器 (daoti-core::decision::command_gen)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.3.1。根据调度路径生成平台自适应
//! `CommandSpec`，供 SafeCommandExecutor 执行。所有指令均在安全白名单内。

use crate::executor::CommandSpec;

/// 平台指令生成器
pub struct PlatformCommandGenerator;

impl Default for PlatformCommandGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformCommandGenerator {
    pub fn new() -> Self {
        PlatformCommandGenerator
    }

    /// 通水：重启 Docker daemon（WSL 内 + Windows 服务）
    pub fn restart_docker_daemon(&self) -> Vec<CommandSpec> {
        vec![
            CommandSpec::new("wsl2", "service docker restart").with_timeout(15),
            CommandSpec::new("wsl2", "service docker status").with_timeout(10),
        ]
    }

    /// 培木：复位 WSL 内核
    pub fn reset_wsl(&self) -> Vec<CommandSpec> {
        vec![
            // 通过 windows 平台执行 wsl 命令（wsl 是 windows 可执行程序）
            CommandSpec::new("windows", "wsl --shutdown").with_timeout(15),
            CommandSpec::new("windows", "wsl -l -v").with_timeout(10),
        ]
    }

    /// 调金：核查 Windows 宿主 Docker 服务
    pub fn check_windows_services(&self) -> Vec<CommandSpec> {
        vec![CommandSpec::new("windows", "Get-Service com.docker.service").with_timeout(10)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::safe::SafeCommandExecutor;

    /// 契约级保证：生成器产出的每条指令都必须通过安全执行器的白名单/禁止模式校验。
    /// 若新增调度指令而忘记同步白名单，本测试即失败（P0-2 白名单完整性的回归护栏）。
    #[test]
    fn all_generated_commands_pass_whitelist() {
        let executor = SafeCommandExecutor::new();
        let g = PlatformCommandGenerator::new();

        let mut all = Vec::new();
        all.extend(g.restart_docker_daemon());
        all.extend(g.reset_wsl());
        all.extend(g.check_windows_services());

        assert!(!all.is_empty(), "不应为空，否则护栏失效");
        for spec in &all {
            assert!(
                executor.validate(spec).is_ok(),
                "指令不在白名单内，应被拦截: target={} cmd={}",
                spec.target,
                spec.command
            );
        }
    }

    #[test]
    fn docker_commands_target_wsl2() {
        let g = PlatformCommandGenerator::new();
        let cmds = g.restart_docker_daemon();
        assert_eq!(cmds.len(), 2);
        assert!(cmds.iter().all(|c| c.target == "wsl2"));
        assert_eq!(cmds[0].command, "service docker restart");
    }

    #[test]
    fn wsl_commands_target_windows() {
        let g = PlatformCommandGenerator::new();
        let cmds = g.reset_wsl();
        assert!(cmds.iter().all(|c| c.target == "windows"));
    }

    #[test]
    fn commands_have_sane_timeout() {
        let g = PlatformCommandGenerator::new();
        for c in g.restart_docker_daemon() {
            assert!(c.timeout > 0);
        }
    }
}
