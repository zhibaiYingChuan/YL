//! M0 统一执行契约：目标、模式、诊断报告与能力注册表。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 可执行目标平台。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTarget {
    Windows,
    Wsl2,
    Docker,
    Native,
    StaticElfInterpreter,
    DynamicElfInterpreter,
    PeInterpreter,
    RemoteMacOs,
    RemoteLinux,
    RemoteWindows,
}

impl ExecutionTarget {
    pub const ALL: [Self; 10] = [
        Self::Windows,
        Self::Wsl2,
        Self::Docker,
        Self::Native,
        Self::StaticElfInterpreter,
        Self::DynamicElfInterpreter,
        Self::PeInterpreter,
        Self::RemoteMacOs,
        Self::RemoteLinux,
        Self::RemoteWindows,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Wsl2 => "wsl2",
            Self::Docker => "docker",
            Self::Native => "native",
            Self::StaticElfInterpreter => "static_elf_interpreter",
            Self::DynamicElfInterpreter => "dynamic_elf_interpreter",
            Self::PeInterpreter => "pe_interpreter",
            Self::RemoteMacOs => "remote_macos",
            Self::RemoteLinux => "remote_linux",
            Self::RemoteWindows => "remote_windows",
        }
    }
}

impl std::fmt::Display for ExecutionTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ExecutionTarget {
    /// 只报告真实可用性：远程节点和解释器没有配置时不可用。
    pub fn probe(self) -> (bool, &'static str) {
        match self {
            Self::Windows | Self::Native => (true, "内部符号能力已注册"),
            Self::Wsl2 => (true, "内部符号桥接能力已注册"),
            Self::Docker => (true, "内部符号容器能力已注册"),
            Self::StaticElfInterpreter => (true, "本地静态 ELF 解释器已注册"),
            Self::DynamicElfInterpreter => crate::probe::dynamic_elf_interpreter_probe(),
            Self::PeInterpreter => match std::env::var_os("DAOTI_PE_FIXTURE") {
                Some(path) if std::path::Path::new(&path).is_file() => {
                    (true, "PE 控制台 fixture 已存在，解释器可验收")
                }
                Some(_) => (false, "DAOTI_PE_FIXTURE 指向的文件不存在"),
                None => (false, "未配置真实 PE fixture"),
            },
            Self::RemoteMacOs => match (
                std::env::var("DAOTI_MACOS_ENDPOINT"),
                std::env::var("DAOTI_MACOS_TOKEN"),
            ) {
                (Ok(endpoint), Ok(token)) if !endpoint.trim().is_empty() && !token.is_empty() => {
                    (true, "远程 macOS 节点已配置，待健康探测")
                }
                _ => (false, "未配置远程 macOS 节点"),
            },
            Self::RemoteLinux | Self::RemoteWindows => (false, "未配置远程节点"),
        }
    }
}

impl std::str::FromStr for ExecutionTarget {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "windows" => Ok(Self::Windows),
            "wsl2" => Ok(Self::Wsl2),
            "docker" => Ok(Self::Docker),
            "native" => Ok(Self::Native),
            "static_elf_interpreter" => Ok(Self::StaticElfInterpreter),
            "dynamic_elf_interpreter" => Ok(Self::DynamicElfInterpreter),
            "pe_interpreter" => Ok(Self::PeInterpreter),
            "remote_macos" => Ok(Self::RemoteMacOs),
            "remote_linux" => Ok(Self::RemoteLinux),
            "remote_windows" => Ok(Self::RemoteWindows),
            other => Err(format!("未知执行目标: {other}")),
        }
    }
}

/// 命令生命周期模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    Sync,
    Async,
    FireAndForget,
}

/// 统一调度请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchRequest {
    pub command: String,
    pub target: ExecutionTarget,
    pub mode: ExecutionMode,
}

/// 调度决策及其可选诊断。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub target: ExecutionTarget,
    pub mode: ExecutionMode,
    pub accepted: bool,
    pub diagnostics: Vec<ExecutionDiagnostic>,
}

impl DispatchRequest {
    pub fn decide(self, registry: &CapabilityRegistry) -> Decision {
        let mut diagnostics = Vec::new();
        if self.command.trim().is_empty() {
            diagnostics.push(ExecutionDiagnostic::new("EMPTY_COMMAND", "命令不能为空"));
        }
        let target_available = if registry.is_empty() {
            self.target.probe().0
        } else {
            registry.target_available(self.target)
        };
        if !target_available {
            let (_, reason) = self.target.probe();
            let mut diagnostic = ExecutionDiagnostic::new(
                "TARGET_UNAVAILABLE",
                format!("目标 {} 不可用：{reason}", self.target),
            );
            diagnostic.target = Some(self.target);
            diagnostic.blocking = true;
            diagnostics.push(diagnostic);
        }
        Decision {
            target: self.target,
            mode: self.mode,
            accepted: diagnostics.is_empty(),
            diagnostics,
        }
    }
}

/// 单项执行诊断。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionDiagnostic {
    pub code: String,
    pub message: String,
    pub target: Option<ExecutionTarget>,
    pub blocking: bool,
}

impl ExecutionDiagnostic {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            target: None,
            blocking: false,
        }
    }
}

/// 一次执行的统一诊断报告。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub diagnostics: Vec<ExecutionDiagnostic>,
    /// 实际选择的目标；报告不得把模拟能力伪装成真实能力。
    pub target: Option<ExecutionTarget>,
    pub status: String,
    pub fallback_reason: Option<String>,
    /// 输入格式、执行模式与版本证据，供所有执行目标统一验收。
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub mode: Option<ExecutionMode>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub capability_evidence: Vec<String>,
    /// 统一捕获的标准输出字节；二进制输出不得被强制按文本解码。
    #[serde(default)]
    pub stdout: Vec<u8>,
    /// 统一捕获的标准错误字节。
    #[serde(default)]
    pub stderr: Vec<u8>,
    /// 进程或解释器报告的退出码。
    #[serde(default)]
    pub exit_code: Option<i32>,
}

impl ExecutionReport {
    pub fn success() -> Self {
        Self {
            status: "success".into(),
            ..Self::default()
        }
    }

    /// 构造本地受限解释器的统一结果，保留 stdout/stderr/exit_code 契约。
    pub fn local_result(
        target: ExecutionTarget,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: Option<i32>,
    ) -> Self {
        Self {
            target: Some(target),
            status: if exit_code == Some(0) {
                "success"
            } else {
                "failed"
            }
            .into(),
            stdout,
            stderr,
            exit_code,
            ..Self::default()
        }
    }

    pub fn unavailable(target: ExecutionTarget, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let mut report = Self {
            target: Some(target),
            status: "degraded".into(),
            fallback_reason: Some(reason.clone()),
            ..Self::default()
        };
        report.push(ExecutionDiagnostic {
            code: "UNAVAILABLE".into(),
            message: reason,
            target: Some(target),
            blocking: true,
        });
        report
    }

    pub fn from_error(
        target: ExecutionTarget,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let mut report = Self {
            target: Some(target),
            ..Self::default()
        };
        report.push(ExecutionDiagnostic {
            code: code.into(),
            message: message.into(),
            target: Some(target),
            blocking: true,
        });
        report
    }

    pub fn push(&mut self, diagnostic: ExecutionDiagnostic) {
        self.diagnostics.push(diagnostic);
    }
    pub fn is_blocked(&self) -> bool {
        self.diagnostics.iter().any(|d| d.blocking)
    }

    pub fn with_target(mut self, target: ExecutionTarget) -> Self {
        self.target = Some(target);
        self
    }
}

/// 目标能力描述，用于调度前发现能力缺口。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCapability {
    pub name: String,
    pub targets: Vec<ExecutionTarget>,
}

/// 能力注册表。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityRegistry {
    capabilities: BTreeMap<String, ExecutionCapability>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 所有 target 的单一注册入口；能力状态由真实环境探测填充。
    pub fn for_current_environment() -> Self {
        let mut registry = Self::new();
        for target in ExecutionTarget::ALL {
            let (available, reason) = target.probe();
            registry.register(ExecutionCapability {
                name: target.as_str().into(),
                targets: if available { vec![target] } else { Vec::new() }, // 仅注册真实探测通过的能力
            });
            if !available {
                registry.register(ExecutionCapability {
                    name: format!("{}:unavailable:{reason}", target.as_str()),
                    targets: Vec::new(),
                });
            }
        }
        registry
    }

    pub fn target_available(&self, target: ExecutionTarget) -> bool {
        self.supports(target.as_str(), target)
    }

    /// 返回能力探测结果，供 CLI、daemon 和 CI 使用同一份事实。
    pub fn probe_results(&self) -> Vec<(ExecutionTarget, bool, &'static str)> {
        ExecutionTarget::ALL
            .into_iter()
            .map(|target| {
                let (_, reason) = target.probe();
                (target, self.target_available(target), reason)
            })
            .collect()
    }

    pub fn register(&mut self, capability: ExecutionCapability) {
        self.capabilities
            .insert(capability.name.clone(), capability);
    }
    pub fn get(&self, name: &str) -> Option<&ExecutionCapability> {
        self.capabilities.get(name)
    }
    pub fn supports(&self, name: &str, target: ExecutionTarget) -> bool {
        self.get(name).is_some_and(|c| c.targets.contains(&target))
    }
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_round_trip() {
        for target in ExecutionTarget::ALL {
            assert_eq!(target.to_string().parse(), Ok(target));
        }
        assert!("elf".parse::<ExecutionTarget>().is_err());
    }

    #[test]
    fn registry_reports_capability() {
        let mut registry = CapabilityRegistry::new();
        registry.register(ExecutionCapability {
            name: "shell".into(),
            targets: vec![ExecutionTarget::Windows],
        });
        assert!(registry.supports("shell", ExecutionTarget::Windows));
        assert!(!registry.supports("shell", ExecutionTarget::Docker));
    }

    #[test]
    fn local_result_contract_is_format_neutral() {
        for target in [
            ExecutionTarget::PeInterpreter,
            ExecutionTarget::Native,
            ExecutionTarget::StaticElfInterpreter,
        ] {
            let report =
                ExecutionReport::local_result(target, b"out".to_vec(), b"err".to_vec(), Some(7));
            assert_eq!(report.target, Some(target));
            assert_eq!(report.stdout, b"out");
            assert_eq!(report.stderr, b"err");
            assert_eq!(report.exit_code, Some(7));
            assert_eq!(report.status, "failed");
        }
    }

    #[test]
    fn old_report_json_defaults_new_result_fields() {
        let report: ExecutionReport = serde_json::from_str(
            r#"{"diagnostics":[],"target":"pe_interpreter","status":"success","fallback_reason":null}"#,
        )
        .expect("旧契约 JSON 应保持可反序列化");
        assert!(report.stdout.is_empty());
        assert!(report.stderr.is_empty());
        assert_eq!(report.exit_code, None);
    }

    #[test]
    fn from_error_preserves_real_target() {
        for target in [
            ExecutionTarget::DynamicElfInterpreter,
            ExecutionTarget::PeInterpreter,
            ExecutionTarget::RemoteMacOs,
        ] {
            let report = ExecutionReport::from_error(target, "FAILED", "执行失败");
            assert_eq!(report.target, Some(target));
            assert_eq!(report.diagnostics[0].target, Some(target));
        }
    }

    #[test]
    fn report_detects_blocking_diagnostic() {
        let mut report = ExecutionReport::default();
        report.push(ExecutionDiagnostic {
            code: "UNAVAILABLE".into(),
            message: "缺少能力".into(),
            target: Some(ExecutionTarget::Docker),
            blocking: true,
        });
        assert!(report.is_blocked());
    }

    #[test]
    fn dispatch_decision_rejects_empty_command() {
        let request = DispatchRequest {
            command: "  ".into(),
            target: ExecutionTarget::Native,
            mode: ExecutionMode::Sync,
        };
        let decision = request.decide(&CapabilityRegistry::new());
        assert!(!decision.accepted);
        assert_eq!(decision.diagnostics[0].code, "EMPTY_COMMAND");
    }

    #[test]
    fn dynamic_elf_probe_requires_real_runtime_evidence() {
        assert!(!ExecutionTarget::DynamicElfInterpreter.probe().0);
    }

    #[test]
    fn dispatch_decision_covers_all_targets() {
        for target in ExecutionTarget::ALL {
            let decision = DispatchRequest {
                command: "run".into(),
                target,
                mode: ExecutionMode::Async,
            }
            .decide(&CapabilityRegistry::new());
            assert_eq!(decision.accepted, target.probe().0);
            assert_eq!(decision.target, target);
            if !decision.accepted {
                assert_eq!(decision.diagnostics[0].target, Some(target));
            }
        }
    }
}
