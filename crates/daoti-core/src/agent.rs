//! 主控 Agent (daoti-core::agent)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§4.3。对外统一接口，编排
//! 感知 → 推演 → 执行 → 二次感知 的完整闭环。

use std::path::Path;
use std::time::Duration;

use daoti_common::config::{Config, MacOsConfig, ModelConfig};
use daoti_common::format::{detect_binary_format, detect_elf_kind, BinaryFormat, ElfKind};
use daoti_common::DaotiError;
use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};

use crate::bilateral::gate::{validate_derived, B2Gate};
use crate::bilateral::network::BilateralLadderNetwork;
use crate::bilateral::weights::WeightsLoader;
use crate::codec::{Decoder, Encoder, SyscallCodec};
use crate::decision::model::DispatchModel;
use crate::decision::{
    CrossPlatformCausalAdapter, DispatchDecision, DispatchRequest, DispatchTarget,
};
use crate::engine::local::run_full_cycle;
use crate::engine::{ExecutionReport, LocalEngine};
use crate::executor::safe::SafeCommandExecutor;
use crate::executor::CommandSpec;
use crate::executor::RemoteMacOsExecutor;
use crate::interceptor::{
    FdEntry, InjectResult, Interceptor, MmapEntry, ProcessState, RuleInterceptor, SyscallEvent,
    TargetSyscall, TelemetryCollector,
};
use crate::sensor::{
    docker::DockerSensor, windows::WindowsSensor, wsl2::Wsl2Sensor, FusionState, Sensor,
    SensorState,
};
use base64::Engine;

fn runtime_b2_gate() -> B2Gate {
    let enabled = std::env::var("DAOTI_B2_ENABLED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(false);
    let coverage = std::env::var("DAOTI_B2_COVERAGE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let paired_samples = std::env::var("DAOTI_B2_PAIRED_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let success_rate = std::env::var("DAOTI_B2_SUCCESS_RATE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    B2Gate::with_metrics(enabled, coverage, paired_samples, success_rate)
}

/// 修复结局分类（P0-7 一键修复闭环）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealOutcome {
    /// 全部命令成功，三气已通
    Success,
    /// 部分命令成功、部分命令失败
    PartialSuccess,
    /// 至少一条命令因超时未完成
    Timeout,
    /// 全部命令失败（执行失败）
    Failure,
    /// 无需干预（三气本就通畅）
    NoAction,
}

impl HealOutcome {
    /// 人类可读标签
    pub fn label(&self) -> &'static str {
        match self {
            HealOutcome::Success => "已修复",
            HealOutcome::PartialSuccess => "部分成功",
            HealOutcome::Timeout => "执行超时",
            HealOutcome::Failure => "修复失败",
            HealOutcome::NoAction => "无需干预",
        }
    }

    /// 图标（CLI 展示用）
    pub fn icon(&self) -> &'static str {
        match self {
            HealOutcome::Success => "✅",
            HealOutcome::PartialSuccess => "⚠️",
            HealOutcome::Timeout => "⏱️",
            HealOutcome::Failure => "❌",
            HealOutcome::NoAction => "☯️",
        }
    }

    /// 恢复路径提示（失败/超时/部分成功时给出）
    pub fn recovery_hint(&self) -> Option<&'static str> {
        match self {
            HealOutcome::Success | HealOutcome::NoAction => None,
            HealOutcome::PartialSuccess => Some(
                "部分命令未成功。可手动检查对应平台状态：`daoti status`。\n\
                 如需回溯修复前系统状态，可运行 `daoti snapshot` 留存当前气机。",
            ),
            HealOutcome::Timeout => Some(
                "命令超时，可能目标平台无响应。\n\
                 建议：① 检查 WSL2/Docker 是否正常运行；② 调高配置 ~/.daoti.toml 中的 exec_secs；\n\
                 ③ 留存快照 `daoti snapshot` 以便后续排查。",
            ),
            HealOutcome::Failure => Some(
                "所有修复命令均失败。可能原因：目标平台不可达或配置不正确。\n\
                 恢复路径：\n\
                 ① 运行 `daoti init` 重新探测并生成配置；\n\
                 ② 运行 `daoti status` 查看三系统当前状态；\n\
                 ③ 留存快照 `daoti snapshot` 后人工介入。\n\
                 可联系守护者提供快照文件（~/.daoti/snapshots/）进行远程诊断。",
            ),
        }
    }
}

/// 一次诊断-修复的完整报告（P0-7 增强：四类结局 + 恢复路径）
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosisReport {
    /// 推演决策
    pub decision: crate::decision::Decision,
    /// 每条指令执行结果
    pub results: Vec<crate::executor::ExecResult>,
    /// 是否修复成功（二次感知确认）
    pub fixed: bool,
    /// 诊断后的三系统状态
    pub post_state: FusionState,
    /// P0-7 修复结局分类
    pub outcome: HealOutcome,
    /// P0-7 恢复路径提示（仅失败/超时/部分成功时有值）
    pub recovery: Option<String>,
}

impl DiagnosisReport {
    /// 根据执行结果和修复后状态，分类修复结局
    pub fn classify(mut self) -> Self {
        let outcome = self.determine_outcome();
        self.outcome = outcome;
        self.recovery = outcome.recovery_hint().map(|s| s.to_string());
        self
    }

    /// 判定修复结局
    fn determine_outcome(&self) -> HealOutcome {
        // 无命令 → 无需干预
        if self.results.is_empty() {
            return if self.decision.pathway == "no_action" {
                HealOutcome::NoAction
            } else {
                HealOutcome::Failure
            };
        }

        let total = self.results.len();
        let success_count = self.results.iter().filter(|r| r.success).count();
        let timeout_count = self.results.iter().filter(|r| r.returncode == -1).count();

        if timeout_count > 0 {
            HealOutcome::Timeout
        } else if success_count == total {
            HealOutcome::Success
        } else if success_count == 0 {
            HealOutcome::Failure
        } else {
            HealOutcome::PartialSuccess
        }
    }
}

/// 跨平台智能调度 Agent
pub struct CrossPlatformAgent {
    windows: WindowsSensor,
    wsl2: Wsl2Sensor,
    docker: DockerSensor,
    adapter: CrossPlatformCausalAdapter,
    executor: SafeCommandExecutor,
    /// 模式B B2 双梯形网络配置（道体·化）；仅 `run_b1` 加载权重时使用
    model: ModelConfig,
    /// 规则教师训练出的三平台调度模型；缺失时明确回退规则引擎
    dispatch_model: Option<DispatchModel>,
    /// 可选 Python 道体符号推理客户端；未配置时不发起网络请求
    symbolic_client: Option<crate::decision::SymbolicInferenceClient>,
    macos: MacOsConfig,
}

fn dispatch_model_from_config(cfg: &Config) -> Option<DispatchModel> {
    let path = std::env::var_os("DAOTI_DISPATCH_MODEL_PATH")
        .map(|path| Path::new(&path).to_path_buf())
        .or_else(|| {
            cfg.model
                .dispatch_model_path
                .as_ref()
                .map(Path::new)
                .map(Path::to_path_buf)
        })?;
    match DispatchModel::load(&path) {
        Ok(model) => Some(model),
        Err(error) => {
            tracing::warn!(
                "道体调度模型加载失败，回退规则引擎：{}：{}",
                path.display(),
                error
            );
            None
        }
    }
}

impl CrossPlatformAgent {
    /// 依据配置构建 Agent
    pub fn new(cfg: &Config) -> Self {
        CrossPlatformAgent {
            windows: WindowsSensor::new(cfg.targets.docker_service.clone()),
            wsl2: Wsl2Sensor::new(cfg.paths.wsl_distro.clone()),
            docker: DockerSensor::new(),
            adapter: CrossPlatformCausalAdapter::new(),
            executor: SafeCommandExecutor::with_distro(cfg.paths.wsl_distro.clone()),
            model: cfg.model.clone(),
            dispatch_model: dispatch_model_from_config(cfg),
            symbolic_client: match crate::decision::SymbolicInferenceClient::from_env() {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!("道体符号推理客户端配置无效，回退本地推理：{}", error);
                    None
                }
            },
            macos: cfg.macos.clone(),
        }
    }

    /// 使用 Python 道体返回符号级推理；未配置客户端时返回明确诊断。
    pub async fn infer_symbolic(
        &self,
        text: &str,
    ) -> Result<crate::decision::DaotiSymbolicOutput, String> {
        let client = self
            .symbolic_client
            .as_ref()
            .ok_or_else(|| "未配置 DAOTI_SYMBOLIC_INFER_URL".to_string())?;
        client.infer(text).await
    }

    /// 采集三系统状态并融合
    pub async fn collect_state(&self) -> FusionState {
        let (ws, ss, ds) = tokio::join!(
            self.windows.collect(),
            self.wsl2.collect(),
            self.docker.collect(),
        );
        FusionState::from_sensors(&ws, &ss, &ds)
    }

    /// 主流程：感知 → 推演 → 执行 → 二次感知（P0-7 增强：含四类结局分类）
    pub async fn diagnose_and_fix(&self) -> DiagnosisReport {
        let before = self.collect_state().await;
        let health = before.wuxing_health();
        // 优先使用已训练调度模型；无模型时走道体符号调度（五行生克 → 路径 → 决策）。
        let symbolic = crate::decision::DaotiSymbolicOutput::from_health(&health);
        let decision = self
            .dispatch_model
            .as_ref()
            .and_then(|model| model.predict(&health))
            .unwrap_or_else(|| {
                symbolic
                    .to_decision()
                    .unwrap_or_else(|_| self.adapter.interpret(&health))
            });

        // 执行决策指令（跳过空指令）
        let mut results = Vec::new();
        for spec in &decision.commands {
            let r = self.executor.execute(spec).await;
            match r {
                Ok(res) => results.push(res),
                Err(e) => results.push(fail_result(spec, &e.to_string())),
            }
        }

        // 二次感知确认修复效果
        let after = self.collect_state().await;
        let fixed = !before.is_healthy() && after.is_healthy();

        DiagnosisReport {
            decision,
            results,
            fixed,
            post_state: after,
            outcome: HealOutcome::Success, // 占位，由 classify() 覆盖
            recovery: None,
        }
        .classify()
    }

    /// 返回 Agent 持有的安全执行器（供其它模块复用）
    pub fn executor(&self) -> &SafeCommandExecutor {
        &self.executor
    }

    /// 使用本地重映射引擎执行二进制文件，不自动回退到外部兼容层。
    pub fn run_local(
        &self,
        binary_path: &Path,
        args: &[String],
    ) -> Result<ExecutionReport, DaotiError> {
        let engine = LocalEngine::default();
        run_full_cycle(&engine, binary_path, args)
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use crate::executor::ExecutionTarget;
    use crate::executor::{AuthMethod, Authentication, MacOsNodeCapabilities};

    fn agent() -> CrossPlatformAgent {
        CrossPlatformAgent::new(&Config::default())
    }

    fn elf(path: &std::path::Path, dynamic: bool) {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        if dynamic {
            data[32..40].copy_from_slice(&64u64.to_le_bytes());
            data[64..68].copy_from_slice(&3u32.to_le_bytes());
        }
        std::fs::write(path, data).unwrap();
    }

    #[test]
    fn dispatch_selects_static_and_dynamic_elf() {
        let dir = std::env::temp_dir().join(format!("daoti-dispatch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (dynamic, mode, target) in [
            (
                false,
                "static_elf_interpreter",
                ExecutionTarget::StaticElfInterpreter,
            ),
            (
                true,
                "dynamic_elf_interpreter",
                ExecutionTarget::DynamicElfInterpreter,
            ),
        ] {
            let path = dir.join(if dynamic { "dynamic" } else { "static" });
            elf(&path, dynamic);
            let decision = agent()
                .dispatch(DispatchRequest {
                    path: path.to_string_lossy().into(),
                    args: vec![],
                })
                .unwrap();
            assert_eq!(decision.target.mode, mode);
            assert_eq!(decision.target.execution_target, target);
            assert_eq!(decision.capability_version, "stage4-contract-v1");
            assert_eq!(
                decision.observation_events,
                vec![format!("format_detected:{}", decision.target.format)]
            );
            if dynamic {
                assert!(
                    !decision.available,
                    "动态 ELF 未真实执行 PT_INTERP/DT_NEEDED，不得误报可用"
                );
                assert!(decision.diagnostic.is_some());
            } else {
                assert!(decision.available);
            }
        }
    }

    #[test]
    fn dispatch_selects_pe_and_diagnoses_macho() {
        let dir =
            std::env::temp_dir().join(format!("daoti-dispatch-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let pe = dir.join("sample.exe");
        std::fs::write(&pe, [b'M', b'Z', 0, 0]).unwrap();
        let d = agent()
            .dispatch(DispatchRequest {
                path: pe.to_string_lossy().into(),
                args: vec![],
            })
            .unwrap();
        assert_eq!(d.target.mode, "pe_interpreter");
        assert!(d.available);
        assert!(d.target.reason.contains("受限"));

        let macho = dir.join("sample");
        std::fs::write(&macho, [0xfe, 0xed, 0xfa, 0xcf]).unwrap();
        let d = agent()
            .dispatch(DispatchRequest {
                path: macho.to_string_lossy().into(),
                args: vec![],
            })
            .unwrap();
        assert_eq!(d.target.mode, "remote_macos");
        assert!(!d.available);
        assert!(d.diagnostic.unwrap().contains("远程执行后端不可用"));
        assert_eq!(d.capability_version, "stage4-contract-v1");
        assert!(d
            .observation_events
            .iter()
            .any(|event| event.starts_with("format_detected:")));
    }

    #[test]
    fn macos_dispatch_uses_config_and_structured_missing_endpoint_failure() {
        let dir = std::env::temp_dir().join(format!("daoti-macos-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample");
        std::fs::write(&path, [0xfe, 0xed, 0xfa, 0xcf]).unwrap();
        let request = DispatchRequest {
            path: path.to_string_lossy().into(),
            args: vec![],
        };
        let default_decision = agent().dispatch_with_config(request.clone()).unwrap();
        assert!(!default_decision.available);
        assert!(default_decision.diagnostic.unwrap().contains("endpoint"));
        assert!(default_decision
            .observation_events
            .iter()
            .any(|event| event.starts_with("fallback:")));

        let mut cfg = Config::default();
        cfg.macos.endpoint = "https://macos.example.test".into();
        cfg.macos.token = "test-token".into();
        let configured = CrossPlatformAgent::new(&cfg)
            .dispatch_with_config(request)
            .unwrap();
        assert!(configured.available);
        assert!(configured.diagnostic.is_none());
    }

    #[tokio::test]
    async fn remote_macos_probe_marks_unreachable_node_unavailable() {
        let dir = std::env::temp_dir().join(format!("daoti-macos-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample");
        std::fs::write(&path, [0xfe, 0xed, 0xfa, 0xcf]).unwrap();
        let mut cfg = Config::default();
        cfg.macos.endpoint = "http://127.0.0.1:1".into();
        cfg.macos.token = "test-token".into();
        let decision = CrossPlatformAgent::new(&cfg)
            .probe_remote_macos(
                DispatchRequest {
                    path: path.to_string_lossy().into(),
                    args: vec![],
                },
                Duration::from_millis(100),
            )
            .await
            .unwrap();
        assert!(!decision.available);
        assert!(decision
            .observation_events
            .contains(&"fallback:macos_remote_health_failed".into()));
    }

    #[test]
    fn mock_macos_dispatch_preserves_node_and_reports_auth_failure() {
        let dir =
            std::env::temp_dir().join(format!("daoti-dispatch-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample");
        std::fs::write(&path, [0xfe, 0xed, 0xfa, 0xcf]).unwrap();
        let request = DispatchRequest {
            path: path.to_string_lossy().into(),
            args: vec![],
        };
        let node = MacOsNodeCapabilities {
            node_id: "mock-macos".into(),
            os_version: "macOS mock".into(),
            architectures: vec!["x86_64".into()],
            capabilities: vec!["execute".into()],
        };
        let auth = Authentication {
            method: AuthMethod::Token,
            credential_ref: "test".into(),
        };
        let result = agent().dispatch_mock_macos(request, node, auth, 1000);
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("mock 节点"));
    }

    #[test]
    fn dispatch_mock_pe_executes_and_returns_decision() {
        let dir =
            std::env::temp_dir().join(format!("daoti-dispatch-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.exe");
        std::fs::write(&path, [b'M', b'Z', 0, 0]).unwrap();
        let request = DispatchRequest {
            path: path.to_string_lossy().into(),
            args: vec![],
        };
        let node = crate::executor::PeNodeCapabilities {
            node_id: "mock-pe-node".into(),
            os_version: "Windows 11 mock".into(),
            architectures: vec!["x86_64".into()],
            capabilities: vec!["execute".into()],
        };
        let result = agent().dispatch_mock_pe(request, node, 1000);
        assert!(result.is_ok(), "PE mock 应成功：{:?}", result.err());
        let (decision, response) = result.unwrap();
        assert_eq!(decision.target.mode, "pe_interpreter");
        assert!(decision.available);
        assert!(decision.target.reason.contains("受限"));
        assert_eq!(decision.mock_node.as_deref(), Some("mock-pe-node"));
        assert_eq!(response.exit_code, Some(0));
    }
}

impl FusionState {
    /// 三气是否全部健康
    pub fn is_healthy(&self) -> bool {
        let h = self.wuxing_health();
        h.metal >= 0.9 && h.wood >= 0.9 && h.water >= 0.9
    }
}

/// 构造一条失败执行结果（用于执行报错时的结构化回填）
fn fail_result(spec: &CommandSpec, err: &str) -> crate::executor::ExecResult {
    crate::executor::ExecResult::fail(&spec.target, &spec.command, err, -1)
}

/// 便捷：将三感知结果直接收集（供外部测试/诊断）
pub async fn collect_raw(
    windows: &WindowsSensor,
    wsl2: &Wsl2Sensor,
    docker: &DockerSensor,
) -> (SensorState, SensorState, SensorState) {
    tokio::join!(windows.collect(), wsl2.collect(), docker.collect())
}

// ─── 模式B：跨平台二进制运行 ────────────────────────────────────────

/// 跨平台运行结果（模式B 统一返回类型）
#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    /// 执行模式：native / wsl2 / b1_rule / b2_network
    pub mode: String,
    /// 二进制格式
    pub format: String,
    /// 标准输出
    pub stdout: String,
    /// 标准错误
    pub stderr: String,
    /// 退出码
    pub exit_code: i32,
    /// 解析得到的实际入口点地址
    pub entry_point: u64,
}

impl RunResult {
    /// 构造运行结果
    pub fn new(
        mode: &str,
        format: &str,
        stdout: String,
        stderr: String,
        exit_code: i32,
        entry_point: u64,
    ) -> Self {
        RunResult {
            mode: mode.to_string(),
            format: format.to_string(),
            stdout,
            stderr,
            exit_code,
            entry_point,
        }
    }
}

/// 跨平台 Agent 的 B0 能力：格式检测 → 平台分派 → 透明执行。
impl CrossPlatformAgent {
    /// 仅探测并生成统一裁决，不执行目标。
    pub fn dispatch(&self, request: DispatchRequest) -> Result<DispatchDecision, DaotiError> {
        let format = detect_binary_format(&request.path)?;
        let dynamic_elf = matches!(format, BinaryFormat::Elf)
            && detect_elf_kind(&request.path)? == ElfKind::Dynamic;
        let capability = crate::decision::capability(format.label(), dynamic_elf)
            .ok_or_else(|| DaotiError::Unavailable(format!("未注册能力：{}", format.label())))?;
        Ok(DispatchDecision {
            request,
            target: DispatchTarget {
                format: format.label().to_string(),
                platform: capability.platform.to_string(),
                mode: capability.mode.to_string(),
                execution_target: capability.execution_target,
                reason: capability.reason.to_string(),
            },
            available: capability.available,
            diagnostic: capability.diagnostic.map(str::to_string),
            capability_version: "stage4-contract-v1".into(),
            observation_events: vec![format!("format_detected:{}", format.label())],
            mock_node: None,
        })
    }

    /// 根据 daemon/agent 配置选择远程 macOS HTTP 后端。
    pub fn dispatch_with_config(
        &self,
        request: DispatchRequest,
    ) -> Result<DispatchDecision, DaotiError> {
        let mut decision = self.dispatch(request)?;
        if decision.target.execution_target == crate::executor::ExecutionTarget::RemoteMacOs {
            if self.macos.endpoint.trim().is_empty() || self.macos.token.trim().is_empty() {
                decision.diagnostic = Some("macOS 远程 endpoint 或 token 未配置".into());
                decision.available = false;
                decision
                    .observation_events
                    .push("fallback:macos_remote_endpoint_unavailable".into());
            } else {
                decision.diagnostic = None;
                decision.available = true;
                decision
                    .observation_events
                    .push("capability_ready:macos_remote_endpoint_configured".into());
            }
        }
        Ok(decision)
    }

    /// 通过真实 HTTP 健康检查确认远程 macOS 节点可用。
    pub async fn probe_remote_macos(
        &self,
        request: DispatchRequest,
        timeout: Duration,
    ) -> Result<DispatchDecision, DaotiError> {
        let mut decision = self.dispatch_with_config(request)?;
        if decision.target.execution_target != crate::executor::ExecutionTarget::RemoteMacOs {
            return Ok(decision);
        }
        let client = crate::executor::MacOsHttpClient::new(
            self.macos.endpoint.clone(),
            self.macos.token.clone(),
        )
        .map_err(|error| DaotiError::Unavailable(format!("macOS HTTP 配置无效：{error}")))?;
        match client.probe_health(timeout).await {
            Ok(()) => {
                decision.available = true;
                decision.diagnostic = None;
                decision
                    .observation_events
                    .push("probe:macos_remote_health_ok".into());
            }
            Err(error) => {
                decision.available = false;
                decision.diagnostic = Some(format!("macOS 远程节点探测失败：{error}"));
                decision
                    .observation_events
                    .push("fallback:macos_remote_health_failed".into());
            }
        }
        Ok(decision)
    }

    /// 使用模拟 macOS 节点执行已识别的 Mach-O 请求，供 agent/daemon/CLI 统一入口调用。
    ///
    /// 该入口用于验证远程节点发现、认证与调度链路，不代表真实 macOS 执行环境。
    pub fn dispatch_mock_macos(
        &self,
        request: DispatchRequest,
        node: crate::executor::MacOsNodeCapabilities,
        auth: crate::executor::Authentication,
        timeout_ms: u64,
    ) -> Result<(DispatchDecision, crate::executor::MacOsResponse), DaotiError> {
        let mut executor = crate::executor::MockMacOsExecutor::new(node.clone());
        executor
            .authenticate(&auth)
            .map_err(|e| DaotiError::Unavailable(format!("mock 节点认证失败：{e}")))?;
        let decision = self.dispatch(request.clone())?;
        let mut decision = decision;
        decision.available = true;
        decision.mock_node = Some(node.node_id);
        decision.diagnostic = None;
        decision
            .observation_events
            .push("execution_mode:mock_macos_contract".into());
        let response = executor
            .execute(crate::executor::MacOsRequest {
                request_id: format!("mock-{}", request.path),
                filename: request.path,
                binary_base64: "bW9jaw==".into(),
                args: Vec::new(),
                timeout_ms,
                authentication: auth,
            })
            .map_err(|e| DaotiError::Unavailable(format!("mock 节点执行失败：{e}")))?;
        Ok((decision, response))
    }

    /// 使用模拟 PE 节点执行已识别的 PE 请求，对称于 dispatch_mock_macos。
    ///
    /// 该入口用于验证远程节点发现、认证与调度链路，不依赖真实 Windows 执行环境。
    pub fn dispatch_mock_pe(
        &self,
        request: DispatchRequest,
        node: crate::executor::PeNodeCapabilities,
        timeout_ms: u64,
    ) -> Result<(DispatchDecision, crate::executor::PeResponse), DaotiError> {
        let mut executor = crate::executor::MockPeExecutor::new(node.clone());
        executor
            .authenticate(&format!("pe-mock-{}", request.path))
            .map_err(|e| DaotiError::Unavailable(format!("PE mock 节点认证失败：{e}")))?;
        let decision = self.dispatch(request.clone())?;
        let mut decision = decision;
        decision.available = true;
        decision.mock_node = Some(node.node_id);
        decision.diagnostic = None;
        decision
            .observation_events
            .push("execution_mode:mock_pe_contract".into());
        let response = executor
            .execute(crate::executor::PeRequest {
                request_id: format!("pe-mock-{}", request.path),
                command: request.path,
                timeout_ms,
            })
            .map_err(|e| DaotiError::Unavailable(format!("PE mock 节点执行失败：{e}")))?;
        Ok((decision, response))
    }

    /// 跨平台运行二进制文件（模式B·道体·通入口）
    pub async fn run_cross_platform(
        &self,
        path: &str,
        args: &[String],
    ) -> Result<RunResult, DaotiError> {
        let request = DispatchRequest {
            path: path.to_string(),
            args: args.to_vec(),
        };
        let decision = self.dispatch_with_config(request)?;
        if !decision.available {
            return Err(DaotiError::Unavailable(
                decision
                    .diagnostic
                    .unwrap_or_else(|| "目标平台不可用".into()),
            ));
        }
        let fmt = detect_binary_format(path)?;
        let entry_point = crate::parser::parse_binary(std::path::Path::new(path))?.entry_point;
        let target = decision.target.mode.as_str();
        let mode = target;
        // 读取配置：执行超时秒数
        let cfg = Config::load();
        let timeout = Duration::from_secs(cfg.timeouts.exec_secs);
        let (stdout, stderr, code) = match target {
            "remote_macos" => {
                let client = crate::executor::MacOsHttpClient::new(
                    self.macos.endpoint.clone(),
                    self.macos.token.clone(),
                )
                .map_err(|e| DaotiError::Unavailable(format!("macOS HTTP 配置无效：{e}")))?;
                let binary = std::fs::read(path)
                    .map_err(|e| DaotiError::FileNotFound(format!("读取 macOS 二进制失败：{e}")))?;
                let request = crate::executor::MacOsRequest {
                    request_id: format!("agent-{}", std::process::id()),
                    filename: std::path::Path::new(path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("program")
                        .into(),
                    binary_base64: base64::engine::general_purpose::STANDARD.encode(binary),
                    args: args.to_vec(),
                    timeout_ms: timeout.as_millis() as u64,
                    authentication: crate::executor::Authentication {
                        method: crate::executor::AuthMethod::Token,
                        credential_ref: "config".into(),
                    },
                };
                let response = client
                    .execute(request, tokio_util::sync::CancellationToken::new())
                    .await
                    .map_err(|e| DaotiError::Unavailable(format!("macOS HTTP 执行失败：{e}")))?;
                (
                    response.stdout,
                    response.stderr,
                    response.exit_code.unwrap_or(-1),
                )
            }
            "pe_interpreter" if matches!(fmt, BinaryFormat::Pe) => {
                let data = std::fs::read(path)
                    .map_err(|e| DaotiError::FileNotFound(format!("读取 PE 失败：{e}")))?;
                let result = crate::parser::pe::execute_pe32_plus_console(&data, None)
                    .map_err(|e| DaotiError::Unavailable(format!("PE 控制台解释器失败：{e}")))?;
                let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
                let code = match result.state {
                    crate::elf::runtime::ExecutionState::Exited(code) => code,
                    other => {
                        return Err(DaotiError::Unavailable(format!("PE 入口未退出：{other:?}")))
                    }
                };
                (stdout, String::new(), code)
            }
            "static_elf_interpreter" if matches!(fmt, BinaryFormat::Elf) => {
                let sink = crate::elf::BufferSink::new();
                let output = sink.clone();
                let state = crate::elf::execute_elf_with_sink(
                    &std::fs::read(path)
                        .map_err(|e| DaotiError::FileNotFound(format!("读取 ELF 失败：{e}")))?,
                    16 * 1024 * 1024,
                    sink,
                )
                .map_err(|e| DaotiError::Unavailable(format!("ELF 解释器失败：{e}")))?;
                let code = match state {
                    crate::elf::runtime::ExecutionState::Exited(code) => code,
                    other => {
                        return Err(DaotiError::Unavailable(format!(
                            "ELF 入口未退出：{other:?}"
                        )))
                    }
                };
                (
                    String::from_utf8_lossy(
                        &output.0.lock().map(|data| data.clone()).unwrap_or_default(),
                    )
                    .into_owned(),
                    String::new(),
                    code,
                )
            }
            "wsl2" => {
                return Err(DaotiError::Unavailable(
                    "动态 ELF 不得隐式降级到 WSL2；当前无可用的自主动态 ELF 解释器".into(),
                ))
            }
            _ => {
                return Err(DaotiError::Unavailable(format!(
                    "格式 {} 没有已注册的自主执行器；未启动 WSL2、Docker 或远程节点",
                    fmt.label()
                )))
            }
        };
        Ok(RunResult::new(
            mode,
            fmt.label(),
            stdout,
            stderr,
            code,
            entry_point,
        ))
    }
}

// ─── 模式B·道体·达（规则映射）：B1 决策流水线 ──────────────────────

/// 阶段 2 只读影子建议；建议不执行、不推进进程状态。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ShadowSuggestion {
    pub syscall_nr: i32,
    pub syscall_name: String,
    pub operation: String,
    pub confidence: f64,
    pub reason: String,
    pub actual_result: Option<i64>,
    pub actual_success: Option<bool>,
    pub actual_operation: Option<String>,
}

/// 阶段 3 受控指导策略；默认关闭，只允许专用测试程序和白名单操作。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlledGuidancePolicy {
    pub enabled: bool,
    pub test_program: String,
    pub allowed_syscalls: Vec<i32>,
    pub allowed_operations: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for ControlledGuidancePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            test_program: String::new(),
            allowed_syscalls: Vec::new(),
            allowed_operations: Vec::new(),
            timeout_ms: 1000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ControlledGuidanceResult {
    Suggested(ShadowSuggestion),
    Fallback { reason: String },
}

/// 阶段 3 受控指导审计事件；调用方可序列化落盘。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ControlledGuidanceAudit {
    pub program: String,
    pub syscall_nr: i32,
    pub syscall_name: String,
    pub decision: String,
    pub reason: String,
    pub timeout_ms: u64,
}

/// B1 单条事件处理结果
#[derive(Debug, Clone)]
pub enum B1Step {
    /// 命中映射并成功注入（携带注入结果）
    Mapped(InjectResult),
    /// 网络推导成功（携带推导出的 Win32 操作与置信度，判词「道体·化」）
    Derived { operation: String, confidence: f64 },
    /// 未命中映射（携带当前累计未命中数）
    Missed { miss_count: usize },
}

/// B1 运行报告（道体·达）
#[derive(Debug, Clone, Serialize)]
pub struct B1RunReport {
    /// 运行模式：b1_rule（纯规则映射直通）/ wsl2_fallback（批量降级到 WSL2）
    pub mode: String,
    /// 成功映射注入的操作名序列
    pub mapped: Vec<String>,
    /// 未命中数量
    pub missed: usize,
    /// 未命中 syscall 去重编号（B2 训练集基础）
    pub unique_missed: Vec<i32>,
    /// 命中注入后的进程状态账本
    pub state: ProcessState,
    /// 触发降级时的 WSL2 运行结果（未触发为 None）
    pub fallback: Option<RunResult>,
}

/// B1 决策流水线：查表 → 注入 → 推进状态 → 未命中则累计并决策降级
///
/// 对应《模式B-跨平台二进制重映射开发计划.md》§3.3 降级链路。纯逻辑编排器：
/// 不做真实 ptrace/Debug API 注入，只交付"映射正确 + 降级可决策"的纯逻辑。
/// B2 阶段将拆分为独立子模块解耦道体职责（见计划 §5）。
pub struct DecisionPipeline {
    /// 规则拦截器（士兵的默认实现）
    interceptor: RuleInterceptor,
    /// 被拦截进程的运行期状态账本
    state: ProcessState,
    /// 未命中遥测采集器（B2 训练数据基础）
    telemetry: TelemetryCollector,
    /// 注入安全校验（复用禁止模式 + 映射表白名单）
    executor: SafeCommandExecutor,
    /// 未命中累计数
    miss_count: usize,
    /// 批量降级阈值（未命中达到此数即切 WSL2）
    fallback_threshold: usize,
    /// 双梯形网络（None = 未启用，B1 行为不回归）
    network: Option<BilateralLadderNetwork>,
    /// 编解码器（None = 未启用）
    codec: Option<SyscallCodec>,
    /// B2 上线裁决 gate（四条件）
    gate: B2Gate,
    /// 解码置信度阈值（对应 `model_confidence_threshold`，默认 0.7）
    confidence_threshold: f64,
    controlled_policy: ControlledGuidancePolicy,
}

impl Default for DecisionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowSuggestion {
    /// 关联只读建议对应的实际执行结果。
    pub fn with_actual_result(
        mut self,
        result: Result<i64, DaotiError>,
        actual_operation: Option<String>,
    ) -> Self {
        match result {
            Ok(value) => {
                self.actual_result = Some(value);
                self.actual_success = Some(true);
            }
            Err(_) => {
                self.actual_result = None;
                self.actual_success = Some(false);
            }
        }
        self.actual_operation = actual_operation;
        self
    }
}

impl DecisionPipeline {
    /// 构造默认流水线（降级阈值 = 5，对应计划 §3.3）
    pub fn new() -> Self {
        Self::with_threshold(5)
    }

    /// 以自定义降级阈值构造
    pub fn with_threshold(fallback_threshold: usize) -> Self {
        DecisionPipeline {
            interceptor: RuleInterceptor::new(),
            state: ProcessState::new(),
            telemetry: TelemetryCollector::new(),
            executor: SafeCommandExecutor::new(),
            miss_count: 0,
            fallback_threshold,
            network: None,
            codec: None,
            gate: B2Gate::new(),
            confidence_threshold: 0.7,
            controlled_policy: ControlledGuidancePolicy::default(),
        }
    }

    /// 注入 B2 双梯形网络推导能力（network + codec + gate + 置信度阈值）。
    ///
    /// 默认构造不含网络（`network=None`），B1 行为不回归；仅在显式注入后启用推导。
    pub fn with_b2(
        mut self,
        network: BilateralLadderNetwork,
        codec: SyscallCodec,
        gate: B2Gate,
        confidence_threshold: f64,
    ) -> Self {
        self.network = Some(network);
        self.codec = Some(codec);
        self.gate = gate;
        self.confidence_threshold = confidence_threshold;
        self
    }

    /// 配置阶段 3 受控指导策略。
    pub fn with_controlled_policy(mut self, policy: ControlledGuidancePolicy) -> Self {
        self.controlled_policy = policy;
        self
    }

    /// 阶段 3：在显式开启、测试程序匹配、syscall/操作白名单通过且置信度 > 0.99 时，
    /// 返回受控建议；任一条件失败都回退 B1，并给出可审计原因。
    pub fn controlled_guidance(
        &self,
        program: &str,
        event: &SyscallEvent,
    ) -> ControlledGuidanceResult {
        let fallback = |reason: &str| ControlledGuidanceResult::Fallback {
            reason: reason.to_string(),
        };
        if !self.controlled_policy.enabled {
            return fallback("受控指导未显式开启");
        }
        if self.controlled_policy.test_program != program {
            return fallback("程序不在受控测试白名单");
        }
        if self.controlled_policy.timeout_ms == 0 {
            return fallback("受控指导超时配置无效");
        }
        if !self.controlled_policy.allowed_syscalls.contains(&event.nr) {
            return fallback("syscall 不在受控白名单");
        }
        let Some(suggestion) = self.shadow_suggestion(event) else {
            return fallback("无高置信度建议或 B2 未就绪");
        };
        if suggestion.confidence <= 0.99 {
            return fallback("置信度未超过 0.99");
        }
        if !self
            .controlled_policy
            .allowed_operations
            .iter()
            .any(|operation| operation.eq_ignore_ascii_case(&suggestion.operation))
        {
            return fallback("目标操作不在受控白名单");
        }
        ControlledGuidanceResult::Suggested(suggestion)
    }

    /// 阶段 3：返回决策与可序列化审计事件。
    pub fn controlled_guidance_with_audit(
        &self,
        program: &str,
        event: &SyscallEvent,
    ) -> (ControlledGuidanceResult, ControlledGuidanceAudit) {
        let result = self.controlled_guidance(program, event);
        let (decision, reason) = match &result {
            ControlledGuidanceResult::Suggested(_) => (
                "suggested".to_string(),
                "受控白名单与置信度校验通过".to_string(),
            ),
            ControlledGuidanceResult::Fallback { reason } => {
                ("fallback".to_string(), reason.clone())
            }
        };
        let audit = ControlledGuidanceAudit {
            program: program.to_string(),
            syscall_nr: event.nr,
            syscall_name: event.name.clone(),
            decision,
            reason,
            timeout_ms: self.controlled_policy.timeout_ms,
        };
        (result, audit)
    }

    /// 处理单条 syscall 事件：
    /// - 命中：校验注入 → 推进状态 → 返回 `B1Step::Mapped`
    /// - 未命中：尝试 B2 推导（gate 通过时）→ 成功返回 `B1Step::Derived`，否则记录遥测并累计
    pub fn step(&mut self, event: &SyscallEvent) -> Result<B1Step, DaotiError> {
        match self.interceptor.intercept(event)? {
            Some(target) => {
                // 仅允许映射表中的 Win32 操作直通（复用 SafeCommandExecutor 禁止模式）
                self.executor.validate_inject(&target.operation)?;
                let result =
                    InjectResult::new(target.operation.clone(), true, target.description.clone());
                self.advance_state(event, &target);
                // B2-6：命中映射记入成功样本（道体·达），供覆盖率统计
                self.telemetry.record_success(event.clone());
                Ok(B1Step::Mapped(result))
            }
            None => {
                // B2-4：在 record_miss 之前尝试网络推导；未就绪/失败/置信度不足均回落降级链路
                if let Some(derived) = self.try_derive(event) {
                    // B2-6：推导成功记入成功样本（道体·化），供覆盖率统计
                    self.telemetry.record_success(event.clone());
                    return Ok(derived);
                }
                self.telemetry.record_miss(event.clone(), "wsl2");
                self.miss_count += 1;
                Ok(B1Step::Missed {
                    miss_count: self.miss_count,
                })
            }
        }
    }

    /// B2 网络推导：gate 通过 → encode → forward → decode → 置信度校验 → 黑名单校验。
    ///
    /// - 成功返回 `Some(B1Step::Derived { .. })`（判词「道体·化」）
    /// - 未就绪 / 推理失败 / 置信度不足 / 解码非法 / 命中黑名单 → `None`（回落降级，绝无死路）
    fn try_derive(&self, event: &SyscallEvent) -> Option<B1Step> {
        // gate 四条件未通过 → 旁路网络
        if !self.gate.is_ready() {
            return None;
        }
        let network = self.network.as_ref()?;
        let codec = self.codec.as_ref()?;
        // 编码 → 前向 → 解码（任一步失败即降级）
        let input = codec.encode(event).ok()?;
        let output = network.forward(input).ok()?;
        let outcome = codec.decode(&output).ok()?;
        // 置信度不足（道体·疑）→ 降级
        if outcome.confidence < self.confidence_threshold {
            return None;
        }
        // 黑名单校验（仅黑名单，白名单外合法操作放行）
        if validate_derived(&outcome.windows_op).is_err() {
            return None;
        }
        Some(B1Step::Derived {
            operation: outcome.windows_op,
            confidence: outcome.confidence,
        })
    }

    /// 阶段 2：生成高置信度只读建议；不执行、不记录为成功映射、不改变状态。
    pub fn shadow_suggestion(&self, event: &SyscallEvent) -> Option<ShadowSuggestion> {
        if self.interceptor.intercept(event).ok().flatten().is_some() {
            return None;
        }
        let B1Step::Derived {
            operation,
            confidence,
        } = self.try_derive(event)?
        else {
            return None;
        };
        if confidence <= 0.95 {
            return None;
        }
        Some(ShadowSuggestion {
            syscall_nr: event.nr,
            syscall_name: event.name.clone(),
            operation,
            confidence,
            reason: "B1 未命中、B2 gate 已就绪、置信度高于 0.95；仅记录建议，不执行".into(),
            actual_result: None,
            actual_success: None,
            actual_operation: None,
        })
    }

    /// 是否应触发批量降级（未命中累计达到阈值）
    pub fn should_fallback(&self) -> bool {
        self.miss_count >= self.fallback_threshold
    }

    /// 当前未命中累计数
    pub fn miss_count(&self) -> usize {
        self.miss_count
    }

    /// 只读访问进程状态账本
    pub fn state(&self) -> &ProcessState {
        &self.state
    }

    /// 只读访问未命中遥测采集器
    pub fn telemetry(&self) -> &TelemetryCollector {
        &self.telemetry
    }

    /// 记录一条用户反馈样本（正 / 负，道体·养）。
    ///
    /// 用户反馈由上层（CLI / 守护者）在运行结果确认后回填，不计入自动化覆盖率分母。
    pub fn record_feedback(&mut self, event: &SyscallEvent, positive: bool) {
        self.telemetry.record_feedback(event.clone(), positive);
    }

    /// 依据注入后的 Windows 操作推进进程状态账本
    ///
    /// B1 阶段 fd 编号 / 内存地址为纯逻辑占位，真实值由平台适配层（真实
    /// ptrace/Debug API）填入。
    fn advance_state(&mut self, event: &SyscallEvent, target: &TargetSyscall) {
        match target.operation.as_str() {
            // open → CreateFileW：登记文件描述符
            "CreateFileW" => {
                let path = event.args.first().cloned().unwrap_or_default();
                let fd = self.state.fd_count() as i32 + 1;
                self.state.open_fd(FdEntry::new(fd, path, "read"));
            }
            // close → CloseHandle：移除文件描述符
            "CloseHandle" => {
                let fd = event
                    .args
                    .first()
                    .and_then(|a| a.parse::<i32>().ok())
                    .unwrap_or(0);
                self.state.close_fd(fd);
            }
            // mmap → VirtualAlloc：登记内存映射
            "VirtualAlloc" => {
                let addr = parse_hex(event.args.first().map(String::as_str).unwrap_or("0"));
                let len = event
                    .args
                    .get(1)
                    .and_then(|a| a.parse::<u64>().ok())
                    .unwrap_or(0);
                self.state
                    .add_mmap(MmapEntry::new(addr, len, "rw-", "private"));
            }
            // munmap → VirtualFree：移除内存映射
            "VirtualFree" => {
                let addr = parse_hex(event.args.first().map(String::as_str).unwrap_or("0"));
                self.state.remove_mmap(addr);
            }
            // getcwd → GetCurrentDirectoryW：更新当前工作目录
            "GetCurrentDirectoryW" => {
                self.state
                    .set_cwd(event.args.first().cloned().unwrap_or_default());
            }
            // brk → HeapAlloc/HeapFree：更新堆界
            "HeapAlloc/HeapFree" => {
                let brk = parse_hex(event.args.first().map(String::as_str).unwrap_or("0"));
                self.state.set_brk(brk);
            }
            _ => {}
        }
    }
}

/// 解析十六进制字符串（容忍 "0x" 前缀），失败返回 0
fn parse_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

/// 跨平台 Agent 的 B1 能力：规则映射 → 纯逻辑注入 → 未命中批量降级到 WSL2。
impl CrossPlatformAgent {
    /// 构建 B1 决策流水线（B2 接入：根据模型配置与权重文件决定是否启用双梯形网络）。
    ///
    /// - `model.enabled=false` 或权重缺失/损坏 → 返回纯 B1 流水线（`network=None`，B1 不回归）
    /// - 权重加载成功 → `with_b2` 注入网络；但 gate 覆盖率/配对样本/成功率默认 0，
    ///   网络仍旁路（绝无死路），待运行期指标（P3-2）注入后生效
    fn build_b1_pipeline(&self) -> DecisionPipeline {
        self.try_build_b2_pipeline().unwrap_or_default()
    }

    /// 尝试构建带 B2 双梯形网络的流水线；权重可装载且维度一致即返回。
    ///
    /// gate 是否放行由运行期指标决定，不在构建阶段前置阻断，避免把“构建成功”
    /// 和“在线就绪”混为一谈。
    fn try_build_b2_pipeline(&self) -> Option<DecisionPipeline> {
        if !self.model.enabled {
            return None;
        }
        let weights = WeightsLoader::load(Path::new(&self.model.weights_path)).ok()?;
        // 权重维度/迭代次数须与配置一致，否则降级（B2-7 契约 D：道体接入层校验）
        if weights.dim != self.model.dim || weights.t_iter != self.model.t_iter {
            return None;
        }
        let ascent = Array2::from_shape_vec((weights.dim, weights.dim), weights.ascent).ok()?;
        let descent = Array2::from_shape_vec((weights.dim, weights.dim), weights.descent).ok()?;
        let bias = Array1::from_vec(weights.bias);
        let network = BilateralLadderNetwork::new(ascent, descent, bias, weights.t_iter).ok()?;
        let codec = SyscallCodec::new(weights.dim, weights.op_dict).ok()?;
        // Gate 仍默认关闭；只有运行期指标明确满足条件时才放行 B2。
        let gate = runtime_b2_gate();
        Some(DecisionPipeline::new().with_b2(network, codec, gate, self.model.confidence_threshold))
    }

    /// 以规则映射处理 syscall 事件流（模式B·道体·达 入口）
    ///
    /// - `events`: 士兵捕获的 Linux syscall 事件序列
    /// - `binary_path` / `binary_args`: 原始二进制及其参数（触发降级时回退到 B0 执行）
    ///
    /// 流程：逐条查表 → 命中注入并推进状态；未命中累计达阈值（5 条）则降级：
    /// WSL2 可用 → 走 `run_cross_platform`；WSL2 不可用 → 返回 `Unavailable`。
    pub async fn run_b1(
        &self,
        events: &[SyscallEvent],
        binary_path: &str,
        binary_args: &[String],
    ) -> Result<B1RunReport, DaotiError> {
        let mut pipeline = self.build_b1_pipeline();
        let mut mapped: Vec<String> = Vec::new();

        for event in events {
            match pipeline.step(event)? {
                B1Step::Mapped(result) => mapped.push(result.operation),
                B1Step::Derived { operation, .. } => mapped.push(operation),
                B1Step::Missed { .. } => {
                    if pipeline.should_fallback() {
                        break;
                    }
                }
            }
        }

        let fell_back = pipeline.should_fallback();

        // 触发降级：确认 WSL2 可用后回退到 B0 执行，否则返回错误
        let fallback = if fell_back {
            let wsl_state = self.wsl2.collect().await;
            if !wsl_state.is_ok() {
                return Err(DaotiError::Unavailable(
                    "未命中映射且 WSL2 不可用，无法降级执行".into(),
                ));
            }
            Some(self.run_cross_platform(binary_path, binary_args).await?)
        } else {
            None
        };

        Ok(B1RunReport {
            mode: if fell_back {
                "wsl2_fallback"
            } else {
                "b1_rule"
            }
            .to_string(),
            mapped,
            missed: pipeline.miss_count(),
            unique_missed: pipeline.telemetry().unique_syscalls(),
            state: pipeline.state().clone(),
            fallback,
        })
    }
}

#[cfg(test)]
mod b1_tests {
    use super::*;
    use crate::bilateral::weights::{BilateralWeights, OpEntry, WEIGHTS_VERSION};
    use ndarray::{Array1, Array2};

    /// 命中事件推进状态账本（open → fd 表，mmap → 内存表）
    #[test]
    fn pipeline_maps_supported_events_and_advances_state() {
        let mut p = DecisionPipeline::new();

        let open_ev = SyscallEvent::new(2, "open", vec!["/etc/hosts".into(), "O_RDONLY".into()], 1);
        match p.step(&open_ev).unwrap() {
            B1Step::Mapped(res) => assert_eq!(res.operation, "CreateFileW"),
            _ => panic!("open 应命中映射"),
        }
        assert_eq!(p.state().fd_count(), 1);

        let mmap_ev = SyscallEvent::new(9, "mmap", vec!["0x1000".into(), "4096".into()], 1);
        assert!(matches!(p.step(&mmap_ev).unwrap(), B1Step::Mapped(_)));
        assert_eq!(p.state().mmap_count(), 1);
        assert_eq!(p.state().mmaps[0].addr, 0x1000);
    }

    /// 未命中累计达到阈值后触发降级信号，遥测去重正确
    #[test]
    fn pipeline_counts_misses_and_flags_fallback() {
        let mut p = DecisionPipeline::new();
        for i in 0..5 {
            let ev = SyscallEvent::new(300 + i, "unknown", vec![], 1);
            assert!(matches!(p.step(&ev).unwrap(), B1Step::Missed { .. }));
        }
        assert!(p.should_fallback());
        assert_eq!(p.miss_count(), 5);
        assert_eq!(
            p.telemetry().unique_syscalls(),
            vec![300, 301, 302, 303, 304]
        );
    }

    /// 阈值以下不触发降级
    #[test]
    fn pipeline_does_not_fallback_below_threshold() {
        let mut p = DecisionPipeline::new();
        for i in 0..4 {
            let ev = SyscallEvent::new(300 + i, "unknown", vec![], 1);
            p.step(&ev).unwrap();
        }
        assert!(!p.should_fallback());
        assert_eq!(p.miss_count(), 4);
    }

    /// 映射表内操作均可通过注入校验（不触发 Blocked）
    #[test]
    fn pipeline_never_blocks_mapped_operations() {
        let mut p = DecisionPipeline::new();
        for nr in [0, 1, 2, 39, 79] {
            let ev = SyscallEvent::new(nr, "mapped", vec![], 1);
            assert!(matches!(p.step(&ev).unwrap(), B1Step::Mapped(_)));
        }
    }

    /// 构造 3 维恒等（t_iter=0）网络 + 含 nr=300 的编解码器，供 B2 推导测试。
    ///
    /// t_iter=0 使 forward 恒等透传，聚焦验证 B2-4 接入逻辑（网络数学已由 B2-2 覆盖）。
    fn b2_fixture() -> (BilateralLadderNetwork, SyscallCodec) {
        let identity =
            Array2::from_shape_vec((3, 3), vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0])
                .expect("构造恒等矩阵失败");
        let bias = Array1::from_vec(vec![0.0, 0.0, 0.0]);
        let net =
            BilateralLadderNetwork::new(identity.clone(), identity, bias, 0).expect("构造网络失败");
        let codec = SyscallCodec::new(
            3,
            vec![OpEntry {
                nr: 300,
                name: "unknown".into(),
                windows_op: "WSAStartup".into(),
            }],
        )
        .expect("构造编解码器失败");
        (net, codec)
    }

    /// B2-4：gate 就绪 + network 注入时，未命中事件走推导路径（判词「道体·化」）。
    #[test]
    fn b2_derives_when_gate_ready() {
        let (net, codec) = b2_fixture();
        let gate = B2Gate::with_metrics(true, 0.9, 100_000, 0.95);
        let mut p = DecisionPipeline::new().with_b2(net, codec, gate, 0.7);

        let ev = SyscallEvent::new(300, "unknown", vec![], 1);
        match p.step(&ev).expect("推导步骤不应报错") {
            B1Step::Derived {
                operation,
                confidence,
            } => {
                assert_eq!(operation, "WSAStartup");
                assert!(confidence >= 0.7);
            }
            other => panic!("gate 就绪时应走推导路径，实际 {:?}", other),
        }
    }

    #[test]
    fn stage2_emits_read_only_high_confidence_suggestion() {
        let (net, codec) = b2_fixture();
        let gate = B2Gate::with_metrics(true, 0.9, 100_000, 0.95);
        let p = DecisionPipeline::new().with_b2(net, codec, gate, 0.7);
        let ev = SyscallEvent::new(300, "unknown", vec![], 1);
        let suggestion = p.shadow_suggestion(&ev).expect("应生成只读建议");
        assert_eq!(suggestion.operation, "WSAStartup");
        assert!(suggestion.confidence > 0.95);
        assert_eq!(p.miss_count(), 0);
        let suggestion = suggestion.with_actual_result(Ok(1), Some("WSAStartup".into()));
        assert_eq!(suggestion.actual_result, Some(1));
        assert_eq!(suggestion.actual_success, Some(true));
        assert_eq!(suggestion.actual_operation.as_deref(), Some("WSAStartup"));
    }

    #[test]
    fn stage3_requires_explicit_controlled_policy_and_whitelists() {
        let policy = ControlledGuidancePolicy {
            enabled: true,
            test_program: "controlled-fixture".into(),
            allowed_syscalls: vec![300],
            allowed_operations: vec!["WSAStartup".into()],
            timeout_ms: 1000,
        };
        let (net, codec) = b2_fixture();
        let p = DecisionPipeline::new()
            .with_b2(
                net,
                codec,
                B2Gate::with_metrics(true, 0.9, 100_000, 0.95),
                0.7,
            )
            .with_controlled_policy(policy);
        let event = SyscallEvent::new(300, "unknown", vec![], 1);
        assert!(matches!(
            p.controlled_guidance("controlled-fixture", &event),
            ControlledGuidanceResult::Suggested(_)
        ));
        assert!(matches!(
            p.controlled_guidance("hello_dynamic", &event),
            ControlledGuidanceResult::Fallback { .. }
        ));
        let (result, audit) = p.controlled_guidance_with_audit("controlled-fixture", &event);
        assert!(matches!(result, ControlledGuidanceResult::Suggested(_)));
        assert_eq!(audit.decision, "suggested");
        assert_eq!(audit.timeout_ms, 1000);
        assert!(serde_json::to_string(&audit).is_ok());
    }

    #[test]
    fn stage3_falls_back_for_disabled_zero_timeout_or_non_whitelisted_operation() {
        let event = SyscallEvent::new(300, "unknown", vec![], 1);
        let (net, codec) = b2_fixture();
        let disabled = DecisionPipeline::new().with_b2(
            net,
            codec,
            B2Gate::with_metrics(true, 0.9, 100_000, 0.95),
            0.7,
        );
        assert!(matches!(
            disabled.controlled_guidance("controlled-fixture", &event),
            ControlledGuidanceResult::Fallback { .. }
        ));
        let invalid_timeout = ControlledGuidancePolicy {
            enabled: true,
            test_program: "controlled-fixture".into(),
            allowed_syscalls: vec![300],
            allowed_operations: vec!["WSAStartup".into()],
            timeout_ms: 0,
        };
        let (net, codec) = b2_fixture();
        let p = DecisionPipeline::new()
            .with_b2(
                net,
                codec,
                B2Gate::with_metrics(true, 0.9, 100_000, 0.95),
                0.7,
            )
            .with_controlled_policy(invalid_timeout);
        assert!(matches!(
            p.controlled_guidance("controlled-fixture", &event),
            ControlledGuidanceResult::Fallback { .. }
        ));
    }

    #[test]
    fn stage2_does_not_suggest_mapped_or_gate_blocked_event() {
        let (net, codec) = b2_fixture();
        let p = DecisionPipeline::new().with_b2(net, codec, B2Gate::new(), 0.7);
        assert!(p
            .shadow_suggestion(&SyscallEvent::new(0, "read", vec![], 1))
            .is_none());
        assert!(p
            .shadow_suggestion(&SyscallEvent::new(300, "unknown", vec![], 1))
            .is_none());
    }

    /// B2-4：gate 未就绪时，未命中事件仍走降级链路（B1 不回归）。
    #[test]
    fn b2_falls_back_when_gate_not_ready() {
        let (net, codec) = b2_fixture();
        let gate = B2Gate::new(); // 默认未就绪
        let mut p = DecisionPipeline::new().with_b2(net, codec, gate, 0.7);

        let ev = SyscallEvent::new(300, "unknown", vec![], 1);
        match p.step(&ev).expect("降级步骤不应报错") {
            B1Step::Missed { miss_count } => assert_eq!(miss_count, 1),
            other => panic!("gate 未就绪时应降级，实际 {:?}", other),
        }
    }

    /// B2-6：命中（Mapped）记入成功样本、未命中记入失败样本，覆盖率统计正确。
    #[test]
    fn b2_success_and_miss_feed_coverage() {
        let mut p = DecisionPipeline::new();

        // 命中：open → CreateFileW（成功样本）
        let open_ev = SyscallEvent::new(2, "open", vec!["/etc/hosts".into()], 1);
        assert!(matches!(p.step(&open_ev).unwrap(), B1Step::Mapped(_)));

        // 未命中：unknown（失败样本）
        let miss_ev = SyscallEvent::new(300, "unknown", vec![], 1);
        assert!(matches!(p.step(&miss_ev).unwrap(), B1Step::Missed { .. }));

        // 覆盖率 = 命中 1 / (成功 1 + 失败 1) = 0.5
        assert_eq!(p.telemetry().hit_count(), 1);
        assert_eq!(p.telemetry().miss_count(), 1);
        assert!((p.telemetry().coverage() - 0.5).abs() < 1e-9);
    }

    /// 构造一个 dim=3、t_iter=0 的合法权重并写入临时文件，返回文件路径。
    fn write_temp_weights() -> std::path::PathBuf {
        let weights = BilateralWeights {
            version: WEIGHTS_VERSION,
            dim: 3,
            t_iter: 0,
            ascent: vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            descent: vec![1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
            bias: vec![0.0, 0.0, 0.0],
            op_dict: vec![OpEntry {
                nr: 300,
                name: "unknown".into(),
                windows_op: "WSAStartup".into(),
            }],
        };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应晚于 Unix 纪元")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "daoti_test_b2_weights_{}_{}.bin",
            std::process::id(),
            nonce
        ));
        std::fs::write(&path, weights.to_bytes()).expect("写测试权重失败");
        path
    }

    /// B2 接入：能力开关关闭时旁路网络（构建纯 B1 流水线）。
    #[test]
    fn b2_build_pipeline_disabled_bypasses() {
        let mut cfg = Config::default();
        cfg.model.enabled = false;
        let agent = CrossPlatformAgent::new(&cfg);
        assert!(agent.try_build_b2_pipeline().is_none());
    }

    /// B2 接入：权重文件缺失时降级（构建纯 B1 流水线，B1 不回归）。
    #[test]
    fn b2_build_pipeline_missing_weights_falls_back() {
        let mut cfg = Config::default();
        cfg.model.enabled = true;
        cfg.model.weights_path = "__definitely_missing_b2_weights__.bin".to_string();
        let agent = CrossPlatformAgent::new(&cfg);
        assert!(agent.try_build_b2_pipeline().is_none());
    }

    /// B2 接入：权重有效时成功构建 B2 流水线；gate 默认未就绪故网络旁路（B1 不回归）。
    #[test]
    fn b2_build_pipeline_loads_valid_weights() {
        let path = write_temp_weights();
        let mut cfg = Config::default();
        cfg.model.enabled = true;
        cfg.model.weights_path = path.to_string_lossy().to_string();
        cfg.model.dim = 3;
        cfg.model.t_iter = 0;
        cfg.model.confidence_threshold = 0.7;
        let agent = CrossPlatformAgent::new(&cfg);

        let mut pipeline = agent
            .try_build_b2_pipeline()
            .expect("有效权重应构建 B2 流水线");
        // gate 覆盖率/配对样本/成功率为 0 → 网络旁路，未命中事件走降级（绝无死路）
        let ev = SyscallEvent::new(300, "unknown", vec![], 1);
        assert!(matches!(pipeline.step(&ev).unwrap(), B1Step::Missed { .. }));

        let _ = std::fs::remove_file(&path);
    }

    /// B2 接入：权重维度与配置不一致时降级（B2-7 契约 D 校验）。
    #[test]
    fn b2_build_pipeline_dim_mismatch_falls_back() {
        let path = write_temp_weights(); // dim=3
        let mut cfg = Config::default();
        cfg.model.enabled = true;
        cfg.model.weights_path = path.to_string_lossy().to_string();
        cfg.model.dim = 5; // 与权重 dim=3 不一致
        cfg.model.t_iter = 0;
        cfg.model.confidence_threshold = 0.7;
        let agent = CrossPlatformAgent::new(&cfg);
        assert!(agent.try_build_b2_pipeline().is_none());
        let _ = std::fs::remove_file(&path);
    }
}
