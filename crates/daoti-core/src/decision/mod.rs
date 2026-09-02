//! 调度输出层 (daoti-core::decision)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.2 / §3.3。将五行健康度推演为
//! 调度决策（priority/pathway/commands/explanation），由规则引擎（五行映射表）
//! 确定性推演生成。

use serde::{Deserialize, Serialize};

use crate::executor::{CommandSpec, ExecutionTarget};

pub mod causal_adapter;
pub mod command_gen;
pub mod engine;
pub mod model;
pub mod scheduler;
pub mod symbolic;
pub mod symbolic_client;

pub use causal_adapter::CrossPlatformCausalAdapter;
pub use command_gen::PlatformCommandGenerator;
pub use engine::{InferenceEngine, RuleEngine};
pub use symbolic::DaotiSymbolicOutput;
pub use symbolic_client::SymbolicInferenceClient;

/// 统一跨平台二进制调度请求。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchRequest {
    pub path: String,
    pub args: Vec<String>,
}

/// 格式探测后的结构化目标。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchTarget {
    pub format: String,
    pub platform: String,
    pub mode: String,
    pub execution_target: ExecutionTarget,
    pub reason: String,
}

/// 能力注册表：调度器只依赖注册能力，不把格式与执行目标散落在调用方。
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub format: &'static str,
    pub platform: &'static str,
    pub mode: &'static str,
    pub execution_target: ExecutionTarget,
    pub available: bool,
    pub reason: &'static str,
    pub diagnostic: Option<&'static str>,
}

pub const CAPABILITIES: &[Capability] = &[
    Capability {
        format: "Linux 之躯",
        platform: "linux",
        mode: "static_elf_interpreter",
        execution_target: ExecutionTarget::StaticElfInterpreter,
        available: true,
        reason: "静态 ELF 无需动态链接器，保持本地解释执行",
        diagnostic: None,
    },
    Capability {
        format: "Linux 之躯",
        platform: "linux",
        mode: "dynamic_elf_interpreter",
        execution_target: ExecutionTarget::DynamicElfInterpreter,
        available: false,
        reason: "动态 ELF 的 PT_INTERP/DT_NEEDED 尚未由解释器真实执行",
        diagnostic: Some("当前仅完成动态对象解析、映射和重定位规划，不能宣称入口已执行"),
    },
    Capability {
        format: "Windows 之体",
        platform: "windows",
        mode: "pe_interpreter",
        execution_target: ExecutionTarget::PeInterpreter,
        available: true,
        reason: "仅支持受限受控 x86_64 PE32+ 控制台 fixture，不代表通用 PE", 
        diagnostic: Some("仅支持 x86_64 PE32+ 控制台 fixture：已实现指令集与 WriteFile/ExitProcess shim；不代表通用 Windows PE 兼容性"),
    },
    Capability {
        format: "macOS 之形",
        platform: "macos",
        mode: "remote_macos",
        execution_target: ExecutionTarget::RemoteMacOs,
        available: false,
        reason: "Mach-O 仅允许远程 macOS，当前未配置远程节点",
        diagnostic: Some("macOS 目标已识别，但当前远程执行后端不可用；请配置远程节点"),
    },
];

pub fn capability(format: &'static str, dynamic_elf: bool) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|c| {
        c.format == format
            && (format != "Linux 之躯"
                || c.execution_target
                    == if dynamic_elf {
                        ExecutionTarget::DynamicElfInterpreter
                    } else {
                        ExecutionTarget::StaticElfInterpreter
                    })
    })
}

/// 统一调度裁决；不可用时保留明确诊断而非丢失格式信息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchDecision {
    pub request: DispatchRequest,
    pub target: DispatchTarget,
    pub available: bool,
    pub diagnostic: Option<String>,
    /// 目标能力版本，便于跨平台契约追踪。
    #[serde(default)]
    pub capability_version: String,
    /// 调度过程中的可观测事件。
    #[serde(default)]
    pub observation_events: Vec<String>,
    /// 可选的模拟节点标识，仅用于测试/离线验收。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mock_node: Option<String>,
}

/// 一次调度决策（卦象 → 五行 → 平台指令）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// 调度优先级（如 wsl2_first / docker_first）
    pub priority: String,
    /// 处理路径（如 reset_wsl / restart_daemon）
    pub pathway: String,
    /// 主卦名（如 坎 / 艮）
    pub gua: String,
    /// 置信度（0~1）
    pub confidence: f64,
    /// 人类可读判词
    pub explanation: String,
    /// 平台自适应指令
    pub commands: Vec<CommandSpec>,
    /// 道体五行调度参数（步长/阻尼/检索混合），JSON 中空调度自动省略。
    #[serde(
        default,
        skip_serializing_if = "scheduler::SchedulerParams::is_default"
    )]
    pub scheduler: scheduler::SchedulerParams,
}
