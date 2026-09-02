//! 执行层 (daoti-core::executor)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.3 与《rust语言开发.md》第 3 节
//! （PlatformExecutor trait 多态 + 工厂按 target 分派）。
//! SafeCommandExecutor 提供白名单/禁止模式/超时/回滚安全沙箱。

use daoti_common::DaotiError;
use serde::{Deserialize, Serialize};

pub mod adapter;
pub mod execution;
pub mod remote_macos;
pub mod remote_pe;
pub mod safe;

pub use remote_macos::{
    timeout_duration, AuditEvent, AuthMethod, Authentication, BinaryUpload, ExecutorState,
    MacOsExecutorError, MacOsHttpClient, MacOsNodeCapabilities, MacOsRequest, MacOsResponse,
    MockMacOsExecutor, NodeHealth, NodeRegistration, NodeRegistry, ProtocolError,
    RemoteMacOsExecutor, RequestStatus, MAX_BINARY_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

pub use remote_pe::{MockPeExecutor, PeNodeCapabilities, PeRequest, PeRequestStatus, PeResponse};

pub use execution::{
    CapabilityRegistry, Decision, DispatchRequest, ExecutionCapability, ExecutionDiagnostic,
    ExecutionMode, ExecutionReport, ExecutionTarget,
};

/// 单条平台指令规格（由 PlatformCommandGenerator 产出）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandSpec {
    /// 目标平台：windows / wsl2 / docker
    pub target: String,
    /// 指令（参数已拆分，由执行器决定如何传给子进程）
    pub command: String,
    /// 执行超时秒数
    pub timeout: u64,
    /// 执行模式：sync（等待）/ async（异步）/ fire_and_forget（发射后不管）
    pub execution_mode: String,
}

impl CommandSpec {
    /// 构造指令规格
    pub fn new(target: impl Into<String>, command: impl Into<String>) -> Self {
        CommandSpec {
            target: target.into(),
            command: command.into(),
            timeout: 10,
            execution_mode: "sync".into(),
        }
    }

    /// 链式设置超时
    pub fn with_timeout(mut self, t: u64) -> Self {
        self.timeout = t;
        self
    }
}

/// 单条命令执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub returncode: i32,
    pub command: String,
    pub target: String,
}

impl ExecResult {
    /// 构造成功结果
    pub fn ok(target: &str, command: &str, stdout: String, returncode: i32) -> Self {
        ExecResult {
            success: true,
            stdout,
            stderr: String::new(),
            returncode,
            command: command.to_string(),
            target: target.to_string(),
        }
    }

    /// 构造失败结果
    pub fn fail(target: &str, command: &str, stderr: impl Into<String>, returncode: i32) -> Self {
        ExecResult {
            success: false,
            stdout: String::new(),
            stderr: stderr.into(),
            returncode,
            command: command.to_string(),
            target: target.to_string(),
        }
    }
}

/// 平台执行器统一契约（多态，按 target 分派）
///
/// 注意：trait 含 async fn，无法作为 `dyn` 装箱；实际分派由
/// `SafeCommandExecutor` 持有具体执行器并按 target match 完成（工厂语义内聚于安全层）。
pub trait PlatformExecutor: Send + Sync {
    /// 执行一条平台指令，返回结构化结果；失败返回 ExecutionError
    async fn execute(&self, spec: &CommandSpec) -> Result<ExecResult, DaotiError>;
}
