//! 领域错误枚举 (DaotiError)
//!
//! 依据《道体跨平台智能调度系统设计方案.md》全局错误设计：无论哪个环节出错
//! （管道断了、命令超时、模型加载失败、路径映射失败），都不导致守护进程崩溃，
//! 只优雅返回错误。

use serde::Serialize;

/// 驭灵全局领域错误
#[derive(Debug, thiserror::Error)]
pub enum DaotiError {
    /// 消息通道断开（感知/推演/执行层之间用 mpsc 通信，见《rust语言开发.md》）
    #[error("消息通道已断开: {0}")]
    ChannelClosed(String),

    /// 子进程命令执行超时，携带超时秒数与命令摘要
    #[error("命令执行超时 (>{timeout}s): {command}")]
    CommandTimeout { timeout: u64, command: String },

    /// 跨系统路径映射失败（Windows 盘符 <-> WSL /mnt，见开发计划 R3）
    #[error("路径映射失败: {0}")]
    PathMapping(String),

    /// 配置加载错误
    #[error("配置错误: {0}")]
    Config(String),

    /// 命令被安全策略拦截（SafeCommandExecutor 白名单/禁止模式，见设计方案 §3.3.2）
    #[error("命令被安全策略拦截: {0}")]
    Blocked(String),

    /// 感知器/执行器对某目标不可用（系统不存在、命令不可用）
    #[error("目标平台不可用: {0}")]
    Unavailable(String),

    // ─── 模式B：跨平台二进制运行 ────────────────────────────
    /// 文件不存在
    #[error("文件不存在: {0}")]
    FileNotFound(String),

    /// 无法识别的二进制格式（非 ELF/PE/Mach-O）
    #[error("无法识别的二进制格式: {0}")]
    UnrecognizedFormat(String),

    /// 二进制格式解析错误（文件结构非法/数据不完整/字段值无效）
    #[error("解析错误: {0}")]
    ParseError(String),

    /// 权限不足（syscall 拦截/注入需要管理员权限）
    #[error("权限不足: {0}")]
    PermissionDenied(String),

    /// syscall 解码失败（输出向量无法映射为有效系统调用）
    #[error("解码错误: {0}")]
    DecodeError(String),

    /// 双梯形网络权重文件缺失
    #[error("模型权重缺失")]
    ModelMissing,

    /// 双梯形网络权重文件损坏或格式非法（magic/版本/长度不匹配）
    #[error("模型权重损坏: {0}")]
    ModelCorrupt(String),

    /// 双梯形网络推理失败（NaN/Inf 等数值异常）
    #[error("推理失败: {0}")]
    InferenceFailed(String),

    /// 底层 I/O 错误
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),

    /// 序列化错误
    #[error("序列化错误: {0}")]
    Json(#[from] serde_json::Error),

    /// 其它未分类错误
    #[error("其它错误: {0}")]
    Other(String),
}

impl DaotiError {
    /// 判断是否为可恢复/可降级错误（用于主控决定是否继续执行）
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DaotiError::Unavailable(_)
                | DaotiError::CommandTimeout { .. }
                | DaotiError::ModelMissing
                | DaotiError::ModelCorrupt(_)
                | DaotiError::InferenceFailed(_)
                | DaotiError::DecodeError(_)
                | DaotiError::ParseError(_)
        )
    }

    /// 返回错误类型的稳定标识（供序列化/日志分类）
    pub fn kind(&self) -> &'static str {
        match self {
            DaotiError::ChannelClosed(_) => "channel_closed",
            DaotiError::CommandTimeout { .. } => "command_timeout",
            DaotiError::PathMapping(_) => "path_mapping",
            DaotiError::Config(_) => "config",
            DaotiError::Blocked(_) => "blocked",
            DaotiError::Unavailable(_) => "unavailable",
            DaotiError::FileNotFound(_) => "file_not_found",
            DaotiError::UnrecognizedFormat(_) => "unrecognized_format",
            DaotiError::ParseError(_) => "parse_error",
            DaotiError::PermissionDenied(_) => "permission_denied",
            DaotiError::DecodeError(_) => "decode_error",
            DaotiError::ModelMissing => "model_missing",
            DaotiError::ModelCorrupt(_) => "model_corrupt",
            DaotiError::InferenceFailed(_) => "inference_failed",
            DaotiError::Io(_) => "io",
            DaotiError::Json(_) => "json",
            DaotiError::Other(_) => "other",
        }
    }
}

/// 供 UI/日志序列化使用的错误快照（不含栈信息）
#[derive(Debug, Clone, Serialize)]
pub struct ErrorSnapshot {
    pub kind: String,
    pub message: String,
}

impl From<&DaotiError> for ErrorSnapshot {
    fn from(e: &DaotiError) -> Self {
        ErrorSnapshot {
            kind: e.kind().to_string(),
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_carries_context() {
        let err = DaotiError::CommandTimeout {
            timeout: 5,
            command: "docker version".into(),
        };
        assert!(err.is_recoverable());
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("docker version"));
    }

    #[test]
    fn blocked_is_not_recoverable() {
        let err = DaotiError::Blocked("rm -rf /".into());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn snapshot_is_serializable() {
        let err = DaotiError::Config("缺省值错误".into());
        let snap: ErrorSnapshot = (&err).into();
        let json = serde_json::to_string(&snap).expect("快照序列化失败");
        assert!(json.contains("配置错误"));
    }
}
