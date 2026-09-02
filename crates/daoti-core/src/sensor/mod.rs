//! 感知层 (daoti-core::sensor)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.1。三感知器统一实现 `Sensor` trait，
//! 输出结构化 `SensorState`。感知器对"系统不存在/命令不可用"返回 `Unavailable` 而非 panic。

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::runner::run_with_timeout;

pub mod docker;
pub mod fusion;
pub mod windows;
pub mod wsl2;

// 在模块根再导出融合类型，便于上层（CLI/Daemon）使用
pub use fusion::{FusionState, WuxingHealth};

/// 感知器统一接口（感知层契约）
pub trait Sensor: Send + Sync {
    /// 采集一次目标平台的状态；对"系统不存在/命令不可用"返回 `Unavailable` 而非 panic
    ///
    /// 返回 `Send` 的 future，以便在 Daemon 中被 `tokio::spawn` 到多线程运行时。
    fn collect(&self) -> impl std::future::Future<Output = SensorState> + Send;
}

/// 单平台感知结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensorState {
    /// 采集成功，携带结构化指标
    Ok(SensorSnapshot),
    /// 目标平台不可达（Docker daemon 断连、WSL 不存在、命令不可用等）
    Unavailable,
}

impl SensorState {
    /// 是否成功
    pub fn is_ok(&self) -> bool {
        matches!(self, SensorState::Ok(_))
    }
}

/// 结构化状态快照（各平台共性字段，扩展字段保留在自定义 map 中）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensorSnapshot {
    /// 目标平台标识（windows / wsl2 / docker）
    pub target: String,
    /// 关键数值指标（如 CPU、容器数）
    pub metrics: std::collections::HashMap<String, f64>,
    /// 关键文本指标（如内核版本、服务状态）
    pub fields: std::collections::HashMap<String, String>,
}

impl SensorSnapshot {
    /// 新建快照
    pub fn new(target: impl Into<String>) -> Self {
        SensorSnapshot {
            target: target.into(),
            ..Default::default()
        }
    }

    /// 写入数值指标
    pub fn metric(mut self, key: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(key.into(), value);
        self
    }

    /// 写入文本指标
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    /// 读取数值指标，缺失返回 0.0
    pub fn metric_of(&self, key: &str) -> f64 {
        self.metrics.get(key).copied().unwrap_or(0.0)
    }

    /// 读取文本指标，缺失返回空串
    pub fn field_of(&self, key: &str) -> &str {
        self.fields.get(key).map(String::as_str).unwrap_or("")
    }
}

/// 便捷：调用一个感知命令并应用默认超时（秒）
pub(crate) async fn probe(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<String, crate::DaotiError> {
    run_with_timeout(program, args, Duration::from_secs(timeout_secs)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_defaults_to_zero() {
        let s = SensorSnapshot::new("docker");
        assert_eq!(s.metric_of("containers"), 0.0);
    }

    #[test]
    fn snapshot_chain_builds() {
        let s = SensorSnapshot::new("wsl2")
            .metric("cpu", 0.3)
            .field("kernel", "6.6");
        assert_eq!(s.target, "wsl2");
        assert_eq!(s.metric_of("cpu"), 0.3);
        assert_eq!(s.fields.get("kernel").map(String::as_str), Some("6.6"));
    }

    #[test]
    fn state_is_ok_only_for_ok() {
        assert!(SensorState::Ok(SensorSnapshot::new("wsl2")).is_ok());
        assert!(!SensorState::Unavailable.is_ok());
    }
}
