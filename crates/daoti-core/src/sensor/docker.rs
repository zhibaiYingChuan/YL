//! Docker 感知器 (daoti-core::sensor::docker)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.1.3。通过 docker CLI 采集容器运行时状态。
//! 自动探测可用端点，全部失败返回 Unavailable（开发计划 R6）。

use super::{probe, Sensor, SensorSnapshot, SensorState};

/// 候选 Docker 端点（依次探测）
const ENDPOINTS: &[&str] = &[
    "unix:///var/run/docker.sock",    // WSL2 原生
    "npipe:////./pipe/docker_engine", // Windows 命名管道
];

/// Docker 感知器
#[derive(Default)]
pub struct DockerSensor;

impl DockerSensor {
    /// 构造感知器
    pub fn new() -> Self {
        DockerSensor
    }

    /// 探测可用端点；返回第一个可用端点
    async fn find_active_endpoint(&self) -> Option<String> {
        // 简化探测：优先检查本机 docker CLI 是否能连接（不设 DOCKER_HOST 走默认端点）
        // 端点候选通过文件存在性初筛，避免逐个拉起 docker 进程
        for ep in ENDPOINTS {
            let path = ep
                .strip_prefix("unix://")
                .or_else(|| ep.strip_prefix("npipe://"))
                .unwrap_or(ep);
            if std::path::Path::new(path).exists() {
                return Some((*ep).to_string());
            }
        }
        // 兜底：直接跑 docker version 看默认端点是否可达
        match probe("docker", &["version", "--format", "{{.Server.Version}}"], 3).await {
            Ok(v) if !v.trim().is_empty() => Some("default".to_string()),
            _ => None,
        }
    }

    /// 执行 docker 子命令，返回输出
    async fn docker(&self, args: &[&str], timeout: u64) -> Option<String> {
        probe("docker", args, timeout).await.ok()
    }
}

impl Sensor for DockerSensor {
    async fn collect(&self) -> SensorState {
        let endpoint = self.find_active_endpoint().await;
        if endpoint.is_none() {
            return SensorState::Unavailable;
        }

        let mut snap =
            SensorSnapshot::new("docker").field("endpoint", endpoint.unwrap_or_default());

        if let Some(ver) = self
            .docker(&["version", "--format", "{{.Server.Version}}"], 3)
            .await
        {
            snap = snap.field("daemon_version", ver.trim());
        }
        // 使用非管道方式统计容器数（docker ps -aq 每行一个容器 ID）
        if let Some(list) = self.docker(&["ps", "-aq"], 5).await {
            let count = list.lines().filter(|l| !l.trim().is_empty()).count() as f64;
            snap = snap.metric("containers", count);
        }

        SensorState::Ok(snap)
    }
}

#[cfg(test)]
mod tests {
    /// 纯函数：从 docker ps -aq 输出统计容器数
    fn count_containers(raw: &str) -> f64 {
        raw.lines().filter(|l| !l.trim().is_empty()).count() as f64
    }

    #[test]
    fn counts_containers() {
        assert_eq!(count_containers(""), 0.0);
        assert_eq!(count_containers("abc\n"), 1.0);
        assert_eq!(count_containers("abc\ndef\nghi\n"), 3.0);
        assert_eq!(count_containers("\n\n"), 0.0);
    }
}
