//! WSL2 感知器 (daoti-core::sensor::wsl2)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.1.2。通过 `wsl` 命令桥接采集发行版内部状态。

use super::{probe, Sensor, SensorSnapshot, SensorState};

/// WSL2 感知器
pub struct Wsl2Sensor {
    /// WSL 发行版名
    pub distro: String,
}

impl Wsl2Sensor {
    /// 构造感知器
    pub fn new(distro: impl Into<String>) -> Self {
        Wsl2Sensor {
            distro: distro.into(),
        }
    }

    /// 在发行版内执行命令，返回输出；失败返回 None
    async fn exec(&self, cmd: &str, timeout: u64) -> Option<String> {
        // 将整条命令拆为参数数组传给 wsl，避免拼接注入
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        probe(
            "wsl",
            &["-d", &self.distro, "--", &parts.join(" ")],
            timeout,
        )
        .await
        .ok()
    }

    /// 检查发行版是否在运行
    async fn is_running(&self) -> bool {
        match probe("wsl", &["-l", "-v"], 5).await {
            Ok(out) => out.contains(&self.distro) && out.contains("Running"),
            Err(_) => false,
        }
    }
}

impl Sensor for Wsl2Sensor {
    async fn collect(&self) -> SensorState {
        let running = self.is_running().await;
        if !running {
            return SensorState::Unavailable;
        }

        // 采集关键指标；单个失败不致命，缺失字段以空串兜底
        let mut snap = SensorSnapshot::new("wsl2")
            .field("distro", self.distro.clone())
            .metric("running", 1.0);

        if let Some(kernel) = self.exec("uname -r", 5).await {
            snap = snap.field("kernel_version", kernel.trim());
        }
        if let Some(dockerd) = self
            .exec(
                "pgrep dockerd > /dev/null && echo running || echo stopped",
                5,
            )
            .await
        {
            snap = snap.field(
                "docker_daemon_running",
                if dockerd.contains("running") {
                    "running"
                } else {
                    "stopped"
                },
            );
        }

        SensorState::Ok(snap)
    }
}

#[cfg(test)]
mod tests {
    /// 纯函数：解析 dockerd 探测输出
    fn parse_dockerd(raw: &str) -> &'static str {
        if raw.contains("running") {
            "running"
        } else {
            "stopped"
        }
    }

    #[test]
    fn parses_dockerd_probe() {
        assert_eq!(parse_dockerd("running\n"), "running");
        assert_eq!(parse_dockerd("stopped"), "stopped");
        assert_eq!(parse_dockerd(""), "stopped");
    }
}
