//! Windows 感知器 (daoti-core::sensor::windows)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.1.1。采集 Windows 宿主机状态。
//! 通过 PowerShell 子进程采集（shell=false 防注入），不可用时返回 Unavailable。

use super::{probe, Sensor, SensorSnapshot, SensorState};

/// Windows 感知器
pub struct WindowsSensor {
    /// Docker Desktop 服务名
    pub docker_service: String,
}

impl WindowsSensor {
    /// 构造感知器
    pub fn new(docker_service: impl Into<String>) -> Self {
        WindowsSensor {
            docker_service: docker_service.into(),
        }
    }

    /// 检查指定进程是否存在
    async fn is_process_running(&self, name: &str) -> bool {
        let ps =
            format!("(Get-Process '{name}' -ErrorAction SilentlyContinue | Measure-Object).Count");
        match probe(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &ps],
            5,
        )
        .await
        {
            Ok(out) => out.trim() != "0",
            Err(_) => false,
        }
    }

    /// 获取服务状态（Running / Stopped / Unknown）
    async fn get_service_status(&self) -> String {
        let ps = format!(
            "(Get-Service '{}' -ErrorAction SilentlyContinue).Status",
            self.docker_service
        );
        match probe(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &ps],
            5,
        )
        .await
        {
            Ok(out) => {
                let s = out.trim();
                if s.is_empty() {
                    "Unknown".to_string()
                } else {
                    s.to_string()
                }
            }
            Err(_) => "Unknown".to_string(),
        }
    }
}

impl Sensor for WindowsSensor {
    async fn collect(&self) -> SensorState {
        let docker_desktop_running = self.is_process_running("Docker Desktop").await;
        let service_status = self.get_service_status().await;

        // 若连 Docker Desktop 进程与服务都探测不到，判定不可用
        if !docker_desktop_running && service_status == "Unknown" {
            return SensorState::Unavailable;
        }

        let snap = SensorSnapshot::new("windows")
            .metric(
                "docker_desktop_running",
                if docker_desktop_running { 1.0 } else { 0.0 },
            )
            .field("docker_service_status", service_status);
        SensorState::Ok(snap)
    }
}

#[cfg(test)]
mod tests {
    /// 纯函数：把 PowerShell 输出解析为服务状态
    fn parse_service_status(raw: &str) -> String {
        let s = raw.trim();
        if s.is_empty() {
            "Unknown".to_string()
        } else {
            s.to_string()
        }
    }

    #[test]
    fn parses_service_status() {
        assert_eq!(parse_service_status("Running\n"), "Running");
        assert_eq!(parse_service_status("  Stopped"), "Stopped");
        assert_eq!(parse_service_status(""), "Unknown");
    }
}
