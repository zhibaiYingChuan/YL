//! 状态融合编码器 (daoti-core::sensor::fusion)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.1.4。将三感知器异构数据统一编码为
//! 状态向量，供推演层使用。此处实现确定性降级映射（规则引擎的唯一输入），
//! 与符号/几何推演（双梯形镜像递归架构）对齐。

use serde::{Deserialize, Serialize};

use super::{SensorSnapshot, SensorState};

/// 三系统融合状态
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FusionState {
    /// windows / wsl2 / docker 各自的状态
    pub windows: Option<SensorSnapshot>,
    pub wsl2: Option<SensorSnapshot>,
    pub docker: Option<SensorSnapshot>,
}

/// 五行健康度分数（0~1，越高越健康），供推演层使用
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WuxingHealth {
    /// 金：Windows 宿主机健康度
    pub metal: f64,
    /// 木：WSL2 内核健康度
    pub wood: f64,
    /// 水：Docker 流动健康度
    pub water: f64,
}

impl WuxingHealth {
    /// 依据五行健康度给出判词（CLI / daemon 共用，单一文案来源）。
    ///
    /// - 三气全通（均 ≥0.9）→ 安
    /// - 任一受滞（<0.5）→ 病
    /// - 其余 → 将变未变
    pub fn verdict(&self) -> &'static str {
        if self.metal >= 0.9 && self.wood >= 0.9 && self.water >= 0.9 {
            "金坚、木盛、水流，三气通畅。"
        } else if self.metal < 0.5 || self.wood < 0.5 || self.water < 0.5 {
            "三气有滞，此快照为病，可后续对比回魂。"
        } else {
            "三气微滞，此快照为将变未变之态。"
        }
    }
}

impl FusionState {
    /// 从三感知结果构建
    pub fn from_sensors(windows: &SensorState, wsl2: &SensorState, docker: &SensorState) -> Self {
        FusionState {
            windows: windows.as_ok(),
            wsl2: wsl2.as_ok(),
            docker: docker.as_ok(),
        }
    }

    /// 计算五行健康度（确定性规则，供降级推演使用）
    pub fn wuxing_health(&self) -> WuxingHealth {
        let metal = self.windows.as_ref().map_or(0.0, |s| {
            let d = s.metric_of("docker_desktop_running");
            if d > 0.0 {
                1.0
            } else if s.field_of("docker_service_status") == "Running" {
                0.8
            } else {
                0.2
            }
        });
        let wood = self.wsl2.as_ref().map_or(0.0, |s| s.metric_of("running"));
        // 水：Docker 可达性
        let water = self.docker.as_ref().map_or(0.0, |s| {
            if s.field_of("daemon_version").is_empty() {
                0.0
            } else {
                1.0
            }
        });
        WuxingHealth { metal, wood, water }
    }
}

impl SensorState {
    /// 若为 Ok，返回内部快照引用
    fn as_ok(&self) -> Option<SensorSnapshot> {
        match self {
            SensorState::Ok(s) => Some(s.clone()),
            SensorState::Unavailable => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(target: &str) -> SensorSnapshot {
        SensorSnapshot::new(target)
    }

    #[test]
    fn all_unavailable_is_zero_health() {
        let f = FusionState::from_sensors(
            &SensorState::Unavailable,
            &SensorState::Unavailable,
            &SensorState::Unavailable,
        );
        let h = f.wuxing_health();
        assert_eq!(h.metal, 0.0);
        assert_eq!(h.wood, 0.0);
        assert_eq!(h.water, 0.0);
    }

    #[test]
    fn symbolic_snapshots_are_full_health() {
        let w = snap("windows")
            .field("mode", "symbolic_only")
            .metric("health", 1.0)
            .metric("docker_desktop_running", 1.0);
        let wsl = snap("wsl2")
            .field("mode", "symbolic_only")
            .metric("health", 1.0)
            .metric("running", 1.0);
        let d = snap("docker")
            .field("mode", "symbolic_only")
            .field("daemon_version", "symbolic")
            .metric("health", 1.0);
        let f = FusionState {
            windows: Some(w),
            wsl2: Some(wsl),
            docker: Some(d),
        };
        let h = f.wuxing_health();
        assert_eq!(h.metal, 1.0);
        assert_eq!(h.wood, 1.0);
        assert_eq!(h.water, 1.0);
    }

    #[test]
    fn healthy_all_is_full() {
        let w = snap("windows").metric("docker_desktop_running", 1.0);
        let wsl = snap("wsl2").metric("running", 1.0);
        let d = snap("docker").field("daemon_version", "27.2.0");
        let f = FusionState::from_sensors(
            &SensorState::Ok(w),
            &SensorState::Ok(wsl),
            &SensorState::Ok(d),
        );
        let h = f.wuxing_health();
        assert_eq!(h.metal, 1.0);
        assert_eq!(h.wood, 1.0);
        assert_eq!(h.water, 1.0);
    }

    #[test]
    fn verdict_phases_cover_healthy_sick_and_transition() {
        let healthy = WuxingHealth {
            metal: 1.0,
            wood: 0.95,
            water: 0.92,
        };
        assert!(healthy.verdict().contains("三气通"));

        let sick = WuxingHealth {
            metal: 0.9,
            wood: 0.2,
            water: 0.9,
        };
        assert!(sick.verdict().contains("为病"));

        let transition = WuxingHealth {
            metal: 0.9,
            wood: 0.7,
            water: 0.9,
        };
        assert!(transition.verdict().contains("将变未变"));
    }
}
