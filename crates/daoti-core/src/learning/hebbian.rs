//! Hebbian 学习预留接口 (daoti-core::learning::hebbian)
//!
//! 对应《开发计划-TechnicalPlan.md》步骤 9：Hebbian 学习预留接口。
//! 本模块提供 `HebbianLearner` trait 契约与一个确定性的 `HebbianRule` 默认实现，
//! 依据决策轨迹结果（fixed 成败）微调参数库权重（有界、稳定），
//! 默认确定性实现，供后续接入更复杂学习策略时替换/扩展。默认关闭（`learning` feature 门控），不影响主链路。

use super::params::LibraryParams;
use super::trajectory::TrajectoryRecord;

/// Hebbian 权重的有界范围（防止单一轨迹将权重推到极端）
pub const MIN_WEIGHT: f64 = 0.5;
pub const MAX_WEIGHT: f64 = 1.5;

/// Hebbian 学习契约（预留接口）：依据一条决策轨迹更新参数库。
pub trait HebbianLearner {
    /// 依据轨迹结果调整参数库（成功后强化对应 pathway 权重，失败则弱化）
    fn update(&mut self, record: &TrajectoryRecord, params: &mut LibraryParams);
}

/// 确定性 Hebbian 规则（默认实现，可替换）
pub struct HebbianRule;

impl HebbianRule {
    /// 依据决策成败计算权重增量（有界）
    fn delta(&self, record: &TrajectoryRecord, lr: f64) -> f64 {
        // 仅对"实际执行了干预"的轨迹学习；no_action 不扰动权重
        if record.pathway == "no_action" {
            return 0.0;
        }
        let base = if record.fixed { lr } else { -lr };
        // 置信度调制：越有把握的成败，调整越明确
        base * record.confidence.clamp(0.0, 1.0)
    }
}

impl HebbianLearner for HebbianRule {
    fn update(&mut self, record: &TrajectoryRecord, params: &mut LibraryParams) {
        let lr = params.learning_rate.clamp(0.0, 0.2);
        let delta = self.delta(record, lr);
        let target = match record.priority.as_str() {
            "docker_first" => &mut params.water_weight,
            "wsl2_first" => &mut params.wood_weight,
            "windows_first" => &mut params.metal_weight,
            _ => return,
        };
        *target = (*target + delta).clamp(MIN_WEIGHT, MAX_WEIGHT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::trajectory::TrajectoryRecord;

    fn record(priority: &str, pathway: &str, confidence: f64, fixed: bool) -> TrajectoryRecord {
        TrajectoryRecord {
            ts_ms: 0,
            gua: "坎".into(),
            priority: priority.into(),
            pathway: pathway.into(),
            confidence,
            explanation: "".into(),
            commands: vec![],
            outcomes: vec![],
            fixed,
        }
    }

    #[test]
    fn success_strengthens_water_weight() {
        let mut params = LibraryParams::default();
        let mut ler = HebbianRule;
        ler.update(
            &record("docker_first", "restart_daemon", 1.0, true),
            &mut params,
        );
        assert!(params.water_weight > 1.0);
    }

    #[test]
    fn failure_weakens_wood_weight() {
        let mut params = LibraryParams::default();
        let mut ler = HebbianRule;
        ler.update(&record("wsl2_first", "reset_wsl", 1.0, false), &mut params);
        assert!(params.wood_weight < 1.0);
    }

    #[test]
    fn no_action_does_not_perturb() {
        let mut params = LibraryParams::default();
        let mut ler = HebbianRule;
        ler.update(&record("none", "no_action", 1.0, true), &mut params);
        assert_eq!(params.metal_weight, 1.0);
        assert_eq!(params.wood_weight, 1.0);
        assert_eq!(params.water_weight, 1.0);
    }

    #[test]
    fn weight_stays_bounded() {
        let mut params = LibraryParams::default();
        let mut ler = HebbianRule;
        for _ in 0..100 {
            ler.update(
                &record("docker_first", "restart_daemon", 1.0, true),
                &mut params,
            );
        }
        assert!(params.water_weight <= MAX_WEIGHT);
    }
}
