//! 慢调节学习器 (daoti-core::learning::slow)
//!
//! P3-2：将 Hebbian/参数库从"轨迹持久化"推进到"可观测的慢调节"。
//! `SlowLearner` 封装「批量轨迹 → Hebbian 有界微调 → 可观测学习报告」的闭环，
//! 权重增量与最终权重经 `LearnReport` 对外可观测（供 daemon / CLI 查询学习状态）。
//!
//! 本模块以 `learning` feature 门控（默认关闭），不影响主链路（M6 验收口径）。

use serde::Serialize;

use super::hebbian::{HebbianLearner, HebbianRule};
use super::params::{LibraryParams, ParameterLibrary};
use super::trajectory::TrajectoryRecord;

/// 一次慢调节学习的结果报告（可观测：样本数 + 各权重增量 + 最终权重）
#[derive(Debug, Clone, Serialize)]
pub struct LearnReport {
    /// 处理的轨迹样本数
    pub samples: usize,
    /// 金（Windows）权重增量
    pub metal_delta: f64,
    /// 木（WSL2）权重增量
    pub wood_delta: f64,
    /// 水（Docker）权重增量
    pub water_delta: f64,
    /// 更新后的参数（含最终权重，可观测）
    pub params: LibraryParams,
}

/// 慢调节学习器：批量消费决策轨迹，用 Hebbian 规则有界微调参数库权重。
pub struct SlowLearner {
    rule: HebbianRule,
    library: ParameterLibrary,
}

impl SlowLearner {
    /// 用默认参数库构建（无需外部文件）
    pub fn with_defaults() -> Self {
        SlowLearner {
            rule: HebbianRule,
            library: ParameterLibrary::defaults(),
        }
    }

    /// 用给定参数库构建（可从磁盘加载后接入）
    pub fn new(library: ParameterLibrary) -> Self {
        SlowLearner {
            rule: HebbianRule,
            library,
        }
    }

    /// 批量学习：逐条用 Hebbian 规则更新权重，返回可观测的学习报告。
    ///
    /// 学习速率与权重上下界由参数库（`learning_rate` / `MIN_WEIGHT` / `MAX_WEIGHT`）约束，
    /// 故为"慢调节"——单条轨迹仅小幅移动权重，且不越界。
    pub fn learn(&mut self, records: &[TrajectoryRecord]) -> LearnReport {
        let before = self.library.params().clone();
        for record in records {
            self.rule.update(record, self.library.params_mut());
        }
        let after = self.library.params().clone();
        LearnReport {
            samples: records.len(),
            metal_delta: after.metal_weight - before.metal_weight,
            wood_delta: after.wood_weight - before.wood_weight,
            water_delta: after.water_weight - before.water_weight,
            params: after,
        }
    }

    /// 只读访问参数库（可观测当前权重）
    pub fn library(&self) -> &ParameterLibrary {
        &self.library
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::MAX_WEIGHT;

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

    /// 成功轨迹强化水权重（docker_first → water_weight 上升）。
    #[test]
    fn learn_success_strengthens_water() {
        let mut learner = SlowLearner::with_defaults();
        let report = learner.learn(&[
            record("docker_first", "restart_daemon", 1.0, true),
            record("docker_first", "restart_daemon", 1.0, true),
        ]);
        assert_eq!(report.samples, 2);
        assert!(report.water_delta > 0.0);
        assert!(report.params.water_weight > 1.0);
    }

    /// 失败轨迹弱化木权重（wsl2_first → wood_weight 下降）。
    #[test]
    fn learn_failure_weakens_wood() {
        let mut learner = SlowLearner::with_defaults();
        let report = learner.learn(&[record("wsl2_first", "reset_wsl", 1.0, false)]);
        assert!(report.wood_delta < 0.0);
        assert!(report.params.wood_weight < 1.0);
    }

    /// 批量累积仍受上界约束（慢调节不越界）。
    #[test]
    fn learn_accumulates_bounded() {
        let mut learner = SlowLearner::with_defaults();
        for _ in 0..100 {
            learner.learn(&[record("docker_first", "restart_daemon", 1.0, true)]);
        }
        assert!(learner.library().params().water_weight <= MAX_WEIGHT);
    }

    /// P3-2c 闭环：轨迹 → 慢调节学习 → 权重 → 决策方向改变（可观测的慢调节影响决策）。
    #[test]
    fn learning_steers_decision_direction() {
        use crate::decision::CrossPlatformCausalAdapter;
        use crate::sensor::WuxingHealth;

        let health = WuxingHealth {
            metal: 0.6,
            wood: 0.5,
            water: 0.5,
        };

        // 初始：默认权重下，木与水同样弱（0.5）→ 水优先（docker_first）
        let default_decision = CrossPlatformCausalAdapter::new().interpret(&health);
        assert_eq!(default_decision.priority, "docker_first");

        // 慢调节：反复学习"wsl2 成功"轨迹，木权重逐步上升（超过 1.0）
        let mut learner = SlowLearner::with_defaults();
        for _ in 0..20 {
            learner.learn(&[record("wsl2_first", "reset_wsl", 1.0, true)]);
        }
        let p = learner.library().params();
        assert!(p.wood_weight > 1.0);

        // 注入学习后的权重 → 决策从 docker_first 翻转为 wsl2_first
        let weighted = CrossPlatformCausalAdapter::new().with_weights(
            p.metal_weight,
            p.wood_weight,
            p.water_weight,
        );
        assert_eq!(weighted.interpret(&health).priority, "wsl2_first");
    }
}
