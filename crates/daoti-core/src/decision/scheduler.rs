//! 道体五行生克调度的无副作用实现。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SchedulerSignals {
    pub coherence: f64,
    pub deviation: f64,
    pub curiosity: f64,
    pub alpha: f64,
    pub wuxing_max: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SchedulerDecision {
    pub step_size: f64,
    pub max_steps: u32,
    pub convergence_stable: u32,
    pub uncertainty_entropy_thresh: f64,
    pub uncertainty_margin_thresh: f64,
    pub retrieval_blend: f64,
    pub damping: f64,
    pub over_strong_base_thresh: f64,
    pub alpha_thresh_yang: f64,
    pub alpha_thresh_yin: f64,
    pub pathway: &'static str,
}

/// 随决策结构化暴露的调度参数精简快照，便于外部直接查询，不丢失调度可观测性。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchedulerParams {
    pub step_size: f64,
    pub max_steps: u32,
    pub damping: f64,
    pub retrieval_blend: f64,
    pub pathway: String,
}

impl Default for SchedulerParams {
    fn default() -> Self {
        Self {
            step_size: 0.0,
            max_steps: 0,
            damping: 0.0,
            retrieval_blend: 0.0,
            pathway: String::new(),
        }
    }
}

impl SchedulerParams {
    /// 是否仍为未填充的默认值，用于 JSON 序列化时省略空调度。
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

impl From<&SchedulerDecision> for SchedulerParams {
    fn from(s: &SchedulerDecision) -> Self {
        Self {
            step_size: s.step_size,
            max_steps: s.max_steps,
            damping: s.damping,
            retrieval_blend: s.retrieval_blend,
            pathway: s.pathway.to_string(),
        }
    }
}

pub fn sheng(element: usize) -> usize {
    [2, 3, 0, 4, 1][element % 5]
}

pub fn ke(element: usize) -> usize {
    [1, 4, 3, 0, 2][element % 5]
}

pub fn sheng_ke_weight(dominant: usize, module: usize) -> f64 {
    let mut weight: f64 = 1.0;
    if sheng(dominant) == module || sheng(module) == dominant {
        weight += 0.3;
    }
    if ke(module) == dominant {
        weight -= 0.5;
    }
    if ke(dominant) == module {
        weight -= 0.2;
    }
    weight.max(0.0)
}

pub fn pathway(signals: SchedulerSignals) -> &'static str {
    if signals.coherence < 0.35 && signals.curiosity > 0.6 {
        "explore"
    } else if signals.deviation > 0.6 && signals.coherence > 0.5 {
        "retrieve"
    } else {
        "stabilize"
    }
}

pub fn schedule(signals: SchedulerSignals) -> SchedulerDecision {
    let c = signals.coherence.clamp(0.0, 1.0);
    let d = signals.deviation.clamp(0.0, 1.0);
    let curiosity = signals.curiosity.clamp(0.0, 1.0);
    let base_step = if c < 0.3 {
        0.45
    } else if c < 0.5 {
        0.30
    } else if c < 0.7 {
        0.21
    } else {
        0.15
    };
    let step_size = (base_step * (1.0 + 0.2 * curiosity)).clamp(0.05, 0.60);
    let base_steps = if c < 0.3 {
        25
    } else if c < 0.5 {
        20
    } else if c < 0.7 {
        15
    } else {
        10
    };
    let max_steps = ((base_steps as f64) * (1.0 - 0.3 * curiosity))
        .round()
        .clamp(5.0, 30.0) as u32;
    let convergence_stable = if c < 0.3 {
        2
    } else if c < 0.5 {
        3
    } else if c < 0.7 {
        4
    } else {
        5
    };
    let entropy = if c < 0.3 {
        0.55
    } else if c < 0.5 {
        0.70
    } else if c < 0.7 {
        0.80
    } else {
        0.85
    };
    let margin = (0.05 * (1.0 + d)).min(0.15);
    let blend = (0.30 * (1.0 + d) * (1.0 + 0.3 * curiosity)).min(0.80);
    let damping = (0.15 + 0.20 * c).clamp(0.10, 0.50);
    let mut strong = 0.55 + (c - 0.5) * 0.16;
    if signals.wuxing_max > 0.4 {
        strong *= 0.9;
    }
    SchedulerDecision {
        step_size,
        max_steps,
        convergence_stable,
        uncertainty_entropy_thresh: entropy,
        uncertainty_margin_thresh: margin,
        retrieval_blend: blend,
        damping,
        over_strong_base_thresh: strong,
        alpha_thresh_yang: 0.55 - 0.10 * (1.0 - c),
        alpha_thresh_yin: 0.45 + 0.10 * (1.0 - c),
        pathway: pathway(SchedulerSignals {
            coherence: c,
            deviation: d,
            curiosity,
            ..signals
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 生克权重与_python_一致() {
        assert_eq!(sheng(0), 2);
        assert_eq!(ke(0), 1);
        assert!((sheng_ke_weight(0, 2) - 1.3).abs() < f64::EPSILON);
        assert!((sheng_ke_weight(0, 1) - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn 路径优先级与_python_一致() {
        assert_eq!(
            pathway(SchedulerSignals {
                coherence: 0.2,
                deviation: 0.1,
                curiosity: 0.8,
                alpha: 0.5,
                wuxing_max: 0.3
            }),
            "explore"
        );
        assert_eq!(
            pathway(SchedulerSignals {
                coherence: 0.8,
                deviation: 0.8,
                curiosity: 0.1,
                alpha: 0.5,
                wuxing_max: 0.3
            }),
            "retrieve"
        );
        assert_eq!(
            pathway(SchedulerSignals {
                coherence: 0.8,
                deviation: 0.2,
                curiosity: 0.1,
                alpha: 0.5,
                wuxing_max: 0.3
            }),
            "stabilize"
        );
    }

    #[test]
    fn 调度参数遵守边界() {
        let result = schedule(SchedulerSignals {
            coherence: 0.0,
            deviation: 1.0,
            curiosity: 1.0,
            alpha: 0.0,
            wuxing_max: 0.8,
        });
        assert!((0.05..=0.60).contains(&result.step_size));
        assert!((5..=30).contains(&result.max_steps));
        assert_eq!(result.pathway, "explore");
    }
}
