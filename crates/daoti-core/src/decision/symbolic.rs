//! 道体符号输出协议与三平台调度适配。

use super::{scheduler, Decision, InferenceEngine, RuleEngine};
use crate::sensor::WuxingHealth;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaotiSymbolicOutput {
    pub schema_version: u32,
    pub model_version: String,
    pub gua_name: String,
    pub gua_index: u8,
    pub best_bagua: String,
    pub wuxing_scores: [f64; 5],
    pub alpha: f64,
    pub coherence: f64,
    pub target_gua: Option<String>,
    pub pathway: String,
    pub confidence: f64,
    pub explanation: String,
    pub source: String,
}

impl DaotiSymbolicOutput {
    /// 将三平台健康度编码为道体符号输出，保持 Python 五行顺序：木、火、土、金、水。
    pub fn from_health(health: &WuxingHealth) -> Self {
        let scores = [
            health.wood,
            0.0,
            1.0 - health.metal,
            health.metal,
            health.water,
        ];
        let (gua_name, best_bagua) = if health.water <= health.wood && health.water <= health.metal
        {
            ("坎", "坎")
        } else if health.wood <= health.metal {
            ("震", "震")
        } else {
            ("乾", "乾")
        };
        let coherence = ((health.metal + health.wood + health.water) / 3.0).clamp(0.0, 1.0);
        Self {
            schema_version: 1,
            model_version: "rust-symbolic-v1".into(),
            gua_name: gua_name.into(),
            gua_index: 0,
            best_bagua: best_bagua.into(),
            wuxing_scores: scores,
            alpha: health.metal.clamp(0.0, 1.0),
            coherence,
            target_gua: Some(gua_name.into()),
            pathway: if coherence < 0.5 {
                "explore"
            } else {
                "stabilize"
            }
            .into(),
            confidence: coherence,
            explanation: "由三平台健康度生成符号状态".into(),
            source: "rust-symbolic".into(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!("不支持的道体符号协议版本：{}", self.schema_version));
        }
        if self.gua_name.trim().is_empty() || self.best_bagua.trim().is_empty() {
            return Err("卦象字段不能为空".into());
        }
        if !self
            .wuxing_scores
            .iter()
            .all(|value| value.is_finite() && *value >= 0.0)
        {
            return Err("五行分布必须是有限非负数".into());
        }
        let total: f64 = self.wuxing_scores.iter().sum();
        if total <= f64::EPSILON {
            return Err("五行分布总和必须大于零".into());
        }
        if !self.alpha.is_finite() || !(0.0..=1.0).contains(&self.alpha) {
            return Err("alpha 必须位于 0 到 1".into());
        }
        if !self.coherence.is_finite() || !(0.0..=1.0).contains(&self.coherence) {
            return Err("coherence 必须位于 0 到 1".into());
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err("confidence 必须位于 0 到 1".into());
        }
        Ok(())
    }

    pub fn health(&self) -> Result<WuxingHealth, String> {
        self.validate()?;
        let total: f64 = self.wuxing_scores.iter().sum();
        Ok(WuxingHealth {
            metal: self.wuxing_scores[3] / total,
            wood: self.wuxing_scores[0] / total,
            water: self.wuxing_scores[4] / total,
        })
    }

    pub fn to_decision(&self) -> Result<Decision, String> {
        let health = self.health()?;
        let mut engine = RuleEngine::new();
        let mut decision = engine.interpret(&health);
        let signals = scheduler::SchedulerSignals {
            coherence: self.coherence,
            deviation: (1.0 - health.metal.min(health.wood).min(health.water)).clamp(0.0, 1.0),
            curiosity: (1.0 - self.coherence).clamp(0.0, 1.0),
            alpha: self.alpha,
            wuxing_max: self.wuxing_scores.iter().copied().fold(0.0_f64, f64::max),
        };
        let schedule = scheduler::schedule(signals);
        decision.pathway = schedule.pathway.to_string();
        decision.confidence = self.confidence;
        decision.scheduler = scheduler::SchedulerParams::from(&schedule);
        decision.explanation = format!(
            "道体符号模型[{}]：{}；步长 {:.3}，阻尼 {:.3}",
            self.model_version, self.explanation, schedule.step_size, schedule.damping
        );
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output() -> DaotiSymbolicOutput {
        DaotiSymbolicOutput {
            schema_version: 1,
            model_version: "trigram-v23".into(),
            gua_name: "坎".into(),
            gua_index: 28,
            best_bagua: "坎".into(),
            wuxing_scores: [0.1, 0.2, 0.1, 0.1, 0.5],
            alpha: 0.6,
            coherence: 0.8,
            target_gua: Some("坎".into()),
            pathway: "stabilize".into(),
            confidence: 0.9,
            explanation: "水势主导".into(),
            source: "python-daoti".into(),
        }
    }

    #[test]
    fn 三平台健康度可以生成合法符号输出() {
        let value = DaotiSymbolicOutput::from_health(&WuxingHealth {
            metal: 0.9,
            wood: 0.7,
            water: 0.2,
        });
        assert_eq!(value.best_bagua, "坎");
        assert!(value.validate().is_ok());
    }

    #[test]
    fn 合法符号输出可以转换健康度和决策() {
        let result = output().to_decision().unwrap();
        assert!(!result.priority.is_empty());
        assert_eq!(result.confidence, 0.9);
    }

    #[test]
    fn 符号调度路径会写入最终决策() {
        let mut value = output();
        value.coherence = 0.2;
        value.confidence = 0.2;
        value.wuxing_scores = [0.1, 0.1, 0.1, 0.1, 0.6];
        assert_eq!(value.to_decision().unwrap().pathway, "explore");

        value.coherence = 0.8;
        value.wuxing_scores = [0.1, 0.1, 0.1, 0.6, 0.1];
        let decision = value.to_decision().unwrap();
        assert_eq!(decision.pathway, "retrieve");
        assert!(decision.explanation.contains("步长"));
        assert!(decision.explanation.contains("阻尼"));
        assert!(decision.explanation.contains("trigram-v23"));
    }

    #[test]
    fn 拒绝错误协议版本() {
        let mut value = output();
        value.schema_version = 2;
        assert!(value.validate().is_err());
    }

    #[test]
    fn 拒绝非法置信度() {
        let mut value = output();
        value.confidence = 2.0;
        assert!(value.validate().is_err());
    }
}
