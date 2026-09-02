//! 面向三平台调度的规则教师模型。

use super::{Decision, InferenceEngine, RuleEngine};
use crate::sensor::WuxingHealth;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeacherSample {
    pub health: WuxingHealth,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchModel {
    pub version: u32,
    pub classes: Vec<String>,
    pub centroids: Vec<[f64; 3]>,
    pub prototypes: Vec<[f64; 3]>,
    pub prototype_decisions: Vec<Decision>,
    pub decisions: Vec<Decision>,
    pub min_confidence: f64,
}

impl DispatchModel {
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let bytes =
            serde_json::to_vec_pretty(self).map_err(|error| format!("模型序列化失败：{error}"))?;
        std::fs::write(path, bytes).map_err(|error| format!("模型写入失败：{error}"))
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|error| format!("模型读取失败：{error}"))?;
        serde_json::from_slice(&bytes).map_err(|error| format!("模型解析失败：{error}"))
    }

    pub fn train(samples: &[TeacherSample], min_confidence: f64) -> Result<Self, String> {
        if samples.is_empty() {
            return Err("教师样本不能为空".into());
        }
        let mut classes = Vec::new();
        let mut sums = Vec::<[f64; 3]>::new();
        let mut counts = Vec::<f64>::new();
        let mut decisions = Vec::<Decision>::new();
        let mut prototypes = Vec::<[f64; 3]>::new();
        let mut prototype_decisions = Vec::<Decision>::new();
        for sample in samples {
            prototypes.push([sample.health.metal, sample.health.wood, sample.health.water]);
            prototype_decisions.push(sample.decision.clone());
            let key = sample.decision.priority.clone();
            let index = match classes.iter().position(|v| v == &key) {
                Some(index) => index,
                None => {
                    classes.push(key);
                    sums.push([0.0; 3]);
                    counts.push(0.0);
                    decisions.push(sample.decision.clone());
                    classes.len() - 1
                }
            };
            let values = [sample.health.metal, sample.health.wood, sample.health.water];
            for (sum, value) in sums[index].iter_mut().zip(values) {
                *sum += value;
            }
            counts[index] += 1.0;
        }
        let centroids = sums
            .into_iter()
            .zip(counts)
            .map(|(sum, count)| [sum[0] / count, sum[1] / count, sum[2] / count])
            .collect();
        Ok(Self {
            version: 1,
            classes,
            centroids,
            prototypes,
            prototype_decisions,
            decisions,
            min_confidence,
        })
    }

    pub fn predict(&self, health: &WuxingHealth) -> Option<Decision> {
        let values = [health.metal, health.wood, health.water];
        let (index, distance) = self
            .prototypes
            .iter()
            .enumerate()
            .map(|(index, centroid)| {
                let distance = centroid
                    .iter()
                    .zip(values)
                    .map(|(a, b)| (a - b).powi(2))
                    .sum::<f64>();
                (index, distance)
            })
            .min_by(|a, b| a.1.total_cmp(&b.1))?;
        let confidence = 1.0 / (1.0 + distance.sqrt());
        if confidence < self.min_confidence {
            return None;
        }
        let mut decision = self.prototype_decisions.get(index)?.clone();
        decision.confidence = confidence;
        decision.explanation = format!("道体教师模型推理：{}", decision.explanation);
        Some(decision)
    }
}

impl InferenceEngine for DispatchModel {
    fn status(&self) -> &str {
        "道体调度模型"
    }

    fn interpret(&mut self, health: &WuxingHealth) -> Decision {
        let mut teacher = RuleEngine::new();
        self.predict(health)
            .unwrap_or_else(|| teacher.interpret(health))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(health: WuxingHealth) -> TeacherSample {
        let mut rule = RuleEngine::new();
        let decision = rule.interpret(&health);
        TeacherSample { health, decision }
    }

    #[test]
    fn 训练模型复现规则教师标签() {
        let samples = vec![
            sample(WuxingHealth {
                metal: 1.0,
                wood: 1.0,
                water: 1.0,
            }),
            sample(WuxingHealth {
                metal: 1.0,
                wood: 1.0,
                water: 0.0,
            }),
            sample(WuxingHealth {
                metal: 1.0,
                wood: 0.0,
                water: 1.0,
            }),
        ];
        let model = DispatchModel::train(&samples, 0.5).unwrap();
        let health = WuxingHealth {
            metal: 1.0,
            wood: 1.0,
            water: 0.0,
        };
        let decision = model.predict(&health).unwrap();
        assert_eq!(decision.priority, "docker_first");
    }

    #[test]
    fn 模型保存加载后保持推理结果() {
        let samples = vec![sample(WuxingHealth {
            metal: 1.0,
            wood: 1.0,
            water: 0.0,
        })];
        let model = DispatchModel::train(&samples, 0.5).unwrap();
        let path = std::env::temp_dir().join("daoti-dispatch-model-roundtrip.json");
        model.save(&path).unwrap();
        let loaded = DispatchModel::load(&path).unwrap();
        let decision = loaded
            .predict(&WuxingHealth {
                metal: 1.0,
                wood: 1.0,
                water: 0.0,
            })
            .unwrap();
        assert_eq!(decision.priority, "docker_first");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn 五档健康度网格复现教师优先级() {
        let levels = [0.0, 0.25, 0.5, 0.75, 1.0];
        let mut samples = Vec::new();
        for metal in levels {
            for wood in levels {
                for water in levels {
                    samples.push(sample(WuxingHealth { metal, wood, water }));
                }
            }
        }
        let model = DispatchModel::train(&samples, 0.0).unwrap();
        for sample in samples {
            assert_eq!(
                model.predict(&sample.health).unwrap().priority,
                sample.decision.priority
            );
        }
    }

    #[test]
    fn 低置信度时回退教师引擎() {
        let model = DispatchModel {
            version: 1,
            classes: vec!["docker_first".into()],
            centroids: vec![[0.0, 0.0, 0.0]],
            prototypes: vec![[0.0, 0.0, 0.0]],
            prototype_decisions: vec![sample(WuxingHealth {
                metal: 1.0,
                wood: 1.0,
                water: 0.0,
            })
            .decision
            .clone()],
            decisions: vec![
                sample(WuxingHealth {
                    metal: 1.0,
                    wood: 1.0,
                    water: 0.0,
                })
                .decision,
            ],
            min_confidence: 1.1,
        };
        let mut model = model;
        let decision = model.interpret(&WuxingHealth {
            metal: 1.0,
            wood: 1.0,
            water: 0.0,
        });
        assert_eq!(decision.priority, "docker_first");
        assert!(!decision.explanation.starts_with("道体教师模型"));
    }
}
