//! 推演引擎抽象 (daoti-core::decision::engine)
//!
//! 统一推演入口，兑现"推演→决策"的可插拔链路：
//! - `InferenceEngine`：推演契约，`status()` 描述引擎状态，`interpret()` 输出调度决策。
//! - `RuleEngine`：确定性实现（包装 `CrossPlatformCausalAdapter`），**始终可用**，不依赖权重。
//!
//! daemon 通过该 trait 持有推演引擎，实现"感知→推演"链路可插拔。

use crate::sensor::WuxingHealth;

use super::{CrossPlatformCausalAdapter, Decision};

/// 推演引擎契约（`Send + Sync`，可被 daemon 协调者单任务持有）
///
/// `interpret` 取 `&mut self`：为未来接入可演化推演（如道体符号推演）保留可变位，
/// 统一为可变借用以兼容各方实现。
pub trait InferenceEngine: Send + Sync {
    /// 引擎状态描述（用于事件/日志，如"规则引擎"）
    fn status(&self) -> &str;

    /// 推演：五行健康度 → 调度决策
    fn interpret(&mut self, health: &WuxingHealth) -> Decision;
}

/// 规则引擎：确定性推演实现，始终可用（当前为主推演引擎）
pub struct RuleEngine {
    adapter: CrossPlatformCausalAdapter,
}

impl RuleEngine {
    /// 构建规则引擎
    pub fn new() -> Self {
        RuleEngine {
            adapter: CrossPlatformCausalAdapter::new(),
        }
    }

    /// 注入五行权重（金/木/水），供 Hebbian 慢调节影响决策。
    /// 默认（未注入）权重为 1.0，行为与确定性规则引擎一致（不回归）。
    pub fn with_weights(metal: f64, wood: f64, water: f64) -> Self {
        RuleEngine {
            adapter: CrossPlatformCausalAdapter::new().with_weights(metal, wood, water),
        }
    }

    /// 运行时更新五行权重（供 Hebbian 慢调节在每次决策前注入最新权重）。
    pub fn set_weights(&mut self, metal: f64, wood: f64, water: f64) {
        self.adapter.set_weights(metal, wood, water);
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl InferenceEngine for RuleEngine {
    fn status(&self) -> &str {
        "规则引擎"
    }

    fn interpret(&mut self, health: &WuxingHealth) -> Decision {
        self.adapter.interpret(health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_engine_status_and_interpret() {
        let mut e = RuleEngine::new();
        assert_eq!(e.status(), "规则引擎");

        // 全畅通 → 无行动
        let d = e.interpret(&WuxingHealth {
            metal: 1.0,
            wood: 1.0,
            water: 1.0,
        });
        assert_eq!(d.pathway, "no_action");

        // 水弱 → docker_first（与 CrossPlatformCausalAdapter 行为一致）
        let d = e.interpret(&WuxingHealth {
            metal: 1.0,
            wood: 1.0,
            water: 0.0,
        });
        assert_eq!(d.priority, "docker_first");
    }

    #[test]
    fn rule_engine_with_weights_modulates_decision() {
        // 木与水同样弱（0.5），木权重放大（1.5）→ 优先培木（wsl2_first）
        let mut e = RuleEngine::with_weights(1.0, 1.5, 1.0);
        let d = e.interpret(&WuxingHealth {
            metal: 0.6,
            wood: 0.5,
            water: 0.5,
        });
        assert_eq!(d.priority, "wsl2_first");
    }
}
