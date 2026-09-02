//! 跨平台因果推演适配器 (daoti-core::decision::causal_adapter)
//!
//! 对应《道体跨平台智能调度系统设计方案.md》§3.2.2。将五行健康度（金=Windows / 木=WSL2 / 水=Docker）
//! 推演为"最需疏通的势态"，并映射到调度策略。模型权重缺失时作为确定性降级规则引擎。

use crate::sensor::WuxingHealth;

use super::{command_gen::PlatformCommandGenerator, Decision};

/// 五行势态推演适配器（降级规则引擎）
pub struct CrossPlatformCausalAdapter {
    command_gen: PlatformCommandGenerator,
    /// 五行权重（金/木/水，默认 `[1.0; 3]`），Hebbian 慢调节注入；`None` = 确定性默认
    weights: Option<[f64; 3]>,
}

impl Default for CrossPlatformCausalAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossPlatformCausalAdapter {
    pub fn new() -> Self {
        CrossPlatformCausalAdapter {
            command_gen: PlatformCommandGenerator::new(),
            weights: None,
        }
    }

    /// 注入五行权重（金/木/水），供 Hebbian 慢调节影响"最弱气"判断。
    ///
    /// 权重越大 → 该平台加权健康度越低 → 越优先被判定为需疏通。
    /// 默认（未注入）权重为 `1.0`，行为与确定性规则引擎一致（不回归）。
    pub fn with_weights(mut self, metal: f64, wood: f64, water: f64) -> Self {
        self.weights = Some([metal, wood, water]);
        self
    }

    /// 运行时更新五行权重（供 Hebbian 慢调节在每次决策前注入最新权重）。
    pub fn set_weights(&mut self, metal: f64, wood: f64, water: f64) {
        self.weights = Some([metal, wood, water]);
    }

    /// 推演：根据五行健康度给出调度决策
    pub fn interpret(&self, health: &WuxingHealth) -> Decision {
        // 找到最衰弱的"气"（越低越需疏通）
        let metal = health.metal;
        let wood = health.wood;
        let water = health.water;

        // 全畅通
        if metal >= 0.9 && wood >= 0.9 && water >= 0.9 {
            return Decision {
                priority: "none".into(),
                pathway: "no_action".into(),
                gua: "泰".into(),
                confidence: 1.0,
                explanation: "三气通畅，天地交泰，无需干预。".into(),
                commands: vec![],
                scheduler: Default::default(),
            };
        }

        // 权重调制（Hebbian 慢调节）：默认 1.0 时加权健康度等于原始值，行为不回归。
        // 权重越大 → 加权健康度越低 → 该平台越易被判定为"最弱"而优先疏通。
        let [w_metal, w_wood, w_water] = self.weights.unwrap_or([1.0, 1.0, 1.0]);
        let eff_metal = metal / w_metal.max(1e-9);
        let eff_wood = wood / w_wood.max(1e-9);
        let eff_water = water / w_water.max(1e-9);

        // 选"加权最弱"的气作为主推演方向；平局时按 金→木→水 优先级
        let weakest = if eff_water <= eff_metal && eff_water <= eff_wood {
            "水"
        } else if eff_wood <= eff_metal {
            "木"
        } else {
            "金"
        };

        match weakest {
            "水" => self.water_blocked(water),
            "木" => self.wood_stagnant(wood),
            _ => self.metal_deficient(metal),
        }
    }

    /// 水滞不通（Docker daemon 断流）→ 通水
    fn water_blocked(&self, water: f64) -> Decision {
        let commands = self.command_gen.restart_docker_daemon();
        Decision {
            priority: "docker_first".into(),
            pathway: "restart_daemon".into(),
            gua: "坎".into(),
            confidence: 1.0 - water,
            explanation:
                "坎水滞涩（Docker 断流），需通水：重启 WSL 内 daemon 并复位 Windows 管道。".into(),
            commands,
            scheduler: Default::default(),
        }
    }

    /// 木气滞（WSL2 内核）→ 培木
    fn wood_stagnant(&self, wood: f64) -> Decision {
        let commands = self.command_gen.reset_wsl();
        Decision {
            priority: "wsl2_first".into(),
            pathway: "reset_wsl".into(),
            gua: "震".into(),
            confidence: 1.0 - wood,
            explanation: "震木滞涩（WSL 未运行/内核异常），需培木：复位 WSL 内核。".into(),
            commands,
            scheduler: Default::default(),
        }
    }

    /// 金气弱（Windows 宿主）→ 调金
    fn metal_deficient(&self, metal: f64) -> Decision {
        let commands = self.command_gen.check_windows_services();
        Decision {
            priority: "windows_first".into(),
            pathway: "check_windows_services".into(),
            gua: "乾".into(),
            confidence: 1.0 - metal,
            explanation: "乾金受制（Windows 宿主异常），需调金：核查宿主服务。".into(),
            commands,
            scheduler: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(metal: f64, wood: f64, water: f64) -> WuxingHealth {
        WuxingHealth { metal, wood, water }
    }

    #[test]
    fn all_healthy_no_action() {
        let a = CrossPlatformCausalAdapter::new();
        let d = a.interpret(&health(1.0, 1.0, 1.0));
        assert_eq!(d.pathway, "no_action");
        assert!(d.commands.is_empty());
    }

    #[test]
    fn water_weak_triggers_docker_first() {
        let a = CrossPlatformCausalAdapter::new();
        let d = a.interpret(&health(1.0, 1.0, 0.0));
        assert_eq!(d.priority, "docker_first");
        assert_eq!(d.gua, "坎");
        assert!(!d.commands.is_empty());
    }

    #[test]
    fn wood_weak_triggers_wsl_first() {
        let a = CrossPlatformCausalAdapter::new();
        let d = a.interpret(&health(1.0, 0.0, 1.0));
        assert_eq!(d.priority, "wsl2_first");
        assert_eq!(d.gua, "震");
    }

    #[test]
    fn metal_weak_triggers_windows_first() {
        let a = CrossPlatformCausalAdapter::new();
        let d = a.interpret(&health(0.0, 1.0, 1.0));
        assert_eq!(d.priority, "windows_first");
    }

    #[test]
    fn unit_weights_preserve_default_behavior() {
        let a = CrossPlatformCausalAdapter::new().with_weights(1.0, 1.0, 1.0);
        let d = a.interpret(&health(1.0, 1.0, 0.0));
        assert_eq!(d.priority, "docker_first");
    }

    #[test]
    fn weights_modulate_weakest_judgement() {
        // 木与水同样弱（0.5），默认水优先（docker_first）
        let default_adapter = CrossPlatformCausalAdapter::new();
        let d_default = default_adapter.interpret(&health(0.6, 0.5, 0.5));
        assert_eq!(d_default.priority, "docker_first");

        // 木权重放大（1.5）→ 木加权健康度更低 → 优先培木（wsl2_first）
        let weighted = CrossPlatformCausalAdapter::new().with_weights(1.0, 1.5, 1.0);
        let d_weighted = weighted.interpret(&health(0.6, 0.5, 0.5));
        assert_eq!(d_weighted.priority, "wsl2_first");
    }
}
