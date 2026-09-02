//! 参数库 (daoti-core::learning::params)
//!
//! 对应《PRD-驭灵》"本地知识库：内置压缩「卦原型库」与轻量参数库（CPU 浮点运算）"。
//! 参数库以 JSON 落盘可加载/保存，供因果推演阈值与 Hebbian 学习速率使用。
//! 默认参数为确定性降级值（与 `decision::causal_adapter` 当下规则一致），
//! 权重缺失时无需外部文件即可独立运行（开发计划 R1 降级模式）。

use daoti_common::DaotiError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 推演/学习用轻量参数（CPU 浮点）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryParams {
    /// 判定"三气全通"的健康阈值（三个健康度均 ≥ 此值视为畅通）
    pub healthy_threshold: f64,
    /// 金（Windows）弱判定阈值
    pub metal_threshold: f64,
    /// 木（WSL2）弱判定阈值
    pub wood_threshold: f64,
    /// 水（Docker）弱判定阈值
    pub water_threshold: f64,
    /// Hebbian 学习速率（0~1，取小值以保证稳定）
    pub learning_rate: f64,
    /// 金 / 木 / 水 权重基值（Hebbian 在此微调，范围受 `MinWeight`/`MaxWeight` 约束）
    pub metal_weight: f64,
    pub wood_weight: f64,
    pub water_weight: f64,
}

impl Default for LibraryParams {
    fn default() -> Self {
        LibraryParams {
            healthy_threshold: 0.9,
            metal_threshold: 0.5,
            wood_threshold: 0.5,
            water_threshold: 0.5,
            learning_rate: 0.05,
            metal_weight: 1.0,
            wood_weight: 1.0,
            water_weight: 1.0,
        }
    }
}

/// 参数库：加载/保存轻量参数，提供推演阈值与学习速率的单一来源
#[derive(Debug, Clone)]
pub struct ParameterLibrary {
    params: LibraryParams,
}

impl ParameterLibrary {
    /// 使用确定性默认参数构建（无需外部文件）
    pub fn defaults() -> Self {
        ParameterLibrary {
            params: LibraryParams::default(),
        }
    }

    /// 从 JSON 文件加载参数库；文件不存在/损坏时回退默认并返回缺省值（降级模式）
    pub fn load(path: impl AsRef<Path>) -> Result<Self, DaotiError> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(ParameterLibrary::defaults());
        }
        let raw = std::fs::read_to_string(p)?;
        let params: LibraryParams = serde_json::from_str(&raw)?;
        Ok(ParameterLibrary { params })
    }

    /// 保存参数库到 JSON 文件（自动创建父目录）
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DaotiError> {
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(&self.params)?;
        std::fs::write(p, raw)?;
        Ok(())
    }

    /// 只读访问参数
    pub fn params(&self) -> &LibraryParams {
        &self.params
    }

    /// 可变访问参数（供 Hebbian 学习更新后落盘）
    pub fn params_mut(&mut self) -> &mut LibraryParams {
        &mut self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_deterministic() {
        let lib = ParameterLibrary::defaults();
        let p = lib.params();
        assert_eq!(p.healthy_threshold, 0.9);
        assert_eq!(p.learning_rate, 0.05);
        assert_eq!(p.metal_weight, 1.0);
    }

    #[test]
    fn load_missing_file_falls_back_to_defaults() {
        let lib =
            ParameterLibrary::load("__no_such_file__.json").expect("缺失文件应回退默认而非报错");
        assert_eq!(lib.params().healthy_threshold, 0.9);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = std::env::temp_dir().join(format!("daoti_params_{}", std::process::id()));
        let path = dir.join("params.json");
        let mut lib = ParameterLibrary::defaults();
        lib.params_mut().learning_rate = 0.1;
        lib.save(&path).expect("保存失败");

        let loaded = ParameterLibrary::load(&path).expect("加载失败");
        assert_eq!(loaded.params().learning_rate, 0.1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
