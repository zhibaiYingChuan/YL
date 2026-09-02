//! 遥测层 (daoti-core::interceptor::telemetry)
//!
//! 收集 syscall 事件样本，作为 B2 双梯形网络的训练数据基础。
//! 道体（DecisionPipeline）把「命中 / 未命中 / 用户反馈」三类样本送入采集器；
//! B2 阶段据此学习"复杂调用 → Windows 操作"的转换规则。
//!
//! 对应《模式B-B2双梯形网络增强开发计划.md》§3 B2-6 —— 样本四分类 + 覆盖率统计。

use serde::{Deserialize, Serialize};

use crate::interceptor::SyscallEvent;

/// 样本四分类（B2 离线训练标签）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleOutcome {
    /// 命中映射 / 推导成功（道体·达 / 道体·化）
    Success,
    /// 未命中降级（道体·退）
    Failure,
    /// 用户反馈：结果正确（道体·养）
    UserPositive,
    /// 用户反馈：结果错误（道体·养）
    UserNegative,
}

impl SampleOutcome {
    /// 人类可读标签
    pub fn label(&self) -> &'static str {
        match self {
            SampleOutcome::Success => "成功",
            SampleOutcome::Failure => "失败",
            SampleOutcome::UserPositive => "反馈·正",
            SampleOutcome::UserNegative => "反馈·负",
        }
    }
}

/// 一条样本记录：syscall + 稳定序号 + 降级去向 + 四分类标签
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissRecord {
    /// 单调递增序号（保证训练样本顺序稳定）
    pub seq: u64,
    /// 样本对应的 syscall 事件
    pub event: SyscallEvent,
    /// 降级去向（"wsl2" / "error"；成功/反馈样本为空串）
    pub fallback: String,
    /// 四分类标签
    pub outcome: SampleOutcome,
}

/// 遥测采集器：收集四分类样本（B2 训练数据基础）+ 覆盖率统计
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TelemetryCollector {
    records: Vec<MissRecord>,
    next_seq: u64,
}

impl TelemetryCollector {
    /// 构造空采集器
    pub fn new() -> Self {
        TelemetryCollector::default()
    }

    /// 记录一条未命中事件及其降级去向（分类 = 失败，兼容 B1 行为）
    pub fn record_miss(&mut self, event: SyscallEvent, fallback: impl Into<String>) {
        self.record(event, fallback, SampleOutcome::Failure);
    }

    /// 记录一条命中 / 推导成功样本（道体·达 / 道体·化）
    pub fn record_success(&mut self, event: SyscallEvent) {
        self.record(event, "", SampleOutcome::Success);
    }

    /// 记录一条用户反馈样本（正 / 负，道体·养）
    pub fn record_feedback(&mut self, event: SyscallEvent, positive: bool) {
        let outcome = if positive {
            SampleOutcome::UserPositive
        } else {
            SampleOutcome::UserNegative
        };
        self.record(event, "", outcome);
    }

    /// 通用记录入口（内部）：追加样本并推进序号
    fn record(&mut self, event: SyscallEvent, fallback: impl Into<String>, outcome: SampleOutcome) {
        self.next_seq += 1;
        self.records.push(MissRecord {
            seq: self.next_seq,
            event,
            fallback: fallback.into(),
            outcome,
        });
    }

    /// 失败 / 未命中样本数量（语义与旧 `miss_count` 一致）
    pub fn miss_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == SampleOutcome::Failure)
            .count()
    }

    /// 命中（成功）样本数量
    pub fn hit_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.outcome == SampleOutcome::Success)
            .count()
    }

    /// 自动化决策样本总数（成功 + 失败，不含用户反馈）
    pub fn total_count(&self) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(r.outcome, SampleOutcome::Success | SampleOutcome::Failure))
            .count()
    }

    /// 覆盖率 = 命中数 / 自动化决策总数（无样本时返回 0.0）
    pub fn coverage(&self) -> f64 {
        let total = self.total_count();
        if total == 0 {
            0.0
        } else {
            self.hit_count() as f64 / total as f64
        }
    }

    /// 全部样本记录（只读）
    pub fn records(&self) -> &[MissRecord] {
        &self.records
    }

    /// 去重后的未命中 syscall 编号（升序，供 B2 训练集去重）
    pub fn unique_syscalls(&self) -> Vec<i32> {
        let mut nrs: Vec<i32> = self
            .records
            .iter()
            .filter(|r| r.outcome == SampleOutcome::Failure)
            .map(|r| r.event.nr)
            .collect();
        nrs.sort_unstable();
        nrs.dedup();
        nrs
    }

    /// 清空采集器（例如降级到 WSL2 后重新开始统计）
    pub fn reset(&mut self) {
        self.records.clear();
        self.next_seq = 0;
    }

    /// 序列化全部样本为 JSON（落盘 `~/.daoti/telemetry/` 用）
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// 从 JSON 重载样本（落盘后恢复用）
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(nr: i32) -> SyscallEvent {
        SyscallEvent::new(nr, "unknown", vec![], 1)
    }

    /// 记录后计数、序号单调递增（失败样本）
    #[test]
    fn records_misses_with_monotonic_seq() {
        let mut c = TelemetryCollector::new();
        c.record_miss(ev(300), "wsl2");
        c.record_miss(ev(301), "error");
        assert_eq!(c.miss_count(), 2);
        assert_eq!(c.records()[0].seq, 1);
        assert_eq!(c.records()[1].seq, 2);
        assert_eq!(c.records()[0].fallback, "wsl2");
        assert_eq!(c.records()[0].outcome, SampleOutcome::Failure);
    }

    /// 去重后的未命中 syscall 编号升序（仅统计失败样本）
    #[test]
    fn unique_syscalls_dedups_and_sorts() {
        let mut c = TelemetryCollector::new();
        c.record_miss(ev(300), "wsl2");
        c.record_miss(ev(301), "wsl2");
        c.record_miss(ev(300), "wsl2");
        assert_eq!(c.unique_syscalls(), vec![300, 301]);
    }

    /// 重置后清空计数
    #[test]
    fn reset_clears_records() {
        let mut c = TelemetryCollector::new();
        c.record_miss(ev(300), "wsl2");
        c.reset();
        assert_eq!(c.miss_count(), 0);
        assert!(c.unique_syscalls().is_empty());
    }

    /// 四分类记录：成功 / 失败 / 反馈正 / 反馈负 各归其类，覆盖率统计正确
    #[test]
    fn four_class_records_and_coverage() {
        let mut c = TelemetryCollector::new();
        c.record_success(ev(300));
        c.record_miss(ev(301), "wsl2");
        c.record_miss(ev(302), "error");
        c.record_feedback(ev(303), true);
        c.record_feedback(ev(304), false);

        assert_eq!(c.hit_count(), 1);
        assert_eq!(c.miss_count(), 2);
        // 自动化决策总数 = 成功 + 失败 = 3（用户反馈不计入覆盖率分母）
        assert_eq!(c.total_count(), 3);
        assert!((c.coverage() - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(c.records()[0].outcome, SampleOutcome::Success);
        assert_eq!(c.records()[1].outcome, SampleOutcome::Failure);
        assert_eq!(c.records()[3].outcome, SampleOutcome::UserPositive);
        assert_eq!(c.records()[4].outcome, SampleOutcome::UserNegative);
        assert_eq!(SampleOutcome::UserPositive.label(), "反馈·正");
    }

    /// 覆盖率：无样本时为 0.0，避免除零
    #[test]
    fn coverage_is_zero_when_empty() {
        let c = TelemetryCollector::new();
        assert_eq!(c.coverage(), 0.0);
        assert_eq!(c.total_count(), 0);
    }

    /// 落盘 / 重载 roundtrip：序列化后反序列化，四分类标签与样本数保持
    #[test]
    fn roundtrip_preserves_outcome() {
        let mut c = TelemetryCollector::new();
        c.record_success(ev(300));
        c.record_miss(ev(301), "wsl2");
        c.record_feedback(ev(302), true);

        let json = c.to_json();
        let restored = match TelemetryCollector::from_json(&json) {
            Ok(collector) => collector,
            Err(err) => panic!("反序列化失败: {err}"),
        };
        assert_eq!(restored.records(), c.records());
        assert_eq!(restored.coverage(), c.coverage());
    }
}
