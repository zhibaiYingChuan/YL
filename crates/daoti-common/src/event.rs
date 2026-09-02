//! 事件类型 (DaotiEvent)
//!
//! 对应《产品形态.md》"决策时间轴" 与《设计方案.md》推演循环。
//! Daemon 通过 mpsc 向 UI/日志发布事件，形成可回放的时间轴（开发计划 R8：单一数据源）。

use serde::{Deserialize, Serialize};

/// 事件发生阶段（与五层架构对应）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// 感知层：采集到某系统状态
    Sense,
    /// 推演层：卦象推演 / 判词产出
    Infer,
    /// 调度输出：生成平台指令
    Decide,
    /// 执行层：执行某条命令
    Execute,
    /// 结果：修复验证结果
    Result,
    /// 学习层：慢调节学习（Hebbian 权重更新，道体·养）
    Learn,
    // ─── 模式B：跨平台二进制运行 ────────────────────────────
    /// 跨平台运行：提交了运行请求
    CrossPlatformRun,
    /// 跨平台运行：降级触发（含降级原因与层级）
    RunFallback,
}

/// 一条决策时间轴事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaotiEvent {
    /// 事件序号（自增）
    pub seq: u64,
    /// 事件发生阶段
    pub kind: EventKind,
    /// 事件标题（如 "坎水动荡（Docker 无响应）"）
    pub title: String,
    /// 附加详情（判词、命令、结果等）
    pub detail: String,
    /// 事件时间（Unix 毫秒）
    pub ts_ms: u64,
    /// 目标平台（windows / wsl2 / docker / all），可为空
    pub target: Option<String>,
}

impl DaotiEvent {
    /// 构造一条事件（seq 由上游分配，ts 由调用方传入）
    pub fn new(seq: u64, kind: EventKind, title: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        DaotiEvent {
            seq,
            kind,
            title: title.into(),
            detail: String::new(),
            ts_ms: now,
            target: None,
        }
    }

    /// 链式设置详情
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// 链式设置目标平台
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_builds_with_chain() {
        let e = DaotiEvent::new(1, EventKind::Sense, "坎水动荡")
            .with_target("docker")
            .with_detail("Docker Daemon 无响应");
        assert_eq!(e.seq, 1);
        assert_eq!(e.target.as_deref(), Some("docker"));
        assert_eq!(e.kind, EventKind::Sense);
        assert!(e.ts_ms > 0);
    }

    #[test]
    fn event_roundtrips_json() {
        let e = DaotiEvent::new(2, EventKind::Infer, "推演").with_detail("水困于土，上卦变艮");
        let json = serde_json::to_string(&e).expect("序列化失败");
        let back: DaotiEvent = serde_json::from_str(&json).expect("反序列化失败");
        assert_eq!(back.title, "推演");
        assert_eq!(back.detail, "水困于土，上卦变艮");
    }
}
