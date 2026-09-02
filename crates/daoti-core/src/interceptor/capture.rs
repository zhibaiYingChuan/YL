//! syscall 捕获源契约与模拟桩（L0-3）
//!
//! L0-3 目标：把「捕获 syscall」与「B1 规则映射」连接成闭环骨架。
//! 本模块不做真实 OS 注入（ptrace / Windows Debug API 留待平台适配层），
//! 而是定义 `SyscallCaptureSource` 契约 + `MockCaptureSource` 可测试模拟桩，
//! 让 `RuleInterceptor` 能消费「从捕获源流出的 `SyscallEvent`」。
//!
//! 真实实现后续接入：`ElfLoader`（L0/内存沙箱）内嵌入断点桩，产出同样的事件流。

use std::collections::VecDeque;

use daoti_common::DaotiError;

use super::{Interceptor, RuleInterceptor, SyscallEvent, TargetSyscall};

/// syscall 捕获源契约
///
/// 任何真实拦截层（ptrace / Debug API / 仿真器嵌入桩）都应实现此接口，
/// 统一产出 `SyscallEvent` 流，供 `RuleInterceptor` 翻译。
pub trait SyscallCaptureSource: Send {
    /// 尝试取出下一条被捕获的 syscall 事件。
    ///
    /// - `Ok(Some(event))`：捕获到一条事件
    /// - `Ok(None)`：当前无更多事件（非错误）
    /// - `Err(e)`：捕获失败（如被调试进程退出）
    fn next_event(&mut self) -> Result<Option<SyscallEvent>, DaotiError>;
}

/// 可测试模拟捕获桩：预置事件队列，逐条产出。
///
/// 用于单元测试与开发期验证，不涉及任何真实进程。
#[derive(Debug, Default)]
pub struct MockCaptureSource {
    /// 待产出的 syscall 事件队列
    queue: VecDeque<SyscallEvent>,
}

impl MockCaptureSource {
    /// 以预置事件构造模拟源
    pub fn new(events: Vec<SyscallEvent>) -> Self {
        MockCaptureSource {
            queue: events.into_iter().collect(),
        }
    }

    /// 追加一条待捕获事件
    pub fn push(&mut self, event: SyscallEvent) {
        self.queue.push_back(event);
    }

    /// 队列中剩余事件数
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

impl SyscallCaptureSource for MockCaptureSource {
    fn next_event(&mut self) -> Result<Option<SyscallEvent>, DaotiError> {
        Ok(self.queue.pop_front())
    }
}

/// 「捕获→映射」流水线运行结果
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaptureRunOutcome {
    /// 捕获到的 syscall 事件总数
    pub captured: usize,
    /// 命中 B1 映射并翻译为 TargetSyscall 的数量
    pub mapped: usize,
    /// 未命中映射的事件编号列表（供道体降级决策）
    pub missed_nrs: Vec<i32>,
    /// 翻译结果（按捕获顺序）
    pub targets: Vec<TargetSyscall>,
}

/// 驱动「捕获源 → 规则映射」流水线
///
/// 逐条从 `source` 读取事件，交给 `interceptor` 翻译；
/// 直到捕获源返回 `Ok(None)` 或发生错误。
pub fn capture_and_map<S: SyscallCaptureSource>(
    source: &mut S,
    interceptor: &RuleInterceptor,
) -> Result<CaptureRunOutcome, DaotiError> {
    let mut captured = 0usize;
    let mut mapped = 0usize;
    let mut missed_nrs: Vec<i32> = Vec::new();
    let mut targets: Vec<TargetSyscall> = Vec::new();

    while let Some(ev) = source.next_event()? {
        captured += 1;
        match interceptor.intercept(&ev)? {
            Some(t) => {
                mapped += 1;
                targets.push(t);
            }
            None => missed_nrs.push(ev.nr),
        }
    }

    Ok(CaptureRunOutcome {
        captured,
        mapped,
        missed_nrs,
        targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::SyscallEvent;

    #[test]
    fn test_mock_empty_source_yields_none() {
        let mut src = MockCaptureSource::default();
        assert_eq!(src.pending(), 0);
        let ev = src
            .next_event()
            .unwrap_or_else(|e| panic!("空源不应出错：{e}"));
        assert!(ev.is_none(), "空模拟源应返回 None");
    }

    #[test]
    fn test_mock_emits_queued_events_in_order() {
        let mut src = MockCaptureSource::new(vec![
            SyscallEvent::new(0, "read", vec![], 1),
            SyscallEvent::new(1, "write", vec![], 1),
        ]);
        let first = src.next_event().unwrap_or_else(|e| panic!("读取失败：{e}"));
        assert_eq!(first.unwrap().nr, 0);
        let second = src.next_event().unwrap_or_else(|e| panic!("读取失败：{e}"));
        assert_eq!(second.unwrap().nr, 1);
        assert!(src
            .next_event()
            .unwrap_or_else(|e| panic!("读取失败：{e}"))
            .is_none());
    }

    #[test]
    fn test_pipeline_maps_supported_events() {
        // read(0) + write(1) 均命中 B1 映射
        let mut src = MockCaptureSource::new(vec![
            SyscallEvent::new(0, "read", vec!["3".into(), "buf".into(), "10".into()], 1),
            SyscallEvent::new(1, "write", vec!["1".into(), "buf".into(), "4".into()], 1),
        ]);
        let interceptor = RuleInterceptor::new();
        let outcome =
            capture_and_map(&mut src, &interceptor).unwrap_or_else(|e| panic!("流水线失败：{e}"));
        assert_eq!(outcome.captured, 2);
        assert_eq!(outcome.mapped, 2);
        assert!(outcome.missed_nrs.is_empty());
        assert_eq!(outcome.targets.len(), 2);
        assert_eq!(outcome.targets[0].operation, "ReadFile");
        assert_eq!(outcome.targets[1].operation, "WriteFile");
    }

    #[test]
    fn test_pipeline_records_misses() {
        // getpid(39) 命中，4999 未命中
        let mut src = MockCaptureSource::new(vec![
            SyscallEvent::new(39, "getpid", vec![], 1),
            SyscallEvent::new(4999, "unknown", vec![], 1),
        ]);
        let interceptor = RuleInterceptor::new();
        let outcome =
            capture_and_map(&mut src, &interceptor).unwrap_or_else(|e| panic!("流水线失败：{e}"));
        assert_eq!(outcome.captured, 2);
        assert_eq!(outcome.mapped, 1);
        assert_eq!(outcome.missed_nrs, vec![4999]);
        assert_eq!(outcome.targets.len(), 1);
        assert_eq!(outcome.targets[0].operation, "GetCurrentProcessId");
    }

    #[test]
    fn test_pipeline_empty_source() {
        let mut src = MockCaptureSource::default();
        let interceptor = RuleInterceptor::new();
        let outcome =
            capture_and_map(&mut src, &interceptor).unwrap_or_else(|e| panic!("流水线失败：{e}"));
        assert_eq!(outcome.captured, 0);
        assert_eq!(outcome.mapped, 0);
        assert!(outcome.missed_nrs.is_empty());
        assert!(outcome.targets.is_empty());
    }

    #[test]
    fn test_outcome_is_serializable() {
        let outcome = CaptureRunOutcome {
            captured: 1,
            mapped: 1,
            missed_nrs: vec![],
            targets: vec![TargetSyscall::new("ReadFile", "读文件")],
        };
        let json = serde_json::to_string(&outcome).unwrap_or_else(|e| panic!("序列化失败：{e}"));
        assert!(
            json.contains("\"captured\":1"),
            "应含 captured 字段：{json}"
        );
        let back: CaptureRunOutcome =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("反序列化失败：{e}"));
        assert_eq!(back, outcome);
    }

    #[test]
    fn test_capture_consumes_all_until_empty() {
        // 大量事件流一次消费干净
        let mut src = MockCaptureSource::new(
            (0..50)
                .map(|i| SyscallEvent::new(i, format!("sys_{i}"), vec![], i as u64))
                .collect(),
        );
        let interceptor = RuleInterceptor::new();
        let outcome =
            capture_and_map(&mut src, &interceptor).unwrap_or_else(|e| panic!("流水线失败：{e}"));
        assert_eq!(outcome.captured, 50, "应消费全部 50 条");
        assert_eq!(outcome.mapped + outcome.missed_nrs.len(), 50);
        assert_eq!(src.pending(), 0, "模拟源应被完全消费");
    }
}
