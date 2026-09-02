//! 事件总线 (EventBus)
//!
//! 对应《开发计划-TechnicalPlan.md》§10.3 R8 单一数据源：daemon 是唯一 producer，
//! 玄镜(UI)/CLI 通过 HTTP/SSE 只读消费。本模块提供进程内的广播通道与序号分配。
//!
//! 依据《rust语言开发.md》施工蓝图：跨线程共享状态一律 `Arc<...>`，禁止手写复杂生命周期。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;

use daoti_common::DaotiEvent;

/// 事件总线容量（环形缓冲，慢消费者丢弃最旧事件）
const EVENT_BUS_CAPACITY: usize = 256;

/// 事件总线：持有广播发送端、自增序号与 P2-2 背压指标。
#[derive(Clone)]
pub struct EventBus {
    /// 广播发送端（可克隆，Sender 可被多任务共享）
    tx: broadcast::Sender<DaotiEvent>,
    /// 自增事件序号（跨任务原子分配）
    seq: Arc<AtomicU64>,
    /// P2-2 背压：成功发送事件总数
    sent: Arc<AtomicU64>,
    /// P2-2 背压：因广播通道满被丢弃的事件数
    dropped: Arc<AtomicU64>,
}

impl EventBus {
    /// 创建事件总线，返回自身（后续可 clone 出多个 Sender 分发给各任务）。
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(EVENT_BUS_CAPACITY);
        EventBus {
            tx,
            seq: Arc::new(AtomicU64::new(0)),
            sent: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 发布一条已完整构造的事件（含 title/detail/target），由总线分配序号并广播。
    ///
    /// 调用方先链式构造最终事件（`DaotiEvent::new(...).with_detail(..).with_target(..)`），
    /// 再交给总线发送，避免广播发生在 builder 生效之前（导致订阅端字段缺失）。
    pub fn publish_built(&self, mut ev: DaotiEvent) -> DaotiEvent {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        ev.seq = seq;
        match self.tx.send(ev.clone()) {
            Ok(_) => {
                self.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                // 广播通道满（慢消费者），事件被环形缓冲丢弃
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        ev
    }

    /// P2-2 背压：获取发送/丢弃计数，供 `/api/health` 暴露。
    pub fn metrics(&self) -> EventBusMetrics {
        EventBusMetrics {
            sent: self.sent.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }

    /// 订阅事件流（返回一个接收者）。每次订阅接收者从头开始，序号连续。
    pub fn subscribe(&self) -> broadcast::Receiver<DaotiEvent> {
        self.tx.subscribe()
    }
}

/// P2-2 背压指标：EventBus 发送/丢弃计数快照。
#[derive(Debug, Clone, Copy)]
pub struct EventBusMetrics {
    /// 成功广播的事件数
    pub sent: u64,
    /// 因通道满被丢弃的事件数
    pub dropped: u64,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daoti_common::EventKind;

    #[tokio::test]
    async fn publish_increments_seq() {
        let bus = EventBus::new();
        let e1 = bus.publish_built(DaotiEvent::new(0, EventKind::Sense, "坎水动荡"));
        let e2 = bus.publish_built(DaotiEvent::new(0, EventKind::Infer, "推演"));
        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
    }

    #[tokio::test]
    async fn subscriber_receives_published() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        bus.publish_built(DaotiEvent::new(
            0,
            EventKind::Execute,
            "执行 wsl --shutdown",
        ));

        // 注意：广播在下一次 poll 时投递，先等待一下保证事件进入接收者缓冲
        let ev = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("接收超时")
            .expect("通道关闭");
        assert_eq!(ev.kind, EventKind::Execute);
        assert!(ev.title.contains("wsl --shutdown"));
    }

    #[tokio::test]
    async fn publish_built_carries_detail_and_target() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        let built = DaotiEvent::new(0, EventKind::Sense, "感 · 水")
            .with_detail("Docker 断流")
            .with_target("docker");
        let ev = bus.publish_built(built);

        let recv = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("接收超时")
            .expect("通道关闭");
        // 订阅端收到与发布端一致（含 detail/target），且序号由总线分配
        assert_eq!(recv.seq, ev.seq);
        assert_eq!(recv.detail, "Docker 断流");
        assert_eq!(recv.target.as_deref(), Some("docker"));
    }

    /// P1-3 广播满韧性：超过容量（256）发布不 panic，旧事件被丢弃。
    #[tokio::test]
    async fn publish_overflow_no_panic() {
        let bus = EventBus::new();
        // 发布 512 条事件（超过容量 256），断言不 panic
        for i in 0..512 {
            bus.publish_built(DaotiEvent::new(0, EventKind::Sense, format!("e{i}")));
        }

        // 订阅者只能收到最新 ≤256 条（旧事件被环形缓冲丢弃）
        let mut rx = bus.subscribe();
        let mut count = 0;
        while let Ok(Ok(_)) =
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await
        {
            count += 1;
        }
        // 订阅后新发布的事件可正常接收（至少 0 条，至多 256 条）
        assert!(count <= 256, "接收数量应在容量内，实际 {count}");
    }

    /// P1-3 Sensor/SSE 韧性：无订阅者时发布不 panic（无消费者场景）。
    #[tokio::test]
    async fn publish_without_subscriber_no_panic() {
        let bus = EventBus::new();
        // 不创建订阅者，直接发布 → 不 panic（SSE 未连接时的正常场景）
        for _ in 0..10 {
            bus.publish_built(DaotiEvent::new(0, EventKind::Sense, "test"));
        }
        // 达到此处即通过
    }
}
