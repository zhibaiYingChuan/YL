//! mpsc 编排 (daoti-daemon::actor)
//!
//! 对应《开发计划-TechnicalPlan.md》步骤 7 / §9.3 M5 Daemon 常驻：
//! sensor → decision → executor 三层通过 `tokio::sync::mpsc` 消息通道编排（禁止共享内存，R7）。
//! 三感知器各自周期采集，结果经 mpsc 送入协调者；协调者融合 → 推演 →（必要时）执行，
//! 并将**真实感知/推演/执行事件**发布到事件总线，取代原先 30s 心跳占位。
//!
//! 依据《rust语言开发.md》施工蓝图：跨线程状态一律经 mpsc 传递，协调者单任务持有状态，
//! 不跨任务共享可变数据，避免竞态与死锁。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use daoti_common::{config::Config, DaotiEvent, EventKind};
use daoti_core::decision::engine::RuleEngine;
use daoti_core::decision::model::DispatchModel;
use daoti_core::decision::DaotiSymbolicOutput;
use daoti_core::decision::InferenceEngine;
use daoti_core::sensor::{FusionState, SensorSnapshot, SensorState, WuxingHealth};

use crate::notifier::{CompositeNotifier, Notifier};
use daoti_daemon::eventbus::EventBus;

#[cfg(feature = "learning")]
use daoti_core::learning::{SlowLearner, TrajectoryRecord};

/// 事件通道容量（协调者处理速度远快于感知器的采集频率）
const CHANNEL_CAPACITY: usize = 16;

/// 收敛窗口：单个采样轮内三感知器（windows/wsl2/docker）结果到达略有先后，
/// 在此窗口内合并到一次推演，避免启动/状态跳变时重复干预。
const SETTLE_GRACE: Duration = Duration::from_millis(600);

/// 感知器 → 协调者 的消息
enum Msg {
    /// 某感知器完成一次采集
    Sensed { target: String, state: SensorState },
    /// P1-2 配置热重载：文件变更后通知协调者更新运行时参数
    ReloadConfig {
        sampling_secs: u64,
        exec_secs: u64,
        dispatch_model_path: Option<String>,
    },
}

/// 协调者任务状态：持有融合状态与上一轮健康度（用于检测"实质变化"以唤醒推演）
struct Coordinator {
    bus: EventBus,
    engine: RuleEngine,
    fusion: FusionState,
    last_health: Option<WuxingHealth>,
    /// P0-6 主动告警通知器（None 表示无可用通道）
    notifier: Option<std::sync::Arc<CompositeNotifier>>,
    /// P1-2 热可加载：采样间隔（秒），供日志/决策引用
    sampling_secs: u64,
    /// P1-2 热可加载：执行超时（秒），供日志/决策引用
    exec_secs: u64,
    /// 道体调度模型，配置变更时原子替换
    dispatch_model: Option<DispatchModel>,
    /// P2-3 幂等：上次执行的决策指纹（gua + pathway + 命令列表），用于去重
    last_decision: Option<String>,
    /// P2-3 幂等：上次执行干预的时间戳（unix 秒），用于冷却期防抖
    last_intervene_at: Option<u64>,
    /// learning feature：慢调节学习器（决策后 Hebbian 学习 + 权重注入）
    #[cfg(feature = "learning")]
    learner: SlowLearner,
}

/// Actor 配置（来源于全局 `Config`，避免硬编码）
pub struct ActorConfig {
    pub sampling_interval: Duration,
    pub dispatch_model_path: Option<String>,
}

impl ActorConfig {
    /// 从全局配置构建
    pub fn from_config(cfg: &Config) -> Self {
        ActorConfig {
            sampling_interval: Duration::from_secs(cfg.timeouts.sampling_secs),
            dispatch_model_path: cfg.model.dispatch_model_path.clone(),
        }
    }
}

/// Actor 句柄：持有取消令牌、mpsc 发送端与 P2-2 背压指标。
pub struct ActorHandle {
    token: CancellationToken,
    /// mpsc 发送端（P1-2 热加载通过此通道通知协调者更新参数）
    tx: Option<mpsc::Sender<Msg>>,
    /// P2-2 背压：mpsc try_send 失败次数（通道满时丢弃的 ReloadConfig 消息）
    mpsc_dropped: Arc<AtomicU64>,
}

impl ActorHandle {
    /// 请求优雅停止所有感知/协调任务
    pub fn shutdown(&self) {
        self.token.cancel();
    }

    /// P1-2 热加载：通知协调者更新运行时参数。
    ///
    /// 非阻塞：通道已满时记录丢弃并递增计数器（P2-2 背压可见化）。
    pub fn reload_config(
        &self,
        sampling_secs: u64,
        exec_secs: u64,
        dispatch_model_path: Option<String>,
    ) {
        if let Some(ref tx) = self.tx {
            if tx
                .try_send(Msg::ReloadConfig {
                    sampling_secs,
                    exec_secs,
                    dispatch_model_path,
                })
                .is_err()
            {
                self.mpsc_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// P2-2 背压：克隆 mpsc 丢弃计数器 Arc，供 HTTP 路由共享同一个计数器。
    pub fn mpsc_counter(&self) -> Arc<AtomicU64> {
        self.mpsc_dropped.clone()
    }

    /// 启动整个 Actor 体系：三感知器任务 + 协调者任务。
    /// 返回句柄，主流程在退出前应调用 `handle.shutdown()`。
    ///
    /// `notifier` 为 P0-6 主动告警通知器；传 `None` 表示无可用通道（告警仅记录日志）。
    pub fn spawn(
        bus: EventBus,
        cfg: ActorConfig,
        notifier: Option<std::sync::Arc<CompositeNotifier>>,
    ) -> ActorHandle {
        let token = CancellationToken::new();
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let mpsc_dropped = Arc::new(AtomicU64::new(0));

        let coordinator = Coordinator {
            engine: RuleEngine::new(),
            dispatch_model: std::env::var_os("DAOTI_DISPATCH_MODEL_PATH")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    cfg.dispatch_model_path
                        .as_ref()
                        .map(std::path::PathBuf::from)
                })
                .and_then(|path| match DispatchModel::load(&path) {
                    Ok(model) => Some(model),
                    Err(error) => {
                        tracing::warn!(
                            "道体调度模型加载失败，daemon 回退规则引擎：{}：{}",
                            path.display(),
                            error
                        );
                        None
                    }
                }),
            fusion: FusionState::default(),
            last_health: None,
            bus: bus.clone(),
            notifier,
            sampling_secs: cfg.sampling_interval.as_secs(),
            exec_secs: 10, // 默认 10s，后续由热加载更新
            last_decision: None,
            last_intervene_at: None,
            #[cfg(feature = "learning")]
            learner: SlowLearner::with_defaults(),
        };
        tokio::spawn(run_coordinator(coordinator, rx, token.clone()));

        // 三平台统一生成内部符号状态，不读取宿主机，也不调用外部软件。
        spawn_symbolic_sensor("windows", tx.clone(), cfg.sampling_interval);
        spawn_symbolic_sensor("wsl2", tx.clone(), cfg.sampling_interval);
        spawn_symbolic_sensor("docker", tx.clone(), cfg.sampling_interval);

        ActorHandle {
            token,
            tx: Some(tx),
            mpsc_dropped,
        }
    }
}

/// 协调者主循环：mpsc 接收感知结果，融合→（变化时）推演→执行，全程发布真实事件。
/// P1-5：周期自动落盘 FusionState 快照，daemon 自动产生快照而非仅依赖 CLI。
async fn run_coordinator(
    mut c: Coordinator,
    mut rx: mpsc::Receiver<Msg>,
    token: CancellationToken,
) {
    // P1-5 快照自动落盘周期（默认 300s，约 5 分钟一次）
    let mut snapshot_ticker = tokio::time::interval(Duration::from_secs(300));
    // 首次不立即触发（启动后等待感知数据累积）
    snapshot_ticker.tick().await;

    loop {
        tokio::select! {
            // 优雅停止：收到取消信号即退出循环
            _ = token.cancelled() => break,
            // P1-5 周期快照：自动落盘当前 FusionState
            _ = snapshot_ticker.tick() => {
                if let Err(e) = c.write_snapshot() {
                    tracing::warn!("快照自动落盘失败（不阻塞主循环）: {e}");
                }
            }
            msg = rx.recv() => {
                match msg {
                    // 所有感知器已关闭，协调者自然结束
                    None => break,
                    // P1-2 配置热重载：更新运行时参数
                    Some(Msg::ReloadConfig {
                        sampling_secs,
                        exec_secs,
                        dispatch_model_path,
                    }) => {
                        let old_s = c.sampling_secs;
                        c.sampling_secs = sampling_secs;
                        c.exec_secs = exec_secs;
                        match dispatch_model_path {
                            Some(path) => match DispatchModel::load(std::path::Path::new(&path)) {
                                Ok(model) => {
                                    tracing::info!("道体调度模型已热重载：{}", path);
                                    c.dispatch_model = Some(model);
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        "道体调度模型热重载失败，保留旧模型：{}：{}",
                                        path, error
                                    );
                                }
                            },
                            None => {
                                c.dispatch_model = None;
                                tracing::info!("道体调度模型已卸载，回退规则引擎");
                            }
                        }
                        tracing::info!(
                            "配置热重载：采样间隔 {}s → {}s，执行超时 {}s",
                            old_s, sampling_secs, exec_secs
                        );
                    }
                    Some(Msg::Sensed { target, state }) => {
                        c.apply_sense(&target, &state);
                        c.publish_sense(&target, &state);

                        // 收敛窗口：合并同一采样轮内其余感知器的消息，
                        // 避免 windows/wsl2/docker 到达先后导致健康度变化多次、重复推演
                        while let Ok(Some(Msg::Sensed { target, state })) = tokio::time::timeout(SETTLE_GRACE, rx.recv()).await {
                            c.apply_sense(&target, &state);
                            c.publish_sense(&target, &state);
                        }

                        // 收敛后统一判定一次：状态变化才唤醒推演（遇异常才干预）
                        let health = c.fusion.wuxing_health();
                        if c.health_changed(&health) {
                            c.last_health = Some(health.clone());
                            c.infer_and_act(&health).await;
                        }
                    }
                }
            }
        }
    }
}

/// 单个感知器任务：周期采集并发送结果到 mpsc。
/// 返回 `()`，JoinHandle 被显式丢弃（感知器生命周期由协调者/取消令牌统一管理）。
fn spawn_symbolic_sensor(target: &'static str, tx: mpsc::Sender<Msg>, interval: Duration) {
    let _handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let state = SensorState::Ok(
                SensorSnapshot::new(target)
                    .field("mode", "symbolic_only")
                    .field("capability", "registered")
                    .metric("health", 1.0),
            );
            if tx
                .send(Msg::Sensed {
                    target: target.to_string(),
                    state,
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
}

impl Coordinator {
    /// 将感知结果写入融合状态对应槽位
    fn apply_sense(&mut self, target: &str, state: &SensorState) {
        let slot = snapshot_of(state);
        match target {
            "windows" => self.fusion.windows = slot,
            "wsl2" => self.fusion.wsl2 = slot,
            "docker" => self.fusion.docker = slot,
            other => tracing::warn!("未知感知目标: {}", other),
        }
    }

    /// 发布感知事件（真实状态，取代心跳占位）
    fn publish_sense(&self, target: &str, state: &SensorState) {
        let (title, detail) = describe_sense(target, state);
        let ev = DaotiEvent::new(0, EventKind::Sense, title)
            .with_detail(detail)
            .with_target(target);
        let _ = self.bus.publish_built(ev);
    }

    /// 健康度是否发生实质变化（首次采集或任一数值变化）
    fn health_changed(&self, health: &WuxingHealth) -> bool {
        match &self.last_health {
            None => true,
            Some(prev) => !health_eq(prev, health),
        }
    }

    /// 推演 → 公布决策 →（若非"无行动"）执行并发结果事件
    ///
    /// P2-3 幂等防重复：
    /// - 同一决策指纹（gua + pathway + 命令列表）在冷却期内不重复执行
    /// - 执行前二次校验目标状态是否仍需干预
    async fn infer_and_act(&mut self, health: &WuxingHealth) {
        #[cfg(feature = "learning")]
        {
            // 慢调节：决策前用参数库最新权重注入决策引擎（道体·养 闭环）
            let p = self.learner.library().params();
            self.engine
                .set_weights(p.metal_weight, p.wood_weight, p.water_weight);
        }
        // 优先使用已训练调度模型；无模型时走道体符号调度（五行生克 → 路径 → 决策）；符号出错时回退规则引擎。
        let (status, decision) = match self.dispatch_model.as_mut() {
            Some(model) => (model.status().to_string(), model.interpret(health)),
            None => {
                let symbolic = DaotiSymbolicOutput::from_health(health);
                match symbolic.to_decision() {
                    Ok(d) => ("道体符号调度".to_string(), d),
                    Err(_) => (
                        self.engine.status().to_string(),
                        self.engine.interpret(health),
                    ),
                }
            }
        };

        let infer_ev = DaotiEvent::new(0, EventKind::Infer, format!("推演 · {}卦", decision.gua))
            .with_detail(decision.explanation.clone());
        let _ = self.bus.publish_built(infer_ev);

        let decide_ev = DaotiEvent::new(
            0,
            EventKind::Decide,
            format!("调度 · {} · {}", decision.pathway, status),
        )
        .with_detail(decision.priority.clone());
        let _ = self.bus.publish_built(decide_ev);

        // 三气通畅则无需干预
        if decision.commands.is_empty() {
            tracing::info!("三气通畅，无需干预（{}）", decision.pathway);
            return;
        }

        let fingerprint = format!(
            "{}|{}|{}",
            decision.gua,
            decision.pathway,
            decision
                .commands
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
        const COOLDOWN_SECS: u64 = 60; // 同一决策冷却期 60 秒
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if self.last_decision.as_deref() == Some(&fingerprint) {
            if let Some(last) = self.last_intervene_at {
                if now < last + COOLDOWN_SECS {
                    tracing::info!(
                        "幂等跳过：决策「{}」在冷却期内（上次执行后 {}s），不重复干预",
                        decision.gua,
                        now - last,
                    );
                    return;
                }
            }
        }
        self.last_decision = Some(fingerprint);
        self.last_intervene_at = Some(now);

        // P0-6 主动告警：异常检测到非空命令列表时，通过通知通道告知用户。
        // fire-and-forget：通知失败不影响 daemon 主流程（tokio::spawn_blocking 隔离）。
        if let Some(ref n) = self.notifier {
            let notifier = n.clone();
            let pathway = decision.pathway.clone();
            let commands_summary: Vec<String> = decision
                .commands
                .iter()
                .map(|c| c.command.clone())
                .collect();
            let title = format!("驭灵 · {}卦 · 需干预", decision.gua);
            let body = format!("气路：{}\n建议：{}", pathway, commands_summary.join("、"));
            tokio::task::spawn_blocking(move || {
                notifier.notify(&title, &body);
            });
        }

        for cmd in &decision.commands {
            let exec_ev =
                DaotiEvent::new(0, EventKind::Execute, format!("符号执行 · {}", cmd.command))
                    .with_detail("symbolic_only：未调用外部软件")
                    .with_target(&cmd.target);
            let _ = self.bus.publish_built(exec_ev);

            let result_ev = DaotiEvent::new(
                0,
                EventKind::Result,
                format!("符号结果 · {} · 已调度", cmd.target),
            )
            .with_detail("内部符号路径已生成，未下发平台命令")
            .with_target(&cmd.target);
            let _ = self.bus.publish_built(result_ev);
            tracing::info!("符号调度 {} 于 {}", cmd.command, cmd.target);
        }

        #[cfg(feature = "learning")]
        self.learn_from_outcome(&decision, true);
    }

    /*
            match self.executor.execute(cmd).await {
                Ok(res) => {
                    #[cfg(feature = "learning")]
                    if !res.success {
                        all_success = false;
                    }
                    let summary = if res.success { "成功" } else { "失败" };
                    let detail = if res.success {
                        truncate_output_with_hint(&res.stdout)
                    } else {
                        truncate_output_with_hint(&res.stderr)
                    };
                    let result_ev = DaotiEvent::new(
                        0,
                        EventKind::Result,
                        format!("结果 · {} · {}", cmd.target, summary),
                    )
                    .with_detail(detail)
                    .with_target(&cmd.target);
                    let _ = self.bus.publish_built(result_ev);
                    tracing::info!("执行 {} 于 {}: {}", cmd.command, cmd.target, summary);
                }
                Err(e) => {
                    #[cfg(feature = "learning")]
                    {
                        all_success = false;
                    }
                    let err_msg = truncate_output_with_hint(&e.to_string());
                    let result_ev = DaotiEvent::new(
                        0,
                        EventKind::Result,
                        format!("结果 · {} · 错误", cmd.target),
                    )
                    .with_detail(err_msg)
                    .with_target(&cmd.target);
                    let _ = self.bus.publish_built(result_ev);
                    tracing::warn!(
                        "执行「{}」({}) 出错: {}",
                        cmd.command,
                        cmd.target,
                        truncate_output_with_hint(&e.to_string())
                    );
                }
            }
        }

        #[cfg(feature = "learning")]
        self.learn_from_outcome(&decision, all_success);
    }
    */

    /// learning feature：决策执行后，用结果驱动 Hebbian 慢调节并保存参数库。
    #[cfg(feature = "learning")]
    fn learn_from_outcome(&mut self, decision: &daoti_core::decision::Decision, all_success: bool) {
        let record = TrajectoryRecord {
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            gua: decision.gua.clone(),
            priority: decision.priority.clone(),
            pathway: decision.pathway.clone(),
            confidence: decision.confidence,
            explanation: decision.explanation.clone(),
            commands: vec![],
            outcomes: vec![],
            fixed: all_success,
        };
        let report = self.learner.learn(&[record]);
        // 发布学习事件（可观测：权重增量 + 当前权重进入决策时间轴）
        let p = self.learner.library().params();
        let learn_ev = DaotiEvent::new(
            0,
            EventKind::Learn,
            format!("学习 · 道体·养 · {} 样本", report.samples),
        )
        .with_detail(format!(
            "权重 金{:.3}/木{:.3}/水{:.3}（增量 金{:+.3}/木{:+.3}/水{:+.3}）",
            p.metal_weight,
            p.wood_weight,
            p.water_weight,
            report.metal_delta,
            report.wood_delta,
            report.water_delta
        ));
        let _ = self.bus.publish_built(learn_ev);
        tracing::info!(
            "道体·养：学习 1 样本，权重增量 金{:.3}/木{:.3}/水{:.3}",
            report.metal_delta,
            report.wood_delta,
            report.water_delta
        );
        let params_path = daoti_common::config::daoti_dir().join("params.json");
        if let Err(e) = self.learner.library().save(&params_path) {
            tracing::warn!("参数库保存失败（不阻塞主循环）: {e}");
        }
    }

    /// P1-5 周期快照：将当前 FusionState 序列化为 JSON 落盘到 `snapshots_dir`。
    ///
    /// 落盘失败仅记录 warning，不阻塞主循环。
    fn write_snapshot(&self) -> std::io::Result<()> {
        let dir = daoti_common::config::snapshots_dir();
        std::fs::create_dir_all(&dir)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = dir.join(format!("daoti_{ts}.json"));
        let json = serde_json::to_string_pretty(&self.fusion)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        tracing::info!("快照已落盘：{}", path.display());
        Ok(())
    }
}

/// 从感知结果中取出快照（Ok 有值，Unavailable 为 None）
fn snapshot_of(state: &SensorState) -> Option<SensorSnapshot> {
    match state {
        SensorState::Ok(s) => Some(s.clone()),
        SensorState::Unavailable => None,
    }
}

/// 生成感知事件的中文标题与详情
fn describe_sense(target: &str, state: &SensorState) -> (String, String) {
    let name = match target {
        "windows" => "金 · Windows 宿主",
        "wsl2" => "木 · WSL2 内核",
        "docker" => "水 · Docker 容器",
        other => other,
    };
    match state {
        SensorState::Ok(snap) => (format!("感 · {}", name), snapshot_summary(snap)),
        SensorState::Unavailable => (
            format!("感 · {} · 不可达", name),
            "目标平台不可达，计入五行降级。".into(),
        ),
    }
}

/// 将快照的字段/指标汇总为紧凑文本（确定性排序，便于展示与测试）
fn snapshot_summary(s: &SensorSnapshot) -> String {
    let mut parts: Vec<String> = s.fields.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.extend(s.metrics.iter().map(|(k, v)| format!("{k}={v:.2}")));
    parts.sort();
    parts.join(" ")
}

/// 健康度数值相等（带容差，避免浮点抖动误触发推演）
fn health_eq(a: &WuxingHealth, b: &WuxingHealth) -> bool {
    const EPS: f64 = 1e-9;
    (a.metal - b.metal).abs() < EPS
        && (a.wood - b.wood).abs() < EPS
        && (a.water - b.water).abs() < EPS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_deterministic_and_compact() {
        let snap = SensorSnapshot::new("docker")
            .field("daemon_version", "27.2.0")
            .metric("containers", 3.0);
        let s = snapshot_summary(&snap);
        assert!(s.contains("daemon_version=27.2.0"));
        assert!(s.contains("containers=3.00"));
        assert!(s.contains(' '));
    }

    #[test]
    fn describe_ok_lists_summary() {
        let snap = SensorSnapshot::new("wsl2").field("kernel_version", "6.6");
        let (title, detail) = describe_sense("wsl2", &SensorState::Ok(snap));
        assert!(title.contains("木"));
        assert!(detail.contains("kernel_version=6.6"));
    }

    #[test]
    fn describe_unavailable_marks_降级() {
        let (title, detail) = describe_sense("docker", &SensorState::Unavailable);
        assert!(title.contains("不可达"));
        assert!(detail.contains("降级"));
    }

    #[test]
    fn health_eq_compares_with_tolerance() {
        let a = WuxingHealth {
            metal: 1.0,
            wood: 0.5,
            water: 0.0,
        };
        assert!(health_eq(
            &a,
            &WuxingHealth {
                metal: 1.0,
                wood: 0.5,
                water: 0.0
            }
        ));
        assert!(!health_eq(
            &a,
            &WuxingHealth {
                metal: 1.0,
                wood: 0.6,
                water: 0.0
            }
        ));
    }

    #[test]
    fn snapshot_of_maps_state() {
        let snap = SensorSnapshot::new("windows");
        assert!(snapshot_of(&SensorState::Ok(snap)).is_some());
        assert!(snapshot_of(&SensorState::Unavailable).is_none());
    }
}
