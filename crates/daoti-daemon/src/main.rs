//! 驭灵 · 内核 (daoti-daemon)
//!
//! 对应《产品形态.md》"无头守护进程（道体内核）"：常驻后台，静默监听三系统，
//! 平时只记录"气"的流动，遇异常才被唤醒推演。
//! M5 落地：mpsc Actor 编排（sensor→decision→executor，注入真实感知事件）+ HTTP/SSE 出口。

mod actor;
mod notifier;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use clap::Parser;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use daoti_common::config::{daemon_pid_file, ensure_daemon_token, Config};
use daoti_common::process::{pid_alive, write_pid_file};
use daoti_daemon::eventbus::EventBus;
use daoti_daemon::eventlog;
use daoti_daemon::http;

use crate::actor::{ActorConfig, ActorHandle};

/// 驭灵守护进程
#[derive(Debug, Parser)]
#[command(name = "daoti-daemon", version, about = "驭灵内核：常驻后台守护进程")]
pub struct DaemonArgs {
    /// 以守护模式运行（默认）
    #[arg(long)]
    daemon: bool,

    /// HTTP/SSE 监听端口（默认 17890）
    #[arg(long, default_value_t = 17890)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    daoti_common::logging::init(&daoti_common::config::Config::default().log);
    let args = DaemonArgs::parse();

    // P0-1 单实例锁：同一端口仅允许一个守护进程，重复启动给出明确错误而非静默失败
    acquire_single_instance()?;

    tracing::info!("驭灵内核启动（M5：mpsc Actor 编排 + HTTP/SSE 出口）");

    // 全局配置（含 WSL 发行版 / Docker 服务名 / 采样间隔），避免硬编码
    let cfg = Config::load();

    // 事件总线：整个 daemon 的唯一事件源（R8）
    let bus = EventBus::new();

    // P0-5 事件历史落盘：独立 subscriber 将事件持久化为 JSONL
    let event_log = std::sync::Arc::new(
        eventlog::EventLog::open(&cfg.log.history_dir, cfg.log.history_max_events)
            .map_err(|e| anyhow::anyhow!("事件历史目录创建失败: {e}"))?,
    );
    {
        let log = event_log.clone();
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if let Err(e) = log.append(&ev) {
                            tracing::warn!("事件落盘失败: {e}");
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("事件持久化落后 {n} 条，继续追赶");
                    }
                }
            }
        });
    }

    // mpsc Actor：三感知器周期采集 → 协调者融合/推演/执行，发布真实感知事件
    let notifier = notifier::build_notifier(&cfg.notify).map(std::sync::Arc::new);
    let actor = std::sync::Arc::new(ActorHandle::spawn(
        bus.clone(),
        ActorConfig::from_config(&cfg),
        notifier,
    ));
    tracing::info!(
        "Actor 已启动：采样间隔 {}s，WSL 发行版 {}",
        cfg.timeouts.sampling_secs,
        cfg.paths.wsl_distro
    );

    // P1-2 配置热加载：每 5 秒轮询 ~/.daoti.toml 是否变更，变更后通知 Actor。
    let config_path = std::env::var_os("DAOTI_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(daoti_common::config::Config::default_path);
    let mut watcher = daoti_common::config::ConfigWatcher::new(config_path);
    let actor_reload = actor.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            if let Some(new_cfg) = watcher.check() {
                actor_reload.reload_config(
                    new_cfg.timeouts.sampling_secs,
                    new_cfg.timeouts.exec_secs,
                    new_cfg.model.dispatch_model_path.clone(),
                );
            }
        }
    });

    // HTTP/SSE 服务：仅绑定回环地址，不对外暴露。
    // S2 安全加固：生成/加载写端点鉴权 token，POST 写端点需携带匹配的 X-Daoti-Token。
    let write_token = ensure_daemon_token();
    let router = http::router(
        bus,
        event_log.clone(),
        std::sync::Arc::new(cfg),
        write_token,
        actor.mpsc_counter(),
    );
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, args.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("事件出口监听 {}", addr);

    let token = CancellationToken::new();
    // 传入 clone，保留原 token 供主流程 cancel
    let server_token = token.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            // 优雅关闭：收到信号时停止接收新连接
            .with_graceful_shutdown(server_token.cancelled_owned())
            .await
    });

    // 阻塞等待 Ctrl+C / SIGTERM 实现优雅停止
    wait_for_shutdown().await?;
    token.cancel();
    actor.shutdown();
    server.await??;

    // P0-1：清理单实例 PID 文件（尽力而为，异常不阻塞退出）
    let pid_file = daemon_pid_file();
    if daoti_common::process::read_pid_file(&pid_file) == Some(std::process::id()) {
        let _ = std::fs::remove_file(&pid_file);
    }

    tracing::info!("驭灵内核已优雅退出");
    Ok(())
}

/// P0-1 单实例锁：若已有存活守护进程则拒绝启动，并写入当前进程 PID。
///
/// 陈旧 PID 文件（进程已不存活）会被清理后重新接手，避免积重。
fn acquire_single_instance() -> anyhow::Result<()> {
    let pid_file = daemon_pid_file();
    if let Some(pid) = daoti_common::process::read_pid_file(&pid_file) {
        if pid_alive(pid) {
            anyhow::bail!(
                "驭灵内核已在运行（PID {pid}），同一守护进程仅允许单实例。\n\
                 如需重启请先执行 `daoti daemon stop` 或 `daoti daemon restart`。"
            );
        }
        // 清理陈旧 PID 文件（进程已退出）
        let _ = std::fs::remove_file(&pid_file);
    }
    write_pid_file(&pid_file, std::process::id())?;
    Ok(())
}

/// 等待系统终止信号（Ctrl+C 或 SIGTERM）
async fn wait_for_shutdown() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let ctrl_c = tokio::signal::ctrl_c();
        ctrl_c.await?;
        Ok(())
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        Ok(())
    }
}
