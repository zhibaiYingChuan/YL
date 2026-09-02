//! 驭灵 · 玄镜 UI 宿主 (daoti-ui)
//!
//! 对应《产品形态.md》"玄镜控制台"、《驭灵 UIUX 设计规范.md》与《开发计划》§8
//! （可选交付，Tauri 宿主 + Bun 前端）。
//!
//! - 启用 `ui` feature：作为 Tauri 桌面宿主运行，加载 `daoti-ui-web/dist` 前端，
//!   前端经 HTTP/SSE 只读消费 daemon 事件（R8 单一数据源），宿主自身不采集状态、不执行系统命令。
//! - 未启用 `ui` feature：保留轻量占位二进制，保证 `cargo build --workspace` 默认通过。

#[cfg(feature = "ui")]
mod setup;

/// 玄镜启动时自动拉起守护进程（打包后与主程序同目录的 `daoti-daemon` sidecar）。
///
/// - daemon 为常驻守护，独立于玄镜生命周期（玄镜退出后仍继续守护）。
/// - daemon 自身具备单实例锁：若已运行，本函数 spawn 的新进程会立即退出，幂等无害。
#[cfg(feature = "ui")]
fn spawn_daemon() {
    use std::process::Command;

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let dir = match exe.parent() {
        Some(d) => d.to_path_buf(),
        None => return,
    };

    let daemon = dir.join("daoti-daemon.exe");
    if !daemon.exists() {
        tracing::warn!(
            "未找到守护进程 sidecar（开发模式请手动运行 daoti daemon start）：{}",
            daemon.display()
        );
        return;
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW：后台拉起，不弹出控制台窗口
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        match Command::new(&daemon)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
        {
            Ok(_) => tracing::info!("守护进程已自动启动：{}", daemon.display()),
            Err(e) => tracing::warn!("守护进程自动启动失败（可能已运行）：{e}"),
        }
    }
}

#[cfg(feature = "ui")]
fn main() {
    daoti_common::logging::init(&daoti_common::config::Config::default().log);
    tracing::info!("玄镜 Tauri 宿主启动：加载 daoti-ui-web/dist");

    tauri::Builder::default()
        .setup(|_app| {
            // 玄镜启动即拉起 daemon，保证「装上就能用」（状态栏直接显示「道体已感应」）
            spawn_daemon();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            setup::setup_status,
            setup::run_setup,
            setup::get_daemon_token,
            setup::pick_binary,
        ])
        .run(tauri::generate_context!())
        .expect("玄镜宿主启动失败");
}

#[cfg(not(feature = "ui"))]
fn main() {
    daoti_common::logging::init(&daoti_common::config::Config::default().log);
    eprintln!(
        "玄镜 UI 占位：未启用 Tauri 宿主。\n\
         启用方法：cargo build -p daoti-ui --features ui（需先构建 daoti-ui-web 前端产物）"
    );
}
