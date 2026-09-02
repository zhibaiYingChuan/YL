//! 首次运行设置 (daoti-ui::setup)
//!
//! P0-2 打包安装链路：Tauri 命令供前端调用，实现首次向导自动探测三系统、
//! 生成配置文件、启动守护进程。复用 `daoti_core::probe` 探测能力。

use serde::Serialize;

/// 首次运行状态响应
#[derive(Serialize)]
pub struct SetupStatus {
    /// 配置文件是否已存在
    pub config_exists: bool,
    /// 配置路径
    pub config_path: String,
}

/// 设置执行结果
#[derive(Serialize)]
pub struct SetupResult {
    /// 是否成功
    pub success: bool,
    /// 探测摘要
    pub summary: String,
    /// 错误信息（仅失败时）
    pub error: Option<String>,
    /// 五行健康度（探测后）
    pub health: SetupHealth,
}

#[derive(Serialize)]
pub struct SetupHealth {
    pub metal: f64,
    pub wood: f64,
    pub water: f64,
}

/// 检查首次运行状态：配置文件是否已存在。
#[tauri::command]
pub fn setup_status() -> SetupStatus {
    let path = daoti_common::config::Config::default_path();
    SetupStatus {
        config_exists: path.exists(),
        config_path: path.display().to_string(),
    }
}

/// 读取 daemon 写端点鉴权 token（S2：前端写请求需携带 X-Daoti-Token）。
///
/// 与 daemon 共用 `ensure_daemon_token`，保证两者读取同一文件、同一 token
/// （幂等：已存在则读取，不存在则生成并持久化到 `~/.daoti/daemon.token`）。
#[tauri::command]
pub fn get_daemon_token() -> String {
    daoti_common::config::ensure_daemon_token()
}

/// 打开系统文件选择对话框，返回用户选中的二进制文件绝对路径。
///
/// 供前端「道体·通」面板选择二进制，取绝对路径提交给 daemon（消除相对路径
/// 在 daemon 进程 cwd 下解析失败的歧义）。取消选择返回 None。
#[tauri::command]
pub fn pick_binary() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("选择要运行的二进制文件")
        .pick_file()
        .map(|p| p.to_string_lossy().to_string())
}

/// 执行首次运行设置：探测三系统 → 写配置 → 返回结果。
///
/// 探测失败项回退默认值（绝不 panic）。前端收到结果后可引导用户启动守护进程。
#[tauri::command]
pub async fn run_setup() -> SetupResult {
    // 异步探测三系统（复用 probe.rs 探测能力）
    let cfg = daoti_core::probe::build_probed_config().await;

    // 写入默认配置路径
    let path = daoti_common::config::Config::default_path();
    match cfg.write_to_file(&path) {
        Ok(()) => {
            tracing::info!("首次设置完成：配置已写入 {}", path.display());
            // 计算初始健康度（基于探测结果的模拟状态，探测后需实际感知才能准确）
            let h = daoti_core::sensor::WuxingHealth {
                metal: 1.0,
                wood: 1.0,
                water: 1.0,
            };
            SetupResult {
                success: true,
                summary: format!(
                    "三系统已定位：WSL2({}) Docker({}) | 配置已写入 {}",
                    cfg.paths.wsl_distro,
                    cfg.targets.docker_service,
                    path.display()
                ),
                error: None,
                health: SetupHealth {
                    metal: h.metal,
                    wood: h.wood,
                    water: h.water,
                },
            }
        }
        Err(e) => {
            tracing::warn!("首次设置写入配置失败: {e}");
            SetupResult {
                success: false,
                summary: String::new(),
                error: Some(format!("配置写入失败：{e}")),
                health: SetupHealth {
                    metal: 0.0,
                    wood: 0.0,
                    water: 0.0,
                },
            }
        }
    }
}
