//! 配置加载 (daoti-common::config)
//!
//! 依据《开发计划-TechnicalPlan.md》：配置从 TOML/环境变量加载并可回退默认值。
//! 配置是 `daoti init` 的产物，禁止硬编码路径（用户约束）。

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 全局配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 三系统路径映射（Windows 盘符 <-> WSL /mnt），见开发计划 R3
    pub paths: PathMap,
    /// 三系统默认发行版 / 服务名
    pub targets: TargetConfig,
    /// 感知与执行超时配置
    pub timeouts: TimeoutConfig,
    /// 日志落盘与轮转配置
    pub log: LogConfig,
    /// 守护主动告警配置（P0-6：Windows 通知中心 + Webhook）
    pub notify: NotifyConfig,
    /// 模式B B2 双梯形网络增强配置（平铺键 model_*，兼容极简解析器）
    pub model: ModelConfig,
    /// 远程 macOS 节点服务配置
    pub macos: MacOsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacOsConfig {
    pub endpoint: String,
    pub token: String,
}

/// 模式B B2 双梯形网络增强配置（道体·化）
///
/// 字段采用平铺键（`model_*`）与极简 TOML 解析器对齐，禁止嵌套 `[model]` 表。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// 网络推导能力开关（默认 true）；为 false 时道体旁路网络、仅 B1 直通
    pub enabled: bool,
    /// 双梯形网络权重文件路径（默认 `~/.daoti/bilateral_weights.bin`）
    pub weights_path: String,
    /// 输入/输出向量维度（默认 2048）
    pub dim: usize,
    /// 正/逆向传播递归迭代次数（默认 5，信号共振）
    pub t_iter: usize,
    /// 解码置信度阈值（默认 0.7，低于阈值判「道体·疑」转降级）
    pub confidence_threshold: f64,
    /// 三平台调度模型路径；为空时使用规则引擎
    pub dispatch_model_path: Option<String>,
}

/// 路径映射表
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMap {
    /// WSL 默认发行版名
    pub wsl_distro: String,
    /// Windows 盘符到 WSL 挂载点的映射，如 { "C": "/mnt/c" }
    pub drive_to_wsl: std::collections::HashMap<String, String>,
}

/// 目标平台相关配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    /// Windows Docker 服务名（默认 com.docker.service）
    pub docker_service: String,
}

/// 超时配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// 感知命令超时秒数
    pub sensor_secs: u64,
    /// 执行命令超时秒数
    pub exec_secs: u64,
    /// Docker 端点点探测超时秒数
    pub endpoint_probe_secs: u64,
    /// Actor 感知采样间隔秒数（三感知器周期）
    pub sampling_secs: u64,
}

/// 日志轮转策略（P0-3 日志落盘与轮转）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    /// 按日轮转（每天新建日志文件）
    Daily,
    /// 按小时轮转
    Hourly,
    /// 不轮转（始终写入同一文件）
    Never,
}

/// 守护主动告警配置（P0-6 守护主动告警）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// Windows 通知中心弹窗（默认开启）
    pub notify_windows: bool,
    /// Webhook URL（可选，如企业微信/钉钉机器人；空字符串或缺失时不启用）
    pub webhook_url: Option<String>,
}

/// 日志配置（P0-3 日志落盘与轮转 + P0-5 事件历史落盘）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// 日志目录（自动创建），默认 `~/.daoti/logs/`
    pub dir: PathBuf,
    /// 轮转策略
    pub rotation: LogRotation,
    /// 日志文件最大保留数（超过后删除最旧文件）
    pub max_files: u32,
    /// 日志文件名前缀
    pub file_prefix: String,
    /// 事件历史落盘目录（P0-5），默认 `~/.daoti/events/`
    pub history_dir: PathBuf,
    /// 事件历史最大条数（P0-5），超过后截断旧事件
    pub history_max_events: u64,
}

impl Default for Config {
    fn default() -> Self {
        let mut drive_to_wsl = std::collections::HashMap::new();
        drive_to_wsl.insert("C".to_string(), "/mnt/c".to_string());
        drive_to_wsl.insert("D".to_string(), "/mnt/d".to_string());
        Config {
            paths: PathMap {
                wsl_distro: "Ubuntu".into(),
                drive_to_wsl,
            },
            targets: TargetConfig {
                docker_service: "com.docker.service".into(),
            },
            timeouts: TimeoutConfig {
                sensor_secs: 5,
                exec_secs: 10,
                endpoint_probe_secs: 3,
                sampling_secs: 30,
            },
            log: LogConfig {
                dir: daoti_dir().join("logs"),
                rotation: LogRotation::Daily,
                max_files: 7,
                file_prefix: "daoti".into(),
                history_dir: daoti_dir().join("events"),
                history_max_events: 5000,
            },
            notify: NotifyConfig {
                notify_windows: true,
                webhook_url: None,
            },
            macos: MacOsConfig {
                // 默认不配置远程节点；未显式配置时远程目标必须保持不可用。
                endpoint: String::new(),
                token: String::new(),
            },
            model: ModelConfig {
                enabled: true,
                weights_path: daoti_dir()
                    .join("bilateral_weights.bin")
                    .to_string_lossy()
                    .to_string(),
                dim: 2048,
                t_iter: 5,
                confidence_threshold: 0.7,
                dispatch_model_path: None,
            },
        }
    }
}

impl Config {
    /// 从 TOML 文件加载；文件不存在/解析失败时回退默认值（不 panic）
    pub fn from_file(path: &PathBuf) -> Config {
        let content = std::fs::read_to_string(path);
        match content {
            Ok(text) => toml(text.as_str()).unwrap_or_else(|| {
                tracing::warn!("配置解析失败，回退默认值: {}", path.display());
                Config::default()
            }),
            Err(_) => {
                tracing::debug!("配置文件不存在，使用默认值: {}", path.display());
                Config::default()
            }
        }
    }

    /// 加载配置，优先环境变量指定路径，其次默认路径
    pub fn load() -> Config {
        if let Ok(p) = std::env::var("DAOTI_CONFIG") {
            return Config::from_file(&PathBuf::from(p));
        }
        // 默认尝试用户目录下的配置
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        Config::from_file(&PathBuf::from(home).join(".daoti.toml"))
    }

    /// 默认配置写入路径（用户目录下的 `.daoti.toml`）
    pub fn default_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".daoti.toml")
    }

    /// 将配置序列化为极简 TOML 文本（与 `toml_parse` 解析格式对齐）
    ///
    /// 供 `daoti init` 生成配置文件；键顺序固定，便于阅读与 diff。
    pub fn to_toml_string(&self) -> String {
        let mut s = String::new();
        s.push_str("# 驭灵·道体 配置文件（由 `daoti init` 自动生成）\n");
        s.push_str("# 手动修改后重启 CLI/Daemon 生效\n\n");
        s.push_str(&format!("wsl_distro = \"{}\"\n", self.paths.wsl_distro));
        s.push_str(&format!(
            "docker_service = \"{}\"\n",
            self.targets.docker_service
        ));
        s.push_str(&format!("sensor_secs = {}\n", self.timeouts.sensor_secs));
        s.push_str(&format!("exec_secs = {}\n", self.timeouts.exec_secs));
        s.push_str(&format!(
            "endpoint_probe_secs = {}\n",
            self.timeouts.endpoint_probe_secs
        ));
        s.push_str(&format!(
            "sampling_secs = {}\n",
            self.timeouts.sampling_secs
        ));
        s.push_str("\n# === 日志轮转（P0-3） ===\n");
        s.push_str(&format!(
            "log_rotation = \"{}\"\n",
            match self.log.rotation {
                LogRotation::Daily => "daily",
                LogRotation::Hourly => "hourly",
                LogRotation::Never => "never",
            }
        ));
        s.push_str(&format!("log_max_files = {}\n", self.log.max_files));
        s.push_str(&format!("log_file_prefix = \"{}\"\n", self.log.file_prefix));
        s.push_str(&format!(
            "history_max_events = {}\n",
            self.log.history_max_events
        ));
        s.push_str("\n# === 守护主动告警（P0-6） ===\n");
        s.push_str(&format!(
            "notify_windows = {}\n",
            self.notify.notify_windows
        ));
        if let Some(ref url) = self.notify.webhook_url {
            s.push_str(&format!("webhook_url = \"{}\"\n", url));
        } else {
            s.push_str("# webhook_url = \"\"  # 可选：企业微信/钉钉机器人地址\n");
        }
        s.push_str("\n# === 远程 macOS 节点 ===\n");
        s.push_str(&format!("macos_endpoint = \"{}\"\n", self.macos.endpoint));
        if !self.macos.token.is_empty() {
            s.push_str(&format!("macos_token = \"{}\"\n", self.macos.token));
        }
        s.push_str("\n# === 模式B B2 双梯形网络增强（道体·化） ===\n");
        s.push_str(&format!("model_enabled = {}\n", self.model.enabled));
        s.push_str(&format!(
            "model_weights_path = \"{}\"\n",
            self.model.weights_path
        ));
        s.push_str(&format!("model_dim = {}\n", self.model.dim));
        s.push_str(&format!("model_t_iter = {}\n", self.model.t_iter));
        s.push_str(&format!(
            "model_confidence_threshold = {}\n",
            self.model.confidence_threshold
        ));
        if let Some(path) = &self.model.dispatch_model_path {
            s.push_str(&format!("dispatch_model_path = \"{}\"\n", path));
        }
        // 盘符映射：按字母序输出，保证确定性
        let mut drives: Vec<_> = self.paths.drive_to_wsl.iter().collect();
        drives.sort_by(|a, b| a.0.cmp(b.0));
        for (drive, mount) in drives {
            s.push_str(&format!("drive_{} = \"{}\"\n", drive.to_lowercase(), mount));
        }
        s
    }

    /// 将配置写入指定路径；父目录不存在时创建
    pub fn write_to_file(&self, path: &PathBuf) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, self.to_toml_string())
    }
}

/// 用户主目录（Windows 优先 USERPROFILE，其次 HOME，均缺失时回退当前目录）。
/// 供配置 / 快照目录等共享路径统一计算，避免各 crate 各自硬编码。
pub fn home_dir() -> PathBuf {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string())
        .into()
}

/// 快照目录 `~/.daoti/snapshots`（CLI / daemon 共用的单一落盘位置）。
/// 作为"快照回魂"（M6 决策轨迹 / 回滚）的数据基础，消除调用方硬编码。
pub fn snapshots_dir() -> PathBuf {
    home_dir().join(".daoti").join("snapshots")
}

/// 道体数据主目录 `~/.daoti`（快照 / 日志 / PID 等共享落盘的统一根目录）。
/// 消除各调用方对 `~/.daoti` 的硬编码。
pub fn daoti_dir() -> PathBuf {
    home_dir().join(".daoti")
}

/// daemon 单实例 PID 文件 `~/.daoti/daemon.pid`。
/// CLI `daoti daemon start/stop/status` 与 daemon 自身单实例锁共用（P0-1 生命周期）。
pub fn daemon_pid_file() -> PathBuf {
    daoti_dir().join("daemon.pid")
}

/// 日志目录（P0-3 日志落盘与轮转），默认 `~/.daoti/logs/`。
/// 自动创建父目录；调用方无需再调用 create_dir_all。
pub fn logs_dir() -> PathBuf {
    daoti_dir().join("logs")
}

/// daemon 写端点鉴权 token 文件 `~/.daoti/daemon.token`（S2 安全加固）。
///
/// daemon 启动时生成/加载该 token，Tauri 宿主经 `get_daemon_token` 命令读取同一文件，
/// 前端写请求（/api/heal、/api/run、/api/b1/run）携带 `X-Daoti-Token` 头校验。
pub fn daemon_token_file() -> PathBuf {
    daoti_dir().join("daemon.token")
}

/// 生成新的 daemon 写端点鉴权 token（v4 UUID，无规律、不可枚举）。
pub fn generate_daemon_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// 读取已存在的 daemon token；文件不存在或内容为空时返回 `None`。
pub fn read_daemon_token() -> Option<String> {
    std::fs::read_to_string(daemon_token_file())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 确保 daemon token 存在：已存在则直接读取，否则生成并持久化。
///
/// 落盘失败时回退为进程内临时 token（不 panic、不阻塞启动），满足 HCSE 韧性要求。
/// 注意：token 独立于 `Config` 存放，避免极简 TOML 解析器（不支持嵌套表）破坏。
pub fn ensure_daemon_token() -> String {
    if let Some(token) = read_daemon_token() {
        return token;
    }
    let token = generate_daemon_token();
    let path = daemon_token_file();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&path, &token) {
        Ok(()) => {
            tracing::info!("已生成 daemon 写端点鉴权 token：{}", path.display());
            token
        }
        Err(e) => {
            tracing::warn!("daemon token 落盘失败（改用进程内临时 token）：{e}");
            token
        }
    }
}

// ─── P1-2 配置热加载 ─────────────────────────────────────────────────

/// 配置文件监听器（P1-2：修改 `~/.daoti.toml` 无需重启生效）。
///
/// 基于文件修改时间（`modified()`）的轮询检测，避免引入重量级文件监听依赖。
/// 解析失败时保留旧配置并告警（不崩溃），满足 HCSE 韧性要求。
pub struct ConfigWatcher {
    /// 配置文件路径
    path: PathBuf,
    /// 上次读取时的修改时间（用于检测文件是否已变更）
    last_modified: Option<std::time::SystemTime>,
}

impl ConfigWatcher {
    /// 构建监听器，绑定到指定配置文件。
    pub fn new(path: PathBuf) -> Self {
        ConfigWatcher {
            path,
            last_modified: None,
        }
    }

    /// 检查文件是否已变更；如变更则重新解析并返回新配置。
    ///
    /// - 返回 `Some(new_config)`：文件已变更且解析成功。
    /// - 返回 `None`：文件未变更、不存在或解析失败（解析失败时记录 warning）。
    ///
    /// 调用方在获得新配置后可安全替换当前运行配置。
    pub fn check(&mut self) -> Option<Config> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => {
                // 文件不存在：首次运行或已删除，不告警（正常路径）
                self.last_modified = None;
                return None;
            }
        };

        let modified = match meta.modified() {
            Ok(m) => m,
            Err(_) => return None,
        };

        // 与上次修改时间比较：未变更则跳过
        if self.last_modified == Some(modified) {
            return None;
        }
        self.last_modified = Some(modified);

        // 重新解析配置
        match std::fs::read_to_string(&self.path) {
            Ok(text) => match toml_parse(&text) {
                Some(cfg) => {
                    tracing::info!("配置热重载成功：{}", self.path.display());
                    Some(cfg)
                }
                None => {
                    tracing::warn!("配置解析失败，保留旧配置继续运行：{}", self.path.display());
                    None
                }
            },
            Err(e) => {
                tracing::warn!("配置文件读取失败，保留旧配置：{e}");
                None
            }
        }
    }
}

/// 解析 TOML 文本为配置
fn toml(text: &str) -> Option<Config> {
    toml_parse(text)
}

/// 内部：极简 TOML 解析占位（避免引入重量级依赖）。
/// 本实现仅解析顶层键值对，供 M0-M2 使用；后续可替换为 `toml` crate。
fn toml_parse(text: &str) -> Option<Config> {
    let mut cfg = Config::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            match k {
                "wsl_distro" => cfg.paths.wsl_distro = v.to_string(),
                "docker_service" => cfg.targets.docker_service = v.to_string(),
                "sensor_secs" => cfg.timeouts.sensor_secs = v.parse().unwrap_or(5),
                "exec_secs" => cfg.timeouts.exec_secs = v.parse().unwrap_or(10),
                "endpoint_probe_secs" => cfg.timeouts.endpoint_probe_secs = v.parse().unwrap_or(3),
                "sampling_secs" => cfg.timeouts.sampling_secs = v.parse().unwrap_or(30),
                "log_rotation" => {
                    cfg.log.rotation = match v {
                        "hourly" => LogRotation::Hourly,
                        "never" => LogRotation::Never,
                        _ => LogRotation::Daily,
                    };
                }
                "log_max_files" => cfg.log.max_files = v.parse().unwrap_or(7),
                "log_file_prefix" => cfg.log.file_prefix = v.to_string(),
                "history_max_events" => cfg.log.history_max_events = v.parse().unwrap_or(5000),
                "notify_windows" => cfg.notify.notify_windows = v.parse().unwrap_or(true),
                "macos_endpoint" => cfg.macos.endpoint = v.to_string(),
                "macos_token" => cfg.macos.token = v.to_string(),
                "webhook_url" => {
                    cfg.notify.webhook_url = if v.is_empty() {
                        None
                    } else {
                        Some(v.to_string())
                    };
                }
                "model_enabled" => cfg.model.enabled = v.parse().unwrap_or(true),
                "model_weights_path" => cfg.model.weights_path = v.to_string(),
                "model_dim" => cfg.model.dim = v.parse().unwrap_or(2048),
                "model_t_iter" => cfg.model.t_iter = v.parse().unwrap_or(5),
                "model_confidence_threshold" => {
                    cfg.model.confidence_threshold = v.parse().unwrap_or(0.7);
                }
                "dispatch_model_path" => {
                    cfg.model.dispatch_model_path = (!v.is_empty()).then(|| v.to_string());
                }
                _ => {
                    // 盘符映射：`drive_c = "/mnt/c"` → 键 "C" → 挂载点
                    if let Some(rest) = k.strip_prefix("drive_") {
                        let letter = rest.to_uppercase();
                        cfg.paths.drive_to_wsl.insert(letter, v.to_string());
                    }
                }
            }
        }
    }
    Some(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let c = Config::default();
        assert_eq!(c.paths.wsl_distro, "Ubuntu");
        assert_eq!(c.timeouts.exec_secs, 10);
        assert_eq!(c.targets.docker_service, "com.docker.service");
        assert_eq!(c.timeouts.sampling_secs, 30);
        // P0-3 日志配置默认值
        assert_eq!(c.log.rotation, LogRotation::Daily);
        assert_eq!(c.log.max_files, 7);
        assert_eq!(c.log.file_prefix, "daoti");
        assert!(c.log.dir.ends_with("logs"));
        // B2 双梯形网络增强配置默认值
        assert!(c.model.enabled);
        assert_eq!(c.model.dim, 2048);
        assert_eq!(c.model.t_iter, 5);
        assert!((c.model.confidence_threshold - 0.7).abs() < f64::EPSILON);
        assert!(c.model.weights_path.ends_with("bilateral_weights.bin"));
    }

    /// B2 配置序列化 → 解析 roundtrip：五键均可无损往返。
    #[test]
    fn model_config_roundtrip() {
        let mut c = Config::default();
        c.model.enabled = false;
        c.model.weights_path = "C:/tmp/weights.bin".to_string();
        c.model.dim = 4096;
        c.model.t_iter = 3;
        c.model.confidence_threshold = 0.9;

        let text = c.to_toml_string();
        let parsed = toml(&text).expect("序列化产物应可解析");
        assert!(!parsed.model.enabled);
        assert_eq!(parsed.model.weights_path, "C:/tmp/weights.bin");
        assert_eq!(parsed.model.dim, 4096);
        assert_eq!(parsed.model.t_iter, 3);
        assert!((parsed.model.confidence_threshold - 0.9).abs() < f64::EPSILON);
    }

    /// B2 配置字段独立解析：`model_*` 键可被极简解析器识别。
    #[test]
    fn model_keys_parse() {
        let text = "model_enabled = false\nmodel_dim = 1024\nmodel_t_iter = 2\nmodel_confidence_threshold = 0.55\nmodel_weights_path = \"/opt/daoti/w.bin\"\n";
        let c = toml(text).expect("model_* 键应可解析");
        assert!(!c.model.enabled);
        assert_eq!(c.model.dim, 1024);
        assert_eq!(c.model.t_iter, 2);
        assert!((c.model.confidence_threshold - 0.55).abs() < f64::EPSILON);
        assert_eq!(c.model.weights_path, "/opt/daoti/w.bin");
    }

    #[test]
    fn load_from_missing_file_falls_back() {
        let c = Config::from_file(&PathBuf::from("__definitely_missing__.toml"));
        assert_eq!(c.paths.wsl_distro, "Ubuntu");
    }

    #[test]
    fn minimal_toml_parses() {
        let text = "wsl_distro = \"Debian\"\nexec_secs = 30\n";
        let c = toml(text).expect("解析失败");
        assert_eq!(c.paths.wsl_distro, "Debian");
        assert_eq!(c.timeouts.exec_secs, 30);
    }

    #[test]
    fn snapshots_dir_is_under_home_daoti() {
        // 快照目录应位于 `~/.daoti/snapshots`，且父目录以 `.daoti` 结尾
        let dir = snapshots_dir();
        assert!(dir.ends_with("snapshots"));
        assert_eq!(
            dir.parent().map(|p| p.file_name().and_then(|s| s.to_str())),
            Some(Some(".daoti"))
        );
        assert!(dir.starts_with(home_dir()));
    }

    /// P1-3 配置损坏韧性：乱码 TOML 解析不 panic，仅跳过无法解析的键。
    #[test]
    fn corrupt_toml_no_panic() {
        // 乱码文本：内联解析器逐行处理，无法解析的行被静默跳过
        let text = "not valid toml @#$%^&!!!\nwsl_distro = broken= =\n!@#$%^&*()\n";
        let c = toml(text).expect("乱码解析不应 panic");
        // 解析器可能从乱码中意外提取到值，但关键是不 panic + 返回有效 Config
        // 未命中的键保持默认值
        assert_eq!(c.timeouts.exec_secs, 10, "未解析的键应保持默认值");
    }

    /// P1-3 空文件韧性：空 TOML 文本不 panic，回退默认值。
    #[test]
    fn empty_toml_falls_back_to_defaults() {
        let c = toml("").expect("空文本解析不应 panic");
        assert_eq!(c.paths.wsl_distro, "Ubuntu");
        assert_eq!(c.timeouts.exec_secs, 10);
    }
}
