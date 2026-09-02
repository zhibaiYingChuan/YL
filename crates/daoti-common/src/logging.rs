//! 结构化日志初始化 (daoti-common::logging)
//!
//! P0-3 日志落盘与轮转：统一的 tracing 入口，支持文件轮转（daily/hourly/never）
//! 与 stderr 双写。日志目录自动创建，轮转策略与保留数由 Config::log 控制。
//!
//! P2-4 日志脱敏工具：`sanitize_url` 截断 Webhook/Token 等敏感信息，
//! `truncate_output` 限制命令输出长度，防止敏感信息泄露到日志。

use std::io;

use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::{LogConfig, LogRotation};

/// 初始化日志（双写：stderr + 文件轮转，层级由 `RUST_LOG` 控制）。
///
/// - 文件写入 `cfg.dir`，按 `cfg.rotation` 轮转，保留 `cfg.max_files` 个文件。
/// - 目录不存在时自动创建（不 panic）。
/// - stderr 输出保持 compact 格式（无颜色脱敏，节省终端空间）。
///
/// 注意：本函数仅允许调用一次（tracing-subscriber 全局单例）。
/// 调用两次会导致 panic（或后续调用被忽略，取决于版本行为）。
pub fn init(cfg: &LogConfig) {
    // 确保日志目录存在
    if let Err(e) = std::fs::create_dir_all(&cfg.dir) {
        eprintln!("[daoti] 无法创建日志目录 {}: {e}", cfg.dir.display());
        // 回退：仅输出到 stderr
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .try_init();
        return;
    }

    let rotation = match cfg.rotation {
        LogRotation::Daily => Rotation::DAILY,
        LogRotation::Hourly => Rotation::HOURLY,
        LogRotation::Never => Rotation::NEVER,
    };

    let file_appender = match RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(&cfg.file_prefix)
        .max_log_files(cfg.max_files as usize)
        .build(&cfg.dir)
    {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[daoti] 无法创建日志文件追加器: {e}");
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .compact()
                .try_init();
            return;
        }
    };

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // 文件层：含目标模块名，无 ANSI 颜色（文件不宜含转义码）
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_ansi(false);

    // stderr 层：compact 格式，无目标模块（与旧行为兼容）
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_target(false)
        .compact();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(stderr_layer)
        .init();

    // 守卫必须在程序生命周期内保持存活（非阻塞 writer 的后台线程依赖它）
    // 泄漏是合理的：logging 在 main 启动后即初始化，与程序同寿。
    std::mem::forget(guard);
}

/// 程序版本号（M0 验收：`daoti --version`）
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── P2-4 日志脱敏工具 ──────────────────────────────────────────────────

/// 日志行最大长度：输出超过此长度的命令输出将被截断
const MAX_LOG_LINE: usize = 256;

/// 截断 URL 中的敏感部分（保留域名，隐去路径和参数中的 token/密钥）。
///
/// Webhook URL 形如 `https://hooks.example.com/webhook?token=abc123`，
/// 日志中仅记录 `https://hooks.example.com/…`。
pub fn sanitize_url(url: &str) -> String {
    if url.len() <= 40 {
        return url.to_string();
    }
    // 截断 protocol + domain 之后的部分
    if let Some(pos) = url.find("://") {
        let rest = &url[pos + 3..];
        if let Some(slash) = rest.find('/') {
            return format!("{}://{}/…", &url[..pos], &rest[..slash]);
        }
    }
    format!("{}…", &url[..40])
}

/// 截断过长的命令输出文本，防止日志膨胀或无意中泄露敏感信息。
///
/// 保留前 `MAX_LOG_LINE` 个字符，超出部分替换为 `…（截断N字）`。
/// 空文本返回原样。
pub fn truncate_output(text: &str) -> &str {
    if text.len() <= MAX_LOG_LINE {
        return text;
    }
    // 找到第 MAX_LOG_LINE 个字符的边界（Rust 字符串索引按字节偏移，
    // 但 MAX_LOG_LINE 字符范围内的 UTF-8 中日文均在 3 字节以内，安全）
    let end = text
        .char_indices()
        .nth(MAX_LOG_LINE)
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    &text[..end]
}

/// 截断过长的命令输出，并附加截断提示。
/// `text` 为原始输出文本，返回 `<截断文本>…（截断N字）` 格式的 String。
pub fn truncate_output_with_hint(text: &str) -> String {
    if text.len() <= MAX_LOG_LINE {
        return text.to_string();
    }
    let skipped = text.len().saturating_sub(MAX_LOG_LINE);
    format!("{}…（截断{}字）", truncate_output(text), skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn sanitize_url_truncates_path() {
        let url = "https://hooks.example.com/webhook/abc123def456";
        let s = sanitize_url(url);
        assert!(s.starts_with("https://hooks.example.com/"));
        assert!(s.ends_with("…"));
        assert!(s.len() < url.len());
    }

    #[test]
    fn sanitize_url_short_url_passthrough() {
        let url = "https://example.com";
        assert_eq!(sanitize_url(url), url);
    }

    #[test]
    fn sanitize_url_no_slash_truncates() {
        let url = "https://very-long-domain-name-that-exceeds-40-chars.example.com";
        let s = sanitize_url(url);
        assert!(s.len() <= 43, "截断后应 ≤ 43 字符: {}", s.len());
    }

    #[test]
    fn truncate_output_short_passthrough() {
        assert_eq!(truncate_output("hello"), "hello");
    }

    #[test]
    fn truncate_output_cuts_excess() {
        let long = "x".repeat(400);
        let t = truncate_output(&long);
        assert_eq!(t.len(), MAX_LOG_LINE);
    }

    #[test]
    fn truncate_output_with_hint_shows_skipped() {
        let long = "x".repeat(300);
        let t = truncate_output_with_hint(&long);
        assert!(t.contains("（截断44字）"));
        assert!(t.len() > MAX_LOG_LINE);
    }

    #[test]
    fn truncate_output_with_hint_short_no_hint() {
        let short = "hello";
        let t = truncate_output_with_hint(short);
        assert_eq!(t, short);
        assert!(!t.contains("截断"));
    }
}
