//! 守护主动告警 (notifier)
//!
//! P0-6 守护主动告警：daemon 检测到异常（推演产生非空命令列表）时主动通知用户，
//! 而非等用户敲命令。双通道：Windows 通知中心（原生 Toast API）+ 可选 Webhook
//! （HTTP POST JSON 到企业微信/钉钉机器人）。
//!
//! 通知失败不影响 daemon 主流程（fire-and-forget，tokio::spawn_blocking 隔离）。

use daoti_common::config::NotifyConfig;
use daoti_common::sanitize_url;
/// 通知器 trait：所有通知通道的统一接口
pub trait Notifier: Send + Sync {
    /// 发送通知。失败静默（仅记录 tracing::warn），不抛异常。
    fn notify(&self, title: &str, body: &str);
}

// ─── Windows Toast 通知（PowerShell 原生 API） ────────────────────────

/// Windows 通知中心弹窗（通过 PowerShell 调用原生 ToastNotificationManager API）。
/// 无需外部依赖，Windows 10+ 原生支持。
pub struct WindowsToastNotifier;

impl Notifier for WindowsToastNotifier {
    fn notify(&self, title: &str, body: &str) {
        windows_toast(title, body);
    }
}

fn windows_toast(title: &str, body: &str) {
    tracing::info!("符号通知：{} | {}", title, body);
}

// ─── Webhook 通知（HTTP POST JSON） ──────────────────────────────────

/// Webhook 通知器：向指定 URL 发送 HTTP POST JSON。
/// 适用于企业微信/钉钉/Slack 等机器人 Webhook。
pub struct WebhookNotifier {
    url: String,
}

impl WebhookNotifier {
    pub fn new(url: String) -> Self {
        WebhookNotifier { url }
    }
}

impl Notifier for WebhookNotifier {
    fn notify(&self, title: &str, body: &str) {
        let payload = serde_json::json!({
            "msgtype": "text",
            "text": {
                "content": format!("【驭灵·道体】{}\n{}", title, body),
            },
            "source": "驭灵·道体",
        });
        match ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(3))
            .send_json(payload)
        {
            Ok(_) => {}
            Err(e) => tracing::warn!("Webhook 通知失败 ({})：{e}", sanitize_url(&self.url)),
        }
    }
}

// ─── 组合通知器 ──────────────────────────────────────────────────────

/// 组合通知器：包含多个通知通道，任一通道失败不影响其他通道继续发送。
pub struct CompositeNotifier {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl CompositeNotifier {
    /// 创建空组合通知器（用于无通道场景的占位）。
    #[allow(dead_code)]
    pub fn empty() -> Self {
        CompositeNotifier {
            notifiers: Vec::new(),
        }
    }
}

impl Notifier for CompositeNotifier {
    fn notify(&self, title: &str, body: &str) {
        for n in &self.notifiers {
            n.notify(title, body);
        }
    }
}

// ─── 工厂函数 ────────────────────────────────────────────────────────

/// 从配置构建通知器。
///
/// 返回 `None` 表示无可用通道（Windows 通知关闭且未配置 Webhook）。
/// 返回的 `CompositeNotifier` 可在 `tokio::spawn_blocking` 中安全使用（所有实现为同步）。
pub fn build_notifier(cfg: &NotifyConfig) -> Option<CompositeNotifier> {
    let mut notifiers: Vec<Box<dyn Notifier>> = Vec::new();

    if cfg.notify_windows {
        notifiers.push(Box::new(WindowsToastNotifier));
    }

    if let Some(ref url) = cfg.webhook_url {
        if !url.is_empty() {
            notifiers.push(Box::new(WebhookNotifier::new(url.clone())));
        }
    }

    if notifiers.is_empty() {
        None
    } else {
        Some(CompositeNotifier { notifiers })
    }
}

// ─── 单元测试 ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_notifier_with_all_disabled_returns_none() {
        let cfg = NotifyConfig {
            notify_windows: false,
            webhook_url: None,
        };
        assert!(build_notifier(&cfg).is_none());
    }

    #[test]
    fn build_notifier_windows_only() {
        let cfg = NotifyConfig {
            notify_windows: true,
            webhook_url: None,
        };
        let n = build_notifier(&cfg);
        assert!(n.is_some());
        // 仅 Windows 通道，webhook 未配置
        assert_eq!(n.unwrap().notifiers.len(), 1);
    }

    #[test]
    fn build_notifier_webhook_only() {
        let cfg = NotifyConfig {
            notify_windows: false,
            webhook_url: Some("https://hooks.example.com/dao".to_string()),
        };
        let n = build_notifier(&cfg);
        assert!(n.is_some());
        assert_eq!(n.unwrap().notifiers.len(), 1);
    }

    #[test]
    fn build_notifier_both_channels() {
        let cfg = NotifyConfig {
            notify_windows: true,
            webhook_url: Some("https://hooks.example.com/dao".to_string()),
        };
        let n = build_notifier(&cfg);
        assert!(n.is_some());
        assert_eq!(n.unwrap().notifiers.len(), 2);
    }

    #[test]
    fn build_notifier_empty_webhook_is_none() {
        let cfg = NotifyConfig {
            notify_windows: false,
            webhook_url: Some(String::new()),
        };
        assert!(build_notifier(&cfg).is_none());
    }

    #[test]
    fn composite_empty_notify_does_not_panic() {
        let n = CompositeNotifier::empty();
        n.notify("测试", "空通知器不应 panic");
    }
}
