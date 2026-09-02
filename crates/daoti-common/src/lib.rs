//! 驭灵 · 公共层 (daoti-common)
//!
//! 本 crate 是整个 workspace 的最底层，**禁止依赖任何业务 crate**。
//! 依据《rust语言开发.md》施工蓝图：错误统一 `anyhow + thiserror`，全局禁用 `.unwrap()/expect()`。
//!
//! 对应《开发计划-TechnicalPlan.md》步骤 2：通用层。

pub mod config;
pub mod error;
pub mod event;
pub mod format;
pub mod logging;
pub mod process;

pub use error::DaotiError;
pub use event::{DaotiEvent, EventKind};
// P2-4 日志脱敏工具
pub use logging::{sanitize_url, truncate_output, truncate_output_with_hint};
