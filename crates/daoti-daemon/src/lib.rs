//! 驭灵 · 内核公共库 (daoti-daemon lib)
//!
//! 将 daemon 核心模块暴露为公共 API，供集成测试引用。
//! 主二进制入口仍为 `main.rs`，通过 `daoti_daemon::*` 引用本库。

pub mod eventbus;
pub mod eventlog;
pub mod executor;
pub mod http;
