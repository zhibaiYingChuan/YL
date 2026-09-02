//! 驭灵 · 核心层 (daoti-core)
//!
//! 纯逻辑核心：感知 / 推演 / 决策 / 执行。**不包含 `main`，不启动 tokio 运行时**，
//! 便于单元测试。依据《开发计划-TechnicalPlan.md》第 1.2 / 4 节目录结构与第 3 节开发顺序。
//!
//! 模块在对应里程碑逐步填充：
//! - M1：`sensor`（三感知器 + 状态融合）
//! - M2：`decision`（推演与调度）
//! - M3：`executor`（PlatformExecutor trait + 安全执行器）
//! - M6：`learning`（决策轨迹 + Hebbian 预留）

// trait 中的 async fn：本项目 futures 均为 Send（仅持有所属数据 + tokio process），
// 显式放行该 lint 以保持简洁的感知器契约（见《rust语言开发.md》Actor 模型约束）。
#![allow(async_fn_in_trait)]

pub mod agent;
pub mod bilateral;
pub mod codec;
pub mod decision;
pub mod elf;
pub mod engine;
pub mod executor;
pub mod glibc_knowledge;
pub mod injector;
pub mod interceptor;
pub mod m1;
pub mod macho_runtime;
pub mod mapper;
pub mod parser;
pub mod probe;
pub mod runner;
pub mod sensor;
pub mod stage5;
pub mod stage7;

// M6：学习与参数库（feature 门控，默认关闭不影响主链路，见开发计划步骤 9）
#[cfg(feature = "learning")]
pub mod learning;

// 复用公共层领域错误，避免在 core 层重复定义
pub use daoti_common::{DaotiError, DaotiEvent, EventKind};
