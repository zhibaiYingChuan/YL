//! 学习与参数库 (daoti-core::learning)
//!
//! 对应《开发计划-TechnicalPlan.md》步骤 9（M6）：
//! - `trajectory`：决策轨迹持久化（JSON Lines 落盘 + 回放 + 指令脱敏）
//! - `hebbian`：Hebbian 学习预留接口（确定性默认实现）
//! - `params`：轻量参数库加载/保存（CPU 浮点）
//!
//! 本模块整体以 `learning` feature 门控（默认关闭），保证主链路不受影响（M6 验收"默认关闭不影响主链路"）。

pub mod hebbian;
pub mod params;
pub mod slow;
pub mod trajectory;

pub use hebbian::{HebbianLearner, HebbianRule, MAX_WEIGHT, MIN_WEIGHT};
pub use params::{LibraryParams, ParameterLibrary};
pub use slow::{LearnReport, SlowLearner};
pub use trajectory::{redact_command, TrajectoryOutcome, TrajectoryRecord, TrajectoryStore};
