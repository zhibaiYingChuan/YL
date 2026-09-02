//! 双梯形网络增强（道体·化）模块组
//!
//! 对应《模式B-B2双梯形网络增强开发计划.md》：
//! - `weights`：B2-1 权重加载器（自定义二进制格式）
//! - `network`：B2-2 纯数学变换（`BilateralLadderNetwork::forward`）
//! - `gate`：B2-5 上线裁决（四条件）
//!
//! 职责边界：本模块组 = 「将」，只做纯数学变换与数据结构，不决策、不降级、不读配置。

pub mod gate;
pub mod network;
pub mod weights;
