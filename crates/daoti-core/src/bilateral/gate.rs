//! 上线裁决与注入校验 (daoti-core::bilateral::gate)
//!
//! 对应《模式B-B2双梯形网络增强开发计划.md》§3 B2-5：
//! - `B2Gate`：四条件上线裁决（`is_ready` + `unmet_reasons`）
//! - `validate_derived`：B2 推导注入的黑名单校验（仅黑名单，不复用 B1 白名单）
//!
//! 职责边界：本模块 = 「将」的裁决数据 + 校验，不做推理、不降级、不读配置。

use daoti_common::DaotiError;

/// 覆盖率上线阈值（> 80%）
pub const COVERAGE_THRESHOLD: f64 = 0.8;
/// 配对样本上线阈值（≥ 10 万）
pub const PAIRED_SAMPLES_THRESHOLD: usize = 100_000;
/// 验证成功率上线阈值（> 90%）
pub const SUCCESS_RATE_THRESHOLD: f64 = 0.9;

/// B2 推导注入的危险 Win32 操作黑名单（进程注入 / 破坏性删除）。
///
/// 与 B1 的 30 条白名单互补：B2 推导可能产出白名单之外但合法的操作
/// （如 `WSAStartup`），故校验仅拦黑名单，避免误杀合法推导。
pub const DERIVED_BLOCKLIST: [&str; 10] = [
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "VirtualAllocEx",
    "SetWindowsHookExW",
    "TerminateProcess",
    "DeleteFileW",
    "RegDeleteKeyW",
    "RegDeleteKeyExW",
    "RegDeleteTreeW",
];

/// B2 上线裁决：四条件 gate（网络推理是否参与在线决策的动态开关）。
///
/// 四条件（与计划 §3 B2-5 一致）：
/// 1. 能力开关 `enabled`
/// 2. 覆盖率 > 80%
/// 3. 配对样本 ≥ 10 万
/// 4. 验证成功率 > 90%
#[derive(Debug, Clone)]
pub struct B2Gate {
    enabled: bool,
    coverage: f64,
    paired_samples: usize,
    success_rate: f64,
}

impl B2Gate {
    /// 默认未就绪（四条件均不满足，网络旁路）。
    pub fn new() -> Self {
        B2Gate {
            enabled: false,
            coverage: 0.0,
            paired_samples: 0,
            success_rate: 0.0,
        }
    }

    /// 以显式指标构造（供测试与运行时注入指标）。
    pub fn with_metrics(
        enabled: bool,
        coverage: f64,
        paired_samples: usize,
        success_rate: f64,
    ) -> Self {
        B2Gate {
            enabled,
            coverage,
            paired_samples,
            success_rate,
        }
    }

    /// 四条件是否全部满足（网络可参与在线决策）。
    pub fn is_ready(&self) -> bool {
        self.unmet_reasons().is_empty()
    }

    /// 列出未满足的条件（空 = 已就绪），供「能解释」判词追溯。
    pub fn unmet_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.enabled {
            reasons.push("能力开关未启用（model_enabled=false）".into());
        }
        if self.coverage <= COVERAGE_THRESHOLD {
            reasons.push(format!(
                "覆盖率 {:.1}% 未达 {}% 阈值",
                self.coverage * 100.0,
                COVERAGE_THRESHOLD * 100.0
            ));
        }
        if self.paired_samples < PAIRED_SAMPLES_THRESHOLD {
            reasons.push(format!(
                "配对样本 {} 未达 {} 阈值",
                self.paired_samples, PAIRED_SAMPLES_THRESHOLD
            ));
        }
        if self.success_rate <= SUCCESS_RATE_THRESHOLD {
            reasons.push(format!(
                "验证成功率 {:.1}% 未达 {}% 阈值",
                self.success_rate * 100.0,
                SUCCESS_RATE_THRESHOLD * 100.0
            ));
        }
        reasons
    }
}

impl Default for B2Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// B2 推导注入的黑名单校验（仅黑名单，不复用 B1 白名单）。
///
/// - 命中黑名单 → `DaotiError::Blocked`（道体应降级而非注入）
/// - 未命中 → `Ok(())`（放行，含白名单之外的合法操作）
pub fn validate_derived(operation: &str) -> Result<(), DaotiError> {
    if DERIVED_BLOCKLIST
        .iter()
        .any(|blocked| operation.eq_ignore_ascii_case(blocked))
    {
        return Err(DaotiError::Blocked(operation.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认 gate 未就绪。
    #[test]
    fn gate_is_not_ready_by_default() {
        assert!(!B2Gate::new().is_ready());
    }

    /// 四条件全满足时 gate 就绪，且无未满足理由。
    #[test]
    fn gate_is_ready_when_all_conditions_met() {
        let g = B2Gate::with_metrics(true, 0.9, 100_000, 0.95);
        assert!(g.is_ready());
        assert!(g.unmet_reasons().is_empty());
    }

    /// 默认状态四条件全部未满足。
    #[test]
    fn unmet_reasons_enumerate_all_when_default() {
        assert_eq!(B2Gate::new().unmet_reasons().len(), 4);
    }

    /// 任一条件单独不满足即未就绪（含边界：coverage=0.8 不满足 > 0.8）。
    #[test]
    fn each_condition_independently_blocks() {
        assert!(!B2Gate::with_metrics(false, 0.9, 100_000, 0.95).is_ready());
        assert!(!B2Gate::with_metrics(true, 0.8, 100_000, 0.95).is_ready());
        assert!(!B2Gate::with_metrics(true, 0.9, 99_999, 0.95).is_ready());
        assert!(!B2Gate::with_metrics(true, 0.9, 100_000, 0.9).is_ready());
    }

    /// 危险 Win32 操作被黑名单拦截。
    #[test]
    fn validate_derived_blocks_dangerous_ops() {
        assert!(validate_derived("WriteProcessMemory").is_err());
        assert!(validate_derived("CreateRemoteThread").is_err());
        assert!(validate_derived("DeleteFileW").is_err());
    }

    /// 白名单之外但非黑名单的合法操作放行（如 WSAStartup）。
    #[test]
    fn validate_derived_allows_safe_ops() {
        assert!(validate_derived("WSAStartup").is_ok());
        assert!(validate_derived("ReadFile").is_ok());
        assert!(validate_derived("GetCurrentProcessId").is_ok());
    }
}
