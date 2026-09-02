//! 决策轨迹 (daoti-core::learning::trajectory)
//!
//! 对应《PRD-驭灵》§318 记录决策轨迹（时间、卦象、指令、结果）写入本地；
//! §374 日志中禁止明文记录命令参数中的路径密钥/token，**脱敏后再写入决策轨迹**；
//! §400 决策轨迹完整落盘（时间、卦象、指令、结果、置信度）。
//!
//! `TrajectoryStore` 以 JSON Lines（每行一条记录）追加落盘，支持 `load` 回放（M6 验收"轨迹可回放"）。

use crate::elf::syscall_bridge::ShadowInferenceRecord;
use daoti_common::DaotiError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 单条指令的执行结果摘要（脱敏后，不含 stdout/stderr 全文，仅保留成败与一行提示）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryOutcome {
    /// 脱敏后的指令
    pub command: String,
    /// 目标平台
    pub target: String,
    /// 是否成功
    pub success: bool,
    /// 结果摘要（脱敏、截断）
    pub note: String,
}

/// 一条决策轨迹记录（时间、卦象、指令、结果、置信度）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryRecord {
    /// 决策发生时间（Unix 毫秒）
    pub ts_ms: u64,
    /// 主卦名（坎/震/乾/泰）
    pub gua: String,
    /// 调度优先级（docker_first / wsl2_first / windows_first / none）
    pub priority: String,
    /// 处理路径（restart_daemon / reset_wsl / check_windows_services / no_action）
    pub pathway: String,
    /// 置信度（0~1）
    pub confidence: f64,
    /// 判词
    pub explanation: String,
    /// 脱敏后的指令清单
    pub commands: Vec<String>,
    /// 各指令执行结果摘要
    pub outcomes: Vec<TrajectoryOutcome>,
    /// 是否修复成功（二次感知确认）
    pub fixed: bool,
}

/// 决策轨迹存储：JSON Lines 追加落盘，支持回放
#[derive(Debug, Clone)]
pub struct TrajectoryStore {
    path: PathBuf,
}

impl TrajectoryStore {
    /// 新建轨迹存储（指向某落盘文件）
    pub fn new(path: impl Into<PathBuf>) -> Self {
        TrajectoryStore { path: path.into() }
    }

    /// 追加一条决策轨迹（JSON Line）
    pub fn append(&self, record: &TrajectoryRecord) -> Result<(), DaotiError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(record)?;
        let mut os = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        use std::io::Write;
        writeln!(os, "{line}")?;
        Ok(())
    }

    /// 读出全部决策轨迹（回放）；文件缺失视为空
    pub fn load(&self) -> Result<Vec<TrajectoryRecord>, DaotiError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        let mut records = Vec::new();
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(r) = serde_json::from_str::<TrajectoryRecord>(line) {
                records.push(r);
            }
            // 单行损坏跳过（不中断回放），保证轨迹可读健壮性
        }
        Ok(records)
    }

    /// 清空轨迹文件
    pub fn clear(&self) -> Result<(), DaotiError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    /// 当前轨迹落盘路径
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 敏感键名前缀（键名以这些开头即视为携带凭据，需脱敏）
const SENSITIVE_KEY_PREFIXES: &[&str] = &[
    "token", "key", "pass", "secret", "password", "apikey", "api_key", "auth", "access",
];

/// 判断一段文本是否像不透明凭据（长连续字母数字/连字符/下划线，如 hex/Base64 token）
fn looks_opaque(s: &str) -> bool {
    s.len() >= 16
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
}

/// 对指令做脱敏：掩去 `key=value` 的 value（键名敏感或 value 不透明），以及裸的不透明 token。
///
/// 遵守《PRD-驭灵》§374：路径密钥/token 禁止明文进入决策轨迹。
pub fn redact_command(cmd: &str) -> String {
    cmd.split_whitespace()
        .map(|tok| {
            if let Some(eq) = tok.find('=') {
                let (k, v) = tok.split_at(eq);
                let _ = &v;
                let key = k.trim_start_matches('-');
                let key_lower = key.to_lowercase();
                if SENSITIVE_KEY_PREFIXES
                    .iter()
                    .any(|p| key_lower.starts_with(p))
                {
                    return format!("{k}=***");
                }
                return tok.to_string();
            }
            // 裸 token：不透明长串按凭据处理
            if looks_opaque(tok) {
                return "***".to_string();
            }
            tok.to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// 将一条只读影子记录转换为可学习的决策轨迹。
/// 预测与实际操作不一致、推理失败或无实际标签时标记为未修复，禁止将其当作成功样本。
pub fn shadow_to_trajectory(record: &ShadowInferenceRecord, ts_ms: u64) -> TrajectoryRecord {
    let prediction = record
        .prediction
        .clone()
        .unwrap_or_else(|| "unknown".into());
    let actual = record.actual_windows_op.clone();
    let fixed = actual.as_deref() == Some(prediction.as_str()) && record.error.is_none();
    let note = match (&actual, &record.error) {
        (Some(actual), None) => format!("预测={} 实际={}", prediction, actual),
        (_, Some(error)) => format!("影子推理失败：{error}"),
        _ => "缺少实际宿主操作标签".into(),
    };
    TrajectoryRecord {
        ts_ms,
        gua: "shadow".into(),
        priority: "none".into(),
        pathway: "shadow_inference".into(),
        confidence: record.confidence.unwrap_or(0.0).clamp(0.0, 1.0),
        explanation: "由影子推理记录生成；仅用于离线评估，不直接驱动执行".into(),
        commands: vec![redact_command(&prediction)],
        outcomes: vec![TrajectoryOutcome {
            command: redact_command(&prediction),
            target: "shadow".into(),
            success: fixed,
            note,
        }],
        fixed,
    }
}

/// 批量转换影子记录；只保留明确标签的记录，避免无标签失败路径污染学习输入。
pub fn shadow_records_to_trajectories(
    records: &[ShadowInferenceRecord],
    ts_ms: u64,
) -> Vec<TrajectoryRecord> {
    records
        .iter()
        .filter(|record| record.actual_windows_op.is_some())
        .map(|record| shadow_to_trajectory(record, ts_ms))
        .collect()
}

/// 从决策与执行结果构建轨迹记录（自动脱敏指令与结果摘要）。
#[allow(clippy::too_many_arguments)]
pub fn build_trajectory(
    ts_ms: u64,
    gua: &str,
    priority: &str,
    pathway: &str,
    confidence: f64,
    explanation: &str,
    commands: &[String],
    outcomes: &[TrajectoryOutcome],
    fixed: bool,
) -> TrajectoryRecord {
    TrajectoryRecord {
        ts_ms,
        gua: gua.to_string(),
        priority: priority.to_string(),
        pathway: pathway.to_string(),
        confidence,
        explanation: explanation.to_string(),
        commands: commands.iter().map(|c| redact_command(c)).collect(),
        outcomes: outcomes.to_vec(),
        fixed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_sensitive_values() {
        assert_eq!(
            redact_command("curl -H token=abc123def"),
            "curl -H token=***"
        );
        assert_eq!(redact_command("--key=abcdef1234567890"), "--key=***");
        assert_eq!(redact_command("docker restart"), "docker restart");
    }

    #[test]
    fn store_append_and_replay_roundtrips() {
        let dir = std::env::temp_dir().join(format!("daoti_traj_{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let store = TrajectoryStore::new(dir.join("trajectory.jsonl"));

        let rec = build_trajectory(
            111,
            "坎",
            "docker_first",
            "restart_daemon",
            0.8,
            "通水",
            &["service docker restart --token=abcdef1234567890".into()],
            &[TrajectoryOutcome {
                command: "service docker restart --token=***".into(),
                target: "wsl2".into(),
                success: true,
                note: "ok".into(),
            }],
            true,
        );
        store.append(&rec).expect("追加失败");

        let replay = store.load().expect("回放失败");
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].gua, "坎");
        assert_eq!(replay[0].commands[0], "service docker restart --token=***");
        assert!(replay[0].fixed);
        store.clear().ok();
    }

    #[test]
    fn load_missing_file_is_empty() {
        let store = TrajectoryStore::new("__no_such_trajectory__.jsonl");
        assert!(store.load().expect("加载失败").is_empty());
    }

    #[test]
    fn shadow_records_require_labels_and_preserve_failure() {
        let labeled = ShadowInferenceRecord {
            nr: 0,
            name: "read".into(),
            prediction: Some("ReadFile".into()),
            confidence: Some(0.99),
            actual_result: Some(1),
            actual_success: true,
            actual_error: None,
            error: None,
            actual_windows_op: Some("WriteFile".into()),
        };
        let unlabeled = ShadowInferenceRecord {
            actual_windows_op: None,
            ..labeled.clone()
        };
        let records = shadow_records_to_trajectories(&[labeled.clone(), unlabeled], 42);
        assert_eq!(records.len(), 1);
        assert!(!records[0].fixed);
        assert_eq!(records[0].ts_ms, 42);
        assert!(records[0].explanation.contains("离线评估"));
    }
}
