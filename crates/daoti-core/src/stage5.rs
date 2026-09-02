//! 阶段 5：影子记录、训练评估与权重发布的可审计生命周期。

use crate::elf::syscall_bridge::ShadowInferenceRecord;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Stage5Metrics {
    pub total: usize,
    pub predicted: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub failed: usize,
    pub labeled: usize,
    pub actual_success: usize,
    pub actual_failed: usize,
    pub accuracy: Option<f64>,
    pub coverage: f64,
    pub rejection_rate: f64,
    pub failure_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetManifest {
    pub dataset_version: String,
    pub source_path: String,
    pub source_digest: String,
    pub imported_path: String,
    pub record_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WeightRelease {
    pub version: String,
    pub weights_path: String,
    pub metrics: Stage5Metrics,
    pub source_dataset: String,
    pub published: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ReleaseState {
    pub active_version: Option<String>,
    pub releases: Vec<WeightRelease>,
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn read_records(path: &Path) -> Result<Vec<ShadowInferenceRecord>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("读取影子记录失败：{e}"))?;
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|e| format!("第 {} 行 JSON 无效：{e}", index + 1))
        })
        .collect()
}

/// 将原始 JSONL 以 create_new 方式导入，已有目标文件绝不覆盖。
pub fn import_immutable_records(
    source: &Path,
    destination: &Path,
) -> Result<DatasetManifest, String> {
    let bytes = fs::read(source).map_err(|e| format!("读取原始记录失败：{e}"))?;
    let records = read_records(source)?;
    if records.is_empty() {
        return Err("原始影子记录为空".into());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建导入目录失败：{e}"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|e| format!("创建不可变导入文件失败：{e}"))?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|e| format!("写入导入文件失败：{e}"))?;
    let source_digest = digest(&bytes);
    Ok(DatasetManifest {
        dataset_version: format!("shadow-{}", &source_digest[..12]),
        source_path: source.display().to_string(),
        source_digest,
        imported_path: destination.display().to_string(),
        record_count: records.len(),
    })
}

pub fn evaluate_records(path: &Path, threshold: f64) -> Result<Stage5Metrics, String> {
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        return Err("置信度阈值必须位于 [0, 1] 内".into());
    }
    let records = read_records(path)?;
    let total = records.len();
    let predicted = records.iter().filter(|r| r.prediction.is_some()).count();
    let accepted = records
        .iter()
        .filter(|r| r.confidence.is_some_and(|v| v >= threshold))
        .count();
    let rejected = total.saturating_sub(accepted);
    let failed = records.iter().filter(|r| r.error.is_some()).count();
    let labeled = records
        .iter()
        .filter(|r| r.actual_windows_op.is_some())
        .count();
    let actual_success = records.iter().filter(|r| r.actual_success).count();
    let actual_failed = labeled.saturating_sub(actual_success);
    let correct = records
        .iter()
        .filter(|r| {
            r.prediction.as_deref().is_some_and(|prediction| {
                r.actual_windows_op
                    .as_deref()
                    .is_some_and(|actual| prediction == actual)
            })
        })
        .count();
    Ok(Stage5Metrics {
        total,
        predicted,
        accepted,
        rejected,
        failed,
        labeled,
        actual_success,
        actual_failed,
        accuracy: (labeled > 0).then_some(correct as f64 / labeled as f64),
        coverage: if total == 0 {
            0.0
        } else {
            predicted as f64 / total as f64
        },
        rejection_rate: if total == 0 {
            0.0
        } else {
            rejected as f64 / total as f64
        },
        failure_rate: if total == 0 {
            0.0
        } else {
            failed as f64 / total as f64
        },
    })
}

pub struct ReleaseStore {
    root: PathBuf,
    state_path: PathBuf,
}

impl ReleaseStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            state_path: root.join("release-state.json"),
            root,
        }
    }

    pub fn publish(&self, release: WeightRelease) -> Result<ReleaseState, String> {
        if !release
            .version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err("权重版本包含非法字符".into());
        }
        if !Path::new(&release.weights_path).is_file() {
            return Err("权重文件不存在".into());
        }
        fs::create_dir_all(&self.root).map_err(|e| format!("创建发布目录失败：{e}"))?;
        let mut state = self.load()?;
        let mut release = release;
        release.published = true;
        state
            .releases
            .retain(|item| item.version != release.version);
        state.releases.push(release.clone());
        state.active_version = Some(release.version);
        fs::write(
            &self.state_path,
            serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("写入发布状态失败：{e}"))?;
        Ok(state)
    }

    pub fn rollback(&self, version: &str) -> Result<ReleaseState, String> {
        let mut state = self.load()?;
        if !state.releases.iter().any(|item| item.version == version) {
            return Err("回滚目标版本不存在".into());
        }
        state.active_version = Some(version.to_string());
        fs::write(
            &self.state_path,
            serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("写入回滚状态失败：{e}"))?;
        Ok(state)
    }

    pub fn load(&self) -> Result<ReleaseState, String> {
        if !self.state_path.exists() {
            return Ok(ReleaseState::default());
        }
        serde_json::from_slice(&fs::read(&self.state_path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("发布状态损坏：{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("daoti-stage5-{}-{id}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn record() -> ShadowInferenceRecord {
        ShadowInferenceRecord {
            nr: 0,
            name: "read".into(),
            prediction: Some("ReadFile".into()),
            confidence: Some(0.99),
            actual_result: Some(1),
            actual_success: true,
            actual_error: None,
            error: None,
            actual_windows_op: Some("ReadFile".into()),
        }
    }

    #[test]
    fn immutable_import_and_evaluation_are_reproducible() {
        let dir = tempdir();
        let source = dir.join("raw.jsonl");
        fs::write(&source, serde_json::to_string(&record()).unwrap() + "\n").unwrap();
        let imported = dir.join("datasets/v1.jsonl");
        let manifest = import_immutable_records(&source, &imported).unwrap();
        assert_eq!(manifest.record_count, 1);
        assert!(import_immutable_records(&source, &imported).is_err());
        let metrics = evaluate_records(&imported, 0.95).unwrap();
        assert_eq!(metrics.accuracy, Some(1.0));
        assert_eq!(metrics.accepted, 1);
    }

    #[test]
    fn release_publish_and_rollback_keep_running_artifact_paths() {
        let dir = tempdir();
        let weights = dir.join("v1.daotiblt");
        fs::write(&weights, b"weights").unwrap();
        let store = ReleaseStore::new(dir.join("releases"));
        let metrics = Stage5Metrics {
            total: 1,
            predicted: 1,
            accepted: 1,
            rejected: 0,
            failed: 0,
            labeled: 1,
            actual_success: 1,
            actual_failed: 0,
            accuracy: Some(1.0),
            coverage: 1.0,
            rejection_rate: 0.0,
            failure_rate: 0.0,
        };
        store
            .publish(WeightRelease {
                version: "v1".into(),
                weights_path: weights.display().to_string(),
                metrics: metrics.clone(),
                source_dataset: "shadow-v1".into(),
                published: false,
            })
            .unwrap();
        assert_eq!(
            store.rollback("v1").unwrap().active_version.as_deref(),
            Some("v1")
        );
    }
}
