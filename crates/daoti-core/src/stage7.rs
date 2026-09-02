//! 阶段 7：可复现发布前置检查与证据清单。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreflightCheck {
    pub name: String,
    pub command: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreflightReport {
    pub version: String,
    pub workspace: String,
    pub checks: Vec<PreflightCheck>,
    pub passed: bool,
}

impl PreflightReport {
    pub fn new(version: impl Into<String>, workspace: impl Into<PathBuf>) -> Self {
        Self {
            version: version.into(),
            workspace: workspace.into().display().to_string(),
            checks: Vec::new(),
            passed: true,
        }
    }

    pub fn record(&mut self, name: &str, command: &str, result: Result<(), String>) {
        let (status, detail) = match result {
            Ok(()) => ("passed", "通过".into()),
            Err(error) => {
                self.passed = false;
                ("failed", error)
            }
        };
        self.checks.push(PreflightCheck {
            name: name.into(),
            command: command.into(),
            status: status.into(),
            detail,
        });
    }

    pub fn write_json(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(
            path,
            serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
}

pub fn validate_release_version(version: &str) -> Result<(), String> {
    let parts: Vec<_> = version
        .strip_prefix('v')
        .unwrap_or(version)
        .split('.')
        .collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || part.parse::<u64>().is_err())
    {
        return Err("版本必须符合 v<major>.<minor>.<patch>".into());
    }
    Ok(())
}

pub fn validate_release_artifacts(root: &Path, required: &[&str]) -> Result<(), String> {
    for relative in required {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(format!("缺少发布产物：{}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_artifact_checks_are_deterministic() {
        assert!(validate_release_version("v1.2.3").is_ok());
        assert!(validate_release_version("1.2.3").is_ok());
        assert!(validate_release_version("v1.2").is_err());
        let root = std::env::temp_dir().join(format!("daoti-stage7-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("daoti.exe"), b"fixture").unwrap();
        assert!(validate_release_artifacts(&root, &["daoti.exe"]).is_ok());
        assert!(validate_release_artifacts(&root, &["missing.exe"]).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn failed_check_blocks_report() {
        let mut report = PreflightReport::new("v1.2.3", ".");
        report.record("测试", "test", Err("失败原因".into()));
        assert!(!report.passed);
        assert_eq!(report.checks[0].status, "failed");
    }
}
