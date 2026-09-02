//! 远程 PE executor 的纯 Rust 契约与模拟实现。
//! 对称于 remote_macos，用于 daemon/CLI 端到端测试 PE 远程执行路径。

use serde::{Deserialize, Serialize};

/// PE 远端节点声明的能力。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeNodeCapabilities {
    pub node_id: String,
    pub os_version: String,
    pub architectures: Vec<String>,
    pub capabilities: Vec<String>,
}

/// PE 远程执行请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeRequest {
    pub request_id: String,
    pub command: String,
    pub timeout_ms: u64,
}

/// PE 远程执行响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeResponse {
    pub request_id: String,
    pub status: PeRequestStatus,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeRequestStatus {
    Succeeded,
    Failed,
    TimedOut,
}

/// 测试用模拟 PE executor：可确定性覆盖成功、超时、认证错误。
#[derive(Debug)]
pub struct MockPeExecutor {
    capabilities: PeNodeCapabilities,
    authenticated: bool,
    cancel_next: bool,
}

impl MockPeExecutor {
    pub fn new(capabilities: PeNodeCapabilities) -> Self {
        Self {
            capabilities,
            authenticated: false,
            cancel_next: false,
        }
    }

    /// 模拟认证（credential_ref 非空即成功）
    pub fn authenticate(&mut self, credential_ref: &str) -> Result<(), String> {
        if credential_ref.is_empty() {
            return Err("认证失败：凭证为空".into());
        }
        self.authenticated = true;
        Ok(())
    }

    /// 模拟执行 PE 请求
    pub fn execute(&mut self, request: PeRequest) -> Result<PeResponse, String> {
        if !self.authenticated {
            return Err("PE mock 节点未认证".into());
        }
        if request.command.trim().is_empty() {
            return Err("PE 命令不能为空".into());
        }
        if request.timeout_ms == 0 {
            return Ok(PeResponse {
                request_id: request.request_id,
                status: PeRequestStatus::TimedOut,
                stdout: String::new(),
                stderr: "超时".into(),
                exit_code: None,
            });
        }
        if self.cancel_next {
            self.cancel_next = false;
            return Ok(PeResponse {
                request_id: request.request_id,
                status: PeRequestStatus::Failed,
                stdout: String::new(),
                stderr: "已取消".into(),
                exit_code: None,
            });
        }
        Ok(PeResponse {
            request_id: request.request_id,
            status: PeRequestStatus::Succeeded,
            stdout: format!("PE mock 执行: {}", request.command),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    pub fn capabilities(&self) -> &PeNodeCapabilities {
        &self.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> PeNodeCapabilities {
        PeNodeCapabilities {
            node_id: "mock-pe".into(),
            os_version: "Windows 11".into(),
            architectures: vec!["x86_64".into()],
            capabilities: vec!["execute".into()],
        }
    }

    #[test]
    fn mock_pe_execute_success() {
        let mut ex = MockPeExecutor::new(node());
        ex.authenticate("token").unwrap();
        let resp = ex
            .execute(PeRequest {
                request_id: "r1".into(),
                command: "test.exe".into(),
                timeout_ms: 1000,
            })
            .unwrap();
        assert_eq!(resp.status, PeRequestStatus::Succeeded);
        assert_eq!(resp.exit_code, Some(0));
    }

    #[test]
    fn mock_pe_execute_timeout() {
        let mut ex = MockPeExecutor::new(node());
        ex.authenticate("token").unwrap();
        let resp = ex
            .execute(PeRequest {
                request_id: "r2".into(),
                command: "test.exe".into(),
                timeout_ms: 0,
            })
            .unwrap();
        assert_eq!(resp.status, PeRequestStatus::TimedOut);
    }

    #[test]
    fn mock_pe_auth_failure() {
        let mut ex = MockPeExecutor::new(node());
        let err = ex.authenticate("").unwrap_err();
        assert!(err.contains("凭证为空"));
    }

    #[test]
    fn mock_pe_not_authenticated() {
        let mut ex = MockPeExecutor::new(node());
        let err = ex
            .execute(PeRequest {
                request_id: "r3".into(),
                command: "test.exe".into(),
                timeout_ms: 1000,
            })
            .unwrap_err();
        assert!(err.contains("未认证"));
    }
}
