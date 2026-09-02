//! 远程 macOS executor 的纯 Rust 契约与模拟实现。
//! 本模块只定义协议边界，不建立网络连接，也不执行真实 macOS 命令。

use crate::executor::execution::{ExecutionReport, ExecutionTarget};
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_BINARY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Serialization(String),
    TooLarge { actual: usize, maximum: usize },
    Transport(String),
    Http(String),
    InvalidResponse(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProtocolError {}

fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
    if bytes.len() > maximum {
        return Err(ProtocolError::TooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

fn decode<T: DeserializeOwned>(bytes: &[u8], maximum: usize) -> Result<T, ProtocolError> {
    if bytes.len() > maximum {
        return Err(ProtocolError::TooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    serde_json::from_slice(bytes).map_err(|e| ProtocolError::Serialization(e.to_string()))
}

/// 远端节点声明的能力。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsNodeCapabilities {
    pub node_id: String,
    pub os_version: String,
    pub architectures: Vec<String>,
    pub capabilities: Vec<String>,
}

/// 认证材料只表达契约，不保存或打印秘密。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authentication {
    pub method: AuthMethod,
    pub credential_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    Token,
    SshKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsRequest {
    pub request_id: String,
    pub filename: String,
    pub binary_base64: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub authentication: Authentication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsResponse {
    pub request_id: String,
    pub status: RequestStatus,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestStatus {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorState {
    Disconnected,
    Ready,
    Running,
    Cancelling,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsExecutorError {
    InvalidRequest(String),
    AuthenticationFailed,
    NotReady,
    Timeout,
    Cancelled,
    Closed,
}

impl std::fmt::Display for MacOsExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MacOsExecutorError {}

/// 纯契约：真实传输层可在此之上实现，当前不承诺网络执行。
impl MacOsRequest {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        encode(self, MAX_REQUEST_BYTES)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode(bytes, MAX_REQUEST_BYTES)
    }
}

impl MacOsResponse {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        encode(self, MAX_RESPONSE_BYTES)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode(bytes, MAX_RESPONSE_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub capabilities: MacOsNodeCapabilities,
    pub authentication: Authentication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryUpload {
    pub request_id: String,
    pub filename: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHealth {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Default)]
pub struct NodeRegistry {
    nodes: BTreeMap<String, NodeRegistration>,
    health: BTreeMap<String, NodeHealth>,
}

impl NodeRegistry {
    pub fn register(&mut self, registration: NodeRegistration) {
        let id = registration.capabilities.node_id.clone();
        self.nodes.insert(id.clone(), registration);
        self.health.insert(id, NodeHealth::Unknown);
    }

    pub fn get(&self, node_id: &str) -> Option<&NodeRegistration> {
        self.nodes.get(node_id)
    }

    pub fn health_check(
        &mut self,
        node_id: &str,
        executor: &mut impl RemoteMacOsExecutor,
    ) -> NodeHealth {
        let status = if executor.state() == ExecutorState::Ready {
            NodeHealth::Healthy
        } else {
            NodeHealth::Unhealthy
        };
        self.health.insert(node_id.to_string(), status);
        status
    }

    pub fn health(&self, node_id: &str) -> NodeHealth {
        self.health
            .get(node_id)
            .copied()
            .unwrap_or(NodeHealth::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEvent {
    NodeRegistered {
        node_id: String,
    },
    RequestSent {
        request_id: String,
    },
    ResponseReceived {
        request_id: String,
        status: RequestStatus,
    },
    RequestCancelled {
        request_id: String,
    },
}

pub trait RemoteMacOsExecutor {
    fn capabilities(&self) -> &MacOsNodeCapabilities;
    fn state(&self) -> ExecutorState;
    fn authenticate(&mut self, auth: &Authentication) -> Result<(), MacOsExecutorError>;
    fn execute(&mut self, request: MacOsRequest) -> Result<MacOsResponse, MacOsExecutorError>;
    fn cancel(&mut self, request_id: &str) -> Result<(), MacOsExecutorError>;
}

/// 测试用模拟 executor：可确定性覆盖成功、超时、取消和认证错误。
#[derive(Debug)]
pub struct MockMacOsExecutor {
    capabilities: MacOsNodeCapabilities,
    state: ExecutorState,
    authenticated: bool,
    cancel_next: bool,
}

impl MockMacOsExecutor {
    pub fn new(capabilities: MacOsNodeCapabilities) -> Self {
        Self {
            capabilities,
            state: ExecutorState::Disconnected,
            authenticated: false,
            cancel_next: false,
        }
    }

    pub fn execute_report(&mut self, request: MacOsRequest) -> ExecutionReport {
        match self.execute(request) {
            Ok(response) if response.status == RequestStatus::Succeeded => {
                ExecutionReport::success()
            }
            Ok(response) => ExecutionReport::from_error(
                ExecutionTarget::RemoteMacOs,
                format!("{:?}", response.status),
                "远程执行未成功",
            ),
            Err(MacOsExecutorError::Timeout) => {
                ExecutionReport::from_error(ExecutionTarget::RemoteMacOs, "TIMEOUT", "远程执行超时")
            }
            Err(MacOsExecutorError::Cancelled) => ExecutionReport::from_error(
                ExecutionTarget::RemoteMacOs,
                "CANCELLED",
                "远程执行已取消",
            ),
            Err(MacOsExecutorError::AuthenticationFailed) => ExecutionReport::from_error(
                ExecutionTarget::RemoteMacOs,
                "AUTHENTICATION_FAILED",
                "认证失败",
            ),
            Err(MacOsExecutorError::NotReady) => ExecutionReport::from_error(
                ExecutionTarget::RemoteMacOs,
                "DISCONNECTED",
                "节点未连接",
            ),
            Err(error) => ExecutionReport::from_error(
                ExecutionTarget::RemoteMacOs,
                format!("{:?}", error),
                "远程执行失败",
            ),
        }
    }
}

impl RemoteMacOsExecutor for MockMacOsExecutor {
    fn capabilities(&self) -> &MacOsNodeCapabilities {
        &self.capabilities
    }
    fn state(&self) -> ExecutorState {
        self.state
    }
    fn authenticate(&mut self, auth: &Authentication) -> Result<(), MacOsExecutorError> {
        if auth.credential_ref.is_empty() {
            return Err(MacOsExecutorError::AuthenticationFailed);
        }
        self.authenticated = true;
        self.state = ExecutorState::Ready;
        Ok(())
    }
    fn execute(&mut self, request: MacOsRequest) -> Result<MacOsResponse, MacOsExecutorError> {
        if !self.authenticated {
            return Err(MacOsExecutorError::NotReady);
        }
        if request.filename.trim().is_empty() || request.binary_base64.trim().is_empty() {
            return Err(MacOsExecutorError::InvalidRequest(
                "Mach-O 请求不能为空".into(),
            ));
        }
        if request.timeout_ms == 0 {
            return Err(MacOsExecutorError::Timeout);
        }
        self.state = ExecutorState::Running;
        if self.cancel_next {
            self.cancel_next = false;
            self.state = ExecutorState::Ready;
            return Ok(MacOsResponse {
                request_id: request.request_id,
                status: RequestStatus::Cancelled,
                stdout: String::new(),
                stderr: String::new(),
                exit_code: None,
            });
        }
        self.state = ExecutorState::Ready;
        Ok(MacOsResponse {
            request_id: request.request_id,
            status: RequestStatus::Succeeded,
            stdout: request.filename,
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
    fn cancel(&mut self, _request_id: &str) -> Result<(), MacOsExecutorError> {
        if self.state != ExecutorState::Running {
            return Err(MacOsExecutorError::NotReady);
        }
        self.state = ExecutorState::Cancelling;
        self.cancel_next = true;
        Ok(())
    }
}

/// 通过 HTTP 调用 daemon endpoint 的真实客户端。
#[derive(Clone)]
pub struct MacOsHttpClient {
    client: reqwest::Client,
    endpoint: String,
    token: String,
}

impl MacOsHttpClient {
    pub fn new(
        endpoint: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| ProtocolError::Http(e.to_string()))?;
        let endpoint = endpoint.into().trim_end_matches('/').to_string();
        let is_loopback_http = endpoint.starts_with("http://127.0.0.1")
            || endpoint.starts_with("http://localhost")
            || endpoint.starts_with("http://[::1]");
        if endpoint.is_empty() || (!endpoint.starts_with("https://") && !is_loopback_http) {
            return Err(ProtocolError::Http(
                "macOS endpoint 必须配置为 HTTPS；本地测试仅允许回环 HTTP".into(),
            ));
        }
        let token = token.into();
        if token.is_empty() {
            return Err(ProtocolError::Http("macOS endpoint token 未配置".into()));
        }
        Ok(Self {
            client,
            endpoint,
            token,
        })
    }

    /// 探测远程节点健康；只有返回 2xx 才视为可用。
    pub async fn probe_health(&self, timeout: Duration) -> Result<(), MacOsExecutorError> {
        let response = self
            .client
            .get(format!("{}/health", self.endpoint))
            .header("X-Daoti-Token", &self.token)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    MacOsExecutorError::Timeout
                } else {
                    MacOsExecutorError::InvalidRequest(e.to_string())
                }
            })?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MacOsExecutorError::AuthenticationFailed);
        }
        if !response.status().is_success() {
            return Err(MacOsExecutorError::NotReady);
        }
        Ok(())
    }

    pub async fn register(
        &self,
        registration: &NodeRegistration,
    ) -> Result<(), MacOsExecutorError> {
        let response = self
            .client
            .post(format!("{}/register", self.endpoint))
            .header("X-Daoti-Token", &self.token)
            .json(registration)
            .send()
            .await
            .map_err(|e| MacOsExecutorError::InvalidRequest(e.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MacOsExecutorError::AuthenticationFailed);
        }
        if !response.status().is_success() {
            return Err(MacOsExecutorError::InvalidRequest(format!(
                "daemon HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    pub async fn upload(
        &self,
        upload: BinaryUpload,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), MacOsExecutorError> {
        if upload.bytes.len() > MAX_BINARY_BYTES {
            return Err(MacOsExecutorError::InvalidRequest(
                "二进制超过大小限制".into(),
            ));
        }
        let response = tokio::select! { _ = cancel.cancelled() => return Err(MacOsExecutorError::Cancelled), result = self.client.post(format!("{}/upload", self.endpoint.trim_end_matches('/'))).header("X-Daoti-Token", &self.token).json(&upload).send() => result.map_err(|e| MacOsExecutorError::InvalidRequest(e.to_string()))? };
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MacOsExecutorError::AuthenticationFailed);
        }
        if !response.status().is_success() {
            return Err(MacOsExecutorError::InvalidRequest(format!(
                "daemon HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    pub async fn execute(
        &self,
        request: MacOsRequest,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<MacOsResponse, MacOsExecutorError> {
        let decoded_binary = base64::engine::general_purpose::STANDARD
            .decode(&request.binary_base64)
            .map_err(|_| MacOsExecutorError::InvalidRequest("binary_base64 非法".into()))?;
        if request.filename.trim().is_empty()
            || decoded_binary.is_empty()
            || decoded_binary.len() > MAX_BINARY_BYTES
            || request.timeout_ms == 0
            || request.timeout_ms > 86_400_000
        {
            return Err(MacOsExecutorError::InvalidRequest(
                "命令或超时参数无效".into(),
            ));
        }
        let request_id = request.request_id.clone();
        let response = tokio::select! {
            _ = cancel.cancelled() => return Err(MacOsExecutorError::Cancelled),
            result = self.client.post(format!("{}/execute", self.endpoint))
                .header("X-Daoti-Token", &self.token)
                .json(&request)
                .timeout(Duration::from_millis(request.timeout_ms))
                .send() => result.map_err(|e| if e.is_timeout() { MacOsExecutorError::Timeout } else { MacOsExecutorError::InvalidRequest(e.to_string()) })?,
        };
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MacOsExecutorError::AuthenticationFailed);
        }
        if !response.status().is_success() {
            return Err(MacOsExecutorError::InvalidRequest(format!(
                "daemon HTTP {}",
                response.status()
            )));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| MacOsExecutorError::InvalidRequest(e.to_string()))?;
        let parsed = MacOsResponse::from_bytes(&body)
            .map_err(|e| MacOsExecutorError::InvalidRequest(e.to_string()))?;
        if parsed.request_id != request_id {
            return Err(MacOsExecutorError::InvalidRequest(
                "响应 request_id 不匹配".into(),
            ));
        }
        if parsed.status == RequestStatus::Succeeded && parsed.exit_code != Some(0) {
            return Err(MacOsExecutorError::InvalidRequest(
                "成功响应的退出码必须为 0".into(),
            ));
        }
        Ok(parsed)
    }

    pub async fn cancel(&self, request_id: &str) -> Result<(), MacOsExecutorError> {
        let response = self
            .client
            .post(format!("{}/execute/{}/cancel", self.endpoint, request_id))
            .header("X-Daoti-Token", &self.token)
            .send()
            .await
            .map_err(|e| MacOsExecutorError::InvalidRequest(e.to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(MacOsExecutorError::AuthenticationFailed);
        }
        if !response.status().is_success() {
            return Err(MacOsExecutorError::InvalidRequest(format!(
                "daemon HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}

pub fn timeout_duration(request: &MacOsRequest) -> Duration {
    Duration::from_millis(request.timeout_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn auth(value: &str) -> Authentication {
        Authentication {
            method: AuthMethod::Token,
            credential_ref: value.into(),
        }
    }
    fn node() -> MacOsNodeCapabilities {
        MacOsNodeCapabilities {
            node_id: "mock-mac".into(),
            os_version: "14".into(),
            architectures: vec!["arm64".into()],
            capabilities: vec!["shell".into()],
        }
    }
    fn request() -> MacOsRequest {
        MacOsRequest {
            request_id: "r1".into(),
            filename: "sample-macos".into(),
            binary_base64: "bWFjaC1v".into(),
            args: vec!["uname".into()],
            timeout_ms: 100,
            authentication: auth("ref"),
        }
    }
    #[test]
    fn request_response_roundtrip_and_limits() {
        let r = request();
        let bytes = r.to_bytes().unwrap();
        assert_eq!(MacOsRequest::from_bytes(&bytes).unwrap(), r);
        let oversized = MacOsRequest {
            binary_base64: "x".repeat(MAX_REQUEST_BYTES),
            ..r
        };
        assert!(matches!(
            oversized.to_bytes(),
            Err(ProtocolError::TooLarge { .. })
        ));

        let response = MacOsResponse {
            request_id: "r1".into(),
            status: RequestStatus::Succeeded,
            stdout: "x".repeat(MAX_RESPONSE_BYTES),
            stderr: String::new(),
            exit_code: Some(0),
        };
        assert!(matches!(
            response.to_bytes(),
            Err(ProtocolError::TooLarge {
                maximum: MAX_RESPONSE_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn audit_event_is_serializable() {
        let event = AuditEvent::RequestSent {
            request_id: "r1".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("r1"));
    }

    #[test]
    fn mock_success_and_state() {
        let mut e = MockMacOsExecutor::new(node());
        assert_eq!(e.state(), ExecutorState::Disconnected);
        e.authenticate(&auth("ref")).unwrap();
        let r = e.execute(request()).unwrap();
        assert_eq!(r.status, RequestStatus::Succeeded);
        assert_eq!(e.state(), ExecutorState::Ready);
    }
    #[test]
    fn rejects_missing_auth() {
        let mut e = MockMacOsExecutor::new(node());
        assert_eq!(
            e.authenticate(&auth("")),
            Err(MacOsExecutorError::AuthenticationFailed)
        );
    }
    #[test]
    fn covers_timeout_and_cancel() {
        let mut e = MockMacOsExecutor::new(node());
        e.authenticate(&auth("ref")).unwrap();
        let mut r = request();
        r.timeout_ms = 0;
        assert_eq!(e.execute(r), Err(MacOsExecutorError::Timeout));
        e.state = ExecutorState::Running;
        e.cancel("r1").unwrap();
        assert_eq!(
            e.execute(request()).unwrap().status,
            RequestStatus::Cancelled
        );
        assert_eq!(e.state(), ExecutorState::Ready);
        assert_eq!(e.cancel("r1"), Err(MacOsExecutorError::NotReady));
    }

    #[test]
    fn disconnect_and_recovery_are_observable_without_network() {
        let mut e = MockMacOsExecutor::new(node());
        let mut registry = NodeRegistry::default();
        registry.register(NodeRegistration {
            capabilities: node(),
            authentication: auth("ref"),
        });
        assert_eq!(
            registry.health_check("mock-mac", &mut e),
            NodeHealth::Unhealthy
        );
        assert_eq!(e.execute(request()), Err(MacOsExecutorError::NotReady));
        e.authenticate(&auth("ref")).unwrap();
        assert_eq!(
            registry.health_check("mock-mac", &mut e),
            NodeHealth::Healthy
        );
        assert!(e.execute(request()).is_ok());
    }

    #[test]
    fn registry_health_and_unexpected_states_are_reported() {
        let mut e = MockMacOsExecutor::new(node());
        let registration = NodeRegistration {
            capabilities: node(),
            authentication: auth("ref"),
        };
        let mut registry = NodeRegistry::default();
        registry.register(registration);
        assert_eq!(registry.health("mock-mac"), NodeHealth::Unknown);
        assert_eq!(
            registry.health_check("mock-mac", &mut e),
            NodeHealth::Unhealthy
        );
        e.authenticate(&auth("ref")).unwrap();
        assert_eq!(
            registry.health_check("mock-mac", &mut e),
            NodeHealth::Healthy
        );
        let mut unauthenticated = MockMacOsExecutor::new(node());
        assert!(unauthenticated.execute_report(request()).is_blocked());
        let mut timeout = request();
        timeout.timeout_ms = 0;
        assert_eq!(e.execute_report(timeout).diagnostics[0].code, "TIMEOUT");
    }
}
