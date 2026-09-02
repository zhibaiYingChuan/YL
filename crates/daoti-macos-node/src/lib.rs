use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
#[cfg(target_os = "macos")]
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[cfg(target_os = "macos")]
use tokio::process::Command;
#[cfg(target_os = "macos")]
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct NodeState {
    pub token: Arc<str>,
    cancellations: Arc<Mutex<HashMap<String, CancellationToken>>>,
}

pub type ExecuteRequest = daoti_core::executor::MacOsRequest;
pub type ExecuteResponse = daoti_core::executor::MacOsResponse;

pub fn router(token: impl Into<Arc<str>>) -> Router {
    let token: Arc<str> = token.into();
    Router::new()
        .route("/health", get(health))
        .route("/execute", post(execute))
        .route("/execute/:request_id/cancel", post(cancel))
        .with_state(NodeState {
            token,
            cancellations: Arc::new(Mutex::new(HashMap::new())),
        })
        .layer(DefaultBodyLimit::max(24 * 1024 * 1024))
}

async fn health(
    State(state): State<NodeState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if !authorized(&headers, &state.token) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

async fn execute(
    State(state): State<NodeState>,
    headers: axum::http::HeaderMap,
    Json(request): Json<ExecuteRequest>,
) -> impl IntoResponse {
    if !authorized(&headers, &state.token) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let request_id = request.request_id.clone();
    let cancellation = CancellationToken::new();
    state
        .cancellations
        .lock()
        .unwrap()
        .insert(request_id.clone(), cancellation.clone());
    let result = tokio::select! {
        _ = cancellation.cancelled() => Err("执行已取消".to_string()),
        result = execute_request(request) => result,
    };
    state.cancellations.lock().unwrap().remove(&request_id);
    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "error": error,
            })),
        )
            .into_response(),
    }
}

async fn cancel(
    State(state): State<NodeState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if !authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED;
    }
    if let Some(token) = state.cancellations.lock().unwrap().get(&request_id) {
        token.cancel();
        StatusCode::ACCEPTED
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn execute_request(request: ExecuteRequest) -> Result<ExecuteResponse, String> {
    if request.request_id.trim().is_empty()
        || request.filename.trim().is_empty()
        || request.timeout_ms == 0
        || request.timeout_ms > 86_400_000
    {
        return Err("请求参数无效".into());
    }
    let binary = base64::engine::general_purpose::STANDARD
        .decode(&request.binary_base64)
        .map_err(|_| "binary_base64 不是合法 Base64".to_string())?;
    if binary.is_empty() || binary.len() > 16 * 1024 * 1024 {
        return Err("Mach-O 二进制大小无效".into());
    }
    if !request
        .filename
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("文件名包含非法字符".into());
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = binary;
        Err("macOS 节点只能在 macOS 上执行 Mach-O".into())
    }

    #[cfg(target_os = "macos")]
    {
        let temp_dir = tempfile_dir(&request.request_id)?;
        let binary_path = temp_dir.join(&request.filename);
        std::fs::write(&binary_path, binary).map_err(|e| format!("写入临时 Mach-O 失败: {e}"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("设置 Mach-O 执行权限失败: {e}"))?;
        let mut command = Command::new(&binary_path);
        command.kill_on_drop(true);
        command.args(&request.args);
        command.current_dir(&temp_dir);
        let result = timeout(Duration::from_millis(request.timeout_ms), command.output()).await;
        let _ = std::fs::remove_dir_all(&temp_dir);
        match result {
            Ok(Ok(output)) => Ok(ExecuteResponse {
                request_id: request.request_id,
                status: if output.status.success() {
                    daoti_core::executor::RequestStatus::Succeeded
                } else {
                    daoti_core::executor::RequestStatus::Failed
                },
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code(),
            }),
            Ok(Err(error)) => Err(format!("执行 Mach-O 失败: {error}")),
            Err(_) => Err("执行 Mach-O 超时".into()),
        }
    }
}

#[cfg(target_os = "macos")]
fn tempfile_dir(request_id: &str) -> Result<std::path::PathBuf, String> {
    let root = std::env::temp_dir().join("daoti-macos-node");
    std::fs::create_dir_all(&root).map_err(|e| format!("创建临时目录失败: {e}"))?;
    let path = root.join(format!("{}-{}", request_id, uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).map_err(|e| format!("创建请求目录失败: {e}"))?;
    Ok(path)
}

fn authorized(headers: &axum::http::HeaderMap, token: &str) -> bool {
    headers
        .get("x-daoti-token")
        .and_then(|value| value.to_str().ok())
        == Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use base64::Engine;
    #[cfg(target_os = "macos")]
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn request() -> ExecuteRequest {
        ExecuteRequest {
            request_id: "req-1".into(),
            filename: "hello-macos".into(),
            binary_base64: base64::engine::general_purpose::STANDARD.encode(b"mach-o"),
            args: vec!["arg1".into()],
            timeout_ms: 1000,
            authentication: daoti_core::executor::Authentication {
                method: daoti_core::executor::AuthMethod::Token,
                credential_ref: "node".into(),
            },
        }
    }

    #[cfg(target_os = "macos")]
    fn real_macos_request() -> ExecuteRequest {
        let binary = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        ExecuteRequest {
            request_id: "req-real-macos".into(),
            filename: "test-runner".into(),
            binary_base64: base64::engine::general_purpose::STANDARD.encode(binary),
            args: vec!["--list".into()],
            timeout_ms: 5000,
            authentication: daoti_core::executor::Authentication {
                method: daoti_core::executor::AuthMethod::Token,
                credential_ref: "node".into(),
            },
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn execute_requires_token_and_returns_process_result() {
        let app = router("secret");
        let request = real_macos_request();
        let response = app
            .clone()
            .oneshot(
                Request::post("/execute")
                    .header("content-type", "application/json")
                    .header("x-daoti-token", "secret")
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let result: ExecuteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(result.request_id, "req-real-macos");
        assert!(result
            .stdout
            .contains("execute_requires_token_and_returns_process_result"));
        assert_eq!(result.stderr, "");
        assert_eq!(result.exit_code, Some(0));
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn execute_rejects_execution_on_non_macos() {
        let response = router("secret")
            .oneshot(
                Request::post("/execute")
                    .header("content-type", "application/json")
                    .header("x-daoti-token", "secret")
                    .body(Body::from(serde_json::to_vec(&request()).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn execute_rejects_missing_token() {
        let response = router("secret")
            .oneshot(
                Request::post("/execute")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request()).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
