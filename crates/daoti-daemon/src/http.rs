//! HTTP/SSE 事件出口
//!
//! 对应《开发计划-TechnicalPlan.md》§10.3：玄镜(UI)通过本地 HTTP + SSE 只读消费 daemon 事件。
//! 端点设计（R8 单一数据源，daemon 为唯一 producer）：
//! - `GET /api/health`               ：健康检查（玄镜启动探测）
//! - `GET /api/events`               ：SSE 事件流（玄镜实时消费决策时间轴）
//! - `GET /api/events/history`       ：历史事件拉取（P0-5 断线重连补回放）
//! - `GET /api/snapshots`            ：快照回魂列表（仅元数据，轻量）
//! - `GET /api/snapshots/{ts}`       ：单条快照详情（完整 FusionState）
//! - `POST /api/heal`               ：一键修复（写端点，需 X-Daoti-Token）
//! - `POST /api/run`                ：B0 跨平台运行（写端点，需 X-Daoti-Token）
//! - `POST /api/b1/run`             ：B1 规则映射（写端点，需 X-Daoti-Token）
//!
//! 安全：仅绑定回环地址，不对外暴露；GET 端点只读，POST 写端点需携带
//!       `X-Daoti-Token` 头校验（S2：防本地任意进程 / 跨站副作用触发执行）。
//! CORS：daemon 仅允许回环来源（玄镜 Tauri 宿主 / 本地 dev server）跨域访问，
//!      不向任意站点开放（避免恶意网页读取本地诊断信息 / 触发写端点）。

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use axum::extract::DefaultBodyLimit;
use axum::extract::{Path, Query, State};
use axum::http::{header::HeaderName, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::unfold;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;

use daoti_core::executor::{AuditEvent, BinaryUpload, NodeRegistration, NodeRegistry};

use daoti_common::config::{snapshots_dir, Config};
use daoti_common::{DaotiError, DaotiEvent};
use daoti_core::agent::CrossPlatformAgent;
use daoti_core::decision::DispatchRequest;
use daoti_core::interceptor::SyscallEvent;
use daoti_core::sensor::FusionState;

use crate::eventbus::EventBus;
use crate::eventlog::EventLog;

/// 服务状态：持有事件总线、历史日志、全局配置与 P2-2 背压指标。
#[derive(Clone)]
struct AppState {
    /// 事件总线（daemon 唯一事件源）
    bus: EventBus,
    /// 事件历史落盘（P0-5）
    event_log: Arc<EventLog>,
    /// 全局配置（P0-7 heal 端点需要构建 CrossPlatformAgent）
    config: Arc<Config>,
    /// P2-2 背压：mpsc try_send 丢弃计数（由 ActorHandle 共享）
    mpsc_dropped: Arc<AtomicU64>,
    /// 写端点鉴权 token（S2：/api/heal、/api/run、/api/b1/run 需携带匹配的 X-Daoti-Token）
    write_token: String,
    macos_executor: Arc<Mutex<daoti_core::executor::MockMacOsExecutor>>,
    macos_http_client: Option<daoti_core::executor::MacOsHttpClient>,
    macos_registry: Arc<Mutex<NodeRegistry>>,
    macos_audit: Arc<Mutex<Vec<AuditEvent>>>,
}

/// 快照列表条目（供 UI 快照回魂面板展示，不带完整快照体积）
#[derive(Serialize)]
struct SnapshotMeta {
    /// 快照时间戳（unix 秒，即文件名中的 ts）
    ts: u64,
    /// 五行健康度
    metal: f64,
    wood: f64,
    water: f64,
    /// 判词（共用 WuxingHealth::verdict，单一文案来源）
    verdict: String,
}

/// 玄镜跨域来源白名单（Tauri 宿主 + 本地 dev server）。
/// 仅这些来源可跨域只读 daemon，其余一律拒绝（不定长通配，防恶意站点读取）。
fn allowed_origins() -> Vec<HeaderValue> {
    [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "tauri://localhost",
        "http://tauri.localhost",
    ]
    .iter()
    .filter_map(|o| HeaderValue::from_str(o).ok())
    .collect()
}

/// 写端点鉴权请求头名（S2：本地任意进程调用写端点时需携带）。
const WRITE_TOKEN_HEADER: &str = "x-daoti-token";

/// 写端点鉴权失败响应体（与成功响应同为 JSON，契约一致）。
#[derive(Serialize)]
struct AuthErrorResponse {
    status: &'static str,
    error: &'static str,
}

/// 校验请求头中的写 token 是否与 daemon 生成的 token 一致。
fn token_ok(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(WRITE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        == Some(expected)
}

/// 建立路由（独立于绑定运行，便于测试）。
///
/// `mpsc_dropped` 为 Actor 的 mpsc 丢弃计数器（由 `ActorHandle::mpsc_counter` 共享），
/// 使 `/api/health` 暴露真实背压指标（而非独立的、永远为 0 的本地计数器）。
pub fn router(
    bus: EventBus,
    event_log: Arc<EventLog>,
    config: Arc<Config>,
    write_token: String,
    mpsc_dropped: Arc<AtomicU64>,
) -> Router {
    router_with_macos_executor(
        bus,
        event_log,
        config.clone(),
        write_token,
        mpsc_dropped,
        Arc::new(Mutex::new(default_macos_executor())),
        macos_http_client_from_config(&config),
        Arc::new(Mutex::new(NodeRegistry::default())),
        Arc::new(Mutex::new(Vec::new())),
    )
}

fn macos_http_client_from_config(
    config: &Arc<Config>,
) -> Option<daoti_core::executor::MacOsHttpClient> {
    if config.macos.endpoint.trim().is_empty() || config.macos.token.is_empty() {
        return None;
    }
    daoti_core::executor::MacOsHttpClient::new(
        config.macos.endpoint.clone(),
        config.macos.token.clone(),
    )
    .ok()
}

fn default_macos_executor() -> daoti_core::executor::MockMacOsExecutor {
    daoti_core::executor::MockMacOsExecutor::new(daoti_core::executor::MacOsNodeCapabilities {
        node_id: "mock-mac-node".into(),
        os_version: "mock".into(),
        architectures: vec!["arm64".into()],
        capabilities: vec!["shell".into()],
    })
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_macos_executor(
    bus: EventBus,
    event_log: Arc<EventLog>,
    config: Arc<Config>,
    write_token: String,
    mpsc_dropped: Arc<AtomicU64>,
    macos_executor: Arc<Mutex<daoti_core::executor::MockMacOsExecutor>>,
    macos_http_client: Option<daoti_core::executor::MacOsHttpClient>,
    macos_registry: Arc<Mutex<NodeRegistry>>,
    macos_audit: Arc<Mutex<Vec<AuditEvent>>>,
) -> Router {
    let state = AppState {
        bus,
        event_log,
        config,
        mpsc_dropped,
        write_token,
        macos_executor,
        macos_http_client,
        macos_registry,
        macos_audit,
    };
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins())
        // 只读端点为 GET/HEAD/OPTIONS；写端点需 POST + X-Daoti-Token
        .allow_methods([Method::GET, Method::HEAD, Method::OPTIONS, Method::POST])
        .allow_headers([
            HeaderName::from_static("accept"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static(WRITE_TOKEN_HEADER),
        ])
        .expose_headers([HeaderName::from_static("content-type")]);
    Router::new()
        .route("/api/health", get(health))
        .route("/health", get(health))
        .route("/api/events", get(events))
        .route("/api/events/history", get(events_history))
        .route("/api/snapshots", get(snapshots_list))
        .route("/api/snapshots/diff", get(snapshot_diff))
        .route("/api/snapshots/:ts", get(snapshot_detail))
        .route("/api/heal", post(heal))
        .route("/api/run", post(run_cross_platform))
        .route("/api/dispatch", post(dispatch_endpoint))
        .route("/api/symbolic/infer", post(symbolic_infer))
        .route("/api/b1/run", post(b1_run))
        .route("/api/executor/macos", post(execute_macos))
        .route("/api/executor/macos/:request_id/cancel", post(cancel_macos))
        .route("/register", post(register_macos))
        .route("/upload", post(upload_macos))
        .with_state(state)
        .layer(DefaultBodyLimit::max(
            daoti_core::executor::MAX_REQUEST_BYTES,
        ))
        .layer(cors)
}

/// P2-2 健康检查响应：返回结构化指标供玄镜/CLI 探测与背压监控。
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    event_bus_sent: u64,
    event_bus_dropped: u64,
    mpsc_dropped: u64,
}

/// 健康检查：返回结构化 JSON（含 P2-2 背压指标），供玄镜/CLI 探测 daemon 状态。
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let eb = state.bus.metrics();
    Json(HealthResponse {
        status: "ok",
        event_bus_sent: eb.sent,
        event_bus_dropped: eb.dropped,
        mpsc_dropped: state.mpsc_dropped.load(Ordering::Relaxed),
    })
}

/// 历史事件查询参数（P0-5 分页拉取）
#[derive(Deserialize)]
struct HistoryQuery {
    /// 锚点序号，只返回 seq < before_seq 的事件（默认：所有）
    before_seq: Option<u64>,
    /// 返回上限（默认 100，最大 500）
    limit: Option<u64>,
}

/// 历史事件拉取（P0-5）：GET /api/events/history?before_seq=&limit=
///
/// 从 JSONL 历史日志中分页读取事件（倒序，最新的在前）。
/// 参数缺失时使用默认值；异常路径返回空列表，不 panic。
async fn events_history(
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(100).min(500);
    let events = state.event_log.history(q.before_seq, limit);
    axum::Json(events)
}

/// SSE 事件流：订阅事件总线，将每条 `DaotiEvent` 序列化为 JSON 推送给客户端。
async fn events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>> + 'static> {
    let rx: broadcast::Receiver<DaotiEvent> = state.bus.subscribe();

    // 用 unfold 将异步接收器转为同步 SSE 流；rx 作为状态在闭包间传递，避免 move 捕获冲突
    let stream = unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(ev) => {
                let json = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".into());
                let sse = Event::default().data(json);
                Some((Ok::<Event, Infallible>(sse), rx))
            }
            // 发送端全部关闭（daemon 退出），流正常结束
            Err(broadcast::error::RecvError::Closed) => None,
            // 慢消费者落后，返回结构化丢失信息（P1-1：不再是空 "{}"）
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let lagged = serde_json::json!({"type":"lagged","skipped":n});
                let sse = Event::default().data(lagged.to_string());
                Some((Ok::<Event, Infallible>(sse), rx))
            }
        }
    });

    // KeepAlive 每 15s 发一次注释行，维持长连接
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// 快照回魂列表：扫描 `~/.daoti/snapshots/daoti_<ts>.json`，返回各快照的轻量元数据
/// （ts + 五行健康度 + 判词），按时间倒序（最新在前）。
///
/// 异常路径：目录不存在/不可读返回空列表（200），不 panic（HCSE 韧性要求）。
async fn snapshots_list() -> impl IntoResponse {
    let metas = collect_snapshot_metas(&snapshots_dir());
    axum::Json(metas)
}

/// 快照详情返回序列化格式（P0-7 heal 响应共用）
#[derive(Serialize)]
struct HealResponse {
    /// 修复结局
    outcome: String,
    /// 结局图标
    icon: String,
    /// 推演决策
    decision: daoti_core::decision::Decision,
    /// 执行结果列表
    results: Vec<daoti_core::executor::ExecResult>,
    /// 修复后五行健康度
    health: HealHealth,
    /// 判词
    verdict: String,
    /// 恢复路径提示（仅失败/超时时非空）
    recovery: Option<String>,
}

#[derive(Deserialize)]
struct SymbolicInferRequest {
    text: String,
}

async fn symbolic_infer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SymbolicInferRequest>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    let agent = CrossPlatformAgent::new(&state.config);
    match agent.infer_symbolic(&request.text).await {
        Ok(output) => Json(output).into_response(),
        Err(error) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"status": "error", "error": error})),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct HealHealth {
    metal: f64,
    wood: f64,
    water: f64,
}

/// P0-7 一键修复：POST /api/heal
///
/// 触发一次完整诊断-修复闭环（感知→推演→执行→二次感知），返回四类结局。
/// 与 CLI `daoti heal` 共享同一 CrossPlatformAgent 逻辑。
async fn heal(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    // 从全局配置构建 Agent（每次请求独立构建，避免寿命与状态耦合）
    let agent = CrossPlatformAgent::new(&state.config);
    let report = agent.diagnose_and_fix().await;

    let h = report.post_state.wuxing_health();
    let response = HealResponse {
        outcome: report.outcome.label().to_string(),
        icon: report.outcome.icon().to_string(),
        decision: report.decision,
        results: report.results,
        health: HealHealth {
            metal: h.metal,
            wood: h.wood,
            water: h.water,
        },
        verdict: h.verdict().to_string(),
        recovery: report.recovery,
    };

    Json(response).into_response()
}

#[derive(Serialize)]
struct MacOsErrorResponse {
    status: &'static str,
    kind: &'static str,
    error: String,
}

async fn execute_macos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<daoti_core::executor::MacOsRequest>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(MacOsErrorResponse {
                status: "error",
                kind: "authentication",
                error: "unauthorized".into(),
            }),
        )
            .into_response();
    }
    let request_id = req.request_id.clone();
    if let Some(client) = state.macos_http_client.clone() {
        let result = client
            .execute(req, tokio_util::sync::CancellationToken::new())
            .await;
        return match result {
            Ok(response) => {
                state
                    .macos_audit
                    .lock()
                    .await
                    .push(AuditEvent::ResponseReceived {
                        request_id: request_id.clone(),
                        status: response.status,
                    });
                Json(response).into_response()
            }
            Err(error) => (
                StatusCode::BAD_GATEWAY,
                Json(MacOsErrorResponse {
                    status: "error",
                    kind: "remote",
                    error: error.to_string(),
                }),
            )
                .into_response(),
        };
    }
    state
        .macos_audit
        .lock()
        .await
        .push(AuditEvent::RequestSent {
            request_id: request_id.clone(),
        });
    let timeout = daoti_core::executor::timeout_duration(&req);
    let executor = state.macos_executor.clone();
    let work = async move {
        let mut executor = executor.lock().await;
        use daoti_core::executor::RemoteMacOsExecutor;
        if executor.state() == daoti_core::executor::ExecutorState::Disconnected {
            executor
                .authenticate(&req.authentication)
                .map_err(|e| e.to_string())?;
        }
        executor.execute(req).map_err(|e| e.to_string())
    };
    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(response)) => {
            state
                .macos_audit
                .lock()
                .await
                .push(AuditEvent::ResponseReceived {
                    request_id: request_id.clone(),
                    status: response.status,
                });
            Json(response).into_response()
        }
        Ok(Err(error)) => (
            StatusCode::BAD_REQUEST,
            Json(MacOsErrorResponse {
                status: "error",
                kind: "executor",
                error,
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::GATEWAY_TIMEOUT,
            Json(MacOsErrorResponse {
                status: "error",
                kind: "timeout",
                error: format!("request {request_id} timed out"),
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
struct MacOsAuditResponse {
    status: &'static str,
    node_id: String,
}

async fn cancel_macos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    use daoti_core::executor::RemoteMacOsExecutor;
    let result = state.macos_executor.lock().await.cancel(&request_id);
    match result {
        Ok(()) => {
            state
                .macos_audit
                .lock()
                .await
                .push(AuditEvent::RequestCancelled {
                    request_id: request_id.clone(),
                });
            Json(serde_json::json!({"status":"ok","request_id":request_id})).into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(MacOsErrorResponse {
                status: "error",
                kind: "executor",
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn register_macos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<NodeRegistration>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    if registration.capabilities.node_id.trim().is_empty()
        || registration.authentication.credential_ref.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(MacOsErrorResponse {
                status: "error",
                kind: "validation",
                error: "node_id 与 credential_ref 不能为空".into(),
            }),
        )
            .into_response();
    }
    let node_id = registration.capabilities.node_id.clone();
    state.macos_registry.lock().await.register(registration);
    state
        .macos_audit
        .lock()
        .await
        .push(AuditEvent::NodeRegistered {
            node_id: node_id.clone(),
        });
    Json(MacOsAuditResponse {
        status: "ok",
        node_id,
    })
    .into_response()
}

async fn upload_macos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(upload): Json<BinaryUpload>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    if upload.request_id.trim().is_empty()
        || upload.filename.trim().is_empty()
        || upload.bytes.is_empty()
        || upload.bytes.len() > daoti_core::executor::MAX_BINARY_BYTES
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(MacOsErrorResponse {
                status: "error",
                kind: "validation",
                error: "上传请求无效或文件超过大小限制".into(),
            }),
        )
            .into_response();
    }
    state
        .macos_audit
        .lock()
        .await
        .push(AuditEvent::RequestSent {
            request_id: upload.request_id,
        });
    Json(serde_json::json!({"status":"ok"})).into_response()
}

/// B0 跨平台运行请求体
#[derive(Deserialize)]
struct RunRequest {
    /// 二进制文件路径
    path: String,
    /// 命令行参数（可选）
    #[serde(default)]
    args: Vec<String>,
}

/// B0 跨平台运行响应
#[derive(Serialize)]
struct RunResponse {
    status: String,
    format: String,
    mode: String,
    exit_code: i32,
    entry_point: u64,
    stdout: String,
    stderr: String,
}

/// B0 跨平台运行错误响应（与成功响应同为 JSON，契约一致）
#[derive(Serialize)]
struct RunErrorResponse {
    status: String,
    kind: String,
    error: String,
}

/// 依据领域错误映射 HTTP 状态码，避免所有失败笼统返回 500。
fn run_error_status(e: &DaotiError) -> StatusCode {
    match e {
        DaotiError::FileNotFound(_) => StatusCode::NOT_FOUND,
        DaotiError::Blocked(_) => StatusCode::FORBIDDEN,
        DaotiError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        DaotiError::CommandTimeout { .. } => StatusCode::GATEWAY_TIMEOUT,
        DaotiError::UnrecognizedFormat(_) => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// B0 跨平台运行：POST /api/run
///
/// 接收 `{ "path": "...", "args": [] }`，调用 CrossPlatformAgent 执行并返回结果。
/// 执行过程通过 EventBus 发布 CrossPlatformRun/RunFallback/Result 事件。
async fn run_cross_platform(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RunRequest>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    let agent = CrossPlatformAgent::new(&state.config);

    let ev_start = DaotiEvent::new(
        0,
        daoti_common::EventKind::CrossPlatformRun,
        "道体·通 跨平台运行",
    )
    .with_detail(&req.path);
    let _ = state.bus.publish_built(ev_start);

    match agent.run_cross_platform(&req.path, &req.args).await {
        Ok(r) => {
            let ev = DaotiEvent::new(
                0,
                daoti_common::EventKind::Result,
                format!("运行完成 · {}", r.mode),
            )
            .with_detail(format!("exit_code={}", r.exit_code));
            let _ = state.bus.publish_built(ev);
            Json(RunResponse {
                status: "ok".into(),
                format: r.format,
                mode: r.mode,
                exit_code: r.exit_code,
                entry_point: r.entry_point,
                stdout: r.stdout,
                stderr: r.stderr,
            })
            .into_response()
        }
        Err(e) => {
            let ev = DaotiEvent::new(0, daoti_common::EventKind::RunFallback, "跨平台运行失败")
                .with_detail(e.to_string());
            let _ = state.bus.publish_built(ev);
            (
                run_error_status(&e),
                Json(RunErrorResponse {
                    status: "error".into(),
                    kind: e.kind().to_string(),
                    error: e.to_string(),
                }),
            )
                .into_response()
        }
    }
}

/// 格式探测请求体
#[derive(Deserialize)]
struct DispatchRequestBody {
    /// 二进制文件路径
    path: String,
    /// 命令行参数（可选）
    #[serde(default)]
    args: Vec<String>,
}

/// 格式探测响应
#[derive(Serialize)]
struct DispatchResponseBody {
    status: String,
    format: String,
    platform: String,
    mode: String,
    execution_target: String,
    reason: String,
    available: bool,
    diagnostic: Option<String>,
    mock_node: Option<String>,
    capability_evidence: String,
}

/// 格式探测：POST /api/dispatch
///
/// 接收 `{ "path": "...", "args": [] }`，调用 agent.dispatch() 探测格式并输出决策（不执行）。
async fn dispatch_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DispatchRequestBody>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    let agent = CrossPlatformAgent::new(&state.config);
    let request = DispatchRequest {
        path: req.path,
        args: req.args,
    };
    match agent.dispatch(request) {
        Ok(decision) => Json(DispatchResponseBody {
            status: "ok".into(),
            format: decision.target.format,
            platform: decision.target.platform,
            mode: decision.target.mode,
            execution_target: decision.target.execution_target.to_string(),
            reason: decision.target.reason,
            available: decision.available,
            diagnostic: decision.diagnostic,
            mock_node: decision.mock_node,
            capability_evidence: if decision.available {
                "dispatch_probe_passed".into()
            } else {
                "dispatch_probe_failed".into()
            },
        })
        .into_response(),
        Err(e) => (
            run_error_status(&e),
            Json(RunErrorResponse {
                status: "error".into(),
                kind: e.kind().to_string(),
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// B1 规则映射请求体（道体·达）
#[derive(Deserialize)]
struct B1RunRequest {
    /// 士兵捕获的 Linux syscall 事件序列
    events: Vec<SyscallEvent>,
    /// 原始二进制路径（触发降级时回退到 B0 执行）
    #[serde(default)]
    binary_path: String,
    /// 原始二进制参数（触发降级时回退到 B0 执行）
    #[serde(default)]
    binary_args: Vec<String>,
}

/// B1 规则映射：POST /api/b1/run
///
/// 接收 syscall 事件流，执行 查表映射 → 纯逻辑注入 → 未命中批量降级 链路，
/// 返回 `B1RunReport`（映射结果 + 进程状态账本 + 未命中遥测）。
async fn b1_run(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<B1RunRequest>,
) -> Response {
    if !token_ok(&headers, &state.write_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                status: "error",
                error: "unauthorized",
            }),
        )
            .into_response();
    }
    let agent = CrossPlatformAgent::new(&state.config);
    match agent
        .run_b1(&req.events, &req.binary_path, &req.binary_args)
        .await
    {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            run_error_status(&e),
            Json(RunErrorResponse {
                status: "error".into(),
                kind: e.kind().to_string(),
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// P1-6 快照 diff 查询参数
#[derive(Deserialize)]
struct SnapshotDiffQuery {
    ts1: u64,
    ts2: u64,
}

/// P1-6 快照差异响应
#[derive(Serialize)]
struct SnapshotDiffResponse {
    ts1: u64,
    ts2: u64,
    health_before: DiffHealth,
    health_after: DiffHealth,
    field_changes: Vec<DiffField>,
}

#[derive(Serialize)]
struct DiffHealth {
    metal: f64,
    wood: f64,
    water: f64,
}

#[derive(Serialize)]
struct DiffField {
    system: String,
    key: String,
    before: String,
    after: String,
}

/// P1-6 快照对比：GET /api/snapshots/diff?ts1=&ts2=
async fn snapshot_diff(Query(q): Query<SnapshotDiffQuery>) -> impl IntoResponse {
    let dir = snapshots_dir();
    let f1 = load_snapshot_file(&dir, q.ts1);
    let f2 = load_snapshot_file(&dir, q.ts2);

    let (f1, f2) = match (f1, f2) {
        (Some(a), Some(b)) => (a, b),
        _ => return (StatusCode::NOT_FOUND, "快照不存在或损坏").into_response(),
    };

    let h1 = f1.wuxing_health();
    let h2 = f2.wuxing_health();

    let mut field_changes = Vec::new();
    for sys in &["windows", "wsl2", "docker"] {
        let s1 = snapshot_for(&f1, sys);
        let s2 = snapshot_for(&f2, sys);
        if let (Some(s1), Some(s2)) = (s1, s2) {
            for (k, v1) in &s1.fields {
                let v2 = s2.fields.get(k).cloned().unwrap_or_default();
                if *v1 != v2 {
                    field_changes.push(DiffField {
                        system: sys.to_string(),
                        key: k.clone(),
                        before: v1.clone(),
                        after: v2,
                    });
                }
            }
        }
    }

    Json(SnapshotDiffResponse {
        ts1: q.ts1,
        ts2: q.ts2,
        health_before: DiffHealth {
            metal: h1.metal,
            wood: h1.wood,
            water: h1.water,
        },
        health_after: DiffHealth {
            metal: h2.metal,
            wood: h2.wood,
            water: h2.water,
        },
        field_changes,
    })
    .into_response()
}

/// 从快照文件加载 FusionState
fn load_snapshot_file(dir: &std::path::Path, ts: u64) -> Option<FusionState> {
    let raw = std::fs::read_to_string(dir.join(format!("daoti_{ts}.json"))).ok()?;
    serde_json::from_str(&raw).ok()
}

/// 获取某系统的快照
fn snapshot_for(f: &FusionState, sys: &str) -> Option<daoti_core::sensor::SensorSnapshot> {
    match sys {
        "windows" => f.windows.clone(),
        "wsl2" => f.wsl2.clone(),
        "docker" => f.docker.clone(),
        _ => None,
    }
}

/// 单条快照详情：按 ts 读取 `daoti_<ts>.json`，返回完整 FusionState。
async fn snapshot_detail(Path(ts): Path<u64>) -> impl IntoResponse {
    let path = snapshots_dir().join(format!("daoti_{ts}.json"));
    match std::fs::read_to_string(&path) {
        // 解析为 JSON 值后再输出，保证纯 JSON（而非带引号的字符串）
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => axum::Json(v).into_response(),
            Err(_) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "快照损坏").into_response(),
        },
        Err(_) => (axum::http::StatusCode::NOT_FOUND, "快照不存在").into_response(),
    }
}

/// 扫描快照目录，收集各快照元数据。不可读目录返回空列表（不 panic）。
fn collect_snapshot_metas(dir: &std::path::Path) -> Vec<SnapshotMeta> {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let mut metas = Vec::new();
    for entry in read_dir.flatten() {
        let fname = match entry.file_name().to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        // 仅处理 `daoti_<ts>.json` 命名的快照文件
        let ts = fname
            .strip_prefix("daoti_")
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|s| s.parse::<u64>().ok());
        let Some(ts) = ts else { continue };

        // 解析并计算健康度判词；解析失败则跳过该条（不 panic）
        let fusion: FusionState = match std::fs::read_to_string(entry.path())
            .ok()
            .and_then(|j| serde_json::from_str(&j).ok())
        {
            Some(f) => f,
            None => continue,
        };
        let h = fusion.wuxing_health();
        metas.push(SnapshotMeta {
            ts,
            metal: h.metal,
            wood: h.wood,
            water: h.water,
            verdict: h.verdict().to_string(),
        });
    }

    // 按时间倒序（最新在前）
    metas.sort_by_key(|m| std::cmp::Reverse(m.ts));
    metas
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 写入一个 `daoti_<ts>.json` 快照（内容为三全健康 FusionState）
    fn write_snapshot(dir: &std::path::Path, ts: u64) {
        let fusion = FusionState::from_sensors(
            &daoti_core::sensor::SensorState::Ok(
                daoti_core::sensor::SensorSnapshot::new("windows")
                    .metric("docker_desktop_running", 1.0),
            ),
            &daoti_core::sensor::SensorState::Ok(
                daoti_core::sensor::SensorSnapshot::new("wsl2").metric("running", 1.0),
            ),
            &daoti_core::sensor::SensorState::Ok(
                daoti_core::sensor::SensorSnapshot::new("docker").field("daemon_version", "27.2.0"),
            ),
        );
        let json = serde_json::to_string(&fusion).unwrap();
        std::fs::write(dir.join(format!("daoti_{ts}.json")), json).unwrap();
    }

    #[test]
    fn collect_returns_metas_sorted_desc() {
        let dir = tempfile::tempdir().unwrap();
        write_snapshot(dir.path(), 100);
        write_snapshot(dir.path(), 200);

        let metas = collect_snapshot_metas(dir.path());
        assert_eq!(metas.len(), 2);
        // 最新在前
        assert_eq!(metas[0].ts, 200);
        assert_eq!(metas[1].ts, 100);
        // 快照为三全健康 → 判词含"三气通"
        assert!(metas.iter().all(|m| m.verdict.contains("三气通")));
    }

    #[test]
    fn collect_ignores_non_snapshot_and_corrupt_files() {
        let dir = tempfile::tempdir().unwrap();
        write_snapshot(dir.path(), 100);
        // 非快照命名文件
        std::fs::write(dir.path().join("readme.txt"), "x").unwrap();
        // 命名符合但内容损坏
        std::fs::write(dir.path().join("daoti_999.json"), "not-json").unwrap();

        let metas = collect_snapshot_metas(dir.path());
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].ts, 100);
    }

    #[test]
    fn collect_missing_dir_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no_such_dir");
        assert!(collect_snapshot_metas(&missing).is_empty());
    }

    /// 路由级集成测试：detail 端点在带路径参数时能正确匹配（而非 route 级 404）
    #[tokio::test]
    async fn macos_executor_endpoint_auth_and_mock_response() {
        use axum::body::Body;
        use axum::http::Request;
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let tmpdir = tempfile::tempdir().unwrap();
        let event_log = Arc::new(crate::eventlog::EventLog::open(tmpdir.path(), 100).unwrap());
        let app = super::router(
            crate::eventbus::EventBus::new(),
            event_log,
            Arc::new(daoti_common::config::Config::default()),
            "test-token".into(),
            Arc::new(AtomicU64::new(0)),
        );
        let body = serde_json::json!({"request_id":"r1","filename":"sample-macos","binary_base64":"bWFjaC1v","args":["uname"],"timeout_ms":100,"authentication":{"method":"Token","credential_ref":"test"}});
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/executor/macos")
                    .header("content-type", "application/json")
                    .header("x-daoti-token", "test-token")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(json["status"], "Succeeded");
    }

    #[tokio::test]
    async fn detail_route_matches_parameterized_path() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let event_log =
            std::sync::Arc::new(crate::eventlog::EventLog::open(tmpdir.path(), 100).unwrap());
        let app = super::router(
            crate::eventbus::EventBus::new(),
            event_log,
            std::sync::Arc::new(daoti_common::config::Config::default()),
            "test-token".to_string(),
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );

        // 请求不存在的快照时，应命中 handler 返回 NOT_FOUND（带 body），而非 route 级空 404
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/snapshots/99999999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        // handler 返回的 body 应为"快照不存在"（route 级 404 的 body 为空）
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8_lossy(&body), "快照不存在");
    }
}
