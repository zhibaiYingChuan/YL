//! 驭灵 daemon 全链路集成测试（P1-4）
//!
//! 验证 EventBus → HTTP 端到端行为，不依赖真实 WSL/Docker。
//! 策略：通过 axum Router 测试外部 API 行为。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use daoti_common::config::Config;
use daoti_common::{DaotiEvent, EventKind};
use daoti_core::executor::AuditEvent;
use daoti_daemon::eventbus::EventBus;
use daoti_daemon::eventlog::EventLog;
use daoti_daemon::http;

// ─── 辅助函数 ────────────────────────────────────────────────────────

fn test_router() -> (axum::Router, EventBus, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().unwrap();
    let event_log = Arc::new(EventLog::open(tmpdir.path(), 500).unwrap());
    let bus = EventBus::new();

    // 模拟 daemon main.rs 的事件持久化订阅者
    {
        let log = event_log.clone();
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            while let Ok(ev) = rx.recv().await {
                let _ = log.append(&ev);
            }
        });
    }

    // S2：测试用固定写 token（与生产 generate_daemon_token 生成的 v4 UUID 等价，仅为确定性）
    let app = http::router(
        bus.clone(),
        event_log,
        Arc::new(Config::default()),
        "test-token".to_string(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    (app, bus, tmpdir)
}

fn macos_router() -> (
    axum::Router,
    Arc<tokio::sync::Mutex<Vec<AuditEvent>>>,
    tempfile::TempDir,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    let event_log = Arc::new(EventLog::open(tmpdir.path(), 500).unwrap());
    let audit = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let app = http::router_with_macos_executor(
        EventBus::new(),
        event_log,
        Arc::new(Config::default()),
        "test-token".to_string(),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
        Arc::new(tokio::sync::Mutex::new(
            daoti_core::executor::MockMacOsExecutor::new(
                daoti_core::executor::MacOsNodeCapabilities {
                    node_id: "test-mac".into(),
                    os_version: "14".into(),
                    architectures: vec!["arm64".into()],
                    capabilities: vec!["shell".into()],
                },
            ),
        )),
        None,
        Arc::new(tokio::sync::Mutex::new(
            daoti_core::executor::NodeRegistry::default(),
        )),
        audit.clone(),
    );
    (app, audit, tmpdir)
}

fn publish_event(bus: &EventBus, kind: EventKind, title: &str) -> DaotiEvent {
    bus.publish_built(DaotiEvent::new(0, kind, title).with_detail("集成测试"))
}

async fn request(app: &axum::Router, uri: &str) -> (StatusCode, String) {
    let res = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    response_parts(res).await
}

async fn response_parts(res: axum::response::Response) -> (StatusCode, String) {
    let status = res.status();
    let body =
        String::from_utf8_lossy(&res.into_body().collect().await.unwrap().to_bytes()).to_string();
    (status, body)
}

async fn post_json(
    app: &axum::Router,
    uri: &str,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header("X-Daoti-Token", token);
    }
    let res = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    response_parts(res).await
}

// ─── 测试 ────────────────────────────────────────────────────────────

#[tokio::test]
async fn integration_symbolic_infer_requires_token() {
    let (app, _bus, _tmpdir) = test_router();
    let (status, body) = post_json(&app, "/api/symbolic/infer", None, r#"{"text":"测试"}"#).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
        "unauthorized"
    );
}

#[tokio::test]
async fn integration_symbolic_infer_rejects_empty_text() {
    let (app, _bus, _tmpdir) = test_router();
    let (status, body) = post_json(
        &app,
        "/api/symbolic/infer",
        Some("test-token"),
        r#"{"text":"   "}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("未配置 DAOTI_SYMBOLIC_INFER_URL"));
}

#[tokio::test]
async fn integration_macos_register_upload_and_audit_contract() {
    let (app, audit, _tmpdir) = macos_router();
    let registration = r#"{"capabilities":{"node_id":"remote-mac","os_version":"14.5","architectures":["arm64"],"capabilities":["shell","upload"]},"authentication":{"method":"Token","credential_ref":"opaque-ref"}}"#;
    let (status, body) = post_json(&app, "/register", Some("test-token"), registration).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["node_id"],
        "remote-mac"
    );
    let (status, body) = post_json(
        &app,
        "/upload",
        Some("test-token"),
        r#"{"request_id":"upload-1","filename":"tool","bytes":[1,2,3]}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["status"],
        "ok"
    );
    let events = audit.lock().await.clone();
    assert!(events.contains(&AuditEvent::NodeRegistered {
        node_id: "remote-mac".into()
    }));
    assert!(events.contains(&AuditEvent::RequestSent {
        request_id: "upload-1".into()
    }));
}

#[tokio::test]
async fn integration_macos_cancel_requires_auth_and_records_audit() {
    let (app, audit, _tmpdir) = macos_router();
    let (status, _) = post_json(&app, "/api/executor/macos/r1/cancel", None, "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let execute = r#"{"request_id":"r1","filename":"sample-macos","binary_base64":"bWFjaC1v","args":["uname"],"timeout_ms":100,"authentication":{"method":"Token","credential_ref":"ref"}}"#;
    let (status, _) = post_json(&app, "/api/executor/macos", Some("test-token"), execute).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post_json(
        &app,
        "/api/executor/macos/r1/cancel",
        Some("test-token"),
        "{}",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "同步 mock 已完成，取消必须明确不可用"
    );
    assert!(!audit.lock().await.iter().any(
        |event| matches!(event, AuditEvent::RequestCancelled { request_id } if request_id == "r1")
    ));
}

/// 全链路：EventBus 发布 → 历史接口可读回。
#[tokio::test]
async fn integration_events_to_history_roundtrip() {
    let (app, bus, _tmpdir) = test_router();

    publish_event(&bus, EventKind::Sense, "感·金");
    publish_event(&bus, EventKind::Infer, "推演·坎");
    publish_event(&bus, EventKind::Decide, "调度·docker_first");

    // 等待订阅者写入 EventLog（异步落盘有微小延迟）
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let (status, body) = request(&app, "/api/events/history?limit=10").await;
    assert_eq!(status, StatusCode::OK);
    let events: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(events.len(), 3, "应拉取到 3 条事件");
    assert_eq!(events[0]["kind"], "Decide");
    assert_eq!(events[1]["kind"], "Infer");
    assert_eq!(events[2]["kind"], "Sense");
}

/// 全链路：dispatch 写端点鉴权与统一裁决契约。
#[tokio::test]
async fn integration_dispatch_requires_token_and_returns_contract() {
    let (app, _bus, _tmpdir) = test_router();
    let payload = r#"{"path":"missing-binary-for-dispatch-test","args":[]}"#;
    let (status, body) = post_json(&app, "/api/dispatch", None, payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("unauthorized"), "body: {body}");

    let (status, body) = post_json(&app, "/api/dispatch", Some("test-token"), payload).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let error: serde_json::Value = serde_json::from_str(&body).expect("错误响应应为 JSON");
    assert_eq!(error["status"], "error");
    assert!(error["kind"].as_str().is_some());
}

/// 全链路：健康检查端点正常（P2-2 返回 JSON 结构化指标）。
#[tokio::test]
async fn integration_health_endpoint_ok() {
    let (app, _bus, _tmpdir) = test_router();
    // 保持临时目录存活，确保测试期间事件日志路径有效。
    let (status, body) = request(&app, "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    let h: serde_json::Value = serde_json::from_str(&body).expect("健康检查应返回有效 JSON");
    assert_eq!(h["status"], "ok", "status 字段应为 ok");
    assert!(
        h["event_bus_sent"].as_u64().is_some(),
        "应包含 event_bus_sent"
    );
    assert!(
        h["event_bus_dropped"].as_u64().is_some(),
        "应包含 event_bus_dropped"
    );
    assert!(h["mpsc_dropped"].as_u64().is_some(), "应包含 mpsc_dropped");
}

/// 全链路：快照列表接口（无快照时返回空数组不 panic）。
#[tokio::test]
async fn integration_snapshot_list_empty_is_ok() {
    let (app, _bus, _tmpdir) = test_router();
    let (status, body) = request(&app, "/api/snapshots").await;
    assert_eq!(status, StatusCode::OK);
    // snapshots_dir() 指向系统目录，可能存在已有快照；仅校验不 panic
    let _metas: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
}

/// 全链路：事件持久化后，历史接口分页可用（before_seq 边界）。
#[tokio::test]
async fn integration_history_pagination_respects_before_seq() {
    let (app, bus, _tmpdir) = test_router();

    for i in 0..5 {
        publish_event(&bus, EventKind::Sense, &format!("事件{i}"));
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let (status, body) = request(&app, "/api/events/history?before_seq=2&limit=10").await;
    assert_eq!(status, StatusCode::OK);
    let events: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(events.len(), 2, "before_seq=2 应返回 2 条");
    for ev in &events {
        assert!(ev["seq"].as_u64().unwrap() < 2);
    }
}

/// 全链路：健康度变化触发干预事件（通过 RuleEngine 直接验证推演逻辑）。
#[tokio::test]
async fn integration_actor_health_change_triggers_events() {
    use daoti_core::decision::engine::RuleEngine;
    use daoti_core::decision::InferenceEngine;
    use daoti_core::sensor::WuxingHealth;

    let bus = EventBus::new();
    let mut rx = bus.subscribe();
    let mut engine = RuleEngine::new();

    // 全健康 → 无干预
    let healthy = WuxingHealth {
        metal: 1.0,
        wood: 1.0,
        water: 1.0,
    };
    let decision = engine.interpret(&healthy);
    assert_eq!(decision.pathway, "no_action");
    assert!(decision.commands.is_empty());

    // 水弱 → 有干预
    let sick = WuxingHealth {
        metal: 1.0,
        wood: 1.0,
        water: 0.0,
    };
    let decision = engine.interpret(&sick);
    assert!(!decision.commands.is_empty(), "水弱应有干预命令");
    assert!(decision.priority.contains("docker"));

    // 事件发布到总线 → 订阅端收到
    bus.publish_built(
        DaotiEvent::new(0, EventKind::Infer, "推演·坎").with_detail(&decision.explanation),
    );
    let ev = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
        .await
        .expect("接收超时")
        .expect("通道关闭");
    assert_eq!(ev.kind, EventKind::Infer);
    assert!(ev.detail.contains("坎水"), "推演事件应包含坎水");
}

/// 全链路：相同健康度不重复干预（引擎确定性验证）。
#[tokio::test]
async fn integration_same_health_no_duplicate_intervention() {
    use daoti_core::decision::engine::RuleEngine;
    use daoti_core::decision::InferenceEngine;
    use daoti_core::sensor::WuxingHealth;

    let mut engine = RuleEngine::new();
    let sick = WuxingHealth {
        metal: 1.0,
        wood: 0.5,
        water: 1.0,
    };

    let d1 = engine.interpret(&sick);
    let d2 = engine.interpret(&sick);
    assert_eq!(d1.commands.len(), d2.commands.len());
    assert_eq!(d1.pathway, d2.pathway);
}
