#[tokio::main]
async fn main() {
    let token = std::env::var("DAOTI_MACOS_NODE_TOKEN").expect("DAOTI_MACOS_NODE_TOKEN 必须配置");
    let address =
        std::env::var("DAOTI_MACOS_NODE_ADDR").unwrap_or_else(|_| "127.0.0.1:18767".into());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("macOS 节点监听地址无效");
    axum::serve(listener, daoti_macos_node::router(token))
        .await
        .expect("macOS 节点服务异常退出");
}
