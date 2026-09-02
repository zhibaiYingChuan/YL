//! `daoti daemon` 子命令实现（P0-1 生命周期管理）
//!
//! 对应《推进计划-AdvancePlan.md》P0-1：daemon 可被 CLI 启停、状态探测、端口冲突可感知。
//! 职责：定位守护二进制 → 以指定端口后台启动 → 依据 PID 文件探测存活 → 终止/重启。
//! 进程探测与 PID 读写复用 `daoti-common::process`，避免平台细节重复。

use std::path::PathBuf;
use std::time::Duration;

use daoti_common::config::daemon_pid_file;
use daoti_common::process::{pid_alive, read_pid_file, terminate_process};

/// 默认 daemon 端口（与 daemon clap 默认值一致，避免硬编码漂移）。
const DEFAULT_PORT: u16 = 17890;

/// `daoti daemon start [--port N]`：后台启动守护进程。
pub async fn start(port: Option<u16>) -> i32 {
    let port = port.unwrap_or(DEFAULT_PORT);

    // 已运行则直接提示，不做无意义重启
    if let Some(pid) = read_pid_file(&daemon_pid_file()) {
        if pid_alive(pid) {
            println!("☯ 守护进程已在运行（PID {pid}），无需重复启动。");
            return 0;
        }
    }

    // 定位守护二进制（同目录兄弟产物 / 环境变量覆盖）
    let bin = match daemon_binary_path() {
        Some(b) if b.exists() => b,
        Some(b) => {
            eprintln!("❌ 守护二进制不存在：{}", b.display());
            eprintln!("  请先 `cargo build --release` 或设置 DAOTI_DAEMON_PATH。");
            return 1;
        }
        None => {
            eprintln!("❌ 无法定位守护二进制（daoti-daemon）。");
            eprintln!("  请设置 DAOTI_DAEMON_PATH 指向 daoti-daemon 可执行文件。");
            return 1;
        }
    };

    // 端口占用预检：占用则明确报错，而非后台静默失败
    if let Err(e) = try_bind(port) {
        eprintln!("❌ 端口 {port} 已被占用，无法启动守护进程：{e}");
        eprintln!("  请先释放端口，或改用 `daoti daemon start --port <其他端口>`。");
        return 1;
    }

    println!("☯ 正在启动守护进程：{} --port {port}", bin.display());

    // 后台启动（脱离 CLI 进程组/控制台，避免随 CLI 退出被关闭；重定向输出防调用 shell 挂起）
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("--port").arg(port.to_string());
    // 守护进程不可见，stdin/stdout/stderr 全部重定向到空，
    // 避免继承 CLI 的管道/控制台句柄导致调用 shell 等待后代进程退出
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS(0x08) + CREATE_NO_WINDOW(0x08000000)：完全脱离控制台与会话
        cmd.creation_flags(0x0000_0008 | 0x0800_0000);
    }
    let child = cmd.spawn();
    let child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ 启动守护进程失败：{e}");
            return 1;
        }
    };

    // 短暂等待，确认 daemon 已写入 PID 文件并存活
    let pid = child.id();
    tokio::time::sleep(Duration::from_millis(800)).await;

    if pid_alive(pid) {
        println!("✅ 守护进程已启动（PID {pid}），监听 127.0.0.1:{port}。");
        println!("  三系统守护已就位，可 `daoti status` 观气，`daoti daemon status` 复查。");
        0
    } else {
        eprintln!("❌ 守护进程启动后立即退出（PID {pid}）。");
        eprintln!("  可能原因：单实例冲突、端口冲突或配置损坏。请查看日志。");
        1
    }
}

/// `daoti daemon stop`：终止守护进程并清理 PID 文件。
pub async fn stop() -> i32 {
    match read_pid_file(&daemon_pid_file()) {
        Some(pid) if pid_alive(pid) => {
            println!("☯ 正在终止守护进程（PID {pid}）...");
            terminate_process(pid);
            // 等待进程退出，最多 3s
            for _ in 0..30 {
                if !pid_alive(pid) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if pid_alive(pid) {
                eprintln!("⚠️ 守护进程（PID {pid}）未能及时退出，请手动检查。");
                1
            } else {
                let _ = std::fs::remove_file(daemon_pid_file());
                println!("✅ 守护进程已停止。");
                0
            }
        }
        Some(pid) => {
            // PID 文件存在但进程不存活 → 清理陈旧文件
            let _ = std::fs::remove_file(daemon_pid_file());
            println!("⚠️ PID 文件记录的进程（{pid}）已不在运行，已清理。");
            0
        }
        None => {
            println!("ℹ️ 守护进程未在运行。");
            0
        }
    }
}

/// `daoti daemon status`：报告守护进程存活状态与健康探针。
pub async fn status() -> i32 {
    match read_pid_file(&daemon_pid_file()) {
        Some(pid) if pid_alive(pid) => {
            println!("守护进程状态：运行中（PID {pid}）");
            // 尽力而为的健康探针：命中 HTTP /api/health 且 JSON status == "ok" 才算真正健康
            match probe_health(DEFAULT_PORT).await {
                Ok(true) => {
                    println!("健康探针：状态正常（127.0.0.1:{DEFAULT_PORT}/api/health → ok）");
                    0
                }
                Ok(false) => {
                    eprintln!("⚠️ 进程存活但健康探针异常（status != ok）。");
                    1
                }
                Err(e) => {
                    eprintln!("⚠️ 进程存活但无法连接健康探针：{e}");
                    1
                }
            }
        }
        Some(pid) => {
            println!("守护进程状态：PID 文件陈旧（{pid} 已不运行）");
            1
        }
        None => {
            println!("守护进程状态：未运行");
            1
        }
    }
}

/// `daoti daemon restart`：先停后启。
pub async fn restart(port: Option<u16>) -> i32 {
    let _ = stop().await;
    start(port).await
}

/// 定位守护二进制：优先 `DAOTI_DAEMON_PATH`，其次当前可执行文件同目录的兄弟产物。
fn daemon_binary_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DAOTI_DAEMON_PATH") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(format!("daoti-daemon{}", std::env::consts::EXE_SUFFIX)))
}

/// 尝试绑定 127.0.0.1:port 以感知端口占用；成功即释放（仅作预检）。
fn try_bind(port: u16) -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))?;
    drop(listener);
    Ok(())
}

/// 读取健康探针响应（仅回环，只读）。
///
/// 用 `std::net::TcpStream` 手写极简 HTTP GET，避免为单次探针引入 HTTP 客户端依赖。
/// 返回 `true` 当且仅当 `/api/health` 返回 JSON 且 `status == "ok"`（C1 修复：
/// 此前误以 body == "ok" 判断，与 JSON 响应契约不符）。
async fn probe_health(port: u16) -> Result<bool, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = format!("127.0.0.1:{port}");
    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => return Err(format!("连接失败：{e}")),
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("设置超时失败：{e}"))?;
    let req = format!("GET /api/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("发送请求失败：{e}"))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("读取响应失败：{e}"))?;
    let text = String::from_utf8_lossy(&buf).to_string();
    // 取 body（HTTP 头与 body 以空行分隔）
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    let health: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("健康探针响应非 JSON：{e}"))?;
    Ok(health.get("status").and_then(|v| v.as_str()) == Some("ok"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_binary_path_is_sibling() {
        // 当前可执行文件所在目录应能找到 daoti-daemon 兄弟产物（或 env 覆盖）
        let p = daemon_binary_path();
        assert!(p.is_some(), "应能定位到守护二进制路径");
        let p = p.unwrap();
        assert!(p
            .file_name()
            .map(|f| f.to_string_lossy().contains("daoti-daemon"))
            .unwrap_or(false));
    }

    #[test]
    fn try_bind_reports_occupied_port() {
        // 先占用一个端口，再尝试绑定应失败
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(try_bind(port).is_err(), "已占用端口应返回错误");
    }

    #[test]
    fn try_bind_free_port_ok() {
        // 空闲端口应成功
        let port = 0;
        assert!(try_bind(port).is_ok(), "端口 0 不应被占用");
    }
}
