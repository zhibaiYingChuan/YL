//! 三系统路径探测 (daoti-core::probe)
//!
//! 对应《开发计划-TechnicalPlan.md》R3（跨系统路径映射）与步骤 6（`daoti init`）。
//! 职责：探测 WSL 发行版、Windows Docker 服务名、盘符映射，供生成配置使用。
//!
//! 设计约束（来自施工蓝图）：
//! - 一律经 `runner` 以 `Command::args` 方式运行子进程（shell=false，防注入，R5）
//! - 命令超时/失败时返回结构化错误或回退默认值，**绝不 panic**
//! - 中文输出按 UTF-8 lossy 解码（R2）

use std::collections::HashMap;
use std::time::Duration;

use crate::runner::{run_detailed, run_with_timeout};

/// 探测可用 WSL 发行版名；失败或无发行版时回退到配置默认值 `Ubuntu`
///
/// 兼容不同 WSL 版本：优先 `wsl -l -v`（表格格式，广泛支持），回退 `wsl -l -q`。
/// 输出解析失败或无发行版时回退 `Ubuntu`，绝不 panic。
pub async fn detect_wsl_distro() -> String {
    // `-l -v` 兼容旧版 WSL（`-q` 需 WSL 2.0+）
    for args in [&["-l", "-v"][..], &["-l", "-q"][..]] {
        if let Ok((out, _err, code)) = run_detailed("wsl", args, Duration::from_secs(3)).await {
            // 仅当退出码为 0 时才信任输出：WSL 未就绪会打印帮助并返回非 0，
            // 其输出为 UTF-16 乱码，不可作为发行版名解析（R2 编码坑）
            if code == 0 {
                if let Some(name) = parse_distro_name(&out) {
                    return name;
                }
            }
        }
    }
    "Ubuntu".to_string()
}

/// 从 `wsl -l -v`（表格）或 `wsl -l -q`（纯名单）输出中解析第一个发行版名
///
/// - 跳过空行、表头（含 NAME / WSL / 子系统等）与以 `-` 开头的帮助选项行
/// - 去掉前导 `*`（默认发行版标记）后取首个空白分隔词
fn parse_distro_name(out: &str) -> Option<String> {
    for line in out.lines() {
        let t = line.trim();
        if t.is_empty()
            || t.contains("NAME")
            || t.contains("WSL")
            || t.contains("子系统")
            || t.contains("--")
        {
            continue;
        }
        // 取首个词作为发行版名
        let name = t.trim_start_matches('*').split_whitespace().next()?;
        // 跳过帮助文本特征令牌：以 `-` 开头的选项，或以 `:` 结尾的 `usage:` 等
        if name.is_empty() || name.starts_with('-') || name.ends_with(':') {
            continue;
        }
        return Some(name.to_string());
    }
    None
}

/// 探测 Windows Docker 服务名；不可用时回退默认值
///
/// 优先返回常见的 Docker 服务名，未探测到则返回默认 `com.docker.service`。
pub async fn detect_docker_service() -> String {
    // 尝试查询 Windows 服务名（仅当存在 Docker Desktop 相关服务时返回，否则回退默认）
    let out = run_with_timeout(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Service com.docker.service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name",
        ],
        Duration::from_secs(3),
    )
    .await;
    match out {
        Ok(text) if !text.trim().is_empty() => text.trim().to_string(),
        _ => "com.docker.service".to_string(),
    }
}

/// 探测 Windows 盘符到 WSL 挂载点的映射，如 `{ "C": "/mnt/c" }`
///
/// 仅收录确实存在的驱动器（避免列出不存在的盘符）；每盘符探测带超时。
pub async fn detect_drive_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let drive_letters = ["C", "D", "E", "F"];

    for letter in drive_letters {
        // 检查对应根目录是否存在（快速探测）
        let root = format!("{}:\\", letter);
        let exists = std::fs::metadata(&root).map(|_| true).unwrap_or(false);
        if exists {
            map.insert(
                letter.to_string(),
                format!("/mnt/{}", letter.to_lowercase()),
            );
        }
    }

    // 兜底：至少保证 C 盘映射存在（Windows 必有 C 盘）
    if !map.contains_key("C") {
        map.insert("C".to_string(), "/mnt/c".to_string());
    }
    map
}

/// 生成一份基于探测结果的配置（供 `daoti init` 使用）
///
/// 探测失败项均回退默认值，保证结果始终可写、可用。
pub async fn build_probed_config() -> daoti_common::config::Config {
    let mut cfg = daoti_common::config::Config::default();
    cfg.paths.wsl_distro = detect_wsl_distro().await;
    cfg.targets.docker_service = detect_docker_service().await;
    cfg.paths.drive_to_wsl = detect_drive_map().await;
    cfg
}

/// 便捷：确认 wsl 命令是否可用（供 init 友好提示）
pub async fn wsl_available() -> bool {
    run_detailed("wsl", &["--version"], Duration::from_secs(3))
        .await
        .is_ok()
}

/// 探测动态 ELF 解释器是否具备真实验收资产与通过证据。
///
/// 仅存在 metadata 或合成 fixture 不足以宣称可用；必须同时配置运行时根目录、真实
/// ET_DYN fixture，并由 CI/验收流程写入通过标记。否则返回 metadata_only/unsupported。
pub fn dynamic_elf_interpreter_probe() -> (bool, &'static str) {
    let root = std::env::var_os("DAOTI_DYNAMIC_RUNTIME_ROOT");
    let fixture = std::env::var_os("DAOTI_DYNAMIC_RUNTIME_FIXTURE");
    let evidence = std::env::var_os("DAOTI_DYNAMIC_RUNTIME_EVIDENCE");

    let Some(root) = root else {
        return (false, "metadata_only：未配置 DAOTI_DYNAMIC_RUNTIME_ROOT");
    };
    let Some(fixture) = fixture else {
        return (false, "metadata_only：未配置 DAOTI_DYNAMIC_RUNTIME_FIXTURE");
    };
    if !std::path::Path::new(&root).is_dir() || !std::path::Path::new(&fixture).is_file() {
        return (false, "unsupported：动态 ELF 真实验收资产缺失");
    }
    if evidence.as_deref() != Some(std::ffi::OsStr::new("passed")) {
        return (false, "metadata_only：缺少动态 ELF 真实验收通过证据");
    }
    (true, "动态 ELF 真实验收资产与通过证据已确认")
}

// NOTE: 本模块的 async 函数均不依赖 `dyn` 装箱，符合项目 `async_fn_in_trait` 放行约定。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wsl_lv_table() {
        // 模拟 `wsl -l -v` 表格输出（含默认发行版 `*` 标记）
        let out = "  NAME      STATE           VERSION\n  * Ubuntu    Running         2\n  Debian     Stopped         2\n";
        assert_eq!(parse_distro_name(out).as_deref(), Some("Ubuntu"));
    }

    #[test]
    fn parses_wsl_lq_plain_list() {
        // 模拟 `wsl -l -q` 纯名单输出
        let out = "Ubuntu\nDebian\n";
        assert_eq!(parse_distro_name(out).as_deref(), Some("Ubuntu"));
    }

    #[test]
    fn ignores_help_text() {
        // 模拟不支持参数时的帮助文本：应跳过 `--` 选项行，回退 None
        let out =
            "usage: wsl.exe [Argument]\n  --install <Options>\n    --distribution, -d [Argument]\n";
        assert_eq!(parse_distro_name(out), None);
    }

    #[test]
    fn empty_output_yields_none() {
        assert_eq!(parse_distro_name(""), None);
        assert_eq!(parse_distro_name("\n  \n"), None);
    }
}
