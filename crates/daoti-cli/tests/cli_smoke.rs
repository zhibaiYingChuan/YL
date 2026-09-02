use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate 必须位于 workspace/crates 下")
        .to_path_buf()
}

#[cfg(windows)]
#[test]
fn run_real_static_elf_preserves_stdout_and_exit_code() {
    let elf = workspace_root().join("hello_libc.elf");
    assert!(elf.is_file(), "回归测试资产不存在：{}", elf.display());

    let output = Command::new(env!("CARGO_BIN_EXE_daoti"))
        .args(["run", elf.to_str().expect("ELF 路径必须是有效 UTF-8")])
        .output()
        .expect("应能启动 daoti CLI");

    assert!(
        output.status.success(),
        "CLI stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hello from libc!"), "stdout: {stdout}");
}

#[cfg(windows)]
#[test]
fn run_dynamic_elf_reports_real_entry_evidence_without_fake_success() {
    let configured = std::env::var_os("DAOTI_DYNAMIC_RUNTIME_ROOT").is_some()
        || std::env::var_os("DAOTI_DYNAMIC_RUNTIME_FIXTURE").is_some();
    let input = match std::env::var_os("DAOTI_DYNAMIC_RUNTIME_FIXTURE") {
        Some(fixture) => PathBuf::from(fixture),
        None => std::env::var_os("DAOTI_DYNAMIC_RUNTIME_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(workspace_root)
            .join("target/et_dyn_console_fixture"),
    };
    if !input.is_file() {
        if configured {
            panic!("真实动态 ELF acceptance 资产缺失：{}", input.display());
        }
        eprintln!("跳过动态 ELF smoke：未配置 DAOTI_DYNAMIC_RUNTIME_ROOT/fixture");
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_daoti"))
        .args(["run", input.to_str().expect("路径必须是有效 UTF-8")])
        .output()
        .expect("应能启动 daoti CLI");

    assert_eq!(output.status.code(), Some(0), "入口 exit(0) 应成功退出");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("动态 ELF 已装载到入口：0x401000"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("真实入口证据：RIP=0x401000"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("已应用重定位：0 条"), "stdout: {stdout}");
    assert!(
        stdout.contains("动态 ELF 入口执行完成：退出码 0"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("daoti-et-dyn-ok\n"), "stdout: {stdout}");
}

#[cfg(windows)]
#[test]
fn run_invalid_elf_returns_failure_without_panic() {
    let temp = tempfile::tempdir().expect("应能创建临时目录");
    let input = temp.path().join("invalid.elf");
    std::fs::write(&input, b"not an ELF file").expect("应能写入非法 ELF");

    let output = Command::new(env!("CARGO_BIN_EXE_daoti"))
        .args(["run", input.to_str().expect("路径必须是有效 UTF-8")])
        .output()
        .expect("应能启动 daoti CLI");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("mode: symbolic_only"),
        "CLI stdout: {stdout}"
    );
    assert!(
        stdout.contains("result: dispatched"),
        "CLI stdout: {stdout}"
    );
}

#[test]
fn cli_help_exposes_unified_dispatch_and_daemon_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_daoti"))
        .arg("--help")
        .output()
        .expect("应能启动 daoti CLI");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("dispatch"), "help: {help}");
    assert!(help.contains("daemon"), "help: {help}");
}

#[test]
fn cli_help_exposes_syscall_shadow_pilot() {
    let output = Command::new(env!("CARGO_BIN_EXE_daoti"))
        .arg("--help")
        .output()
        .expect("应能启动 daoti CLI");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("pilot-syscall"), "help: {help}");
}

#[test]
fn cli_dispatch_missing_path_returns_structured_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_daoti"))
        .args(["dispatch", "missing-binary-for-acceptance-test"])
        .output()
        .expect("应能启动 daoti CLI");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("status") && stderr.contains("error"),
        "stderr: {stderr}"
    );
}
