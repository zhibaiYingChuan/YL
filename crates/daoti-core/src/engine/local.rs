//! 本地执行闭环 (daoti-core::engine::local)
//!
//! 对应《本地二进制信号重映射主路线施工计划》P5 端到端闭环。
//! 提供"启动进程→拦截→映射→注入→回填→继续执行"的完整实现。
//!
//! 当前实现为模拟闭环（使用 MockCaptureSource），
//! 真实拦截器（ptrace/Debug API）在各自平台启用。

use std::path::Path;

use daoti_common::DaotiError;

use crate::engine::{CaptureSource, ExecutionReport, LocalEngine};
use crate::interceptor::MockCaptureSource;
use crate::interceptor::SyscallEvent;

/// 从预置事件列表执行本地闭环（供测试/演示用）
///
/// 创建一个模拟捕获源，预置 syscall 事件，然后执行完整闭环。
/// 用于验证 Parser+Mapper+Injector 的集成正确性。
pub fn run_with_mock_events(
    binary_path: &Path,
    events: Vec<SyscallEvent>,
) -> Result<ExecutionReport, DaotiError> {
    let engine = LocalEngine::default();
    let source = MockCaptureSource::new(events);
    engine.execute(binary_path, Box::new(source))
}

/// 从预置事件列表执行本地闭环（使用自定义引擎）
pub fn run_with_mock_events_custom(
    engine: &LocalEngine,
    binary_path: &Path,
    events: Vec<SyscallEvent>,
) -> Result<ExecutionReport, DaotiError> {
    let source = MockCaptureSource::new(events);
    engine.execute(binary_path, Box::new(source))
}

/// 完整的本地执行闭环（需要平台特定的拦截器）
///
/// 流程：
/// 1. 解析二进制格式 → BinaryInfo
/// 2. 创建平台特定的拦截器（ptrace/Debug API）
/// 3. 循环：拦截 syscall → 映射 → 注入 → 回填
/// 4. 返回执行报告
///
/// 在非原生平台（如 Windows 上运行 Linux ELF）返回错误。
pub fn run_full_cycle(
    engine: &LocalEngine,
    binary_path: &Path,
    args: &[String],
) -> Result<ExecutionReport, DaotiError> {
    if !binary_path.exists() {
        return Err(DaotiError::FileNotFound(format!(
            "二进制文件不存在: {}",
            binary_path.display()
        )));
    }

    // 先解析二进制格式，确认支持
    let binary_info = crate::parser::parse_binary(binary_path)?;
    #[cfg(not(target_os = "windows"))]
    let _ = &binary_info;

    #[cfg(target_os = "windows")]
    if binary_info.binary_type == crate::parser::BinaryType::Elf {
        return Err(DaotiError::Unavailable(
            "Windows 原生 Debug API 无法加载 ELF；需要驭灵自身的 ELF 装载器与指令解释执行器，不能借助外部兼容层".into(),
        ));
    }

    // 创建平台特定的捕获源
    // 当前使用模拟源（真实拦截器在各自平台启用）
    let source = create_capture_source(binary_path, args)?;

    engine.execute(binary_path, source)
}

/// 创建平台特定的拦截器捕获源
///
/// - Linux: 使用 ptrace 拦截器
/// - Windows: 使用 Debug API 拦截器
/// - 其他: 返回错误
#[cfg(target_os = "linux")]
fn create_capture_source(path: &Path, args: &[String]) -> Result<CaptureSource, DaotiError> {
    let path_str = path.to_string_lossy();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let source = crate::interceptor::linux::PtraceCaptureSource::spawn(&path_str, &arg_refs)?;
    Ok(Box::new(source))
}

#[cfg(target_os = "windows")]
fn create_capture_source(path: &Path, args: &[String]) -> Result<CaptureSource, DaotiError> {
    let path_str = path.to_string_lossy();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let source = crate::interceptor::windows::DebugCaptureSource::spawn(&path_str, &arg_refs)?;
    Ok(Box::new(source))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn create_capture_source(_path: &Path, _args: &[String]) -> Result<CaptureSource, DaotiError> {
    Err(DaotiError::Unavailable(
        "当前平台不支持本地执行（需 Linux ptrace 或 Windows Debug API）".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_elf_path() -> std::path::PathBuf {
        // 使用进程内唯一序号，避免多个测试并行时共享同一临时文件路径：
        // 若两个测试同时 std::fs::write 截断同一文件，另一测试可能读到 <16 字节，
        // 被 parse_binary 报"文件过短，无法识别格式"（macOS runner 已真实复现）。
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "daoti-engine-local-{}-{unique}.elf",
            std::process::id()
        ));
        let mut data = vec![0u8; 0x1000];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[16..18].copy_from_slice(&2u16.to_le_bytes());
        data[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        data[64..68].copy_from_slice(&1u32.to_le_bytes());
        data[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        data[96..104].copy_from_slice(&0x1000u64.to_le_bytes());
        data[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
        data[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
        std::fs::write(&path, data).expect("应能写入测试 ELF");
        path
    }

    #[test]
    fn test_run_with_mock_events() {
        let events = vec![
            SyscallEvent::new(
                0,
                "read",
                vec!["3".into(), "0x7fff".into(), "1024".into()],
                1,
            ),
            SyscallEvent::new(
                1,
                "write",
                vec!["1".into(), "0x6000".into(), "14".into()],
                1,
            ),
        ];
        let path = test_elf_path();
        let report = run_with_mock_events(&path, events).expect("模拟闭环应成功");
        assert_eq!(report.total_captured, 2);
        assert_eq!(report.total_mapped, 2);
    }

    #[test]
    fn test_run_with_mock_events_custom() {
        let engine = LocalEngine::default();
        let events = vec![SyscallEvent::new(0, "read", vec![], 1)];
        let path = test_elf_path();
        let report =
            run_with_mock_events_custom(&engine, &path, events).expect("自定义引擎模拟闭环应成功");
        assert_eq!(report.total_captured, 1);
    }

    #[test]
    fn test_run_full_cycle_nonexistent() {
        let engine = LocalEngine::default();
        let path = Path::new("/nonexistent/hello.elf");
        let result = run_full_cycle(&engine, path, &[]);
        assert!(result.is_err(), "不存在的文件应返回错误");
    }

    #[test]
    fn test_run_full_cycle_unsupported_platform() {
        let engine = LocalEngine::default();
        let path = std::env::current_exe().expect("应能获取测试可执行文件路径");
        // 在 Linux/Windows 平台，spawn 返回 PermissionDenied
        let result = run_full_cycle(&engine, &path, &[]);
        assert!(result.is_err());
    }
}
