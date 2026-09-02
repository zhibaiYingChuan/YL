//! 拦截层 (daoti-core::interceptor)
//!
//! 模式B·道体·达（规则映射）的核心。对应《模式B-跨平台二进制重映射开发计划.md》§3：
//! - `SyscallEvent`：士兵（Interceptor）捕获的 Linux 系统调用信号
//! - `TargetSyscall`：翻译后要注入到 Windows 侧执行的目标操作
//! - `Interceptor` / `Injector`：拦截与注入的契约（trait）
//! - `SyscallMapper`：20 个 Linux→Windows 确定性映射表（道体的"尺子"，只查表不做决策）
//!
//! 核心原则：映射表是纯数据、纯逻辑，不决策、不编排、不管理状态——何时用、怎么降级由道体（agent）决定。

use daoti_common::DaotiError;
use serde::Serialize;

pub mod capture;
pub mod linux;
pub mod state;
pub mod telemetry;
pub mod windows;

pub use capture::{capture_and_map, CaptureRunOutcome, MockCaptureSource, SyscallCaptureSource};
pub use state::{FdEntry, MmapEntry, ProcessState};
pub use telemetry::TelemetryCollector;

/// 一条被拦截的 Linux 系统调用事件（士兵捕获的信号）
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyscallEvent {
    /// syscall 编号（Linux x86_64 ABI）
    pub nr: i32,
    /// syscall 名称（如 "read"）
    pub name: String,
    /// 参数（B1 阶段以字符串描述为主，B2 由 codec 转为向量）
    pub args: Vec<String>,
    /// 发起线程 id
    pub tid: u64,
}

impl SyscallEvent {
    /// 构造一条 syscall 事件
    pub fn new(nr: i32, name: impl Into<String>, args: Vec<String>, tid: u64) -> Self {
        SyscallEvent {
            nr,
            name: name.into(),
            args,
            tid,
        }
    }
}

/// 映射后的 Windows 目标操作（将捕获的信号翻译后，注入到 Windows 侧）
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TargetSyscall {
    /// Windows 操作名（如 "ReadFile"）
    pub operation: String,
    /// 操作说明（判词风格，人类可读）
    pub description: String,
    /// 原始 syscall 参数（L1 执行适配器消费）
    pub args: Vec<String>,
    /// 是否可安全直通（true=无需降级到 WSL2）
    pub direct: bool,
}

impl TargetSyscall {
    /// 构造一个可直通的目标操作（无参数）
    pub fn new(operation: impl Into<String>, description: impl Into<String>) -> Self {
        TargetSyscall {
            operation: operation.into(),
            description: description.into(),
            args: Vec::new(),
            direct: true,
        }
    }

    /// 链式设置参数
    pub fn with_args(mut self, args: &[String]) -> Self {
        self.args = args.to_vec();
        self
    }
}

/// 一条被拦截的 Windows API 调用事件（PE→ELF 反向，士兵捕获的信号）
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Win32Event {
    /// Windows API 操作名（如 "ReadFile"）
    pub operation: String,
    /// 参数（B1 阶段以字符串描述为主）
    pub args: Vec<String>,
    /// 发起线程 id
    pub tid: u64,
}

impl Win32Event {
    /// 构造一条 Windows API 调用事件
    pub fn new(operation: impl Into<String>, args: Vec<String>, tid: u64) -> Self {
        Win32Event {
            operation: operation.into(),
            args,
            tid,
        }
    }
}

/// 映射后的 Linux 目标（PE→ELF 反向，将 Windows 操作翻译为 Linux syscall）
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LinuxTarget {
    /// Linux syscall 名称（如 "read"）
    pub syscall_name: String,
    /// Linux syscall 编号（x86_64 ABI）
    pub nr: i32,
    /// 是否可安全直通（true=无需降级）
    pub direct: bool,
}

impl LinuxTarget {
    /// 构造一个可直通的 Linux 目标
    pub fn new(syscall_name: impl Into<String>, nr: i32) -> Self {
        LinuxTarget {
            syscall_name: syscall_name.into(),
            nr,
            direct: true,
        }
    }
}

/// 注入执行结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InjectResult {
    /// 被执行的操作名
    pub operation: String,
    /// 是否成功
    pub success: bool,
    /// 附加说明
    pub detail: String,
}

impl InjectResult {
    /// 构造注入结果
    pub fn new(operation: impl Into<String>, success: bool, detail: impl Into<String>) -> Self {
        InjectResult {
            operation: operation.into(),
            success,
            detail: detail.into(),
        }
    }
}

/// 单条确定性映射项（编译期常量，仅可序列化导出，无需反序列化）
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SyscallMapping {
    /// Linux syscall 编号
    pub nr: i32,
    /// Linux syscall 名称
    pub name: &'static str,
    /// 映射后的 Windows 操作
    pub windows_op: &'static str,
    /// 操作说明（判词风格）
    pub description: &'static str,
}

/// 30 个 Linux→Windows 确定性映射表（Linux x86_64 ABI）
///
/// 来源：`模式B-跨平台二进制重映射开发计划.md` §3.2。常用调用直通，无需 WSL2。
/// L1 目标：文件读写/文件系统类映射全部覆盖（read/write/open/close/stat/fstat/lseek/
/// access/getcwd/chdir/mkdir/rmdir/rename/unlink/link/readlink/fsync/ftruncate/statfs）。
pub const SYSCALL_MAPPINGS: [SyscallMapping; 30] = [
    SyscallMapping {
        nr: 0,
        name: "read",
        windows_op: "ReadFile",
        description: "读文件",
    },
    SyscallMapping {
        nr: 1,
        name: "write",
        windows_op: "WriteFile",
        description: "写文件",
    },
    SyscallMapping {
        nr: 2,
        name: "open",
        windows_op: "CreateFileW",
        description: "开卷觅路",
    },
    SyscallMapping {
        nr: 3,
        name: "close",
        windows_op: "CloseHandle",
        description: "合卷归位",
    },
    SyscallMapping {
        nr: 4,
        name: "stat",
        windows_op: "GetFileAttributesExW",
        description: "观文件之形",
    },
    SyscallMapping {
        nr: 5,
        name: "fstat",
        windows_op: "GetFileInformationByHandle",
        description: "凭柄观形",
    },
    SyscallMapping {
        nr: 8,
        name: "lseek",
        windows_op: "SetFilePointerEx",
        description: "移卷定位",
    },
    SyscallMapping {
        nr: 9,
        name: "mmap",
        windows_op: "VirtualAlloc",
        description: "虚拟化形",
    },
    SyscallMapping {
        nr: 11,
        name: "munmap",
        windows_op: "VirtualFree",
        description: "释形还虚",
    },
    SyscallMapping {
        nr: 12,
        name: "brk",
        windows_op: "HeapAlloc/HeapFree",
        description: "堆界伸缩",
    },
    SyscallMapping {
        nr: 13,
        name: "rt_sigaction",
        windows_op: "SetConsoleCtrlHandler",
        description: "信号化形",
    },
    SyscallMapping {
        nr: 16,
        name: "ioctl",
        windows_op: "DeviceIoControl",
        description: "御器之令",
    },
    SyscallMapping {
        nr: 19,
        name: "readv",
        windows_op: "ReadFile(循环)",
        description: "散读多卷",
    },
    SyscallMapping {
        nr: 20,
        name: "writev",
        windows_op: "WriteFile(循环)",
        description: "散写多卷",
    },
    SyscallMapping {
        nr: 21,
        name: "access",
        windows_op: "GetFileAttributesW",
        description: "探路之权",
    },
    SyscallMapping {
        nr: 22,
        name: "pipe",
        windows_op: "CreatePipe",
        description: "引渠成管",
    },
    SyscallMapping {
        nr: 32,
        name: "dup",
        windows_op: "DuplicateHandle",
        description: "复柄分身",
    },
    SyscallMapping {
        nr: 39,
        name: "getpid",
        windows_op: "GetCurrentProcessId",
        description: "问己之身",
    },
    SyscallMapping {
        nr: 79,
        name: "getcwd",
        windows_op: "GetCurrentDirectoryW",
        description: "问己之所在",
    },
    SyscallMapping {
        nr: 186,
        name: "gettid",
        windows_op: "GetCurrentThreadId",
        description: "问己之绪",
    },
    // ── L1 文件读写/文件系统类新增（20 → 30）──
    SyscallMapping {
        nr: 74,
        name: "fsync",
        windows_op: "FlushFileBuffers",
        description: "驻笔定墨",
    },
    SyscallMapping {
        nr: 77,
        name: "ftruncate",
        windows_op: "SetEndOfFile",
        description: "截卷断句",
    },
    SyscallMapping {
        nr: 80,
        name: "chdir",
        windows_op: "SetCurrentDirectoryW",
        description: "移步换境",
    },
    SyscallMapping {
        nr: 82,
        name: "rename",
        windows_op: "MoveFileW",
        description: "更名易号",
    },
    SyscallMapping {
        nr: 83,
        name: "mkdir",
        windows_op: "CreateDirectoryW",
        description: "立新卷府",
    },
    SyscallMapping {
        nr: 84,
        name: "rmdir",
        windows_op: "RemoveDirectoryW",
        description: "拆卷拆府",
    },
    SyscallMapping {
        nr: 86,
        name: "link",
        windows_op: "CreateHardLinkW",
        description: "结链分身",
    },
    SyscallMapping {
        nr: 87,
        name: "unlink",
        windows_op: "DeleteFileW",
        description: "断卷除名",
    },
    SyscallMapping {
        nr: 89,
        name: "readlink",
        windows_op: "GetFinalPathNameByHandleW",
        description: "循链寻真",
    },
    SyscallMapping {
        nr: 137,
        name: "statfs",
        windows_op: "GetDiskFreeSpaceExW",
        description: "量库观存",
    },
];

/// 确定性映射器（道体的"尺子"）：查表返回映射结果，不做决策
#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallMapper;

impl SyscallMapper {
    /// 构造映射器
    pub fn new() -> Self {
        SyscallMapper
    }

    /// 按 syscall 编号查询映射；未命中返回 None
    pub fn map(&self, nr: i32) -> Option<&'static SyscallMapping> {
        SYSCALL_MAPPINGS.iter().find(|m| m.nr == nr)
    }

    /// 按 syscall 名称查询映射
    pub fn map_by_name(&self, name: &str) -> Option<&'static SyscallMapping> {
        SYSCALL_MAPPINGS.iter().find(|m| m.name == name)
    }

    /// 按 Windows 操作名反向查询映射（PE→ELF 方向）；未命中返回 None。
    ///
    /// 反向映射由正向表 `SYSCALL_MAPPINGS` 对称派生，避免重复定义导致两方向不一致。
    pub fn map_windows_op(&self, windows_op: &str) -> Option<&'static SyscallMapping> {
        SYSCALL_MAPPINGS.iter().find(|m| m.windows_op == windows_op)
    }

    /// 判断某 syscall 是否可直通（命中映射表）
    pub fn is_supported(&self, nr: i32) -> bool {
        self.map(nr).is_some()
    }

    /// 返回全部映射（供 telemetry / 报告）
    pub fn all(&self) -> &'static [SyscallMapping] {
        &SYSCALL_MAPPINGS
    }

    /// 支持的 syscall 数量
    pub fn supported_count(&self) -> usize {
        SYSCALL_MAPPINGS.len()
    }
}

/// 拦截契约：捕获 Linux syscall 并翻译为 Windows 目标操作
pub trait Interceptor: Send + Sync {
    /// 拦截一条 syscall 事件；命中映射返回 `Some(TargetSyscall)`，
    /// 未命中返回 `Ok(None)`（交由道体决定降级，不在此抛错）。
    fn intercept(&self, event: &SyscallEvent) -> Result<Option<TargetSyscall>, DaotiError>;
}

/// 注入契约：将翻译后的 Windows 目标操作执行到目标进程
pub trait Injector: Send + Sync {
    /// 注入执行一条目标操作
    fn inject(&self, target: &TargetSyscall) -> Result<InjectResult, DaotiError>;
}

/// 规则拦截器：基于 `SyscallMapper` 的确定性映射实现
///
/// 这是 B1 阶段"士兵"的默认实现——纯查表翻译，不涉及真实 ptrace/Debug API
/// （真实拦截留待后续平台适配层，B1 交付"映射正确 + 降级可决策"的纯逻辑）。
#[derive(Debug, Default)]
pub struct RuleInterceptor {
    mapper: SyscallMapper,
}

impl RuleInterceptor {
    /// 构造规则拦截器
    pub fn new() -> Self {
        RuleInterceptor {
            mapper: SyscallMapper::new(),
        }
    }

    /// 暴露内部映射器（供道体查询覆盖率）
    pub fn mapper(&self) -> &SyscallMapper {
        &self.mapper
    }
}

impl Interceptor for RuleInterceptor {
    fn intercept(&self, event: &SyscallEvent) -> Result<Option<TargetSyscall>, DaotiError> {
        Ok(self
            .mapper
            .map(event.nr)
            .map(|m| TargetSyscall::new(m.windows_op, m.description).with_args(&event.args)))
    }
}

/// 反向规则拦截器（PE→ELF）：Windows API 操作 → Linux syscall。
///
/// 与 `RuleInterceptor`（ELF→PE）对称，二者共同构成双向互调链路。
#[derive(Debug, Default)]
pub struct ReverseRuleInterceptor {
    mapper: SyscallMapper,
}

impl ReverseRuleInterceptor {
    /// 构造反向规则拦截器
    pub fn new() -> Self {
        ReverseRuleInterceptor {
            mapper: SyscallMapper::new(),
        }
    }

    /// 反向拦截：Windows 操作 → Linux syscall；未命中返回 None（交由道体降级）
    pub fn intercept(&self, event: &Win32Event) -> Option<LinuxTarget> {
        self.mapper
            .map_windows_op(&event.operation)
            .map(|m| LinuxTarget::new(m.name, m.nr))
    }

    /// 暴露内部映射器（供查询覆盖率）
    pub fn mapper(&self) -> &SyscallMapper {
        &self.mapper
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 断言映射表恰为 30 条（对应计划文档 §3.2 + L1 文件系统类扩充）
    #[test]
    fn mapping_table_has_exactly_30_entries() {
        assert_eq!(SYSCALL_MAPPINGS.len(), 30);
        assert_eq!(SyscallMapper::new().supported_count(), 30);
    }

    /// 关键映射抽查：read/write/open/close
    #[test]
    fn maps_core_file_io() {
        let m = SyscallMapper::new();
        assert_eq!(m.map(0).unwrap().windows_op, "ReadFile");
        assert_eq!(m.map(1).unwrap().windows_op, "WriteFile");
        assert_eq!(m.map(2).unwrap().windows_op, "CreateFileW");
        assert_eq!(m.map(3).unwrap().windows_op, "CloseHandle");
    }

    /// 按名称查询与编号查询一致
    #[test]
    fn map_by_name_matches_nr() {
        let m = SyscallMapper::new();
        let by_nr = m.map(39).unwrap();
        let by_name = m.map_by_name("getpid").unwrap();
        assert_eq!(by_nr.windows_op, by_name.windows_op);
        assert_eq!(by_nr.windows_op, "GetCurrentProcessId");
    }

    /// 未命中返回 None（交由道体降级）
    #[test]
    fn unknown_syscall_is_none() {
        let m = SyscallMapper::new();
        assert!(m.map(9999).is_none());
        assert!(!m.is_supported(9999));
    }

    /// 全部映射项均可直通（direct 标记由拦截器生成）
    #[test]
    fn rule_interceptor_maps_supported_event() {
        let interceptor = RuleInterceptor::new();
        let ev = SyscallEvent::new(0, "read", vec!["3".into(), "buf".into(), "128".into()], 100);
        let target = interceptor.intercept(&ev).unwrap().expect("read 应命中");
        assert_eq!(target.operation, "ReadFile");
        assert!(target.direct);
    }

    /// 未命中事件返回 Ok(None) 而非错误
    #[test]
    fn rule_interceptor_returns_none_for_unknown() {
        let interceptor = RuleInterceptor::new();
        let ev = SyscallEvent::new(9999, "unknown", vec![], 100);
        assert!(interceptor.intercept(&ev).unwrap().is_none());
    }

    /// 反向映射对称性：全部正向映射均可反向查询（PE→ELF 与 ELF→PE 对称）
    #[test]
    fn reverse_mapping_is_symmetric() {
        let m = SyscallMapper::new();
        for mapping in m.all() {
            let rev = m.map_windows_op(mapping.windows_op).expect("反向应命中");
            assert_eq!(rev.nr, mapping.nr);
            assert_eq!(rev.name, mapping.name);
        }
    }

    /// Windows 操作名全局唯一：`map_windows_op` 反向查询依赖该性质（首中即命）
    #[test]
    fn windows_op_is_unique() {
        let m = SyscallMapper::new();
        let mut seen: Vec<&str> = Vec::with_capacity(m.all().len());
        for mapping in m.all() {
            assert!(
                !seen.contains(&mapping.windows_op),
                "windows_op 重复：{}",
                mapping.windows_op
            );
            seen.push(mapping.windows_op);
        }
        assert_eq!(seen.len(), m.all().len());
    }

    /// L1 文件读写/文件系统类映射抽查：chdir/mkdir/rename/unlink 等
    #[test]
    fn l1_file_system_mappings_exist() {
        let m = SyscallMapper::new();
        assert_eq!(m.map(74).unwrap().windows_op, "FlushFileBuffers"); // fsync
        assert_eq!(m.map(80).unwrap().windows_op, "SetCurrentDirectoryW"); // chdir
        assert_eq!(m.map(82).unwrap().windows_op, "MoveFileW"); // rename
        assert_eq!(m.map(83).unwrap().windows_op, "CreateDirectoryW"); // mkdir
        assert_eq!(m.map(84).unwrap().windows_op, "RemoveDirectoryW"); // rmdir
        assert_eq!(m.map(87).unwrap().windows_op, "DeleteFileW"); // unlink
        assert_eq!(m.map(137).unwrap().windows_op, "GetDiskFreeSpaceExW"); // statfs
    }

    /// L1 文件系统类反向命中：Windows 操作 → Linux syscall 编号一致
    #[test]
    fn l1_file_system_reverse_maps() {
        let m = SyscallMapper::new();
        assert_eq!(m.map_windows_op("CreateDirectoryW").unwrap().nr, 83);
        assert_eq!(m.map_windows_op("DeleteFileW").unwrap().nr, 87);
        assert_eq!(m.map_windows_op("MoveFileW").unwrap().nr, 82);
    }

    /// 反向拦截器：Windows 操作 → Linux syscall
    #[test]
    fn reverse_interceptor_maps_windows_op() {
        let interceptor = ReverseRuleInterceptor::new();
        let ev = Win32Event::new("ReadFile", vec!["h".into(), "buf".into()], 200);
        let target = interceptor.intercept(&ev).expect("ReadFile 应反向命中");
        assert_eq!(target.syscall_name, "read");
        assert_eq!(target.nr, 0);
        assert!(target.direct);
    }

    /// 反向未命中返回 None（交由道体降级）
    #[test]
    fn reverse_unknown_windows_op_is_none() {
        let interceptor = ReverseRuleInterceptor::new();
        let ev = Win32Event::new("NonExistentApi", vec![], 200);
        assert!(interceptor.intercept(&ev).is_none());
    }
}
