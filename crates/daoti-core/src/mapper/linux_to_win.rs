//! Linux → Win32 确定性映射表（50 条）
//!
//! 对应《本地二进制信号重映射主路线施工计划》P3 映射器扩展。
//! 基于 Linux x86_64 ABI 编号，覆盖以下类别：
//! - 文件读写 (0-25)
//! - 文件系统 (26-50)
//! - 进程/线程 (51-100)
//! - 内存管理 (101-150)
//! - 网络 (151-200)
//! - 设备/其他 (200+)

use super::MappingEntry;

/// 50 条 Linux → Win32 确定性映射表
pub const MAPPINGS: [MappingEntry; 50] = [
    // ── 文件读写 (nr 0-10) ────────────────────────────────────
    MappingEntry {
        nr: 0,
        name: "read",
        windows_op: "ReadFile",
        description: "读文件",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 1,
        name: "write",
        windows_op: "WriteFile",
        description: "写文件",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 2,
        name: "open",
        windows_op: "CreateFileW",
        description: "开卷觅路",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 3,
        name: "close",
        windows_op: "CloseHandle",
        description: "合卷归位",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 4,
        name: "stat",
        windows_op: "GetFileAttributesExW",
        description: "观文件之形",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 5,
        name: "fstat",
        windows_op: "GetFileInformationByHandle",
        description: "凭柄观形",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 6,
        name: "lstat",
        windows_op: "GetFileAttributesExW",
        description: "观链接之形",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 7,
        name: "poll",
        windows_op: "WaitForMultipleObjects",
        description: "候多路之信",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 8,
        name: "lseek",
        windows_op: "SetFilePointerEx",
        description: "移卷定位",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 9,
        name: "mmap",
        windows_op: "VirtualAlloc",
        description: "虚拟化形",
        needs_param_convert: true,
        direct: true,
    },
    // ── 内存管理 (nr 10-20) ────────────────────────────────────
    MappingEntry {
        nr: 10,
        name: "mprotect",
        windows_op: "VirtualProtect",
        description: "易形护法",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 11,
        name: "munmap",
        windows_op: "VirtualFree",
        description: "释形还虚",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 12,
        name: "brk",
        windows_op: "HeapAlloc/HeapFree",
        description: "堆界伸缩",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 13,
        name: "rt_sigaction",
        windows_op: "SetConsoleCtrlHandler",
        description: "信号化形",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 14,
        name: "rt_sigprocmask",
        windows_op: "SetConsoleCtrlHandler",
        description: "掩信号之形",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 15,
        name: "rt_sigreturn",
        windows_op: "NtContinue",
        description: "返信号之境",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 16,
        name: "ioctl",
        windows_op: "DeviceIoControl",
        description: "御器之令",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 17,
        name: "pread64",
        windows_op: "ReadFile(偏移)",
        description: "定偏移读",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 18,
        name: "pwrite64",
        windows_op: "WriteFile(偏移)",
        description: "定偏移写",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 19,
        name: "readv",
        windows_op: "ReadFile(循环)",
        description: "散读多卷",
        needs_param_convert: true,
        direct: true,
    },
    // ── 文件系统 (nr 20-35) ────────────────────────────────────
    MappingEntry {
        nr: 20,
        name: "writev",
        windows_op: "WriteFile(循环)",
        description: "散写多卷",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 21,
        name: "access",
        windows_op: "GetFileAttributesW",
        description: "探路之权",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 22,
        name: "pipe",
        windows_op: "CreatePipe",
        description: "引渠成管",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 23,
        name: "select",
        windows_op: "WaitForMultipleObjects",
        description: "候多路选",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 24,
        name: "sched_yield",
        windows_op: "SwitchToThread",
        description: "让时之令",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 25,
        name: "mremap",
        windows_op: "VirtualAlloc(重映射)",
        description: "重映射形",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 32,
        name: "dup",
        windows_op: "DuplicateHandle",
        description: "复柄分身",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 33,
        name: "dup2",
        windows_op: "DuplicateHandle(指定)",
        description: "复柄指定",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 39,
        name: "getpid",
        windows_op: "GetCurrentProcessId",
        description: "问己之身",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 56,
        name: "clone",
        windows_op: "CreateThread",
        description: "分身化形",
        needs_param_convert: true,
        direct: true,
    },
    // ── 进程/线程 (nr 56-80) ──────────────────────────────────
    MappingEntry {
        nr: 57,
        name: "fork",
        windows_op: "CreateProcess",
        description: "分叉生子",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 59,
        name: "execve",
        windows_op: "CreateProcess",
        description: "易形换体",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 60,
        name: "exit",
        windows_op: "ExitProcess",
        description: "归元化虚",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 61,
        name: "wait4",
        windows_op: "WaitForSingleObject",
        description: "候子归元",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 62,
        name: "kill",
        windows_op: "TerminateProcess",
        description: "断命之令",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 63,
        name: "uname",
        windows_op: "GetVersionExW",
        description: "问系统之名",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 74,
        name: "fsync",
        windows_op: "FlushFileBuffers",
        description: "驻笔定墨",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 77,
        name: "ftruncate",
        windows_op: "SetEndOfFile",
        description: "截卷断句",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 79,
        name: "getcwd",
        windows_op: "GetCurrentDirectoryW",
        description: "问己之所在",
        needs_param_convert: false,
        direct: true,
    },
    // ── 目录/文件系统 (nr 80-100) ─────────────────────────────
    MappingEntry {
        nr: 80,
        name: "chdir",
        windows_op: "SetCurrentDirectoryW",
        description: "移步换境",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 82,
        name: "rename",
        windows_op: "MoveFileW",
        description: "更名易号",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 83,
        name: "mkdir",
        windows_op: "CreateDirectoryW",
        description: "立新卷府",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 84,
        name: "rmdir",
        windows_op: "RemoveDirectoryW",
        description: "拆卷拆府",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 86,
        name: "link",
        windows_op: "CreateHardLinkW",
        description: "结链分身",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 87,
        name: "unlink",
        windows_op: "DeleteFileW",
        description: "断卷除名",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 89,
        name: "readlink",
        windows_op: "GetFinalPathNameByHandleW",
        description: "循链寻真",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 102,
        name: "getuid",
        windows_op: "GetUserNameW",
        description: "问己之名",
        needs_param_convert: false,
        direct: true,
    },
    MappingEntry {
        nr: 137,
        name: "statfs",
        windows_op: "GetDiskFreeSpaceExW",
        description: "量库观存",
        needs_param_convert: true,
        direct: true,
    },
    MappingEntry {
        nr: 186,
        name: "gettid",
        windows_op: "GetCurrentThreadId",
        description: "问己之绪",
        needs_param_convert: false,
        direct: true,
    },
    // ── 网络/其他 (nr 200+) ────────────────────────────────────
    MappingEntry {
        nr: 231,
        name: "exit_group",
        windows_op: "ExitProcess",
        description: "全群归元",
        needs_param_convert: false,
        direct: true,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mappings_count() {
        assert_eq!(MAPPINGS.len(), 50, "应有 50 条映射");
    }

    #[test]
    fn test_mappings_cover_core_categories() {
        let names: Vec<&str> = MAPPINGS.iter().map(|m| m.name).collect();
        // 文件读写
        assert!(names.contains(&"read"));
        assert!(names.contains(&"write"));
        assert!(names.contains(&"open"));
        assert!(names.contains(&"close"));
        // 内存管理
        assert!(names.contains(&"mmap"));
        assert!(names.contains(&"munmap"));
        assert!(names.contains(&"brk"));
        // 进程/线程
        assert!(names.contains(&"fork"));
        assert!(names.contains(&"execve"));
        assert!(names.contains(&"exit"));
        assert!(names.contains(&"getpid"));
        // 文件系统
        assert!(names.contains(&"mkdir"));
        assert!(names.contains(&"rmdir"));
        assert!(names.contains(&"rename"));
        assert!(names.contains(&"unlink"));
        assert!(names.contains(&"statfs"));
    }

    #[test]
    fn test_mappings_have_valid_descriptions() {
        for entry in &MAPPINGS {
            assert!(!entry.description.is_empty(), "{} 缺少描述", entry.name);
            assert!(entry.direct, "{} 应可直通", entry.name);
        }
    }

    #[test]
    fn test_mappings_are_sorted_by_nr() {
        // 验证映射按 nr 排序（便于二分查找）
        for i in 1..MAPPINGS.len() {
            assert!(
                MAPPINGS[i].nr >= MAPPINGS[i - 1].nr,
                "{} (nr={}) 应排在 {} (nr={}) 之后",
                MAPPINGS[i].name,
                MAPPINGS[i].nr,
                MAPPINGS[i - 1].name,
                MAPPINGS[i - 1].nr,
            );
        }
    }
}
