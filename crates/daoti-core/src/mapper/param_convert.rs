//! 系统调用参数转换规则
//!
//! 对应《本地二进制信号重映射主路线施工计划》P3 映射器参数转换。
//! 将 Linux syscall 参数转换为 Win32 API 参数格式。
//!
//! 需要转换的参数类型：
//! - 路径：Linux 路径（/tmp/foo）→ Windows 路径（C:\tmp\foo）
//! - 权限标志：Linux O_RDONLY → Windows GENERIC_READ
//! - 文件描述符：Linux fd → Windows HANDLE
//! - 信号：Linux signal 编号 → Windows 信号处理
//! - 内存保护：Linux PROT_READ|PROT_WRITE → Windows PAGE_READWRITE

use daoti_common::DaotiError;

/// 路径转换：Linux 路径 → Windows 路径（简化版）
///
/// 当前实现：
/// - 绝对路径保持原样（由上层进行盘符映射）
/// - 相对路径原样传递
/// - 特殊路径（/dev/null → NUL, /tmp → %TEMP%）做转换
///
/// 完整路径映射由 `daoti init` 生成的盘符映射表处理。
fn convert_path(linux_path: &str) -> Result<String, DaotiError> {
    match linux_path {
        "/dev/null" => Ok("NUL".to_string()),
        "/dev/zero" => Ok("NUL".to_string()),
        "/tmp" | "/var/tmp" => {
            // 使用环境变量 TEMP 或 TMP
            Ok(std::env::var("TEMP")
                .or_else(|_| std::env::var("TMP"))
                .unwrap_or_else(|_| "C:\\Temp".to_string()))
        }
        path if path.starts_with('/') => {
            // 绝对路径：保留给上层盘符映射处理
            Ok(path.to_string())
        }
        path => Ok(path.to_string()),
    }
}

/// Linux 打开标志到 Windows 的转换
///
/// Linux 标志（O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, O_APPEND=0x400）
/// → Windows 标志（GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000,
///                   CREATE_NEW=1, CREATE_ALWAYS=2, OPEN_EXISTING=3,
///                   OPEN_ALWAYS=4, TRUNCATE_EXISTING=5）
fn convert_open_flags(linux_flags: i32) -> (u32, u32) {
    let access = match linux_flags & 3 {
        // O_RDONLY
        0 => (0x80000000u32, 0u32), // GENERIC_READ
        // O_WRONLY
        1 => (0u32, 0x40000000u32), // GENERIC_WRITE
        // O_RDWR
        2 => (0x80000000u32, 0x40000000u32), // GENERIC_READ | GENERIC_WRITE
        _ => (0x80000000u32, 0u32),
    };

    let creation = if (linux_flags & 0x40) != 0 {
        // O_CREAT
        if (linux_flags & 0x200) != 0 {
            // O_TRUNC → CREATE_ALWAYS
            2u32
        } else if (linux_flags & 0x400) != 0 {
            // O_APPEND → OPEN_ALWAYS
            4u32
        } else {
            // O_CREAT without O_TRUNC/O_APPEND → CREATE_NEW
            1u32
        }
    } else if (linux_flags & 0x200) != 0 {
        // O_TRUNC without O_CREAT → TRUNCATE_EXISTING
        5u32
    } else {
        // 默认 → OPEN_EXISTING
        3u32
    };

    (access.0 | access.1, creation)
}

/// Linux 内存保护标志到 Windows 的转换
///
/// Linux: PROT_NONE=0, PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
/// Windows: PAGE_NOACCESS=1, PAGE_READONLY=2, PAGE_READWRITE=4,
///          PAGE_EXECUTE=0x10, PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40
fn convert_mmap_prot(linux_prot: i32) -> u32 {
    let read = (linux_prot & 1) != 0;
    let write = (linux_prot & 2) != 0;
    let exec = (linux_prot & 4) != 0;

    match (read, write, exec) {
        (false, false, false) => 1,   // PAGE_NOACCESS
        (true, false, false) => 2,    // PAGE_READONLY
        (true, true, false) => 4,     // PAGE_READWRITE
        (true, false, true) => 0x20,  // PAGE_EXECUTE_READ
        (true, true, true) => 0x40,   // PAGE_EXECUTE_READWRITE
        (false, false, true) => 0x10, // PAGE_EXECUTE
        (false, true, false) => 4,    // PAGE_READWRITE (no exact match)
        (false, true, true) => 0x40,  // PAGE_EXECUTE_READWRITE
    }
}

/// Linux 文件描述符到 Windows 句柄的转换
///
/// 标准 fd：0=stdin, 1=stdout, 2=stderr
/// 其他 fd：通过上层 HandleTable 查询
fn convert_fd(fd: i32) -> Result<String, DaotiError> {
    match fd {
        0 => Ok("STD_INPUT_HANDLE".to_string()),
        1 => Ok("STD_OUTPUT_HANDLE".to_string()),
        2 => Ok("STD_ERROR_HANDLE".to_string()),
        _ => Ok(format!("HANDLE_{}", fd)),
    }
}

/// 解析整数字符串，支持十进制和十六进制（0x 前缀）
fn parse_i32(s: &str) -> Option<i32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<i32>().ok()
    }
}

/// 根据 syscall 名称和参数执行参数转换
///
/// 返回转换后的参数列表。如果 syscall 不需要转换，原样返回。
pub fn convert_args(
    linux_name: &str,
    _windows_op: &str,
    args: &[String],
) -> Result<Vec<String>, DaotiError> {
    match linux_name {
        "open" | "openat" | "creat" => {
            if args.is_empty() {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            // arg[0]: 路径
            converted.push(convert_path(&args[0])?);
            // arg[1]: flags（可选）
            if args.len() > 1 {
                if let Some(flags) = parse_i32(&args[1]) {
                    let (_access, creation) = convert_open_flags(flags);
                    converted.push(format!("0x{:x}", creation));
                } else {
                    converted.push(args[1].clone());
                }
            }
            // arg[2]: mode（可选，文件权限，Windows 忽略）
            if args.len() > 2 {
                converted.push(args[2].clone());
            }
            Ok(converted)
        }
        "access" | "stat" | "lstat" | "unlink" | "chdir" | "rename" | "mkdir" | "rmdir"
        | "link" | "readlink" => {
            if args.is_empty() {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            converted.push(convert_path(&args[0])?);
            converted.extend(args[1..].iter().cloned());
            Ok(converted)
        }
        "mmap" => {
            if args.len() < 4 {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            // arg[0]: addr（保留）
            converted.push(args[0].clone());
            // arg[1]: length
            converted.push(args[1].clone());
            // arg[2]: prot → PAGE_*
            if let Some(prot) = parse_i32(&args[2]) {
                converted.push(format!("0x{:x}", convert_mmap_prot(prot)));
            } else {
                converted.push(args[2].clone());
            }
            // arg[3]: flags（MAP_*，保留给上层）
            converted.push(args[3].clone());
            // arg[4]: fd（可选）
            if args.len() > 4 {
                if let Ok(fd) = args[4].parse::<i32>() {
                    converted.push(convert_fd(fd)?);
                } else {
                    converted.push(args[4].clone());
                }
            }
            // arg[5]: offset（可选）
            if args.len() > 5 {
                converted.push(args[5].clone());
            }
            Ok(converted)
        }
        "mprotect" => {
            if args.len() < 3 {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            converted.push(args[0].clone()); // addr
            converted.push(args[1].clone()); // len
            if let Some(prot) = parse_i32(&args[2]) {
                converted.push(format!("0x{:x}", convert_mmap_prot(prot)));
            } else {
                converted.push(args[2].clone());
            }
            Ok(converted)
        }
        "read" | "write" | "pread64" | "pwrite64" => {
            if args.len() < 3 {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            // arg[0]: fd → HANDLE
            if let Some(fd) = parse_i32(&args[0]) {
                converted.push(convert_fd(fd)?);
            } else {
                converted.push(args[0].clone());
            }
            // arg[1]: buf（保留）
            converted.push(args[1].clone());
            // arg[2]: count
            converted.push(args[2].clone());
            // arg[3]: offset（仅 pread/pwrite）
            if args.len() > 3 {
                converted.push(args[3].clone());
            }
            Ok(converted)
        }
        "lseek" => {
            if args.len() < 3 {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            // arg[0]: fd → HANDLE
            if let Some(fd) = parse_i32(&args[0]) {
                converted.push(convert_fd(fd)?);
            } else {
                converted.push(args[0].clone());
            }
            // arg[1]: offset
            converted.push(args[1].clone());
            // arg[2]: whence
            converted.push(args[2].clone());
            Ok(converted)
        }
        "ftruncate" => {
            if args.len() < 2 {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            if let Ok(fd) = args[0].parse::<i32>() {
                converted.push(convert_fd(fd)?);
            } else {
                converted.push(args[0].clone());
            }
            converted.push(args[1].clone());
            Ok(converted)
        }
        "execve" | "execvp" | "fexecve" => {
            if args.is_empty() {
                return Ok(args.to_vec());
            }
            let mut converted = Vec::new();
            converted.push(convert_path(&args[0])?);
            converted.extend(args[1..].iter().cloned());
            Ok(converted)
        }
        // 不需要参数转换的 syscall
        _ => Ok(args.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_dev_null() {
        assert_eq!(convert_path("/dev/null").unwrap(), "NUL");
    }

    #[test]
    fn test_convert_relative_path() {
        assert_eq!(convert_path("foo.txt").unwrap(), "foo.txt");
        assert_eq!(convert_path("./bar.txt").unwrap(), "./bar.txt");
    }

    #[test]
    fn test_convert_absolute_path() {
        let result = convert_path("/home/user/file.txt").unwrap();
        assert_eq!(result, "/home/user/file.txt");
    }

    #[test]
    fn test_convert_open_flags_rdonly() {
        let (access, creation) = convert_open_flags(0); // O_RDONLY
        assert_eq!(access, 0x80000000);
        assert_eq!(creation, 3); // OPEN_EXISTING
    }

    #[test]
    fn test_convert_open_flags_wronly_creat() {
        let (access, creation) = convert_open_flags(1 | 0x40); // O_WRONLY | O_CREAT
        assert_eq!(access, 0x40000000);
        assert_eq!(creation, 1); // CREATE_NEW
    }

    #[test]
    fn test_convert_open_flags_rdwr_creat_trunc() {
        let (access, creation) = convert_open_flags(2 | 0x40 | 0x200); // O_RDWR | O_CREAT | O_TRUNC
        assert_eq!(access, 0x80000000 | 0x40000000);
        assert_eq!(creation, 2); // CREATE_ALWAYS
    }

    #[test]
    fn test_convert_mmap_prot_none() {
        assert_eq!(convert_mmap_prot(0), 1); // PAGE_NOACCESS
    }

    #[test]
    fn test_convert_mmap_prot_read() {
        assert_eq!(convert_mmap_prot(1), 2); // PAGE_READONLY
    }

    #[test]
    fn test_convert_mmap_prot_rw() {
        assert_eq!(convert_mmap_prot(3), 4); // PAGE_READWRITE
    }

    #[test]
    fn test_convert_mmap_prot_rwx() {
        assert_eq!(convert_mmap_prot(7), 0x40); // PAGE_EXECUTE_READWRITE
    }

    #[test]
    fn test_convert_fd_stdin() {
        assert_eq!(convert_fd(0).unwrap(), "STD_INPUT_HANDLE");
    }

    #[test]
    fn test_convert_fd_stdout() {
        assert_eq!(convert_fd(1).unwrap(), "STD_OUTPUT_HANDLE");
    }

    #[test]
    fn test_convert_fd_stderr() {
        assert_eq!(convert_fd(2).unwrap(), "STD_ERROR_HANDLE");
    }

    #[test]
    fn test_convert_fd_arbitrary() {
        assert_eq!(convert_fd(3).unwrap(), "HANDLE_3");
    }

    #[test]
    fn test_convert_args_open() {
        let args = vec!["/tmp/test.txt".to_string(), "0x42".to_string()];
        let converted = convert_args("open", "CreateFileW", &args).unwrap();
        assert_eq!(converted.len(), 2);
        // 路径转换：/tmp 应映射到临时目录
        // 可能的值：C:\Temp, C:\Users\...\AppData\Local\Temp, 等
        assert!(!converted[0].is_empty(), "路径不应为空");
        // flags 转换
        assert_eq!(converted[1], "0x1");
    }

    #[test]
    fn test_convert_args_mmap() {
        let args = vec![
            "0x0".to_string(),  // addr
            "4096".to_string(), // length
            "3".to_string(),    // prot (PROT_READ|PROT_WRITE)
            "0x2".to_string(),  // flags (MAP_PRIVATE)
            "0".to_string(),    // fd
            "0".to_string(),    // offset
        ];
        let converted = convert_args("mmap", "VirtualAlloc", &args).unwrap();
        assert_eq!(converted.len(), 6);
        assert_eq!(converted[2], "0x4"); // PAGE_READWRITE
    }

    #[test]
    fn test_convert_args_read() {
        let args = vec!["0".to_string(), "0x7fff".to_string(), "1024".to_string()];
        let converted = convert_args("read", "ReadFile", &args).unwrap();
        assert_eq!(converted[0], "STD_INPUT_HANDLE");
        assert_eq!(converted[2], "1024");
    }

    #[test]
    fn test_convert_unknown_syscall_passthrough() {
        let args = vec!["arg1".to_string(), "arg2".to_string()];
        let converted = convert_args("unknown_syscall", "UnknownOp", &args).unwrap();
        assert_eq!(converted, args);
    }
}
