use std::sync::{Arc, Mutex};

use daoti_common::DaotiError;

use super::{InjectionResult, Injector};
use crate::interceptor::{InjectResult, TargetSyscall};

fn parse_u64(value: Option<&String>) -> Option<u64> {
    let value = value?.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

/// Linux 仿真器的审计缓冲区；不会写入真实控制台。
#[derive(Debug, Clone, Default)]
pub struct AuditBuffer {
    records: Arc<Mutex<Vec<String>>>,
}

impl AuditBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<String> {
        self.records.lock().expect("审计缓冲区锁不应中毒").clone()
    }

    fn push(&self, record: String) {
        self.records
            .lock()
            .expect("审计缓冲区锁不应中毒")
            .push(record);
    }
}

/// 动态 ELF 使用的 Linux x86_64 syscall 仿真注入器。
#[derive(Debug, Clone)]
pub struct LinuxEmulationInjector {
    audit: AuditBuffer,
    next_mmap: Arc<Mutex<u64>>,
    heap_top: Arc<Mutex<u64>>,
}

impl LinuxEmulationInjector {
    pub fn new(audit: AuditBuffer) -> Self {
        Self {
            audit,
            next_mmap: Arc::new(Mutex::new(0x1000_0000)),
            heap_top: Arc::new(Mutex::new(0x2000_0000)),
        }
    }

    pub fn audit(&self) -> &AuditBuffer {
        &self.audit
    }
}

impl Injector for LinuxEmulationInjector {
    fn inject(&self, target: &TargetSyscall) -> Result<InjectionResult, DaotiError> {
        match target.operation.as_str() {
            "write" | "WriteFile" => {
                let payload = target.args.join(" ");
                self.audit.push(format!("write:{payload}"));
                Ok(InjectionResult {
                    result: InjectResult::new("write", true, "已写入 Linux 仿真审计缓冲区"),
                    ret_value: Some(payload.len() as i64),
                    register_snapshot: vec![],
                })
            }
            "writev" => {
                let payload = target.args.join("");
                self.audit.push(format!("write:{payload}"));
                Ok(InjectionResult {
                    result: InjectResult::new("writev", true, "已拼接写入 Linux 仿真审计缓冲区"),
                    ret_value: Some(payload.len() as i64),
                    register_snapshot: vec![],
                })
            }
            "mmap" => {
                let length = parse_u64(target.args.first())
                    .ok_or_else(|| DaotiError::Unavailable("mmap 缺少有效长度".into()))?;
                if length == 0 {
                    return Err(DaotiError::Unavailable("mmap 长度不能为 0".into()));
                }
                let pages = length.saturating_add(0xfff) & !0xfff;
                let mut next = self.next_mmap.lock().expect("mmap 记账锁不应中毒");
                let address = *next;
                *next = next.saturating_add(pages);
                self.audit.push(format!("mmap:0x{address:x}:{pages}"));
                Ok(InjectionResult {
                    result: InjectResult::new("mmap", true, "已分配仿真虚拟地址"),
                    ret_value: Some(address as i64),
                    register_snapshot: vec![],
                })
            }
            "brk" => {
                let mut heap_top = self.heap_top.lock().expect("brk 记账锁不应中毒");
                if let Some(requested) =
                    target.args.first().and_then(|value| parse_u64(Some(value)))
                {
                    *heap_top = requested;
                }
                let current = *heap_top;
                self.audit.push(format!("brk:0x{current:x}"));
                Ok(InjectionResult {
                    result: InjectResult::new("brk", true, "已更新仿真堆顶"),
                    ret_value: Some(current as i64),
                    register_snapshot: vec![],
                })
            }
            "access" => Ok(InjectionResult {
                result: InjectResult::new("access", true, "已返回受限运行根目录的不可访问结果"),
                ret_value: Some(-2),
                register_snapshot: vec![],
            }),
            "arch_prctl" => Ok(InjectionResult {
                result: InjectResult::new("arch_prctl", true, "已处理 TLS 基址设置"),
                ret_value: Some(0),
                register_snapshot: vec![],
            }),
            "uname" => Ok(InjectionResult {
                result: InjectResult::new("uname", true, "已写入稳定 Linux 系统标识"),
                ret_value: Some(0),
                register_snapshot: vec![],
            }),
            "openat" => Ok(InjectionResult {
                result: InjectResult::new("openat", true, "已交由受控文件桥接器处理"),
                ret_value: Some(3),
                register_snapshot: vec![],
            }),
            "newfstatat" => Ok(InjectionResult {
                result: InjectResult::new("newfstatat", true, "已交由受控文件状态桥接器处理"),
                ret_value: Some(0),
                register_snapshot: vec![],
            }),
            "close" => Ok(InjectionResult {
                result: InjectResult::new("close", true, "已关闭受控文件描述符"),
                ret_value: Some(0),
                register_snapshot: vec![],
            }),
            "read" => Ok(InjectionResult {
                result: InjectResult::new("read", true, "已读取受控文件内容"),
                ret_value: Some(0),
                register_snapshot: vec![],
            }),
            "mprotect" => {
                let address = target.args.first().cloned().unwrap_or_default();
                let length = target.args.get(1).cloned().unwrap_or_default();
                let permissions = target.args.get(2).cloned().unwrap_or_default();
                self.audit
                    .push(format!("mprotect:{address}:{length}:{permissions}"));
                Ok(InjectionResult {
                    result: InjectResult::new("mprotect", true, "已记录仿真内存权限"),
                    ret_value: Some(0),
                    register_snapshot: vec![],
                })
            }
            operation => Err(DaotiError::Unavailable(format!(
                "Linux 仿真器尚未实现 syscall 操作: {operation}"
            ))),
        }
    }

    fn supported_operations(&self) -> Vec<&str> {
        vec![
            "write",
            "WriteFile",
            "writev",
            "mmap",
            "brk",
            "access",
            "arch_prctl",
            "uname",
            "openat",
            "newfstatat",
            "close",
            "read",
            "mprotect",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_goes_to_audit_buffer_not_console() {
        let audit = AuditBuffer::new();
        let injector = LinuxEmulationInjector::new(audit.clone());
        let target = TargetSyscall::new("write", "写入审计缓冲区")
            .with_args(&["stdout".into(), "Hello from libc!".into()]);

        let result = injector.inject(&target).expect("write 仿真应成功");

        assert!(result.result.success);
        assert_eq!(
            result.ret_value,
            Some("stdout Hello from libc!".len() as i64)
        );
        assert_eq!(
            audit.records(),
            vec!["write:stdout Hello from libc!".to_string()]
        );
    }

    #[test]
    fn writev_concatenates_iovec_payload_in_audit_buffer() {
        let audit = AuditBuffer::new();
        let injector = LinuxEmulationInjector::new(audit.clone());
        let target = TargetSyscall::new("writev", "拼接 iovec")
            .with_args(&["Hello ".into(), "from libc!".into()]);

        let result = injector.inject(&target).expect("writev 仿真应成功");

        assert_eq!(result.ret_value, Some("Hello from libc!".len() as i64));
        assert_eq!(audit.records(), vec!["write:Hello from libc!".to_string()]);
    }

    #[test]
    fn access_returns_enoent_for_runtime_probe() {
        let injector = LinuxEmulationInjector::new(AuditBuffer::new());
        let result = injector
            .inject(&TargetSyscall::new("access", "探测运行时文件"))
            .expect("access 仿真应返回受限结果");
        assert_eq!(result.ret_value, Some(-2));
    }

    #[test]
    fn unsupported_operation_is_unavailable() {
        let injector = LinuxEmulationInjector::new(AuditBuffer::new());
        let error = injector
            .inject(&TargetSyscall::new("getdents", "读取目录"))
            .expect_err("未实现操作必须不可用");
        assert!(matches!(error, DaotiError::Unavailable(_)));
    }

    #[test]
    fn mmap_returns_accumulating_virtual_addresses_and_audits() {
        let audit = AuditBuffer::new();
        let injector = LinuxEmulationInjector::new(audit.clone());
        let first = injector
            .inject(&TargetSyscall::new("mmap", "虚拟映射").with_args(&["4096".into()]))
            .expect("第一次 mmap 仿真应成功");
        let second = injector
            .inject(&TargetSyscall::new("mmap", "虚拟映射").with_args(&["8192".into()]))
            .expect("第二次 mmap 仿真应成功");

        assert_eq!(first.ret_value, Some(0x1000_0000));
        assert_eq!(second.ret_value, Some(0x1000_1000));
        assert_eq!(audit.records().len(), 2);
        assert!(audit.records()[0].starts_with("mmap:"));
    }

    #[test]
    fn brk_maintains_heap_top_without_os_memory_api() {
        let audit = AuditBuffer::new();
        let injector = LinuxEmulationInjector::new(audit.clone());
        let initial = injector
            .inject(&TargetSyscall::new("brk", "查询堆顶").with_args(&[]))
            .expect("查询 brk 应成功");
        let updated = injector
            .inject(&TargetSyscall::new("brk", "设置堆顶").with_args(&["0x20008000".into()]))
            .expect("设置 brk 应成功");
        let current = injector
            .inject(&TargetSyscall::new("brk", "再次查询堆顶").with_args(&[]))
            .expect("再次查询 brk 应成功");

        assert_eq!(initial.ret_value, Some(0x2000_0000));
        assert_eq!(updated.ret_value, Some(0x2000_8000));
        assert_eq!(current.ret_value, Some(0x2000_8000));
        assert!(audit
            .records()
            .iter()
            .all(|record| !record.contains("mmap_real") && !record.contains("brk_real")));
    }

    #[test]
    fn mprotect_records_permissions_without_touching_os_memory() {
        let audit = AuditBuffer::new();
        let injector = LinuxEmulationInjector::new(audit.clone());
        let result = injector
            .inject(&TargetSyscall::new("mprotect", "更新权限").with_args(&[
                "0x10000000".into(),
                "4096".into(),
                "r-x".into(),
            ]))
            .expect("mprotect 仿真应成功");

        assert_eq!(result.ret_value, Some(0));
        assert_eq!(audit.records(), vec!["mprotect:0x10000000:4096:r-x"]);
    }
}
