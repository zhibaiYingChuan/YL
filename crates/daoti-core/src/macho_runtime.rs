//! Windows 上运行受限 Mach-O x86_64 控制台 fixture 的本地解释器。
//!
//! 仅覆盖小端 64 位 MH_EXECUTE、LC_SEGMENT_64、LC_MAIN，以及少量
//! syscall/寄存器抽象；不提供 dyld、Objective-C、GUI 或完整 macOS ABI。

use crate::elf::runtime::{
    ExecutionState, MemPerm, MemoryModel, MemoryRegion, RuntimeContext, SyscallHandler,
    X86_64Interpreter,
};
use crate::elf::syscall_bridge::{NativeSyscallBridge, OutputSink};
use crate::parser::macho;
use daoti_common::DaotiError;

const PAGE_SIZE: u64 = 0x1000;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_EXECUTE: u32 = 2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x80000028;
const DARWIN_CLASS_UNIX: u64 = 0x0200_0000;

fn darwin_syscall_to_linux(number: u64) -> u64 {
    let syscall = number & 0x00ff_ffff;
    if number & 0xff00_0000 == DARWIN_CLASS_UNIX {
        return match syscall {
            1 => crate::elf::syscall_bridge::SYS_EXIT,
            4 => crate::elf::syscall_bridge::SYS_WRITE,
            121 => crate::elf::syscall_bridge::SYS_WRITEV,
            _ => syscall,
        };
    }
    number & 0x0fff_ffff
}

fn u32le(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}
fn u64le(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}
fn align(value: u64) -> u64 {
    (value + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// 将 Mach-O 的 Darwin syscall 编号转换为当前最小桥接支持的 Linux 语义编号。
struct DarwinBridge<S: OutputSink> {
    inner: NativeSyscallBridge<S>,
}
impl<S: OutputSink> DarwinBridge<S> {
    fn new(sink: S) -> Self {
        Self {
            inner: NativeSyscallBridge::new(sink),
        }
    }
}
impl<S: OutputSink> SyscallHandler for DarwinBridge<S> {
    fn handle(
        &mut self,
        event: &crate::elf::runtime::RuntimeSyscallEvent,
    ) -> Result<i64, DaotiError> {
        let mut translated = event.clone();
        translated.nr = darwin_syscall_to_linux(event.nr);
        self.inner.handle(&translated)
    }
    fn handle_with_memory(
        &mut self,
        event: &crate::elf::runtime::RuntimeSyscallEvent,
        memory: &mut MemoryModel,
    ) -> Result<i64, DaotiError> {
        let mut translated = event.clone();
        translated.nr = darwin_syscall_to_linux(event.nr);
        self.inner.handle_with_memory(&translated, memory)
    }
    fn exit_code(&self) -> Option<i32> {
        self.inner.exit_code()
    }
}

/// 在 Windows 进程内装载并解释执行最小 Mach-O x86_64 控制台程序。
pub fn execute_macho_with_sink<S: OutputSink>(
    data: &[u8],
    stack_size: u64,
    sink: S,
) -> Result<ExecutionState, DaotiError> {
    if data.len() < 32 || u32le(data, 0) != MH_MAGIC_64 {
        return Err(DaotiError::Unavailable("仅支持小端 Mach-O 64 位".into()));
    }
    if u32le(data, 12) != MH_EXECUTE || u32le(data, 4) != 0x01000007 {
        return Err(DaotiError::Unavailable("仅支持 x86_64 MH_EXECUTE".into()));
    }
    let ncmds = u32le(data, 16) as usize;
    let cmds_size = u32le(data, 20) as usize;
    let end = 32usize
        .checked_add(cmds_size)
        .ok_or_else(|| DaotiError::Other("Mach-O load commands 溢出".into()))?;
    if end > data.len() {
        return Err(DaotiError::Other(
            "Mach-O load commands 超出文件边界".into(),
        ));
    }
    let mut regions = Vec::new();
    let mut entryoff = None;
    let mut offset = 32usize;
    for _ in 0..ncmds {
        if offset + 8 > end {
            return Err(DaotiError::Other("Mach-O load command 截断".into()));
        }
        let cmd = u32le(data, offset);
        let size = u32le(data, offset + 4) as usize;
        if size < 8 || offset + size > end {
            return Err(DaotiError::Other("Mach-O load command 大小无效".into()));
        }
        match cmd {
            LC_SEGMENT_64 if size >= 72 => {
                let vmaddr = u64le(data, offset + 24);
                let vmsize = u64le(data, offset + 32);
                let fileoff = u64le(data, offset + 40);
                let filesize = u64le(data, offset + 48);
                let initprot = u32le(data, offset + 60);
                let fs =
                    usize::try_from(fileoff).map_err(|_| DaotiError::Other("段偏移过大".into()))?;
                let fe = fs
                    .checked_add(filesize as usize)
                    .ok_or_else(|| DaotiError::Other("段大小溢出".into()))?;
                if fe > data.len() || vmsize < filesize {
                    return Err(DaotiError::Other("Mach-O 段范围无效".into()));
                }
                let mut bytes = data[fs..fe].to_vec();
                bytes.resize(vmsize as usize, 0);
                let perm = MemPerm {
                    read: initprot & 1 != 0,
                    write: initprot & 2 != 0,
                    execute: initprot & 4 != 0,
                };
                regions.push((vmaddr, bytes, perm));
            }
            LC_MAIN if size >= 24 => entryoff = Some(u64le(data, offset + 8)),
            _ => {}
        }
        offset += size;
    }
    let entryoff = entryoff.ok_or_else(|| DaotiError::Unavailable("Mach-O 缺少 LC_MAIN".into()))?;
    let entry = macho::parse_macho64(data)?.entry_point;
    if entry == 0 || entryoff == 0 {
        return Err(DaotiError::Other("Mach-O 缺少有效入口".into()));
    }
    let mut memory = MemoryModel::new(0x1000_0000, 0x7fff_ffff_ffff);
    for (base, bytes, perm) in regions {
        memory.add_region(MemoryRegion::with_data(base, perm, bytes))?;
    }
    let stack_base = 0x7000_0000_0000u64;
    let stack_size = align(stack_size.max(PAGE_SIZE));
    memory.add_region(MemoryRegion::with_data(
        stack_base,
        MemPerm::rw(),
        vec![0; stack_size as usize],
    ))?;
    let context = RuntimeContext::new(entry, stack_base + stack_size - 8, memory);
    X86_64Interpreter::new(context)
        .with_syscall_handler(Box::new(DarwinBridge::new(sink)))
        .run()
}

/// 从文件读取并执行 Mach-O（Stdout 输出）。CLI 便捷入口。
pub fn execute_macho_file(path: &str, stack_size: u64) -> Result<ExecutionState, DaotiError> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| DaotiError::Other(format!("无法打开 Mach-O 文件 {path}：{e}")))?;
    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut data)
        .map_err(|e| DaotiError::Other(format!("读取 Mach-O 文件 {path} 失败：{e}")))?;
    execute_macho_with_sink(&data, stack_size, crate::elf::syscall_bridge::StdoutSink)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_macho() {
        assert!(
            execute_macho_with_sink(&[], 4096, crate::elf::syscall_bridge::StdoutSink).is_err()
        );
    }

    #[test]
    fn maps_darwin_console_syscalls() {
        assert_eq!(darwin_syscall_to_linux(DARWIN_CLASS_UNIX | 1), 60);
        assert_eq!(darwin_syscall_to_linux(DARWIN_CLASS_UNIX | 4), 1);
        assert_eq!(darwin_syscall_to_linux(DARWIN_CLASS_UNIX | 121), 20);
    }

    #[test]
    fn executes_real_macho_console_fixture() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/macho_console_fixture");
        assert!(
            fixture.is_file(),
            "真实 Mach-O fixture 缺失：{}",
            fixture.display()
        );
        let data = std::fs::read(&fixture).expect("读取真实 Mach-O fixture 失败");
        let sink = crate::elf::syscall_bridge::BufferSink::new();
        let output = sink.clone();
        let state = execute_macho_with_sink(&data, 0x10000, sink).expect("解释执行 Mach-O 失败");
        assert_eq!(output.into_bytes(), b"macho-runtime-ok\n");
        assert_eq!(state, ExecutionState::Exited(7));
    }
}
