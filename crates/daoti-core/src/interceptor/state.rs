//! 进程状态账本 (daoti-core::interceptor::state)
//!
//! 模式B·道体·达（规则映射）的"状态账本"。士兵（Interceptor/Injector）每命中一条
//! 映射并注入成功后，由道体在此登记被拦截进程的运行期状态，使后续 syscall 翻译具备
//! 上下文（如 dup 复用 fd、getcwd 返回当前目录、mmap/munmap 维护地址区间）。
//!
//! 对应《模式B-跨平台二进制重映射开发计划.md》§3.1 —— ProcessState（FD表/内存表/cwd/env）。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 文件描述符表项：记录一个已打开的描述符与目标路径
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FdEntry {
    /// 文件描述符编号
    pub fd: i32,
    /// 打开的文件路径
    pub path: String,
    /// 打开模式（read / write / append 等）
    pub mode: String,
}

impl FdEntry {
    /// 构造一条 fd 表项
    pub fn new(fd: i32, path: impl Into<String>, mode: impl Into<String>) -> Self {
        FdEntry {
            fd,
            path: path.into(),
            mode: mode.into(),
        }
    }
}

/// 内存映射表项：记录一段已映射的虚拟地址区间
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MmapEntry {
    /// 起始地址
    pub addr: u64,
    /// 映射长度（字节）
    pub len: u64,
    /// 保护标志（如 "r-x"）
    pub prot: String,
    /// 映射标志（如 "private" / "shared"）
    pub flags: String,
}

impl MmapEntry {
    /// 构造一条 mmap 表项
    pub fn new(addr: u64, len: u64, prot: impl Into<String>, flags: impl Into<String>) -> Self {
        MmapEntry {
            addr,
            len,
            prot: prot.into(),
            flags: flags.into(),
        }
    }
}

/// 被拦截进程的运行期状态账本
///
/// B1 阶段由道体（DecisionPipeline）持有并随注入推进更新；真实 fd 编号、
/// 内存地址由平台适配层（真实 ptrace/Debug API）填入，B1 仅交付纯逻辑账本。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessState {
    /// 文件描述符表（fd → 表项）
    pub fds: HashMap<i32, FdEntry>,
    /// 内存映射表
    pub mmaps: Vec<MmapEntry>,
    /// 当前工作目录
    pub cwd: String,
    /// 环境变量（键 → 值）
    pub env: HashMap<String, String>,
    /// 堆界（brk 当前值，Linux x86_64 语义）
    pub brk: u64,
}

impl ProcessState {
    /// 构造空账本
    pub fn new() -> Self {
        ProcessState::default()
    }

    // ── 文件描述符表 ──────────────────────────────
    /// 登记一个打开的文件描述符
    pub fn open_fd(&mut self, entry: FdEntry) {
        self.fds.insert(entry.fd, entry);
    }

    /// 关闭并移除一个文件描述符，返回被移除的表项
    pub fn close_fd(&mut self, fd: i32) -> Option<FdEntry> {
        self.fds.remove(&fd)
    }

    /// 查询一个文件描述符表项
    pub fn get_fd(&self, fd: i32) -> Option<&FdEntry> {
        self.fds.get(&fd)
    }

    /// 当前已登记的文件描述符数量
    pub fn fd_count(&self) -> usize {
        self.fds.len()
    }

    // ── 内存映射表 ──────────────────────────────
    /// 登记一段内存映射
    pub fn add_mmap(&mut self, entry: MmapEntry) {
        // 同一起始地址视为覆盖旧映射（munmap 前不重复登记）
        self.mmaps.retain(|m| m.addr != entry.addr);
        self.mmaps.push(entry);
    }

    /// 移除一段内存映射，返回被移除的表项
    pub fn remove_mmap(&mut self, addr: u64) -> Option<MmapEntry> {
        if let Some(pos) = self.mmaps.iter().position(|m| m.addr == addr) {
            Some(self.mmaps.remove(pos))
        } else {
            None
        }
    }

    /// 当前已登记的内存映射数量
    pub fn mmap_count(&self) -> usize {
        self.mmaps.len()
    }

    // ── 当前工作目录 / 堆界 / 环境 ──────────────────────────────
    /// 设置当前工作目录
    pub fn set_cwd(&mut self, cwd: impl Into<String>) {
        self.cwd = cwd.into();
    }

    /// 读取当前工作目录
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// 设置堆界
    pub fn set_brk(&mut self, brk: u64) {
        self.brk = brk;
    }

    /// 读取堆界
    pub fn brk(&self) -> u64 {
        self.brk
    }

    /// 写入环境变量
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    /// 读取环境变量
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(|s| s.as_str())
    }

    /// 当前已登记的环境变量数量
    pub fn env_count(&self) -> usize {
        self.env.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fd 表可登记、查询、关闭
    #[test]
    fn fd_table_open_query_close() {
        let mut s = ProcessState::new();
        s.open_fd(FdEntry::new(3, "/etc/hosts", "read"));
        assert_eq!(s.fd_count(), 1);
        assert_eq!(s.get_fd(3).unwrap().path, "/etc/hosts");
        let removed = s.close_fd(3).expect("应存在 fd 3");
        assert_eq!(removed.mode, "read");
        assert_eq!(s.fd_count(), 0);
        assert!(s.get_fd(3).is_none());
    }

    /// mmap 登记、去重覆盖、移除
    #[test]
    fn mmap_add_dedup_remove() {
        let mut s = ProcessState::new();
        s.add_mmap(MmapEntry::new(0x1000, 0x2000, "r-x", "private"));
        s.add_mmap(MmapEntry::new(0x1000, 0x3000, "rw-", "private")); // 同址覆盖
        assert_eq!(s.mmap_count(), 1);
        assert_eq!(s.mmaps[0].len, 0x3000);
        let removed = s.remove_mmap(0x1000).expect("应存在映射");
        assert_eq!(removed.prot, "rw-");
        assert_eq!(s.mmap_count(), 0);
        assert!(s.remove_mmap(0x1000).is_none());
    }

    /// cwd / brk / env 基础读写
    #[test]
    fn cwd_brk_env_roundtrip() {
        let mut s = ProcessState::new();
        s.set_cwd("/home/ling");
        s.set_brk(0x7000);
        s.set_env("PATH", "/usr/bin");
        assert_eq!(s.cwd(), "/home/ling");
        assert_eq!(s.brk(), 0x7000);
        assert_eq!(s.get_env("PATH"), Some("/usr/bin"));
        assert_eq!(s.env_count(), 1);
    }
}
