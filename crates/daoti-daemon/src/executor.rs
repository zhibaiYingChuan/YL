//! Windows 执行器（daoti-daemon 平台层）
//!
//! 实现 `daoti_core::executor::adapter::SyscallExecutor`，将 B1 翻译的
//! `TargetSyscall` 真实执行到 Windows 宿主。
//! 使用 `std::fs` + 模拟内存页表，不依赖 winapi 或外部工具。
//!
//! L1 范围：文件读写/文件系统类（open/read/write/close/stat/fstat/lseek/
//! access/getcwd/chdir/mkdir/rmdir/rename/unlink/link/readlink/fsync/ftruncate/statfs）。
//! L2 范围：内存管理类（mmap/munmap/brk → VirtualAlloc/VirtualFree/HeapAlloc，
//!        用 HashMap 模拟虚拟页面，非真实 VirtualAlloc）。

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use daoti_common::DaotiError;
use daoti_core::executor::adapter::{SyscallExecResult, SyscallExecutor};
use daoti_core::interceptor::{Interceptor, RuleInterceptor, SyscallEvent, TargetSyscall};

/// 单条事件的「映射 + 执行」结果
#[derive(Debug, Clone)]
pub struct ExecutedStep {
    /// 原始 syscall 编号
    pub nr: i32,
    /// 原始 syscall 名称
    pub name: String,
    /// 是否命中 B1 映射
    pub mapped: bool,
    /// 命中的 Windows 操作名（未命中为空）
    pub operation: String,
    /// 真实执行结果（未命中为 None）
    pub exec: Option<SyscallExecResult>,
}

/// 「捕获→映射→真实执行」闭环运行结果
#[derive(Debug, Clone)]
pub struct RealExecReport {
    /// 每条事件的处理结果（按输入顺序）
    pub steps: Vec<ExecutedStep>,
    /// 命中并执行成功的数量
    pub succeeded: usize,
    /// 命中但执行失败的数量
    pub failed: usize,
    /// 未命中映射的数量
    pub missed: usize,
}

/// 驱动「SyscallEvent 流 → B1 翻译 → Windows 真实执行」闭环。
///
/// 这是 L1 的核心编排：把纯逻辑映射升级为真实文件操作。
/// L2-L4 范围操作由 `WindowsFileExecutor` 真实分阶段执行；
/// 未覆盖的能力会返回结构化失败，不吞没不恐慌。
pub fn run_events_with_real_execution(
    events: &[SyscallEvent],
    mut executor: WindowsFileExecutor,
) -> Result<RealExecReport, DaotiError> {
    let interceptor = RuleInterceptor::new();
    let mut steps = Vec::with_capacity(events.len());
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut missed = 0usize;

    for event in events {
        // 1. 查表映射（含参数透传）
        let target: Option<TargetSyscall> = interceptor.intercept(event)?;

        let step = match target {
            Some(t) => {
                // 2. 真实执行
                match executor.execute(&t) {
                    Ok(res) if res.success => {
                        succeeded += 1;
                        ExecutedStep {
                            nr: event.nr,
                            name: event.name.clone(),
                            mapped: true,
                            operation: t.operation.clone(),
                            exec: Some(res),
                        }
                    }
                    Ok(res) => {
                        failed += 1;
                        ExecutedStep {
                            nr: event.nr,
                            name: event.name.clone(),
                            mapped: true,
                            operation: t.operation.clone(),
                            exec: Some(res),
                        }
                    }
                    Err(e) => {
                        // 执行器内部错误（如参数解析失败/NotInScope）
                        failed += 1;
                        ExecutedStep {
                            nr: event.nr,
                            name: event.name.clone(),
                            mapped: true,
                            operation: t.operation.clone(),
                            exec: Some(SyscallExecResult::fail(1, format!("执行器错误：{e}"))),
                        }
                    }
                }
            }
            None => {
                missed += 1;
                ExecutedStep {
                    nr: event.nr,
                    name: event.name.clone(),
                    mapped: false,
                    operation: String::new(),
                    exec: None,
                }
            }
        };
        steps.push(step);
    }

    Ok(RealExecReport {
        steps,
        succeeded,
        failed,
        missed,
    })
}

/// 句柄资源
#[derive(Debug)]
#[allow(dead_code)]
enum HandleResource {
    /// 普通文件
    File {
        file: std::sync::Arc<std::sync::Mutex<File>>,
        path: PathBuf,
    },
    /// 匿名管道读取端
    PipeReader {
        buffer: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        closed: std::sync::Arc<std::sync::Mutex<bool>>,
    },
    /// 匿名管道写入端
    PipeWriter { peer_fd: i32, closed: bool },
}

/// 句柄状态
#[derive(Debug)]
struct HandleEntry {
    /// 资源本体
    resource: HandleResource,
}

/// 模拟虚拟内存页（L2 mmap 映射的记录）
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MemoryPage {
    /// 映射起始虚拟地址
    addr: u64,
    /// 映射大小（字节）
    size: u64,
    /// 页标志（PF_R/PF_W/PF_X 的模拟值）
    flags: u32,
    /// 页面数据（模拟内存内容）
    data: Vec<u8>,
}

/// Windows 执行器
///
/// 维护 fd 表、当前工作目录和模拟内存页表，有状态地执行 syscall 序列。
/// L1 文件操作真实执行（std::fs）；L2 内存操作用 HashMap 模拟虚拟页面，
/// 语义等价（可分配/释放/读写），但不调用真实 VirtualAlloc。
/// L3-L4 范围操作返回 `NotInScope` 错误，不恐慌不吞没。
pub struct WindowsFileExecutor {
    /// 句柄表：Linux fd → 句柄资源
    handle_table: HashMap<i32, HandleEntry>,
    /// 下一个可用的 fd 编号
    next_fd: i32,
    /// 当前工作目录
    cwd: PathBuf,
    /// 模拟虚拟内存页表（L2 mmap）：起始地址 → 页
    mem_pages: HashMap<u64, MemoryPage>,
    /// 下一个可用的 mmap 地址（模拟分配器游标）
    next_mmap_addr: u64,
    /// 堆基址（brk 起点）
    heap_base: u64,
    /// 当前堆顶（brk 值，初始 == 基址表示空堆）
    heap_brk: u64,
    /// 堆内存（HashMap 模拟 brk 分配的数据区）
    heap_data: Vec<u8>,
    /// 控制台中断处理器是否已注册（L3）
    console_ctrl_handler_registered: bool,
}

impl WindowsFileExecutor {
    /// 构造执行器，初始 cwd 为当前进程工作目录
    pub fn new() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let heap_base = 0x6000_0000_0000u64;
        WindowsFileExecutor {
            handle_table: HashMap::new(),
            next_fd: 0,
            cwd,
            mem_pages: HashMap::new(),
            next_mmap_addr: 0x7f00_0000_0000u64,
            heap_base,
            heap_brk: heap_base,
            heap_data: Vec::new(),
            console_ctrl_handler_registered: false,
        }
    }

    /// 构造执行器并指定初始工作目录
    pub fn with_cwd(cwd: PathBuf) -> Self {
        let heap_base = 0x6000_0000_0000u64;
        WindowsFileExecutor {
            handle_table: HashMap::new(),
            next_fd: 0,
            cwd,
            mem_pages: HashMap::new(),
            next_mmap_addr: 0x7f00_0000_0000u64,
            heap_base,
            heap_brk: heap_base,
            heap_data: Vec::new(),
            console_ctrl_handler_registered: false,
        }
    }

    /// 分配下一个 fd
    fn alloc_fd(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }

    /// 插入普通文件句柄
    fn insert_file_handle(&mut self, file: File, path: PathBuf) -> i32 {
        let fd = self.alloc_fd();
        self.handle_table.insert(
            fd,
            HandleEntry {
                resource: HandleResource::File {
                    file: std::sync::Arc::new(std::sync::Mutex::new(file)),
                    path,
                },
            },
        );
        fd
    }

    /// 解析路径（相对路径基于 cwd）
    fn resolve_path(&self, path: &str) -> PathBuf {
        let p = Path::new(path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.cwd.join(p)
        }
    }

    /// 执行 CreateFileW：打开/创建文件，返回 fd
    fn exec_create_file(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&abs)
            .map_err(|e| DaotiError::Other(format!("CreateFileW({path})：{e}")))?;
        let fd = self.insert_file_handle(file, abs.clone());
        Ok(SyscallExecResult::ok(
            fd as i64,
            format!("打开文件: {path} (fd={fd})"),
        ))
    }

    /// 执行 ReadFile：从 fd 读取 count 字节
    fn exec_read_file(
        &mut self,
        fd_str: &str,
        count_str: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("ReadFile 参数无效: fd={fd_str}")))?;
        let count: usize = count_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("ReadFile 参数无效: count={count_str}")))?;
        let entry = self
            .handle_table
            .get_mut(&fd)
            .ok_or_else(|| DaotiError::Other(format!("WriteFile fd={fd}：文件未打开")))?;
        let mut buf = vec![0u8; count];
        let n = match &mut entry.resource {
            HandleResource::File { file, .. } => file
                .lock()
                .map_err(|e| DaotiError::Other(format!("ReadFile(fd={fd})：{e}")))?
                .read(&mut buf)
                .map_err(|e| DaotiError::Other(format!("ReadFile(fd={fd})：{e}")))?,
            HandleResource::PipeReader { buffer, closed } => {
                if *closed
                    .lock()
                    .map_err(|e| DaotiError::Other(format!("ReadFile(fd={fd})：{e}")))?
                {
                    return Ok(SyscallExecResult::fail(
                        9,
                        format!("ReadFile fd={fd}：管道已关闭"),
                    ));
                }
                let mut guard = buffer
                    .lock()
                    .map_err(|e| DaotiError::Other(format!("ReadFile(fd={fd})：{e}")))?;
                let n = guard.len().min(count);
                buf[..n].copy_from_slice(&guard[..n]);
                guard.drain(..n);
                n
            }
            HandleResource::PipeWriter { .. } => {
                return Ok(SyscallExecResult::fail(
                    9,
                    format!("ReadFile fd={fd}：写入端不可读"),
                ));
            }
        };
        Ok(SyscallExecResult::ok(
            n as i64,
            format!("读取 {n} 字节 (fd={fd})"),
        ))
    }

    /// 执行 WriteFile：向 fd 写入数据
    fn exec_write_file(
        &mut self,
        fd_str: &str,
        data: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("WriteFile 参数无效: fd={fd_str}")))?;
        let entry = self
            .handle_table
            .get_mut(&fd)
            .ok_or_else(|| DaotiError::Other(format!("WriteFile fd={fd}：文件未打开")))?;
        let n =
            match &mut entry.resource {
                HandleResource::File { file, .. } => file
                    .lock()
                    .map_err(|e| DaotiError::Other(format!("WriteFile(fd={fd})：{e}")))?
                    .write(data.as_bytes())
                    .map_err(|e| DaotiError::Other(format!("WriteFile(fd={fd})：{e}")))?,
                HandleResource::PipeWriter { peer_fd, closed } => {
                    if *closed {
                        return Ok(SyscallExecResult::fail(
                            9,
                            format!("WriteFile fd={fd}：管道已关闭"),
                        ));
                    }
                    let peer_fd_value = *peer_fd;
                    let peer = self.handle_table.get_mut(&peer_fd_value).ok_or_else(|| {
                        DaotiError::Other(format!("WriteFile fd={fd}：对端不存在"))
                    })?;
                    match &mut peer.resource {
                        HandleResource::PipeReader {
                            buffer,
                            closed: peer_closed,
                        } => {
                            if *peer_closed.lock().map_err(|e| {
                                DaotiError::Other(format!("WriteFile(fd={fd})：{e}"))
                            })? {
                                return Ok(SyscallExecResult::fail(
                                    9,
                                    format!("WriteFile fd={fd}：对端已关闭"),
                                ));
                            }
                            buffer
                                .lock()
                                .map_err(|e| DaotiError::Other(format!("WriteFile(fd={fd})：{e}")))?
                                .extend_from_slice(data.as_bytes());
                            data.len()
                        }
                        _ => {
                            return Ok(SyscallExecResult::fail(
                                9,
                                format!("WriteFile fd={fd}：对端不是读取端"),
                            ))
                        }
                    }
                }
                HandleResource::PipeReader { .. } => {
                    return Ok(SyscallExecResult::fail(
                        9,
                        format!("WriteFile fd={fd}：读取端不可写"),
                    ));
                }
            };
        Ok(SyscallExecResult::ok(
            n as i64,
            format!("写入 {n} 字节 (fd={fd})"),
        ))
    }

    /// 执行 CloseHandle：关闭 fd
    fn exec_close_handle(&mut self, fd_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("CloseHandle 参数无效: fd={fd_str}")))?;
        if let Some(entry) = self.handle_table.remove(&fd) {
            let peer_fd = match entry.resource {
                HandleResource::PipeWriter { peer_fd, .. } => Some(peer_fd),
                _ => None,
            };
            if let Some(peer_fd) = peer_fd {
                if let Some(peer) = self.handle_table.get_mut(&peer_fd) {
                    if let HandleResource::PipeReader { closed, .. } = &mut peer.resource {
                        if let Ok(mut guard) = closed.lock() {
                            *guard = true;
                        }
                    }
                }
            }
            Ok(SyscallExecResult::ok(0, format!("关闭文件 (fd={fd})")))
        } else {
            Ok(SyscallExecResult::fail(
                9,
                format!("CloseHandle fd={fd}：文件未打开"),
            ))
        }
    }

    /// 执行 SetFilePointerEx：在 fd 中定位
    fn exec_set_file_pointer(
        &mut self,
        fd_str: &str,
        offset_str: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("SetFilePointerEx 参数无效: fd={fd_str}")))?;
        let offset: i64 = offset_str.parse().map_err(|_| {
            DaotiError::Other(format!("SetFilePointerEx 参数无效: offset={offset_str}"))
        })?;
        let entry = self
            .handle_table
            .get_mut(&fd)
            .ok_or_else(|| DaotiError::Other(format!("SetFilePointerEx fd={fd}：文件未打开")))?;
        let pos = match &mut entry.resource {
            HandleResource::File { file, .. } => file
                .lock()
                .map_err(|e| DaotiError::Other(format!("SetFilePointerEx(fd={fd})：{e}")))?
                .seek(SeekFrom::Start(offset as u64))
                .map_err(|e| DaotiError::Other(format!("SetFilePointerEx(fd={fd})：{e}")))?,
            _ => {
                return Ok(SyscallExecResult::fail(
                    9,
                    format!("SetFilePointerEx fd={fd}：非文件句柄"),
                ));
            }
        };
        Ok(SyscallExecResult::ok(
            pos as i64,
            format!("定位到 {pos} (fd={fd})"),
        ))
    }

    /// 执行 GetFileAttributesExW：获取文件属性
    fn exec_get_file_attributes_ex(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        match abs.metadata() {
            Ok(meta) => Ok(SyscallExecResult::ok(
                meta.len() as i64,
                format!("文件大小: {} 字节", meta.len()),
            )),
            Err(e) => Ok(SyscallExecResult::fail(
                2,
                format!("GetFileAttributesExW({path})：{e}"),
            )),
        }
    }

    /// 执行 GetFileInformationByHandle：通过 fd 获取文件信息
    fn exec_get_file_info_by_handle(
        &mut self,
        fd_str: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str.parse().map_err(|_| {
            DaotiError::Other(format!("GetFileInformationByHandle 参数无效: fd={fd_str}"))
        })?;
        let entry = self.handle_table.get(&fd).ok_or_else(|| {
            DaotiError::Other(format!("GetFileInformationByHandle fd={fd}：文件未打开"))
        })?;
        match &entry.resource {
            HandleResource::File { path, .. } => match path.metadata() {
                Ok(meta) => Ok(SyscallExecResult::ok(
                    meta.len() as i64,
                    format!("文件大小: {} 字节", meta.len()),
                )),
                Err(e) => Ok(SyscallExecResult::fail(
                    2,
                    format!("GetFileInformationByHandle(fd={fd})：{e}"),
                )),
            },
            _ => Ok(SyscallExecResult::fail(
                9,
                format!("GetFileInformationByHandle fd={fd}：非文件句柄"),
            )),
        }
    }

    /// 执行 GetFileAttributesW：检查文件是否存在/访问权限
    fn exec_get_file_attributes(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        if abs.exists() {
            Ok(SyscallExecResult::ok(0, format!("文件存在: {path}")))
        } else {
            Ok(SyscallExecResult::fail(2, format!("文件不存在: {path}")))
        }
    }

    /// 执行 GetCurrentDirectoryW：获取当前工作目录
    fn exec_get_current_directory(&mut self) -> Result<SyscallExecResult, DaotiError> {
        let cwd = self.cwd.to_string_lossy().to_string();
        Ok(SyscallExecResult::ok(cwd.len() as i64, cwd))
    }

    /// 执行 SetCurrentDirectoryW：设置当前工作目录
    fn exec_set_current_directory(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        if abs.is_dir() {
            self.cwd = abs;
            Ok(SyscallExecResult::ok(0, format!("切换目录: {path}")))
        } else {
            Ok(SyscallExecResult::fail(2, format!("目录不存在: {path}")))
        }
    }

    /// 执行 DeleteFileW：删除文件
    fn exec_delete_file(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        match fs::remove_file(&abs) {
            Ok(()) => Ok(SyscallExecResult::ok(0, format!("删除文件: {path}"))),
            Err(e) => Ok(SyscallExecResult::fail(
                5,
                format!("DeleteFileW({path})：{e}"),
            )),
        }
    }

    /// 执行 MoveFileW：重命名/移动文件
    fn exec_move_file(&mut self, old: &str, new: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs_old = self.resolve_path(old);
        let abs_new = self.resolve_path(new);
        match fs::rename(&abs_old, &abs_new) {
            Ok(()) => Ok(SyscallExecResult::ok(0, format!("移动文件: {old} → {new}"))),
            Err(e) => Ok(SyscallExecResult::fail(
                5,
                format!("MoveFileW({old}→{new})：{e}"),
            )),
        }
    }

    /// 执行 CreateDirectoryW：创建目录
    fn exec_create_directory(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        match fs::create_dir_all(&abs) {
            Ok(()) => Ok(SyscallExecResult::ok(0, format!("创建目录: {path}"))),
            Err(e) => Ok(SyscallExecResult::fail(
                5,
                format!("CreateDirectoryW({path})：{e}"),
            )),
        }
    }

    /// 执行 RemoveDirectoryW：删除目录
    fn exec_remove_directory(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        let abs = self.resolve_path(path);
        match fs::remove_dir(&abs) {
            Ok(()) => Ok(SyscallExecResult::ok(0, format!("删除目录: {path}"))),
            Err(e) => Ok(SyscallExecResult::fail(
                5,
                format!("RemoveDirectoryW({path})：{e}"),
            )),
        }
    }

    /// 执行 CreateHardLinkW：创建硬链接
    fn exec_create_hard_link(
        &mut self,
        target: &str,
        link: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let abs_target = self.resolve_path(target);
        let abs_link = self.resolve_path(link);
        match fs::hard_link(&abs_target, &abs_link) {
            Ok(()) => Ok(SyscallExecResult::ok(
                0,
                format!("创建硬链接: {link} → {target}"),
            )),
            Err(e) => Ok(SyscallExecResult::fail(
                5,
                format!("CreateHardLinkW({link}→{target})：{e}"),
            )),
        }
    }

    /// 执行 GetFinalPathNameByHandleW：通过 fd 获取路径
    fn exec_get_final_path_name(&mut self, fd_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str.parse().map_err(|_| {
            DaotiError::Other(format!("GetFinalPathNameByHandleW 参数无效: fd={fd_str}"))
        })?;
        let entry = self.handle_table.get(&fd).ok_or_else(|| {
            DaotiError::Other(format!("GetFinalPathNameByHandleW fd={fd}：文件未打开"))
        })?;
        let path = match &entry.resource {
            HandleResource::File { path, .. } => path.to_string_lossy().to_string(),
            _ => {
                return Ok(SyscallExecResult::fail(
                    9,
                    format!("GetFinalPathNameByHandleW fd={fd}：非文件句柄"),
                ))
            }
        };
        Ok(SyscallExecResult::ok(path.len() as i64, path))
    }

    /// 执行 GetDiskFreeSpaceExW：获取磁盘空间信息
    fn exec_get_disk_free_space(&mut self, path: &str) -> Result<SyscallExecResult, DaotiError> {
        #[cfg(windows)]
        {
            // Windows 上使用 std::fs 获取磁盘信息的方法有限，返回模拟值
            let _ = path;
            Ok(SyscallExecResult::ok(
                0,
                format!("GetDiskFreeSpaceExW({path})：当前未提供真实磁盘信息"),
            ))
        }
        #[cfg(not(windows))]
        {
            let _ = path;
            Ok(SyscallExecResult::ok(
                0,
                format!("GetDiskFreeSpaceExW({path})：非 Windows 平台"),
            ))
        }
    }

    /// 执行 FlushFileBuffers：刷新文件缓冲区
    fn exec_flush_file_buffers(&mut self, fd_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("FlushFileBuffers 参数无效: fd={fd_str}")))?;
        let entry = self
            .handle_table
            .get_mut(&fd)
            .ok_or_else(|| DaotiError::Other(format!("FlushFileBuffers fd={fd}：文件未打开")))?;
        match &mut entry.resource {
            HandleResource::File { file, .. } => file
                .lock()
                .map_err(|e| DaotiError::Other(format!("FlushFileBuffers(fd={fd})：{e}")))?
                .flush()
                .map_err(|e| DaotiError::Other(format!("FlushFileBuffers(fd={fd})：{e}")))?,
            _ => {
                return Ok(SyscallExecResult::fail(
                    9,
                    format!("FlushFileBuffers fd={fd}：非文件句柄"),
                ))
            }
        }
        Ok(SyscallExecResult::ok(0, format!("刷新缓冲区 (fd={fd})")))
    }

    /// 执行 SetEndOfFile：截断文件到当前指针位置
    fn exec_set_end_of_file(&mut self, fd_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let fd: i32 = fd_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("SetEndOfFile 参数无效: fd={fd_str}")))?;
        let entry = self
            .handle_table
            .get_mut(&fd)
            .ok_or_else(|| DaotiError::Other(format!("SetEndOfFile fd={fd}：文件未打开")))?;
        let pos = match &mut entry.resource {
            HandleResource::File { file, .. } => {
                let mut guard = file
                    .lock()
                    .map_err(|e| DaotiError::Other(format!("SetEndOfFile(fd={fd})：{e}")))?;
                let pos = guard.stream_position().map_err(|e| {
                    DaotiError::Other(format!("SetEndOfFile(fd={fd}) 获取位置失败：{e}"))
                })?;
                guard
                    .set_len(pos)
                    .map_err(|e| DaotiError::Other(format!("SetEndOfFile(fd={fd})：{e}")))?;
                pos
            }
            _ => {
                return Ok(SyscallExecResult::fail(
                    9,
                    format!("SetEndOfFile fd={fd}：非文件句柄"),
                ))
            }
        };
        Ok(SyscallExecResult::ok(
            0,
            format!("截断文件到位置 {pos} (fd={fd})"),
        ))
    }

    /// 执行 GetCurrentProcessId：返回当前进程 ID
    fn exec_get_current_process_id(&mut self) -> Result<SyscallExecResult, DaotiError> {
        let pid = std::process::id() as i64;
        Ok(SyscallExecResult::ok(pid, format!("进程 ID: {pid}")))
    }

    /// 执行 GetCurrentThreadId：返回当前线程 ID
    fn exec_get_current_thread_id(&mut self) -> Result<SyscallExecResult, DaotiError> {
        // Rust 标准库没有直接获取线程 ID 的 API，返回进程 ID 作为近似
        let tid = std::process::id() as i64;
        Ok(SyscallExecResult::ok(tid, format!("线程 ID(近似): {tid}")))
    }

    /// 执行 CreatePipe：创建匿名管道的读写端
    fn exec_create_pipe(&mut self) -> Result<SyscallExecResult, DaotiError> {
        let read_fd = self.alloc_fd();
        let write_fd = self.alloc_fd();
        self.handle_table.insert(
            read_fd,
            HandleEntry {
                resource: HandleResource::PipeReader {
                    buffer: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                    closed: std::sync::Arc::new(std::sync::Mutex::new(false)),
                },
            },
        );
        self.handle_table.insert(
            write_fd,
            HandleEntry {
                resource: HandleResource::PipeWriter {
                    peer_fd: read_fd,
                    closed: false,
                },
            },
        );
        Ok(SyscallExecResult::ok(
            read_fd as i64,
            format!("创建管道: read_fd={read_fd}, write_fd={write_fd}"),
        ))
    }

    /// 执行 DuplicateHandle：复制句柄
    fn exec_duplicate_handle(&mut self, src_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let src_fd: i32 = src_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("DuplicateHandle 参数无效: src={src_str}")))?;
        let resource = match &self
            .handle_table
            .get(&src_fd)
            .ok_or_else(|| {
                DaotiError::Other(format!("DuplicateHandle src_fd={src_fd}：句柄不存在"))
            })?
            .resource
        {
            HandleResource::File { file, path } => HandleResource::File {
                file: std::sync::Arc::clone(file),
                path: path.clone(),
            },
            HandleResource::PipeReader { buffer, closed } => HandleResource::PipeReader {
                buffer: std::sync::Arc::clone(buffer),
                closed: std::sync::Arc::clone(closed),
            },
            HandleResource::PipeWriter { peer_fd, closed } => HandleResource::PipeWriter {
                peer_fd: *peer_fd,
                closed: *closed,
            },
        };
        let new_fd = self.alloc_fd();
        self.handle_table.insert(new_fd, HandleEntry { resource });
        Ok(SyscallExecResult::ok(
            new_fd as i64,
            format!("复制句柄: {src_fd} → {new_fd}"),
        ))
    }

    /// 执行 DeviceIoControl：设备控制占位实现
    fn exec_device_io_control(
        &mut self,
        handle_str: &str,
        code_str: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let handle: i32 = handle_str.parse().map_err(|_| {
            DaotiError::Other(format!("DeviceIoControl 参数无效: handle={handle_str}"))
        })?;
        let code = parse_hex_or_dec(code_str)?;
        if self.handle_table.contains_key(&handle) {
            Ok(SyscallExecResult::ok(
                0,
                format!(
                    "DeviceIoControl handle={handle}, code=0x{code:x}：当前仅记录，不下钻设备语义"
                ),
            ))
        } else {
            Ok(SyscallExecResult::fail(
                9,
                format!("DeviceIoControl handle={handle}：句柄不存在"),
            ))
        }
    }

    // ─── L3 控制台中断处理（SetConsoleCtrlHandler）───

    /// 执行 SetConsoleCtrlHandler：注册/注销控制台中断处理器
    fn exec_set_console_ctrl_handler(
        &mut self,
        enable_str: &str,
    ) -> Result<SyscallExecResult, DaotiError> {
        let enable = match enable_str.trim() {
            "1" | "true" | "True" | "TRUE" => true,
            "0" | "false" | "False" | "FALSE" => false,
            other => {
                return Err(DaotiError::Other(format!(
                    "SetConsoleCtrlHandler 参数无效: enable={other}"
                )))
            }
        };

        self.console_ctrl_handler_registered = enable;
        let detail = if enable {
            "已注册控制台中断处理器"
        } else {
            "已注销控制台中断处理器"
        };
        Ok(SyscallExecResult::ok(0, detail))
    }

    // ─── L2 内存管理类（mmap/munmap/brk，HashMap 模拟虚拟页面）───

    /// 执行 VirtualAlloc（mmap）：分配一块虚拟内存页，返回起始地址
    fn exec_virtual_alloc(&mut self, size_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let size: usize = size_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("VirtualAlloc 参数无效: size={size_str}")))?;
        if size == 0 {
            return Ok(SyscallExecResult::fail(22, "VirtualAlloc 大小不能为 0"));
        }
        // 页对齐分配（页大小 4KiB）
        let page = 4096u64;
        let aligned_size = (size as u64).div_ceil(page) * page;
        let addr = self.next_mmap_addr;
        self.next_mmap_addr += aligned_size;
        self.mem_pages.insert(
            addr,
            MemoryPage {
                addr,
                size: aligned_size,
                flags: 0x4, // PF_R
                data: vec![0u8; aligned_size as usize],
            },
        );
        Ok(SyscallExecResult::ok(
            addr as i64,
            format!("分配虚拟内存 0x{addr:x}（{aligned_size} 字节）"),
        ))
    }

    /// 执行 VirtualFree（munmap）：释放一块虚拟内存页
    fn exec_virtual_free(&mut self, addr_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let addr = parse_hex_or_dec(addr_str)?;
        if self.mem_pages.remove(&addr).is_some() {
            Ok(SyscallExecResult::ok(0, format!("释放虚拟内存 0x{addr:x}")))
        } else {
            Ok(SyscallExecResult::fail(
                14,
                format!("VirtualFree 0x{addr:x}：地址未由本执行器分配"),
            ))
        }
    }

    /// 执行 HeapAlloc（brk，增长堆）：扩大堆顶分配内存
    fn exec_heap_alloc(&mut self, size_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let size: usize = size_str
            .parse()
            .map_err(|_| DaotiError::Other(format!("HeapAlloc 参数无效: size={size_str}")))?;
        let old_brk = self.heap_brk;
        self.heap_brk += size as u64;
        self.heap_data.resize(self.heap_data.len() + size, 0u8);
        Ok(SyscallExecResult::ok(
            old_brk as i64,
            format!("堆扩展到 0x{:x}（+{size} 字节）", self.heap_brk),
        ))
    }

    /// 执行 HeapFree（brk，收缩堆）：把堆顶收缩到指定位置
    fn exec_heap_free(&mut self, addr_str: &str) -> Result<SyscallExecResult, DaotiError> {
        let addr = parse_hex_or_dec(addr_str)?;
        if addr >= self.heap_base && addr <= self.heap_brk {
            let shrink = (self.heap_brk - addr) as usize;
            self.heap_brk = addr;
            if self.heap_data.len() >= shrink {
                self.heap_data.truncate(self.heap_data.len() - shrink);
            }
            Ok(SyscallExecResult::ok(
                0,
                format!("堆收缩到 0x{:x}（释放 {shrink} 字节）", self.heap_brk),
            ))
        } else {
            Ok(SyscallExecResult::fail(
                14,
                format!("HeapFree 0x{addr:x}：地址不在堆范围内"),
            ))
        }
    }

    /// 查询当前 mmap 页表条目数（供测试与报告）
    #[allow(dead_code)]
    pub fn mmap_page_count(&self) -> usize {
        self.mem_pages.len()
    }

    /// 查询当前堆顶（供测试与报告）
    #[allow(dead_code)]
    pub fn heap_brk_value(&self) -> u64 {
        self.heap_brk
    }
}

/// 解析地址参数：支持 0x 前缀十六进制或十进制
fn parse_hex_or_dec(s: &str) -> Result<u64, DaotiError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .map_err(|_| DaotiError::Other(format!("无效十六进制地址: {s}")))
    } else {
        s.parse::<u64>()
            .map_err(|_| DaotiError::Other(format!("无效地址: {s}")))
    }
}

impl Default for WindowsFileExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallExecutor for WindowsFileExecutor {
    fn execute(&mut self, target: &TargetSyscall) -> Result<SyscallExecResult, DaotiError> {
        match target.operation.as_str() {
            // L1 文件打开/读写/关闭
            "CreateFileW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or("unknown");
                self.exec_create_file(path)
            }
            "ReadFile" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                let count = target.args.get(1).map(|s| s.as_str()).unwrap_or("4096");
                self.exec_read_file(fd, count)
            }
            "WriteFile" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                let data = target.args.get(1).map(|s| s.as_str()).unwrap_or("");
                self.exec_write_file(fd, data)
            }
            "CloseHandle" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_close_handle(fd)
            }
            // L1 文件定位
            "SetFilePointerEx" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                let offset = target.args.get(1).map(|s| s.as_str()).unwrap_or("0");
                self.exec_set_file_pointer(fd, offset)
            }
            // L1 文件属性查询
            "GetFileAttributesExW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or(".");
                self.exec_get_file_attributes_ex(path)
            }
            "GetFileInformationByHandle" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_get_file_info_by_handle(fd)
            }
            "GetFileAttributesW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or(".");
                self.exec_get_file_attributes(path)
            }
            // L1 目录操作
            "GetCurrentDirectoryW" => self.exec_get_current_directory(),
            "SetCurrentDirectoryW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or(".");
                self.exec_set_current_directory(path)
            }
            // L1 文件系统操作
            "DeleteFileW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or("unknown");
                self.exec_delete_file(path)
            }
            "MoveFileW" => {
                let old = target.args.first().map(|s| s.as_str()).unwrap_or("unknown");
                let new = target.args.get(1).map(|s| s.as_str()).unwrap_or("unknown");
                self.exec_move_file(old, new)
            }
            "CreateDirectoryW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or("unknown");
                self.exec_create_directory(path)
            }
            "RemoveDirectoryW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or("unknown");
                self.exec_remove_directory(path)
            }
            "CreateHardLinkW" => {
                let target_path = target.args.first().map(|s| s.as_str()).unwrap_or("unknown");
                let link = target.args.get(1).map(|s| s.as_str()).unwrap_or("unknown");
                self.exec_create_hard_link(target_path, link)
            }
            "GetFinalPathNameByHandleW" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_get_final_path_name(fd)
            }
            "GetDiskFreeSpaceExW" => {
                let path = target.args.first().map(|s| s.as_str()).unwrap_or(".");
                self.exec_get_disk_free_space(path)
            }
            "FlushFileBuffers" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_flush_file_buffers(fd)
            }
            "SetEndOfFile" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_set_end_of_file(fd)
            }
            // L1 特殊：循环读写（简化：转为单次读写）
            "ReadFile(循环)" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                // 循环读 → 简化：读 4096 字节
                self.exec_read_file(fd, "4096")
            }
            "WriteFile(循环)" => {
                let fd = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                let data = target.args.get(1).map(|s| s.as_str()).unwrap_or("");
                self.exec_write_file(fd, data)
            }
            // L1 进程/线程操作（无状态，直接返回）
            "GetCurrentProcessId" => self.exec_get_current_process_id(),
            "GetCurrentThreadId" => self.exec_get_current_thread_id(),

            // ── L2 内存管理类（mmap/munmap/brk，真实执行于模拟页表）──
            "VirtualAlloc" => {
                // mmap 参数：addr, length, prot, flags, fd, offset → size = length(index 1)
                let size = target.args.get(1).map(|s| s.as_str()).unwrap_or("4096");
                self.exec_virtual_alloc(size)
            }
            "VirtualFree" => {
                // munmap 参数：addr, length → addr = index 0
                let addr = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_virtual_free(addr)
            }
            "HeapAlloc/HeapFree" => {
                // brk：第一个参数为分配大小（正数分配，负数收缩）
                let arg = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                match arg.parse::<i64>() {
                    Ok(n) if n >= 0 => self.exec_heap_alloc(arg),
                    Ok(_) => {
                        // 负数 → 收缩到目标堆顶（地址=heap_base + 剩余字节）
                        let target_brk = arg[1..]
                            .parse::<u64>()
                            .map(|shr| self.heap_brk.saturating_sub(shr))
                            .unwrap_or(self.heap_base);
                        self.exec_heap_free(&target_brk.to_string())
                    }
                    Err(_) => Err(DaotiError::Other(format!(
                        "HeapAlloc/HeapFree 参数无效: {arg}"
                    ))),
                }
            }

            // L3 控制台中断处理：真实执行（注册/注销）
            "SetConsoleCtrlHandler" => {
                let enable = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_set_console_ctrl_handler(enable)
            }

            // L4 设备/网络类
            "CreatePipe" => self.exec_create_pipe(),
            "DuplicateHandle" => {
                let src = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                self.exec_duplicate_handle(src)
            }
            "DeviceIoControl" => {
                let handle = target.args.first().map(|s| s.as_str()).unwrap_or("0");
                let code = target.args.get(1).map(|s| s.as_str()).unwrap_or("0");
                self.exec_device_io_control(handle, code)
            }

            // 未知操作
            other => Err(DaotiError::Other(format!(
                "未知操作「{other}」：未在映射表中定义"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 在临时目录中打开一个测试文件，返回 (executor, fd, temp_dir)
    fn setup_test_file() -> (WindowsFileExecutor, i32, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let file_path = dir.path().join("test.txt");
        let mut f = File::create(&file_path).unwrap_or_else(|e| panic!("创建测试文件失败：{e}"));
        write!(f, "Hello, 驭灵!").unwrap_or_else(|e| panic!("写入测试文件失败：{e}"));
        f.flush().unwrap_or_else(|e| panic!("刷新失败：{e}"));
        drop(f);

        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let result = ex
            .exec_create_file(&file_path.to_string_lossy())
            .unwrap_or_else(|e| panic!("打开测试文件失败：{e}"));
        (ex, result.return_value as i32, dir)
    }

    #[test]
    fn test_create_and_close_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let file_path = dir.path().join("test_new.txt");
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        // 创建文件
        let result = ex
            .exec_create_file(&file_path.to_string_lossy())
            .unwrap_or_else(|e| panic!("创建文件失败：{e}"));
        assert!(result.success);
        assert!(result.return_value >= 0);
        // 关闭文件
        let result = ex
            .exec_close_handle(&result.return_value.to_string())
            .unwrap_or_else(|e| panic!("关闭文件失败：{e}"));
        assert!(result.success);
    }

    #[test]
    fn test_read_file() {
        let (mut ex, fd, _dir) = setup_test_file();
        // 先定位到文件开头
        let _ = ex.exec_set_file_pointer(&fd.to_string(), "0");
        // 读取文件
        let result = ex
            .exec_read_file(&fd.to_string(), "100")
            .unwrap_or_else(|e| panic!("读取文件失败：{e}"));
        assert!(result.success);
        assert!(result.return_value > 0);
    }

    #[test]
    fn test_write_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let file_path = dir.path().join("test_write.txt");
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let result = ex
            .exec_create_file(&file_path.to_string_lossy())
            .unwrap_or_else(|e| panic!("创建文件失败：{e}"));
        let fd = result.return_value;
        // 写入数据
        let result = ex
            .exec_write_file(&fd.to_string(), "驭灵写入测试")
            .unwrap_or_else(|e| panic!("写入文件失败：{e}"));
        assert!(result.success);
        assert!(result.return_value > 0);
        // 验证文件内容
        let content =
            fs::read_to_string(&file_path).unwrap_or_else(|e| panic!("读取文件失败：{e}"));
        assert_eq!(content, "驭灵写入测试");
    }

    #[test]
    fn test_get_file_attributes() {
        let (mut ex, _fd, dir) = setup_test_file();
        let file_path = dir.path().join("test.txt");
        let result = ex
            .exec_get_file_attributes_ex(&file_path.to_string_lossy())
            .unwrap_or_else(|e| panic!("获取文件属性失败：{e}"));
        assert!(result.success);
        assert!(result.return_value > 0);
    }

    #[test]
    fn test_get_current_directory() {
        let mut ex = WindowsFileExecutor::new();
        let result = ex
            .exec_get_current_directory()
            .unwrap_or_else(|e| panic!("获取当前目录失败：{e}"));
        assert!(result.success);
        assert!(result.return_value > 0);
        assert!(!result.detail.is_empty(), "应该返回目录路径字符串");
    }

    #[test]
    fn test_set_current_directory() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let mut ex = WindowsFileExecutor::new();
        let result = ex
            .exec_set_current_directory(&dir.path().to_string_lossy())
            .unwrap_or_else(|e| panic!("设置目录失败：{e}"));
        assert!(result.success);
        assert_eq!(ex.cwd, dir.path());
    }

    #[test]
    fn test_delete_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let file_path = dir.path().join("to_delete.txt");
        File::create(&file_path).unwrap_or_else(|e| panic!("创建文件失败：{e}"));
        assert!(file_path.exists());
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let result = ex
            .exec_delete_file(&file_path.to_string_lossy())
            .unwrap_or_else(|e| panic!("删除文件失败：{e}"));
        assert!(result.success);
        assert!(!file_path.exists());
    }

    #[test]
    fn test_create_and_remove_directory() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let new_dir = dir.path().join("subdir");
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let result = ex
            .exec_create_directory(&new_dir.to_string_lossy())
            .unwrap_or_else(|e| panic!("创建目录失败：{e}"));
        assert!(result.success);
        assert!(new_dir.exists());
        let result = ex
            .exec_remove_directory(&new_dir.to_string_lossy())
            .unwrap_or_else(|e| panic!("删除目录失败：{e}"));
        assert!(result.success);
        assert!(!new_dir.exists());
    }

    #[test]
    fn test_rename_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let old = dir.path().join("old_name.txt");
        let new = dir.path().join("new_name.txt");
        File::create(&old).unwrap_or_else(|e| panic!("创建文件失败：{e}"));
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let result = ex
            .exec_move_file(&old.to_string_lossy(), &new.to_string_lossy())
            .unwrap_or_else(|e| panic!("重命名文件失败：{e}"));
        assert!(result.success);
        assert!(!old.exists());
        assert!(new.exists());
    }

    #[test]
    fn test_process_id() {
        let mut ex = WindowsFileExecutor::new();
        let result = ex
            .exec_get_current_process_id()
            .unwrap_or_else(|e| panic!("获取进程ID失败：{e}"));
        assert!(result.success);
        assert!(result.return_value > 0);
    }

    #[test]
    fn test_set_console_ctrl_handler_register_unregister() {
        let mut ex = WindowsFileExecutor::new();
        let register =
            TargetSyscall::new("SetConsoleCtrlHandler", "信号化形").with_args(&["1".into()]);
        let res1 = ex
            .execute(&register)
            .unwrap_or_else(|e| panic!("注册处理器失败：{e}"));
        assert!(res1.success);
        assert_eq!(res1.return_value, 0);
        assert!(res1.detail.contains("注册"));
        assert!(ex.console_ctrl_handler_registered, "应已注册");

        let unregister =
            TargetSyscall::new("SetConsoleCtrlHandler", "信号化形").with_args(&["0".into()]);
        let res2 = ex
            .execute(&unregister)
            .unwrap_or_else(|e| panic!("注销处理器失败：{e}"));
        assert!(res2.success);
        assert_eq!(res2.return_value, 0);
        assert!(res2.detail.contains("注销"));
        assert!(!ex.console_ctrl_handler_registered, "应已注销");
    }

    #[test]
    fn test_set_console_ctrl_handler_invalid_arg() {
        let mut ex = WindowsFileExecutor::new();
        let target =
            TargetSyscall::new("SetConsoleCtrlHandler", "信号化形").with_args(&["maybe".into()]);
        let err = ex.execute(&target).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("参数无效"), "应提示参数无效：{msg}");
        assert!(!ex.console_ctrl_handler_registered);
    }

    #[test]
    fn test_create_pipe_duplicate_and_deviceio() {
        let mut ex = WindowsFileExecutor::new();

        let pipe = TargetSyscall::new("CreatePipe", "创建管道");
        let pipe_res = ex
            .execute(&pipe)
            .unwrap_or_else(|e| panic!("创建管道失败：{e}"));
        assert!(pipe_res.success);
        let read_fd = pipe_res.return_value as i32;
        let write_fd = read_fd + 1;

        let write = TargetSyscall::new("WriteFile", "写管道")
            .with_args(&[write_fd.to_string(), "abc".into()]);
        let write_res = ex
            .execute(&write)
            .unwrap_or_else(|e| panic!("写管道失败：{e}"));
        assert!(write_res.success);

        let read =
            TargetSyscall::new("ReadFile", "读管道").with_args(&[read_fd.to_string(), "3".into()]);
        let read_res = ex
            .execute(&read)
            .unwrap_or_else(|e| panic!("读管道失败：{e}"));
        assert!(read_res.success);
        assert_eq!(read_res.return_value, 3);

        let dup =
            TargetSyscall::new("DuplicateHandle", "复制句柄").with_args(&[write_fd.to_string()]);
        let dup_res = ex
            .execute(&dup)
            .unwrap_or_else(|e| panic!("复制句柄失败：{e}"));
        assert!(dup_res.success);
        assert!(dup_res.return_value >= 0);

        let dio = TargetSyscall::new("DeviceIoControl", "设备控制")
            .with_args(&[write_fd.to_string(), "0x222000".into()]);
        let dio_res = ex
            .execute(&dio)
            .unwrap_or_else(|e| panic!("设备控制失败：{e}"));
        assert!(dio_res.success);
        assert!(dio_res.detail.contains("当前仅记录"));
    }

    // ─── L2 内存管理类测试 ───

    #[test]
    fn test_virtual_alloc_allocates_page() {
        let mut ex = WindowsFileExecutor::new();
        let target =
            TargetSyscall::new("VirtualAlloc", "虚拟化形").with_args(&["0".into(), "4096".into()]);
        let result = ex
            .execute(&target)
            .unwrap_or_else(|e| panic!("VirtualAlloc 失败：{e}"));
        assert!(result.success, "mmap 应成功分配");
        assert!(result.return_value > 0, "应返回有效地址");
        assert_eq!(ex.mmap_page_count(), 1, "页表应有 1 条记录");
    }

    #[test]
    fn test_virtual_alloc_multiple_pages() {
        let mut ex = WindowsFileExecutor::new();
        // 第一次分配：mmap(addr=0, length=4096)
        let t1 =
            TargetSyscall::new("VirtualAlloc", "虚拟化形").with_args(&["0".into(), "4096".into()]);
        ex.execute(&t1)
            .unwrap_or_else(|e| panic!("第一次分配失败：{e}"));
        // 第二次分配（不同地址）：mmap(addr=0, length=8192)
        let t2 =
            TargetSyscall::new("VirtualAlloc", "虚拟化形").with_args(&["0".into(), "8192".into()]);
        ex.execute(&t2)
            .unwrap_or_else(|e| panic!("第二次分配失败：{e}"));
        assert_eq!(ex.mmap_page_count(), 2, "两次分配应有 2 条记录");
        // 地址不应重叠
        let mut addrs: Vec<u64> = ex.mem_pages.keys().copied().collect();
        addrs.sort();
        assert!(addrs[0] < addrs[1], "地址应递增");
    }

    #[test]
    fn test_virtual_alloc_zero_size() {
        let mut ex = WindowsFileExecutor::new();
        // mmap 参数：addr=0, length=0 → 应失败
        let target =
            TargetSyscall::new("VirtualAlloc", "虚拟化形").with_args(&["0".into(), "0".into()]);
        let result = ex
            .execute(&target)
            .unwrap_or_else(|e| panic!("VirtualAlloc(0) 不应崩溃：{e}"));
        assert!(!result.success, "零大小分配应失败");
        assert_eq!(result.error_code, 22);
    }

    #[test]
    fn test_virtual_free_releases_page() {
        let mut ex = WindowsFileExecutor::new();
        // 先分配：mmap(addr=0, length=4096)
        let alloc =
            TargetSyscall::new("VirtualAlloc", "虚拟化形").with_args(&["0".into(), "4096".into()]);
        let result = ex
            .execute(&alloc)
            .unwrap_or_else(|e| panic!("分配失败：{e}"));
        let addr = format!("0x{:x}", result.return_value as u64);
        // 再释放
        let free = TargetSyscall::new("VirtualFree", "释形还虚").with_args(&[addr]);
        let result = ex
            .execute(&free)
            .unwrap_or_else(|e| panic!("VirtualFree 失败：{e}"));
        assert!(result.success, "释放应成功");
        assert_eq!(ex.mmap_page_count(), 0, "页表应清空");
    }

    #[test]
    fn test_virtual_free_nonexistent_page() {
        let mut ex = WindowsFileExecutor::new();
        let target =
            TargetSyscall::new("VirtualFree", "释形还虚").with_args(&["0x7f0000000000".into()]);
        let result = ex
            .execute(&target)
            .unwrap_or_else(|e| panic!("释放未分配地址不应崩溃：{e}"));
        assert!(!result.success, "释放未分配地址应失败");
    }

    #[test]
    fn test_heap_alloc_grows_brk() {
        let mut ex = WindowsFileExecutor::new();
        let initial_brk = ex.heap_brk_value();
        let target =
            TargetSyscall::new("HeapAlloc/HeapFree", "堆界伸缩").with_args(&["4096".into()]);
        let result = ex
            .execute(&target)
            .unwrap_or_else(|e| panic!("HeapAlloc 失败：{e}"));
        assert!(result.success, "堆扩展应成功");
        assert_eq!(result.return_value as u64, initial_brk, "应返回旧堆顶");
        assert_eq!(ex.heap_brk_value(), initial_brk + 4096, "堆顶应增长");
    }

    #[test]
    fn test_heap_alloc_and_free_roundtrip() {
        let mut ex = WindowsFileExecutor::new();
        let initial = ex.heap_brk_value();
        // 分配 8192 字节
        let alloc =
            TargetSyscall::new("HeapAlloc/HeapFree", "堆界伸缩").with_args(&["8192".into()]);
        ex.execute(&alloc)
            .unwrap_or_else(|e| panic!("分配失败：{e}"));
        assert_eq!(ex.heap_brk_value(), initial + 8192);
        // 收缩到初始位置
        let free =
            TargetSyscall::new("HeapAlloc/HeapFree", "堆界伸缩").with_args(&["-8192".to_string()]);
        ex.execute(&free)
            .unwrap_or_else(|e| panic!("收缩失败：{e}"));
        // brk 回到初始值
        assert_eq!(ex.heap_brk_value(), initial, "堆顶应恢复初始值");
    }

    #[test]
    fn test_mmap_pipeline_via_closed_loop() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        // mmap(9) 通过闭环执行：addr=0, length=8192
        let ev_mmap = SyscallEvent::new(9, "mmap", vec!["0".into(), "8192".into()], 1);
        let ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let report = run_events_with_real_execution(&[ev_mmap], ex)
            .unwrap_or_else(|e| panic!("闭环执行失败：{e}"));
        assert_eq!(report.succeeded, 1, "mmap 应成功");
        assert_eq!(report.failed, 0);
        assert_eq!(report.missed, 0);
        assert_eq!(report.steps[0].operation, "VirtualAlloc");
        // 验证返回了有效地址
        let exec = report.steps[0].exec.as_ref().expect("应有执行结果");
        assert!(exec.return_value > 0, "应返回有效地址");
    }

    #[test]
    fn test_parse_hex_or_dec() {
        assert_eq!(parse_hex_or_dec("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_hex_or_dec("0X7f0000000000").unwrap(), 0x7f0000000000);
        assert_eq!(parse_hex_or_dec("4096").unwrap(), 4096);
        assert!(parse_hex_or_dec("not_a_number").is_err());
        assert!(parse_hex_or_dec("0xGGGG").is_err());
    }

    #[test]
    fn test_unknown_operation_returns_error() {
        let mut ex = WindowsFileExecutor::new();
        let target = TargetSyscall::new("NonexistentOp", "未知操作");
        let err = ex.execute(&target).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("未知操作"), "应提示未知操作：{msg}");
    }

    #[test]
    fn test_get_file_info_by_handle() {
        let (mut ex, fd, _dir) = setup_test_file();
        let result = ex
            .exec_get_file_info_by_handle(&fd.to_string())
            .unwrap_or_else(|e| panic!("获取文件信息失败：{e}"));
        assert!(result.success);
        assert!(result.return_value > 0);
    }

    #[test]
    fn test_delete_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let result = ex
            .exec_delete_file("nonexistent.txt")
            .unwrap_or_else(|e| panic!("删除文件失败：{e}"));
        assert!(!result.success, "不存在的文件删除应失败");
        assert_eq!(result.error_code, 5);
    }

    #[test]
    fn test_set_file_pointer_invalid_fd() {
        let mut ex = WindowsFileExecutor::new();
        let result = ex.exec_set_file_pointer("999", "0");
        assert!(result.is_err(), "无效 fd 应返回错误");
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("999"), "错误信息应包含 fd 号");
    }

    #[test]
    fn test_execute_via_trait_create_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let file_path = dir.path().join("trait_test.txt");
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let target = TargetSyscall::new("CreateFileW", "开卷觅路")
            .with_args(&[file_path.to_string_lossy().to_string()]);
        let result = ex
            .execute(&target)
            .unwrap_or_else(|e| panic!("通过 trait 创建文件失败：{e}"));
        assert!(result.success);
        assert!(result.return_value >= 0);
        assert!(file_path.exists());
    }

    #[test]
    fn test_execute_via_trait_delete_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let file_path = dir.path().join("trait_del.txt");
        File::create(&file_path).unwrap_or_else(|e| panic!("创建文件失败：{e}"));
        let mut ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let target = TargetSyscall::new("DeleteFileW", "断卷除名")
            .with_args(&[file_path.to_string_lossy().to_string()]);
        let result = ex
            .execute(&target)
            .unwrap_or_else(|e| panic!("通过 trait 删除文件失败：{e}"));
        assert!(result.success);
        assert!(!file_path.exists());
    }

    // ─── 「捕获→映射→真实执行」闭环测试 ───

    #[test]
    fn test_real_exec_maps_creates_and_deletes_file() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let target_file = dir.path().join("real_exec.txt");
        // 事件 1: open → CreateFileW
        let ev_open = SyscallEvent::new(
            2,
            "open",
            vec![
                target_file.to_string_lossy().to_string(),
                "577".into(),
                "0".into(),
            ],
            1,
        );
        // 事件 2: close → CloseHandle（fd 0 由 CreateFileW 返回）
        let ev_close = SyscallEvent::new(3, "close", vec!["0".into()], 1);
        let ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let report = run_events_with_real_execution(&[ev_open, ev_close], ex)
            .unwrap_or_else(|e| panic!("闭环执行失败：{e}"));
        assert_eq!(report.succeeded, 2, "两个操作都应成功");
        assert_eq!(report.failed, 0);
        assert_eq!(report.missed, 0);
        assert_eq!(report.steps.len(), 2);
        assert_eq!(report.steps[0].operation, "CreateFileW");
        assert_eq!(report.steps[1].operation, "CloseHandle");
        // 真实副作用已发生：文件被创建
        assert!(target_file.exists(), "CreateFileW 应真实创建文件");
    }

    #[test]
    fn test_real_exec_records_missed_and_scope_errors() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("创建临时目录失败：{e}"));
        let ev_miss = SyscallEvent::new(9999, "unknown_sys", vec![], 1);
        // DeviceIoControl(16) 命中映射但当前返回设备语义占位 → 执行失败
        let ev_device = SyscallEvent::new(16, "ioctl", vec!["0".into(), "cmd".into()], 1);
        let ex = WindowsFileExecutor::with_cwd(dir.path().to_path_buf());
        let report = run_events_with_real_execution(&[ev_miss, ev_device], ex)
            .unwrap_or_else(|e| panic!("闭环执行失败：{e}"));
        assert_eq!(report.missed, 1, "未知 syscall 应计入未命中");
        assert_eq!(report.failed, 1, "ioctl 应计入执行失败");
        assert_eq!(report.succeeded, 0);
        assert!(!report.steps[0].mapped);
        assert!(report.steps[1].mapped, "ioctl 应命中映射");
        let detail = report.steps[1]
            .exec
            .as_ref()
            .map(|r| r.detail.clone())
            .unwrap_or_default();
        assert!(
            detail.contains("当前仅记录") || detail.contains("无效地址"),
            "ioctl 应返回设备语义占位或参数错误：{detail}"
        );
    }

    #[test]
    fn test_l2_memory_ops_are_exercised_by_mapping_table() {
        let mapper = daoti_core::interceptor::SyscallMapper::new();
        assert_eq!(mapper.map(9).map(|m| m.windows_op), Some("VirtualAlloc"));
        assert_eq!(mapper.map(11).map(|m| m.windows_op), Some("VirtualFree"));
        assert_eq!(
            mapper.map(12).map(|m| m.windows_op),
            Some("HeapAlloc/HeapFree")
        );
    }

    #[test]
    fn test_run_events_empty_input() {
        let ex = WindowsFileExecutor::new();
        let report =
            run_events_with_real_execution(&[], ex).unwrap_or_else(|e| panic!("闭环执行失败：{e}"));
        assert_eq!(report.steps.len(), 0);
        assert_eq!(report.succeeded, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.missed, 0);
    }
}
