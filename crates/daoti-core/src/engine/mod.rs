//! 端到端执行引擎 (daoti-core::engine)
//!
//! 对应《本地二进制信号重映射主路线施工计划》P5 端到端编排。
//! LocalEngine 组装 Parser + Interceptor + Mapper + Injector，
//! 实现完整的"启动进程→拦截→映射→注入→回填→继续执行"闭环。

pub mod local;

use std::path::Path;
use std::sync::Arc;

use daoti_common::DaotiError;
use serde::{Deserialize, Serialize};

use crate::executor::ExecutionTarget;

use crate::injector::Injector;
use crate::injector::MockInjector;
use crate::interceptor::SyscallCaptureSource;
use crate::mapper::DeterministicMapper;
use crate::mapper::Mapper;
use crate::parser::BinaryInfo;

/// 本地执行引擎核心类型
pub type CaptureSource = Box<dyn SyscallCaptureSource>;
pub type MapperImpl = Arc<dyn Mapper>;
pub type InjectorImpl = Arc<dyn Injector>;

/// 单次执行报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    /// 统一调度目标。
    pub target: ExecutionTarget,
    /// 执行模式。
    pub mode: String,
    /// 调度原因。
    pub reason: String,
    /// 远程或模拟节点标识。
    pub node: Option<String>,
    /// 二进制信息
    pub binary_info: BinaryInfo,
    /// 被拦截的 syscall 总数
    pub total_captured: usize,
    /// 成功映射的 syscall 数
    pub total_mapped: usize,
    /// 成功注入的 syscall 数
    pub total_injected: usize,
    /// 未命中的 syscall 编号列表
    pub missed_nrs: Vec<i32>,
    /// 退出码（如果进程已退出）
    pub exit_code: Option<i32>,
    /// 执行状态
    pub status: ExecutionStatus,
}

/// 执行状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    /// 成功完成
    Success,
    /// 部分成功（部分 syscall 未命中）
    PartialSuccess,
    /// 执行失败
    Failed(String),
}

impl ExecutionReport {
    fn new(binary_info: BinaryInfo) -> Self {
        ExecutionReport {
            target: ExecutionTarget::StaticElfInterpreter,
            mode: "static_elf_interpreter".into(),
            reason: "本地执行引擎默认报告".into(),
            node: None,
            binary_info,
            total_captured: 0,
            total_mapped: 0,
            total_injected: 0,
            missed_nrs: Vec::new(),
            exit_code: None,
            status: ExecutionStatus::Success,
        }
    }
}

/// 本地执行引擎：组装 Parser + Interceptor + Mapper + Injector
///
/// 这是 P5 端到端闭环的核心，负责编排整个执行流程。
pub struct LocalEngine {
    /// 格式解析器（通过 parser::parse_binary）
    /// 映射器（Linux→Win32 映射表 + 参数转换）
    mapper: MapperImpl,
    /// 注入器（执行映射后的目标操作）
    injector: InjectorImpl,
}

impl Default for LocalEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl LocalEngine {
    /// 创建新的本地执行引擎
    pub fn new(mapper: MapperImpl, injector: InjectorImpl) -> Self {
        LocalEngine { mapper, injector }
    }

    /// 使用默认组件创建引擎
    fn with_defaults() -> Self {
        LocalEngine {
            mapper: Arc::new(DeterministicMapper::new()),
            injector: Arc::new(MockInjector::new()),
        }
    }

    /// 设置映射器
    pub fn with_mapper(mut self, mapper: MapperImpl) -> Self {
        self.mapper = mapper;
        self
    }

    /// 设置注入器
    pub fn with_injector(mut self, injector: InjectorImpl) -> Self {
        self.injector = injector;
        self
    }

    /// 获取映射器引用
    pub fn mapper(&self) -> &MapperImpl {
        &self.mapper
    }

    /// 获取注入器引用
    pub fn injector(&self) -> &InjectorImpl {
        &self.injector
    }

    /// 执行完整的"解析→拦截→映射→注入"闭环
    ///
    /// 1. 解析二进制格式（cli::parser::parse_binary）
    /// 2. 创建拦截器并附加到目标进程
    /// 3. 循环拦截 syscall → 映射 → 注入 → 回填
    /// 4. 进程退出时返回执行报告
    pub fn execute(
        &self,
        binary_path: &Path,
        mut source: CaptureSource,
    ) -> Result<ExecutionReport, DaotiError> {
        // 步骤 1：解析二进制格式
        let binary_info = crate::parser::parse_binary(binary_path)?;

        let mut report = ExecutionReport::new(binary_info);

        // 步骤 2-4：循环拦截→映射→注入
        while let Some(event) = source.next_event()? {
            report.total_captured += 1;

            // 步骤 2：映射 syscall
            match self.mapper.map(&event)? {
                Some(target) => {
                    report.total_mapped += 1;

                    // 步骤 3：注入执行
                    match self.injector.inject(&target) {
                        Ok(_result) => {
                            report.total_injected += 1;
                        }
                        Err(_) => {
                            // 注入失败，记录但不中断
                            report.status = ExecutionStatus::PartialSuccess;
                        }
                    }
                }
                None => {
                    // 未命中映射，记录
                    report.missed_nrs.push(event.nr);
                }
            }
        }

        // 更新最终状态
        if !report.missed_nrs.is_empty() {
            report.status = ExecutionStatus::PartialSuccess;
        }
        if report.total_captured == 0 {
            report.status = ExecutionStatus::Failed("未捕获到任何 syscall 事件".into());
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interceptor::MockCaptureSource;
    use crate::interceptor::SyscallEvent;
    use std::path::PathBuf;

    fn test_elf_path() -> PathBuf {
        let path = std::env::temp_dir().join(format!("daoti-engine-{}.elf", std::process::id()));
        let mut data = vec![0u8; 120];
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
    fn test_engine_default_creation() {
        let engine = LocalEngine::default();
        assert_eq!(engine.mapper.supported_count(), 50);
    }

    #[test]
    fn test_engine_execute_with_mock_source() {
        let engine = LocalEngine::default();

        // 创建模拟捕获源，预置一些 syscall 事件
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
            SyscallEvent::new(2, "open", vec!["/tmp/test.txt".into(), "0x0".into()], 1),
        ];
        let source = MockCaptureSource::new(events);

        // 需要一个可读的二进制路径
        let path = test_elf_path();
        let report = engine.execute(&path, Box::new(source)).expect("执行应成功");

        assert_eq!(report.total_captured, 3, "应捕获 3 个 syscall");
        assert_eq!(report.total_mapped, 3, "应映射 3 个 syscall");
        assert_eq!(report.total_injected, 3, "应注入 3 个 syscall");
        assert!(report.missed_nrs.is_empty(), "不应有未命中");
    }

    #[test]
    fn test_engine_execute_with_unmapped_syscalls() {
        let engine = LocalEngine::default();

        // 包含已知和未知 syscall
        let events = vec![
            SyscallEvent::new(0, "read", vec![], 1),
            SyscallEvent::new(9999, "unknown", vec![], 1),
            SyscallEvent::new(1, "write", vec![], 1),
        ];
        let source = MockCaptureSource::new(events);

        let path = test_elf_path();
        let report = engine.execute(&path, Box::new(source)).expect("执行应成功");

        assert_eq!(report.total_captured, 3);
        assert_eq!(report.total_mapped, 2, "应映射 2 个（unknown 未命中）");
        assert_eq!(report.total_injected, 2);
        assert_eq!(report.missed_nrs, vec![9999], "应记录未命中");
        assert_eq!(report.status, ExecutionStatus::PartialSuccess);
    }

    #[test]
    fn test_engine_execute_empty_source() {
        let engine = LocalEngine::default();
        let source = MockCaptureSource::new(vec![]);

        let path = test_elf_path();
        let report = engine.execute(&path, Box::new(source)).expect("执行应成功");

        assert_eq!(report.total_captured, 0);
        assert_eq!(
            report.status,
            ExecutionStatus::Failed("未捕获到任何 syscall 事件".into())
        );
    }

    #[test]
    fn test_engine_execute_nonexistent_path() {
        let engine = LocalEngine::default();
        let source = MockCaptureSource::new(vec![]);

        let path = PathBuf::from("/nonexistent/binary.elf");
        let result = engine.execute(&path, Box::new(source));
        assert!(result.is_err(), "不存在的路径应返回错误");
    }

    #[test]
    fn test_execution_report_defaults() {
        let binary_info = crate::parser::BinaryInfo::new(
            crate::parser::BinaryType::Elf,
            crate::parser::CpuArch::X86_64,
            0x400000,
        );
        let report = ExecutionReport::new(binary_info);
        assert_eq!(report.total_captured, 0);
        assert_eq!(report.status, ExecutionStatus::Success);
        assert!(report.missed_nrs.is_empty());
        assert_eq!(report.target, ExecutionTarget::StaticElfInterpreter);
        assert_eq!(report.mode, "static_elf_interpreter");
        assert!(report.reason.contains("本地执行引擎"));
        assert!(report.node.is_none());
    }

    #[test]
    fn test_execution_report_with_target_fields() {
        let binary_info = crate::parser::BinaryInfo::new(
            crate::parser::BinaryType::Pe,
            crate::parser::CpuArch::X86_64,
            0x400000,
        );
        let mut report = ExecutionReport::new(binary_info);
        report.target = ExecutionTarget::PeInterpreter;
        report.mode = "pe_interpreter".into();
        report.reason = "PE 远程 mock 测试".into();
        report.node = Some("mock-pe-node".into());
        assert_eq!(report.target, ExecutionTarget::PeInterpreter);
        assert_eq!(report.mode, "pe_interpreter");
        assert_eq!(report.reason, "PE 远程 mock 测试");
        assert_eq!(report.node.as_deref(), Some("mock-pe-node"));
    }
}
