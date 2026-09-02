//! 受控 ET_DYN 装载骨架：只在沙箱内映射、重定位并构造入口上下文。

use daoti_common::DaotiError;
use ndarray::{Array1, Array2};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn load_glibc_daoti_network(
) -> Result<crate::bilateral::network::BilateralLadderNetwork, DaotiError> {
    let path = std::env::var_os("DAOTI_B2_WEIGHTS_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            [
                PathBuf::from("knowledge/glibc_network.daotiblt"),
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../knowledge/glibc_network.daotiblt"),
            ]
            .into_iter()
            .find(|candidate| candidate.is_file())
        })
        .ok_or_else(|| {
            DaotiError::InferenceFailed("未加载道体权重，动态 ELF 阶段决策无法继续".into())
        })?;
    let weights = crate::bilateral::weights::WeightsLoader::load(&path)?;
    let ascent = Array2::from_shape_vec((weights.dim, weights.dim), weights.ascent)
        .map_err(|error| DaotiError::ModelCorrupt(format!("上梯形权重维度错误：{error}")))?;
    let descent = Array2::from_shape_vec((weights.dim, weights.dim), weights.descent)
        .map_err(|error| DaotiError::ModelCorrupt(format!("下梯形权重维度错误：{error}")))?;
    crate::bilateral::network::BilateralLadderNetwork::new(
        ascent,
        descent,
        Array1::from_vec(weights.bias),
        weights.t_iter,
    )
}

fn apply_daoti_phase(
    memory: &mut MemoryModel,
    phase: super::runtime::PhaseId,
    network: &crate::bilateral::network::BilateralLadderNetwork,
    load_bias: u64,
    main_map: u64,
    rip: u64,
) -> Result<(), DaotiError> {
    // loader 自有状态必须由 ld.so 真实代码维护，道体阶段只做观测，不预写链表。
    let _ = (memory, phase, network, load_bias, main_map, rip);
    return Ok(());
    #[allow(unreachable_code)]
    let rtld_global = load_bias
        .checked_add(0x33020)
        .ok_or_else(|| DaotiError::Other("阶段决策的 _rtld_global 地址溢出".into()))?;
    let ns_loaded = rtld_global
        .checked_add(0xa30)
        .ok_or_else(|| DaotiError::Other("阶段决策的 _ns_loaded 地址溢出".into()))?;
    let fields = ["_dl_rtld_map.l_next", "_ns_loaded"];
    let mut sample = super::super::glibc_knowledge::official_knowledge_samples()
        .into_iter()
        .next()
        .ok_or_else(|| DaotiError::ModelCorrupt("道体知识样本为空".into()))?;
    sample.context = phase.label().into();
    sample.target_fields = fields.iter().map(|field| (*field).into()).collect();
    sample.input_vector.fill(0.0);
    sample.output_vector.fill(0.0);
    for field in &sample.target_fields {
        let index = super::super::glibc_knowledge::field_label_index(field);
        sample.input_vector[index] = 1.0;
        sample.output_vector[index] = 1.0;
    }
    let candidate = super::super::glibc_knowledge::infer_candidate_state(network, &sample)?;
    let decision =
        super::super::glibc_knowledge::decode_state_decision(&sample, &candidate, phase.label())?;
    let state_fields = [
        super::super::glibc_knowledge::StateField {
            name: "_dl_rtld_map.l_next".into(),
            address: rtld_global + 0x18,
            value: main_map.to_le_bytes().to_vec(),
        },
        super::super::glibc_knowledge::StateField {
            name: "_ns_loaded".into(),
            address: ns_loaded,
            value: main_map.to_le_bytes().to_vec(),
        },
    ];
    super::super::glibc_knowledge::StateApplier::apply_decision(memory, &state_fields, &decision)?;
    if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
        let current_next = memory.read(rtld_global + 0x18, 8)?;
        let current_loaded = memory.read(ns_loaded, 8)?;
        eprintln!(
            "TRACE daoti-phase={} rip=0x{:x} approved={:?} l_next=0x{:x} ns_loaded=0x{:x} main_map=0x{:x}",
            phase.label(),
            rip,
            decision.fields.iter().filter(|field| field.approved).map(|field| field.field.as_str()).collect::<Vec<_>>(),
            u64::from_le_bytes(current_next.try_into().unwrap()),
            u64::from_le_bytes(current_loaded.try_into().unwrap()),
            main_map,
        );
    }
    Ok(())
}

use super::linux_emulation_handler::LinuxEmulationHandler;
use super::{
    parse_elf_from_bytes, plan_dynamic_load, read_dynamic_relocations,
    read_dynamic_relocations_with_plt, read_full_symtab_symbols, read_loaded_dynamic_symbols,
    relocation::{
        apply_x86_64_relocations, apply_x86_64_relocations_with_tls, AppliedRelocation,
        CrossObjectSymbolResolver, SymbolResolver, TlsContext, TlsSymbolLocation,
    },
    runtime::{MemPerm, MemoryModel, MemoryRegion, RuntimeContext},
    DynamicLoadPlan, ElfInfo, TlsMetadata, PAGE_SIZE,
};

const TLS_TCB_RESERVED: u64 = 0x800;

/// 已安装 TLS 镜像的模块记录。
///
/// `module_id` 按对象装载顺序从 1 开始分配（0 保留给 glibc DTV 的生成计数器槽），
/// 与镜像在 TLS 区内的物理布局顺序无关；`start` 是该模块 TLS 块的运行时地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsModule {
    pub module_id: u64,
    pub start: u64,
    pub memory_size: u64,
    pub align: u64,
}

fn install_tls_images(
    memory: &mut MemoryModel,
    tls_base_addr: u64,
    tls_region_base: u64,
    tls_region_size: u64,
    objects: &[(&[u8], &TlsMetadata)],
) -> Result<Vec<TlsModule>, DaotiError> {
    let region_end = tls_region_base
        .checked_add(tls_region_size)
        .ok_or_else(|| DaotiError::Other("TLS 区域终点溢出".into()))?;
    let first = tls_base_addr
        .checked_add(TLS_TCB_RESERVED)
        .ok_or_else(|| DaotiError::Other("TLS 镜像起始地址溢出".into()))?;
    if first < tls_region_base || first > region_end {
        return Err(DaotiError::Other("TLS 镜像起始地址超出 TLS 区域".into()));
    }

    let mut ordered: Vec<(usize, &[u8], &TlsMetadata)> = objects
        .iter()
        .enumerate()
        .map(|(index, (bytes, metadata))| (index, *bytes, *metadata))
        .collect();
    ordered.sort_by_key(|(_, _, metadata)| metadata.align);
    let mut starts = vec![0; objects.len()];
    let mut cursor = first;

    for (index, bytes, metadata) in ordered {
        if metadata.memory_size < metadata.file_size {
            return Err(DaotiError::Other("PT_TLS 内存大小小于文件大小".into()));
        }
        let file_end = metadata
            .file_offset
            .checked_add(metadata.file_size)
            .ok_or_else(|| DaotiError::Other("PT_TLS 文件范围溢出".into()))?;
        let file_offset = usize::try_from(metadata.file_offset)
            .map_err(|_| DaotiError::Other("PT_TLS 文件偏移无法转换为 usize".into()))?;
        let file_size = usize::try_from(metadata.file_size)
            .map_err(|_| DaotiError::Other("PT_TLS 文件大小无法转换为 usize".into()))?;
        let file_end_usize = usize::try_from(file_end)
            .map_err(|_| DaotiError::Other("PT_TLS 文件终点无法转换为 usize".into()))?;
        if file_end_usize > bytes.len() || file_offset > bytes.len() {
            return Err(DaotiError::Other("PT_TLS 文件范围超出对象字节".into()));
        }
        let image = bytes
            .get(file_offset..file_end_usize)
            .ok_or_else(|| DaotiError::Other("PT_TLS 文件范围无效".into()))?;
        debug_assert_eq!(image.len(), file_size);

        let align = metadata.align.max(1);
        let remainder = cursor % align;
        let start = if remainder == 0 {
            cursor
        } else {
            cursor
                .checked_add(align - remainder)
                .ok_or_else(|| DaotiError::Other("TLS 镜像对齐地址溢出".into()))?
        };
        let end = start
            .checked_add(metadata.memory_size)
            .ok_or_else(|| DaotiError::Other("TLS 镜像终点溢出".into()))?;
        if start < tls_region_base || end > region_end {
            return Err(DaotiError::Other("TLS 镜像超出 TLS 区域".into()));
        }
        if !image.is_empty() {
            memory.write(start, image)?;
        }
        let bss_size = metadata.memory_size - metadata.file_size;
        if bss_size != 0 {
            let bss_len = usize::try_from(bss_size)
                .map_err(|_| DaotiError::Other("PT_TLS BSS 大小无法转换为 usize".into()))?;
            memory.write(
                start
                    .checked_add(metadata.file_size)
                    .ok_or_else(|| DaotiError::Other("TLS BSS 起始地址溢出".into()))?,
                &vec![0; bss_len],
            )?;
        }
        starts[index] = start;
        cursor = end;
    }
    // module_id 按装载顺序（objects 下标）从 1 开始分配，与物理布局顺序无关。
    let modules = starts
        .iter()
        .enumerate()
        .zip(objects.iter())
        .map(|((index, start), (_, metadata))| TlsModule {
            module_id: (index + 1) as u64,
            start: *start,
            memory_size: metadata.memory_size,
            align: metadata.align,
        })
        .collect();
    Ok(modules)
}

/// 构造 glibc 风格的 DTV（Dynamic Thread Vector）并写入内存。
///
/// DTV 布局：槽 0 存放生成计数器（generation），槽 `module_id` 存放对应模块 TLS 块
/// 地址。返回 DTV 起始地址。模块 ID 必须落在 `1..=max`，越界视为装载错误。
fn build_dtv(
    memory: &mut MemoryModel,
    dtv_addr: u64,
    modules: &[TlsModule],
) -> Result<(), DaotiError> {
    // 校验 module_id 连续且从 1 开始，避免 DTV 出现空洞槽位。
    let mut ids: Vec<u64> = modules.iter().map(|module| module.module_id).collect();
    ids.sort_unstable();
    if ids.iter().enumerate().any(|(i, id)| *id != (i as u64) + 1) {
        return Err(DaotiError::Other("TLS module ID 不连续".into()));
    }
    // 槽 0：generation 计数器，初始化线程为 1。
    memory.write(dtv_addr, &1u64.to_le_bytes())?;
    for module in modules {
        let slot = dtv_addr
            .checked_add(
                module
                    .module_id
                    .checked_mul(8)
                    .ok_or_else(|| DaotiError::Other("DTV 槽位偏移溢出".into()))?,
            )
            .ok_or_else(|| DaotiError::Other("DTV 槽位地址溢出".into()))?;
        memory.write(slot, &module.start.to_le_bytes())?;
    }
    Ok(())
}
use crate::injector::AuditBuffer;

fn build_shadow_observer() -> Option<(
    super::syscall_bridge::RuntimeSyscallObserver,
    Arc<Mutex<Vec<super::syscall_bridge::ShadowInferenceRecord>>>,
)> {
    std::env::var_os("DAOTI_SHADOW_INFERENCE")?;
    let path = std::env::var("DAOTI_B2_WEIGHTS_PATH").ok()?;
    let weights = crate::bilateral::weights::WeightsLoader::load(Path::new(&path)).ok()?;
    let ascent = Array2::from_shape_vec((weights.dim, weights.dim), weights.ascent).ok()?;
    let descent = Array2::from_shape_vec((weights.dim, weights.dim), weights.descent).ok()?;
    let bias = Array1::from_vec(weights.bias);
    let network = crate::bilateral::network::BilateralLadderNetwork::new(
        ascent,
        descent,
        bias,
        weights.t_iter,
    )
    .ok()?;
    let codec = crate::codec::SyscallCodec::new(weights.dim, weights.op_dict).ok()?;
    let records = Arc::new(Mutex::new(Vec::new()));
    let observer =
        super::syscall_bridge::shadow_inference_observer(network, codec, records.clone());
    Some((observer, records))
}

fn flush_shadow_records(records: &Arc<Mutex<Vec<super::syscall_bridge::ShadowInferenceRecord>>>) {
    let Ok(records) = records.lock() else {
        return;
    };
    if records.is_empty() {
        return;
    }
    let Some(path) = std::env::var_os("DAOTI_SHADOW_OUTPUT")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .map(|home| PathBuf::from(home).join(".daoti/shadow/shadow.jsonl"))
        })
    else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    for record in records.iter() {
        if let Ok(line) = serde_json::to_string(record) {
            use std::io::Write;
            let _ = writeln!(file, "{line}");
        }
    }
}

/// 动态 ELF 已装载但尚未执行的结果。
#[derive(Debug)]
pub struct DynamicLoadResult {
    pub plan: DynamicLoadPlan,
    pub context: RuntimeContext,
    pub relocations: Vec<AppliedRelocation>,
    pub dependencies: Vec<DynamicMappedObject>,
    pub interpreter: Option<DynamicMappedObject>,
    pub breakpoints: Vec<super::runtime::RuntimeBreakpoint>,
    /// 跨对象 TLS 上下文（装载期构建）；执行期 `__tls_get_addr` 功能断点据此解析 TLS 变量地址。
    pub tls_context: TlsContext,
    /// 按装载顺序分配的 TLS 模块及其运行时块地址。
    pub tls_modules: Vec<TlsModule>,
    /// 当前线程 DTV 数组地址；槽 0 为 generation，槽 N 对应 module_id=N。
    pub dtv_addr: Option<u64>,
}

#[derive(Debug)]
pub struct DynamicExecutionResult {
    pub state: super::runtime::ExecutionState,
    pub mode: &'static str,
    pub stdout: Vec<u8>,
    pub audit: AuditBuffer,
}

/// 受控根目录内已经解析并映射的依赖对象。
#[derive(Debug)]
pub struct DynamicMappedObject {
    pub path: PathBuf,
    pub plan: DynamicLoadPlan,
    pub bytes: Vec<u8>,
}

/// 受控动态 ELF 装载器。
///
/// 该类型不会调用宿主动态链接器，也不会宣称入口已经运行成功；调用方必须显式决定
/// 是否以及如何把 `context` 交给解释器。
fn resolve_controlled_path(
    interpreter: &str,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, DaotiError> {
    let raw = Path::new(interpreter);
    let file_name = raw
        .file_name()
        .ok_or_else(|| DaotiError::Unavailable(format!("PT_INTERP 路径无文件名：{interpreter}")))?;
    let candidates = allowed_roots
        .iter()
        .map(|root| root.join(file_name))
        .collect::<Vec<_>>();
    candidates
        .into_iter()
        .map(|candidate| super::normalize_path(&candidate))
        .find(|candidate| {
            allowed_roots
                .iter()
                .map(|root| super::normalize_path(root))
                .any(|root| candidate.starts_with(root))
                && candidate.is_file()
        })
        .ok_or_else(|| {
            DaotiError::Unavailable(format!("PT_INTERP 不在受控根目录内或不存在：{interpreter}"))
        })
}

fn validate_runtime_asset(
    path: &Path,
    bytes: &[u8],
    expected_arch: &str,
    role: &str,
) -> Result<DynamicLoadPlan, DaotiError> {
    let info = parse_elf_from_bytes(bytes).map_err(|e| {
        DaotiError::Unavailable(format!("受控 {role} {} 不是有效 ELF：{e}", path.display()))
    })?;
    if info.arch != expected_arch || !info.is_64 {
        return Err(DaotiError::Unavailable(format!(
            "受控 {role} {} 架构不一致：需要 64 位 {expected_arch}，实际 {}",
            path.display(),
            info.arch
        )));
    }
    let plan = plan_dynamic_load(bytes, 0x700000).map_err(|e| {
        DaotiError::Unavailable(format!(
            "受控 {role} {} 版本/装载格式不兼容：{e}",
            path.display()
        ))
    })?;
    if role == "动态链接器" && plan.interpreter.is_some() {
        return Err(DaotiError::Unavailable(format!(
            "受控动态链接器 {} 不应再声明 PT_INTERP",
            path.display()
        )));
    }
    Ok(plan)
}

pub struct DynamicElfLoader<R> {
    resolver: R,
    preferred_base: u64,
    stack_size: u64,
}

/// 把单个 ET_DYN 的 PT_LOAD 合并镜像映射进内存模型。
///
/// 将全部 PT_LOAD 段按其内存范围铺进一个页对齐的连续缓冲区，并按段最高权限合并
/// 为一个内存区域，从而支持真实的依赖对象在共享地址空间内装载。
fn map_dynamic_object(
    memory: &mut MemoryModel,
    data: &[u8],
    plan: &DynamicLoadPlan,
    info: &ElfInfo,
) -> Result<(), DaotiError> {
    let map_start = plan
        .load_segments
        .iter()
        .map(|s| s.mapped_start)
        .min()
        .ok_or_else(|| DaotiError::Other("动态 ELF 缺少映射段".into()))?;
    let map_end = plan
        .load_segments
        .iter()
        .map(|s| s.mapped_end)
        .max()
        .ok_or_else(|| DaotiError::Other("动态 ELF 缺少映射段".into()))?;
    let mut merged = vec![
        0;
        usize::try_from(map_end - map_start)
            .map_err(|_| DaotiError::Other("PT_LOAD 合并范围过大".into()))?
    ];
    let mut merged_perm = MemPerm {
        read: false,
        write: false,
        execute: false,
    };
    for segment in &plan.load_segments {
        let source = info
            .segments
            .iter()
            .find(|item| item.vaddr == segment.vaddr)
            .ok_or_else(|| DaotiError::Other("动态 ELF 映射段缺失".into()))?;
        let start = usize::try_from(source.offset)
            .map_err(|_| DaotiError::Other("段文件偏移过大".into()))?;
        let file_size = usize::try_from(source.filesz)
            .map_err(|_| DaotiError::Other("段文件大小过大".into()))?;
        let end = start
            .checked_add(file_size)
            .ok_or_else(|| DaotiError::Other("段文件范围溢出".into()))?;
        if end > data.len() {
            return Err(DaotiError::Other("动态 ELF 段超出文件边界".into()));
        }
        let mut bytes = data[start..end].to_vec();
        bytes.resize(
            usize::try_from(source.memsz)
                .map_err(|_| DaotiError::Other("段内存大小过大".into()))?,
            0,
        );
        let raw_start = source
            .vaddr
            .checked_add(plan.load_bias)
            .ok_or_else(|| DaotiError::Other("PT_LOAD 装载地址溢出".into()))?;
        let offset = usize::try_from(raw_start - map_start)
            .map_err(|_| DaotiError::Other("PT_LOAD 合并偏移过大".into()))?;
        let end_offset = offset
            .checked_add(bytes.len())
            .ok_or_else(|| DaotiError::Other("PT_LOAD 合并范围溢出".into()))?;
        if end_offset > merged.len() {
            return Err(DaotiError::Other("PT_LOAD 合并范围超出映射区域".into()));
        }
        merged[offset..end_offset].copy_from_slice(&bytes);
        if std::env::var_os("DAOTI_TRACE_OBJECT_MAP").is_some()
            && source.offset <= 0x169a60
            && 0x169a60 < source.offset.saturating_add(source.filesz)
        {
            let target_offset = usize::try_from(0x169a60 - source.offset).unwrap();
            eprintln!(
                "TRACE object-map target=0x169a60 map_start=0x{map_start:x} map_end=0x{map_end:x} source_offset=0x{:x} source_vaddr=0x{:x} source_filesz=0x{:x} copied_offset=0x{offset:x} target_bytes={:02x?}",
                source.offset,
                source.vaddr,
                source.filesz,
                &bytes[target_offset..bytes.len().min(target_offset + 8)]
            );
        }
        merged_perm.read |= source.flags & 4 != 0;
        merged_perm.write |= source.flags & 2 != 0;
        merged_perm.execute |= source.flags & 1 != 0;
    }
    if std::env::var_os("DAOTI_TRACE_PTLOAD_MAPPING").is_some() {
        if let Some(dynamic) = info.segments.iter().find(|segment| segment.type_ == 2) {
            let dynamic_addr = plan.load_bias + dynamic.vaddr;
            let dynamic_file = usize::try_from(dynamic.offset).unwrap_or(usize::MAX);
            let expected = data.get(dynamic_file..dynamic_file.saturating_add(16));
            let actual = if dynamic_addr >= map_start && dynamic_addr.saturating_add(16) <= map_end
            {
                let start = usize::try_from(dynamic_addr - map_start).unwrap_or(usize::MAX);
                merged.get(start..start.saturating_add(16))
            } else {
                None
            };
            eprintln!(
                "TRACE ptload-mapping path-object load_bias=0x{:x} dynamic_vaddr=0x{:x} runtime=0x{:x} file_offset=0x{:x} expected={expected:02x?} actual={actual:02x?}",
                plan.load_bias, dynamic.vaddr, dynamic_addr, dynamic.offset
            );
        }
    }
    memory.add_region(MemoryRegion::with_data(map_start, merged_perm, merged))?;
    Ok(())
}

/// 在栈顶区域布置初始进程栈：argc/argv/envp/auxv。
///
/// 返回栈指针（rsp），指向 argc 所在位置。auxv 包含 AT_PHDR/AT_PHENT/AT_PHNUM/
/// AT_PAGESZ/AT_ENTRY/AT_RANDOM，并写入随机种子数据。
const STACK_DATA_CAPACITY: u64 = 0x2000; // 8 KiB 栈数据区

fn initialize_link_map_fields(memory: &mut MemoryModel, map_addr: u64) -> Result<(), DaotiError> {
    memory.write(map_addr + 0x28, &map_addr.to_le_bytes())
}

#[allow(clippy::too_many_arguments)]
fn initialize_main_link_map(
    memory: &mut MemoryModel,
    main_map_addr: u64,
    main_load_bias: u64,
    phdr_addr: u64,
    phnum: u64,
    main_dynamic_addr: Option<u64>,
    _rtld_map_addr: Option<u64>,
    _ns_loaded_addr: Option<u64>,
) -> Result<(), DaotiError> {
    // 真实 ld.so 会在 dl_main 中填写这些 link_map 基础字段；这里只写入
    // 装载器已经确定的主对象事实，不通过 MemoryModel::write 做隐式修正。
    memory.write(main_map_addr, &main_load_bias.to_le_bytes())?;
    if let Some(dynamic_addr) = main_dynamic_addr {
        memory.write(main_map_addr + 0x10, &dynamic_addr.to_le_bytes())?;
    }
    initialize_link_map_fields(memory, main_map_addr)?;
    memory.write(main_map_addr + 0x30, &phdr_addr.to_le_bytes())?;
    memory.write(main_map_addr + 0x38, &phnum.to_le_bytes())?;
    Ok(())
}

/// 在 ld.so 创建新 link_map 后补齐符号查找依赖字段。
///
/// glibc 2.35 的 link_map 中 l_ld 位于 +0x10，l_real 位于 +0x28；
/// l_info 是 map+0x40 起的内联数组（66 槽），map+0x68 恰为
/// l_info[DT_STRTAB]（index 5）槽位，由 glibc 自身在 _dl_map_object
/// 阶段填充。loader 只补齐 _dl_lookup_direct 依赖的 hash/版本字段
/// （l_nbuckets/l_gnu_*/l_versions/l_versyms），绝不覆写内联 l_info，否则
/// 会破坏符号名解析（曾导致 dl-mutex.c:44 `sym != NULL` 断言失败）。
/// 动态段中的 d_ptr 对 ET_DYN 通常是对象内虚拟地址，需要加 l_addr
/// 才能得到运行时地址。
/// 读取动态段内的 u32 值。
fn read_u32_at(memory: &MemoryModel, address: u64) -> Result<u32, DaotiError> {
    let bytes = memory.read(address, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// 动态段 d_ptr 的运行时地址规范化：ET_DYN 优先使用 value + load_bias，
/// 只有加偏置地址不可读时，才接受已绝对化的 value。
///
/// 动态段内地址形态是混合的：glibc 已填充的 l_info 相关 d_ptr（如
/// DT_GNU_HASH/DT_STRTAB/DT_VERSYM）已是运行时绝对地址；而 DT_VERDEF/
/// DT_VERNEED 等仍为未加偏置的 raw vaddr。本函数对两种形态都做静默
/// 可读性探测（probe_read 不触发诊断打印），返回正确的运行时地址。
fn absolutize(memory: &MemoryModel, load_bias: u64, value: u64) -> Option<u64> {
    let biased = load_bias.checked_add(value)?;
    if memory.probe_read(biased, 4) {
        return Some(biased);
    }
    memory.probe_read(value, 4).then_some(value)
}

pub(crate) fn initialize_link_map_info(
    memory: &mut MemoryModel,
    map_addr: u64,
) -> Result<(), DaotiError> {
    initialize_link_map_fields(memory, map_addr)?;
    let read_u64 = |address: u64| -> Result<u64, DaotiError> {
        let bytes = memory.read(address, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    };
    let load_bias = read_u64(map_addr)?;
    let raw_dynamic = read_u64(map_addr + 0x10)?;
    if raw_dynamic == 0 {
        return Ok(());
    }
    let dynamic_addr = if memory.read(raw_dynamic, 16).is_ok() {
        raw_dynamic
    } else {
        load_bias
            .checked_add(raw_dynamic)
            .ok_or_else(|| DaotiError::Other("link_map l_ld 地址溢出".into()))?
    };
    if memory.read(dynamic_addr, 16).is_err() {
        return Err(DaotiError::Other(format!(
            "link_map l_ld 不可访问：0x{dynamic_addr:x}"
        )));
    }
    let trace_info_scan = std::env::var_os("DAOTI_TRACE_LINK_MAP_INFO_SCAN").is_some();
    let mut version_hits = Vec::new();
    // 收集 _dl_lookup_direct 快路径依赖的动态段条目（value 可能是已绝对化的
    // 运行时地址，也可能是未加 load_bias 的原始 vaddr，统一做可读性探测）。
    // 对 ET_DYN 优先验证 load_bias + vaddr，避免把 raw vaddr 的失败探测误报为
    // 运行时访问错误；仅当加偏置地址不可读时，才回退到已绝对化地址。
    // 注意：l_info 是 map+0x40 起的内联数组，由 glibc 自身填充，这里只收集
    // hash/版本字段，不再分配独立 l_info 表（历史版本曾把 map+0x68 覆写为
    // 独立表地址，破坏了内联 l_info[DT_STRTAB]，导致 _dl_lookup_direct
    // 符号名解析损坏）。
    let mut gnu_hash_raw: Option<u64> = None;
    let mut sysv_hash_raw: Option<u64> = None;
    let mut versym_raw: Option<u64> = None;
    let mut verdef_raw: Option<u64> = None;
    let mut strtab_raw: Option<u64> = None;
    let mut cursor = dynamic_addr;
    for index in 0..256 {
        let entry = memory.read(cursor, 16)?.to_vec();
        let tag = i64::from_le_bytes(entry[..8].try_into().unwrap());
        let value = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        if trace_info_scan {
            eprintln!(
                "TRACE link-map-info-scan map=0x{map_addr:x} dynamic=0x{dynamic_addr:x} index={index} entry=0x{cursor:x} tag=0x{tag:x} value=0x{value:x}"
            );
        }
        if tag == 0 {
            break;
        }
        let info_index = match tag {
            0..=63 => Some(tag as u64),
            0x6ffffff0 => Some(50),
            0x6ffffffc => Some(38),
            0x6ffffffd => Some(37),
            0x6ffffffe => Some(36),
            0x6fffffff => Some(35),
            _ => None,
        };
        if let Some(index) = info_index {
            if (0x6ffffff0..=0x6fffffff).contains(&(tag as u64)) {
                version_hits.push((tag, index, cursor, value));
            }
            // 内联 l_info 槽由 glibc 自身填充（实测布局：DT_VERDEF→38、
            // DT_VERDEFNUM→37、DT_VERNEED→36、DT_VERNEEDNUM→35、DT_VERSYM→50），此处只做只读校验，绝不写入,
            // 避免污染 glibc 已填好的槽位。
            if trace_info_scan {
                let existing = memory
                    .read(map_addr + 0x40 + index * 8, 8)
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .unwrap_or(0);
                eprintln!(
                    "TRACE link-map-info-slot map=0x{map_addr:x} tag=0x{tag:x} index={index} slot=0x{:x} existing=0x{existing:x} scan_value=0x{cursor:x}",
                    map_addr + 0x40 + index * 8
                );
            }
        }
        match tag {
            0x6ffffef5 => gnu_hash_raw = Some(value), // DT_GNU_HASH
            4 => sysv_hash_raw = Some(value),         // DT_HASH
            0x6ffffff0 => versym_raw = Some(value),   // DT_VERSYM
            0x6ffffffc => verdef_raw = Some(value),   // DT_VERDEF
            // DT_VERDEFNUM（0x6fffffff）不可信：实测 fixture libc 链 37 条
            // 而该字段为 1，故不在此收集，版本表遍历见下方注释。
            5 => strtab_raw = Some(value), // DT_STRTAB
            _ => {}
        }
        cursor = cursor
            .checked_add(16)
            .ok_or_else(|| DaotiError::Other("link_map 动态段遍历溢出".into()))?;
    }
    // 注意：绝不写 map+0x68（内联 l_info[DT_STRTAB] 槽），该槽由 glibc 在
    // _dl_map_object 阶段填充；历史版本曾在此覆写为独立表地址，直接破坏了
    // D_PTR(map, l_info[DT_STRTAB]) 的符号名解析。
    memory.write(map_addr + 0x10, &dynamic_addr.to_le_bytes())?;
    let trace_hash = std::env::var_os("DAOTI_TRACE_LINK_MAP_HASH").is_some();
    // 1. GNU hash 表：填充 l_nbuckets(+0x2f4)/l_gnu_shift(+0x2f8)/
    //    l_gnu_bitmask(+0x300)/l_gnu_buckets(+0x308)/l_gnu_chain_zero(+0x310)。
    //    表头布局：nbuckets@0、symoffset@4、bitmask_nwords@8、bloom_shift@12，
    //    bloom 数组紧随表头，bucket 数组在 bloom 之后，chain 数组在 bucket 之后。
    if let Some(raw) = gnu_hash_raw {
        if let Some(hash_addr) = absolutize(memory, load_bias, raw) {
            let nbuckets = read_u32_at(memory, hash_addr);
            let symoffset = read_u32_at(memory, hash_addr + 4);
            let nwords = read_u32_at(memory, hash_addr + 8);
            let shift = read_u32_at(memory, hash_addr + 12);
            if let (Ok(nbuckets), Ok(symoffset), Ok(nwords), Ok(shift)) =
                (nbuckets, symoffset, nwords, shift)
            {
                let bitmask = hash_addr
                    .checked_add(16)
                    .ok_or_else(|| DaotiError::Other("l_gnu_bitmask 地址溢出".into()))?;
                let buckets = bitmask
                    .checked_add(u64::from(nwords) * 8)
                    .ok_or_else(|| DaotiError::Other("l_gnu_buckets 地址溢出".into()))?;
                // l_gnu_chain_zero 必须是 chain[0] 的地址，即 buckets 末尾减去
                // symoffset 个链头：chain[0] = buckets + nbuckets*4 − symoffset*4。
                // _dl_lookup_direct 在 0xd10f 用 `lea r15,[rsi+rax*4]`（rsi=chain_zero、
                // rax=符号索引）定位 chain 项；若漏减 symoffset，查找永远错位
                // symoffset 个表项 → 名称/hash 不匹配 → 返回 NULL → 断言失败。
                let bucketed = buckets
                    .checked_add(u64::from(nbuckets) * 4)
                    .ok_or_else(|| DaotiError::Other("l_gnu_chain_zero 地址溢出".into()))?;
                let chain_zero = bucketed
                    .checked_sub(u64::from(symoffset) * 4)
                    .ok_or_else(|| DaotiError::Other("l_gnu_chain_zero 下溢".into()))?;
                memory.write(map_addr + 0x2f4, &nbuckets.to_le_bytes())?;
                memory.write(map_addr + 0x2f8, &shift.to_le_bytes())?;
                memory.write(map_addr + 0x300, &bitmask.to_le_bytes())?;
                memory.write(map_addr + 0x308, &buckets.to_le_bytes())?;
                memory.write(map_addr + 0x310, &chain_zero.to_le_bytes())?;
                if trace_hash {
                    // 写后立即回读验证持久性（临时诊断，定位 div ecx 除数为 0）。
                    let verify = memory
                        .read(map_addr + 0x2f4, 4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                        .unwrap_or(0xffff_ffff);
                    eprintln!(
                        "TRACE link-map-hash map=0x{map_addr:x} kind=gnu hash=0x{hash_addr:x} nbuckets={nbuckets} nwords={nwords} shift={shift} bitmask=0x{bitmask:x} buckets=0x{buckets:x} chain_zero=0x{chain_zero:x} readback=0x{verify:x}"
                    );
                }
            }
        }
    }
    // 2. SysV hash 回退：l_gnu_bitmask 保持 0 时 _dl_lookup_direct 走
    //    [rdi+0x310]（l_buckets，与 l_gnu_chain_zero 是 union）与 +0x2f4。
    if sysv_hash_raw.is_some()
        && memory
            .read(map_addr + 0x300, 8)
            .is_ok_and(|b| u64::from_le_bytes(b.try_into().unwrap()) == 0)
    {
        if let Some(hash_addr) = sysv_hash_raw.and_then(|raw| absolutize(memory, load_bias, raw)) {
            if let Ok(nbuckets) = read_u32_at(memory, hash_addr) {
                let buckets = hash_addr
                    .checked_add(8)
                    .ok_or_else(|| DaotiError::Other("l_buckets 地址溢出".into()))?;
                memory.write(map_addr + 0x2f4, &nbuckets.to_le_bytes())?;
                memory.write(map_addr + 0x310, &buckets.to_le_bytes())?;
                if trace_hash {
                    eprintln!(
                        "TRACE link-map-hash map=0x{map_addr:x} kind=sysv hash=0x{hash_addr:x} nbuckets={nbuckets} buckets=0x{buckets:x}"
                    );
                }
            }
        }
    }
    // 3. 版本表：l_versyms(+0x348) 指向 DT_VERSYM 的 u16 数组；
    //    l_versions(+0x2e8)/l_nversions(+0x2f0) 由 DT_VERDEF 链构建
    //    （r_found_version { name@+0, hash@+8, hidden@+16 }，元素 24 字节，
    //    数组下标 = vd_ndx，与 l_versyms[symidx] & 0x7fff 的索引一致）。
    if let Some(raw) = versym_raw {
        if let Some(addr) = absolutize(memory, load_bias, raw) {
            memory.write(map_addr + 0x348, &addr.to_le_bytes())?;
        }
    }
    if let (Some(raw), Some(strtab_raw)) = (verdef_raw, strtab_raw) {
        if let (Some(def_addr), Some(strtab_addr)) = (
            absolutize(memory, load_bias, raw),
            absolutize(memory, load_bias, strtab_raw),
        ) {
            let mut entries: Vec<(u32, u32, u32)> = Vec::new(); // (vd_ndx, vd_hash, vda_name_off)
            let mut vcursor = def_addr;
            let mut max_ndx: u32 = 0;
            // 注意：DT_VERDEFNUM 只是链条目数的"提示"，实测部分 fixture
            // （libc.so.6：链共 37 条但 DT_VERDEFNUM=1）该字段被裁剪/异常，
            // 与真实链长度不符；若以其为遍历上限会漏掉 vd_ndx>=2 的条目，
            // 导致 _dl_lookup_direct 版本校验（versym 索引对应槽位缺失）失败。
            // 因此不能依赖它——必须沿 vd_next 链完整走到 vd_next==0 或读取
            // 失败为止（上限 4096 仅防野指针死循环）。
            for _ in 0..4096 {
                let Ok(hdr) = memory.read(vcursor, 20) else {
                    break;
                };
                let vd_ndx = u32::from(u16::from_le_bytes(hdr[4..6].try_into().unwrap()));
                let vd_cnt = u32::from(u16::from_le_bytes(hdr[6..8].try_into().unwrap()));
                let vd_hash = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
                let vd_aux = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
                let vd_next = u32::from_le_bytes(hdr[16..20].try_into().unwrap());
                if vd_cnt == 0 {
                    if vd_next == 0 {
                        break;
                    }
                    let Some(next) = vcursor.checked_add(u64::from(vd_next)) else {
                        break;
                    };
                    vcursor = next;
                    continue;
                }
                let Ok(aux) = memory.read(
                    vcursor
                        .checked_add(u64::from(vd_aux))
                        .ok_or_else(|| DaotiError::Other("vd_aux 偏移溢出".into()))?,
                    8,
                ) else {
                    break;
                };
                let vda_name = u32::from_le_bytes(aux[..4].try_into().unwrap());
                entries.push((vd_ndx, vd_hash, vda_name));
                max_ndx = max_ndx.max(vd_ndx);
                if vd_next == 0 {
                    break;
                }
                let Some(next) = vcursor.checked_add(u64::from(vd_next)) else {
                    break;
                };
                vcursor = next;
            }
            if !entries.is_empty() {
                let count = usize::try_from(max_ndx + 1).ok().unwrap_or(entries.len());
                let versions_addr = memory
                    .mmap_anonymous_private((count * 24).try_into().unwrap(), MemPerm::rw())?;
                for (ndx, vd_hash, vda_name) in &entries {
                    let Some(name_addr) = strtab_addr.checked_add(u64::from(*vda_name)) else {
                        continue;
                    };
                    let slot = versions_addr + u64::from(*ndx) * 24;
                    memory.write(slot, &name_addr.to_le_bytes())?;
                    memory.write(slot + 8, &u64::from(*vd_hash).to_le_bytes())?;
                }
                memory.write(map_addr + 0x2e8, &versions_addr.to_le_bytes())?;
                // l_nversions 是 u32 字段（+0x2f0），紧随其后的是 l_nbuckets(+0x2f4)。
                // 必须写 4 字节；若按 u64 写 count 会把 l_nbuckets 覆盖清零，
                // 导致 _dl_lookup_direct 内 `div ecx`（ecx = [rdi+0x2f4]）除数为 0。
                memory.write(map_addr + 0x2f0, &(count as u32).to_le_bytes())?;
                if trace_hash {
                    eprintln!(
                        "TRACE link-map-hash map=0x{map_addr:x} kind=versions entries={} count={count} versions=0x{versions_addr:x} strtab=0x{strtab_addr:x}",
                        entries.len()
                    );
                }
            }
        }
    }
    if trace_info_scan {
        eprintln!(
            "TRACE link-map-info-summary map=0x{map_addr:x} dynamic=0x{dynamic_addr:x} l_info=inline(glibc) version_hits={version_hits:?}"
        );
    }
    Ok(())
}

/// 初始化 ld.so 启动前的 link_map 链表边界，使其与 glibc 语义一致。
///
/// 只清理镜像残留的垃圾值，绝不预链任何 map：
/// 1. _ns_loaded（_rtld_global + 0，namespace 0 的链头指针）必须为 NULL。
///    glibc dl_main（rtld.c:1728-1738）调用
///    `_dl_add_to_namespace_list(main_map, LM_ID_BASE)` 并断言
///    `main_map == _ns_loaded`，只有 _ns_loaded 为 NULL 时 main_map 才会
///    走链头分支（mov [rcx], rbp）成为 _ns_loaded。实测该地址残留
///    ld.so map 地址（0x2700000），导致 main_map 被追加为链尾、断言失败。
/// 2. main_map.l_next 在堆区残留垃圾，必须清零，使 main_map 成为链尾
///    （断言要求 dl_main 的 _dl_add_to_namespace_list 追加 main_map 时
///    其 l_next == NULL）。
///
/// 注意：ld.so 在 0x270ac00 把 _dl_rtld_map.l_next 写成 main_map 是合法
/// 链构建，绝不能被拦截改写。libc map 由 dl_main 加载时通过
/// _dl_add_to_namespace_list 自然追加到链尾，本函数不做预链。
fn initialize_main_program_header_state(
    memory: &mut MemoryModel,
    dl_phdr_addr: Option<u64>,
    dl_phnum_addr: Option<u64>,
    phdr_addr: u64,
    phnum: u64,
) -> Result<(), DaotiError> {
    if let Some(address) = dl_phdr_addr {
        memory.write(address, &phdr_addr.to_le_bytes())?;
    }
    if let Some(address) = dl_phnum_addr {
        memory.write(address, &phnum.to_le_bytes())?;
    }
    if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
        eprintln!(
            "TRACE main-program-header-state _dl_phdr_addr={dl_phdr_addr:#x?} _dl_phdr=0x{phdr_addr:x} _dl_phnum_addr={dl_phnum_addr:#x?} _dl_phnum={phnum}"
        );
    }
    Ok(())
}

struct PreExecState<'a> {
    memory: &'a mut MemoryModel,
    main_map_addr: u64,
    main_load_bias: u64,
    phdr_addr: u64,
    phnum: u64,
    main_dynamic_addr: Option<u64>,
}

impl PreExecState<'_> {
    fn inject(self) -> Result<(), DaotiError> {
        initialize_main_link_map(
            self.memory,
            self.main_map_addr,
            self.main_load_bias,
            self.phdr_addr,
            self.phnum,
            self.main_dynamic_addr,
            None,
            None,
        )?;
        initialize_link_map_info(self.memory, self.main_map_addr)?;
        eprintln!(
            "TRACE preexec-state-injection main_map=0x{:x} l_info=initialized",
            self.main_map_addr
        );
        Ok(())
    }
}

fn initialize_rtld_process_state(
    memory: &mut MemoryModel,
    interpreter: &DynamicMappedObject,
    stack_ptr: u64,
) -> Result<(), DaotiError> {
    if std::env::var_os("DAOTI_FIX_RTLD_STATE").is_none() {
        return Ok(());
    }
    let argv_addr = stack_ptr
        .checked_add(8)
        .ok_or_else(|| DaotiError::Other("_dl_argv 地址溢出".into()))?;
    let argc = u64::from_le_bytes(memory.read(stack_ptr, 8)?.try_into().unwrap());
    let names = [
        "_dl_argv",
        "_dl_argc",
        "_dl_error_catch_tsd",
        "_dl_load_lock",
    ];
    for name in names {
        let address = find_loaded_symbol(&interpreter.bytes, &interpreter.plan, name);
        eprintln!("TRACE rtld-state-init name={name} addr={address:#x?}");
        let Some(address) = address else {
            continue;
        };
        let value = match name {
            "_dl_argv" => argv_addr,
            "_dl_argc" => argc,
            "_dl_error_catch_tsd" | "_dl_load_lock" => 0,
            _ => unreachable!(),
        };
        let width = if name == "_dl_argc" { 4 } else { 8 };
        memory.write(address, &value.to_le_bytes()[..width])?;
        eprintln!("TRACE rtld-state-init-write name={name} addr=0x{address:x} value=0x{value:x} width={width}");
    }
    Ok(())
}

fn find_loaded_symbol(data: &[u8], plan: &DynamicLoadPlan, name: &str) -> Option<u64> {
    read_loaded_dynamic_symbols(data, plan)
        .ok()
        .and_then(|symbols| {
            symbols
                .into_iter()
                .find(|symbol| symbol.name == name && symbol.defined)
                .map(|symbol| symbol.loaded_address)
        })
        .or_else(|| {
            read_full_symtab_symbols(data).ok().and_then(|symbols| {
                symbols
                    .into_iter()
                    .find(|(symbol, value)| symbol == name && *value != 0)
                    .and_then(|(_, value)| plan.load_bias.checked_add(value))
            })
        })
}

#[cfg(test)]
fn initialize_rtld_link_chain(
    memory: &mut MemoryModel,
    load_bias: u64,
    main_map_addr: u64,
) -> Result<(), DaotiError> {
    initialize_rtld_link_chain_at(memory, load_bias + 0x33020, 0xa30, main_map_addr)
}

#[cfg(test)]
fn initialize_rtld_link_chain_at(
    memory: &mut MemoryModel,
    rtld_global_addr: u64,
    ns_loaded_offset: u64,
    main_map_addr: u64,
) -> Result<(), DaotiError> {
    let ns_loaded_addr = rtld_global_addr + ns_loaded_offset;
    let ns_loaded = memory
        .read(ns_loaded_addr, 8)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    if ns_loaded != 0 {
        memory.write(ns_loaded_addr, &0u64.to_le_bytes())?;
        eprintln!(
            "TRACE ns-loaded-init-clear addr=0x{ns_loaded_addr:x} before=0x{ns_loaded:x} corrected=0x0"
        );
    }
    let main_l_next_addr = main_map_addr + 0x18;
    let main_current = memory
        .read(main_l_next_addr, 8)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    if main_current != 0 {
        memory.write(main_l_next_addr, &0u64.to_le_bytes())?;
        eprintln!(
            "TRACE main-map-l-next-init-clear addr=0x{main_l_next_addr:x} before=0x{main_current:x} corrected=0x0"
        );
    }
    Ok(())
}

fn write_dynamic_stack(
    memory: &mut MemoryModel,
    stack_end: u64,
    program_name: &[u8],
    phdr_vaddr: u64,
    phnum: u64,
    entry: u64,
    interpreter_base: u64,
) -> Result<u64, DaotiError> {
    const AT_PHDR: u64 = 3;
    const AT_PHENT: u64 = 4;
    const AT_HWCAP: u64 = 16;
    const AT_CLKTCK: u64 = 17;
    const AT_UID: u64 = 11;
    const AT_EUID: u64 = 12;
    const AT_GID: u64 = 13;
    const AT_EGID: u64 = 14;
    const AT_SECURE: u64 = 23;
    const AT_SYSINFO_EHDR: u64 = 33;
    const AT_PHNUM: u64 = 5;
    const AT_PAGESZ: u64 = 6;
    const AT_ENTRY: u64 = 9;
    const AT_BASE: u64 = 7;
    const AT_FLAGS: u64 = 8;
    const AT_RANDOM: u64 = 25;
    const AT_PLATFORM: u64 = 15;
    const AT_EXECFN: u64 = 31;
    const AT_NULL: u64 = 0;
    let program_name_len = program_name
        .len()
        .checked_add(1)
        .ok_or_else(|| DaotiError::Other("栈程序名长度溢出".into()))?
        as u64;
    let stack_data_size = STACK_DATA_CAPACITY
        .checked_add(program_name_len)
        .ok_or_else(|| DaotiError::Other("栈数据大小溢出".into()))?;
    let stack_ptr = stack_end
        .checked_sub(stack_data_size)
        .ok_or_else(|| DaotiError::Other("栈指针下溢".into()))?
        & !0xf;
    // 程序名位于实际写入缓冲区的末尾；不能用 stack_end 反推，否则会因 16 字节对齐
    // 产生偏移，导致 ld-linux 读取到错误的 argv[0]/AT_EXECFN。
    let name_addr = stack_ptr
        .checked_add(STACK_DATA_CAPACITY)
        .and_then(|address| address.checked_sub(program_name_len))
        .ok_or_else(|| DaotiError::Other("栈程序名地址溢出或下溢".into()))?;
    let random_addr = name_addr
        .checked_sub(16)
        .ok_or_else(|| DaotiError::Other("栈随机地址下溢".into()))?;
    let platform = b"x86_64\0";
    let platform_addr = random_addr
        .checked_sub(platform.len() as u64)
        .ok_or_else(|| DaotiError::Other("栈平台字符串地址下溢".into()))?;
    let mut stack_data = Vec::with_capacity(STACK_DATA_CAPACITY as usize);
    stack_data.extend_from_slice(&1u64.to_le_bytes()); // argc
    stack_data.extend_from_slice(&name_addr.to_le_bytes()); // argv[0]
    stack_data.extend_from_slice(&0u64.to_le_bytes()); // argv[1] NULL
    stack_data.extend_from_slice(&0u64.to_le_bytes()); // envp[0] NULL
                                                       // auxv 条目
    for (tag, val) in [
        (AT_PHDR, phdr_vaddr),
        (AT_PHENT, 56u64),
        (AT_PHNUM, phnum),
        (AT_HWCAP, 0),
        (AT_CLKTCK, 100),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_SYSINFO_EHDR, 0),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_ENTRY, entry),
        (AT_BASE, interpreter_base),
        (AT_FLAGS, 0),
        (AT_RANDOM, random_addr),
        (AT_PLATFORM, platform_addr),
        (AT_EXECFN, name_addr),
        (AT_NULL, 0u64),
    ] {
        stack_data.extend_from_slice(&tag.to_le_bytes());
        stack_data.extend_from_slice(&val.to_le_bytes());
    }
    // 填充到容量末尾（程序名 + 16 字节随机种子前的对齐）
    while (stack_data.len() as u64)
        .checked_add(program_name.len() as u64)
        .is_none_or(|total| total < STACK_DATA_CAPACITY)
    {
        stack_data.push(0);
    }
    stack_data.extend_from_slice(program_name);
    stack_data.push(0);
    memory.write(stack_ptr, &stack_data)?;
    memory.write(platform_addr, platform)?;
    memory.write(
        random_addr,
        &[
            0x6d, 0x31, 0x92, 0xa7, 0x44, 0x18, 0x5f, 0xc3, 0x28, 0xe6, 0x70, 0x0b, 0x9d, 0x52,
            0xf1, 0x86,
        ],
    )?;
    if std::env::var_os("DAOTI_TRACE_PHDR").is_some() {
        let phdr_bytes = memory.read(phdr_vaddr, 16).ok();
        eprintln!(
            "TRACE write-dynamic-stack at_phdr=0x{phdr_vaddr:x} phdr_head={phdr_bytes:02x?} stack_ptr=0x{stack_ptr:x}",
        );
    }
    super::runtime::record_auxv_snapshot(memory, stack_ptr + 24);
    Ok(stack_ptr)
}

fn collect_pending_link_maps(
    memory: &MemoryModel,
    ns_loaded_addr: u64,
) -> Result<Vec<u64>, DaotiError> {
    let mut current = u64::from_le_bytes(memory.read(ns_loaded_addr, 8)?.try_into().unwrap());
    let mut visited = std::collections::HashSet::new();
    let mut pending = Vec::new();
    while current != 0 && visited.insert(current) {
        let read_u64 = |offset: u64| {
            memory
                .read(current + offset, 8)
                .ok()
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let l_addr = read_u64(0x00);
        let l_ld = read_u64(0x10);
        let l_real = read_u64(0x28);
        let l_info = read_u64(0x68);
        if l_addr.is_none() || l_ld.is_none() || l_info.is_none() || l_real != Some(current) {
            pending.push(current);
        }
        current = read_u64(0x18).unwrap_or(0);
    }
    Ok(pending)
}

pub(crate) fn initialize_all_link_maps_in_memory(
    memory: &mut MemoryModel,
    ns_loaded_addr: u64,
) -> Result<usize, DaotiError> {
    let mut current = {
        let bytes = memory.read(ns_loaded_addr, 8)?;
        u64::from_le_bytes(bytes.try_into().unwrap())
    };
    let mut visited = std::collections::HashSet::new();
    let mut initialized = 0usize;
    while current != 0 {
        if !visited.insert(current) {
            return Err(DaotiError::Other(format!(
                "link_map 链表出现循环：0x{current:x}"
            )));
        }
        let read_optional = |offset: u64| {
            memory
                .read(current + offset, 8)
                .ok()
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        };
        let l_addr = read_optional(0x00);
        let l_ld = read_optional(0x10);
        let l_next = read_optional(0x18);
        let l_prev = read_optional(0x20);
        let l_real = read_optional(0x28);
        let l_info = read_optional(0x68);
        if l_addr.is_none() || l_real != Some(current) {
            eprintln!(
                "TRACE invalid-link-map map=0x{current:x} l_addr={l_addr:#x?} l_ld={l_ld:#x?} l_real={l_real:#x?} l_info={l_info:#x?} l_next={l_next:#x?} l_prev={l_prev:#x?} action=skip"
            );
        } else {
            initialize_link_map_info(memory, current)?;
            initialized += 1;
        }
        current = {
            let bytes = memory.read(current + 0x18, 8)?;
            u64::from_le_bytes(bytes.try_into().unwrap())
        };
    }
    Ok(initialized)
}

impl<R> DynamicElfLoader<R>
where
    R: SymbolResolver,
{
    pub fn initialize_all_link_maps(
        &self,
        memory: &mut MemoryModel,
        ns_loaded_addr: u64,
    ) -> Result<usize, DaotiError> {
        initialize_all_link_maps_in_memory(memory, ns_loaded_addr)
    }

    pub fn new(resolver: R, preferred_base: u64, stack_size: u64) -> Result<Self, DaotiError> {
        if !preferred_base.is_multiple_of(PAGE_SIZE) {
            return Err(DaotiError::Other("动态 ELF 首选基址必须页对齐".into()));
        }
        if stack_size == 0 {
            return Err(DaotiError::Other("动态 ELF 安全栈大小不能为 0".into()));
        }
        Ok(Self {
            resolver,
            preferred_base,
            stack_size,
        })
    }

    /// 在显式白名单根目录内解析并读取全部 DT_NEEDED 对象。
    ///
    /// 该接口不扫描宿主目录，也不调用宿主动态链接器；返回的每个对象字节均来自
    /// `allowed_roots` 下的真实文件，供后续映射与重定位阶段使用。
    pub fn load_dependency_objects(
        &self,
        root: &Path,
        allowed_roots: &[PathBuf],
    ) -> Result<Vec<DynamicMappedObject>, DaotiError> {
        let graph = super::plan_dynamic_dependency_graph(
            root,
            allowed_roots,
            &super::FileDynamicDependencySource,
        )?;
        let mut next_base = self.preferred_base + 0x1000000;
        graph
            .nodes
            .into_iter()
            .map(|path| {
                let bytes = std::fs::read(&path).map_err(|error| {
                    DaotiError::Other(format!("读取受控动态对象 {} 失败：{error}", path.display()))
                })?;
                let _ = validate_runtime_asset(&path, &bytes, "x86_64", "动态依赖")?;
                let plan = plan_dynamic_load(&bytes, next_base)?;
                next_base = plan
                    .load_segments
                    .iter()
                    .map(|segment| segment.mapped_end)
                    .max()
                    .and_then(|end| end.checked_add(PAGE_SIZE))
                    .ok_or_else(|| DaotiError::Other("动态依赖地址空间溢出".into()))?;
                Ok::<DynamicMappedObject, DaotiError>(DynamicMappedObject { path, plan, bytes })
            })
            .collect()
    }

    /// 在受控根目录装载主对象及其真实 DT_NEEDED 图；PT_INTERP 也必须位于白名单根内。
    pub fn load_with_root(
        &self,
        root: &Path,
        allowed_roots: &[PathBuf],
    ) -> Result<DynamicLoadResult, DaotiError> {
        let main =
            std::fs::read(root).map_err(|e| DaotiError::Other(format!("读取主 ELF 失败：{e}")))?;
        let loaded = self.load(&main)?;
        if let Some(interp) = loaded.plan.interpreter.as_deref() {
            let path = resolve_controlled_path(interp, allowed_roots)?;
            let _ = std::fs::read(&path).map_err(|e| {
                DaotiError::Other(format!("读取 PT_INTERP {} 失败：{e}", path.display()))
            })?;
        }
        let dependencies = self.load_dependency_objects(root, allowed_roots)?;
        let interpreter = loaded
            .plan
            .interpreter
            .as_deref()
            .map(|path| resolve_controlled_path(path, allowed_roots))
            .transpose()?
            .map(|path| {
                let bytes = std::fs::read(&path).map_err(|e| {
                    DaotiError::Other(format!("读取 PT_INTERP {} 失败：{e}", path.display()))
                })?;
                let plan = plan_dynamic_load(&bytes, self.preferred_base + 0x2000000)?;
                Ok::<DynamicMappedObject, DaotiError>(DynamicMappedObject { path, plan, bytes })
            })
            .transpose()?;
        Ok(DynamicLoadResult {
            dependencies,
            interpreter,
            ..loaded
        })
    }

    pub fn execute(&self, data: &[u8]) -> Result<super::runtime::ExecutionState, DaotiError> {
        let loaded = self.load(data)?;
        let bridge =
            super::syscall_bridge::NativeSyscallBridge::new(super::syscall_bridge::StdoutSink)
                .with_brk(loaded.context.heap_brk, loaded.context.heap_end);
        let mut interpreter = super::runtime::X86_64Interpreter::new(loaded.context)
            .with_syscall_handler(Box::new(bridge));
        interpreter.run()
    }

    /// 通过真实 PT_INTERP 入口启动组合镜像；无 PT_INTERP 时从主对象入口启动。
    pub fn load_and_run(
        &self,
        root: &Path,
        allowed_roots: &[PathBuf],
        audit: AuditBuffer,
    ) -> Result<DynamicExecutionResult, DaotiError> {
        let loaded = self.load_combined_dynamic(root, allowed_roots)?;
        let main_bytes = std::fs::read(root)
            .map_err(|error| DaotiError::Other(format!("读取主动态 ELF 失败：{error}")))?;
        let rtld_global = loaded
            .interpreter
            .as_ref()
            .and_then(|object| find_loaded_symbol(&object.bytes, &object.plan, "_rtld_global"));
        let handler = LinuxEmulationHandler::new(audit.clone())
            .with_allowed_roots(allowed_roots)
            .with_brk(loaded.context.heap_brk, loaded.context.heap_end)
            .with_link_map_diagnostics(rtld_global.unwrap_or(0), loaded.context.heap_brk);
        let captured = handler.captured_stdout_shared();
        let user_entry = loaded.plan.relocated_entry;
        eprintln!("TRACE runtime-user-entry value=0x{user_entry:x}");
        let mut breakpoints = loaded.breakpoints;
        // 按实际 libc load_bias 动态注入 early-init 与 brk 标志写入断点，避免固定地址漂移。
        if std::env::var_os("DAOTI_TRACE_EARLY_INIT").is_some() {
            if let Some(libc) = loaded.dependencies.iter().find(|object| {
                object
                    .path
                    .file_name()
                    .is_some_and(|name| name == "libc.so.6")
            }) {
                let libc_base = libc.plan.load_bias;
                if let Some(early_init) =
                    find_loaded_symbol(&libc.bytes, &libc.plan, "__libc_early_init")
                {
                    let early_init_write = early_init + 0x2f;
                    let brk_flag = libc_base + 0x228e4e;
                    eprintln!(
                        "TRACE dynamic-early-init libc_base=0x{libc_base:x} entry=0x{early_init:x} write=0x{early_init_write:x} brk_flag=0x{brk_flag:x}"
                    );
                    breakpoints.push(super::runtime::RuntimeBreakpoint {
                        name: "__libc_early_init".into(),
                        addr: early_init,
                    });
                    breakpoints.push(super::runtime::RuntimeBreakpoint {
                        name: format!("gen:early_init_w watch=0x{brk_flag:x}"),
                        addr: early_init_write,
                    });
                } else {
                    eprintln!("TRACE dynamic-early-init symbol-not-found");
                }
            } else {
                eprintln!("TRACE dynamic-early-init libc-not-found");
            }
        }
        // 诊断探针：DAOTI_BP_EARLY_INIT=<hex addr> 注入 __libc_early_init 入口断点，
        // 用于验证 ld 是否调用了 libc 早期初始化（ptmalloc_init 依赖它）
        if let Some(addr) = std::env::var("DAOTI_BP_EARLY_INIT")
            .ok()
            .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        {
            eprintln!("TRACE bp-early-init armed addr=0x{addr:x}");
            breakpoints.push(super::runtime::RuntimeBreakpoint {
                name: "__libc_early_init".into(),
                addr,
            });
        }
        // 通用断点：DAOTI_BP="gen:名字@hex地址[,gen:名2@hex2 ...]"，命中时打印
        // ABI 寄存器；每项可带 " watch=0x<addr>" 后缀，命中时额外读该地址 8 字节
        if let Ok(list) = std::env::var("DAOTI_BP") {
            for entry in list.split(',') {
                let mut it = entry.rsplitn(2, '@');
                let addr_s = it.next().unwrap_or("");
                let name = it.next().unwrap_or("gen:unnamed");
                let mut parts = addr_s.split_whitespace();
                let addr_hex = parts.next().unwrap_or("");
                let watch = parts
                    .next()
                    .and_then(|w| w.strip_prefix("watch=0x"))
                    .and_then(|w| u64::from_str_radix(w, 16).ok());
                if let Ok(addr) = u64::from_str_radix(addr_hex.trim_start_matches("0x"), 16) {
                    let full_name = match watch {
                        Some(w) => format!("{name} watch=0x{w:x}"),
                        None => name.to_string(),
                    };
                    eprintln!("TRACE bp armed {full_name} addr=0x{addr:x}");
                    breakpoints.push(super::runtime::RuntimeBreakpoint {
                        name: full_name,
                        addr,
                    });
                }
            }
        }
        let mut interpreter = super::runtime::X86_64Interpreter::new(loaded.context)
            .with_user_entry(user_entry)
            .with_breakpoints(breakpoints)
            .with_tls_context(loaded.tls_context.clone())
            .with_syscall_handler(Box::new(handler));
        if let Some(object) = &loaded.interpreter {
            interpreter = interpreter.with_load_bias(object.plan.load_bias);
            let rtld_global = find_loaded_symbol(&object.bytes, &object.plan, "_rtld_global")
                .ok_or_else(|| DaotiError::Other("ld-linux 中未找到 _rtld_global 符号".into()))?;
            let ns_loaded_addr = rtld_global
                .checked_add(0)
                .ok_or_else(|| DaotiError::Other("_ns_loaded 地址溢出".into()))?;
            eprintln!(
                "TRACE link-map-init-deferred rtld_global=0x{rtld_global:x} ns_loaded=0x{ns_loaded_addr:x}"
            );
            interpreter = interpreter.with_link_map_initializer(Box::new(move |memory| {
                initialize_all_link_maps_in_memory(memory, ns_loaded_addr)
            }));
            interpreter =
                interpreter.with_link_map_object_initializer(Box::new(|memory, map_addr| {
                    initialize_link_map_info(memory, map_addr)
                }));
            interpreter = interpreter.with_namespace_root_addr(ns_loaded_addr);
        }
        // 旧的 libc link_map 补链钩子（0x270ac2f）会篡改 dl_main 正在构建的
        // namespace 链表（main_map.l_prev/l_next），导致 rtld.c:1720 断言
        // `main_map == _ns_loaded` 失败。写修正（MemoryModel::write 对
        // 0x2700018/0x275a018 的即时修正）已替代该补链职责，此处不再注入钩子。
        if let Some(object) = &loaded.interpreter {
            interpreter.resolve_irelative_relocs(&object.bytes, object.plan.load_bias)?;
        }
        for object in &loaded.dependencies {
            interpreter.resolve_irelative_relocs(&object.bytes, object.plan.load_bias)?;
        }
        interpreter.resolve_irelative_relocs(&main_bytes, loaded.plan.load_bias)?;
        let state = interpreter.run()?;
        if let Some(object) = &loaded.interpreter {
            let rtld_global = find_loaded_symbol(&object.bytes, &object.plan, "_rtld_global")
                .ok_or_else(|| DaotiError::Other("ld-linux 中未找到 _rtld_global 符号".into()))?;
            let ns_loaded_addr = rtld_global
                .checked_add(0xa30)
                .ok_or_else(|| DaotiError::Other("_ns_loaded 地址溢出".into()))?;
            for attempt in 0..3 {
                let initialized =
                    self.initialize_all_link_maps(&mut interpreter.context.memory, ns_loaded_addr)?;
                let pending =
                    collect_pending_link_maps(&interpreter.context.memory, ns_loaded_addr)?;
                eprintln!(
                    "TRACE link-map-post-dl-start attempt={} initialized={} pending={pending:?}",
                    attempt + 1,
                    initialized
                );
                if pending.is_empty() {
                    break;
                }
            }
        }
        let stdout = captured.lock().expect("输出缓冲区锁不应中毒").clone();
        Ok(DynamicExecutionResult {
            state,
            mode: "native_interpreter",
            stdout,
            audit,
        })
    }

    pub fn execute_combined(
        &self,
        root: &Path,
        allowed_roots: &[PathBuf],
    ) -> Result<super::runtime::ExecutionState, DaotiError> {
        let loaded = self.load_combined_dynamic(root, allowed_roots)?;
        let main_bytes = std::fs::read(root)
            .map_err(|error| DaotiError::Other(format!("读取主动态 ELF 失败：{error}")))?;
        let main_ptload: Vec<(u64, u64)> = loaded
            .plan
            .load_segments
            .iter()
            .map(|s| (s.mapped_start, s.mapped_end))
            .collect();
        let shadow = build_shadow_observer();
        let shadow_records = shadow.as_ref().map(|(_, records)| records.clone());
        let bridge =
            super::syscall_bridge::NativeSyscallBridge::new(super::syscall_bridge::StdoutSink)
                .with_brk(loaded.context.heap_brk, loaded.context.heap_end)
                .with_main_ptload(main_ptload)
                .with_allowed_roots(allowed_roots);
        let bridge = match shadow {
            Some((observer, _)) => bridge.with_observer(observer),
            None => bridge,
        };
        let interpreter_load_bias = loaded
            .interpreter
            .as_ref()
            .map(|object| object.plan.load_bias);
        let mut interpreter = super::runtime::X86_64Interpreter::new(loaded.context);
        if let Some(load_bias) = interpreter_load_bias {
            let phase_handler: super::runtime::PhaseHandler<'static> =
                Box::new(move |_context, _phase| Ok(()));
            /*
            if phase == super::runtime::PhaseId::Four {
                let (_rbp, score) = infer_main_map_source(context, &network)?;
                let main_map_from_cmp = context.registers.general.rbx;
                if score > 0.8 {
                    let load_bias = load_bias;
                    let rtld_global = load_bias.checked_add(0x33020).ok_or_else(|| {
                        DaotiError::Other("阶段4 _rtld_global 地址溢出".into())
                    })?;
                    let ns_loaded = rtld_global.checked_add(0).ok_or_else(|| {
                        DaotiError::Other("阶段4 _ns_loaded 地址溢出".into())
                    })?;
                    let main_map_addr = main_map_from_cmp;
                    if main_map_addr == 0 {
                        return Err(DaotiError::Other(
                            "阶段4真实 cmp 的 main_map 操作数为空".into(),
                        ));
                    }
                    let rtld_l_prev_addr =
                        load_bias.checked_add(0x20).ok_or_else(|| {
                            DaotiError::Other("阶段4 _dl_rtld_map.l_prev 地址溢出".into())
                        })?;
                    let rtld_l_next_addr = rtld_global + 0x18;
                    let main_l_next_addr =
                        main_map_addr.checked_add(0x18).ok_or_else(|| {
                            DaotiError::Other("阶段4 main_map.l_next 地址溢出".into())
                        })?;
                    let main_l_prev_addr =
                        main_map_addr.checked_add(0x20).ok_or_else(|| {
                            DaotiError::Other("阶段4 main_map.l_prev 地址溢出".into())
                        })?;
                    let read_u64 = |memory: &super::runtime::MemoryModel,
                                    address: u64|
                     -> Result<u64, DaotiError> {
                        let bytes = memory.read(address, 8)?;
                        Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
                            DaotiError::Other("阶段4 link_map 字段长度错误".into())
                        })?))
                    };
                    let before = [
                        (
                            "_dl_rtld_map.l_prev",
                            rtld_l_prev_addr,
                            read_u64(&context.memory, rtld_l_prev_addr)?,
                        ),
                        (
                            "_dl_rtld_map.l_next",
                            rtld_l_next_addr,
                            read_u64(&context.memory, rtld_l_next_addr)?,
                        ),
                        (
                            "main_map.l_next",
                            main_l_next_addr,
                            read_u64(&context.memory, main_l_next_addr)?,
                        ),
                        (
                            "main_map.l_prev",
                            main_l_prev_addr,
                            read_u64(&context.memory, main_l_prev_addr)?,
                        ),
                    ];
                    eprintln!(
                        "TRACE daoti-phase4-link-map-before main_map=0x{main_map_addr:x} rtld=0x{load_bias:x} fields={before:?}"
                    );
                    let zero = 0u64.to_le_bytes();
                    let rtld = load_bias.to_le_bytes();
                    context
                        .memory
                        .write(rtld_global, &main_map_addr.to_le_bytes())?;
                    context.memory.write(rtld_l_prev_addr, &zero)?;
                    context
                        .memory
                        .write(rtld_l_next_addr, &main_map_addr.to_le_bytes())?;
                    context
                        .memory
                        .write(ns_loaded, &main_map_addr.to_le_bytes())?;
                    context.memory.write(main_l_next_addr, &zero)?;
                    context.memory.write(main_l_prev_addr, &rtld)?;
                    let after = [
                        (
                            "_dl_rtld_map.l_prev",
                            rtld_l_prev_addr,
                            read_u64(&context.memory, rtld_l_prev_addr)?,
                        ),
                        (
                            "_dl_rtld_map.l_next",
                            rtld_l_next_addr,
                            read_u64(&context.memory, rtld_l_next_addr)?,
                        ),
                        (
                            "main_map.l_next",
                            main_l_next_addr,
                            read_u64(&context.memory, main_l_next_addr)?,
                        ),
                        (
                            "main_map.l_prev",
                            main_l_prev_addr,
                            read_u64(&context.memory, main_l_prev_addr)?,
                        ),
                        (
                            "_ns_loaded",
                            ns_loaded,
                            read_u64(&context.memory, ns_loaded)?,
                        ),
                    ];
                    eprintln!(
                        "TRACE daoti-phase4-link-map-after score={score:.6} fields={after:?}"
                    );
                } else {
                    eprintln!(
                        "TRACE daoti-phase4-repair approved=false score={score:.6} threshold=0.8"
                    );
                }
                Ok(())
            } else {
                let main_map = context.heap_brk;
                let rip = context.registers.general.rip;
                apply_daoti_phase(
                    &mut context.memory,
                    phase,
                    &network,
                    load_bias,
                    main_map,
                    rip,
                )
            }
            */
            interpreter = interpreter
                .with_load_bias(load_bias)
                .with_phase_handler(phase_handler);
        }
        let mut interpreter = interpreter
            .with_breakpoints(loaded.breakpoints)
            .with_syscall_handler(Box::new(bridge));
        if let Some(object) = &loaded.interpreter {
            interpreter.resolve_irelative_relocs(&object.bytes, object.plan.load_bias)?;
        }
        for object in &loaded.dependencies {
            interpreter.resolve_irelative_relocs(&object.bytes, object.plan.load_bias)?;
        }
        interpreter.resolve_irelative_relocs(&main_bytes, loaded.plan.load_bias)?;
        let result = interpreter.run();
        if let Some(records) = shadow_records.as_ref() {
            flush_shadow_records(records);
        }
        result
    }

    /// 返回结构化解析 metadata；`execution_verified` 固定为 false，避免将规划证据误报为真实执行。
    pub fn metadata(&self, data: &[u8]) -> Result<super::DynamicElfMetadata, DaotiError> {
        let info = parse_elf_from_bytes(data)?;
        let plan = plan_dynamic_load(data, self.preferred_base)?;
        Ok(super::DynamicElfMetadata::from_plan(&info, &plan))
    }

    pub fn load(&self, data: &[u8]) -> Result<DynamicLoadResult, DaotiError> {
        if data.is_empty() {
            return Err(DaotiError::Other("动态 ELF 文件不能为空".into()));
        }
        let info = parse_elf_from_bytes(data)?;
        let plan = plan_dynamic_load(data, self.preferred_base)?;
        let stack_base = plan
            .load_segments
            .iter()
            .map(|segment| segment.mapped_end)
            .max()
            .ok_or_else(|| DaotiError::Other("动态 ELF 缺少映射段".into()))?;
        let stack_size = super::align_up(self.stack_size, PAGE_SIZE);
        let stack_end = stack_base
            .checked_add(stack_size)
            .ok_or_else(|| DaotiError::Other("动态 ELF 栈地址溢出".into()))?;
        let mut memory = MemoryModel::new(self.preferred_base, stack_end + PAGE_SIZE);
        map_dynamic_object(&mut memory, data, &plan, &info)?;
        memory.add_region(MemoryRegion::with_data(
            stack_base,
            MemPerm::rw(),
            vec![0; stack_size as usize],
        ))?;
        let mut context = RuntimeContext::new(plan.relocated_entry, stack_end - 8, memory);
        context.registers.general.rip = plan.relocated_entry;
        let entries = read_dynamic_relocations(data, &info, &plan)?;
        let relocations =
            apply_x86_64_relocations(&mut context.memory, &plan, &entries, &self.resolver)?;
        Ok(DynamicLoadResult {
            plan,
            context,
            relocations,
            dependencies: Vec::new(),
            interpreter: None,
            breakpoints: Vec::new(),
            tls_context: TlsContext::default(),
            tls_modules: Vec::new(),
            dtv_addr: None,
        })
    }

    /// 在主对象基础上装载真实依赖图并完成跨对象重定位。
    ///
    /// 将主 ET_DYN 与全部 DT_NEEDED 对象合并进同一内存模型：
    /// - 逐个对象合并 PT_LOAD 镜像（`map_dynamic_object`）；
    /// - 从各对象 DT_SYMTAB/DT_STRTAB 构建跨对象动态符号解析器（按名称优先）；
    /// - 对主对象与每个依赖对象写入其动态重定位（GLOB_DAT/JUMP_SLOT/RELATIVE）；
    /// - 在初始栈布置 auxv（含 AT_PHDR/AT_ENTRY/AT_RANDOM）并为 TLS/TCB 和堆预留区域。
    pub fn load_combined_dynamic(
        &self,
        root: &Path,
        allowed_roots: &[PathBuf],
    ) -> Result<DynamicLoadResult, DaotiError> {
        // 1. 读取并规划主对象
        let main =
            std::fs::read(root).map_err(|e| DaotiError::Other(format!("读取主 ELF 失败：{e}")))?;
        let main_info = parse_elf_from_bytes(&main)?;
        let main_plan = plan_dynamic_load(&main, self.preferred_base)?;
        let interpreter = if let Some(path) = main_plan.interpreter.as_deref() {
            let path = resolve_controlled_path(path, allowed_roots)?;
            let bytes = std::fs::read(&path).map_err(|e| {
                DaotiError::Other(format!("读取 PT_INTERP {} 失败：{e}", path.display()))
            })?;
            let _ = validate_runtime_asset(&path, &bytes, "x86_64", "动态链接器")?;
            let plan = plan_dynamic_load(&bytes, self.preferred_base + 0x2000000)?;
            Some(DynamicMappedObject { path, plan, bytes })
        } else {
            None
        };

        // 2. 解析依赖图，过滤根对象（主对象已单独装载）
        let deps = self.load_dependency_objects(root, allowed_roots)?;
        let root_canon = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let real_deps: Vec<DynamicMappedObject> = deps
            .into_iter()
            .filter(|d| d.path != root_canon)
            .filter(|d| {
                interpreter
                    .as_ref()
                    .is_none_or(|interp| d.path != interp.path)
            })
            .collect();

        // 3. 计算总地址范围，构造统一内存模型
        let mut max_end = 0u64;
        for s in &main_plan.load_segments {
            max_end = max_end.max(s.mapped_end);
        }
        for dep in &real_deps {
            for s in &dep.plan.load_segments {
                max_end = max_end.max(s.mapped_end);
            }
        }
        if let Some(interp) = &interpreter {
            for s in &interp.plan.load_segments {
                max_end = max_end.max(s.mapped_end);
            }
        }
        let stack_region_size = super::align_up(
            self.stack_size
                .max(STACK_DATA_CAPACITY + root.to_string_lossy().len() as u64),
            PAGE_SIZE,
        );
        let stack_base = max_end;
        let stack_end = stack_base
            .checked_add(stack_region_size)
            .ok_or_else(|| DaotiError::Other("动态组合栈地址溢出".into()))?;
        let tls_region_base = stack_end;
        // 预留完整的 TLS 正方向访问窗口，覆盖 FS+0x4000/FS+0x5000。
        let tls_region_size = PAGE_SIZE * 8;
        let tls_base_addr = tls_region_base
            .checked_add(0x800)
            .ok_or_else(|| DaotiError::Other("TLS 基址溢出".into()))?;
        // ld 引导 bump 分配器独立区域：若与 libc malloc 堆共用，ld 已写入的
        // link_map 字节会被 malloc 当作 top chunk 元数据，触发
        // "malloc(): corrupted top size"。真实 glibc 的 bump 区也独立于主堆。
        let bump_region_size = 1024u64 * 1024;
        let bump_region_base = tls_region_base
            .checked_add(tls_region_size)
            .ok_or_else(|| DaotiError::Other("bump 区地址溢出".into()))?
            .checked_add(PAGE_SIZE)
            .ok_or_else(|| DaotiError::Other("bump 区地址溢出".into()))?;
        let heap_addr = bump_region_base
            .checked_add(bump_region_size)
            .ok_or_else(|| DaotiError::Other("堆地址溢出".into()))?
            .checked_add(PAGE_SIZE)
            .ok_or_else(|| DaotiError::Other("堆地址溢出".into()))?;
        let heap_size: u64 = 8 * 1024 * 1024;
        let heap_end = heap_addr
            .checked_add(heap_size)
            .ok_or_else(|| DaotiError::Other("堆大小溢出".into()))?;
        let memory_max = heap_end
            // 顶部预留 64MB 作为 mmap 区：glibc 的 sysmalloc 假设匿名 mmap 返回
            // 地址高于 brk 段（Linux top-down mmap 语义），否则
            // "malloc(): corrupted top size"
            .checked_add(0x10000000)
            .ok_or_else(|| DaotiError::Other("内存上界溢出".into()))?;
        let mut memory = MemoryModel::new(self.preferred_base.min(stack_base), memory_max);
        memory.trace_writable_pt_load = interpreter
            .as_ref()
            .map(|object| {
                object
                    .plan
                    .load_segments
                    .iter()
                    .filter(|segment| segment.flags & 2 != 0)
                    .map(|segment| (segment.mapped_start, segment.mapped_end))
                    .collect()
            })
            .unwrap_or_default();
        if std::env::var_os("DAOTI_TRACE_WRITABLE_PT_LOAD").is_some() {
            eprintln!(
                "TRACE writable-pt-load-ranges ranges={:?}",
                memory.trace_writable_pt_load
            );
        }

        // 4. 映射主对象与依赖对象的 PT_LOAD
        map_dynamic_object(&mut memory, &main, &main_plan, &main_info)?;
        for dep in &real_deps {
            let dep_info = parse_elf_from_bytes(&dep.bytes)?;
            if std::env::var_os("DAOTI_TRACE_OBJECT_MAP").is_some() {
                let range = dep
                    .plan
                    .load_segments
                    .iter()
                    .map(|segment| (segment.mapped_start, segment.mapped_end))
                    .collect::<Vec<_>>();
                eprintln!(
                    "TRACE object path={} load_bias=0x{:x} ranges={range:?}",
                    dep.path.display(),
                    dep.plan.load_bias
                );
            }
            map_dynamic_object(&mut memory, &dep.bytes, &dep.plan, &dep_info)?;
        }
        if let Some(interp) = &interpreter {
            let interp_info = parse_elf_from_bytes(&interp.bytes)?;
            map_dynamic_object(&mut memory, &interp.bytes, &interp.plan, &interp_info)?;
            if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                let header = memory.read(interp.plan.load_bias, 0x40)?;
                eprintln!("TRACE interpreter-header-after-map e_phoff=0x{:x} e_ehsize=0x{:x} e_phentsize=0x{:x}",
                    u64::from_le_bytes(header[0x20..0x28].try_into().unwrap()),
                    u16::from_le_bytes(header[0x34..0x36].try_into().unwrap()),
                    u16::from_le_bytes(header[0x36..0x38].try_into().unwrap()));
            }
            if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                if let Ok(symbols) = super::read_loaded_dynamic_symbols(&interp.bytes, &interp.plan)
                {
                    if let Some(symbol) = symbols
                        .iter()
                        .find(|symbol| symbol.name == "_r_debug" && symbol.defined)
                    {
                        let r_debug_addr = symbol.loaded_address;
                        let r_map = u64::from_le_bytes(
                            memory.read(r_debug_addr + 8, 8)?.try_into().unwrap(),
                        );
                        eprintln!("TRACE r-debug addr=0x{r_debug_addr:x} r_map=0x{r_map:x}");
                        if r_map != 0 {
                            let map_data = memory.read(r_map, 128)?;
                            for offset in (0..128).step_by(8) {
                                let value = u64::from_le_bytes(
                                    map_data[offset..offset + 8].try_into().unwrap(),
                                );
                                eprintln!("TRACE link-map +0x{offset:02x}=0x{value:016x}");
                                if value == interp.plan.load_bias + 0x40 {
                                    eprintln!(
                                        "TRACE link-map candidate l_phdr offset=0x{offset:x}"
                                    );
                                }
                                if value == 9 {
                                    eprintln!(
                                        "TRACE link-map candidate l_phnum offset=0x{offset:x}"
                                    );
                                }
                            }
                        }
                    } else {
                        eprintln!("TRACE _r_debug symbol unavailable in interpreter dynsym");
                    }
                }
            }
        }

        // 5. 栈、TLS、堆区域
        memory.add_region(MemoryRegion::with_data(
            stack_base,
            MemPerm::rw(),
            vec![0; stack_region_size as usize],
        ))?;
        memory.add_region(MemoryRegion::with_data(
            tls_region_base,
            MemPerm::rw(),
            vec![0; tls_region_size as usize],
        ))?;
        // x86_64 TLS 的 FS:0 必须是自指 TCB；glibc 在 ld.so 自重定位和
        // main_map 建立前就会读取这些字段，不能只提供一片清零内存。
        memory.write(tls_base_addr, &tls_base_addr.to_le_bytes())?;
        memory.write(tls_base_addr + 8, &(tls_base_addr + 0x100).to_le_bytes())?;
        memory.write(tls_base_addr + 0x10, &tls_base_addr.to_le_bytes())?;
        memory.write(tls_base_addr + 0x28, &0x6d3192a744185fc3u64.to_le_bytes())?;
        memory.write(tls_base_addr + 0x30, &0x28e6700b9d52f186u64.to_le_bytes())?;
        let mut tls_objects = Vec::new();
        let mut tls_object_plans: Vec<&DynamicLoadPlan> = Vec::new();
        if let Some(tls) = main_plan.tls.as_ref() {
            tls_objects.push((main.as_slice(), tls));
            tls_object_plans.push(&main_plan);
        }
        for dep in &real_deps {
            if let Some(tls) = dep.plan.tls.as_ref() {
                tls_objects.push((dep.bytes.as_slice(), tls));
                tls_object_plans.push(&dep.plan);
            }
        }
        if let Some(interp) = &interpreter {
            if let Some(tls) = interp.plan.tls.as_ref() {
                tls_objects.push((interp.bytes.as_slice(), tls));
                tls_object_plans.push(&interp.plan);
            }
        }
        let tls_modules = install_tls_images(
            &mut memory,
            tls_base_addr,
            tls_region_base,
            tls_region_size,
            &tls_objects,
        )?;
        // 构建跨对象 TLS 上下文：把每个对象的 STT_TLS 符号映射到
        // (module_id, block_start, 块内偏移)，供 DTPMOD64/DTPOFF64/TPOFF64 解析。
        // module_id/block_start 与 install_tls_images 的 tls_objects 顺序严格一致。
        let mut tls_context = TlsContext::new(tls_base_addr);
        for (index, plan) in tls_object_plans.iter().enumerate() {
            let module = &tls_modules[index];
            let data = tls_objects[index].0;
            let symbols = match super::read_loaded_dynamic_symbols(data, plan) {
                Ok(symbols) => symbols,
                Err(_) => continue,
            };
            for symbol in symbols {
                // STT_TLS = 6；仅收录已定义的 TLS 符号。
                if symbol.symbol_type == 6 && symbol.defined {
                    tls_context.insert(
                        symbol.name,
                        TlsSymbolLocation {
                            module_id: module.module_id,
                            block_start: module.start,
                            offset: symbol.raw_value,
                        },
                    );
                }
            }
        }
        // glibc Variant I：DTV 指针位于 TP + TLS_DTV_OFFSET(0x4000)，DTV 数组本身
        // 放在已预留的正方向窗口 TP + 0x5000，槽 0 为 generation、槽 module_id 为
        // 该模块 TLS 块地址。此处先建立静态装载期 DTV，供 __tls_get_addr 与
        // DTPMOD64/DTPOFF64 语义在后续竖切中消费。
        let dtv_addr = if !tls_modules.is_empty() {
            let dtv_array_addr = tls_base_addr
                .checked_add(0x5000)
                .ok_or_else(|| DaotiError::Other("DTV 数组地址溢出".into()))?;
            let dtv_end = dtv_array_addr.checked_add(
                (tls_modules.len() as u64 + 1)
                    .checked_mul(8)
                    .ok_or_else(|| DaotiError::Other("DTV 数组长度溢出".into()))?,
            );
            if dtv_end
                .map(|end| end > tls_region_base + tls_region_size)
                .unwrap_or(true)
            {
                return Err(DaotiError::Other("DTV 数组超出 TLS 区域".into()));
            }
            build_dtv(&mut memory, dtv_array_addr, &tls_modules)?;
            memory.write(
                tls_base_addr
                    .checked_add(0x4000)
                    .ok_or_else(|| DaotiError::Other("DTV 指针地址溢出".into()))?,
                &dtv_array_addr.to_le_bytes(),
            )?;
            Some(dtv_array_addr)
        } else {
            None
        };
        // bump 区实映射：ld 引导分配器（__minimal_malloc）在 dl_main 期间从这里分配
        memory.add_region(MemoryRegion::with_data(
            bump_region_base,
            MemPerm::rw(),
            vec![0; bump_region_size as usize],
        ))?;
        memory.add_region(MemoryRegion::with_data(
            heap_addr,
            MemPerm::rw(),
            vec![0; heap_size as usize],
        ))?;

        // 5.5 初始化 ld-linux 引导分配器（bump allocator）的全局状态。
        // glibc 的 __minimal_malloc 在启动早期检查 [rip+disp] alloc_end 全局；若为 0，
        // 它立即返回 NULL（rtld.c:1712 main_map != NULL 断言）。必须在任何 calloc 前
        // 把 alloc_ptr/alloc_end 指向运行时堆，分配器才能成功返回非零 link_map。
        if let Some(interp) = &interpreter {
            // alloc_end 映射：mov rdx,[rip+0x29a90] @ 0xa6e9 → l_bias + 0x34180
            // alloc_ptr 映射：mov rax,[rip+0x29a88] @ 0xa6f9 → l_bias + 0x34188
            let bias = interp.plan.load_bias;
            let alloc_end_addr = bias + 0x34180;
            let alloc_ptr_addr = bias + 0x34188;
            // bump 区与 libc malloc 堆分离：alloc 区终点 = bump 区末尾
            memory.write(
                alloc_end_addr,
                &(bump_region_base + bump_region_size).to_le_bytes(),
            )?;
            memory.write(alloc_ptr_addr, &bump_region_base.to_le_bytes())?;
            // glibc 2.35 在 __rtld_malloc_init_stubs 被调用前，早期路径已经
            // 可能通过 __rtld_malloc 分配 link_map。按 ld.so 自身符号布局预置
            // 三个最小分配器入口，避免空函数指针把控制流跳到 RIP=0。
            let rtld_malloc_addr = bias + 0x39a60;
            let rtld_free_addr = bias + 0x39a68;
            let rtld_realloc_addr = bias + 0x39a58;
            memory.write(rtld_malloc_addr, &(bias + 0xd3d0).to_le_bytes())?;
            memory.write(rtld_free_addr, &(bias + 0xd530).to_le_bytes())?;
            memory.write(rtld_realloc_addr, &(bias + 0xd570).to_le_bytes())?;
            if std::env::var_os("DAOTI_TRACE_DLMAIN").is_some() {
                eprintln!(
                    "TRACE init-ldso-alloc alloc_ptr=0x{alloc_ptr_addr:x}<-0x{heap_addr:x} alloc_end=0x{alloc_end_addr:x}<-0x{heap_end:x} rtld_malloc=0x{rtld_malloc_addr:x}->0x{:x}",
                    bias + 0xd3d0
                );
            }
        }

        // 5.6 ld-linux 的 _rtld_global 是 _rtld_local 的起始对象；glibc
        // 通过其首字段 _dl_rtld_map.l_addr 计算自身 load_bias。
        let mut rtld_global_address = None;
        if let Some(interp) = &interpreter {
            let bias = interp.plan.load_bias;
            let mut rtld_global = None;
            if let Ok(symbols) = super::read_loaded_dynamic_symbols(&interp.bytes, &interp.plan) {
                rtld_global = symbols
                    .into_iter()
                    .find(|symbol| symbol.name == "_rtld_global" && symbol.defined)
                    .map(|symbol| symbol.loaded_address);
            }
            if rtld_global.is_none() {
                if let Ok(symbols) = super::read_full_symtab_symbols(&interp.bytes) {
                    rtld_global = symbols
                        .into_iter()
                        .find(|(name, value)| name == "_rtld_global" && *value != 0)
                        .and_then(|(_, value)| bias.checked_add(value));
                }
            }
            let address = rtld_global
                .ok_or_else(|| DaotiError::Other("ld-linux 中未找到 _rtld_global 符号".into()))?;
            rtld_global_address = Some(address);
            // _rtld_global + 0 是 namespace 0 的链表头指针，必须保持 NULL，
            // 由 dl_main 首次挂入主程序 map；不能把 ELF 映像基址当作 link_map。
            if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                eprintln!("TRACE rtld-global-namespace-head addr=0x{address:x} initial=NULL");
            }
            let phoff = u64::from_le_bytes(interp.bytes[0x20..0x28].try_into().unwrap());
            let phentsize = u16::from_le_bytes(interp.bytes[0x36..0x38].try_into().unwrap()) as u64;
            let phnum = u16::from_le_bytes(interp.bytes[0x38..0x3a].try_into().unwrap());
            let mut dynamic_vaddr = None;
            let mut phdr_vaddr = None;
            let mut phdr_segment = None;
            for index in 0..phnum as u64 {
                let offset = phoff + index * phentsize;
                let p_type = u32::from_le_bytes(
                    interp.bytes[offset as usize..offset as usize + 4]
                        .try_into()
                        .unwrap(),
                );
                let p_offset = u64::from_le_bytes(
                    interp.bytes[offset as usize + 8..offset as usize + 16]
                        .try_into()
                        .unwrap(),
                );
                let p_vaddr = u64::from_le_bytes(
                    interp.bytes[offset as usize + 16..offset as usize + 24]
                        .try_into()
                        .unwrap(),
                );
                let p_filesz = u64::from_le_bytes(
                    interp.bytes[offset as usize + 32..offset as usize + 40]
                        .try_into()
                        .unwrap(),
                );
                let p_memsz = u64::from_le_bytes(
                    interp.bytes[offset as usize + 40..offset as usize + 48]
                        .try_into()
                        .unwrap(),
                );
                match p_type {
                    2 => dynamic_vaddr = Some(p_vaddr),
                    6 => phdr_vaddr = Some(p_vaddr),
                    1 if phdr_segment.is_none()
                        && phoff >= p_offset
                        && phoff < p_offset + p_filesz =>
                    {
                        phdr_segment = Some((p_offset, p_vaddr, p_filesz, p_memsz));
                    }
                    _ => {}
                }
            }
            let phdr_vaddr = phdr_vaddr.or_else(|| {
                phdr_segment.and_then(|(p_offset, p_vaddr, p_filesz, p_memsz)| {
                    (phoff >= p_offset && phoff < p_offset + p_filesz)
                        .then_some(p_vaddr + phoff - p_offset)
                        .or_else(|| {
                            (phoff >= p_offset && phoff < p_offset + p_memsz)
                                .then_some(p_vaddr + phoff - p_offset)
                        })
                })
            });
            let _ = (dynamic_vaddr, phdr_vaddr, phnum);
            if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                eprintln!(
                    "TRACE rtld-map-init addr=0x{address:x} l_ld={:?} l_phdr={:?} l_phnum={phnum}",
                    dynamic_vaddr.map(|value| bias + value),
                    phdr_vaddr.map(|value| bias + value)
                );
                let phdr_addr =
                    bias + u64::from_le_bytes(interp.bytes[0x20..0x28].try_into().unwrap());
                eprintln!("TRACE rtld-global-scan addr=0x{address:x} phdr=0x{phdr_addr:x}");
                for offset in (0..256).step_by(8) {
                    let value =
                        u64::from_le_bytes(memory.read(address + offset, 8)?.try_into().unwrap());
                    if value == phdr_addr || value == 9 {
                        eprintln!("TRACE rtld-global candidate +0x{offset:x}=0x{value:x}");
                    }
                }
            }
            if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                eprintln!("DEBUG: Fixed _dl_rtld_map.l_next/l_prev/l_real addr=0x{address:x}");
                let raw = memory.read(address, 64)?;
                eprintln!("TRACE rtld-global-raw addr=0x{address:x}");
                for offset in (0..64).step_by(8) {
                    let value = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
                    eprintln!("TRACE rtld-global +0x{offset:02x}=0x{value:016x}");
                }
                eprintln!("TRACE rtld-global expected l_addr=0x{bias:x}");
            }
        }

        // 6. 计算主对象 PT_PHDR 装载地址，用于 auxv AT_PHDR
        let e_phoff = u64::from_le_bytes(main[0x20..0x28].try_into().unwrap());
        let e_phnum = u16::from_le_bytes(main[0x38..0x3a].try_into().unwrap()) as u64;
        // AT_PHDR 必须是主对象 PT_PHDR 的运行时地址。优先使用显式
        // PT_PHDR，只有缺少该段时才从包含程序头表的 PT_LOAD 推导。
        let raw_phdr = main_info
            .segments
            .iter()
            .find(|seg| seg.type_ == 6)
            .map(|seg| seg.vaddr)
            .or_else(|| {
                main_info
                    .segments
                    .iter()
                    .find(|seg| {
                        e_phoff >= seg.offset && e_phoff + (e_phnum * 56) <= seg.offset + seg.filesz
                    })
                    .map(|seg| seg.vaddr + (e_phoff - seg.offset))
            })
            .unwrap_or(e_phoff);
        let phdr_vaddr = raw_phdr
            .checked_add(main_plan.load_bias)
            .ok_or_else(|| DaotiError::Other("PT_PHDR 地址溢出".into()))?;
        if let Some(interpreter) = &interpreter {
            let dl_phdr_addr =
                find_loaded_symbol(&interpreter.bytes, &interpreter.plan, "_dl_phdr");
            let dl_phnum_addr =
                find_loaded_symbol(&interpreter.bytes, &interpreter.plan, "_dl_phnum");
            initialize_main_program_header_state(
                &mut memory,
                dl_phdr_addr,
                dl_phnum_addr,
                phdr_vaddr,
                e_phnum,
            )?;
        }
        let main_map_addr = heap_addr;
        let rtld_map_addr = interpreter.as_ref().map(|object| object.plan.load_bias);
        if std::env::var_os("DAOTI_TRACE_RTLD_STATE").is_some() {
            if let Some(interp) = &interpreter {
                let bias = interp.plan.load_bias;
                for offset in 0x32a80..=0x32aa8 {
                    let address = bias + offset;
                    let value = memory
                        .read(address, 8)
                        .ok()
                        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()));
                    eprintln!("TRACE rtld-state-candidate addr=0x{address:x} offset=0x{offset:x} value={value:#x?}");
                }
                eprintln!(
                    "TRACE rtld-state-layout bias=0x{bias:x} argv=0x{:x}",
                    bias + 0x32a98
                );
            }
        }
        let ns_loaded_addr = rtld_global_address
            .map(|address| {
                address
                    .checked_add(0)
                    .ok_or_else(|| DaotiError::Other("_ns_loaded 地址溢出".into()))
            })
            .transpose()?;
        // 由 ld.so 的 _dl_start 创建主程序 link_map 和 namespace 链表。
        let main_dynamic_addr = main_plan
            .entries
            .iter()
            .find(|entry| entry.tag == 2)
            .and_then(|entry| main_plan.load_bias.checked_add(entry.value));
        PreExecState {
            memory: &mut memory,
            main_map_addr,
            main_load_bias: main_plan.load_bias,
            phdr_addr: phdr_vaddr,
            phnum: e_phnum,
            main_dynamic_addr,
        }
        .inject()?;
        if std::env::var_os("DAOTI_FIX_NS_LOADED_WRITE").is_some() {
            if let Some(ns_loaded_addr) = ns_loaded_addr {
                memory.ns_loaded_write_fix = Some((ns_loaded_addr, main_map_addr));
                eprintln!(
                    "TRACE ns-loaded-write-fix-config addr=0x{ns_loaded_addr:x} main_map=0x{main_map_addr:x}"
                );
            }
        }
        if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
            eprintln!(
                "TRACE link-map-init ns_loaded_addr={:#x?} main_map=0x{main_map_addr:x} ldso_next={:?}",
                ns_loaded_addr,
                rtld_map_addr.map(|_| 0)
            );
        }
        let phase_network = interpreter
            .as_ref()
            .map(|_| load_glibc_daoti_network())
            .transpose()?;
        if let Some(phase_network) = phase_network.as_ref() {
            apply_daoti_phase(
                &mut memory,
                super::runtime::PhaseId::Zero,
                phase_network,
                interpreter
                    .as_ref()
                    .map(|object| object.plan.load_bias)
                    .unwrap_or(main_plan.load_bias),
                main_map_addr,
                0,
            )?;
        }
        if std::env::var_os("DAOTI_FIX_L_INFO").is_some() {
            if let Some(ns_loaded_addr) = ns_loaded_addr {
                let initialized = initialize_all_link_maps_in_memory(&mut memory, ns_loaded_addr)?;
                eprintln!(
                    "TRACE phase-zero-link-map-init ns_loaded=0x{ns_loaded_addr:x} initialized={initialized}"
                );
            }
        }
        let e_phentsize = u16::from_le_bytes(main[0x36..0x38].try_into().unwrap()) as usize;
        let phdr_len = e_phnum
            .checked_mul(e_phentsize as u64)
            .ok_or_else(|| DaotiError::Other("程序头表长度溢出".into()))?
            as usize;
        let phdr_end = (e_phoff as usize)
            .checked_add(phdr_len)
            .ok_or_else(|| DaotiError::Other("程序头表文件范围溢出".into()))?;
        let expected_phdr = main
            .get(e_phoff as usize..phdr_end)
            .ok_or_else(|| DaotiError::Other("程序头表超出 ELF 文件范围".into()))?;
        let loaded_phdr = memory.read(phdr_vaddr, phdr_len as u64)?;
        if loaded_phdr != expected_phdr {
            let first_diff = loaded_phdr
                .iter()
                .zip(expected_phdr.iter())
                .position(|(actual, expected)| actual != expected)
                .unwrap_or(expected_phdr.len().min(loaded_phdr.len()));
            eprintln!(
                "AT_PHDR 校验失败: addr=0x{phdr_vaddr:x}, len={phdr_len}, first_diff=0x{first_diff:x}, actual={:02x?}, expected={:02x?}",
                &loaded_phdr[first_diff..loaded_phdr.len().min(first_diff + 16)],
                &expected_phdr[first_diff..expected_phdr.len().min(first_diff + 16)]
            );
            return Err(DaotiError::Other(
                "AT_PHDR 内容与 ELF 程序头表不一致".into(),
            ));
        }

        // 7. auxv 写入栈
        let stack_ptr = write_dynamic_stack(
            &mut memory,
            stack_end,
            root.to_string_lossy().as_bytes(),
            phdr_vaddr,
            e_phnum,
            main_plan.relocated_entry,
            interpreter
                .as_ref()
                .map(|value| value.plan.load_bias)
                .unwrap_or(0),
        )?;
        if let Some(interpreter) = &interpreter {
            initialize_rtld_process_state(&mut memory, interpreter, stack_ptr)?;
        }

        // 8. 构建跨对象解析器：主对象 + 依赖对象 + 解释器（ld-linux）
        let mut objects: Vec<(Vec<u8>, DynamicLoadPlan)> = Vec::new();
        objects.push((main.clone(), main_plan.clone()));
        for dep in &real_deps {
            objects.push((dep.bytes.clone(), dep.plan.clone()));
        }
        if let Some(interp) = &interpreter {
            objects.push((interp.bytes.clone(), interp.plan.clone()));
        }
        let resolver = CrossObjectSymbolResolver::from_objects(&objects)?;
        if let Some(phase_network) = phase_network.as_ref() {
            apply_daoti_phase(
                &mut memory,
                super::runtime::PhaseId::Two,
                phase_network,
                interpreter
                    .as_ref()
                    .map(|object| object.plan.load_bias)
                    .unwrap_or(main_plan.load_bias),
                main_map_addr,
                0,
            )?;
        }
        // 收集 ld-linux 内部调用点（_dl_map_object/_dl_new_object/calloc）的已装载地址，
        // 供解释器在 rip 命中时记录 x86_64 ABI 参数。
        let mut breakpoints = Vec::<super::runtime::RuntimeBreakpoint>::new();
        if let Some(interp) = &interpreter {
            if let Some(dl_start) = find_loaded_symbol(&interp.bytes, &interp.plan, "_dl_start") {
                eprintln!("TRACE dl-start-symbol addr=0x{dl_start:x} source=runtime-symbol");
            } else {
                let fallback = interp.plan.load_bias + 0x1ab70;
                eprintln!("TRACE dl-start-symbol addr=0x{fallback:x} source=verified-offset offset=0x1ab70");
                breakpoints.push(super::runtime::RuntimeBreakpoint {
                    name: "_dl_start".into(),
                    addr: fallback,
                });
            }
        }
        // 先从 .dynsym 查找导出符号
        for (obj_data, obj_plan) in &objects {
            let Ok(symbols) = super::read_loaded_dynamic_symbols(obj_data, obj_plan) else {
                continue;
            };
            for symbol in symbols {
                if matches!(
                    symbol.name.as_str(),
                    "_dl_map_object"
                        | "_dl_new_object"
                        | "_dl_start"
                        | "_dl_relocate_object"
                        | "_dl_exception_create_format"
                        | "calloc"
                ) {
                    if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                        eprintln!(
                            "TRACE runtime breakpoint symbol={} addr=0x{:x} (dynsym)",
                            symbol.name, symbol.loaded_address
                        );
                    }
                    breakpoints.push(super::runtime::RuntimeBreakpoint {
                        name: symbol.name.clone(),
                        addr: symbol.loaded_address,
                    });
                }
            }
        }
        // 再从 .symtab 查找内部隐藏符号（_dl_map_object/_dl_new_object 不在 .dynsym 中导出）
        for (obj_data, obj_plan) in &objects {
            let Ok(symtab_symbols) = super::read_full_symtab_symbols(obj_data) else {
                if std::env::var_os("DAOTI_TRACE_RELOC_SYMBOLS").is_some() {
                    eprintln!(
                        "TRACE reloc-symbol-scan failed bias=0x{:x}",
                        obj_plan.load_bias
                    );
                }
                continue;
            };
            if std::env::var_os("DAOTI_TRACE_RELOC_SYMBOLS").is_some() {
                let candidates = symtab_symbols
                    .iter()
                    .filter(|(name, _)| name.contains("relocat") || name.contains("reloc"))
                    .map(|(name, value)| format!("{name}=0x{value:x}"))
                    .collect::<Vec<_>>();
                eprintln!(
                    "TRACE reloc-symbol-scan bias=0x{:x} symbols={} candidates={candidates:?}",
                    obj_plan.load_bias,
                    symtab_symbols.len()
                );
            }
            for (name, st_value) in &symtab_symbols {
                if !matches!(
                    name.as_str(),
                    "_dl_map_object"
                        | "_dl_new_object"
                        | "_dl_start"
                        | "_dl_relocate_object"
                        | "_dl_exception_create_format"
                ) {
                    continue;
                }
                if *st_value == 0 {
                    continue;
                }
                let Some(loaded_addr) = obj_plan.load_bias.checked_add(*st_value) else {
                    continue;
                };
                if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
                    eprintln!(
                        "TRACE runtime breakpoint symbol={} addr=0x{:x} (symtab)",
                        name, loaded_addr
                    );
                }
                breakpoints.push(super::runtime::RuntimeBreakpoint {
                    name: name.clone(),
                    addr: loaded_addr,
                });
            }
        }
        // 功能型断点：`__tls_get_addr`（动态 TLS 取址入口）。装载期把它的已装载地址
        // 注册为断点，执行循环命中后由解释器模拟 glibc 语义（读 tls_index、查
        // TlsContext.get_addr、模拟 ret 返回），无需真实执行 ld.so 的取址例程。
        for (obj_data, obj_plan) in &objects {
            if let Some(addr) = find_loaded_symbol(obj_data, obj_plan, "__tls_get_addr") {
                if std::env::var_os("DAOTI_TRACE_TLS").is_some() {
                    eprintln!("TRACE tls-get-addr-breakpoint addr=0x{addr:x}");
                }
                breakpoints.push(super::runtime::RuntimeBreakpoint {
                    name: "__tls_get_addr".into(),
                    addr,
                });
                break;
            }
        }

        // 9. 逐对象写入重定位
        let mut applied = Vec::new();
        for (obj_data, obj_plan) in &objects {
            let obj_info = parse_elf_from_bytes(obj_data)?;
            let is_interpreter = interpreter
                .as_ref()
                .is_some_and(|object| object.plan.load_bias == obj_plan.load_bias);
            let entries = read_dynamic_relocations_with_plt(obj_data, &obj_info, obj_plan, true)?;
            if std::env::var_os("DAOTI_TRACE_RELOCATIONS").is_some() {
                eprintln!(
                    "TRACE reloc-object bias=0x{:x} interpreter={} rela={:?} rel={:?} jmprel={:?} parsed={}",
                    obj_plan.load_bias,
                    is_interpreter,
                    obj_plan.rela,
                    obj_plan.rel,
                    obj_plan.jmprel,
                    entries.len()
                );
                for (index, entry) in entries.iter().enumerate() {
                    let target = entry.offset.checked_add(obj_plan.load_bias);
                    let current = target.and_then(|address| {
                        memory
                            .read(address, 8)
                            .ok()
                            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    });
                    eprintln!(
                        "TRACE reloc-entry index={} bias=0x{:x} offset=0x{:x} target={:?} info=0x{:x} type={:?} symbol={} name={:?} addend={:?} size={} current={:?}",
                        index,
                        obj_plan.load_bias,
                        entry.offset,
                        target.map(|address| format!("0x{address:x}")),
                        entry.info,
                        entry.relocation_type,
                        entry.symbol,
                        entry.symbol_name,
                        entry.addend,
                        entry.symbol_size,
                        current.map(|value| format!("0x{value:x}")),
                    );
                }
            }
            let batch = apply_x86_64_relocations_with_tls(
                &mut memory,
                obj_plan,
                &entries,
                &resolver,
                Some(&tls_context),
            )?;
            applied.extend(batch);
        }
        if let Some(phase_network) = phase_network.as_ref() {
            apply_daoti_phase(
                &mut memory,
                super::runtime::PhaseId::Three,
                phase_network,
                interpreter
                    .as_ref()
                    .map(|object| object.plan.load_bias)
                    .unwrap_or(main_plan.load_bias),
                main_map_addr,
                0,
            )?;
        }

        // _rtld_global 起始区域同时承载 ld.so 的内部状态，不能在 loader
        // 阶段将推测的 link_map 字段写入其中；namespace 链表由 ld.so 自己维护。
        let mut state_fields = Vec::new();
        state_fields.extend([
            super::super::glibc_knowledge::StateField {
                name: "link_map.l_phdr".into(),
                address: main_map_addr + 0x30,
                value: phdr_vaddr.to_le_bytes().to_vec(),
            },
            super::super::glibc_knowledge::StateField {
                name: "link_map.l_phnum".into(),
                address: main_map_addr + 0x38,
                value: (e_phnum as u16).to_le_bytes().to_vec(),
            },
        ]);
        let mut decision_sample = super::super::glibc_knowledge::official_knowledge_samples()
            .into_iter()
            .next()
            .ok_or_else(|| DaotiError::ModelCorrupt("道体知识样本为空".into()))?;
        decision_sample.target_fields = vec![
            "_dl_rtld_map.l_addr".into(),
            "_dl_rtld_map.l_next".into(),
            "_dl_rtld_map.l_prev".into(),
            "_ns_loaded".into(),
            "link_map.l_phdr".into(),
            "link_map.l_phnum".into(),
        ];
        decision_sample.context = "dynamic_elf_loader_state".into();
        decision_sample.input_vector.fill(0.0);
        decision_sample.output_vector.fill(0.0);
        for field in &decision_sample.target_fields {
            let index = super::super::glibc_knowledge::field_label_index(field);
            decision_sample.input_vector[index] = 1.0;
            decision_sample.output_vector[index] = 1.0;
        }
        let model_path = std::env::var_os("DAOTI_B2_WEIGHTS_PATH")
            .map(PathBuf::from)
            .or_else(|| {
                [
                    PathBuf::from("knowledge/glibc_network.daotiblt"),
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../knowledge/glibc_network.daotiblt"),
                ]
                .into_iter()
                .find(|path| path.is_file())
            });
        let candidate = model_path
            .map(|path| {
                let weights = crate::bilateral::weights::WeightsLoader::load(&path)?;
                let ascent = Array2::from_shape_vec((weights.dim, weights.dim), weights.ascent)
                    .map_err(|error| {
                        DaotiError::ModelCorrupt(format!("上梯形权重维度错误：{error}"))
                    })?;
                let descent = Array2::from_shape_vec((weights.dim, weights.dim), weights.descent)
                    .map_err(|error| {
                    DaotiError::ModelCorrupt(format!("下梯形权重维度错误：{error}"))
                })?;
                let network = crate::bilateral::network::BilateralLadderNetwork::new(
                    ascent,
                    descent,
                    Array1::from_vec(weights.bias),
                    weights.t_iter,
                )?;
                super::super::glibc_knowledge::infer_candidate_state(&network, &decision_sample)
            })
            .transpose()?;
        let candidate = candidate.ok_or_else(|| {
            DaotiError::InferenceFailed("未加载道体权重，动态 ELF 状态决策无法继续".into())
        })?;
        let decision = super::super::glibc_knowledge::decode_state_decision(
            &decision_sample,
            &candidate,
            "dynamic_elf_loader",
        )?;
        super::super::glibc_knowledge::StateApplier::apply_decision(
            &mut memory,
            &state_fields,
            &decision,
        )?;
        if std::env::var_os("DAOTI_TRACE_RUNTIME").is_some() {
            let next = memory.read(rtld_global_address.unwrap_or_default() + 0x18, 8)?;
            let loaded = memory.read(rtld_global_address.unwrap_or_default(), 8)?;
            eprintln!(
                "TRACE glibc-decision continue={} approved={:?} l_next=0x{:x} ns_loaded=0x{:x} main_map=0x{:x}",
                decision.continue_execution,
                decision.fields.iter().filter(|field| field.approved).map(|field| field.field.as_str()).collect::<Vec<_>>(),
                u64::from_le_bytes(next.try_into().unwrap()),
                u64::from_le_bytes(loaded.try_into().unwrap()),
                main_map_addr
            );
        }

        // 10. 在返回装载结果前，只初始化当前已存在的 namespace 链表节点。
        // 运行时符号解析和 ld.so 自身建链仍由解释器负责，不参与此处触发。
        if let Some(ns_loaded_addr) = ns_loaded_addr {
            let initialized = self.initialize_all_link_maps(&mut memory, ns_loaded_addr)?;
            if std::env::var_os("DAOTI_TRACE_LINK_MAP_INIT").is_some() {
                eprintln!("TRACE explicit-link-map-init ns_loaded=0x{ns_loaded_addr:x} count={initialized}");
            }
        }

        // 11. 构造运行时上下文
        let entry = interpreter
            .as_ref()
            .map_or(main_plan.relocated_entry, |object| {
                object.plan.relocated_entry
            });
        // 解释器 `_start` 遵循 Linux 内核入口约定：RSP 指向 argc；不能把 RSP
        // 指到栈数据区起点以外，否则它读取到错误的 argc/argv/auxv。
        let mut context = RuntimeContext::new(entry, stack_ptr, memory);
        context.registers.general.rip = entry;
        context.registers.general.rflags = 0x202;
        // Linux 在进入 PT_INTERP 时仅保证栈和 rdx(rtld_fini)；其余通用寄存器清零，避免把构造器残值传入 ld.so。
        context.registers.general.rax = 0;
        context.registers.general.rbx = 0;
        context.registers.general.rcx = 0;
        context.registers.general.rdx = 0;
        // ld.so 的真实入口 `_start` 只从 RSP 读取 argc/argv/auxv；RDI 不是入口参数，
        // 必须保持内核进入解释器时的零值，避免把伪造的栈地址误当作 ABI 参数。
        context.registers.general.rdi = 0;
        context.registers.general.rsi = 0;
        context.registers.general.rbp = 0;
        context.registers.general.r8 = 0;
        context.registers.general.r9 = 0;
        context.registers.general.r10 = 0;
        context.registers.general.r11 = 0;
        context.registers.general.r12 = 0;
        context.registers.general.r13 = 0;
        context.registers.general.r14 = 0;
        context.registers.general.r15 = 0;
        context.tls_base = tls_base_addr;
        context.heap_brk = heap_addr;
        context.heap_end = heap_end;

        Ok(DynamicLoadResult {
            plan: main_plan,
            context,
            relocations: applied,
            dependencies: real_deps,
            interpreter,
            breakpoints,
            tls_context,
            tls_modules,
            dtv_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::EmptyDynamicResolver;

    #[test]
    fn tls_images_respect_alignment_and_zero_bss() {
        let region_base = 0x1000;
        let region_size = 0x1000;
        let tls_base = 0x1100;
        let mut memory = MemoryModel::new(region_base, region_base + region_size);
        memory
            .add_region(MemoryRegion::with_data(
                region_base,
                MemPerm::rw(),
                vec![0xcc; region_size as usize],
            ))
            .expect("应创建 TLS 区域");
        let first = [0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        let second = [0, 0x11, 0x22, 0x33];
        let metadata = [
            TlsMetadata {
                vaddr: 0,
                file_offset: 2,
                file_size: 4,
                memory_size: 10,
                align: 16,
            },
            TlsMetadata {
                vaddr: 0,
                file_offset: 1,
                file_size: 3,
                memory_size: 7,
                align: 64,
            },
        ];
        let objects: [(&[u8], &TlsMetadata); 2] = [(&first, &metadata[0]), (&second, &metadata[1])];
        let modules = install_tls_images(&mut memory, tls_base, region_base, region_size, &objects)
            .expect("TLS 镜像应安装成功");
        let starts: Vec<u64> = modules.iter().map(|m| m.start).collect();

        // module_id 按装载顺序从 1 开始，与物理布局顺序无关。
        assert_eq!(modules[0].module_id, 1);
        assert_eq!(modules[1].module_id, 2);
        assert_eq!(starts[0] % metadata[0].align, 0);
        assert_eq!(starts[1] % metadata[1].align, 0);
        assert!(
            starts[0] + metadata[0].memory_size <= starts[1]
                || starts[1] + metadata[1].memory_size <= starts[0]
        );
        assert_eq!(
            memory.read(starts[0], 4).unwrap(),
            &[0xaa, 0xbb, 0xcc, 0xdd]
        );
        assert_eq!(memory.read(starts[0] + 4, 6).unwrap(), &[0; 6]);
        assert_eq!(memory.read(starts[1], 3).unwrap(), &[0x11, 0x22, 0x33]);
        assert_eq!(memory.read(starts[1] + 3, 4).unwrap(), &[0; 4]);
        assert_eq!(memory.read(tls_base, 8).unwrap(), &[0xcc; 8]);
    }

    #[test]
    fn dtv_maps_module_ids_to_tls_block_addresses() {
        let region_base = 0x1000;
        let region_size = 0x2000;
        let tls_base = 0x1100;
        let mut memory = MemoryModel::new(region_base, region_base + region_size);
        memory
            .add_region(MemoryRegion::with_data(
                region_base,
                MemPerm::rw(),
                vec![0; region_size as usize],
            ))
            .expect("应创建 TLS 区域");
        let image_a = [0xAA; 4];
        let image_b = [0xBB; 8];
        let metadata = [
            TlsMetadata {
                vaddr: 0,
                file_offset: 0,
                file_size: 4,
                memory_size: 4,
                align: 8,
            },
            TlsMetadata {
                vaddr: 0,
                file_offset: 0,
                file_size: 8,
                memory_size: 8,
                align: 16,
            },
        ];
        let objects: [(&[u8], &TlsMetadata); 2] =
            [(&image_a, &metadata[0]), (&image_b, &metadata[1])];
        let modules = install_tls_images(&mut memory, tls_base, region_base, region_size, &objects)
            .expect("TLS 镜像应安装成功");

        let dtv_addr = 0x2000;
        build_dtv(&mut memory, dtv_addr, &modules).expect("DTV 应构造成功");

        // 槽 0 是 generation 计数器。
        let generation = u64::from_le_bytes(memory.read(dtv_addr, 8).unwrap().try_into().unwrap());
        assert_eq!(generation, 1);
        // 槽 module_id 指向对应模块 TLS 块地址。
        for module in &modules {
            let slot = dtv_addr + module.module_id * 8;
            let stored = u64::from_le_bytes(memory.read(slot, 8).unwrap().try_into().unwrap());
            assert_eq!(stored, module.start);
        }
    }

    #[test]
    fn dtv_rejects_duplicate_and_zero_module_ids() {
        let region_base = 0x1000;
        let mut memory = MemoryModel::new(region_base, region_base + 0x1000);
        memory
            .add_region(MemoryRegion::with_data(
                region_base,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();

        for modules in [
            vec![TlsModule {
                module_id: 0,
                start: 0x1200,
                memory_size: 8,
                align: 8,
            }],
            vec![
                TlsModule {
                    module_id: 1,
                    start: 0x1200,
                    memory_size: 8,
                    align: 8,
                },
                TlsModule {
                    module_id: 1,
                    start: 0x1300,
                    memory_size: 8,
                    align: 8,
                },
            ],
        ] {
            let err = build_dtv(&mut memory, 0x1800, &modules).unwrap_err();
            assert!(format!("{err}").contains("不连续"));
        }
    }

    #[test]
    fn dtv_rejects_non_contiguous_module_ids() {
        let region_base = 0x1000;
        let mut memory = MemoryModel::new(region_base, region_base + 0x1000);
        memory
            .add_region(MemoryRegion::with_data(
                region_base,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let modules = vec![
            TlsModule {
                module_id: 1,
                start: 0x1200,
                memory_size: 8,
                align: 8,
            },
            TlsModule {
                module_id: 3,
                start: 0x1300,
                memory_size: 8,
                align: 8,
            },
        ];
        let err = build_dtv(&mut memory, 0x1800, &modules).unwrap_err();
        assert!(format!("{err}").contains("不连续"));
    }

    fn self_contained_dynamic_elf(with_interp: bool, interpreter: &str) -> Vec<u8> {
        let phnum = if with_interp { 3u16 } else { 2u16 };
        let mut data = vec![0u8; 0x400];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;
        data[16..18].copy_from_slice(&3u16.to_le_bytes());
        data[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        data[20..24].copy_from_slice(&1u32.to_le_bytes());
        data[24..32].copy_from_slice(&0x100u64.to_le_bytes());
        data[32..40].copy_from_slice(&64u64.to_le_bytes());
        data[40..48].copy_from_slice(&0u64.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&phnum.to_le_bytes());
        let write_phdr = |slot: usize,
                          typ: u32,
                          flags: u32,
                          offset: u64,
                          vaddr: u64,
                          filesz: u64,
                          memsz: u64,
                          data: &mut [u8]| {
            let at = 64 + slot * 56;
            data[at..at + 4].copy_from_slice(&typ.to_le_bytes());
            data[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            data[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            data[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            data[at + 24..at + 32].copy_from_slice(&vaddr.to_le_bytes());
            data[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            data[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            data[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        };
        write_phdr(0, 1, 5, 0, 0, 0x400, 0x400, &mut data);
        write_phdr(1, 2, 6, 0x200, 0x200, 16, 16, &mut data);
        data[0x200..0x210].copy_from_slice(&[0; 16]);
        if with_interp {
            let interp_bytes = interpreter.as_bytes();
            write_phdr(
                2,
                3,
                4,
                0x220,
                0x220,
                (interp_bytes.len() + 1) as u64,
                (interp_bytes.len() + 1) as u64,
                &mut data,
            );
            data[0x220..0x220 + interp_bytes.len()].copy_from_slice(interp_bytes);
            data[0x220 + interp_bytes.len()] = 0;
        }
        data
    }

    #[test]
    fn self_contained_dynamic_elf_enters_pt_interp_loader_path() {
        let tempdir = std::env::temp_dir().join(format!(
            "daoti-dynamic-elf-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("系统时间应有效")
                .as_nanos()
        ));
        std::fs::create_dir(&tempdir).expect("应创建临时目录");
        let interpreter_path = tempdir.join("ld-self-contained.so");
        let main_path = tempdir.join("hello_dynamic");
        std::fs::write(&interpreter_path, self_contained_dynamic_elf(false, ""))
            .expect("应写入自包含解释器");
        std::fs::write(
            &main_path,
            self_contained_dynamic_elf(true, "/lib64/ld-self-contained.so"),
        )
        .expect("应写入自包含主对象");

        let loader = DynamicElfLoader::new(EmptyDynamicResolver, 0x700000, 0x20000)
            .expect("动态 ELF 加载器应创建");
        let result = loader
            .load_with_root(&main_path, std::slice::from_ref(&tempdir))
            .expect("自包含 PT_INTERP 应进入解释器装载路径");
        assert_eq!(
            result.plan.interpreter.as_deref(),
            Some("/lib64/ld-self-contained.so")
        );
        let interpreter = result.interpreter.expect("应装载自包含解释器");
        assert_eq!(interpreter.plan.interpreter, None);
        assert_eq!(result.plan.load_segments.len(), 1);
        assert_eq!(interpreter.plan.load_segments.len(), 1);
        assert_eq!(result.context.tls_base, 0);
        assert_eq!(result.context.heap_brk, 0);
    }

    #[test]
    fn initializes_main_program_header_state_for_rtld() {
        let mut memory = MemoryModel::new(0x2700000, 0x2740000);
        memory
            .add_region(MemoryRegion::with_data(
                0x2700000,
                MemPerm::rw(),
                vec![0; 0x40000],
            ))
            .expect("应映射 rtld 状态区域");
        initialize_main_program_header_state(
            &mut memory,
            Some(0x2732a90),
            Some(0x2732a98),
            0x700040,
            9,
        )
        .expect("应初始化主程序程序头状态");
        assert_eq!(
            u64::from_le_bytes(memory.read(0x2732a90, 8).unwrap().try_into().unwrap()),
            0x700040
        );
        assert_eq!(
            u64::from_le_bytes(memory.read(0x2732a98, 8).unwrap().try_into().unwrap()),
            9
        );
    }

    #[test]
    fn dynamic_stack_records_at_phdr_and_preserves_program_header_bytes() {
        let mut memory = MemoryModel::new(0x1000, 0x9000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x8000],
            ))
            .expect("测试栈区域应可映射");
        let phdr = 0x3000;
        let expected = [
            0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        memory.write(phdr, &expected).expect("应写入程序头样本");
        let stack_ptr = write_dynamic_stack(
            &mut memory,
            0x8000,
            b"./hello",
            phdr,
            9,
            0x401000,
            0x2700000,
        )
        .expect("应构造动态栈");
        let stack = memory.read(stack_ptr, 0x2000).expect("应读取动态栈");
        let at_phdr = stack
            .windows(16)
            .find(|entry| u64::from_le_bytes(entry[..8].try_into().unwrap()) == 3)
            .map(|entry| u64::from_le_bytes(entry[8..16].try_into().unwrap()));
        assert_eq!(at_phdr, Some(phdr));
        assert_eq!(memory.read(phdr, 16).unwrap(), expected);
    }

    // 动态段 d_ptr 地址形态是混合的：glibc 已填充的 l_info 相关 d_ptr
    // （DT_GNU_HASH/DT_STRTAB/DT_VERSYM）已是运行时绝对地址，而
    // DT_VERDEF/DT_VERNEED 仍为未加 load_bias 的 raw vaddr。absolutize
    // 必须对两种形态都返回正确的运行时地址，且探测过程不得触发
    // find_region 的失败诊断打印。
    fn memory_with_region(base: u64, len: u64) -> MemoryModel {
        let mut memory = MemoryModel::new(0, 0x4000_0000);
        memory
            .add_region(MemoryRegion::with_data(
                base,
                MemPerm::rw(),
                vec![0; len as usize],
            ))
            .expect("测试区域应可映射");
        memory
    }

    #[test]
    fn absolutize_prefers_biased_for_raw_vaddr_form() {
        // 场景：DT_VERDEF 等 raw vaddr（0x1fd08 形态）——只有加偏置地址可读。
        let load_bias = 0x1000_0000;
        let raw_vaddr = 0x1fd08;
        let memory = memory_with_region(load_bias + raw_vaddr, 0x100);
        assert_eq!(
            absolutize(&memory, load_bias, raw_vaddr),
            Some(load_bias + raw_vaddr)
        );
        // raw vaddr 本身不可读（0x1fd08 处无映射），绝不回退到它。
        assert!(!memory.probe_read(raw_vaddr, 4));
    }

    #[test]
    fn absolutize_falls_back_to_absolute_form() {
        // 场景：DT_GNU_HASH/DT_STRTAB 等已被 glibc 绝对化——只有 value 可读。
        let load_bias = 0x1000_0000;
        let absolute = 0x25c7_0000;
        let memory = memory_with_region(absolute, 0x100);
        assert_eq!(absolutize(&memory, load_bias, absolute), Some(absolute));
        // 加偏置地址不可读，不误报。
        assert!(!memory.probe_read(load_bias + absolute, 4));
    }

    #[test]
    fn absolutize_returns_none_when_neither_readable() {
        let load_bias = 0x1000_0000;
        let memory = memory_with_region(0x3000_0000, 0x100); // 与候选地址均无关
        assert_eq!(absolutize(&memory, load_bias, 0x5000), None);
        assert_eq!(absolutize(&memory, load_bias, 0x25c7_0000), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_and_run_minimal_dynamic_hello_uses_native_interpreter() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/runtime/hello_minimal_dynamic.elf");
        let runtime_root = root.parent().expect("fixture 必须有父目录").to_path_buf();
        let loader = DynamicElfLoader::new(EmptyDynamicResolver, 0x700000, 0x20_000)
            .expect("动态 ELF 加载器应创建");
        let audit = AuditBuffer::new();
        let result = loader
            .load_and_run(&root, std::slice::from_ref(&runtime_root), audit)
            .expect("极简动态 ELF 应由本地解释器执行");

        assert_eq!(result.mode, "native_interpreter");
        assert_eq!(result.stdout, b"Hello from minimal dynamic!\n");
        assert!(result
            .audit
            .records()
            .iter()
            .any(|record| record.contains("Hello from minimal dynamic!")));
        assert_eq!(
            result.state,
            super::super::runtime::ExecutionState::Exited(0)
        );
    }

    #[test]
    #[ignore = "验收门禁：先运行 scripts/build-tls-dynamic-fixture.sh 生成真实 TLS fixture"]
    fn load_and_run_real_tls_dynamic_chain() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tls_dynamic");
        assert!(root.is_file(), "真实 TLS 主对象不存在：{}", root.display());
        let runtime_root = root.parent().expect("fixture 必须有父目录").to_path_buf();
        let loader = DynamicElfLoader::new(EmptyDynamicResolver, 0x700000, 0x20_000)
            .expect("动态 ELF 加载器应创建");
        let loaded = loader
            .load_combined_dynamic(&root, std::slice::from_ref(&runtime_root))
            .expect("真实 TLS 多依赖对象应完成组合装载");
        assert!(loaded.tls_modules.len() >= 2);
        assert_eq!(loaded.tls_modules[0].module_id, 1);
        assert_eq!(loaded.tls_modules[1].module_id, 2);
        for (index, module) in loaded.tls_modules.iter().enumerate() {
            assert_eq!(module.module_id, (index + 1) as u64);
        }
        let dtv_addr = loaded.dtv_addr.expect("真实 TLS 装载应建立 DTV");
        let generation = u64::from_le_bytes(
            loaded
                .context
                .memory
                .read(dtv_addr, 8)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(generation, 1);
        for module in &loaded.tls_modules {
            let slot = dtv_addr + module.module_id * 8;
            let stored = u64::from_le_bytes(
                loaded
                    .context
                    .memory
                    .read(slot, 8)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(stored, module.start);
        }

        let result = loader
            .load_and_run(
                &root,
                std::slice::from_ref(&runtime_root),
                AuditBuffer::new(),
            )
            .expect("真实 TLS 主对象应完成跨对象取址");

        // _start 读取两个 provider 中的 TLS 值 41+59，并直接通过 exit syscall 返回。
        // DAOTI_TRACE_TLS 应同时出现 module_id=1 和 module_id=2，分别对应两个 DTV 槽位。
        assert_eq!(
            result.state,
            super::super::runtime::ExecutionState::Exited(100)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn load_and_run_dynamic_hello_uses_native_interpreter_and_audit() {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/runtime/hello_dynamic");
        let runtime_root = root.parent().expect("fixture 必须有父目录").to_path_buf();
        let loader = DynamicElfLoader::new(EmptyDynamicResolver, 0x700000, 0x20_000)
            .expect("动态 ELF 加载器应创建");
        let audit = AuditBuffer::new();
        let result = loader
            .load_and_run(&root, std::slice::from_ref(&runtime_root), audit)
            .expect("动态 Hello 应由本地解释器执行");

        assert_eq!(result.mode, "native_interpreter");
        assert!(
            String::from_utf8_lossy(&result.stdout).contains("Hello"),
            "stdout={:?} audit={:?} state={:?}",
            String::from_utf8_lossy(&result.stdout),
            result.audit.records(),
            result.state
        );
        assert!(result
            .audit
            .records()
            .iter()
            .any(|record| record.starts_with("write:")));
        assert_eq!(
            result.state,
            super::super::runtime::ExecutionState::Exited(0)
        );
    }

    struct DummyResolver;
    impl SymbolResolver for DummyResolver {
        fn resolve(&self, _symbol: u32) -> Option<u64> {
            None
        }
    }

    fn elf_header(entry: u64, phnum: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(64);
        h.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        h.push(2); // 64 位
        h.push(1); // 小端
        h.push(1); // version
        h.push(0); // ABI
        h.extend_from_slice(&[0u8; 8]);
        h.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
        h.extend_from_slice(&0x3e_u16.to_le_bytes()); // x86_64
        h.extend_from_slice(&1u32.to_le_bytes());
        h.extend_from_slice(&entry.to_le_bytes());
        h.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        h.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        h.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        h.extend_from_slice(&phnum.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        h.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        h.extend_from_slice(&0u16.to_le_bytes());
        h
    }

    fn phdr(
        typ: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(56);
        b.extend_from_slice(&typ.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&vaddr.to_le_bytes());
        b.extend_from_slice(&vaddr.to_le_bytes()); // paddr
        b.extend_from_slice(&filesz.to_le_bytes());
        b.extend_from_slice(&memsz.to_le_bytes());
        b.extend_from_slice(&align.to_le_bytes());
        b
    }

    #[test]
    fn initialize_all_link_maps_walks_existing_chain() {
        let mut memory = MemoryModel::new(0x700000, 0x720000);
        memory
            .add_region(MemoryRegion::with_data(
                0x700000,
                MemPerm::rwx(),
                vec![0; 0x20000],
            ))
            .unwrap();
        let loader = DynamicElfLoader::new(EmptyDynamicResolver, 0x700000, 0x1000).unwrap();
        let ns_loaded: u64 = 0x700100;
        let first: u64 = 0x701000;
        let second: u64 = 0x702000;
        memory.write(ns_loaded, &first.to_le_bytes()).unwrap();
        memory.write(first, &0x700000u64.to_le_bytes()).unwrap();
        memory.write(first + 0x28, &first.to_le_bytes()).unwrap();
        memory.write(first + 0x18, &second.to_le_bytes()).unwrap();
        memory.write(second, &0x700000u64.to_le_bytes()).unwrap();
        memory.write(second + 0x28, &second.to_le_bytes()).unwrap();
        memory.write(second + 0x18, &0u64.to_le_bytes()).unwrap();
        assert_eq!(
            loader
                .initialize_all_link_maps(&mut memory, ns_loaded)
                .unwrap(),
            2
        );
    }

    #[test]
    fn initialize_link_map_info_builds_dynamic_tag_index() {
        let mut memory = MemoryModel::new(0x700000, 0x720000);
        memory
            .add_region(MemoryRegion::with_data(
                0x700000,
                MemPerm::rwx(),
                vec![0; 0x10000],
            ))
            .unwrap();
        let map: u64 = 0x700800;
        let dynamic: u64 = 0x701000;
        memory.write(map, &0x700000u64.to_le_bytes()).unwrap();
        memory.write(map + 0x10, &dynamic.to_le_bytes()).unwrap();
        memory.write(dynamic, &5i64.to_le_bytes()).unwrap();
        memory.write(dynamic + 8, &0x1234u64.to_le_bytes()).unwrap();
        memory.write(dynamic + 16, &0i64.to_le_bytes()).unwrap();
        memory
            .write(map + 0x40 + 5 * 8, &dynamic.to_le_bytes())
            .unwrap();
        initialize_link_map_info(&mut memory, map).unwrap();
        assert_eq!(
            u64::from_le_bytes(
                memory
                    .read(map + 0x40 + 5 * 8, 8)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            dynamic
        );
    }

    #[test]
    fn initialize_link_map_info_indexes_version_tags() {
        let mut memory = MemoryModel::new(0x700000, 0x720000);
        memory
            .add_region(MemoryRegion::with_data(
                0x700000,
                MemPerm::rwx(),
                vec![0; 0x10000],
            ))
            .unwrap();
        let map = 0x700800;
        let dynamic: u64 = 0x701000;
        memory.write(map, &0x700000u64.to_le_bytes()).unwrap();
        memory.write(map + 0x10, &dynamic.to_le_bytes()).unwrap();
        let entries = [
            dtag(0x6ffffff0, 0x701100),
            dtag(0x6ffffffe, 0x701200),
            dtag(0x6fffffff, 0x701300),
            dtag(0, 0),
        ];
        for (index, entry) in entries.iter().enumerate() {
            memory.write(dynamic + index as u64 * 16, entry).unwrap();
        }
        memory
            .write(map + 0x40 + 50 * 8, &dynamic.to_le_bytes())
            .unwrap();
        memory
            .write(map + 0x40 + 36 * 8, &(dynamic + 16).to_le_bytes())
            .unwrap();
        memory
            .write(map + 0x40 + 35 * 8, &(dynamic + 32).to_le_bytes())
            .unwrap();
        initialize_link_map_info(&mut memory, map).unwrap();
        assert_eq!(
            u64::from_le_bytes(
                memory
                    .read(map + 0x40 + 50 * 8, 8)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            dynamic
        );
        assert_eq!(
            u64::from_le_bytes(
                memory
                    .read(map + 0x40 + 36 * 8, 8)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            dynamic + 16
        );
        assert_eq!(
            u64::from_le_bytes(
                memory
                    .read(map + 0x40 + 35 * 8, 8)
                    .unwrap()
                    .try_into()
                    .unwrap()
            ),
            dynamic + 32
        );
    }

    fn dtag(tag: i64, val: u64) -> Vec<u8> {
        let mut b = Vec::with_capacity(16);
        b.extend_from_slice(&tag.to_le_bytes());
        b.extend_from_slice(&val.to_le_bytes());
        b
    }

    /// 主对象：在 RW 段槽位 0x600500 处有 GLOB_DAT 重定位，引用动态符号 "func"（UNDEF），
    /// 并通过 DT_NEEDED 依赖 "libdep.so"。
    fn build_main_so() -> Vec<u8> {
        let mut buf = elf_header(0x400000, 3);
        buf.extend_from_slice(&phdr(1, 5, 0, 0x400000, 0x1000, 0x1000, 0x1000));
        buf.extend_from_slice(&phdr(1, 6, 0x2000, 0x600000, 0x800, 0x800, 0x1000));
        buf.extend_from_slice(&phdr(2, 6, 0x2000, 0x600000, 0x90, 0x90, 8));
        buf.resize(0x2800, 0);
        // 9 个 DT_* 条目（0x2000 起）
        let mut dynamic = Vec::new();
        dynamic.extend_from_slice(&dtag(5, 0x600100)); // strtab
        dynamic.extend_from_slice(&dtag(6, 0x600200)); // symtab
        dynamic.extend_from_slice(&dtag(4, 0x600300)); // hash
        dynamic.extend_from_slice(&dtag(11, 24)); // syment
        dynamic.extend_from_slice(&dtag(7, 0x600400)); // rela
        dynamic.extend_from_slice(&dtag(8, 24)); // relasz
        dynamic.extend_from_slice(&dtag(9, 24)); // relaent
        dynamic.extend_from_slice(&dtag(1, 1)); // needed offset=1 -> "libdep.so"
        dynamic.extend_from_slice(&dtag(0, 0)); // null
        buf[0x2000..0x2000 + dynamic.len()].copy_from_slice(&dynamic);
        // strtab @0x2100：空 + "libdep.so" + "func"
        buf[0x2100] = 0;
        buf[0x2101..0x210b].copy_from_slice(b"libdep.so\0");
        buf[0x210c..0x2111].copy_from_slice(b"func\0");
        // dynsym @0x2200：entry0 null，entry1 UNDEF "func"（index 1）
        buf[0x2218..0x221c].copy_from_slice(&12u32.to_le_bytes()); // st_name
        buf[0x221c] = 0x10; // st_info: STB_GLOBAL | STT_NOTYPE
        buf[0x221e..0x2220].copy_from_slice(&0u16.to_le_bytes()); // st_shndx=0 (UNDEF)
                                                                  // hash @0x2300：nbucket=1, nchain=2, bucket[0]=0, chain[0]=0, chain[1]=0
        buf[0x2300..0x2304].copy_from_slice(&1u32.to_le_bytes());
        buf[0x2304..0x2308].copy_from_slice(&2u32.to_le_bytes());
        buf[0x2308..0x230c].copy_from_slice(&0u32.to_le_bytes());
        buf[0x230c..0x2310].copy_from_slice(&0u32.to_le_bytes());
        buf[0x2310..0x2314].copy_from_slice(&0u32.to_le_bytes());
        // rela @0x2400：r_offset=0x600500, symbol=1, type=GLOB_DAT(6), addend=0
        buf[0x2400..0x2408].copy_from_slice(&0x600500u64.to_le_bytes());
        buf[0x2408..0x2410].copy_from_slice(&((1u64 << 32) | 6).to_le_bytes());
        buf
    }

    /// 依赖对象：dynsym 定义 "func"（st_value=0x400050, inline shndx=4），无重定位。
    fn build_dep_so() -> Vec<u8> {
        let mut buf = elf_header(0, 3);
        buf.extend_from_slice(&phdr(1, 5, 0, 0x400000, 0x1000, 0x1000, 0x1000));
        buf.extend_from_slice(&phdr(1, 6, 0x2000, 0x600000, 0x800, 0x800, 0x1000));
        buf.extend_from_slice(&phdr(2, 6, 0x2000, 0x600000, 0x80, 0x80, 8));
        buf.resize(0x2800, 0);
        // 5 个 DT_* 条目
        let mut dynamic = Vec::new();
        dynamic.extend_from_slice(&dtag(5, 0x600100));
        dynamic.extend_from_slice(&dtag(6, 0x600200));
        dynamic.extend_from_slice(&dtag(4, 0x600300));
        dynamic.extend_from_slice(&dtag(11, 24));
        dynamic.extend_from_slice(&dtag(0, 0));
        buf[0x2000..0x2000 + dynamic.len()].copy_from_slice(&dynamic);
        // strtab @0x2100：空 + "func"
        buf[0x2100] = 0;
        buf[0x2101..0x2106].copy_from_slice(b"func\0");
        // dynsym @0x2200：entry1 DEF "func"（index 1, st_value=0x400050, shndx=4）
        buf[0x2218..0x221c].copy_from_slice(&1u32.to_le_bytes());
        buf[0x221c] = 0x10;
        buf[0x221e..0x2220].copy_from_slice(&4u16.to_le_bytes()); // defined
        buf[0x2220..0x2228].copy_from_slice(&0x400050u64.to_le_bytes());
        // hash @0x2300：nbucket=1, nchain=2, chain[1]=1
        buf[0x2300..0x2304].copy_from_slice(&1u32.to_le_bytes());
        buf[0x2304..0x2308].copy_from_slice(&2u32.to_le_bytes());
        buf[0x230c..0x2310].copy_from_slice(&0u32.to_le_bytes());
        buf[0x2310..0x2314].copy_from_slice(&1u32.to_le_bytes());
        buf
    }

    /// 带临时目录的 fixture：写完文件后执行 body，随后清理。
    fn with_fixtures<T>(f: impl FnOnce(&Path) -> T) -> T {
        static NEXT_FIXTURE_ID: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("daoti_synth_{}_{}", std::process::id(), fixture_id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.so"), build_main_so()).unwrap();
        std::fs::write(dir.join("libdep.so"), build_dep_so()).unwrap();
        let out = f(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn build_missing_interp_so() -> Vec<u8> {
        let mut buf = build_dep_so();
        buf[56..58].copy_from_slice(&4u16.to_le_bytes());
        let phdr_offset = 64 + 3 * 56;
        buf[phdr_offset..phdr_offset + 56]
            .copy_from_slice(&phdr(3, 4, 0x2800, 0x600800, 16, 16, 1));
        buf.resize(0x2810, 0);
        buf[0x2800..0x280f].copy_from_slice(b"/missing-ld.so\0");
        buf
    }

    fn build_unknown_syscall_so() -> Vec<u8> {
        let mut buf = build_dep_so();
        buf[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
        // mov eax, 999; syscall; ret
        buf[0x100..0x109].copy_from_slice(&[0xb8, 0xe7, 0x03, 0, 0, 0x0f, 0x05, 0xc3, 0x90]);
        buf
    }

    #[test]
    fn test_execute_combined_reports_missing_pt_interp_parent() {
        with_fixtures(|dir| {
            std::fs::write(dir.join("missing-interp.so"), build_missing_interp_so()).unwrap();
            let loader = DynamicElfLoader::new(DummyResolver, 0x700000, 4096).unwrap();
            let error = loader
                .execute_combined(
                    &dir.join("missing-interp.so"),
                    std::slice::from_ref(&dir.to_path_buf()),
                )
                .unwrap_err();
            let message = format!("{error}");
            assert!(
                message.contains("PT_INTERP"),
                "错误必须包含 PT_INTERP：{message}"
            );
            assert!(
                message.contains("/missing-ld.so"),
                "错误必须包含解释器路径：{message}"
            );
        });
    }

    #[test]
    fn test_execute_combined_reports_missing_dt_needed_dependency_parent() {
        with_fixtures(|dir| {
            std::fs::remove_file(dir.join("libdep.so")).unwrap();
            let loader = DynamicElfLoader::new(DummyResolver, 0x700000, 4096).unwrap();
            let error = loader
                .execute_combined(
                    &dir.join("main.so"),
                    std::slice::from_ref(&dir.to_path_buf()),
                )
                .unwrap_err();
            let message = format!("{error}");
            assert!(
                message.contains("DT_NEEDED"),
                "错误必须包含 DT_NEEDED：{message}"
            );
            assert!(
                message.contains("libdep.so"),
                "错误必须包含依赖名：{message}"
            );
            assert!(message.contains("main.so"), "错误必须包含父对象：{message}");
        });
    }

    #[test]
    fn test_execute_combined_reports_unknown_syscall_number() {
        with_fixtures(|dir| {
            std::fs::write(dir.join("unknown-syscall.so"), build_unknown_syscall_so()).unwrap();
            let loader = DynamicElfLoader::new(DummyResolver, 0x700000, 4096).unwrap();
            let error = loader
                .execute_combined(
                    &dir.join("unknown-syscall.so"),
                    std::slice::from_ref(&dir.to_path_buf()),
                )
                .unwrap_err();
            let message = format!("{error}");
            assert!(
                message.contains("syscall"),
                "错误必须标识 syscall：{message}"
            );
            assert!(
                message.contains("999"),
                "错误必须包含未知 syscall 编号：{message}"
            );
        });
    }

    #[test]
    fn initializes_rtld_link_chain_without_ld_so_map_garbage() {
        // 模拟镜像残留垃圾值：_ns_loaded 残留 ld.so map 地址，
        // main_map.l_next 残留堆区垃圾。
        let mut memory = MemoryModel::new(0x1000, 0x36000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x35000],
            ))
            .unwrap();
        memory
            .write(0x1000 + 0x33a50, &0x1000u64.to_le_bytes())
            .unwrap();
        memory
            .write(0x2000 + 0x18, &0xdeadbeefu64.to_le_bytes())
            .unwrap();

        initialize_rtld_link_chain(&mut memory, 0x1000, 0x2000).unwrap();

        let read =
            |address| u64::from_le_bytes(memory.read(address, 8).unwrap().try_into().unwrap());
        // _ns_loaded 垃圾清零：dl_main 断言要求它最终 == main_map（链头）
        assert_eq!(read(0x1000 + 0x33a50), 0);
        // main_map.l_next 垃圾被清零：main_map 是链尾，断言要求 l_next == NULL
        assert_eq!(read(0x2000 + 0x18), 0);
    }

    #[test]
    fn keeps_ld_so_map_l_next_null_when_already_clean() {
        // 初始已是 NULL 时不应产生修正。
        let mut memory = MemoryModel::new(0x1000, 0x36000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x35000],
            ))
            .unwrap();
        initialize_rtld_link_chain(&mut memory, 0x1000, 0x2000).unwrap();
        assert_eq!(memory.read(0x1000 + 0x33a50, 8).unwrap(), [0u8; 8]);
        let read =
            |address| u64::from_le_bytes(memory.read(address, 8).unwrap().try_into().unwrap());
        assert_eq!(read(0x2000 + 0x18), 0);
    }

    #[test]
    fn initialize_main_link_map_initializes_main_object_fields() {
        let mut memory = MemoryModel::new(0x1000, 0x5000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x4000],
            ))
            .unwrap();
        let sentinel_main = 0x1111u64;
        let sentinel_namespace = 0x2222u64;
        memory.write(0x2000, &sentinel_main.to_le_bytes()).unwrap();
        memory
            .write(0x3800, &sentinel_namespace.to_le_bytes())
            .unwrap();

        initialize_main_link_map(
            &mut memory,
            0x2000,
            0x700000,
            0x700040,
            9,
            Some(0x3000),
            Some(0x3900),
            Some(0x3800),
        )
        .unwrap();

        let read =
            |address| u64::from_le_bytes(memory.read(address, 8).unwrap().try_into().unwrap());
        assert_eq!(read(0x2000), 0x700000, "主 map 的 l_addr 应为 load bias");
        assert_eq!(read(0x2010), 0x3000, "主 map 的 l_ld 应来自 DT_DYNAMIC");
        assert_eq!(read(0x2028), 0x2000, "主 map 的 l_real 应指向自身");
        assert_eq!(read(0x3800), sentinel_namespace, "不得预先写入 _ns_loaded");
    }

    #[test]
    fn test_execute_combined_reports_missing_main_elf_boundary() {
        let loader = DynamicElfLoader::new(DummyResolver, 0x700000, 4096).unwrap();
        let missing = std::env::temp_dir().join("daoti_missing_dynamic_fixture");
        let error = loader
            .execute_combined(&missing, std::slice::from_ref(&std::env::temp_dir()))
            .unwrap_err();
        assert!(
            format!("{error}").contains("读取主 ELF 失败"),
            "缺失主对象必须在实际执行入口处返回明确错误：{error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_combined_dynamic_merges_dependency_ptload_and_cross_object_reloc() {
        with_fixtures(|dir| {
            let allowed = vec![dir.to_path_buf()];
            let loader = DynamicElfLoader::new(DummyResolver, 0x700000, 4096).unwrap();
            let result = loader
                .load_combined_dynamic(dir.join("main.so").as_path(), &allowed)
                .unwrap();

            // 依赖图解析出真实 libdep.so
            assert_eq!(result.dependencies.len(), 1);
            let dep = &result.dependencies[0];
            assert_eq!(dep.path.file_name().unwrap(), "libdep.so");

            // 跨对象重定位：main 的 GLOB_DAT 被解析为 dep 定义 "func" 的已装载地址
            assert_eq!(result.relocations.len(), 1);
            let expected_func = dep.plan.load_bias + 0x400050;
            assert_eq!(
                result.relocations[0].value, expected_func,
                "跨对象符号 'func' 应解析到依赖的装载地址"
            );

            // 重定位结果写入主对象内存槽位
            let slot = result.plan.load_bias + 0x600500;
            let written = result
                .context
                .memory
                .read(slot, 8)
                .expect("重定位槽位应可读");
            assert_eq!(
                u64::from_le_bytes(written.try_into().unwrap()),
                expected_func,
                "内存槽位应写入跨对象解析结果"
            );

            // 主对象与依赖对象都有独立映射区域（可执行段计数）
            let reached = result.context.memory.regions.len();
            assert!(
                reached >= 5,
                "应有主对象PT_LOAD+依赖PT_LOAD+栈+TLS+堆共 5+ 区域，实际 {reached}"
            );

            // auxv/TLS/堆已布置
            assert!(result.context.tls_base > 0, "应布置 TLS/TCB 基址");
            assert!(result.context.heap_brk > 0, "应布置堆起始");
            assert!(result.context.heap_end > result.context.heap_brk);
            assert!(result.context.stack_ptr > 0);
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_real_hello_dynamic_uses_page_aligned_pt_load_ranges() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/runtime/hello_dynamic");
        let data = std::fs::read(&path).expect("真实 hello_dynamic fixture 应存在");
        let plan = plan_dynamic_load(&data, 0x400000).unwrap();
        assert!(plan.load_segments.iter().all(|segment| {
            segment.mapped_start % PAGE_SIZE == 0 && segment.mapped_end % PAGE_SIZE == 0
        }));
        let mut memory = MemoryModel::new(0x400000, 0x5000000);
        let info = parse_elf_from_bytes(&data).unwrap();
        map_dynamic_object(&mut memory, &data, &plan, &info)
            .expect("真实 ET_DYN 的 PT_LOAD 应能映射而不触发内存段越界");

        // hello_dynamic 使用真实 glibc 链接，通常只带 DT_GNU_HASH；验证 dynsym
        // 数量、strtab 地址和符号索引没有退化为“未解析动态符号：9”。
        let symbols = crate::elf::read_loaded_dynamic_symbols(&data, &plan)
            .expect("真实 hello_dynamic 的 GNU dynsym/strtab 应可读取");
        assert!(symbols
            .iter()
            .any(|symbol| symbol.name == "__libc_start_main"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_combined_dynamic_auxv_contains_entry() {
        with_fixtures(|dir| {
            let allowed = vec![dir.to_path_buf()];
            let loader = DynamicElfLoader::new(DummyResolver, 0x700000, 4096).unwrap();
            let result = loader
                .load_combined_dynamic(dir.join("main.so").as_path(), &allowed)
                .unwrap();
            let entry = result.plan.relocated_entry;
            let stack_data = result
                .context
                .memory
                .read(result.context.stack_ptr, 256)
                .unwrap();
            // auxv 区域在 argc/argv/envp 之后（约偏移 32 字节起），每对 16 字节
            let mut found = false;
            for i in (32..stack_data.len()).step_by(16) {
                if i + 16 <= stack_data.len() {
                    let tag = u64::from_le_bytes(stack_data[i..i + 8].try_into().unwrap());
                    let val = u64::from_le_bytes(stack_data[i + 8..i + 16].try_into().unwrap());
                    if tag == 9 && val == entry {
                        found = true;
                        break;
                    }
                }
            }
            assert!(found, "auxv 应包含 AT_ENTRY=0x{entry:x}");
        });
    }

    /// 真实动态 libc 门禁测试。
    ///
    /// 这是动态 libc 端到端装载的验收门禁：只有当环境中真实存在可读的动态 libc
    /// （如 Linux 的 libc.so.6/ld-linux 等受控根内对象）时才应通过。当前 Windows
    /// 环境往往不具备该 fixture，此时该测试会以明确的"环境阻断"信息失败——这是
    /// 可验证的失败，而非静默的假成功。启用方式：在提供真实 libc fixture 的环境
    /// 中取消 `#[ignore]` 并指定 `allowed_roots`。
    #[test]
    #[ignore = "验收门禁：需真实动态 libc fixture（当前 Windows 环境被阻断）；在有 libc.so.6/ld-linux 的 Linux 环境取消 ignore 后作为真实验收"]
    fn real_libc_fixture_acceptance_gate() {
        let candidates = [
            r"G:\Yl\fixtures\runtime\extract\lib\x86_64-linux-gnu\libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib64/ld-linux-x86-64.so.2",
        ];
        let root = candidates
            .iter()
            .find(|path| std::path::Path::new(path).is_file())
            .copied()
            .unwrap_or_else(|| {
                panic!(
                    "环境阻断：未找到真实动态 libc fixture（候选：{:?}）。\
                     无真实 libc 时无法验收动态装载端到端行为；已构建合成 fixture 验证 \
                     PT_LOAD 合并/跨对象 dynsym/重定位写入/auxv/TLS。",
                    candidates
                )
            });
        // 以实际存在的 libc 文件作为根对象尝试规划装载；此处即使解析失败也会暴露真实错误，
        // 而不会伪报成功。
        let data =
            std::fs::read(root).unwrap_or_else(|e| panic!("环境阻断：读取 libc fixture 失败：{e}"));
        let plan = plan_dynamic_load(&data, 0x700000)
            .unwrap_or_else(|e| panic!("环境阻断：libc fixture 无法规划装载：{e}"));
        assert!(
            plan.tls.is_some(),
            "libc fixture 规划结果应包含 PT_TLS 元数据"
        );
    }
}
