//! 纯逻辑 x86_64 动态重定位应用器。

use daoti_common::DaotiError;

use super::{runtime::MemoryModel, DynamicLoadPlan, RelocationEntry, X86_64RelocationType};

/// 动态符号解析接口；解析结果必须是已装载地址。
pub trait SymbolResolver {
    fn resolve(&self, symbol: u32) -> Option<u64>;

    fn resolve_name(&self, _name: &str) -> Option<u64> {
        None
    }

    fn resolve_with_name(&self, symbol: u32, name: Option<&str>) -> Option<u64> {
        name.and_then(|value| self.resolve_name(value))
            .or_else(|| self.resolve(symbol))
    }

    /// 符号所属对象的 TLS module ID（若该对象带 PT_TLS）。
    /// 用于 DTPMOD64 在缺少完整 TLS 上下文时仍能感知符号归属。
    fn tls_owner(&self, _name: &str) -> Option<u64> {
        None
    }
}

/// 单个 TLS 符号在其所属模块 TLS 块内的定位信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsSymbolLocation {
    /// 该符号所属模块的 TLS module ID（DTV 槽位下标）。
    pub module_id: u64,
    /// 该模块 TLS 块在本解释器 TLS 区中的运行时起始地址。
    pub block_start: u64,
    /// 符号相对 PT_TLS 起始的块内偏移（STT_TLS 符号的原始 st_value）。
    pub offset: u64,
}

/// 跨对象 TLS 上下文：装载期由 `install_tls_images` 与各对象 STT_TLS 符号构建，
/// 供 DTPMOD64/DTPOFF64/TPOFF64 重定位解析，以及 `__tls_get_addr` 的查找算法复用。
#[derive(Debug, Clone, Default)]
pub struct TlsContext {
    /// 线程指针（FS base / TLS 块布局基准地址）。
    pub tp: u64,
    /// 符号名 → TLS 定位信息。
    symbol_tls: std::collections::HashMap<String, TlsSymbolLocation>,
}

impl TlsContext {
    pub fn new(tp: u64) -> Self {
        Self {
            tp,
            symbol_tls: std::collections::HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: impl Into<String>, location: TlsSymbolLocation) {
        self.symbol_tls.entry(name.into()).or_insert(location);
    }

    pub fn resolve(&self, name: &str) -> Option<TlsSymbolLocation> {
        self.symbol_tls.get(name).copied()
    }

    /// `__tls_get_addr` 的纯查找算法：给定 module_id 与块内偏移，返回该 TLS
    /// 变量的运行时地址（block_start + offset）。找不到模块时返回 None。
    /// 执行循环中的功能型断点处理器（下一竖切）将直接复用此函数。
    pub fn get_addr(&self, module_id: u64, offset: i64) -> Option<u64> {
        let block_start = self
            .symbol_tls
            .values()
            .find(|loc| loc.module_id == module_id)
            .map(|loc| loc.block_start)?;
        if offset >= 0 {
            block_start.checked_add(offset as u64)
        } else {
            block_start.checked_sub(offset.unsigned_abs())
        }
    }
}

/// 已装载对象的动态符号索引，用于跨对象解析。
#[derive(Debug, Clone, Default)]
pub struct CrossObjectSymbolResolver {
    symbols: std::collections::HashMap<u32, u64>,
    names: std::collections::HashMap<String, u64>,
    /// 符号名 → 定义该符号的对象 TLS module ID（仅带 PT_TLS 的对象有值）。
    /// 与 `install_tls_images` 的模块编号规则一致：按对象顺序、只数带 PT_TLS 的对象，从 1 起。
    owners: std::collections::HashMap<String, u64>,
}

impl CrossObjectSymbolResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, symbol: u32, address: u64) {
        self.symbols.entry(symbol).or_insert(address);
    }

    pub fn insert_name(&mut self, name: impl Into<String>, address: u64) {
        self.names.entry(name.into()).or_insert(address);
    }

    /// 从一组对象（主对象 + 依赖）的动态符号表（DT_SYMTAB/DT_STRTAB）构建跨对象解析器。
    ///
    /// 仅收录"已定义"符号；先插入的对象（装载顺序靠前）优先解析同名符号。
    /// 同时记录每个符号所属对象的 TLS module ID（对象 `plan.tls` 存在时），
    /// 编号规则与 `install_tls_images` 严格一致，使解析器"感知符号所属对象"。
    pub fn from_objects(objects: &[(Vec<u8>, super::DynamicLoadPlan)]) -> Result<Self, DaotiError> {
        let mut resolver = Self::new();
        let mut next_module: u64 = 1;
        for (data, plan) in objects {
            let module_id = if plan.tls.is_some() {
                let id = next_module;
                next_module += 1;
                Some(id)
            } else {
                None
            };
            for symbol in super::read_loaded_dynamic_symbols(data, plan)? {
                if symbol.defined {
                    resolver.insert_name(symbol.name.clone(), symbol.loaded_address);
                    if let Some(id) = module_id {
                        resolver.owners.entry(symbol.name).or_insert(id);
                    }
                }
            }
        }
        Ok(resolver)
    }
}

impl SymbolResolver for CrossObjectSymbolResolver {
    fn resolve(&self, symbol: u32) -> Option<u64> {
        self.symbols.get(&symbol).copied()
    }

    fn resolve_name(&self, name: &str) -> Option<u64> {
        self.names.get(name).copied()
    }

    fn tls_owner(&self, name: &str) -> Option<u64> {
        self.owners.get(name).copied()
    }

    fn resolve_with_name(&self, symbol: u32, name: Option<&str>) -> Option<u64> {
        name.and_then(|value| self.resolve_name(value))
            .or_else(|| self.resolve(symbol))
    }
}

/// 已应用的一条重定位，便于调用方审计结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRelocation {
    pub offset: u64,
    pub address: u64,
    pub relocation_type: X86_64RelocationType,
    pub value: u64,
}

/// 对内存模型应用 RELATIVE/GLOB_DAT/JUMP_SLOT 重定位。
///
/// 仅修改模型中的 8 字节槽位，不执行代码，也不访问真实动态链接器。
/// 不含 TLS 上下文时，DTPMOD64/DTPOFF64/TPOFF64 走"可解析则填、否则跳过"的安全路径。
pub fn apply_x86_64_relocations<R: SymbolResolver>(
    memory: &mut MemoryModel,
    plan: &DynamicLoadPlan,
    entries: &[RelocationEntry],
    resolver: &R,
) -> Result<Vec<AppliedRelocation>, DaotiError> {
    apply_x86_64_relocations_with_tls(memory, plan, entries, resolver, None)
}

/// 同 [`apply_x86_64_relocations`]，但额外提供跨对象 TLS 上下文，
/// 用于把 DTPMOD64/DTPOFF64/TPOFF64 解析为真实 TLS 槽值。
pub fn apply_x86_64_relocations_with_tls<R: SymbolResolver>(
    memory: &mut MemoryModel,
    plan: &DynamicLoadPlan,
    entries: &[RelocationEntry],
    resolver: &R,
    tls: Option<&TlsContext>,
) -> Result<Vec<AppliedRelocation>, DaotiError> {
    let mut applied = Vec::with_capacity(entries.len());
    for entry in entries {
        let address = entry
            .offset
            .checked_add(plan.load_bias)
            .ok_or_else(|| DaotiError::Other("重定位目标地址溢出".into()))?;
        let value = match entry.relocation_type {
            X86_64RelocationType::Relative => add_signed(
                plan.load_bias,
                entry
                    .addend
                    .unwrap_or_else(|| read_u64(memory, address).unwrap_or(0) as i64),
            )?,
            // IRELATIVE 的槽位先写入 resolver 地址；由运行时在映射完成后调用 resolver，
            // 不能把 resolver 地址误当成最终函数地址。
            X86_64RelocationType::IRelative => add_signed(
                plan.load_bias,
                entry
                    .addend
                    .ok_or_else(|| DaotiError::Other("IRELATIVE 缺少 addend".into()))?,
            )?,
            // DTPMOD64：GOT 槽写入符号所属模块的 TLS module ID（__tls_get_addr 的第一参数）。
            X86_64RelocationType::DtpMod64 => match tls
                .zip(entry.symbol_name.as_deref())
                .and_then(|(ctx, name)| ctx.resolve(name))
            {
                Some(loc) => loc.module_id,
                // TLS 上下文未收录时，退化为解析器的"符号所属对象"感知：
                // 只要符号定义在带 PT_TLS 的对象里，其 module ID 即可确定。
                None => entry
                    .symbol_name
                    .as_deref()
                    .and_then(|name| resolver.tls_owner(name))
                    // 真实 libc 的动态 TLS 若两者都缺失，交由运行时
                    // __tls_get_addr 处理，装载期保持槽位原值（跳过），不报错。
                    .unwrap_or_else(|| read_u64(memory, address).unwrap_or(0)),
            },
            // DTPOFF64：GOT 槽写入符号相对模块 TLS 块的偏移（__tls_get_addr 的第二参数）。
            X86_64RelocationType::DtpOff64 => match tls
                .zip(entry.symbol_name.as_deref())
                .and_then(|(ctx, name)| ctx.resolve(name))
            {
                Some(loc) => add_signed(loc.offset, entry.addend.unwrap_or(0))?,
                None => entry
                    .addend
                    .map(|addend| add_signed(0, addend))
                    .transpose()?
                    .unwrap_or_else(|| read_u64(memory, address).unwrap_or(0)),
            },
            // TPOFF64（local-exec）：GOT 槽写入 (块起始 + 偏移 + addend - TP)，
            // 运行时 fs:[got] 即得变量地址。本解释器 TLS 块位于 TP 之上，故为正值。
            X86_64RelocationType::TpOff64 => match tls
                .zip(entry.symbol_name.as_deref())
                .and_then(|(ctx, name)| ctx.resolve(name))
            {
                Some(loc) => {
                    let var_addr = add_signed(
                        loc.block_start
                            .checked_add(loc.offset)
                            .ok_or_else(|| DaotiError::Other("TLS 变量地址溢出".into()))?,
                        entry.addend.unwrap_or(0),
                    )?;
                    var_addr
                        .checked_sub(tls.map(|ctx| ctx.tp).unwrap_or(0))
                        .ok_or_else(|| DaotiError::Other("TPOFF64 相对 TP 下溢".into()))?
                }
                None => entry
                    .addend
                    .map(|addend| add_signed(0, addend))
                    .transpose()?
                    .unwrap_or_else(|| read_u64(memory, address).unwrap_or(0)),
            },
            X86_64RelocationType::GlobDat
            | X86_64RelocationType::JumpSlot
            | X86_64RelocationType::Type64 => {
                if entry.symbol == 0 {
                    entry
                        .addend
                        .map(|addend| add_signed(0, addend))
                        .transpose()?
                        .unwrap_or_else(|| read_u64(memory, address).unwrap_or(0))
                } else {
                    let symbol = resolver
                        .resolve_with_name(entry.symbol, entry.symbol_name.as_deref())
                        .or_else(|| {
                            entry
                                .symbol_name
                                .as_deref()
                                .filter(|name| {
                                    matches!(
                                        *name,
                                        "_ITM_deregisterTMCloneTable"
                                            | "_ITM_registerTMCloneTable"
                                            | "__gmon_start__"
                                    )
                                })
                                .map(|_| 0)
                        })
                        .ok_or_else(|| {
                            DaotiError::Other(format!(
                                "未解析动态符号：{} ({})",
                                entry.symbol,
                                entry.symbol_name.as_deref().unwrap_or("<无名称>"),
                            ))
                        })?;
                    add_signed(
                        symbol,
                        entry
                            .addend
                            .unwrap_or_else(|| read_u64(memory, address).unwrap_or(0) as i64),
                    )?
                }
            }
            X86_64RelocationType::Copy => {
                let symbol = resolver
                    .resolve_with_name(entry.symbol, entry.symbol_name.as_deref())
                    .ok_or_else(|| {
                        DaotiError::Other(format!(
                            "未解析动态符号：{} ({})",
                            entry.symbol,
                            entry.symbol_name.as_deref().unwrap_or("<无名称>"),
                        ))
                    })?;
                let size = entry.symbol_size.max(1) as usize;
                let src = memory.read(symbol, size as u64).map_err(|_| {
                    DaotiError::Other(format!("COPY 重定位源地址读取失败：0x{symbol:x}"))
                })?;
                let src_copy = src.to_vec();
                memory.write(address, &src_copy)?;
                u64::from_le_bytes(src_copy[..size.min(8)].try_into().unwrap_or([0u8; 8]))
            }
            X86_64RelocationType::None => continue,
            _ => {
                return Err(DaotiError::Unavailable(format!(
                    "不支持的 x86_64 重定位类型：{:?}",
                    entry.relocation_type
                )))
            }
        };
        memory.write(address, &value.to_le_bytes())?;
        applied.push(AppliedRelocation {
            offset: entry.offset,
            address,
            relocation_type: entry.relocation_type,
            value,
        });
    }
    Ok(applied)
}

fn add_signed(base: u64, addend: i64) -> Result<u64, DaotiError> {
    if addend >= 0 {
        base.checked_add(addend as u64)
    } else {
        base.checked_sub(addend.unsigned_abs())
    }
    .ok_or_else(|| DaotiError::Other("符号重定位值溢出".into()))
}

fn read_u64(memory: &MemoryModel, address: u64) -> Result<u64, DaotiError> {
    Ok(u64::from_le_bytes(
        memory.read(address, 8)?.try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::runtime::{MemPerm, MemoryRegion};

    struct Resolver;
    impl SymbolResolver for Resolver {
        fn resolve(&self, symbol: u32) -> Option<u64> {
            (symbol == 7).then_some(0x9000)
        }
    }
    fn plan(bias: u64) -> DynamicLoadPlan {
        DynamicLoadPlan {
            load_bias: bias,
            relocated_entry: 0,
            load_segments: vec![],
            tls: None,
            dependency_graph: vec![],
            interpreter: None,
            entries: vec![],
            needed: vec![],
            strtab: None,
            symtab: None,
            rela: None,
            rel: None,
            relr: None,
            jmprel: None,
        }
    }
    fn entry(
        offset: u64,
        symbol: u32,
        kind: X86_64RelocationType,
        addend: Option<i64>,
    ) -> RelocationEntry {
        RelocationEntry {
            offset,
            info: 0,
            addend,
            symbol,
            symbol_name: None,
            symbol_size: 0,
            relocation_type: kind,
        }
    }

    fn named_entry(
        offset: u64,
        symbol: u32,
        name: &str,
        kind: X86_64RelocationType,
        addend: Option<i64>,
    ) -> RelocationEntry {
        RelocationEntry {
            symbol_name: Some(name.to_string()),
            ..entry(offset, symbol, kind, addend)
        }
    }

    fn tls_context() -> TlsContext {
        let mut ctx = TlsContext::new(0x1000);
        ctx.insert(
            "tls_var",
            TlsSymbolLocation {
                module_id: 2,
                block_start: 0x1800,
                offset: 0x10,
            },
        );
        ctx
    }

    #[test]
    fn applies_relative_and_symbol_relocations() {
        let mut memory = MemoryModel::new(0x4000, 0xa000);
        memory
            .add_region(MemoryRegion::with_data(
                0x5000,
                MemPerm::rw(),
                vec![0; 0x20],
            ))
            .unwrap();
        let result = apply_x86_64_relocations(
            &mut memory,
            &plan(0x4000),
            &[
                entry(0x1000, 0, X86_64RelocationType::Relative, Some(0x20)),
                entry(0x1008, 7, X86_64RelocationType::GlobDat, Some(-0x10)),
            ],
            &Resolver,
        )
        .unwrap();
        assert_eq!(result[0].value, 0x4020);
        assert_eq!(result[1].value, 0x8ff0);
    }

    #[test]
    fn rejects_missing_symbol_and_out_of_bounds() {
        let mut memory = MemoryModel::new(0x4000, 0xa000);
        memory
            .add_region(MemoryRegion::with_data(0x5000, MemPerm::rw(), vec![0; 8]))
            .unwrap();
        let missing = apply_x86_64_relocations(
            &mut memory,
            &plan(0x4000),
            &[entry(0x1000, 8, X86_64RelocationType::JumpSlot, Some(0))],
            &Resolver,
        )
        .unwrap_err();
        assert!(format!("{missing}").contains("未解析"));
        let bounds = apply_x86_64_relocations(
            &mut memory,
            &plan(0x4000),
            &[entry(0x2000, 7, X86_64RelocationType::GlobDat, Some(0))],
            &Resolver,
        )
        .unwrap_err();
        assert!(format!("{bounds}").contains("地址不可访问"));
    }

    #[test]
    fn applies_tls_relocations_with_context() {
        let mut memory = MemoryModel::new(0x4000, 0xa000);
        memory
            .add_region(MemoryRegion::with_data(
                0x5000,
                MemPerm::rw(),
                vec![0; 0x20],
            ))
            .unwrap();
        let result = apply_x86_64_relocations_with_tls(
            &mut memory,
            &plan(0x4000),
            &[
                named_entry(
                    0x1000,
                    3,
                    "tls_var",
                    X86_64RelocationType::DtpMod64,
                    Some(0),
                ),
                named_entry(
                    0x1008,
                    3,
                    "tls_var",
                    X86_64RelocationType::DtpOff64,
                    Some(0x8),
                ),
                named_entry(0x1010, 3, "tls_var", X86_64RelocationType::TpOff64, Some(0)),
            ],
            &Resolver,
            Some(&tls_context()),
        )
        .unwrap();
        // DTPMOD64 → module_id=2；DTPOFF64 → offset(0x10)+addend(0x8)=0x18；
        // TPOFF64 → block_start(0x1800)+offset(0x10)-tp(0x1000)=0x810。
        assert_eq!(result[0].value, 2);
        assert_eq!(result[1].value, 0x18);
        assert_eq!(result[2].value, 0x810);
        // 槽位应真实写回内存。
        assert_eq!(
            u64::from_le_bytes(memory.read(0x5000, 8).unwrap().try_into().unwrap()),
            2
        );
    }

    #[test]
    fn tls_relocations_without_context_are_skipped_not_fatal() {
        let mut memory = MemoryModel::new(0x4000, 0xa000);
        memory
            .add_region(MemoryRegion::with_data(
                0x5000,
                MemPerm::rw(),
                vec![0; 0x20],
            ))
            .unwrap();
        // 无 TLS 上下文时，DTPMOD64/DTPOFF64/TPOFF64 不得报"不支持"，
        // 而是保持槽位原值（真实 libc 的动态 TLS 交由运行时 __tls_get_addr）。
        let result = apply_x86_64_relocations(
            &mut memory,
            &plan(0x4000),
            &[
                named_entry(
                    0x1000,
                    3,
                    "tls_var",
                    X86_64RelocationType::DtpMod64,
                    Some(0),
                ),
                named_entry(
                    0x1008,
                    3,
                    "tls_var",
                    X86_64RelocationType::DtpOff64,
                    Some(0x8),
                ),
            ],
            &Resolver,
        )
        .unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn tls_context_get_addr_resolves_module_and_offset() {
        let ctx = tls_context();
        // __tls_get_addr 查找算法：block_start(0x1800) + offset(0x10) = 0x1810。
        assert_eq!(ctx.get_addr(2, 0x10), Some(0x1810));
        // 未知 module_id 返回 None。
        assert_eq!(ctx.get_addr(9, 0x0), None);
        // 负偏移沿用 checked_sub，避免地址下溢。
        assert_eq!(ctx.get_addr(2, -0x10), Some(0x17f0));
        assert_eq!(ctx.get_addr(2, -0x2000), None);
    }

    #[test]
    fn dtpmod64_falls_back_to_resolver_symbol_ownership() {
        // 跨对象解析器感知符号所属对象：即便缺少完整 TLS 上下文，
        // 只要符号定义在带 PT_TLS 的对象里，DTPMOD64 仍能解析出 module ID。
        struct OwnerResolver;
        impl SymbolResolver for OwnerResolver {
            fn resolve(&self, _symbol: u32) -> Option<u64> {
                None
            }
            fn tls_owner(&self, name: &str) -> Option<u64> {
                (name == "tls_var").then_some(3)
            }
        }
        let mut memory = MemoryModel::new(0x4000, 0xa000);
        memory
            .add_region(MemoryRegion::with_data(
                0x5000,
                MemPerm::rw(),
                vec![0; 0x20],
            ))
            .unwrap();
        let result = apply_x86_64_relocations_with_tls(
            &mut memory,
            &plan(0x4000),
            &[named_entry(
                0x1000,
                3,
                "tls_var",
                X86_64RelocationType::DtpMod64,
                Some(0),
            )],
            &OwnerResolver,
            None,
        )
        .unwrap();
        assert_eq!(result[0].value, 3);
    }

    #[test]
    fn cross_object_resolver_tracks_symbol_ownership() {
        let mut resolver = CrossObjectSymbolResolver::new();
        resolver.insert_name("tls_var", 0x9000);
        resolver.owners.insert("tls_var".to_string(), 2);
        assert_eq!(resolver.tls_owner("tls_var"), Some(2));
        assert_eq!(resolver.tls_owner("other"), None);
    }

    #[test]
    fn rejects_unsupported_relocation_type() {
        // 未知重定位类型（如 ABI 保留值 42）必须显式报错，
        // 不得静默跳过或错误应用，确保不支持的类型不会被假装成功。
        let mut memory = MemoryModel::new(0x4000, 0xa000);
        memory
            .add_region(MemoryRegion::with_data(
                0x5000,
                MemPerm::rw(),
                vec![0; 0x20],
            ))
            .unwrap();
        let unsupported = entry(0x1000, 7, X86_64RelocationType::Unknown(42), Some(0));
        let error = apply_x86_64_relocations(&mut memory, &plan(0x4000), &[unsupported], &Resolver)
            .unwrap_err();
        let message = format!("{error}");
        assert!(
            message.contains("不支持的 x86_64 重定位类型"),
            "错误必须标识不支持的类型：{message}"
        );
        // 报错后目标槽位不得被写入，保持原值。
        assert_eq!(memory.read(0x5000, 8).unwrap(), [0u8; 8]);
    }
}
