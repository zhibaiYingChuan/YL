//! Unix/glibc 动态执行知识样本与受控状态应用。
//!
//! 该模块负责知识样本的边界校验和候选字段写入，不宣称替代 glibc
//! 自身初始化，也不允许未经验证的模型输出直接覆盖解释器内存。

use crate::bilateral::network::BilateralLadderNetwork;
use crate::elf::runtime::{MainMapSourceEvidence, MemoryModel};
use daoti_common::DaotiError;
use ndarray::Array1;
use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::path::Path;

pub const KNOWLEDGE_VECTOR_DIM: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructFieldFact {
    pub structure: String,
    pub field: String,
    pub c_type: String,
    pub ordinal: usize,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowRuleFact {
    pub function: String,
    pub rule: String,
    pub source: String,
}

/// 从 glibc C 源码中提取结构字段和 dl_main 关键规则。
pub fn extract_glibc_source_facts(
    source: &str,
    source_name: &str,
) -> (Vec<StructFieldFact>, Vec<FlowRuleFact>) {
    let mut structures = Vec::new();
    let mut current = None;
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("struct ") {
            if rest.ends_with('{') {
                current = Some(rest.trim_end_matches('{').trim().to_string());
                continue;
            }
        }
        if trimmed == "};" {
            current = None;
            continue;
        }
        if let Some(structure) = current.as_ref() {
            let declaration = trimmed.trim_end_matches(';');
            let parts: Vec<_> = declaration.split_whitespace().collect();
            if parts.len() >= 2 && !declaration.contains('(') && !declaration.starts_with("/*") {
                let field = parts.last().unwrap().trim_matches('*').to_string();
                let c_type = parts[..parts.len() - 1].join(" ");
                if field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    let ordinal = structures
                        .iter()
                        .filter(|fact: &&StructFieldFact| fact.structure == *structure)
                        .count();
                    structures.push(StructFieldFact {
                        structure: structure.clone(),
                        field,
                        c_type,
                        ordinal,
                        source: source_name.into(),
                    });
                }
            }
        }
    }
    let mut rules = Vec::new();
    for line in source.lines().map(str::trim) {
        if line.contains("main_map = GL(dl_ns)[LM_ID_BASE]._ns_loaded")
            || line.contains("_dl_add_to_namespace_list")
            || line.contains("rtld_setup_main_map")
            || line.contains("init_tls")
            || line.contains("_dl_relocate_object")
        {
            rules.push(FlowRuleFact {
                function: "dl_main".into(),
                rule: line.into(),
                source: source_name.into(),
            });
        }
    }
    (structures, rules)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEvidence {
    pub context: String,
    pub facts: Vec<String>,
}

/// 从真实运行日志中提取可审计事实，不把日志直接当作“正确状态”。
pub fn extract_debug_log_evidence(log: &str) -> Vec<ExtractedEvidence> {
    let mut evidence = Vec::new();
    for line in log.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let context = if line.contains("init-ldso-alloc") {
            "ldso_allocator_init"
        } else if line.contains("_rtld_global") || line.contains("rtld-global") {
            "rtld_global_observation"
        } else if line.contains("syscall") {
            "runtime_syscall_observation"
        } else if line.contains("Inconsistency detected") || line.contains("Assertion") {
            "glibc_failure_observation"
        } else if line.contains("动态 ELF 内存访问失败") {
            "runtime_memory_fault"
        } else {
            continue;
        };
        evidence.push(ExtractedEvidence {
            context: context.into(),
            facts: vec![line.into()],
        });
    }
    evidence
}

/// 将真实日志事实编码为可复现的稀疏输入向量；该编码不是神经网络训练结果。
pub fn evidence_to_sample(evidence: &ExtractedEvidence) -> GlibcKnowledgeSample {
    let text = format!("{}\\n{}", evidence.context, evidence.facts.join("\\n"));
    let mut input = vec![0.0; KNOWLEDGE_VECTOR_DIM];
    for (index, byte) in text.bytes().enumerate() {
        let slot = (index * 131 + byte as usize) % KNOWLEDGE_VECTOR_DIM;
        input[slot] += (byte as f64 / 255.0).min(1.0);
    }
    let mut output = vec![0.0; KNOWLEDGE_VECTOR_DIM];
    for (index, value) in input.iter().enumerate() {
        output[index] = value.tanh();
    }
    let target_fields = match evidence.context.as_str() {
        "rtld_global_observation" => {
            vec!["_dl_rtld_map.l_addr".into(), "_dl_rtld_map.l_next".into()]
        }
        "glibc_failure_observation" => vec!["_ns_loaded".into(), "_dl_rtld_map.l_next".into()],
        "main_map_source_observation" => vec![
            "source.main_map.rbp".into(),
            "source.main_map.rsp_slot".into(),
            "source.main_map.register".into(),
            "source.main_map.link_map_l_next".into(),
        ],
        "runtime_memory_fault" => vec!["_dl_rtld_map.l_addr".into()],
        _ => Vec::new(),
    };
    GlibcKnowledgeSample {
        context: evidence.context.clone(),
        input_vector: input,
        output_vector: output,
        source: KnowledgeSource::DebugLog,
        target_fields,
        evidence_url: String::new(),
        evidence_confidence: 0.5,
    }
}

pub fn extract_debug_log_samples(log: &str) -> Vec<GlibcKnowledgeSample> {
    extract_debug_log_evidence(log)
        .iter()
        .map(evidence_to_sample)
        .collect()
}

/// 将断言前的 main_map 来源证据编码为训练样本；该样本只描述来源，不申请写入状态。
pub fn source_evidence_to_training_sample(
    evidence: &MainMapSourceEvidence,
) -> GlibcKnowledgeSample {
    let mut sample = main_map_source_sample(evidence);
    sample.context = "main_map_source_supervised".into();
    sample.output_vector.fill(0.0);
    for field in &sample.target_fields {
        let value = match field.as_str() {
            "source.main_map.rbp" if Some(evidence.rbp) == evidence.ns_loaded => 1.0,
            "source.main_map.rsp_slot"
                if evidence.rsp_slot.is_some() && evidence.rsp_slot == evidence.ns_loaded =>
            {
                1.0
            }
            "source.main_map.register"
                if evidence.rdi_value == evidence.ns_loaded
                    || evidence.rax_l_next == evidence.ns_loaded =>
            {
                0.5
            }
            "source.main_map.link_map_l_next" if evidence.rax_l_next == evidence.ns_loaded => 1.0,
            _ => 0.0,
        };
        sample.output_vector[field_label_index(field)] = value;
    }
    sample.evidence_confidence = if Some(evidence.rbp) == evidence.ns_loaded {
        0.8
    } else {
        0.4
    };
    sample
}

pub fn main_map_source_sample(evidence: &MainMapSourceEvidence) -> GlibcKnowledgeSample {
    let facts = format!(
        "rip=0x{:x};rbp=0x{:x};rsp=0x{:x};rax=0x{:x};rdi=0x{:x};rbp_slot={:?};rsp_slot={:?};rax_l_next={:?};rdi_value={:?};ns_loaded={:?}",
        evidence.rip,
        evidence.rbp,
        evidence.rsp,
        evidence.rax,
        evidence.rdi,
        evidence.rbp_slot,
        evidence.rsp_slot,
        evidence.rax_l_next,
        evidence.rdi_value,
        evidence.ns_loaded,
    );
    let sample = evidence_to_sample(&ExtractedEvidence {
        context: "main_map_source_observation".into(),
        facts: vec![facts],
    });
    GlibcKnowledgeSample {
        evidence_confidence: if Some(evidence.rbp) == evidence.ns_loaded {
            0.8
        } else {
            0.4
        },
        ..sample
    }
}

/// 使用现有双梯形网络生成候选状态；输出必须经过调用方字段校验后才能应用。
pub fn infer_candidate_state(
    network: &BilateralLadderNetwork,
    sample: &GlibcKnowledgeSample,
) -> Result<Array1<f64>, DaotiError> {
    network.forward(sample.input_array()?)
}

pub fn public_runtime_knowledge_samples() -> Vec<GlibcKnowledgeSample> {
    let evidence = ExtractedEvidence {
        context: "public_gdb_rtld_global".into(),
        facts: vec![
            "Fedora 38 GDB: _ns_loaded is non-null".into(),
            "Fedora 38 GDB: _ns_nloaded is 4".into(),
            "Fedora 38 GDB: _ns_main_searchlist is non-null".into(),
        ],
    };
    let mut sample = evidence_to_sample(&evidence);
    sample.source = KnowledgeSource::GdbSnapshot;
    sample.target_fields = vec![
        "_ns_loaded".into(),
        "link_map.l_next".into(),
        "link_map.l_prev".into(),
    ];
    sample.evidence_url = "https://github.com/crisprss/windows-vs-linux-loader-architecture/blob/main/load-library/gdb-log.html".into();
    sample.evidence_confidence = 0.7;
    vec![sample]
}

pub fn official_knowledge_samples() -> Vec<GlibcKnowledgeSample> {
    // 官方资料按动态执行域拆分，避免只训练 namespace 的局部知识。
    let facts = [
        (
            "glibc_source",
            "dl_main creates main_map then reads namespace loaded map",
        ),
        (
            "glibc_source",
            "link_map l_addr is load bias and l_next/l_prev form a chain",
        ),
        (
            "glibc_source",
            "dynamic linker initializes TLS before final relocations",
        ),
        (
            "glibc_source",
            "_r_debug publishes the loaded object chain and debugger state",
        ),
        (
            "glibc_source",
            "dependency objects are mapped before relocation and symbol lookup",
        ),
        (
            "glibc_source",
            "dynamic linker performs early self relocation before libc setup",
        ),
        (
            "glibc_source",
            "link map search lists control global and local symbol scopes",
        ),
        (
            "glibc_source",
            "symbol version requirements are checked during dependency loading",
        ),
        (
            "glibc_source",
            "constructors and init arrays run after relocation completion",
        ),
        ("linux_kernel", "PT_INTERP selects the program interpreter"),
        (
            "linux_kernel",
            "PT_LOAD segments define mapped file and zero-filled memory ranges",
        ),
        (
            "linux_kernel",
            "PT_GNU_STACK controls initial stack executability",
        ),
        (
            "linux_kernel",
            "AT_PHDR AT_PHNUM AT_ENTRY AT_BASE describe process startup",
        ),
        (
            "linux_kernel",
            "FS base is used for x86-64 thread local storage",
        ),
        ("elf_abi", "R_X86_64_RELATIVE writes load bias plus addend"),
        (
            "elf_abi",
            "R_X86_64_GLOB_DAT resolves a data symbol into a GOT slot",
        ),
        ("elf_abi", "R_X86_64_JUMP_SLOT resolves a PLT call target"),
        ("elf_abi", "DT_NEEDED entries form the dependency graph"),
        (
            "elf_abi",
            "DT_RELA DT_SYMTAB DT_STRTAB describe relocation and symbol tables",
        ),
        (
            "elf_abi",
            "GNU symbol version tables constrain compatible definitions",
        ),
        (
            "glibc_source",
            "link_map l_info is an inline DT_* slot array at map+0x40; map+0x68 is the DT_STRTAB slot and the loader keeps it read-only",
        ),
    ];
    facts
        .iter()
        .map(|(source, fact)| {
            let evidence = ExtractedEvidence {
                context: (*source).into(),
                facts: vec![(*fact).into()],
            };
            let mut sample = evidence_to_sample(&evidence);
            sample.target_fields = match *fact {
                "dl_main creates main_map then reads namespace loaded map" => {
                    vec!["_ns_loaded".into()]
                }
                "link_map l_addr is load bias and l_next/l_prev form a chain" => vec![
                    "_dl_rtld_map.l_addr".into(),
                    "_dl_rtld_map.l_next".into(),
                    "_dl_rtld_map.l_prev".into(),
                ],
                "dynamic linker initializes TLS before final relocations" => {
                    vec!["tls.fs_base".into()]
                }
                "_r_debug publishes the loaded object chain and debugger state" => {
                    vec!["r_debug.r_map".into(), "r_debug.r_state".into()]
                }
                "dependency objects are mapped before relocation and symbol lookup" => {
                    vec!["namespace.loaded_count".into(), "link_map.l_scope".into()]
                }
                "dynamic linker performs early self relocation before libc setup" => {
                    vec!["relocation.relative".into()]
                }
                "link map search lists control global and local symbol scopes" => {
                    vec!["link_map.l_searchlist".into()]
                }
                "symbol version requirements are checked during dependency loading" => {
                    vec!["symbol.version".into()]
                }
                "constructors and init arrays run after relocation completion" => {
                    vec!["init_array".into()]
                }
                "PT_INTERP selects the program interpreter" => vec!["auxv.AT_BASE".into()],
                "PT_LOAD segments define mapped file and zero-filled memory ranges" => {
                    vec!["program_header.PT_LOAD".into()]
                }
                "PT_GNU_STACK controls initial stack executability" => {
                    vec!["program_header.PT_GNU_STACK".into()]
                }
                "AT_PHDR AT_PHNUM AT_ENTRY AT_BASE describe process startup" => vec![
                    "auxv.AT_PHDR".into(),
                    "auxv.AT_PHNUM".into(),
                    "auxv.AT_ENTRY".into(),
                    "auxv.AT_BASE".into(),
                ],
                "FS base is used for x86-64 thread local storage" => vec!["tls.fs_base".into()],
                "R_X86_64_RELATIVE writes load bias plus addend" => {
                    vec!["relocation.relative".into()]
                }
                "R_X86_64_GLOB_DAT resolves a data symbol into a GOT slot" => {
                    vec!["relocation.glob_dat".into()]
                }
                "R_X86_64_JUMP_SLOT resolves a PLT call target" => {
                    vec!["relocation.jump_slot".into()]
                }
                "DT_NEEDED entries form the dependency graph" => vec!["dynamic.DT_NEEDED".into()],
                "DT_RELA DT_SYMTAB DT_STRTAB describe relocation and symbol tables" => vec![
                    "dynamic.DT_RELA".into(),
                    "dynamic.DT_SYMTAB".into(),
                    "dynamic.DT_STRTAB".into(),
                ],
                "GNU symbol version tables constrain compatible definitions" => {
                    vec!["symbol.version".into()]
                }
                "link_map l_info is an inline DT_* slot array at map+0x40; map+0x68 is the DT_STRTAB slot and the loader keeps it read-only" => {
                    vec!["link_map.l_info".into()]
                }
                _ => Vec::new(),
            };
            sample.source = match *source {
                "glibc_source" => KnowledgeSource::GlibcSource,
                "linux_kernel" => KnowledgeSource::LinuxKernel,
                "elf_abi" => KnowledgeSource::ElfAbi,
                _ => KnowledgeSource::DebugLog,
            };
            sample.evidence_url = match *source {
                "glibc_source" => "https://github.com/bminor/glibc/blob/master/elf/rtld.c",
                "linux_kernel" => "https://docs.kernel.org/next/ELF/ELF.html",
                "elf_abi" => "https://bx.github.io/rtld-debugging/slides/slides-published.html",
                _ => "",
            }
            .into();
            sample.evidence_confidence = if *source == "glibc_source" { 0.95 } else { 0.8 };
            sample
        })
        .collect()
}

pub fn field_label_index(field: &str) -> usize {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in field.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize) % KNOWLEDGE_VECTOR_DIM
}

pub fn fine_tune_glibc_network_weights(
    initial: &crate::bilateral::weights::BilateralWeights,
    samples: &[GlibcKnowledgeSample],
    epochs: usize,
    learning_rate: f64,
) -> Result<crate::bilateral::weights::BilateralWeights, DaotiError> {
    if samples.is_empty() || samples.iter().any(|sample| sample.validate().is_err()) {
        return Err(DaotiError::ModelCorrupt("来源微调样本为空或非法".into()));
    }
    if initial.dim != KNOWLEDGE_VECTOR_DIM
        || initial.ascent.len() != KNOWLEDGE_VECTOR_DIM * KNOWLEDGE_VECTOR_DIM
        || initial.descent.len() != KNOWLEDGE_VECTOR_DIM * KNOWLEDGE_VECTOR_DIM
        || initial.bias.len() != KNOWLEDGE_VECTOR_DIM
    {
        return Err(DaotiError::ModelCorrupt("来源微调初始权重维度错误".into()));
    }
    if !learning_rate.is_finite() || learning_rate <= 0.0 {
        return Err(DaotiError::ModelCorrupt("来源微调学习率非法".into()));
    }
    let mut weights = initial.clone();
    let mut last_loss = f64::INFINITY;
    for _ in 0..epochs.max(1) {
        let network = bilateral_network_from_weights(&weights)?;
        let mut loss = 0.0;
        for sample in samples {
            let input = sample.input_array()?;
            let prediction = network.forward(input.clone())?;
            for field in &sample.target_fields {
                let index = field_label_index(field);
                let target = sample.output_vector[index];
                let error = target - prediction[index];
                loss += error * error;
                // 误差反馈更新：同时调整来源输出偏置和对应输入通道的对角权重。
                weights.bias[index] += learning_rate * error;
                weights.ascent[index * KNOWLEDGE_VECTOR_DIM + index] +=
                    learning_rate * error * input[index];
            }
        }
        last_loss = loss / samples.len().max(1) as f64;
        if last_loss < 1e-4 {
            break;
        }
    }
    if !last_loss.is_finite() {
        return Err(DaotiError::InferenceFailed("来源微调损失非法".into()));
    }
    Ok(weights)
}

fn bilateral_network_from_weights(
    weights: &crate::bilateral::weights::BilateralWeights,
) -> Result<BilateralLadderNetwork, DaotiError> {
    let ascent =
        ndarray::Array2::from_shape_vec((weights.dim, weights.dim), weights.ascent.clone())
            .map_err(|error| {
                DaotiError::ModelCorrupt(format!("来源微调上梯形维度错误：{error}"))
            })?;
    let descent =
        ndarray::Array2::from_shape_vec((weights.dim, weights.dim), weights.descent.clone())
            .map_err(|error| {
                DaotiError::ModelCorrupt(format!("来源微调下梯形维度错误：{error}"))
            })?;
    BilateralLadderNetwork::new(
        ascent,
        descent,
        Array1::from_vec(weights.bias.clone()),
        weights.t_iter,
    )
}

pub fn train_glibc_network_weights(
    samples: &[GlibcKnowledgeSample],
) -> Result<crate::bilateral::weights::BilateralWeights, DaotiError> {
    if samples.is_empty() || samples.iter().any(|sample| sample.validate().is_err()) {
        return Err(DaotiError::ModelCorrupt("glibc 训练样本为空或非法".into()));
    }
    let dim = KNOWLEDGE_VECTOR_DIM;
    let mut ascent = vec![0.0; dim * dim];
    let mut descent = vec![0.0; dim * dim];
    let mut bias = vec![0.0; dim];
    for index in 0..dim {
        ascent[index * dim + index] = 1.0;
        descent[index * dim + index] = 1.0;
    }
    // 以字段标签构造监督目标：正样本字段得到正偏置，未标注字段保持拒绝态。
    for sample in samples {
        for field in &sample.target_fields {
            let index = field_label_index(field);
            bias[index] += 1.0;
        }
    }
    let scale = samples.len().max(1) as f64;
    for value in &mut bias {
        *value = (*value / scale).tanh();
    }
    Ok(crate::bilateral::weights::BilateralWeights {
        version: crate::bilateral::weights::WEIGHTS_VERSION,
        dim,
        t_iter: 1,
        ascent,
        descent,
        bias,
        op_dict: Vec::new(),
    })
}

pub fn load_source_evidence_jsonl(path: &Path) -> Result<Vec<MainMapSourceEvidence>, DaotiError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)
        .map_err(|error| DaotiError::Other(format!("打开来源证据失败：{error}")))?;
    let reader = std::io::BufReader::new(file);
    let mut evidence = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|error| DaotiError::Other(format!("读取来源证据失败：{error}")))?;
        if line.trim().is_empty() {
            continue;
        }
        evidence.push(serde_json::from_str(&line).map_err(|error| {
            DaotiError::ModelCorrupt(format!("解析来源证据 JSONL 失败：{error}"))
        })?);
    }
    Ok(evidence)
}

pub fn write_jsonl(path: &Path, samples: &[GlibcKnowledgeSample]) -> Result<(), DaotiError> {
    if samples.is_empty() {
        return Err(DaotiError::ModelCorrupt("禁止写入空 glibc 知识库".into()));
    }
    let mut output = String::new();
    for sample in samples {
        sample.validate()?;
        output.push_str(&serde_json::to_string(sample).map_err(|error| {
            DaotiError::ModelCorrupt(format!("序列化 glibc 知识样本失败：{error}"))
        })?);
        output.push('\n');
    }
    std::fs::write(path, output)
        .map_err(|error| DaotiError::Other(format!("写入 glibc 知识库失败：{error}")))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlibcKnowledgeSample {
    pub context: String,
    pub input_vector: Vec<f64>,
    pub output_vector: Vec<f64>,
    pub source: KnowledgeSource,
    #[serde(default)]
    pub target_fields: Vec<String>,
    #[serde(default)]
    pub evidence_url: String,
    #[serde(default)]
    pub evidence_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldDecision {
    pub field: String,
    pub approved: bool,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateDecision {
    pub context: String,
    pub fields: Vec<FieldDecision>,
    pub continue_execution: bool,
}

const APPROVED_FIELDS: [&str; 7] = [
    "_dl_rtld_map.l_addr",
    "_dl_rtld_map.l_next",
    "_dl_rtld_map.l_prev",
    "_dl_rtld_map.l_real",
    "_ns_loaded",
    "link_map.l_phdr",
    "link_map.l_phnum",
];

const KNOWN_DECISION_FIELDS: [&str; 30] = [
    "_dl_rtld_map.l_addr",
    "_dl_rtld_map.l_next",
    "_dl_rtld_map.l_prev",
    "_dl_rtld_map.l_real",
    "_ns_loaded",
    "link_map.l_phdr",
    "link_map.l_phnum",
    "link_map.l_info",
    "tls.fs_base",
    "r_debug.r_map",
    "r_debug.r_state",
    "namespace.loaded_count",
    "link_map.l_scope",
    "relocation.relative",
    "link_map.l_searchlist",
    "symbol.version",
    "init_array",
    "auxv.AT_BASE",
    "program_header.PT_LOAD",
    "program_header.PT_GNU_STACK",
    "auxv.AT_PHDR",
    "auxv.AT_PHNUM",
    "auxv.AT_ENTRY",
    "relocation.glob_dat",
    "relocation.jump_slot",
    "dynamic.DT_NEEDED",
    "source.main_map.rbp",
    "source.main_map.rsp_slot",
    "source.main_map.register",
    "source.main_map.link_map_l_next",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeSource {
    GlibcSource,
    LinuxKernel,
    ElfAbi,
    GdbSnapshot,
    DebugLog,
}

impl GlibcKnowledgeSample {
    pub fn validate(&self) -> Result<(), DaotiError> {
        if self.context.trim().is_empty() {
            return Err(DaotiError::ModelCorrupt("glibc 知识样本上下文为空".into()));
        }
        if self.input_vector.len() != KNOWLEDGE_VECTOR_DIM
            || self.output_vector.len() != KNOWLEDGE_VECTOR_DIM
        {
            return Err(DaotiError::ModelCorrupt("glibc 知识样本维度错误".into()));
        }
        if self
            .input_vector
            .iter()
            .chain(self.output_vector.iter())
            .any(|value| !value.is_finite())
        {
            return Err(DaotiError::ModelCorrupt("glibc 知识样本含 NaN/Inf".into()));
        }
        Ok(())
    }

    pub fn input_array(&self) -> Result<Array1<f64>, DaotiError> {
        self.validate()?;
        Ok(Array1::from(self.input_vector.clone()))
    }

    pub fn output_array(&self) -> Result<Array1<f64>, DaotiError> {
        self.validate()?;
        Ok(Array1::from(self.output_vector.clone()))
    }
}

pub fn load_jsonl(path: &Path) -> Result<Vec<GlibcKnowledgeSample>, DaotiError> {
    let file = std::fs::File::open(path)
        .map_err(|error| DaotiError::Other(format!("读取 glibc 知识库失败：{error}")))?;
    let reader = std::io::BufReader::new(file);
    let mut samples = Vec::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|error| DaotiError::Other(format!("读取 glibc 知识库行失败：{error}")))?;
        if line.trim().is_empty() {
            continue;
        }
        let sample: GlibcKnowledgeSample = serde_json::from_str(&line).map_err(|error| {
            DaotiError::ModelCorrupt(format!(
                "解析 glibc 知识样本第 {} 行失败：{error}",
                line_number + 1
            ))
        })?;
        sample.validate()?;
        samples.push(sample);
    }
    if samples.is_empty() {
        return Err(DaotiError::ModelCorrupt("glibc 知识库为空".into()));
    }
    Ok(samples)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateField {
    pub name: String,
    pub address: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateApplicationDecision {
    pub context: String,
    pub field_names: Vec<String>,
    pub output_finite: bool,
}

pub fn decode_state_decision(
    sample: &GlibcKnowledgeSample,
    candidate: &Array1<f64>,
    context: &str,
) -> Result<StateDecision, DaotiError> {
    sample.validate()?;
    if candidate.len() != KNOWLEDGE_VECTOR_DIM || candidate.iter().any(|value| !value.is_finite()) {
        return Err(DaotiError::InferenceFailed(
            "道体候选状态维度或数值非法".into(),
        ));
    }
    let fields = sample
        .target_fields
        .iter()
        .filter(|field| KNOWN_DECISION_FIELDS.contains(&field.as_str()))
        .map(|field| {
            let confidence = candidate[field_label_index(field)].max(0.0);
            FieldDecision {
                field: field.clone(),
                approved: confidence >= 0.05 && APPROVED_FIELDS.contains(&field.as_str()),
                confidence,
            }
        })
        .collect::<Vec<_>>();
    let approved = fields.iter().any(|field| field.approved);
    let fields = fields
        .into_iter()
        .map(|mut field| {
            if !approved {
                field.approved = false;
            }
            field
        })
        .collect::<Vec<_>>();
    Ok(StateDecision {
        context: context.into(),
        continue_execution: approved && !fields.is_empty(),
        fields,
    })
}

pub struct StateApplier;

impl StateApplier {
    pub fn apply_decision(
        memory: &mut MemoryModel,
        fields: &[StateField],
        decision: &StateDecision,
    ) -> Result<StateApplicationDecision, DaotiError> {
        if !decision.continue_execution {
            return Err(DaotiError::InferenceFailed(format!(
                "道体拒绝 glibc 状态应用：{}",
                decision.context
            )));
        }
        let approved = fields
            .iter()
            .filter(|field| {
                decision
                    .fields
                    .iter()
                    .any(|item| item.field == field.name && item.approved)
            })
            .cloned()
            .collect::<Vec<_>>();
        if approved.is_empty() {
            return Err(DaotiError::InferenceFailed("道体未批准任何状态字段".into()));
        }
        apply_state_fields(memory, &approved)?;
        Ok(StateApplicationDecision {
            context: decision.context.clone(),
            field_names: approved.iter().map(|field| field.name.clone()).collect(),
            output_finite: decision
                .fields
                .iter()
                .all(|field| field.confidence.is_finite()),
        })
    }
}

pub fn apply_state_fields(
    memory: &mut MemoryModel,
    fields: &[StateField],
) -> Result<(), DaotiError> {
    for field in fields {
        if field.name.trim().is_empty() || field.value.is_empty() {
            return Err(DaotiError::ModelCorrupt("glibc 状态字段为空".into()));
        }
        if !matches!(
            field.name.as_str(),
            "_dl_rtld_map.l_addr"
                | "_dl_rtld_map.l_next"
                | "_dl_rtld_map.l_prev"
                | "_dl_rtld_map.l_real"
                | "_ns_loaded"
                | "link_map.l_phdr"
                | "link_map.l_phnum"
        ) {
            return Err(DaotiError::ModelCorrupt(format!(
                "禁止应用未审核的 glibc 字段：{}",
                field.name
            )));
        }
        memory.write(field.address, &field.value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::runtime::{MemPerm, MemoryRegion};

    fn sample() -> GlibcKnowledgeSample {
        GlibcKnowledgeSample {
            context: "rtld_global_init".into(),
            input_vector: vec![0.0; KNOWLEDGE_VECTOR_DIM],
            output_vector: vec![1.0; KNOWLEDGE_VECTOR_DIM],
            source: KnowledgeSource::DebugLog,
            target_fields: Vec::new(),
            evidence_url: String::new(),
            evidence_confidence: 0.0,
        }
    }

    #[test]
    fn extracts_real_runtime_evidence_contexts() {
        let log = "TRACE init-ldso-alloc alloc_ptr=0x2434188\nInconsistency detected by ld.so: rtld.c: 1712: dl_main: Assertion `main_map != NULL' failed!\nTRACE syscall nr=12";
        let evidence = extract_debug_log_evidence(log);
        assert_eq!(evidence.len(), 3);
        assert_eq!(evidence[0].context, "ldso_allocator_init");
        assert_eq!(evidence[1].context, "glibc_failure_observation");
        assert_eq!(evidence[2].context, "runtime_syscall_observation");
        let samples = extract_debug_log_samples(log);
        assert_eq!(samples.len(), 3);
        assert!(samples.iter().all(|sample| sample.validate().is_ok()));
    }

    #[test]
    fn official_samples_are_non_test_knowledge() {
        let samples = official_knowledge_samples();
        assert_eq!(samples.len(), 21usize);
        assert!(samples.iter().all(|sample| sample.validate().is_ok()));
        assert!(samples
            .iter()
            .any(|sample| matches!(sample.source, KnowledgeSource::LinuxKernel)));
        assert!(samples
            .iter()
            .any(|sample| matches!(sample.source, KnowledgeSource::ElfAbi)));
        assert!(samples
            .iter()
            .any(|sample| sample.target_fields.contains(&"symbol.version".into())));
        assert!(samples
            .iter()
            .any(|sample| sample.target_fields.contains(&"link_map.l_info".into())));
    }

    #[test]
    fn network_inference_accepts_knowledge_sample() {
        let sample = official_knowledge_samples().remove(0);
        let identity = ndarray::Array2::eye(KNOWLEDGE_VECTOR_DIM);
        let network = BilateralLadderNetwork::new(
            identity.clone(),
            identity,
            Array1::zeros(KNOWLEDGE_VECTOR_DIM),
            1,
        )
        .unwrap();
        let output = infer_candidate_state(&network, &sample).unwrap();
        assert_eq!(output.len(), KNOWLEDGE_VECTOR_DIM);
        assert!(output.iter().all(|value| value.is_finite()));
    }

    #[test]
    fn decodes_network_output_into_approved_field_decision() {
        let sample = official_knowledge_samples().remove(0);
        let candidate = Array1::from_vec(vec![1.0; KNOWLEDGE_VECTOR_DIM]);
        let decision = decode_state_decision(&sample, &candidate, "test").unwrap();
        assert!(decision.continue_execution);
        assert_eq!(decision.fields.len(), 1);
        assert!(decision.fields.iter().all(|field| field.approved));
    }

    #[test]
    fn daoti_guards_link_map_l_info_from_auto_apply() {
        // 第二竖切（__rtld_mutex_init）根因：loader 曾把 map+0x68 覆写为独立
        // 表地址，破坏了 glibc 内联 l_info[DT_STRTAB]（index 5），导致
        // D_PTR(map, l_info[DT_STRTAB]) 符号名解析损坏、dl-mutex.c:44
        // `sym != NULL' 断言失败。修复方向是保持 l_info 只读，本测试验证道体
        // 对 link_map.l_info 知识域的裁决：承认该知识、但禁止自动写入。
        let l_info_sample = official_knowledge_samples()
            .into_iter()
            .find(|sample| sample.target_fields.contains(&"link_map.l_info".into()))
            .expect("官方样本必须包含 link_map.l_info 事实");
        let identity = ndarray::Array2::eye(KNOWLEDGE_VECTOR_DIM);
        let network = BilateralLadderNetwork::new(
            identity.clone(),
            identity,
            Array1::zeros(KNOWLEDGE_VECTOR_DIM),
            1,
        )
        .unwrap();
        // 知识推理通路健康：forward 输出必须有限且维度正确。
        let inferred = infer_candidate_state(&network, &l_info_sample).unwrap();
        assert_eq!(inferred.len(), KNOWLEDGE_VECTOR_DIM);
        assert!(inferred.iter().all(|value| value.is_finite()));
        // 解码层验证（模拟网络对该知识槽给出高置信）：l_info 虽进 KNOWN 域并可
        // 打分，但不在写白名单，道体裁决为 not-approved，即「知识确认、禁止
        // 自动覆写 l_info、交由工程固定协议处理」——与本次 no-op 修复一致。
        let mut high_confidence = Array1::zeros(KNOWLEDGE_VECTOR_DIM);
        high_confidence[field_label_index("link_map.l_info")] = 1.0;
        let decision = decode_state_decision(
            &l_info_sample,
            &high_confidence,
            "rtld_mutex_l_info_protocol",
        )
        .unwrap();
        let field = decision
            .fields
            .iter()
            .find(|item| item.field == "link_map.l_info")
            .expect("道体必须对 link_map.l_info 给出裁决");
        assert_eq!(field.confidence, 1.0);
        assert!(!field.approved, "l_info 属人工审核字段，道体禁止自动写入");
        assert!(
            !decision.continue_execution,
            "不允许道体申请对 l_info 的内存写入动作"
        );
    }

    #[test]
    fn rejects_zero_network_decision() {
        let sample = official_knowledge_samples().remove(0);
        let candidate = Array1::zeros(KNOWLEDGE_VECTOR_DIM);
        let decision = decode_state_decision(&sample, &candidate, "test").unwrap();
        assert!(!decision.continue_execution);
        assert!(decision.fields.iter().all(|field| !field.approved));
    }

    #[test]
    fn validates_fixed_dimension_sample() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn rejects_non_finite_sample() {
        let mut value = sample();
        value.output_vector[0] = f64::NAN;
        assert!(value.validate().is_err());
    }

    #[test]
    fn applies_only_non_empty_named_fields() {
        let mut memory = MemoryModel::new(0x1000, 0x2000);
        memory
            .add_region(MemoryRegion::with_data(
                0x1000,
                MemPerm::rw(),
                vec![0; 0x1000],
            ))
            .unwrap();
        let fields = [StateField {
            name: "_ns_loaded".into(),
            address: 0x1010,
            value: 0x1234u64.to_le_bytes().to_vec(),
        }];
        apply_state_fields(&mut memory, &fields).unwrap();
        assert_eq!(memory.read(0x1010, 8).unwrap(), &0x1234u64.to_le_bytes());
    }
}
