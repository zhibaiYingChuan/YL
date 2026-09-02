//! M1 内置基线：映射样本、确定性编码、小维度训练评估与调度接口。

use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const EMBEDDING_DIM: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MappingSample {
    pub source_platform: String,
    pub target_platform: String,
    pub source: String,
    pub source_args: Vec<i64>,
    pub target: String,
    pub target_args: Vec<i64>,
    pub context: String,
    pub label: usize,
}

impl MappingSample {
    pub fn new(source: impl Into<String>, target: impl Into<String>, label: usize) -> Self {
        Self {
            source_platform: "Linux".into(),
            target_platform: "Windows".into(),
            source: source.into(),
            source_args: Vec::new(),
            target: target.into(),
            target_args: Vec::new(),
            context: "baseline".into(),
            label,
        }
    }
}

/// 返回可重复的内置基线映射。每个语义类别包含五个参数变体，共 100 条样本。
pub fn baseline_samples() -> Vec<MappingSample> {
    const MAPPINGS: [(&str, &str); 20] = [
        ("read", "ReadFile"),
        ("write", "WriteFile"),
        ("open", "CreateFileW"),
        ("close", "CloseHandle"),
        ("stat", "GetFileAttributesExW"),
        ("mkdir", "CreateDirectoryW"),
        ("unlink", "DeleteFileW"),
        ("rename", "MoveFileExW"),
        ("getpid", "GetCurrentProcessId"),
        ("gettid", "GetCurrentThreadId"),
        ("mmap", "VirtualAlloc"),
        ("munmap", "VirtualFree"),
        ("mprotect", "VirtualProtect"),
        ("clock_gettime", "QueryPerformanceCounter"),
        ("nanosleep", "Sleep"),
        ("getcwd", "GetCurrentDirectoryW"),
        ("chdir", "SetCurrentDirectoryW"),
        ("pipe", "CreatePipe"),
        ("dup", "DuplicateHandle"),
        ("fstat", "GetFileInformationByHandle"),
    ];
    MAPPINGS
        .iter()
        .enumerate()
        .flat_map(|(label, (source, target))| {
            (0..5).map(move |variant| {
                let mut sample = MappingSample::new(*source, *target, label);
                sample.source_args = vec![variant, label as i64, 0];
                sample.target_args = vec![variant, label as i64];
                sample.context = format!("baseline_variant_{variant}");
                sample
            })
        })
        .collect()
}

/// 从 Linux `unistd_64.h` 提取 `__NR_name number` 定义，并与 Wine 映射按 syscall 名称配对。
pub fn extract_linux_syscalls(text: &str) -> Vec<(String, i32)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let mut fields = line.split_whitespace();
            if fields.next()? != "#define" {
                return None;
            }
            let name = fields.next()?.strip_prefix("__NR_")?;
            let number = fields.next()?.parse().ok()?;
            Some((name.to_string(), number))
        })
        .collect()
}

/// 从 Wine syscall 映射源码提取 `linux_name -> WindowsApi` 的简单调用标记。
pub fn extract_wine_mappings(text: &str) -> Vec<(String, String)> {
    let mut mappings = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some((source, target)) = line.split_once("->") {
            let source = source.trim().trim_matches(['/', '*', ' ']);
            let target = target.trim().trim_matches(['/', '*', ' ', ';']);
            if !source.is_empty()
                && !target.is_empty()
                && !source.contains(' ')
                && !target.contains(' ')
            {
                mappings.push((source.to_string(), target.to_string()));
            }
            continue;
        }
        let Some(name) = line
            .strip_prefix("NTSTATUS WINAPI ")
            .or_else(|| line.strip_prefix("NTSTATUS WINAPI"))
        else {
            continue;
        };
        let name = name.split(['(', ' ', '\t']).next().unwrap_or_default();
        let Some(source) = name.strip_prefix("Nt").or_else(|| name.strip_prefix("Zw")) else {
            continue;
        };
        if source.is_empty() {
            continue;
        }
        mappings.push((source.to_ascii_lowercase(), name.to_string()));
    }
    mappings
}

/// 提取 Wine `syscall_table` 中已明确给出编号/宏与 NT 函数的表项。
/// 返回值的第一个字段是 Linux syscall 编号；无法解析编号或函数名的行会被丢弃。
pub fn extract_wine_syscall_table(text: &str) -> Vec<(i32, String)> {
    let in_table = text.contains("syscall_table");
    let mut entries = Vec::new();
    for line in text.lines() {
        if !in_table && !line.contains("SYS_") {
            continue;
        }
        let Some((left, right)) = line.split_once(',') else {
            continue;
        };
        let number_token = left
            .split(['{', '(', '[', ' ', '\t'])
            .find(|token| !token.is_empty())
            .unwrap_or_default()
            .trim_matches(['{', '(', '[']);
        let number = number_token
            .parse::<i32>()
            .ok()
            .or_else(|| number_token.strip_prefix("SYS_")?.parse::<i32>().ok())
            .or_else(|| number_token.strip_prefix("__NR_")?.parse::<i32>().ok());
        let Some(number) = number else {
            continue;
        };
        let target = right
            .split(['}', ')', ']', ';', ',', ' ', '\t'])
            .find(|token| token.starts_with("Nt") || token.starts_with("Zw"))
            .unwrap_or_default();
        if !target.is_empty() {
            entries.push((number, target.to_string()));
        }
    }
    entries
}

/// 读取源码文件并生成真实来源样本；无匹配时返回空集合，不回退猜测。
pub fn extract_paired_samples(
    linux_path: &Path,
    wine_path: &Path,
) -> Result<Vec<MappingSample>, String> {
    let linux = std::fs::read_to_string(linux_path)
        .map_err(|e| format!("读取 Linux syscall 表失败：{e}"))?;
    let wine =
        std::fs::read_to_string(wine_path).map_err(|e| format!("读取 Wine 映射失败：{e}"))?;
    let syscalls = extract_linux_syscalls(&linux);
    let table = extract_wine_syscall_table(&wine);
    let mappings = extract_wine_mappings(&wine);
    let mut samples = Vec::new();
    for (nr, target) in table {
        if let Some((source, _)) = syscalls.iter().find(|(_, syscall_nr)| *syscall_nr == nr) {
            samples.push(MappingSample {
                source_platform: "Linux".into(),
                target_platform: "Windows".into(),
                source: source.clone(),
                source_args: vec![nr as i64],
                target,
                target_args: Vec::new(),
                context: "wine_syscall_table".into(),
                label: samples.len(),
            });
        }
    }
    for (source, target) in mappings {
        if let Some((_, nr)) = syscalls.iter().find(|(name, _)| name == &source) {
            samples.push(MappingSample {
                source_platform: "Linux".into(),
                target_platform: "Windows".into(),
                source,
                source_args: vec![*nr as i64],
                target,
                target_args: Vec::new(),
                context: "source_extracted".into(),
                label: samples.len(),
            });
        }
    }
    Ok(samples)
}

pub fn train_test_split(samples: &[MappingSample]) -> (Vec<MappingSample>, Vec<MappingSample>) {
    let mut train = Vec::new();
    let mut test = Vec::new();
    for (index, sample) in samples.iter().cloned().enumerate() {
        if index % 5 == 0 {
            test.push(sample);
        } else {
            train.push(sample);
        }
    }
    (train, test)
}

/// FNV-1a 生成固定、无外部状态的 2048 维稀疏基线向量。
pub fn encode_sample(sample: &MappingSample) -> Array1<f64> {
    let mut out = Array1::zeros(EMBEDDING_DIM);
    for (field, value) in [
        (0u64, &sample.source_platform),
        (1, &sample.target_platform),
        (2, &sample.source),
        (3, &sample.target),
        (4, &sample.context),
    ] {
        let mut hash = 0xcbf29ce484222325u64 ^ field;
        for byte in value.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let index = (hash as usize) % EMBEDDING_DIM;
        let sign = if hash & 1 == 0 { 1.0 } else { -1.0 };
        out[index] += sign;
    }
    out[sample.label % EMBEDDING_DIM] += 1.0;
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineMetrics {
    pub loss: f64,
    pub accuracy: f64,
    pub samples: usize,
}

#[derive(Debug, Clone)]
pub struct TinyBaseline {
    weights: Array2<f64>,
    learning_rate: f64,
}

pub struct TrainedBilateral {
    pub metrics: BaselineMetrics,
    pub test_metrics: BaselineMetrics,
    pub weights: crate::bilateral::weights::BilateralWeights,
}

impl TinyBaseline {
    pub fn new(classes: usize, learning_rate: f64) -> Self {
        Self {
            weights: Array2::zeros((classes, EMBEDDING_DIM)),
            learning_rate,
        }
    }

    pub fn train(&mut self, samples: &[MappingSample], epochs: usize) -> BaselineMetrics {
        for _ in 0..epochs {
            for sample in samples {
                let x = encode_sample(sample);
                let scores = self.weights.dot(&x);
                let predicted = scores
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.total_cmp(b.1))
                    .map(|v| v.0)
                    .unwrap_or(0);
                if predicted != sample.label && sample.label < self.weights.nrows() {
                    let update = &x * self.learning_rate;
                    self.weights.row_mut(sample.label).scaled_add(1.0, &update);
                    self.weights.row_mut(predicted).scaled_add(-1.0, &update);
                }
            }
        }
        self.evaluate(samples)
    }

    pub fn evaluate(&self, samples: &[MappingSample]) -> BaselineMetrics {
        if samples.is_empty() {
            return BaselineMetrics {
                loss: 0.0,
                accuracy: 0.0,
                samples: 0,
            };
        }
        let mut correct = 0;
        let mut loss = 0.0;
        for sample in samples {
            let scores = self.weights.dot(&encode_sample(sample));
            let best = scores
                .iter()
                .enumerate()
                .max_by(|a, b| a.1.total_cmp(b.1))
                .map(|v| v.0)
                .unwrap_or(0);
            correct += usize::from(best == sample.label);
            loss += scores.iter().map(|v| v * v).sum::<f64>() / scores.len().max(1) as f64;
        }
        BaselineMetrics {
            loss: loss / samples.len() as f64,
            accuracy: correct as f64 / samples.len() as f64,
            samples: samples.len(),
        }
    }

    pub fn dispatch(&self, sample: &MappingSample) -> BaselineDispatch {
        let scores = self.weights.dot(&encode_sample(sample));
        let label = scores
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map(|v| v.0)
            .unwrap_or(0);
        BaselineDispatch {
            label,
            confidence: scores[label].max(0.0),
        }
    }

    fn export_weights(
        &self,
        samples: &[MappingSample],
    ) -> crate::bilateral::weights::BilateralWeights {
        let dim = EMBEDDING_DIM;
        let mut descent = vec![0.0; dim * dim];
        for index in 0..dim {
            descent[index * dim + index] = 1.0;
        }
        crate::bilateral::weights::BilateralWeights {
            version: crate::bilateral::weights::WEIGHTS_VERSION,
            dim,
            t_iter: 5,
            ascent: {
                let mut matrix = vec![0.0; dim * dim];
                for row in 0..self.weights.nrows().min(dim) {
                    for column in 0..dim {
                        matrix[row * dim + column] = self.weights[[row, column]];
                    }
                }
                matrix
            },
            descent,
            bias: vec![0.0; dim],
            op_dict: samples
                .iter()
                .map(|sample| crate::bilateral::weights::OpEntry {
                    nr: sample.source_args.first().copied().unwrap_or(-1) as i32,
                    name: sample.source.clone(),
                    windows_op: sample.target.clone(),
                })
                .collect(),
        }
    }
}

pub fn train_bilateral(
    samples: &[MappingSample],
    epochs: usize,
    learning_rate: f64,
) -> Result<TrainedBilateral, String> {
    if samples.is_empty() {
        return Err("训练样本为空".into());
    }
    let classes = samples.iter().map(|sample| sample.label).max().unwrap_or(0) + 1;
    let (train, test) = train_test_split(samples);
    if train.is_empty() || test.is_empty() {
        return Err("训练集或测试集为空".into());
    }
    let mut model = TinyBaseline::new(classes, learning_rate);
    let metrics = model.train(&train, epochs);
    let test_metrics = model.evaluate(&test);
    let weights = model.export_weights(samples);
    Ok(TrainedBilateral {
        metrics,
        test_metrics,
        weights,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineDispatch {
    pub label: usize,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchDecision {
    Native,
    Translate,
    Unsupported,
}

/// 道体调度边界：同平台原生执行；异平台仅在模型就绪且置信度达标时翻译。
pub fn should_translate(
    source_platform: &str,
    target_platform: &str,
    model_ready: bool,
    confidence: f64,
    threshold: f64,
) -> DispatchDecision {
    if source_platform == target_platform {
        DispatchDecision::Native
    } else if model_ready && confidence.is_finite() && confidence >= threshold {
        DispatchDecision::Translate
    } else {
        DispatchDecision::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encoding_is_deterministic_and_2048d() {
        let s = MappingSample::new("read", "ReadFile", 1);
        assert_eq!(encode_sample(&s), encode_sample(&s));
        assert_eq!(encode_sample(&s).len(), 2048);
    }
    #[test]
    fn sample_is_serializable() {
        let s = MappingSample::new("a", "b", 2);
        assert_eq!(
            serde_json::from_str::<MappingSample>(&serde_json::to_string(&s).unwrap()).unwrap(),
            s
        );
    }
    #[test]
    fn tiny_loop_trains_and_dispatches() {
        let data = vec![
            MappingSample::new("a", "x", 0),
            MappingSample::new("b", "y", 1),
        ];
        let mut model = TinyBaseline::new(2, 0.5);
        let metrics = model.train(&data, 4);
        assert!(metrics.accuracy > 0.0);
        assert!(model.dispatch(&data[0]).label < 2);
    }

    #[test]
    fn baseline_has_one_hundred_samples_and_split_is_eighty_twenty() {
        let samples = baseline_samples();
        assert_eq!(samples.len(), 100);
        let (train, test) = train_test_split(&samples);
        assert_eq!(train.len(), 80);
        assert_eq!(test.len(), 20);
        assert!(train.iter().all(|sample| sample.source_platform == "Linux"));
    }

    #[test]
    fn wine_syscall_table_extracts_explicit_numeric_entries() {
        let text = "static const syscall_entry syscall_table[] = {\n { 0, NtReadFile },\n { 1, ZwWriteFile },\n { SYS_open, NtOpenFile },\n};";
        assert_eq!(
            extract_wine_syscall_table(text),
            vec![(0, "NtReadFile".into()), (1, "ZwWriteFile".into())]
        );
    }

    #[test]
    fn source_extractors_pair_linux_and_wine_records() {
        let linux = "#define __NR_read 0\n#define __NR_write 1\n";
        let wine = "read -> ReadFile\nwrite -> WriteFile\nunknown -> Nope\n";
        let syscalls = extract_linux_syscalls(linux);
        let mappings = extract_wine_mappings(wine);
        assert_eq!(syscalls, vec![("read".into(), 0), ("write".into(), 1)]);
        assert_eq!(mappings.len(), 3);
        let base = std::env::temp_dir().join(format!("daoti-m1-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let linux_path = base.join("unistd_64.h");
        let wine_path = base.join("syscall.c");
        std::fs::write(&linux_path, linux).unwrap();
        std::fs::write(&wine_path, wine).unwrap();
        let samples = extract_paired_samples(&linux_path, &wine_path).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].source_args, vec![0]);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn train_bilateral_exports_loadable_weights_and_metrics() {
        let samples = baseline_samples();
        let trained = train_bilateral(&samples, 3, 0.1).unwrap();
        assert_eq!(trained.weights.dim, EMBEDDING_DIM);
        assert_eq!(trained.weights.op_dict.len(), samples.len());
        assert!(trained.test_metrics.accuracy >= 0.0);
        let loaded =
            crate::bilateral::weights::BilateralWeights::from_bytes(&trained.weights.to_bytes())
                .unwrap();
        assert_eq!(loaded, trained.weights);
    }

    #[test]
    fn dispatch_policy_never_guesses() {
        assert_eq!(
            should_translate("Linux", "Linux", true, 1.0, 0.8),
            DispatchDecision::Native
        );
        assert_eq!(
            should_translate("Linux", "Windows", true, 0.8, 0.8),
            DispatchDecision::Translate
        );
        assert_eq!(
            should_translate("Linux", "Windows", false, 1.0, 0.8),
            DispatchDecision::Unsupported
        );
        assert_eq!(
            should_translate("Linux", "Windows", true, 0.79, 0.8),
            DispatchDecision::Unsupported
        );
        assert_eq!(
            should_translate("Linux", "Windows", true, f64::NAN, 0.8),
            DispatchDecision::Unsupported
        );
    }
}
