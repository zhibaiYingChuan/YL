use daoti_core::glibc_knowledge::{
    fine_tune_glibc_network_weights, load_source_evidence_jsonl, official_knowledge_samples,
    public_runtime_knowledge_samples, source_evidence_to_training_sample,
    train_glibc_network_weights, write_jsonl,
};
use std::path::{Path, PathBuf};

fn default_source_evidence_path() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(|home| {
            PathBuf::from(home)
                .join(".daoti")
                .join("main_map_source")
                .join("evidence.jsonl")
        })
        .unwrap_or_else(|| PathBuf::from("knowledge/main_map_source_evidence.jsonl"))
}

// 确保输出文件父目录存在；CI 干净 checkout 中 knowledge/ 目录可能未被跟踪。
fn ensure_parent_dir(path: &Path) -> Result<(), daoti_core::DaotiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            daoti_core::DaotiError::Other(format!(
                "创建输出目录失败（{}）：{error}",
                parent.display()
            ))
        })?;
    }
    Ok(())
}

fn main() -> Result<(), daoti_core::DaotiError> {
    let output = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "knowledge/glibc_knowledge.jsonl".into());
    let source_path = std::env::var_os("DAOTI_MAIN_MAP_SOURCE_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(default_source_evidence_path);
    let source_output = Path::new("knowledge/main_map_source_samples.jsonl");

    let mut samples = official_knowledge_samples();
    samples.extend(public_runtime_knowledge_samples());

    let evidence = load_source_evidence_jsonl(&source_path)?;
    let source_samples = evidence
        .iter()
        .map(source_evidence_to_training_sample)
        .collect::<Vec<_>>();
    samples.extend(source_samples.iter().cloned());

    ensure_parent_dir(Path::new(&output))?;
    write_jsonl(Path::new(&output), &samples)?;
    if !source_samples.is_empty() {
        ensure_parent_dir(source_output)?;
        write_jsonl(source_output, &source_samples)?;
    }
    println!(
        "已生成 {} 条 glibc/Linux/ELF 知识样本：{}",
        samples.len(),
        output
    );
    println!(
        "已从 {} 读取 {} 条 main_map 来源证据，写出监督样本：{}",
        source_path.display(),
        evidence.len(),
        source_output.display()
    );

    let mut weights = train_glibc_network_weights(&samples)?;
    if !source_samples.is_empty() {
        weights = fine_tune_glibc_network_weights(&weights, &source_samples, 32, 0.05)?;
        println!(
            "已使用 {} 条来源监督样本执行误差反馈微调",
            source_samples.len()
        );
    }
    let weights_bytes = weights.to_bytes();
    let weights_path = Path::new("knowledge/glibc_network.daotiblt");
    ensure_parent_dir(weights_path)?;
    std::fs::write(weights_path, &weights_bytes)
        .map_err(|error| daoti_core::DaotiError::Other(format!("写出 glibc 权重失败：{error}")))?;
    println!(
        "已生成 glibc 双梯形权重：{} ({} 字节)",
        weights_path.display(),
        weights_bytes.len()
    );
    println!(
        "可通过 DAOTI_B2_WEIGHTS_PATH={} 加载",
        weights_path.display()
    );
    Ok(())
}
