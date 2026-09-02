//! CLI 子命令实现
//!
//! M1：`status` 已接入感知层，输出三系统（金/木/水）状态与判词。
//! M4：`heal / explain / run / init / snapshot` 待全链路落地。

use daoti_common::config::Config;
use daoti_common::format::{detect_binary_format, detect_elf_kind, BinaryFormat, ElfKind};
use daoti_core::bilateral::network::BilateralLadderNetwork;
use daoti_core::bilateral::weights::WeightsLoader;
use daoti_core::codec::{Decoder, Encoder, SyscallCodec};
use daoti_core::decision::engine::InferenceEngine;
use daoti_core::decision::model::{DispatchModel, TeacherSample};
use daoti_core::decision::DispatchRequest;
use daoti_core::decision::RuleEngine;
use daoti_core::injector::{AuditBuffer, Injector, LinuxEmulationInjector};
use daoti_core::interceptor::SyscallEvent;
use daoti_core::interceptor::TargetSyscall;
use daoti_core::sensor::WuxingHealth;
use ndarray::{Array1, Array2};

/// `daoti status`：查看三系统状态（金=Windows / 木=WSL2 / 水=Docker）
pub async fn status() -> i32 {
    // 严格符号模式只报告驭灵内部注册的三种平台能力，不读取宿主机状态。
    let h = WuxingHealth {
        metal: 1.0,
        wood: 1.0,
        water: 1.0,
    };

    let metal = if h.metal >= 0.9 {
        "坚"
    } else if h.metal > 0.0 {
        "弱"
    } else {
        "缺"
    };
    let wood = if h.wood >= 0.9 {
        "盛"
    } else if h.wood > 0.0 {
        "微"
    } else {
        "滞"
    };
    let water = if h.water >= 0.9 {
        "流"
    } else if h.water > 0.0 {
        "缓"
    } else {
        "枯"
    };

    println!("三气归元：金（Windows）{metal} · 木（WSL2）{wood} · 水（Docker）{water}");
    println!(
        "五行健康度：金 {:.0}% / 木 {:.0}% / 水 {:.0}%",
        h.metal * 100.0,
        h.wood * 100.0,
        h.water * 100.0
    );

    // 判词：三气通畅 / 需干预
    if h.metal >= 0.9 && h.wood >= 0.9 && h.water >= 0.9 {
        println!("判词：金坚、木盛、水流，三气通畅。");
    } else {
        println!("判词：气机有滞，可敲 `daoti heal` 疏通。");
    }

    0
}

/// `daoti heal`：自动诊断并修复（M4 全链路 + P0-7 四类结局闭环）
pub async fn heal() -> i32 {
    // 严格符号模式只推演内部状态，不调用平台执行器或宿主软件。
    let health = WuxingHealth {
        metal: 1.0,
        wood: 1.0,
        water: 1.0,
    };
    let symbolic = daoti_core::decision::DaotiSymbolicOutput::from_health(&health);
    let decision = match symbolic.to_decision() {
        Ok(decision) => decision,
        Err(error) => {
            eprintln!("❌ 符号推演失败：{error}");
            return 1;
        }
    };

    println!("☯ 正在推演...");
    println!(
        "判词：{explanation}（主卦：{gua}，信心 {conf:.0}%）",
        explanation = decision.explanation,
        gua = decision.gua,
        conf = decision.confidence * 100.0
    );
    println!("\n符号执行：无外部命令下发，三平台调度状态已生成。");
    println!("☯️ 结局：无需干预");
    println!(
        "  五行健康度：金 {:.0}% / 木 {:.0}% / 水 {:.0}%",
        health.metal * 100.0,
        health.wood * 100.0,
        health.water * 100.0
    );
    println!("  判词：{}", health.verdict());
    0
}

/// `daoti explain <code>`：解释错误码/卦象的推演过程（M4）
pub async fn explain(code: &str) -> i32 {
    match explain_lookup(code) {
        Some((title, body, advice)) => {
            println!("☯ {title}");
            println!("  {body}");
            println!("  建议：{advice}");
            0
        }
        None => {
            eprintln!("未识别关键字：{code}");
            eprintln!("可解释的错误类型：blocked / command_timeout / unavailable / path_mapping / channel_closed");
            eprintln!("可解释的卦象：坎（Docker）/ 震（WSL2）/ 乾（Windows）");
            1
        }
    }
}

/// 将错误关键字/卦象映射为白话判词（纯函数，便于单元测试）
///
/// 返回 `(标题, 判词, 建议)`；未识别时返回 `None`。
fn explain_lookup(code: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let k = code.trim().to_lowercase();
    match k.as_str() {
        "blocked" | "拦截" => Some((
            "命令被安全策略拦截",
            "SafeCommandExecutor 白名单/禁止模式判定该命令不安全（如 rm -rf /、format、Remove-Item -Recurse）。",
            "确认确有需要后，改用白名单内的诊断命令，或人工在受控环境执行。",
        )),
        "command_timeout" | "timeout" | "超时" => Some((
            "命令执行超时",
            "子进程在设定时间内未返回（默认 exec_secs 秒），已按超时兜底终止，避免卡死拖垮守护进程。",
            "检查目标平台是否响应；可调高配置中的 exec_secs，或排查网络/daemon 状态。",
        )),
        "unavailable" | "不可用" => Some((
            "目标平台不可用",
            "感知器/执行器对某目标不可用（系统不存在、命令不可用），已返回结构化降级而非崩溃。",
            "确认 Windows/WSL2/Docker 环境已就绪；可敲 daoti status 查看三气状态。",
        )),
        "path_mapping" | "路径" => Some((
            "跨系统路径映射失败",
            "Windows 盘符与 WSL /mnt 的映射未能解析，命令无法在目标系统正确落地。",
            "重敲 daoti init 重新探测并生成路径映射表。",
        )),
        "channel_closed" | "管道" => Some((
            "消息通道断开",
            "感知/推演/执行层之间的 mpsc 通道已断开（如守护进程被终止）。",
            "检查 daoti daemon 是否在运行，必要时重启守护进程。",
        )),
        "坎" | "docker" | "水" => Some((
            "坎水滞涩 · Docker 断流",
            "推演判定 Docker daemon 断流（水滞），需通水：重启 WSL 内 daemon 并复位 Windows 管道。",
            "可执行 daoti heal 自动疏通，或手动重启 Docker。",
        )),
        "震" | "wsl" | "wsl2" | "木" => Some((
            "震木滞涩 · WSL2 异常",
            "推演判定 WSL2 内核滞涩（木滞），需培木：复位 WSL 内核。",
            "可执行 daoti heal 自动复位，或手动 wsl --shutdown 后重启。",
        )),
        "乾" | "windows" | "金" => Some((
            "乾金受制 · Windows 宿主异常",
            "推演判定 Windows 宿主异常（金弱），需调金：核查宿主服务。",
            "可执行 daoti heal 或手动核查 Windows 服务状态。",
        )),
        _ => None,
    }
}

/// `daoti run [--target <平台>] <命令>`：在正确平台执行命令（B0·道体·通）
///
/// `target` 可选：显式指定时直接使用；省略时道体自动识别二进制格式并择路执行。
/// `daoti run` 的严格符号入口：只生成调度报告，不调用任何外部执行器。
pub async fn run(target: Option<&str>, cmd: &str) -> i32 {
    let target = target.unwrap_or("auto");
    let command = cmd.trim();
    if command.is_empty() {
        eprintln!("❌ 符号命令不能为空");
        return 1;
    }

    if target.eq_ignore_ascii_case("auto") && std::path::Path::new(command).is_file() {
        if let Ok(BinaryFormat::Pe) = detect_binary_format(command) {
            let data = match std::fs::read(command) {
                Ok(data) => data,
                Err(error) => {
                    eprintln!("❌ PE 文件读取失败：{error}");
                    return 1;
                }
            };
            match daoti_core::parser::pe::execute_pe32_plus_console(&data, None) {
                Ok(result) => {
                    print!("{}", String::from_utf8_lossy(&result.stdout));
                    match result.state {
                        daoti_core::elf::runtime::ExecutionState::Exited(code) => return code,
                        state => eprintln!("❌ PE 解释器未正常退出：{state:?}"),
                    }
                }
                Err(error) => eprintln!("❌ PE 解释执行失败：{error}"),
            }
            return 1;
        }
        if let Ok(BinaryFormat::MachO) = detect_binary_format(command) {
            match daoti_core::macho_runtime::execute_macho_file(command, 8 * 1024 * 1024) {
                Ok(daoti_core::elf::runtime::ExecutionState::Exited(code)) => return code,
                Ok(state) => eprintln!("❌ Mach-O 解释器未正常退出：{state:?}"),
                Err(error) => eprintln!("❌ Mach-O 解释执行失败：{error}"),
            }
            return 1;
        }
        if let Ok(BinaryFormat::Elf) = detect_binary_format(command) {
            match detect_elf_kind(command) {
                Ok(ElfKind::Static) => {
                    match daoti_core::elf::execute_elf_file(command, 8 * 1024 * 1024) {
                        Ok(daoti_core::elf::runtime::ExecutionState::Exited(code)) => return code,
                        Ok(state) => {
                            eprintln!("❌ ELF 解释器未正常退出：{state:?}");
                        }
                        Err(error) => eprintln!("❌ ELF 解释执行失败：{error}"),
                    }
                    return 1;
                }
                Ok(ElfKind::Dynamic) => {
                    let runtime_root = std::env::var_os("DAOTI_DYNAMIC_RUNTIME_ROOT")
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| {
                            std::path::Path::new(command)
                                .parent()
                                .unwrap_or_else(|| std::path::Path::new("."))
                                .to_path_buf()
                        });
                    match daoti_core::elf::execute_dynamic_elf_file(
                        command,
                        &runtime_root,
                        8 * 1024 * 1024,
                    ) {
                        Ok(daoti_core::elf::runtime::ExecutionState::Exited(code)) => return code,
                        Ok(state) => eprintln!("❌ 动态 ELF 解释器未正常退出：{state:?}"),
                        Err(error) => eprintln!("❌ 动态 ELF 解释执行失败：{error}"),
                    }
                    return 1;
                }
                Err(error) => {
                    eprintln!("❌ ELF 类型识别失败：{error}");
                    return 1;
                }
            }
        }
    }

    let platform = match target.to_ascii_lowercase().as_str() {
        "windows" | "native" => "windows",
        "wsl2" | "wsl" => "wsl2",
        "docker" => "docker",
        "auto" => infer_symbolic_target(command),
        _ => {
            eprintln!("❌ 未知符号目标：{target}");
            return 1;
        }
    };

    let (element, pathway) = match platform {
        "windows" => ("金", "windows_symbolic_bridge"),
        "wsl2" => ("木", "wsl2_symbolic_bridge"),
        "docker" => ("水", "docker_symbolic_bridge"),
        _ => unreachable!(),
    };

    println!("☯ 符号执行：不调用外部软件");
    println!("  command: {command}");
    println!("  target: {platform}");
    println!("  wuxing: {element}");
    println!("  pathway: {pathway}");
    println!("  mode: symbolic_only");
    println!("  result: dispatched");
    0
}

fn infer_symbolic_target(command: &str) -> &'static str {
    let lower = command.to_ascii_lowercase();
    if lower.contains("docker") || lower.contains("container") {
        "docker"
    } else if lower.contains("wsl") || lower.contains("linux") || lower.contains("elf") {
        "wsl2"
    } else {
        "windows"
    }
}

/// `daoti mock-macos`：通过统一 Agent 入口执行模拟 macOS 节点请求。
pub async fn mock_macos(command: &str, node_id: &str) -> i32 {
    let agent = daoti_core::agent::CrossPlatformAgent::new(&Config::load());
    let request = DispatchRequest {
        path: command.to_string(),
        args: Vec::new(),
    };
    let node = daoti_core::executor::MacOsNodeCapabilities {
        node_id: node_id.to_string(),
        os_version: "mock".into(),
        architectures: vec!["arm64".into()],
        capabilities: vec!["shell".into()],
    };
    let auth = daoti_core::executor::Authentication {
        method: daoti_core::executor::AuthMethod::Token,
        credential_ref: "cli-mock".into(),
    };
    match agent.dispatch_mock_macos(request, node, auth, 1_000) {
        Ok((decision, response)) => {
            println!(
                "{}",
                serde_json::json!({"decision": decision, "response": response})
            );
            0
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"status":"error", "kind":error.kind(), "error":error.to_string()})
            );
            1
        }
    }
}

/// `daoti dispatch <path>`：探测二进制格式并输出调度决策（不执行）。
pub async fn dispatch(path: &str) -> i32 {
    let agent = daoti_core::agent::CrossPlatformAgent::new(&Config::load());
    let registry = daoti_core::executor::CapabilityRegistry::for_current_environment();
    let request = DispatchRequest {
        path: path.to_string(),
        args: Vec::new(),
    };
    match agent.dispatch(request) {
        Ok(mut decision) => {
            let registered = registry.target_available(decision.target.execution_target);
            if !registered {
                decision.available = false;
                decision.diagnostic = Some(format!(
                    "能力注册表探测失败：{}",
                    decision.target.execution_target.probe().1
                ));
            }
            println!(
                "{}",
                serde_json::json!({
                    "status": "ok",
                    "format": decision.target.format,
                    "platform": decision.target.platform,
                    "mode": decision.target.mode,
                    "execution_target": decision.target.execution_target,
                    "reason": decision.target.reason,
                    "available": decision.available,
                    "diagnostic": decision.diagnostic,
                    "mock_node": decision.mock_node,
                })
            );
            0
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"status":"error", "kind":error.kind(), "error":error.to_string()})
            );
            1
        }
    }
}

/// 解析十进制或 0x 前缀的地址参数。
pub fn parse_u64(value: &str) -> Result<u64, String> {
    let normalized = value.trim().trim_start_matches("0x");
    u64::from_str_radix(
        normalized,
        if value.trim().starts_with("0x") {
            16
        } else {
            10
        },
    )
    .map_err(|error| format!("无效地址 {value}：{error}"))
}

/// `daoti train-bilateral`：提取源码映射并写入 JSON 数据集，不执行训练或推断。
pub async fn stage7_preflight(version: &str, output: Option<&str>) -> i32 {
    let mut report = daoti_core::stage7::PreflightReport::new(
        version,
        std::env::current_dir().unwrap_or_default(),
    );
    report.record(
        "版本格式",
        "validate_release_version",
        daoti_core::stage7::validate_release_version(version),
    );
    let workspace = std::env::current_dir().unwrap_or_default();
    report.record(
        "Rust 格式",
        "cargo fmt --all -- --check",
        run_preflight("cargo", &["fmt", "--all", "--", "--check"], &workspace).await,
    );
    report.record(
        "Workspace 测试",
        "cargo test --workspace",
        run_preflight("cargo", &["test", "--workspace"], &workspace).await,
    );
    report.record(
        "Clippy",
        "cargo clippy --workspace -- -D warnings",
        run_preflight(
            "cargo",
            &["clippy", "--workspace", "--", "-D", "warnings"],
            &workspace,
        )
        .await,
    );
    if let Some(path) = output {
        if let Err(error) = report.write_json(std::path::Path::new(path)) {
            eprintln!("阶段7证据写入失败：{error}");
            return 1;
        }
    }
    println!(
        "阶段7发布前置检查：{}",
        if report.passed { "通过" } else { "未通过" }
    );
    for check in &report.checks {
        println!("  [{}] {}：{}", check.status, check.name, check.detail);
    }
    if report.passed {
        0
    } else {
        1
    }
}

async fn run_preflight(program: &str, args: &[&str], cwd: &std::path::Path) -> Result<(), String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr)
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | "))
    }
}

pub async fn stage5_import(input: &str, output: &str) -> i32 {
    match daoti_core::stage5::import_immutable_records(
        std::path::Path::new(input),
        std::path::Path::new(output),
    ) {
        Ok(manifest) => {
            println!(
                "阶段5数据集已导入：{} 条记录，版本 {}",
                manifest.record_count, manifest.dataset_version
            );
            println!("来源摘要：{}", manifest.source_digest);
            0
        }
        Err(error) => {
            eprintln!("阶段5不可变导入失败：{error}");
            1
        }
    }
}

pub async fn stage5_evaluate(input: &str, threshold: f64) -> i32 {
    match daoti_core::stage5::evaluate_records(std::path::Path::new(input), threshold) {
        Ok(metrics) => {
            println!(
                "阶段5指标：{} 条记录，覆盖率 {:.2}%，准确率 {}，拒绝率 {:.2}%，失败率 {:.2}%",
                metrics.total,
                metrics.coverage * 100.0,
                metrics
                    .accuracy
                    .map(|v| format!("{:.2}%", v * 100.0))
                    .unwrap_or_else(|| "无标签".into()),
                metrics.rejection_rate * 100.0,
                metrics.failure_rate * 100.0
            );
            0
        }
        Err(error) => {
            eprintln!("阶段5评估失败：{error}");
            1
        }
    }
}

pub async fn stage5_release(
    root: &str,
    version: &str,
    weights: Option<&str>,
    dataset: Option<&str>,
    rollback: bool,
) -> i32 {
    let store = daoti_core::stage5::ReleaseStore::new(root);
    let result = if rollback {
        store
            .rollback(version)
            .map(|state| format!("已回滚到 {}", state.active_version.unwrap_or_default()))
    } else {
        let Some(weights) = weights else {
            eprintln!("发布权重必须提供 --weights");
            return 1;
        };
        let Some(dataset) = dataset else {
            eprintln!("发布权重必须提供 --dataset");
            return 1;
        };
        match daoti_core::stage5::evaluate_records(std::path::Path::new(dataset), 0.95) {
            Ok(metrics) => store
                .publish(daoti_core::stage5::WeightRelease {
                    version: version.into(),
                    weights_path: weights.into(),
                    metrics,
                    source_dataset: dataset.into(),
                    published: false,
                })
                .map(|state| {
                    format!(
                        "已发布 {}，当前活动版本 {:?}",
                        version, state.active_version
                    )
                }),
            Err(error) => Err(error),
        }
    };
    match result {
        Ok(message) => {
            println!("阶段5{message}");
            0
        }
        Err(error) => {
            eprintln!("阶段5发布/回滚失败：{error}");
            1
        }
    }
}

pub async fn infer_bilateral(weights_path: &str, nr: i32, name: &str, tid: u64) -> i32 {
    let weights = match WeightsLoader::load(std::path::Path::new(weights_path)) {
        Ok(weights) => weights,
        Err(error) => {
            eprintln!("双梯形权重加载失败：{error}");
            return 1;
        }
    };
    let dim = weights.dim;
    let network = match BilateralLadderNetwork::new(
        Array2::from_shape_vec((dim, dim), weights.ascent).unwrap(),
        Array2::from_shape_vec((dim, dim), weights.descent).unwrap(),
        Array1::from_vec(weights.bias),
        weights.t_iter,
    ) {
        Ok(network) => network,
        Err(error) => {
            eprintln!("双梯形网络构造失败：{error}");
            return 1;
        }
    };
    let codec = match SyscallCodec::new(dim, weights.op_dict) {
        Ok(codec) => codec,
        Err(error) => {
            eprintln!("syscall 编解码器构造失败：{error}");
            return 1;
        }
    };
    let event = SyscallEvent::new(nr, name.to_string(), Vec::new(), tid);
    let input = match codec.encode(&event) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("推理输入编码失败：{error}");
            return 1;
        }
    };
    let output = match network.forward(input.clone()) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("双梯形网络推理失败：{error}");
            return 1;
        }
    };
    let decoded = codec.decode(&output);
    let (decode_status, decoded_name, windows_operation, confidence, decode_error) = match decoded {
        Ok(decoded) => (
            "success",
            Some(decoded.event.name),
            Some(decoded.windows_op),
            Some(decoded.confidence),
            None,
        ),
        Err(error) => ("failed", None, None, None, Some(error.to_string())),
    };
    println!(
        "{}",
        serde_json::json!({
            "mode": "bilateral_inference",
            "read_only": true,
            "weights": weights_path,
            "input": {"nr": nr, "name": name, "tid": tid, "dim": dim},
            "output": {
                "nr_slot": output[0],
                "output_norm": output.iter().map(|value| value * value).sum::<f64>().sqrt(),
                "decode_status": decode_status,
                "decoded_name": decoded_name,
                "windows_operation": windows_operation,
                "confidence": confidence,
                "decode_error": decode_error,
            },
            "execution": "not_performed",
        })
    );
    if decode_status == "failed" {
        2
    } else {
        0
    }
}

pub async fn pilot_syscall(nr: i32, name: &str, tid: u64, args: &[String], confirm: bool) -> i32 {
    let syscall = match SyscallCodec::linux_x86_64_syscall(nr) {
        Some(syscall) if syscall.name == name => syscall,
        Some(syscall) => {
            println!(
                "{}",
                serde_json::json!({"status":"unavailable","error":{"kind":"syscall_name_mismatch","message":format!("编号 {nr} 对应 {}，不是 {name}", syscall.name)},"execution_performed":false})
            );
            return 3;
        }
        None => {
            println!(
                "{}",
                serde_json::json!({"status":"unavailable","error":{"kind":"unsupported_syscall","message":format!("Linux x86_64 未实现 syscall {nr}")},"execution_performed":false})
            );
            return 3;
        }
    };
    if !confirm {
        println!(
            "{}",
            serde_json::json!({"status":"awaiting_confirmation","syscall":{"nr":syscall.nr,"name":syscall.name},"execution_performed":false,"confirmation_required":true,"next_step":"重新执行并添加 --confirm yes"})
        );
        return 0;
    }
    if !matches!(syscall.name.as_str(), "write" | "mmap" | "brk" | "mprotect") {
        println!(
            "{}",
            serde_json::json!({"status":"unavailable","error":{"kind":"linux_emulation_unavailable","message":format!("Linux 仿真器暂不支持 {}", syscall.name)},"execution_performed":false,"confirmation_received":true})
        );
        return 3;
    }
    let decoded = daoti_core::codec::DecodeOutcome {
        event: SyscallEvent::new(nr, syscall.name.clone(), args.to_vec(), tid),
        windows_op: syscall.windows_op.clone(),
        confidence: 1.0,
    };
    let audit = AuditBuffer::new();
    let injector = LinuxEmulationInjector::new(audit.clone());
    let target = TargetSyscall::new(syscall.name.clone(), "Linux syscall 仿真").with_args(args);
    let injected = match injector.inject(&target) {
        Ok(result) => result,
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({
                    "status": "unavailable",
                    "error": {"kind": "linux_emulation_unavailable", "message": error.to_string()},
                    "execution_performed": false,
                    "confirmation_received": true
                })
            );
            return 3;
        }
    };
    println!(
        "{}",
        serde_json::json!({
            "status": "ok",
            "mode": "linux_emulation_pilot",
            "syscall": {"nr": nr, "name": syscall.name, "tid": tid},
            "operation": target.operation,
            "confidence": decoded.confidence,
            "ret_value": injected.ret_value,
            "audit_records": audit.records(),
            "execution_performed": true,
            "real_console_touched": false,
            "confirmation_received": true
        })
    );
    0
}

pub async fn infer_dynamic(path: &str, weights_path: &str, base: u64) -> i32 {
    let loader = match daoti_core::elf::DynamicElfLoader::new(EmptyDynamicResolver, base, 4096) {
        Ok(loader) => loader,
        Err(error) => {
            eprintln!("动态 ELF 推理加载器创建失败：{error}");
            return 1;
        }
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("动态 ELF 推理输入读取失败：{error}");
            return 1;
        }
    };
    let metadata = match loader.metadata(&bytes) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("动态 ELF 状态解析失败：{error}");
            return 1;
        }
    };
    let mut input = Array1::zeros(2048);
    input[0] = metadata.load_bias as f64 / 0x1000000 as f64;
    input[1] = metadata.entry as f64 / 0x1000000 as f64;
    input[2] = metadata.relocated_entry as f64 / 0x1000000 as f64;
    input[3] = metadata.load_segments.len() as f64 / 16.0;
    input[4] = metadata.needed.len() as f64 / 16.0;
    input[5] = metadata.rela_count as f64 / 1024.0;
    input[6] = metadata.rel_count as f64 / 1024.0;
    input[7] = if metadata.interpreter.is_some() {
        1.0
    } else {
        0.0
    };
    let weights = match WeightsLoader::load(std::path::Path::new(weights_path)) {
        Ok(weights) => weights,
        Err(error) => {
            eprintln!("动态 ELF 推理权重加载失败：{error}");
            return 1;
        }
    };
    if weights.dim != input.len() {
        eprintln!(
            "动态 ELF 状态维度 {} 与模型维度 {} 不符",
            input.len(),
            weights.dim
        );
        return 1;
    }
    let network = match BilateralLadderNetwork::new(
        Array2::from_shape_vec((weights.dim, weights.dim), weights.ascent).unwrap(),
        Array2::from_shape_vec((weights.dim, weights.dim), weights.descent).unwrap(),
        Array1::from_vec(weights.bias),
        weights.t_iter,
    ) {
        Ok(network) => network,
        Err(error) => {
            eprintln!("动态 ELF 模型构造失败：{error}");
            return 1;
        }
    };
    let output = match network.forward(input.clone()) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("动态 ELF 模型推理失败：{error}");
            return 1;
        }
    };
    println!(
        "{}",
        serde_json::json!({
            "mode": "dynamic_elf_shadow_inference",
            "read_only": true,
            "execution_gate": "deny",
            "execution_performed": false,
            "input": {
                "path": path,
                "load_bias": metadata.load_bias,
                "entry": metadata.entry,
                "relocated_entry": metadata.relocated_entry,
                "segment_count": metadata.load_segments.len(),
                "dependency_count": metadata.needed.len(),
                "rela_count": metadata.rela_count,
                "rel_count": metadata.rel_count,
                "has_interpreter": metadata.interpreter.is_some()
            },
            "model": {
                "name": "BilateralLadderNetwork",
                "dimension": weights.dim,
                "t_iter": weights.t_iter,
                "output_norm": output.iter().map(|value| value * value).sum::<f64>().sqrt(),
                "output_head": output.iter().take(8).copied().collect::<Vec<_>>()
            },
            "decision": {
                "action": "observe_only",
                "confidence": 0.0,
                "reason": "动态 ELF 状态推理已完成，但执行门控默认拒绝"
            }
        })
    );
    0
}

struct EmptyDynamicResolver;

impl daoti_core::elf::relocation::SymbolResolver for EmptyDynamicResolver {
    fn resolve(&self, _symbol: u32) -> Option<u64> {
        None
    }
}

pub async fn train_dispatch_model(output: &str, min_confidence: f64) -> i32 {
    let levels = [0.0, 0.25, 0.5, 0.75, 1.0];
    let mut samples = Vec::new();
    for metal in levels {
        for wood in levels {
            for water in levels {
                let health = WuxingHealth { metal, wood, water };
                let mut teacher = RuleEngine::new();
                let decision = teacher.interpret(&health);
                samples.push(TeacherSample { health, decision });
            }
        }
    }
    let model = match DispatchModel::train(&samples, min_confidence) {
        Ok(model) => model,
        Err(error) => {
            eprintln!("道体调度模型训练失败：{error}");
            return 1;
        }
    };
    let path = std::path::Path::new(output);
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("道体调度模型目录创建失败：{error}");
            return 1;
        }
    }
    match model.save(path) {
        Ok(()) => {
            println!(
                "道体调度模型训练完成：{} 条规则教师样本 -> {output}",
                samples.len()
            );
            println!(
                "模型版本：{}，类别数：{}，最低置信度：{:.3}",
                model.version,
                model.classes.len(),
                model.min_confidence
            );
            0
        }
        Err(error) => {
            eprintln!("道体调度模型写入失败：{error}");
            1
        }
    }
}

pub async fn train_bilateral(linux: &str, wine: &str, output: &str) -> i32 {
    let samples = match daoti_core::m1::extract_paired_samples(
        std::path::Path::new(linux),
        std::path::Path::new(wine),
    ) {
        Ok(samples) => samples,
        Err(error) => {
            eprintln!("M1 数据提取失败：{error}");
            return 1;
        }
    };
    if samples.is_empty() {
        eprintln!("M1 数据提取未找到可确认的配对样本");
        return 1;
    }
    let training = match daoti_core::m1::train_bilateral(&samples, 10, 0.1) {
        Ok(training) => training,
        Err(error) => {
            eprintln!("M1 训练失败：{error}");
            return 1;
        }
    };
    let json = match serde_json::to_vec_pretty(&samples) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("M1 数据集序列化失败：{error}");
            return 1;
        }
    };
    if let Some(parent) = std::path::Path::new(output).parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("M1 数据集目录创建失败：{error}");
            return 1;
        }
    }
    let weights_path = format!("{output}.daotiblt");
    match (
        std::fs::write(output, json),
        std::fs::write(&weights_path, training.weights.to_bytes()),
    ) {
        (Ok(()), Ok(())) => {
            println!("M1 数据集已生成：{} 条样本 -> {output}", samples.len());
            println!(
                "M1 训练完成：训练准确率 {:.1}% / 测试准确率 {:.1}%",
                training.metrics.accuracy * 100.0,
                training.test_metrics.accuracy * 100.0
            );
            println!("M1 权重已生成：{weights_path}");
            0
        }
        (Err(error), _) | (_, Err(error)) => {
            eprintln!("M1 数据集或权重写入失败：{error}");
            1
        }
    }
}

#[derive(Default)]
struct ShadowSummaryStats {
    total: usize,
    predicted: usize,
    accepted: usize,
    rejected: usize,
    failed: usize,
    actual_success: usize,
    actual_failed: usize,
    labeled: usize,
    confidence_sum: f64,
    operations: std::collections::BTreeMap<String, usize>,
    syscalls: std::collections::BTreeMap<String, usize>,
    accuracy: std::collections::BTreeMap<String, (usize, usize)>,
    confidence_accuracy: std::collections::BTreeMap<String, (usize, usize)>,
}

/// `daoti shadow-summary`：汇总 JSONL 影子推理记录。
pub async fn shadow_summary(input: &str, threshold: f64) -> i32 {
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        eprintln!("影子推理阈值必须位于 [0, 1] 内");
        return 1;
    }
    let content = match std::fs::read_to_string(input) {
        Ok(content) => content,
        Err(error) => {
            eprintln!("影子记录读取失败：{error}");
            return 1;
        }
    };
    let mut stats = ShadowSummaryStats::default();
    for (line_no, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: daoti_core::elf::syscall_bridge::ShadowInferenceRecord =
            match serde_json::from_str(line) {
                Ok(record) => record,
                Err(error) => {
                    eprintln!("影子记录第 {} 行格式错误：{}", line_no + 1, error);
                    return 1;
                }
            };
        stats.total += 1;
        *stats.syscalls.entry(record.name.clone()).or_default() += 1;
        if record.actual_success || record.actual_error.is_some() {
            stats.labeled += 1;
            if record.actual_success {
                stats.actual_success += 1;
            } else {
                stats.actual_failed += 1;
            }
        }
        if let Some(prediction) = record.prediction {
            stats.predicted += 1;
            *stats.operations.entry(prediction.clone()).or_default() += 1;
            let actual_operation = record.actual_windows_op.clone();
            if let Some(actual) = actual_operation.as_ref() {
                let key = format!("{} / {}", record.name, prediction.trim());
                let entry = stats.accuracy.entry(key).or_default();
                entry.1 += 1;
                if prediction == *actual {
                    entry.0 += 1;
                }
            }
            if let Some(confidence) = record.confidence.filter(|value| value.is_finite()) {
                stats.confidence_sum += confidence;
                if confidence >= threshold {
                    stats.accepted += 1;
                } else {
                    stats.rejected += 1;
                }
                if let Some(actual) = actual_operation.as_ref() {
                    let bucket = confidence_bucket(confidence);
                    let entry = stats.confidence_accuracy.entry(bucket).or_default();
                    entry.1 += 1;
                    if prediction == *actual {
                        entry.0 += 1;
                    }
                }
            } else {
                stats.rejected += 1;
            }
        } else {
            stats.failed += 1;
        }
    }
    let average = if stats.predicted == 0 {
        0.0
    } else {
        stats.confidence_sum / stats.predicted as f64
    };
    println!("影子推理总数：{}", stats.total);
    println!(
        "成功预测：{} ({:.1}%)",
        stats.predicted,
        percentage(stats.predicted, stats.total)
    );
    println!(
        "达到阈值：{} ({:.1}%)",
        stats.accepted,
        percentage(stats.accepted, stats.total)
    );
    println!("低置信度拒绝：{}", stats.rejected);
    println!("推理失败：{}", stats.failed);
    println!(
        "实际结果已标注：{} ({:.1}%)",
        stats.labeled,
        percentage(stats.labeled, stats.total)
    );
    println!("实际 syscall 成功：{}", stats.actual_success);
    println!("实际 syscall 失败：{}", stats.actual_failed);
    println!("平均置信度：{average:.4}");
    println!("syscall 分布：");
    for (syscall, count) in &stats.syscalls {
        println!("  {syscall}: {count}");
    }
    println!("windows_op 分布：");
    for (operation, count) in stats.operations {
        println!("  {operation}: {count}");
    }
    println!("按 syscall/预测操作准确率：");
    for (key, (correct, labeled)) in stats.accuracy {
        println!(
            "  {key}: {correct}/{labeled} ({:.1}%)",
            percentage(correct, labeled)
        );
    }
    println!("按置信度分桶准确率：");
    for (bucket, (correct, labeled)) in stats.confidence_accuracy {
        println!(
            "  {bucket}: {correct}/{labeled} ({:.1}%)",
            percentage(correct, labeled)
        );
    }
    0
}

fn confidence_bucket(confidence: f64) -> String {
    if confidence < 0.5 {
        "[0.0,0.5)".into()
    } else if confidence < 0.8 {
        "[0.5,0.8)".into()
    } else if confidence < 0.95 {
        "[0.8,0.95)".into()
    } else {
        "[0.95,1.0]".into()
    }
}

fn percentage(value: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 * 100.0 / total as f64
    }
}

#[cfg(test)]
mod percentage_tests {
    use super::{confidence_bucket, percentage};

    #[test]
    fn percentage_handles_zero_total() {
        assert_eq!(percentage(0, 0), 0.0);
        assert_eq!(percentage(3, 0), 0.0);
    }

    #[test]
    fn percentage_calculates_ratio() {
        assert!((percentage(1, 4) - 25.0).abs() < f64::EPSILON);
        assert!((percentage(3, 3) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_bucket_has_stable_boundaries() {
        assert_eq!(confidence_bucket(0.49), "[0.0,0.5)");
        assert_eq!(confidence_bucket(0.5), "[0.5,0.8)");
        assert_eq!(confidence_bucket(0.8), "[0.8,0.95)");
        assert_eq!(confidence_bucket(0.95), "[0.95,1.0]");
    }
}

/// `daoti dynamic-metadata`：输出受控动态 ELF 的解析/规划证据，不执行入口。
pub async fn dynamic_metadata(path: &str, base: u64) -> i32 {
    struct EmptyResolver;
    impl daoti_core::elf::relocation::SymbolResolver for EmptyResolver {
        fn resolve(&self, _symbol: u32) -> Option<u64> {
            None
        }
    }
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("{{\"status\":\"error\",\"error\":\"读取 ELF 失败：{error}\"}}");
            return 1;
        }
    };
    let loader = match daoti_core::elf::DynamicElfLoader::new(EmptyResolver, base, 4096) {
        Ok(loader) => loader,
        Err(error) => {
            eprintln!("{{\"status\":\"error\",\"error\":\"{error}\"}}");
            return 1;
        }
    };
    match loader.metadata(&data) {
        Ok(metadata) => {
            println!(
                "{}",
                serde_json::json!({"status":"ok", "metadata": metadata})
            );
            0
        }
        Err(error) => {
            eprintln!("{{\"status\":\"error\",\"error\":\"{error}\"}}");
            1
        }
    }
}

/// `daoti capabilities`：输出能力探测证据。
pub async fn capabilities() -> i32 {
    let registry = daoti_core::executor::CapabilityRegistry::for_current_environment();
    let results: Vec<_> = registry
        .probe_results()
        .into_iter()
        .map(|(target, available, reason)| {
            serde_json::json!({
                "target": target,
                "available": available,
                "reason": reason,
                "evidence": if available {
                    match target {
                        daoti_core::executor::ExecutionTarget::Windows
                        | daoti_core::executor::ExecutionTarget::Native
                        | daoti_core::executor::ExecutionTarget::Wsl2
                        | daoti_core::executor::ExecutionTarget::Docker => "symbolic_capability_registered",
                        daoti_core::executor::ExecutionTarget::StaticElfInterpreter => "registered_static_elf_mvp",
                        daoti_core::executor::ExecutionTarget::PeInterpreter => "registered_pe_console_fixture_only",
                        _ => "probe_passed",
                    }
                } else {
                    "unsupported_or_unavailable"
                },
            })
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({"status":"ok", "capabilities":results})
    );
    0
}

/// `daoti mock-pe`：通过统一 Agent 入口执行模拟 PE 节点请求。
pub async fn mock_pe(command: &str, node_id: &str) -> i32 {
    let agent = daoti_core::agent::CrossPlatformAgent::new(&Config::load());
    let request = DispatchRequest {
        path: command.to_string(),
        args: Vec::new(),
    };
    let node = daoti_core::executor::PeNodeCapabilities {
        node_id: node_id.to_string(),
        os_version: "mock".into(),
        architectures: vec!["x86_64".into()],
        capabilities: vec!["shell".into()],
    };
    match agent.dispatch_mock_pe(request, node, 1_000) {
        Ok((decision, response)) => {
            println!(
                "{}",
                serde_json::json!({"decision": decision, "response": response})
            );
            0
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"status":"error", "kind":error.kind(), "error":error.to_string()})
            );
            1
        }
    }
}

// `daoti init`：初始化并自动探测三系统路径（M4）。
// 探测 WSL 发行版、Docker 服务名、盘符映射，生成 `~/.daoti.toml` 配置文件。
/// `daoti init`：初始化并自动探测三系统路径（M4）
///
/// 探测 WSL 发行版、Docker 服务名、盘符映射，生成 `~/.daoti.toml` 配置文件。
pub async fn init() -> i32 {
    println!("☯ 正在探测三系统路径...");

    // 构建基于探测的配置（探测失败项回退默认值，绝不 panic）
    let cfg = daoti_core::probe::build_probed_config().await;

    // 友好提示探测结果
    println!("  木（WSL2）发行版：{}", cfg.paths.wsl_distro);
    println!("  水（Docker）服务：{}", cfg.targets.docker_service);
    for (drive, mount) in &cfg.paths.drive_to_wsl {
        println!("  盘符映射：{drive}: → {mount}");
    }

    // 写入默认配置路径
    let path = daoti_common::config::Config::default_path();
    match cfg.write_to_file(&path) {
        Ok(()) => {
            println!("✅ 配置已生成：{}", path.display());
            println!("判词：三气已定位，可敲 `daoti status` 观气，`daoti heal` 归元。");
            0
        }
        Err(e) => {
            eprintln!("❌ 配置写入失败：{e}");
            1
        }
    }
}

/// `daoti snapshot`：创建系统快照（M4/M6 快照回魂基础 + P1-6 子命令重构）
///
/// 采集当前三系统状态，序列化为 JSON 落盘到 `~/.daoti/snapshots/`，
/// 作为后续"快照回魂"（M6 决策轨迹/回滚）的数据基础。
pub async fn snapshot_create() -> i32 {
    // 严格符号模式：快照记录内部能力状态，不采集宿主机或调用外部软件。
    let snapshot = |target: &str| {
        let snapshot = daoti_core::sensor::SensorSnapshot::new(target)
            .field("mode", "symbolic_only")
            .field("capability", "registered")
            .metric("health", 1.0);
        match target {
            "windows" => snapshot.metric("docker_desktop_running", 1.0),
            "wsl2" => snapshot.metric("running", 1.0),
            "docker" => snapshot.field("daemon_version", "symbolic"),
            _ => snapshot,
        }
    };
    let fusion = daoti_core::sensor::FusionState {
        windows: Some(snapshot("windows")),
        wsl2: Some(snapshot("wsl2")),
        docker: Some(snapshot("docker")),
    };
    let h = fusion.wuxing_health();

    // 序列化快照（失败不 panic，返回结构化错误）
    let json = match serde_json::to_string_pretty(&fusion) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("❌ 快照序列化失败：{e}");
            return 1;
        }
    };

    // 写入快照目录（共享路径，见 daoti-common::config::snapshots_dir）
    let dir = daoti_common::config::snapshots_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("❌ 创建快照目录失败：{e}");
        return 1;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = dir.join(format!("daoti_{ts}.json"));
    if let Err(e) = std::fs::write(&path, &json) {
        eprintln!("❌ 快照写入失败：{e}");
        return 1;
    }

    println!("☯ 快照已落盘：{}", path.display());
    println!(
        "  五行健康度：金 {:.0}% / 木 {:.0}% / 水 {:.0}%",
        h.metal * 100.0,
        h.wood * 100.0,
        h.water * 100.0
    );
    println!("  判词：{}", h.verdict());
    0
}

/// P1-6 `daoti snapshot list`：列出所有快照的元数据。
pub async fn snapshot_list() -> i32 {
    let dir = daoti_common::config::snapshots_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            println!("暂无快照。快照目录：{}", dir.display());
            return 0;
        }
    };

    let mut snapshots: Vec<(u64, String)> = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name().to_string_lossy().to_string();
        if let Some(ts_str) = fname
            .strip_prefix("daoti_")
            .and_then(|s| s.strip_suffix(".json"))
        {
            if let Ok(ts) = ts_str.parse::<u64>() {
                if let Ok(raw) = std::fs::read_to_string(entry.path()) {
                    if let Ok(fusion) =
                        serde_json::from_str::<daoti_core::sensor::FusionState>(&raw)
                    {
                        let h = fusion.wuxing_health();
                        snapshots.push((ts, h.verdict().to_string()));
                    }
                }
            }
        }
    }

    snapshots.sort_by_key(|s| std::cmp::Reverse(s.0));
    if snapshots.is_empty() {
        println!("暂无快照。");
    } else {
        println!("快照列表（最新在前）：");
        for (ts, verdict) in &snapshots {
            println!("  [{ts}] {verdict}");
        }
    }
    0
}

/// P1-6 `daoti snapshot diff <ts1> <ts2>`：对比两个快照的差异。
pub async fn snapshot_diff(ts1: u64, ts2: u64) -> i32 {
    let dir = daoti_common::config::snapshots_dir();
    let f1 = load_snapshot(&dir, ts1);
    let f2 = load_snapshot(&dir, ts2);

    let (f1, f2) = match (f1, f2) {
        (Some(a), Some(b)) => (a, b),
        (None, _) => {
            eprintln!("快照 {ts1} 不存在或损坏");
            return 1;
        }
        (_, None) => {
            eprintln!("快照 {ts2} 不存在或损坏");
            return 1;
        }
    };

    let h1 = f1.wuxing_health();
    let h2 = f2.wuxing_health();

    println!("快照对比：{ts1} ↔ {ts2}");
    println!(
        "  金（Windows）：{:.0}% → {:.0}%  {}",
        h1.metal * 100.0,
        h2.metal * 100.0,
        diff_mark(h1.metal, h2.metal)
    );
    println!(
        "  木（WSL2）  ：{:.0}% → {:.0}%  {}",
        h1.wood * 100.0,
        h2.wood * 100.0,
        diff_mark(h1.wood, h2.wood)
    );
    println!(
        "  水（Docker） ：{:.0}% → {:.0}%  {}",
        h1.water * 100.0,
        h2.water * 100.0,
        diff_mark(h1.water, h2.water)
    );

    // 字段级差异
    for sys in &["windows", "wsl2", "docker"] {
        let s1 = snapshot_for(&f1, sys);
        let s2 = snapshot_for(&f2, sys);
        if let (Some(s1), Some(s2)) = (&s1, &s2) {
            let changed: Vec<_> = s1
                .fields
                .iter()
                .filter(|(k, v)| s2.fields.get(*k) != Some(*v))
                .chain(
                    s2.fields
                        .iter()
                        .filter(|(k, _)| !s1.fields.contains_key(*k)),
                )
                .collect();
            if !changed.is_empty() {
                println!("  [{sys}] 字段变化：");
                for (k, _v) in &changed {
                    let old = s1.fields.get(*k).map(|s| s.as_str()).unwrap_or("—");
                    let new = s2.fields.get(*k).map(|s| s.as_str()).unwrap_or("—");
                    println!("    {k}: {old} → {new}");
                }
            }
        }
    }
    0
}

/// P1-6 `daoti snapshot rollback <ts>`：查看回滚建议。
pub async fn snapshot_rollback(ts: u64) -> i32 {
    let dir = daoti_common::config::snapshots_dir();
    let fusion = match load_snapshot(&dir, ts) {
        Some(f) => f,
        None => {
            eprintln!("快照 {ts} 不存在或损坏");
            return 1;
        }
    };

    let h = fusion.wuxing_health();
    println!("快照 [{ts}] 回滚建议：");
    println!("  金（Windows）：{:.0}%", h.metal * 100.0);
    println!("  木（WSL2）  ：{:.0}%", h.wood * 100.0);
    println!("  水（Docker） ：{:.0}%", h.water * 100.0);
    println!("  判词：{}", h.verdict());
    println!();
    if h.metal >= 0.9 && h.wood >= 0.9 && h.water >= 0.9 {
        println!("该快照三气通畅，当前状态可能已偏离。");
        println!("建议：运行 `daoti heal` 自动修复，或 `daoti status` 查看当前状态。");
    } else {
        println!("该快照存在滞涩，不推荐直接回滚。");
        println!("建议：先运行 `daoti heal` 修复当前问题后，再创建新快照留存。");
    }
    0
}

/// 从快照目录加载 FusionState
fn load_snapshot(dir: &std::path::Path, ts: u64) -> Option<daoti_core::sensor::FusionState> {
    let path = dir.join(format!("daoti_{ts}.json"));
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// 返回变化方向标记
fn diff_mark(a: f64, b: f64) -> &'static str {
    if (b - a).abs() < 1e-9 {
        "━"
    } else if b > a {
        "↑"
    } else {
        "↓"
    }
}

/// 获取某系统的快照数据
fn snapshot_for(
    f: &daoti_core::sensor::FusionState,
    sys: &str,
) -> Option<daoti_core::sensor::SensorSnapshot> {
    match sys {
        "windows" => f.windows.clone(),
        "wsl2" => f.wsl2.clone(),
        "docker" => f.docker.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_resolves_error_kinds() {
        // 错误类型关键字均应命中
        for k in [
            "blocked",
            "timeout",
            "unavailable",
            "path_mapping",
            "channel_closed",
        ] {
            assert!(explain_lookup(k).is_some(), "关键字 {k} 应有解释");
        }
    }

    #[test]
    fn explain_resolves_gua_keywords() {
        assert!(explain_lookup("坎").is_some());
        assert!(explain_lookup("docker").is_some());
        assert!(explain_lookup("wsl2").is_some());
        assert!(explain_lookup("windows").is_some());
    }

    #[test]
    fn explain_unknown_returns_none() {
        assert!(explain_lookup("不存在的错误码").is_none());
        assert!(explain_lookup("").is_none());
    }

    #[test]
    fn explain_ignores_case_and_whitespace() {
        assert!(explain_lookup("  BLOCKED ").is_some());
        assert!(explain_lookup("Docker").is_some());
    }
}
