//! 驭灵 · 令牌 CLI (daoti-cli)
//!
//! 对应《产品形态.md》"令牌（CLI）"。统一命令 `status / heal / explain / run / init / snapshot`，
//! 屏蔽 PowerShell/CMD/Bash 差异。M0 先建立 clap 命令骨架与 `--version`。

use clap::{Parser, Subcommand};

mod commands;
use commands::parse_u64;
mod daemonctl;

/// 驭灵 · 系统气运守护者（CLI 令牌）
#[derive(Debug, Parser)]
#[command(name = "daoti", version = daoti_common::logging::VERSION, about = "驭灵：道体跨平台智能调度守护者")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 查看三系统状态（金/木/水）
    Status,
    /// 自动诊断并修复三系统问题
    Heal,
    /// 解释某个错误码的推演过程
    Explain {
        /// 错误码或错误关键字
        code: String,
    },
    /// 在正确平台执行命令
    Run {
        /// 目标平台：windows / wsl2 / docker（不指定时自动识别二进制格式）
        #[arg(long = "target", short = 't')]
        target: Option<String>,
        /// 要执行的命令或二进制路径
        #[arg(required = true, num_args = 1..)]
        cmd: Vec<String>,
    },
    /// 初始化：自动探测三系统路径并生成配置
    Init,
    /// 创建/回滚/对比系统快照
    Snapshot {
        #[command(subcommand)]
        action: Option<SnapshotAction>,
    },
    /// 使用统一 Agent 入口执行模拟 macOS 节点请求
    MockMacos {
        /// 要模拟执行的命令
        command: String,
        /// 模拟节点标识
        #[arg(long, default_value = "mock-mac")]
        node: String,
    },
    /// 探测二进制格式并输出调度决策（不执行）
    Dispatch {
        /// 二进制文件路径
        path: String,
    },
    /// 从 Linux/Wine 源码提取并输出 M1 JSON 数据集
    TrainBilateral {
        /// Linux syscall 头文件或源码路径
        #[arg(long)]
        linux: String,
        /// Wine syscall 源码路径
        #[arg(long)]
        wine: String,
        /// 输出 JSON 数据集路径
        #[arg(long)]
        output: String,
    },
    /// 使用规则教师标签训练三平台调度模型
    TrainDispatchModel {
        /// 输出模型路径
        #[arg(long)]
        output: String,
        /// 模型最低置信度
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f64,
    },
    /// 汇总影子推理 JSONL 记录
    ShadowSummary {
        /// JSONL 输入文件路径
        #[arg(long)]
        input: String,
        /// 置信度阈值
        #[arg(long, default_value_t = 0.5)]
        threshold: f64,
    },
    /// 输出受控动态 ELF 的结构化 metadata（仅解析/规划，不执行）
    DynamicMetadata {
        /// 动态 ELF 文件路径
        path: String,
        /// 装载首选基址
        #[arg(long, default_value = "0x400000", value_parser = parse_u64)]
        base: u64,
    },
    /// 输出当前环境的真实执行能力（不把 mock 当作能力）
    Capabilities,
    /// 使用双梯形网络执行一次只读推理并输出审计结果
    InferBilateral {
        /// 双梯形权重文件路径
        #[arg(long, default_value = "knowledge/glibc_network.daotiblt")]
        weights: String,
        /// Linux x86_64 syscall 编号
        #[arg(long, default_value_t = 1)]
        nr: i32,
        /// syscall 名称
        #[arg(long, default_value = "write")]
        name: String,
        /// 发起线程 ID
        #[arg(long, default_value_t = 1)]
        tid: u64,
    },
    /// 对单条 syscall 执行模型先导、CLI 确认和受控映射
    PilotSyscall {
        /// Linux x86_64 syscall 编号
        nr: i32,
        /// syscall 名称
        name: String,
        /// 发起线程 ID
        #[arg(long, default_value_t = 1)]
        tid: u64,
        /// 明确确认执行；必须精确输入 yes
        #[arg(long)]
        confirm: Option<String>,
        /// syscall 参数；write 的参数会进入审计缓冲区
        #[arg(long = "arg", num_args = 0..)]
        args: Vec<String>,
    },
    /// 对动态 ELF 装载状态执行只读模型推理和安全门控
    InferDynamic {
        /// 动态 ELF 文件路径
        path: String,
        /// 双梯形权重文件路径
        #[arg(long, default_value = "knowledge/glibc_network.daotiblt")]
        weights: String,
        /// 装载首选基址
        #[arg(long, default_value = "0x700000", value_parser = parse_u64)]
        base: u64,
    },
    /// 导入不可变影子记录并生成阶段5数据集清单
    Stage5Import {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
    },
    /// 评估阶段5影子数据集并输出监控指标
    Stage5Evaluate {
        #[arg(long)]
        input: String,
        #[arg(long, default_value_t = 0.95)]
        threshold: f64,
    },
    /// 发布或回滚阶段5权重版本
    Stage5Release {
        #[arg(long)]
        root: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        weights: Option<String>,
        #[arg(long)]
        dataset: Option<String>,
        #[arg(long)]
        rollback: bool,
    },
    /// 执行阶段7发布前置检查并输出 JSON 证据
    Stage7Preflight {
        #[arg(long, default_value = "v0.1.0")]
        version: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// 使用统一 Agent 入口执行模拟 PE 节点请求
    MockPe {
        /// 要模拟执行的命令
        command: String,
        /// 模拟节点标识
        #[arg(long, default_value = "mock-pe")]
        node: String,
    },
    /// 守护进程生命周期管理（启动/停止/状态/重启）
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
}

/// `daoti snapshot` 子命令（P1-6）
#[derive(Debug, Subcommand)]
pub enum SnapshotAction {
    /// 创建新快照（默认行为）
    Create,
    /// 列出所有快照
    List,
    /// 对比两个快照的差异
    Diff {
        /// 快照时间戳 1（unix 秒）
        ts1: u64,
        /// 快照时间戳 2（unix 秒）
        ts2: u64,
    },
    /// 查看回滚建议（回滚到指定快照的状态）
    Rollback {
        /// 目标快照时间戳（unix 秒）
        ts: u64,
    },
}

/// `daoti daemon` 子命令
#[derive(Debug, Subcommand)]
pub enum DaemonAction {
    /// 后台启动守护进程
    Start {
        /// 监听端口（默认 17890）
        #[arg(long, default_value_t = 17890)]
        port: u16,
    },
    /// 停止守护进程
    Stop,
    /// 查询守护进程状态
    Status,
    /// 重启守护进程
    Restart {
        /// 监听端口（默认 17890）
        #[arg(long, default_value_t = 17890)]
        port: u16,
    },
}

#[tokio::main]
async fn main() {
    daoti_common::logging::init(&daoti_common::config::Config::default().log);
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Command::Status => commands::status().await,
        Command::Heal => commands::heal().await,
        Command::Explain { code } => commands::explain(&code).await,
        Command::Run { target, cmd } => commands::run(target.as_deref(), &cmd.join(" ")).await,
        Command::Init => commands::init().await,
        Command::MockMacos { command, node } => commands::mock_macos(&command, &node).await,
        Command::Dispatch { path } => commands::dispatch(&path).await,
        Command::TrainBilateral {
            linux,
            wine,
            output,
        } => commands::train_bilateral(&linux, &wine, &output).await,
        Command::TrainDispatchModel {
            output,
            min_confidence,
        } => commands::train_dispatch_model(&output, min_confidence).await,
        Command::ShadowSummary { input, threshold } => {
            commands::shadow_summary(&input, threshold).await
        }
        Command::DynamicMetadata { path, base } => commands::dynamic_metadata(&path, base).await,
        Command::Capabilities => commands::capabilities().await,
        Command::InferBilateral {
            weights,
            nr,
            name,
            tid,
        } => commands::infer_bilateral(&weights, nr, &name, tid).await,
        Command::PilotSyscall {
            nr,
            name,
            tid,
            confirm,
            args,
        } => {
            commands::pilot_syscall(nr, &name, tid, &args, confirm.as_deref() == Some("yes")).await
        }
        Command::InferDynamic {
            path,
            weights,
            base,
        } => commands::infer_dynamic(&path, &weights, base).await,
        Command::Stage5Import { input, output } => commands::stage5_import(&input, &output).await,
        Command::Stage5Evaluate { input, threshold } => {
            commands::stage5_evaluate(&input, threshold).await
        }
        Command::Stage5Release {
            root,
            version,
            weights,
            dataset,
            rollback,
        } => {
            commands::stage5_release(
                &root,
                &version,
                weights.as_deref(),
                dataset.as_deref(),
                rollback,
            )
            .await
        }
        Command::Stage7Preflight { version, output } => {
            commands::stage7_preflight(&version, output.as_deref()).await
        }
        Command::MockPe { command, node } => commands::mock_pe(&command, &node).await,
        Command::Snapshot { action } => match action.unwrap_or(SnapshotAction::Create) {
            SnapshotAction::Create => commands::snapshot_create().await,
            SnapshotAction::List => commands::snapshot_list().await,
            SnapshotAction::Diff { ts1, ts2 } => commands::snapshot_diff(ts1, ts2).await,
            SnapshotAction::Rollback { ts } => commands::snapshot_rollback(ts).await,
        },
        Command::Daemon { action } => match action {
            DaemonAction::Start { port } => daemonctl::start(Some(port)).await,
            DaemonAction::Stop => daemonctl::stop().await,
            DaemonAction::Status => daemonctl::status().await,
            DaemonAction::Restart { port } => daemonctl::restart(Some(port)).await,
        },
    };

    std::process::exit(exit_code);
}
