# 驭灵（道体）开发计划与技术方案（Technical Plan）

> ## 最终目标（北极星 · 不可变）
>
> **驭灵最终必须实现 Windows / Linux / macOS 三平台任意软件互调：任意平台的二进制文件，在任意其他平台上无差别执行。**
>
> 当前所有阶段性方案（B0 / B1 / B2）均是通往此目标的**路径**，不是对目标的替代或缩窄。任何「当前仅支持 X→Y」的表述均为**阶段性聚焦**，macOS 等其余方向已在路线图中。

> 文档版本：v1.0
> 编制角色：需求定义 / 规范定义智能体（The Specifier）
> 依据文档：
> - g:\Yl\产品形态.md
> - g:\Yl\道体跨平台智能调度系统设计方案.md
> - g:\Yl\驭灵 UIUX 设计规范.md
> - g:\Yl\rust语言开发.md
> 技术栈裁决：**Rust 为主**（AI 生成代码，零学习成本权衡，享内存安全与零成本抽象红利）
>
> ## 当前路线裁决（执行宪法 · 2026-08-17 长期方向对齐）
>
> **当前主路线：本地二进制信号重映射（B1/B2 终极形态）为唯一主干，不搞双轨并行。**
>
> 1. **主干定位**：跨平台运行的唯一主干是「本地二进制信号重映射」——进程级 syscall 拦截 → 查表转换 → 注入目标平台（Windows 上本地执行 Linux ELF，同理互换）。这一步到位，不做「先 WSL2 后推翻」的双轨路径。
> 2. **WSL2 降级为可选加速路径**：WSL2 可用时，作为 ELF 执行的快速通道（对用户透明）；WSL2 不可用时**不报错**，自动切回本地重映射路径（哪怕慢、哪怕暂时只覆盖文件读写类 syscall）。**诊断 UI 不再把「WSL2 不可达」显示为红色错误**，而是显示「ELF 执行模式：本地重映射（实验性）」。
> 3. **Remote（远程节点）为远期选项**：仅在本地无法承载的场景（如 macOS 专属硬件）使用，不是当前交付的依赖项，不占主干排期。
> 4. **B1/B2 升格为主干的正式载体**：B1 规则映射即本地重映射的**逻辑层**（syscall→Win32 双向对称），B2 双梯形网络为未来数据增强层。不再是「默认关闭的实验分支」。
> 5. **交付节奏（按 syscall 分组渐进）**：文件读写类（10 条）→ 内存管理类（10 条）→ 进程/线程类（10 条）→ 设备/网络类（10 条）。**每一组完成后，该组覆盖的程序即可在目标平台本地直跑**，用户看到的是「驭灵跑通了一个 Linux 程序」，而不是「驭灵调用了 WSL2」。
> 6. **Mach-O 边界**：在 ELF 路径跑通 ≥50 常见 syscall 之前，Mach-O 保持「macOS 执行：开发中」的识别状态，**不作为失败显示**、不发送远程节点。
>
> **禁止事项（硬性）**：
> - ❌ 禁止以「WSL2 可用」为验收先决条件构建 ELF 执行宣称。
> - ❌ 禁止把「WSL2 不可达」写成红色失败——那是环境能力边界，不是故障。
> - ❌ 禁止未完成本地重映射主干前，把 Remote 节点作为替代交付。
> - ✅ 北极星仍然有效；所有阶段交付以「本地可验证」为准。

---

## 0. 本计划的性质与阅读约定

本文件是**契约性规范**，不是实现代码。它回答"要做什么、以什么顺序做、怎么证明做完了"。所有后续实现必须能在此计划中找到自己的位置并被验收。

**计划的核心约束（来自《rust语言开发.md》施工蓝图）：**
1. 全项目**禁止手写复杂生命周期 `<'a, T>`**，跨线程共享状态一律 `Arc<tokio::sync::Mutex<T>>`。
2. 感知层/推演层/执行层之间**禁止共享内存**，一律通过 `tokio::sync::mpsc` 消息通道（Actor 模型）。
3. 推演层采用**确定性规则引擎**（`decision::engine`：五行健康度 → 卦象 → 调度决策），经 `InferenceEngine` trait 可插拔；不依赖外部模型权重（onnx 已废弃移除）。
4. 执行器用 `PlatformExecutor` trait 多态 + 工厂按 `target` 字段分派。
5. 错误处理统一 `anyhow` + `thiserror`，**全局禁止 `.unwrap()` / `.expect()`**，一律 `?`。

**产品形态（三体合一）：**
- 内核（Daemon）：常驻后台守护进程，静默监听三系统。
- 令牌（CLI）：`daoti status / heal / explain / run / init` 统一命令。
- 玄镜（UI）：Web/桌面仪表盘，可视化经络图（可选交付）。

---

## 1. 项目总体架构

### 1.1 逻辑分层（与设计方案.md 五层对应）

| 设计文档层 | Rust 层 | 说明 |
|---|---|---|
| 用户交互层 | `ui` + `cli` | CLI 主令牌；UI 为可选 Web 仪表盘 |
| 感知层 (Sensor) | `core::sensor` | Windows/WSL2/Docker 三感知器 + 状态融合编码 |
| 推演层 (Inference) | `core::decision::engine` | 规则引擎（五行映射表）经 `InferenceEngine` trait 推演 |
| 调度输出层 (Action) | `core::decision` | 卦象→调度策略→平台自适应指令 |
| 执行层 (Execution) | `core::executor` | `PlatformExecutor` trait + 安全执行器 |

### 1.2 Cargo Workspace 结构

采用**单一 workspace、多 crate** 划分。crate 边界即物理依赖边界，避免循环依赖：

```
daoti/                          # workspace 根
├── Cargo.toml                  # [workspace] 成员声明 + 依赖统一管理
├── rust-toolchain.toml
├── crates/
│   ├── daoti-core/             # 纯库：感知/推演/决策/执行，无 IO 主循环
│   ├── daoti-daemon/           # 常驻守护进程二进制（后台哨兵 + Actor 编排）
│   ├── daoti-cli/              # CLI 二进制（令牌）
│   ├── daoti-ui/               # 玄镜 UI（Bun + Tauri 宿主，可选特性，独立交付；前端为 Bun 构建，经 HTTP/SSE 只读 daemon）
│   └── daoti-common/           # 共享错误、事件类型、配置、日志工具（被各 crate 引用）
├── daoti-ui-web/               # 玄镜前端（Bun/React-Vue 源码，独立于 Rust workspace 构建）
├── models/                     # （已废弃）原 onnx 权重目录，onnx 推演移除后不再需要
├── scripts/                    # 构建/打包/路径探测脚本
├── docs/                       # 技术文档 + HCSE 审计清单（本目录）
└── tests/                      # 跨 crate 集成测试（可选放 workspace 级）
```

**依赖方向（禁止反向）：**

```
              ┌─────────────── HTTP/SSE 只读 ───────────────┐
              ▼                                             │
daoti-ui-web  │  (Bun 前端，独立 workspace，不链接 core)      │
   │  Tauri 宿主daoti-ui ──> daoti-core                     │
daoti-cli ──> daoti-core <── daoti-daemon                   │
    │                 │                                     │
    └──── daoti-core ─┴─> daoti-common                      │
                            ▲                               │
                            └────────── 事件总线（唯一数据源）│
```

- `daoti-common` 是最底层，不依赖任何业务 crate。
- `daoti-core` 是纯逻辑核心，**不包含 `main`，不启动 tokio 运行时**，便于单元测试。
- `daoti-daemon` / `daoti-cli` / `daoti-ui` 才各自装配运行时与入口。
- `daoti-ui-web`（Bun 前端）**不在 Rust workspace 内**，不链接 `daoti-core`；仅经 daemon 的 HTTP/SSE 出口只读消费 `DaotiEvent`（R8 单一数据源）。

### 1.3 关键抽象（契约）

```
trait PlatformExecutor {
    async fn execute(&self, cmd: &CommandSpec) -> Result<ExecResult, ExecutionError>;
}
```

- `WindowsExecutor`（PowerShell）、`Wsl2Executor`（wsl 桥接）、`DockerExecutor`（docker CLI）。
- 调度指令携带 `target` 字段，通过工厂 `ExecutorFactory` 动态分派。
- 感知器统一接口：`trait Sensor { async fn collect(&self) -> SensorState; }`。

---

## 2. 里程碑与阶段划分

遵循《设计方案.md》Phase 1–5，映射为 **Rust 实施的 M0–M6**。每个里程碑必须**可独立编译、可独立验收**，严禁跨里程碑批量实现。

| 里程碑 | 对应文档 Phase | 目标 | 验收红线 |
|---|---|---|---|
| **M0 骨架** | 前置 | workspace 可编译、三体二进制占位、CI 冒烟 | `cargo build --workspace` 成功；`daoti --version` 输出 |
| **M1 感知层** | Phase 1 | 三感知器 + 状态融合，可在 CLI 打印三系统状态 | `daoti status` 正确输出金/木/水状态 |
| **M2 道体集成** | Phase 2 | 规则引擎推演（五行→卦象→调度策略） | 三气健康度推演给出卦象与判词；`InferenceEngine` trait 可插拔 |
| **M3 执行层** | Phase 3 | `PlatformExecutor` 三实现 + 安全执行器 + 回滚 | 超时/拒绝命令/失败均有结构化返回，无 panic |
| **M4 主控集成** | Phase 4 | `daoti heal / explain / run` 全链路 | 端到端诊断-推演-执行-二次感知闭环 |
| **M5 Daemon + UI** | Phase 4 延伸 | 常驻守护 + 事件推送 + 玄镜 UI（可选） | 守护进程无界面常驻；UI 展示经络图与时间轴 |
| **M6 学习与优化** | Phase 5 | 决策轨迹持久化 + Hebbian 学习预留 + 参数库扩充 | 决策日志落盘、可回放，学习模块为可关特性 |

### 2.1 当前执行编排路线（执行宪法对齐版 · 2026-08-17）

本节优先级高于旧的 B0/B1/B2 叙事；后续实现按此顺序推进，每个阶段独立编译、测试和验收，未通过不得进入下一阶段。
**主干纪律：本地二进制信号重映射为唯一交付主干；WSL2 为可选加速路径，不作为验收先决条件。**

| 优先级 | 任务 | 交付边界 | 完成标准 |
|---|---|---|---|
| **L0** | 本地重映射基础设施 | 本地执行器骨架：ELF 加载器（解析节/入口）+ 内存沙箱 + syscall 拦截桩（Windows Debug API / ptrace 二选一），不要求全量格式 | 最小 ELF 能加载并停在第一条 syscall；拦截桩可捕获并转交映射器；有独立测试 |
| **L1** | 第一组 syscall（文件读写类 10 条） | open/read/write/close/stat/fstat/lseek/access/getcwd 等；映射表 B1 对称扩充到该组 | 覆盖该组的 Linux 程序（如 `cat`、`echo`）在 Windows 本地直跑，**不依赖 WSL2**；双向上伪造证（B1 对称 20→30 条） |
| **L2** | 第二组 syscall（内存管理类 10 条） | mmap/munmap/brk/mprotect 等；进程内存表 | 依赖 mmap 的 ELF 程序本地运行；brk 语义与 Win32 虚拟内存对齐单测通过 |
| **L3** | 第三组 syscall（进程/线程类 10 条） | getpid/gettid/exit/rt_sigaction/wait 等；线程模型映射 | 多线程 ELF 样例本地运行，退出码/信号正确；竞态与取消路径有测试 |
| **L4** | 第四组 syscall（设备/网络类 10 条） | ioctl/pipe/dup/readv/writev 等；管道与 fd 复用 | pipe 通信样例本地贯通；readv/writev 聚合语义正确 |
| **L5**（远期） | Mach-O 执行 | ELF 路径覆盖率 ≥50 常见 syscall 前**不实现**；UI 显示「macOS 执行：开发中」 | 任何场景都不把 Mach-O 未执行显示为失败；UI 状态为「开发中」非红色错误 |

**本路线的禁止事项：** 未完成 L0 前不得宣称 ELF 本地执行；未完成 L1 前不得把「WSL2 可达」当作跨平台验收证据；任何阶段不得把「WSL2 不可达」渲染为红色失败；未达到 L5 前置条件前不得实现 Mach-O 执行；不得把 B1/B2 的逻辑测试描述为真实跨平台执行。

---

## 3. 模块开发顺序（分步实施，严禁批量）

> 每个步骤给出**输出物**与**验收标准**。实现者必须在通过验收后才能进入下一步。

### 步骤 1：Workspace 骨架（M0）
- **输出**：`Cargo.toml`（workspace）、`daoti-common` 空壳、`daoti-core` 空壳、`daoti-cli` 空壳（`daoti --version`）、`daoti-daemon` 空壳（`--daemon` 标志位占位）、`rust-toolchain.toml`。
- **验收**：`cargo build --workspace` 零警告通过；`daoti --version` 打印 `daoti x.y.z`；`cargo test --workspace` 通过（含冒烟测试）。

### 步骤 2：通用层（daoti-common）
- **输出**：`DaotiError`（thiserror 枚举：管道断/命令超时/模型缺失/路径映射失败/配置错误）、事件类型 `DaotiEvent`、配置结构（serde）、`tracing` 日志初始化。
- **验收**：错误枚举可被序列化并携带上下文；配置从 TOML/环境变量加载并可回退默认值；单元测试覆盖错误分类。

### 步骤 3：感知层（daoti-core::sensor）（M1）
- **输出**：`WindowsSensor`、`Wsl2Sensor`、`DockerSensor`（实现 `Sensor` trait）、`StateFusionEncoder`（把三态编码为状态向量，为后续推演预留）。
- **验收**：每个感知器对"系统不存在/命令不可用"返回 `SensorState::Unavailable` 而非 panic；Docker 端点多候选自动探测带 3s 超时；`cargo test` 用 mock 命令验证解析。

### 步骤 4：执行层（daoti-core::executor）（M3，可提前）
- **输出**：`PlatformExecutor` trait、三实现、`ExecutorFactory`、`SafeCommandExecutor`（白名单 + 禁止模式 + 超时 + 回滚）。
- **验收**：危险命令被拦截并返回 `ExecutionError::Blocked`；超时命令返回 `ExecutionError::Timeout`；注入测试验证 `shell=false` 防注入。

### 步骤 5：推演与决策层（daoti-core::decision / engine）（M2）
- **输出**：`decision::engine`（`InferenceEngine` trait + `RuleEngine` 规则引擎）、`CrossPlatformCausalAdapter`（卦象→五行→调度策略）、`PlatformCommandGenerator`。
- **验收**：三气健康度经 `RuleEngine` 确定性推演出卦象与判词；`daemon::actor` 经 trait 调用，行为不回归。

### 步骤 6：CLI 令牌（daoti-cli）（M4 部分）
- **输出**：clap 子命令 `status / heal / explain / run / init / snapshot`，跨平台无感执行。
- **验收**：`daoti heal` 完成"感知→推演→执行→二次感知"闭环并输出耗时；`daoti explain <err>` 输出白话判词；命令超时给兜底反馈。

### 步骤 7：Daemon 常驻（daoti-daemon）（M5 部分）
- **输出**：后台哨兵，监听三系统事件，通过 channel 推演，日志/时间轴落盘。
- **验收**：无界面常驻；收到事件自动唤醒推演；进程可被优雅停止。

### 步骤 8：玄镜 UI（daoti-ui + daoti-ui-web）（M5 可选）
- **输出**：`daoti-ui-web`（Bun/React-Vue 前端，独立 workspace）+ `daoti-ui`（Tauri 宿主）；三环八卦图、决策时间轴、快照回魂。
- **验收**：按《驭灵 UIUX 设计规范》色彩/组件实现；UI 为可选 feature，不阻塞 M0–M4；前端仅经 daemon HTTP/SSE 出口只读取数（R8），零系统命令调用（Bun 红线）。

### 步骤 9：学习与参数库（daoti-core::learning）（M6）
- **输出**：决策轨迹持久化、Hebbian 学习预留接口、参数库加载。
- **验收**：学习为 `feature` 开关；轨迹可回放；默认关闭不影响主链路。

---

## 4. 目录结构规划（详细）

```
g:\Yl\
├── Cargo.toml
├── rust-toolchain.toml
├── .cargo/config.toml
├── crates/
│   ├── daoti-common/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs          # DaotiError (thiserror)
│   │       ├── event.rs          # DaotiEvent (感知/推演/执行/结果事件)
│   │       ├── config.rs         # 配置加载
│   │       └── logging.rs        # tracing 初始化
│   ├── daoti-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── sensor/
│   │       │   ├── mod.rs        # Sensor trait
│   │       │   ├── windows.rs
│   │       │   ├── wsl2.rs
│   │       │   ├── docker.rs
│   │       │   └── fusion.rs     # StateFusionEncoder
│   │       ├── decision/
│   │       │   ├── mod.rs
│   │       │   ├── engine.rs        # InferenceEngine trait + RuleEngine
│   │       │   ├── causal_adapter.rs # CrossPlatformCausalAdapter
│   │       │   └── command_gen.rs    # PlatformCommandGenerator
│   │       ├── executor/
│   │       │   ├── mod.rs        # PlatformExecutor trait + factory
│   │       │   ├── windows.rs
│   │       │   ├── wsl2.rs
│   │       │   ├── docker.rs
│   │       │   └── safe.rs       # SafeCommandExecutor 白名单/超时/回滚
│   │       └── learning/
│   │           ├── mod.rs
│   │           └── trace.rs      # 决策轨迹持久化
│   ├── daoti-daemon/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       └── actor.rs          # mpsc 编排：sensor→decision(engine)→executor
│   ├── daoti-cli/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       └── commands.rs       # status/heal/explain/run/init/snapshot
│   └── daoti-ui/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           └── api.rs            # 桥接 core（可选，或独立 Web 服务）
├── models/                        # （已废弃）原 onnx 权重目录，onnx 推演移除后不再需要
├── scripts/
│   ├── build.ps1
│   ├── detect-paths.ps1          # daoti init 路径探测
│   └── download-models.ps1
├── docs/
│   ├── 开发计划-TechnicalPlan.md  # 本文件
│   └── HCSE_*.md                 # 项目 HCSE 审计清单（见第 8 节）
└── tests/                        # 跨 crate 集成测试
```

**crate 边界约定：**
- `daoti-common` 不得依赖 `daoti-core` 及上层。
- `daoti-core` 不得依赖任何二进制 crate。
- UI crate 通过 `daoti-core` 公开 API 通信，不直接触碰感知/执行内部。

---

## 5. 依赖清单（crates.io 选型建议）

### 5.1 运行时与异步
| crate | 用途 | 版本建议 |
|---|---|---|
| `tokio` | 异步运行时、`sync::Mutex`、`sync::mpsc`、超时 | 1.x（`rt-multi-thread`、`time`、`macros`） |
| `tokio-util` | `CancellationToken` 取消传播 | 0.7 |

### 5.2 推演（规则引擎）
| 模块 | 用途 | 备注 |
|---|---|---|
| `decision::engine` | `InferenceEngine` trait + `RuleEngine`（五行映射表） | 确定性推演，始终可用，不依赖外部权重（onnx 已废弃移除） |

### 5.3 CLI
| crate | 用途 |
|---|---|
| `clap` | 子命令解析（derive） |

### 5.4 HTTP/SSE 事件出口（Daemon）
| crate | 用途 |
|---|---|
| `axum` | HTTP 路由 + SSE（`/api/health`、`/api/events`、`/api/snapshots`、`/api/snapshots/{ts}`） |
| `tower-http` | CORS 白名单（`cors` feature） |
| `futures-util` | SSE 事件流 `Stream` 转换 |
| `tokio-util` | `CancellationToken` 优雅关闭 |

### 5.5 错误与序列化
| crate | 用途 |
|---|---|
| `anyhow` | 应用层快速错误传播 |
| `thiserror` | 定义 `DaotiError` 域错误枚举 |
| `serde` / `serde_json` | 配置、事件、调度指令序列化 |

### 5.6 日志与观测
| crate | 用途 |
|---|---|
| `tracing` / `tracing-subscriber` | 结构化日志（时间轴/决策轨迹） |
| `tracing-appender` | 日志落盘（Daemon） |

### 5.7 进程与系统
| crate | 用途 |
|---|---|
| `tokio::process` | 启动 PowerShell / wsl / docker 子进程（避免 shell） |
| `sysinfo` | CPU/内存采集（可选，Windows 感知器） |
| `windows-sys` / `winapi` | Windows 命名管道 / 服务检测（按需 feature） |

### 5.8 测试
| crate | 用途 |
|---|---|
| `tokio` (test) | 异步测试 |
| `tempfile` | 临时文件/快照测试 |
| `mockall` 或手写 trait mock | 感知器/执行器依赖注入模拟 |

### 5.9 依赖治理规则
- 所有依赖集中到 workspace 根 `Cargo.toml` 的 `[workspace.dependencies]`，子 crate 引用，避免版本漂移。
- 危险/未维护 crate 需在评审中说明；重依赖（如 `sysinfo`）通过 feature 隔离，保证核心链路可独立编译测试。

---

## 6. 风险与缓解

| # | 风险 | 影响 | 缓解策略 |
|---|---|---|---|
| R1 | **推演规则覆盖不足** | 特殊故障组合无法命中规则 | 规则引擎基于五行映射表 + 三器状态，覆盖畅通/单系统异常/多系统异常；`heal` 未修复时明确提示人工检查，不静默通过。**砍掉 onnx 后规则引擎为唯一推演源，需持续扩充五行映射与新故障模式覆盖（经决策轨迹回放驱动）** |
| R2 | **PowerShell 中文乱码** | CLI/感知输出乱码 | 统一以 UTF-8 设置 `$OutputEncoding` / `[Console]::OutputEncoding`；Rust 侧强制 UTF-8 解码并兜底 `lossy`；所有命令输出编码在集成测试断言 |
| R3 | **跨系统路径映射** | Windows 盘符 vs WSL `/mnt` 混乱 | `daoti init` 自动探测并写入路径映射表（如 `C:\` ↔ `/mnt/c`）；`daoti run` 自动判断目标系统并转换路径；提供显式映射 API 供 UI 展示 |
| R4 | **命令超时/卡死** | 守护进程被卡死拖垮 | 所有子进程执行强制 `tokio::time::timeout`；`SafeCommandExecutor` 全局超时兜底；`CancellationToken` 支持取消清理；超时后返回结构化错误并尝试回滚 |
| R5 | **跨系统命令注入** | 安全漏洞 | 一律 `shell=false`（`Command::arg` 传参，不拼字符串）；`SafeCommandExecutor` 白名单 + 禁止模式双重校验 |
| R6 | **Docker 端点不稳定** | 感知失败 | 多端点候选 + 3s 超时自动探测；全部失败返回 `Unavailable` 而非 panic |
| R7 | **Daemon 内存/常驻稳定性** | 长期运行泄漏 | 严格 `Arc<Mutex>` + mpsc，避免共享内存竞态；泄漏用 `cargo miri`/压力测试验证 |
| R8 | **UI 与 CLI 数据不一致** | 展示漂移 | UI 只读 daemon 发布的 `DaotiEvent` 时间轴，单一数据源，不各自造数据 |

---

## 7. 测试策略

遵循用户 **HCSE 五层交互韧性审计模型** 与 **韧性验证规范**（超时/卡死/错误/取消路径）。

### 7.1 单元测试（每个 crate）
- 感知器解析（mock 命令输出）、错误分类、配置回退、路径映射、命令生成模板。
- 覆盖边界：空输入、缺失字段、异常输出、极端数值（0 容器 / 100% CPU / 海量容器）。

### 7.2 集成测试（跨 crate）
- CLI 全链路：`init → status → heal → explain` 端到端（纯规则推演，无外部权重依赖）。
- 执行器三实现 + 回滚链路的真实命令（在可控环境跑）。
- Docker 多端点自动探测（构造可达/不可达端点）。

### 7.3 韧性测试（HCSE 五层模型映射）

| 层级 | 对应场景 | 必测异常路径 |
|---|---|---|
| L1 一级页面 | CLI/Daemon 主链路 | 加载失败 / 数据为空 / 命令超时 |
| L2 二级弹窗 | UI 模态框、推演详情 | 打开失败 / 操作超时 / 取消中断 |
| L3 三级卡片 | UI 三环卡片、日志条目 | 卡片加载失败 / 交互无响应 |
| L4 四级嵌套 | UI 内按钮/表单、快照回魂 | 嵌套操作超时 / 状态不恢复 |
| L5 异常全局 | 跨层级 | 网络断开 / 进程崩溃 / 资源耗尽 |

**异常路径强制清单（每个 invoke/子进程调用必须覆盖）：**
- **超时路径**：子进程长时间无响应 → 有兜底反馈（错误提示 + 状态恢复），`timeout` 真正触发。
- **卡死路径**：底层调用永不返回 → 系统能恢复（`CancellationToken` + 超时），UI 不退死。
- **错误路径**：失败 → 明确错误提示 + 状态恢复（不 panic）。
- **取消路径**：用户取消 → 正确中断 + 清理（kill 子进程、释放句柄）。

**验证方式**：通过注入 mock executor 构造"永不返回/超时/失败"三种假执行器，断言系统行为。

### 7.4 安全测试
- 白名单/禁止模式注入用例（`rm -rf`、`format`、`Remove-Item -Recurse -Force C:\` 等被拦截）。
- `shell=false` 验证：含分号/管道拼接的恶意输入不被执行。

### 7.5 性能基线
- 冷启动 < 1s（纯规则引擎，无外部权重/解释器初始化）。
- 常驻内存基线轻量（**无 onnx 权重常驻**；主要受感知循环、mpsc actor 与 SSE 长连接影响）。
- 感知并行采集，全链路 heal 目标 ≤ 数秒。

---

## 8. 文档同步机制

目标：**技术文档与代码始终一致**，避免文档漂移。

1. **单源文档索引**：本文件为开发计划的单一权威来源（TechnicalPlan），任何里程碑改动先改此处。
2. **HCSE 项目审计清单**：在 `docs/` 下建立 `HCSE_RELEASE_PROTOCOL.md` 与 `HCSE_RESILIENCE_AUDIT.md`（若不存在），将第 7 节的韧性/发布检查项落为清单。
3. **模块-文档绑定**：每个 crate 的 `src/lib.rs` 顶部注释标注对应设计方案章节；新增模块时同步更新本文件第 4 节目录结构。
4. **接口契约同步**：`PlatformExecutor` / `Sensor` / `DaotiEvent` 等公共类型变更，必须同步更新本文件第 1.3 节与相关文档。
5. **风险回写**：按 HCSE 规则，智能体未预警的新故障模式，事后必须回写 `docs/HCSE_*.md` 项目清单。
6. **PR 描述逐项回应**：智能体返回的风险清单，PR 中须逐项回应（已修复/已确认可接受/待跟踪）。
7. **验收驱动**：每个里程碑交付时，检查对应文档章节是否与实际代码一致，不一致则先修文档再合入。

---

## 9. 实施进度追踪（与代码实现保持一致）

> 本节为"文档-代码一致性"的实时快照。每完成一个里程碑即更新，确保技术文档反映真实代码。

### 9.1 已落地（2026-08-11）

| 里程碑 | 状态 | 实际代码位置 | 验收证据 |
|---|---|---|---|
| **M0 骨架** | ✅ 完成 | `Cargo.toml`（workspace）、`.cargo/config.toml`、`crates/daoti-{common,core,cli,daemon,ui}` | `cargo build --workspace` 零警告；`daoti --version` → `daoti 0.1.0` |
| **M1 感知层** | ✅ 完成 | `crates/daoti-core/src/sensor/{mod,windows,wsl2,docker,fusion}.rs`、`runner.rs` | `daoti status` 输出金/木/水判词；超时/不可达降级测试通过 |
| **M3 执行层** | ✅ 完成 | `crates/daoti-core/src/executor/{mod,safe}.rs` | 白名单/禁止模式/未知目标 6 项安全测试通过 |
| **M2 推演/决策** | ✅ 完成 | `crates/daoti-core/src/decision/{mod,causal_adapter,command_gen}.rs` | 五行→卦象→调度策略 5 项测试通过 |
| **M4 主控（CLI 全命令）** | ✅ 完成 | `crates/daoti-cli/src/{main,commands}.rs`、`crates/daoti-core/src/agent.rs`、`crates/daoti-core/src/probe.rs` | 六命令全部真实实现：`status / heal / explain / run / init / snapshot` 均可用 |
| **M5 部分（事件出口）** | ✅ 完成 | `crates/daoti-daemon/src/{main,eventbus,http}.rs` | daemon 启动 HTTP/SSE 出口；`curl /api/health`→ok；`/api/events` 收到心跳事件流 |
| **M5 Daemon 常驻** | ✅ 完成 | `crates/daoti-daemon/src/actor.rs`（mpsc 编排） | 三感知器注入真实事件（见下）；`curl /api/events` 收到 `target`/`detail` 齐全的真实感知流 |
| **M5 玄镜 UI** | ✅ 完成 | `daoti-ui-web`（Bun/React-Vite）+ `daoti-ui`（Tauri） | 浏览器实测渲染真实事件（见下）；`cargo build -p daoti-ui --features ui` 通过 |
| **M6 学习与参数库** | ✅ 完成 | `crates/daoti-core/src/learning/{mod,params,trajectory,hebbian}.rs` | 轨迹持久化+脱敏+回放、Hebbian 预留、参数库加载（见下） |

**本次（M4 剩余命令）新增实现：**
- `daoti init`：经 `daoti-core::probe` 探测 WSL 发行版/Docker 服务/盘符映射，`Config::write_to_file` 生成 `~/.daoti.toml`。
  - 探测兼容旧版 WSL（先 `wsl -l -v` 回退 `-l -q`）；仅当退出码为 0 才信任输出，规避 WSL 未就绪时的 UTF-16 帮助乱码（R2）。
- `daoti run <target> <cmd>`：显式目标平台，经 `SafeCommandExecutor`（白名单+禁止模式+超时）安全执行；新增 `SafeCommandExecutor::with_distro` 消除 WSL2 发行版硬编码。
- `daoti explain <code>`：纯函数 `explain_lookup` 将错误类型/卦象映射为白话判词（含 4 项单测）。
- `daoti snapshot`：采集三气状态序列化 JSON 落盘 `~/.daoti/snapshots/daoti_<unix_ts>.json`（快照回魂 M6 的数据基础）。
- 修复：`agent.rs` 未用变量 `after_health` 警告；`probe` 模块新增 `parse_distro_name` 单测。

**M5 起点（P0·daemon HTTP/SSE 事件出口）新增：**
- `daoti-daemon/src/eventbus.rs`：`EventBus`（`tokio::sync::broadcast` 环形缓冲 256 + `AtomicU64` 自增序号），`publish(kind,title) / subscribe()`，2 项单测通过。
- `daoti-daemon/src/http.rs`：axum 路由 `/api/health`（健康检查）+ `/api/events`（SSE 事件流，`poll_fn` 轮询 broadcast，keep-alive 15s）。仅绑定 `127.0.0.1`。
- `daoti-daemon/src/main.rs`：装配 `EventBus` + HTTP 服务 + 30s 心跳事件（占位，后续感知层接入）；`CancellationToken` 优雅关闭（Ctrl+C/SIGTERM）。
- 依赖：根 `Cargo.toml` 新增 `axum="0.7"`、`futures-util="0.3"`；daemon 新增 `serde_json`。
- **验收证据**：`cargo build --workspace` 零警告；`curl /api/health` → `ok`；`curl -N /api/events` 实测收到 `{"seq":1,"kind":"Sense","title":"气脉流动（30s 心跳）"...}` 心跳事件流。

**P0-2·PlatformExecutor 最终实现确认（2026-08-11）：**
- 复核 `daoti-core/executor/{mod,safe}.rs`：三系统执行器（Windows/WSL2/Docker，模式A 三系统，与北极星「三平台 = Windows/Linux/macOS」区分）统一实现 `PlatformExecutor`，由 `SafeCommandExecutor` 按 `target` 内聚分派（非 `dyn` 装箱）。
- 白名单完整性闭环：新增契约级交叉验证 `all_generated_commands_pass_whitelist`（`command_gen.rs`），断言 `restart_docker_daemon / reset_wsl / check_windows_services` 产出的每条 `CommandSpec` 均通过 `SafeCommandExecutor::validate`。任何新增指令若漏同步白名单即回归失败。
- `runner.rs` 复核：`shell=false`（`Command::args`）+ `tokio::time::timeout` + `kill_on_drop` 兑现 R4/R5 超时与防注入。
- 验收：`cargo test -p daoti-core` → 29 通过、零警告、零错误。

**M5 Daemon 常驻（mpsc Actor 编排，替换心跳占位，2026-08-11）：**
- `daoti-daemon/src/actor.rs`：`Sensor → Coordinator` 经 `tokio::sync::mpsc`（容量 16）编排，禁止共享内存（R7）。三感知器各自周期采集，结果送入协调者；协调者融合 → 推演 →（异常时）执行。
  - `ActorConfig::from_config(Config)`：WSL 发行版 / Docker 服务名 / 采样间隔均来自全局配置（`Config.timeouts.sampling_secs`，默认 30s），消除硬编码。
  - 感知事件发布：`describe_sense` 按平台生成中文标题（金/木/水）与详情，`SnapShot` 字段/指标确定性排序汇总。
  - 推演只触发一次：协调者维护 `last_health`，健康度变化才 `CrossPlatformCausalAdapter::interpret` → `决策` → `SafeCommandExecutor::execute`，并发布 `Infer/Decide/Execute/Result` 事件。
  - 收敛窗口 `SETTLE_GRACE=600ms`：合并同一采样轮内三感知器到达先后，避免启动阶段健康度多次变化导致重复干预。
  - 优雅停止：`ActorHandle::shutdown()` 经 `CancellationToken` 取消协调者与感知任务；感知器随途关闭时 `tx.send` 失败自动退出。
- `daoti-daemon/src/main.rs`：移除 30s 心跳占位，装配 `ActorHandle::spawn`；退出时 `token.cancel(); actor.shutdown();`。
- `daoti-daemon/src/eventbus.rs`：新增 `publish_built(ev)`——调用方先链式构造完整事件（含 detail/target）再广播，修复"广播先于 builder 生效导致订阅端字段缺失"的缺陷；测试 2→3 项。
- `daoti-common/src/config.rs`：`TimeoutConfig` 新增 `sampling_secs`（默认 30），`to_toml_string`/`toml_parse` 同步，默认值测试更新。
- `daoti-core/src/sensor/mod.rs`：`Sensor::collect` 返回值改为 `impl Future + Send`，使感知器 future 可被 `tokio::spawn` 到多线程运行时（与 lib.rs 声明一致）。
- **验收证据**：`cargo build --workspace` 零警告；`cargo test --workspace` 55 通过（daemon 12、core 29、common 10、cli 4）。实测 daemon 启动即感知三系统（Windows 宿主可达、WSL2/Docker 不可达 → 水困坎卦 → docker_first），经 SSE 收到 `{"seq":9,"kind":"Sense","title":"感 · 木 · WSL2 内核 · 不可达","detail":"目标平台不可达，计入五行降级。","target":"wsl2"}` 等真实事件（`target`/`detail` 齐全），收敛窗口确保单次干预。

**P1·Tauri 宿主脚手架（2026-08-11）：**
- `crates/daoti-ui` 升级为 Tauri 2 宿主，整体以 `ui` feature 门控（默认关闭，保持 `cargo build --workspace` 轻量，兑现"UI 可选交付，不阻塞 M0-M4"）。
- 新增文件：`build.rs`（`ui` feature 下调用 `tauri_build::build()`）、`tauri.conf.json`（`frontendDist`→`../../daoti-ui-web/dist`，窗口 1280×800，捆绑图标）、`icons/icon.png`+`icons/icon.ico`（手工构造合法 ICONDIR，规避 `Icon.Save` 产生的非法保留字段）。
- `src/main.rs` 门控：`ui` feature 启用 `tauri::generate_context!()` 启动宿主；否则保留轻量占位二进制。
- 玄镜前端占位页 `daoti-ui-web/dist/index.html`：按《驭灵 UIUX 设计规范》CSS Tokens 实现"道体感应"初始化页，仅 `fetch` daemon `/api/health`（R8 只读，零系统命令）。
- 验收：`cargo build -p daoti-ui --features ui` → `Finished`（Tauri 全栈编译通过）；`cargo build --workspace` 零警告；`cargo test --workspace` → 55 通过。

**P1·Bun 前端构建 + 主题系统（2026-08-11）：**
- `daoti-ui-web` 落地为 React 18 + Vite 5 项目：`src/{main.jsx,App.jsx,theme.css,lib/daemon.js}`，`bun run build` 出 `dist`（index.html + assets），与 Tauri `frontendDist` 对齐。
- 主题系统（`theme.css`）：严格按《驭灵 UIUX 设计规范》CSS Tokens（玄天底/金曦/青木/赤火/土黄/字体灰度）、气运卡片呼吸灯、五行徽章、驭灵/玄启按钮、时间轴、三气归元图、判词字阶、`--yl-ease-flow` 动效。
- 三视图：命轮（三气归元图 + 近期推演轨迹）、推演（SSE 实时时间轴）、归元（判词 + 配置占位）。
- `lib/daemon.js`：HTTP 只读客户端（R8），`fetch /api/health` + `fetch /api/events`（SSE 解析 + 断线退避重连）。零系统命令（Bun 红线）。
- **daemon 补 CORS**：`http.rs` 新增 `tower-http` CorsLayer，来源白名单（`localhost:5173` / `tauri://localhost` / `http://tauri.localhost`），仅 GET/HEAD/OPTIONS；恶意来源不返回 ACAO 头（浏览器拦截），只读诊断不对外暴露。
- 验收：`bun run build` → `✓ built in 669ms`；daemon 实测 `/api/health`→`ok`、`/api/events` 收到心跳事件；浏览器实测玄镜渲染三气图/徽章/时间轴，状态栏"道体已感应"（CORS 打通）。

**M5 玄镜 UI · 真实事件端到端验证（2026-08-11）：**
- 契约步骤 8 验收全部达成：三气归元图/决策时间轴已渲染真实事件；快照回魂为占位（与 M6 决策轨迹持久化衔接）。
- 验证链路：`cargo run -p daoti-daemon`（常驻，30s 采样）→ `bun run build`（721ms）→ `vite --port 5173` → 浏览器访问 `http://localhost:5173`。
- **关键点：CORS 白名单匹配的是 `localhost:5173` 而非 `127.0.0.1:5173`**。页面须经 `localhost` 访问，否则 Origin `http://127.0.0.1:5173` 未在白名单内 → 健康检查/SSE 被 CORS 拦截（curl 验证 `localhost:5173` 返回 `access-control-allow-origin`）。
- 实测：状态栏「道体已感应 · 已收 N 条事件」；近期推演轨迹与推演时间轴渲染真实感知事件（含 `detail`），如 `[感知] 感 · 木 · WSL2 内核 · 不可达 / 目标平台不可达，计入五行降级。`、`[感知] 感 · 金 · Windows 宿主 / docker_desktop_running=0.00 docker_service_...`。
- `cargo build -p daoti-ui --features ui` → `Finished`（Tauri 宿主编译通过，零警告）。
- 截图留档：仪表盘（三气归元图 + 近期轨迹）、推演时间轴两视图均为真实数据渲染。

**M6 学习与参数库（2026-08-11）：**
- `crates/daoti-core/src/learning/`：以 `learning` feature 门控（默认关闭，主链路零影响）。
  - `params.rs`：`LibraryParams`（健康阈值/弱判阈值/学习速率/金木水权重）+ `ParameterLibrary`（`load` 缺失回退默认、`save` 自动建父目录），对应 PRD 本地轻量参数库。
  - `trajectory.rs`：`TrajectoryRecord`（时间/卦象/优先级/路径/置信度/判词/脱敏指令/结果摘要/fixed）+ `TrajectoryStore`（JSON Lines 追加落盘 + `load` 回放 + `clear`）；`redact_command` 按 PRD §374 脱敏（`key=value` 敏感键名或值不透明 → `***`）。对应 PRD §318/§374/§400。
  - `hebbian.rs`：`HebbianLearner` trait（预留接口）+ `HebbianRule` 确定性默认实现（决策成败按置信度调制权重增量，`MIN_WEIGHT=0.5`/`MAX_WEIGHT=1.5` 有界稳定；`no_action` 不扰动）。
- **验收**：默认主链路通过 `cargo build --workspace`；当前工作区全量测试 `cargo test --workspace` 为 **328 通过、0 失败、1 忽略**。启用 `learning` feature 后，`cargo test -p daoti-core --features learning` 通过，覆盖参数库缺失回退/保存回载、轨迹 JSONL append→load 回放、敏感参数脱敏、Hebbian 成功强化/失败削弱/no_action 不扰动/权重有界，以及 SlowLearner 批量学习和决策方向变化。`learning` feature 仍默认关闭，不影响主链路。

**onnx 推理模块（已废弃移除，2026-08-11）：**
- 原 `crates/daoti-core/src/inference/`（`onnx_session` / `onnx_engine`）、`ort` 依赖、`onnx` feature、`models/daoti.onnx`、`DaotiError::ModelMissing` 已**整体移除**。
- **架构决策**：`daoti_core.pt` / `yijing_v53_daoti.pt` 均为其他业务域模型（易经文本/卦象，输入 token 特征，输出卦辞/爻辞/五行），与驭灵「三气健康度 → 调度决策」业务语义不匹配；且道体本质是**符号/几何推演**（双梯形镜像递归架构），非神经网络权重驱动，无需经 onnx 加载。
- **推演现为纯规则引擎**：`decision::engine`（`InferenceEngine` trait + `RuleEngine` 五行映射表），确定性推演，始终可用，不依赖外部权重；`daemon::actor` 经 trait 调用，行为不回归。
- **验收**：`cargo build --workspace` 零警告、55 测试通过；`cargo test -p daoti-core --features learning` → 39 通过。

**M5 快照回魂（snapshot replay）全链路落地（2026-08-11）：**
- **共享路径去硬编码**：`daoti-common/config.rs` 新增 `home_dir()` / `snapshots_dir()`（`~/.daoti/snapshots`），CLI 与 daemon 复用同一落盘位置，消除硬编码路径。
- **判词单一来源**：`daoti-core/sensor/fusion.rs` 为 `WuxingHealth` 新增 `verdict()`（三气全通→"金坚木盛水流"；任一受滞→"为病"；其余→"将变未变"），CLI 与 daemon 共用，避免文案分叉。
- **daemon HTTP 快照端点**（`daoti-daemon/src/http.rs`）：`GET /api/snapshots`（列表，轻量元数据 ts+五行健康度+判词，倒序）+ `GET /api/snapshots/{ts}`（详情，完整 FusionState）。异常路径不 panic：目录不可读返回空列表、快照缺失/损坏返回 404。
- **玄镜 UI 快照面板**（`daoti-ui-web/src/App.jsx` + `daemon.js`）：新增「回魂·快照」视图，左侧快照列表（健康度进度条+判词），右侧点选回放完整 FusionState；只读消费 daemon（R8），零系统命令。
- **axum 路由语法修复（关键）**：本项目 axum 为 **0.7.x**，路径参数必须用 `:ts` 而非 `{ts}`（后者会被当作字面量静态段，导致带参数路由返回 route 级空 404）。新增路由级回归测试 `detail_route_matches_parameterized_path`（tower `oneshot` 断言 404 且 body 为"快照不存在"）。
- **验收**：`cargo test --workspace` **55 通过**（daemon 12，含快照端点单测 + 路由回归测试）；UI `npm run build` 成功；浏览器端到端：快照列表→点选→详情回放真实渲染（金 Windows 指标 / 木 WSL 不可达 / 水 Docker 不可达）。

### 9.2 接口契约（与第 1.3 节一致）

- `Sensor`: `fn collect(&self) -> impl Future<Output = SensorState> + Send`（感知层契约，返回 `Send` future 以便 `tokio::spawn`；`SensorState::Ok/Unavailable`）
- `PlatformExecutor`: `async fn execute(&self, spec: &CommandSpec) -> Result<ExecResult, DaotiError>`
  - 注意：trait 含 async fn，**不作为 `dyn` 装箱**；由 `SafeCommandExecutor` 持有具体执行器按 target match 分派（内聚工厂语义）。
- `SafeCommandExecutor`: `new()`（默认 Ubuntu）/ `with_distro(distro)`；`execute` / `validate` 返回 `DaotiError::Blocked / Unavailable`。
- `DaotiError`（thiserror 枚举）：`ChannelClosed / CommandTimeout / PathMapping / Config / Blocked / Unavailable / Io / Json / Other`，提供 `kind()` 与 `is_recoverable()`。
- `DaotiEvent`（serde）：`seq/kind/title/detail/ts_ms/target`，用于决策时间轴。
- `daoti-core::probe`（新增）：`detect_wsl_distro / detect_docker_service / detect_drive_map / build_probed_config / wsl_available`（均 async，失败回退默认值不 panic）。
- `Config`（daoti-common，新增）：`write_to_file(path)` / `default_path()` / `to_toml_string()`，与极简解析器 `toml_parse` 可互逆（含 `endpoint_probe_secs`、`drive_*` 盘符映射）。
- `daoti-common::config`（快照回魂共享路径）：`home_dir()` / `snapshots_dir()`（`~/.daoti/snapshots`），CLI 与 daemon 复用，消除硬编码。
- `WuxingHealth::verdict()`（daoti-core::sensor::fusion）：按五行健康度给出判词（三气全通→"金坚木盛水流"；任一受滞→"为病"；其余→"将变未变"），CLI 与 daemon 共用单一文案来源。daemon `GET /api/snapshots`（列表元数据）与 `GET /api/snapshots/{ts}`（详情）只读出口。

### 9.3 待推进

| 里程碑 | 目标 | 前置依赖 |
|---|---|---|
| **M5 Daemon 常驻** | ✅ 已完成：`daoti-daemon/src/actor.rs` mpsc Actor 编排（sensor→decision→executor），感知接入并发布真实事件（替换 30s 心跳占位） | 事件出口已就绪（P0 完成） |
| **M5 玄镜 UI** | ✅ 已完成：`daoti-ui-web`（Bun/React-Vite）三视图 + SSE 消费；`daoti-ui`（Tauri 宿主）`ui` feature 编译通过；浏览器实测渲染真实事件 | 事件出口已就绪；Bun/Tauri 工具链 |
| **M6 学习与参数库** | ✅ 已完成：`daoti-core::learning`（决策轨迹持久化 JSON Lines + 脱敏 + 回放；Hebbian 预留接口 + 确定性默认实现；轻量参数库加载/保存），`learning` feature 默认关闭不影响主链路 | 决策/执行层已就绪；`snapshot` 落盘基础已具备 |
| **onnx 推理** | ❌ 已废弃移除（重大方向改变，2026-08-11）：`daoti_core.pt` / `yijing_v53_daoti.pt` 为易经文本模型（输入 token 特征），与驭灵「三气健康度 → 调度决策」业务语义不匹配；且道体本质为**符号/几何推演**（双梯形镜像递归架构），非神经网络权重驱动。`inference/`、`ort` 依赖、`onnx` feature、`models/daoti.onnx` 已整体删除，推演统一走纯规则引擎 `decision::engine`（五行映射表）。**不再需要模型权重，无后续任务** | 无（已废弃） |

---

## 附：交付物与最终形态对齐

对照《产品形态.md》"三件套压缩包"：
1. 安装包（含 Rust 静态二进制 + 玄镜前端产物，**不携带 onnx 权重**；推演为纯规则引擎）。
2. 一条命令 `daoti init`（自动探测三系统路径生成配置）。
3. 一份极简说明书——"以后报错，先敲 `daoti heal`，不行再找我。"

> **道体玄盾·守护每一次生成** —— 本计划是契约，实现必须逐级验收，严禁批量。

---

## 10. 技术栈对齐（定义者 × 创始者定稿）

> 本节由「定义者」与「创始者」智能体基于四份文档对齐定稿，是对 §1.1 用户交互层与 §5 依赖清单的技术落位补充。**核心哲学：道体是帅，平台是将，Bun 是旗。**

### 10.1 三层职责分工

| 层 | 技术 | 职责（Must） | 禁止（Must Not） |
|---|---|---|---|
| **核心层（大脑）** | Rust `daoti-daemon` | 常驻守护、道体推演（符号/几何规则引擎 `decision::engine`，非神经网络）、安全执行、事件总线唯一数据源 | 不可被 Bun 替代 |
| **令牌层（手脚）** | Rust `daoti-cli` | `status/heal/explain/run/init/snapshot` 全链路，`PlatformExecutor` 统一执行 | 不可用 Bun Shell 执行调度命令 |
| **玄镜层（颜面）** | Bun + Tauri | 玄镜 UI 构建、本地 HTTP/SSE 消费 daemon 事件、三环图/时间轴/快照回魂展示 | 不得自行采集三系统状态、不得执行任何系统命令 |
| **胶水判定** | —— | Bun 的"跨平台"能力用于**展示层一致性**（UI 各平台长得一样） | Bun 的"跨平台"**不得**用于**执行层一致性**（命令安全/可回滚/可审计） |

### 10.2 Bun 红线（硬性禁止模式）

**Bun 侧禁止：**
- ❌ 任何 `exec()` / `spawn()` / `$` 模板字符串调用系统命令
- ❌ 任何 `child_process` / `bun:shell` 的导入与使用
- ❌ 任何 `fs` 写入系统关键目录（`/etc`、`C:\Windows` 等）

**Bun 合法系统交互（唯一）：**
- ✅ `fetch()` → `http://127.0.0.1:{port}/api/events`（SSE 消费）
- ✅ `fetch()` → `http://127.0.0.1:{port}/api/restore` 等只读/只传参接口
- ✅ `fetch()` → `http://127.0.0.1:{port}/api/snapshots（/api/snapshots/{ts}）`（快照回魂列表/详情，只读）
- ✅ 读取 `FusionState` 快照 JSON（仅展示回魂数据，不参与推演）

### 10.3 数据流（R8 单一数据源闭环）

- IPC 选 **本地 HTTP + SSE**（daemon 为唯一 producer），弃 Tauri invoke 与命名管道。
- 玄镜 UI **只读** daemon 出口，禁止在 Bun 侧重复采集三系统状态，杜绝第二数据源。

### 10.4 实施优先级（P0–P3）

| 优先级 | 任务 | 模块 | 前置依赖 |
|---|---|---|---|
| P0 | daemon 补齐 HTTP/SSE 事件出口 | daoti-daemon | ✅ 已完成（`eventbus.rs`+`http.rs`，见 §9.1） |
| P0 | Rust `PlatformExecutor` 最终实现确认（白名单完整） | daoti-core | ✅ 已完成：三实现经 `SafeCommandExecutor` 分派；新增契约级交叉验证 `all_generated_commands_pass_whitelist`（生成器每条指令必过白名单，27 项测试通过） |
| P1 | Tauri 宿主脚手架 | daoti-ui | ✅ 已完成：`--features ui` 可编译 Tauri 2 宿主（`build.rs`+`tauri.conf.json`+`main.rs` 门控），加载 `daoti-ui-web/dist` 占位页；默认 feature 保持轻量不阻塞主链路 |
| P1 | Bun 前端构建（React/Vue）+ 主题系统 | daoti-ui-web | ✅ 已完成：React+Vite 项目（`bun run build` 出 `dist`），按 UIUX 规范实现主题系统与命轮/推演/归元三页，SSE 只读 daemon；daemon 补 CORS 白名单 |
| P2 | 修订本文件 §1.2 / 勘误《产品形态.md》 | 文档 | ✅ 已完成 |
| P3 | WebView2 降级预案 | daoti-installer | 打包阶段 |

### 10.5 对现有实施的影响

1. **daemon 事件出口**：✅ 已实现 `eventbus.rs` + `http.rs`（HTTP/SSE 广播通道），并按 `publish_built` 修复 detail/target 透传。Bun 前端现可经 `/api/events` 消费（见 §9.1）。mpsc Actor 编排（`actor.rs`）已接入真实感知事件，替换原心跳占位（见上）。
2. **交付形态**：玄镜随安装包分发为 Tauri 静态编译产物，用户无需安装 Bun；勘误"含 Python 运行时"为"含 Rust 静态二进制 + 可选 Bun/Tauri 前端（不携带 onnx 权重）"。
3. **WebView2 降级**：玄镜为可选 feature，缺失时由 `daoti init` 引导补齐或提示"日常用 CLI 即可"。
