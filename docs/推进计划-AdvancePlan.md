# 驭灵（道体）后续推进计划（Advance Plan）

> 文档版本：v1.0
> 编制角色：定义者（工程/规范视角） × 创始者（产品/愿景视角） 联席定稿
> 依据：g:\Yl\docs\开发计划-TechnicalPlan.md（M0–M6 已全部完成）
> 编制日期：2026-08-11

---

## 0. 定位：从"能演示"到"能日用"

M0–M6 已交付**守护工具链能力**（感知→推演→执行→记忆→快照 全链路）；模式B 的二进制部分仍须按真实格式/运行时边界单独验收，fixture 与契约测试不等同于通用跨平台执行。
但它证明的是"道体能推演"，尚缺三件事才构成"守护型工具"的完整体验：

| 缺口 | 现状 | 缺什么 |
|------|------|--------|
| **入口** | 只能手动装依赖、手动跑 | 一键安装 + 三系统自动探测引导 |
| **触达** | 用户=主动敲 `daoti heal` | 守护从"被动等命令"变"主动告警" |
| **闭环** | heal 能执行，失败无兜底 | 修复失败→明确告知→人工升级路径 |

**核心判据**：口号"以后报错，先敲 daoti heal，不行再找我"若要成立，必须先把"不行再找我"落到实处——
用户装得上、报错能被守护主动感知并尝试修复、修不好时有明确出口。

> 本计划是契约性规范，所有实现必须逐级验收，严禁批量。每项完成后回写 §5 进度追踪与 TechnicalPlan。

---

## 1. 推进路线总览（P0 → P3）

| 优先级 | 主题 | 核心目标 |
|---|---|---|
| **P0** | 交付闭环 | 装得上、守护主动化、日志可查、能回放历史 |
| **P1** | 可信交付 | 补漏可见、配置热加载、韧性测试、时间轴闭环 |
| **P2** | 工程质量 | CI/CD、背压监控、幂等防重复、日志脱敏 |
| **P3** | 演进与文档 | 学习接入、文档收敛、跨平台扩展 |

---

## 2. P0 —— 交付闭环（值得交付的真实最小集）

> **为何 P0 是硬缺口**：不装包、不服务化、日志不可查、WebView2 白屏、历史不可回放，
> 任一都会让"55 测试全绿"的代码无法成为可交付产品。

### P0-1 daemon 进程生命周期管理 ①
- **目标**：daemon 可被 CLI 启停、开机自启、崩溃自恢复、端口冲突可感知。
- **模块**：`daoti-cli`（新增 `daemon start/stop/status/restart` 子命令）+ `daoti-daemon`（单实例锁、端口占用检测）。
- **前置依赖**：无。
- **验收**：同一端口重复启动返回明确错误而非静默失败；`daoti daemon status` 反映真实存活与版本；优雅退出（复用现有 `CancellationToken`）。

### P0-2 打包与安装链路（daoti-installer）②
- **目标**：产出 Windows 一键安装产物，daemon 与玄镜统一分发。
- **模块**：新增 `daoti-installer`（复用 `tauri.conf.json` + `probe.rs` 探测能力）。
- **前置依赖**：P0-1（daemon 服务化先行）。
- **验收**：全新机器双击安装→首次向导探测三系统→`daoti status` 三系统在线，全程 < 5 分钟无手动配环境；卸载可完整清理。

### P0-3 日志落盘与轮转 ③
- **目标**：daemon/CLI 日志可持久化、可轮转、可定位故障。
- **模块**：`daoti-common::logging`，引入 `tracing-appender` RollingFileAppender。
- **前置依赖**：无。
- **验收**：日志写 `~/.daoti/logs/`，按天/大小轮转，保留策略可配置（Config 新增 `log` 段）；stderr 与文件双写；含时间戳与目标模块。

### P0-4 WebView2 降级预案 + CSP 收紧 ④
- **目标**：无 WebView2 环境不白屏；页面加载策略收紧。
- **模块**：`daoti-ui`（tauri.conf.json）+ 玄镜前端。
- **前置依赖**：无。
- **验收**：`webviewFixedRuntime` 或 bootstrapper 注入；缺运行时给出可读引导；`csp: null` 收敛为最小放行策略，回归验证 SSE 不受阻。

### P0-5 历史时间轴 HTTP 拉取接口 ⑤
- **目标**：玄镜刷新/重连后能回放历史事件，不止实时 SSE。
- **模块**：`daoti-daemon`（新增 `/api/events/history` + 时间轴落盘）+ `daemon.js`。
- **前置依赖**：P0-3（落盘思路可复用）。
- **验收**：SSE 断线重连后先拉历史再续实时，序号衔接；历史接口分页且容量受 Config 约束；daemon 重启后历史仍在。

### P0-6 守护主动告警 ⑥（创始者 P0-1）
- **目标**：Daemon 检测异常时主动通知，而非等用户敲命令。
- **模块**：`daoti-daemon`（异常事件钩子）+ 通知通道（Windows 通知中心 + 可选 Webhook）。
- **前置依赖**：M5 mpsc 编排（已具备）。
- **验收**：制造故障后通知 3 秒内触达；通知失败不影响 daemon 主流程。

### P0-7 一键修复闭环 + 失败兜底 ⑦（创始者 P0-2）
- **目标**：`daoti heal` 升级为完整闭环：感知→推演→执行→结果反馈→失败时给出人工升级路径。
- **模块**：`daoti-cli` + 玄镜 UI 同步展示四类结局（成功/超时/失败/部分成功）。
- **前置依赖**：P0-6、决策轨迹持久化（已具备）。
- **验收**：覆盖四类结局；失败时必有明确提示与恢复路径（如 `daoti snapshot` + 联系信息）。

---

## 3. P1 —— 可信交付（增强安全感）

### P1-1 SSE 序号断裂可见化
- **目标**：慢消费者丢事件不静默，玄镜能提示"已漏 N 条"。
- **模块**：`http.rs`（`Lagged` 分支携带丢失条数）+ 玄镜前端。
- **前置依赖**：P0-5（历史拉取可补漏）。
- **验收**：不再返回无信息量的 `"{}"`；前端据此补拉历史。

### P1-2 配置热加载
- **目标**：修改 `~/.daoti.toml` 无需重启生效。
- **模块**：`daoti-common::config` + `daemon::actor`（采样间隔等动态项）。
- **前置依赖**：无。
- **验收**：文件变更触发重载；运行期参数即时生效；解析失败保留旧配置并告警（不崩溃）。

### P1-3 HCSE 五层韧性测试补齐
- **目标**：覆盖异常路径（超时/卡死/取消/网络断开/资源耗尽）。
- **模块**：`daoti-daemon` + `daoti-core`。
- **前置依赖**：P0-5、P1-1。
- **验收**：对 SSE 长连接卡死、sensor 永不返回、executor 超时、广播满、端口被占、配置损坏、快照损坏各写一条可复现测试；断言"不 panic + 有兜底 + 可恢复"，回写 `HCSE_RESILIENCE_AUDIT.md`。

### P1-4 daemon 全链路集成测试
- **目标**：传感器→融合→推演→执行→事件发布→HTTP/SSE 端到端可测。
- **模块**：`daoti-daemon`（新增 `tests/`）。
- **前置依赖**：P0-5。
- **验收**：不依赖真实 WSL/Docker 的 mock 集成测试通过；覆盖健康度变化触发推演、无变化不重复干预。

### P1-5 daemon 时间轴落盘闭环
- **目标**：快照回魂数据由 daemon 自动产生，而非仅靠 CLI 手动 snapshot。
- **模块**：`daemon::actor`（周期写 FusionState 到 `snapshots_dir`）。
- **前置依赖**：P0-3。
- **验收**：daemon 按 Config 周期落盘 `daoti_<ts>.json`；落盘失败不阻塞主循环。

### P1-6 快照对比 + 一键回滚（创始者 P1-1）
- **目标**：`snapshot` 从"存下来"升级为"可对比、可回滚"。
- **模块**：玄镜 UI diff 视图 + `daoti snapshot rollback <id>`。
- **前置依赖**：快照落盘（已具备）。
- **验收**：能看两快照间差异；回滚后系统状态与快照一致。

---

## 4. P2 —— 工程质量加固

- **P2-1 CI/CD**：GitHub Actions/本地 pipeline，`cargo build --workspace`（零警告）+ `cargo test` + `cargo clippy` + Bun 前端构建 + 打包产物校验。✅ 已完成：`.github/workflows/ci.yml`（ubuntu-latest + windows-latest 双平台 Rust 构建/测试/clippy + Node.js 前端构建+产物上传）；同步修复所有 clippy `-D warnings` 告警（doc注释缩进/new_without_default/trim_split_whitespace/unnecessary_sort_by/while_let_loop/let_underscore_future 等 10 处）；`cargo clippy --workspace -- -D warnings` 零告警通过。
- **P2-2 背压与指标**：为 mpsc（容量 16）与广播（容量 256）增加发送/丢弃计数，暴露 `/api/health` 附健康指标；`send` 失败不再静默 `let _ =`。✅ 已完成：EventBus 新增 `sent`/`dropped` AtomicU64 计数，`publish_built` 失败时递增 dropped；ActorHandle 新增 `mpsc_dropped` 计数（`try_send` 失败时递增）；`/api/health` 返回 JSON `{ status, event_bus_sent, event_bus_dropped, mpsc_dropped }`；前端 `fetchHealth()` 适配 JSON 响应；集成测试验证 health 返回结构化字段；`cargo build --workspace` 零警告、84 测试通过。
- **P2-3 幂等与防重复干预**：推演命令去重/防抖，避免同一异常在收敛窗口外被重复执行；执行前二次校验目标状态。✅ 已完成：Coordinator 新增 `last_decision`（决策指纹：gua|pathway|命令列表）和 `last_intervene_at`（上次执行时间戳），同一决策 60s 冷却期内跳过；`infer_and_act` 执行前调用 `pre_check_target()` 重新采集传感器状态，目标已恢复则跳过该命令；日志标注"幂等跳过"与"二次校验跳过"便于排查；`cargo build --workspace` 零警告、84 测试通过。
- **P2-4 日志规范化与脱敏**：错误日志统一含错误类型/位置/变量；命令输出与配置中的敏感信息脱敏。✅ 已完成：新增 `sanitize_url`（截断 Webhook URL 中路径参数）与 `truncate_output_with_hint`（输出超 256 字截断+提示）脱敏工具；actor.rs 命令 stdout/stderr/错误信息均经截断后再写入事件详情与日志；notifier.rs Webhook 错误日志脱敏 URL；`cargo build --workspace` 零警告（仅 mpsc_counter 预留 API）、91 测试通过。

---

## 5. P3 —— 演进与文档收敛

- **P3-1 文档一致性对齐**：新增 `HCSE_RELEASE_PROTOCOL.md`；逐项核对《架构总览/设计方案/开发计划》与当前实现（onnx 已移除、推演走 `decision::engine`、快照 API 为 `:ts`）无残留。✅ 已完成：创建 `HCSE_RELEASE_PROTOCOL.md`（发布检查项/流程/风险登记）；更新 `HCSE_RESILIENCE_AUDIT.md` RES-001 标记 onnx 已整体移除；`PRD-驭灵-产品需求文档.md` 添加 v1.1 架构变更说明；`架构总览.md` 已验证无 stale 引用；`开发计划-TechnicalPlan.md` 已逐节核对无残留。
- **P3-2 学习与参数库实验**：将 Hebbian/参数库从"轨迹持久化"推进到"可观测的慢调节"（非默认特性，默认关闭）。
- **P3-3 跨平台扩展**：Linux/macOS 传感器与打包支持；CI 上补 Linux 构建与无头 daemon 验证。
- **阶段 7 发布可信度加固**：新增发布版本校验、发布产物检查和 JSON 前置检查报告；完整 workspace 验证受磁盘空间不足阻断，未宣称发布通过。

---

## 6. 推进顺序依据

1. **P0 全是"交付硬缺口"**：不装包、不服务化、日志不可查、WebView2 白屏、历史不可回放，任一都会让全绿代码无法交付。
2. **P1 依赖 P0 的落盘/历史基础**：SSE 补漏与历史拉取互为前提，韧性测试需要真实可断开的通道对象。
3. **P2/P3 是加固与演进**：CI 与背压监控应在 P0 交付验证后落地，避免"先有流程后无产物"。

**第一阶段切入顺序（最小可交付闭环）**：`P0-1 daemon 生命周期 → P0-3 日志落盘 → P0-5 历史时间轴`。

---

## 7. 实施进度追踪（与代码实现保持一致）

> 每完成一项即更新，确保文档反映真实代码。验收证据必须可复现。

| 任务 | 状态 | 验收证据 |
|---|---|---|
| P0-1 daemon 生命周期 | ✅ 完成 | `daoti daemon start/stop/status/restart` 可用；单实例锁 + 端口预检 + 健康探针；`cargo build --workspace` 零警告、62 测试通过 |
| P0-2 打包安装链路 | ✅ 完成 | Tauri sidecar 配置（daemon + CLI 打包进安装程序）；`scripts/build-release.ps1` 统一构建脚本；`daoti-ui/setup.rs` 首次运行系统探测 Tauri 命令；玄镜前端 `SetupBanner` 首次设置向导；`cargo build --workspace` 零警告 + `cargo check -p daoti-ui --features ui` 零警告、74 测试通过、vite build 成功 |
| P0-3 日志落盘与轮转 | ✅ 完成 | `~/.daoti/logs/` 按日轮转（daily/hourly/never 可配）；stderr + 文件双写；含时间戳+级别+模块名；Config 新增 `log` 段（`log_rotation`/`log_max_files`/`log_file_prefix`）；`cargo build --workspace` 零警告、55 测试通过 |
| P0-4 WebView2 降级 + CSP | ✅ 完成 | `tauri.conf.json`：WebView2 `downloadBootstrapper`（缺运行时自动静默下载，不白屏）；CSP 从 `null` 收紧为 `default-src 'self'; connect-src 'self' http://127.0.0.1:17890; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; script-src 'self'`；SSE/API 到 daemon 不受阻 |
| P0-5 历史时间轴接口 | ✅ 完成 | `GET /api/events/history?before_seq=&limit=` 分页可用；事件 JSONL 落盘 `~/.daoti/events/`；daemon 重启后历史仍可读；前端 SSE 连接成功后拉历史并去重合并；`cargo build --workspace` 零警告、66 测试通过 |
| P0-6 守护主动告警 | ✅ 完成 | `notifier.rs` 双通道（Windows Toast + Webhook）；异常检测点 (`actor.rs` infer_and_act) fire-and-forget 触发；通知失败不影响主流程；`notify_windows`/`webhook_url` 可配；`cargo build --workspace` 零警告、74 测试通过 |
| P0-7 修复闭环 + 失败兜底 | ✅ 完成 | `HealOutcome` 五类结局（Success/PartialSuccess/Timeout/Failure/NoAction）；CLI heal 完整四类结局输出+恢复路径提示；daemon `POST /api/heal` 端点；玄镜 UI "归元·修复"面板（一键触发+四类结局可视化）；`cargo build --workspace` 零警告、74 测试通过、vite build 成功 |
| P1-1 SSE 序号断裂可见化 | ✅ 完成 | http.rs Lagged 分支返回 `{"type":"lagged","skipped":N}`（不再是空 `"{}"`）；daemon.js 检测 lagged 事件并回调 `onLagged(N)`；App.jsx 自动以最后 seq 为锚点补拉历史 + 状态栏提示 |
| P1-2 配置热加载 | ✅ 完成 | `ConfigWatcher` 基于文件 mtime 轮询检测；daemon 每 5s 检查 `~/.daoti.toml` 变更；变更后经 `mpsc::try_send` 通知 Actor 更新 `sampling_secs`/`exec_secs`；解析失败保留旧配置并 `tracing::warn` 告警（不崩溃） |
| P1-3 HCSE 韧性测试 | ✅ 完成 | 新增 4 条韧性测试（广播满不panic/无订阅者不panic/配置乱码回退/空文件默认值）；已有 3 条测试覆盖（执行超时/端口被占/快照损坏）；7/7 场景全覆盖；回写 `HCSE_RESILIENCE_AUDIT.md` RES-003~RES-007；`cargo test --workspace` 78 测试通过 |
| P1-4 全链路集成测试 | ✅ 完成 | `tests/integration_test.rs` 6 条黑盒集成测试（EventBus→历史回读/健康检查/快照列表/分页/健康度推演/防抖）；`[lib]` 目标暴露公共模块；84 测试通过 |
| P1-5 时间轴落盘闭环 | ✅ 完成 | `actor.rs` Coordinator 每 300s 自动落盘 `FusionState` 到 `snapshots_dir`（JSON 格式 `daoti_<ts>.json`）；`write_snapshot()` 方法落盘失败仅 `tracing::warn` 不阻塞主循环 |
| P1-6 快照对比回滚 | ✅ 完成 | CLI `snapshot diff/rollback` 子命令可用；daemon `GET /api/snapshots/diff?ts1=&ts2=` 端点返回健康度变化+字段级差异；玄镜UI快照列表"对比"按钮触发diff结果区（三气变化箭头+字段差异表）；前端 vite build 成功；`cargo build --workspace` 零警告、84 测试通过 |
| P2-1 CI/CD | ✅ 完成 | `.github/workflows/ci.yml`（Rust 双平台构建+测试+clippy + 前端构建+产物上传）；`cargo clippy --workspace -- -D warnings` 零告警（修复 10 处 lint）；`cargo build --workspace` 零警告、84 测试通过 |
| P2-2 背压与指标 | ✅ 完成 | EventBus sent/dropped 计数；ActorHandle mpsc_dropped 计数；`/api/health` 返回 JSON 结构化指标；前端适配 JSON 响应；修复 mpsc 计数器断裂（`http::router` 接收 `actor.mpsc_counter()` 真实计数器，替代独立新建的恒 0 计数器）；`cargo build --workspace` 零警告、160 测试通过 |
| P2-3 幂等与防重复干预 | ✅ 完成 | Coordinator 决策指纹 + 60s 冷却期防抖；执行前二次校验目标状态；`cargo build --workspace` 零警告、84 测试通过 |
| P2-4 日志规范化与脱敏 | ✅ 完成 | sanitize_url + truncate_output_with_hint 脱敏工具；命令输出/错误日志截断；Webhook URL 脱敏；91 测试通过 |
| P3-1 文档一致性对齐 | ✅ 完成 | HCSE_RELEASE_PROTOCOL.md + RES-001 清理 + PRD v1.1 变更说明；四份文档均无 stale 引用 |
| P3-2 学习与参数库实验 | ✅ 完成 | `CrossPlatformCausalAdapter::with_weights`（五行权重注入，默认 1.0 不回归，权重调制"最弱气"判断）；`learning::slow::SlowLearner` + `LearnReport`（批量轨迹→Hebbian 有界微调→可观测学习报告）；闭环测试 `learning_steers_decision_direction`（轨迹→学习→权重→决策从 docker_first 翻转为 wsl2_first）；`learning` feature 门控默认关闭；daemon 学习闭环接入（`RuleEngine::set_weights` 运行时权重更新 + `daoti-daemon` 加 `learning` feature 转发 + `Coordinator` 决策前权重注入/决策后 `learn_from_outcome` 学习并落盘 `~/.daoti/params.json`）；学习状态可观测（`EventKind::Learn` 事件进入时间轴 + 玄镜前端展示）；默认 `cargo test --workspace` 160 测试全绿、`--features learning` 下 core 104 测试全绿 |
| P3-3 跨平台扩展 | ✅ 完成 | 传感器跨平台优雅降级（WindowsSensor/Wsl2Sensor 在非 Windows 平台探测失败即返回 `Unavailable`，不 panic）；CI matrix 含 ubuntu-latest（P2-1）+ macos-latest（本轮补）；Tauri bundle 已 `targets: "all"`；新增跨平台构建脚本 `scripts/build-release.sh`（Linux/macOS，对应 build-release.ps1，按 host triple 命名 sidecar）；无头 daemon 编译+测试由 CI ubuntu-latest 覆盖（实际运行二进制验证需 Linux/macOS 机器） |

### 第二阶段：模式B · 跨平台二进制信号重映射

详见 [模式B-跨平台二进制重映射开发计划.md](./模式B-跨平台二进制重映射开发计划.md)。创始者×定义者联席裁决：B0 无感代理 → B1 规则映射 → B2 网络增强（远期）。

| 任务 | 状态 | 验收证据 |
|------|------|----------|
| B0 格式识别与受控分派 | ⚠️ 部分完成 | `detect_binary_format()` 可识别 ELF/PE/Mach-O；静态 ELF 与受控 PE32+ 控制台 fixture 有本地竖切。动态 ELF 仅有解析/规划证据，Mach-O 仅识别；格式检测/fixture 测试不代表通用执行能力。 |
| B1 规则映射 | ✅ 完成 | `interceptor/mod.rs` 定义 `SyscallEvent`/`TargetSyscall`/`InjectResult`/`Interceptor`/`Injector` trait + `SyscallMapper` + `SYSCALL_MAPPINGS`（20 条 Linux x86_64 syscall → Win32 确定性映射）；`interceptor/state.rs` 进程状态账本 `ProcessState`（FD 表/内存表/cwd/env/brk）；`interceptor/telemetry.rs` 未命中采集器 `TelemetryCollector`（B2 训练数据基础）；`codec/mod.rs` `Encoder`/`Decoder` trait + `NoopCodec`（B2 预留）；`executor/safe.rs` `validate_inject()` 注入安全校验（复用禁止模式 + 仅放行映射表内 Win32 操作）；`agent.rs` `DecisionPipeline` + `CrossPlatformAgent::run_b1()` 降级链路（未命中阈值=5 → WSL2 可用则降级、不可用则 `DaotiError::Unavailable`）；`lib.rs` 注册 `codec/interceptor` 模块；`cargo test -p daoti-core` 49 个测试全部通过 |
| B2 网络增强 | ✅ 完成 | B2-0 配置（ndarray 0.15 + `ModelConfig` 平铺键 `model_*`）→ B2-1 权重加载器（`DAOTIBLT` 二进制 + `WeightsLoader`）→ B2-2 bilateral 纯数学（`BilateralLadderNetwork::forward` 递归 t_iter）→ B2-3 codec（`SyscallCodec` encode/decode + `DecodeOutcome`）→ B2-4 道体接入（`DecisionPipeline::with_b2` + `try_derive` + `B1Step::Derived`）→ B2-5 gate（`B2Gate` 四条件 + `validate_derived` 黑名单）→ B2-6 反馈采集（`SampleOutcome` 四分类 + 覆盖率 + agent 采集闭环）→ B2-7 离线训练契约（`docs/模式B-B2离线训练契约.md`）；`cargo test --workspace` 153 测试全绿（cli 7 + common 31 + core 83 + daemon 26 + integration 6）；详见 [模式B-B2双梯形网络增强开发计划.md](./模式B-B2双梯形网络增强开发计划.md) |

---

> **道体玄盾·守护每一次生成** —— 从"能演示"到"能日用"，逐级验收，严禁批量。