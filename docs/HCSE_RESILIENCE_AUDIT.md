# HCSE 韧性审计清单 — 驭灵（道体）

> 依据《开发计划-TechnicalPlan.md》§8 文档同步机制与 HCSE 动态差异框架。
> 本文档把项目韧性/发布检查项落为可执行清单；智能体未预警的新故障模式，事后必须回写本文件。

## 检查项（逐条编号，持续追加）

### RES-001 onnx 推理模块已整体移除（2026-08-11 架构决策）
- **状态变更**：onnx 推理模块（`crates/daoti-core/src/inference/`、`ort` 依赖、`onnx` feature、`models/daoti.onnx`）已于 2026-08-11 整体移除。RuleEngine 为唯一推演引擎，道体本质为**符号/几何推演**（双梯形镜像递归架构），非神经网络权重驱动。
- **此项检查不再适用**：无需携带模型权重，亦无需降级路径——RuleEngine 始终可用。

### RES-002 推理接入 Daemon Actor 的降级/韧性路径（2026-08-11 已闭合）
- **故障模式**：`OnnxSession` 的 `run` 需 `&mut self`（非线程安全），若在 Daemon Actor 中被并发调用会内存损坏；且缺模型时若未接入降级，`heal` 全链路会中断。
- **检查项**：推理须在 Actor 任务内**独占**使用；缺模型/加载失败自动降级到 `CrossPlatformCausalAdapter` 规则引擎；用 mock 验证降级与超时/卡死/错误/取消路径。
- **当前状态**：✅ 已闭合——
  - 新增 `decision::engine::InferenceEngine` trait（`interpret(&mut self)`，天然独占、杜绝并发推理），`RuleEngine`（规则引擎，始终可用）+ `OnnxEngine`（`onnx` feature，缺模型/加载失败/输出异常自动降级规则引擎并发布"道体离线，使用规则模式"状态）。
  - `daoti-daemon::actor` 的 `Coordinator` 由 `CrossPlatformCausalAdapter` 改为持有 `RuleEngine`（经 trait 调用），决策事件标题带引擎状态；行为不回归。
  - 验证：默认 `cargo build --workspace` 零警告、52 测试通过；`cargo test -p daoti-core --features onnx inference` → 3 通过（含 onnx_engine 降级 2 用例）；`--features onnx,learning` 组合编译通过。

## 五层交互韧性映射（与开发计划 §7.3 一致）
| 层级 | 场景 | 必测异常路径 | 状态 |
|---|---|---|---|
| L1 | CLI/Daemon 主链路 | 加载失败/数据为空/超时 | ✅ 单测覆盖 |
| L2 | UI 模态框/推演详情 | 打开失败/超时/取消 | ✅ P0-4 CSP 收紧 + P0-7 修复面板 |
| L3 | UI 三环卡片/日志条目 | 加载失败/无响应 | ✅ P1-1 Lagged 补拉 + 指数退避 |
| L4 | UI 按钮/表单/快照回魂 | 超时/状态不恢复 | ✅ P0-7 恢复路径 + P0-5 历史补拉 |
| L5 | 跨层级 | 网络断开/崩溃/资源耗尽 | ✅ P1-3 补充测试（见下） |

---

## P1-3 七条异常路径韧性测试（2026-08-11 补齐）

### RES-003 SSE 长连接卡死 / 广播满
- **故障模式**：SSE 客户端断连或慢消费时，daemon 侧 `broadcast::send` 可能阻塞或 panic。
- **测试**：`publish_overflow_no_panic` — 发布 512 条（超过容量 256），断言不 panic + 接收 ≤256 条（旧事件丢弃）。
- **测试**：`publish_without_subscriber_no_panic` — 无订阅者时连续发布 10 条，断言不 panic。
- **位置**：`crates/daoti-daemon/src/eventbus.rs`
- **状态**：✅ 通过

### RES-004 执行超时 / Sensor 永不返回
- **故障模式**：子进程卡死（如 `Start-Sleep -Seconds 5`）导致 executor 永久阻塞。
- **测试**：`times_out_for_sleep` — PowerShell `Start-Sleep 5s`，100ms 超时断言 `Err` + 实际耗时 < 2s（超时真正触发）。
- **位置**：`crates/daoti-core/src/runner.rs`
- **状态**：✅ 通过（已有）

### RES-005 配置损坏
- **故障模式**：`~/.daoti.toml` 被手动编辑为乱码，解析 panic 导致 daemon 崩溃。
- **测试**：`corrupt_toml_no_panic` — 乱码 TOML 文本解析不 panic，未解析键保持默认值。
- **测试**：`empty_toml_falls_back_to_defaults` — 空文件不 panic，全部默认值。
- **位置**：`crates/daoti-common/src/config.rs`
- **状态**：✅ 通过

### RES-006 端口被占
- **故障模式**：17890 端口已被占用时 daemon 启动静默失败。
- **测试**：`try_bind_reports_occupied_port` — 先占端口，再绑定同一端口 → 返回可读错误。
- **位置**：`crates/daoti-cli/src/daemonctl.rs`
- **状态**：✅ 通过（已有）

### RES-007 快照损坏
- **故障模式**：快照 JSON 文件损坏/非快照文件混入目录 → 列表接口 panic 或返回垃圾数据。
- **测试**：`collect_ignores_non_snapshot_and_corrupt_files` — 损坏 JSON + 非快照文件，列表仅返回有效快照。
- **位置**：`crates/daoti-daemon/src/http.rs`
- **状态**：✅ 通过（已有）

| 场景 | 断言 | 状态 |
|------|------|------|
| SSE/广播满 | 不 panic + 旧事件丢弃 | ✅ RES-003 |
| 执行超时/Sensor卡死 | 超时触发 + 错误返回 | ✅ RES-004 |
| 配置乱码 | 不 panic + 默认值回退 | ✅ RES-005 |
| 端口被占 | 明确错误 + 非静默失败 | ✅ RES-006 |
| 快照损坏 | 跳过损坏条目 + 仅返回有效 | ✅ RES-007 |
