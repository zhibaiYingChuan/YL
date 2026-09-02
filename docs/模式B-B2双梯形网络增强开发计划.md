# 驭灵模式B · B2 双梯形网络增强（道体·化）开发计划

> 文档版本：v1.0 · 编制日期：2026-08-15
> 编制角色：创始者（产品决策）× 定义者（工程规格）联席定稿
> 依据：`驭灵模式B：跨平台二进制信号重映射 — 开发计划（重写版）.md` §5
> 性质：契约性规范（做什么、以什么顺序做、怎么证明做完），非实现代码。
> **重要更正**：B2 由旧版「远期核心 / 不在当前交付范围」更正为「**本期必交付增强能力**」。

---

## 0. 一句话定位与边界（创始者）

- **定位**：B2 是本期**必交付**的「增强能力」，不是预留接口，更不是远期搁置项。
- **加速路径 vs 最终兜底**：双梯形网络是「加速路径」，WSL2 是「最终兜底」。网络任何环节失败（未就绪/置信度不足/解码非法/推理 NaN）都必须降级到 WSL2 跑通，**绝无死路**。
- **职责边界不变**（重申重写版 §6）：
  - 双梯形网络 = 「将」，唯一职责是 `Array1<f64> → Array1<f64>` 纯数学变换；**不决策、不降级、不管理状态、不读配置**。
  - 道体 = 「帅」，负责「什么时候用、怎么用、失败了怎么办」：编码调度、网络调度、解码调度、结果验证、置信度评估、降级决策、学习反馈。

---

## 1. 触发三条件重定义：上线开关 ≠ 开发任务

旧文档把三条触发条件写成「全部满足才启动（否则不实施）」，这是误读。现明确：

| 项目 | 旧语义（错误） | 新语义（正确） |
|---|---|---|
| 覆盖率 > 80% | 不满足就不开发 | 上线开关之一，开发照常进行 |
| ≥ 10 万组配对日志 | 不满足就不开发 | 运行期自然积累，非开发前置 |
| 验证成功率 > 90% | 不满足就不开发 | 离线训练结果门槛，上线开关之一 |

**结论**：三条触发条件 = **上线开关（gate）**，决定「网络推理是否真正参与在线决策」；**与开发解耦**。开发按 B2-0～B2-6 全量交付，上线由 `B2Gate` 动态裁决（默认不满足时网络旁路，B1 行为不回归）。

---

## 2. 优先级分层 P0 / P1 / P2（创始者）

| 层 | 内容 | 性质 |
|---|---|---|
| **P0 必要开发** | bilateral 纯数学 / codec 落地 / decision 接入 / 置信度校验与 gate | 本期交付 |
| **P1 运行积累** | 10 万组配对日志自然积累 + 覆盖率统计能力 + 样本四分类采集 | 运行期产生，非一次性开发 |
| **P2 独立后置** | 离线训练工具链 + 权重版本管理 | 可独立后置，不阻塞 B2 主链路 |

---

## 3. 分步开发计划 B2-0 ~ B2-7（定义者骨架）

> 每步独立编译 + 独立验收，严禁批量修改（用户硬约束）。默认状态下 B1 不回归。

### B2-0 依赖与配置

- 根 `Cargo.toml` `[workspace.dependencies]` 新增 `ndarray = "0.15"`（**不启用 blas feature**：ndarray 的 blas/OpenBLAS 为独立可选 feature、默认即不启用，故保留默认 `std` 而无需 `default-features=false`，以支撑 B2-2 使用 `Array1<f64>` 的 `from_vec/to_vec/dot` 便利 API；稳定版锁定为 0.15.6）。
- `crates/daoti-core/Cargo.toml` 新增 `ndarray = { workspace = true }`。
- `crates/daoti-common/src/config.rs` 新增 `ModelConfig` 平铺字段（**不扩展嵌套表**，兼容现有极简解析器）：
  - `model_enabled: bool`（默认 `true`，能力开关，可随时关）
  - `model_weights_path: String`（默认 `~/.daoti/bilateral_weights.bin`）
  - `model_dim: usize`（默认 `2048`）
  - `model_t_iter: usize`（默认 `5`）
  - `model_confidence_threshold: f64`（默认 `0.7`）
- 同步三处：`Config::default()`、`to_toml_string()`、`toml_parse()`（平铺键 `model_*`），并补默认值单测。

**验收**：`cargo build --workspace` 零警告；`cargo test -p daoti-common` 通过（含 `model_*` 解析/序列化 roundtrip）。

### B2-1 权重加载器

- 新增 `crates/daoti-core/src/bilateral/weights.rs`。
- 自定义二进制权重格式：magic `"DAOTIBLT"` + version + dim + t_iter + 层参数 + 操作字典。
- `WeightsLoader::load(path) -> Result<BilateralWeights, DaotiError>`：缺失 → `DaotiError::ModelMissing`；损坏 → 明确错误，**均不 panic**。
- 无权重文件时网络侧返回「不可用」，由道体旁路（不影响 B1）。

**验收**：加载合法权重成功；缺失/损坏路径返回结构化错误；单测覆盖。

### B2-2 bilateral 纯数学

- 新增 `crates/daoti-core/src/bilateral/mod.rs`，`crates/daoti-core/src/lib.rs` 注册 `pub mod bilateral;`。
- `BilateralLadderNetwork::forward(&self, input: Array1<f64>) -> Result<Array1<f64>, DaotiError>`：
  - 正向传播（底层→顶层抽象意图）+ 逆向传播（顶层→底层具象信号）+ 递归迭代 `t_iter` 次（信号共振）。
  - 维度/`t_iter` 由**构造参数**传入（不读配置，守住「将不做决策」边界）。
  - 检测输出 NaN/Inf → `DaotiError::InferenceFailed`。

**验收**：维度保持 2048→2048；同输入同输出（确定性）；NaN/Inf 被拦截；零向量安全；单测覆盖。

### B2-3 codec 落地

- `crates/daoti-core/src/codec/mod.rs`：
  - `Encoder`/`Decoder` trait 由 `Vec<f64>` / `&[f64]` 改为 `Array1<f64>`。
  - `Decoder::decode` 返回 `DecodeOutcome { event, confidence }`（而非裸 `SyscallEvent`，供置信度校验）。
  - 落地 `SyscallCodec`：`SyscallEvent → Array1<f64>`（nr + name hash + args）与逆向（经 B2-1 的操作字典还原 `SyscallEvent`）。
- 移除 `NoopCodec` 占位，替换为真实实现 + 单测。

**验收**：encode→decode roundtrip 在已知字典内一致；未知操作返回 `DaotiError::DecodeError`；trait 契约单测更新。

### B2-4 道体接入

- `crates/daoti-core/src/agent.rs`：
  - `DecisionPipeline` 新增 `network: Option<BilateralLadderNetwork>`、`codec: Option<SyscallCodec>`、`gate: B2Gate`。
  - `step()` 的 `None` 分支，在 `telemetry.record_miss(...)` **之前**插入 `try_derive`：
    - gate 通过 → encode → forward → decode → 置信度校验 → 成功返回新变体 `B1Step::Derived { operation, confidence }`；
    - gate 未通过 / 推理失败 / 置信度不足 / 解码非法 → 回落到 `record_miss` 降级链路。
  - 默认 `network=None`（构造不含网络），**B1 行为不回归**。

**验收**：`network=None` 时全部现有 B1 测试通过；`network=Some` + gate 通过时未命中事件走推导路径；gate 不通过时仍降级。

### B2-5 置信度 / gate / 注入校验分层

- 新增 `crates/daoti-core/src/bilateral/gate.rs`：`B2Gate` 四条件 `is_ready()` + `unmet_reasons()`：
  1. `model_enabled`（配置）
  2. 覆盖率 > 80%
  3. 配对样本 ≥ 10 万
  4. 验证成功率 > 90%
- 注入校验分层：新增 `validate_derived`（**仅黑名单**），不复用 B1 的 20 条白名单，避免误杀 B2 推导出的合法 Win32 操作（如 `WSAStartup`）。

**验收**：gate 四条件枚举与 `unmet_reasons` 单测；`validate_derived` 放行白名单外但非黑名单的操作、拦截黑名单操作。

### B2-6 反馈采集 / 落盘

- `crates/daoti-core/src/interceptor/telemetry.rs` 扩展样本四分类：成功 / 失败 / 用户反馈（正/负），落盘 `~/.daoti/telemetry/`。
- 保留现有 `MissRecord` 结构并追加 `outcome` 分类字段；新增覆盖率统计（已命中数 / 总数）。
- 在线推理权重不变（重写版 §5.6）；仅采集供离线训练。

**验收**：四分类记录与落盘/重载 roundtrip；覆盖率统计单测。

### B2-7 离线训练契约（非开发项，仅定义）

- 定义训练数据格式、离线脚本职责（读 telemetry → 训练 → 产出权重文件 → 写版本号）。
- 权重版本管理：版本号随权重文件持久化，加载时校验与 `model_dim` 一致。
- **不引入 ONNX / 重型 ML 依赖**。

**验收**：契约文档与代码加载格式一致（文档-代码一致性）。

> 契约正文见 [`模式B-B2离线训练契约.md`](./模式B-B2离线训练契约.md)，其中契约 A/B/C/D 与 `telemetry.rs`、`weights.rs` 实现逐项对齐。

---

## 4. 接口契约总表（与 TechnicalPlan §9.2 一致）

| 契约 | 签名 | 备注 |
|---|---|---|
| 网络前向 | `BilateralLadderNetwork::forward(&self, Array1<f64>) -> Result<Array1<f64>, DaotiError>` | 纯数学，无副作用 |
| 编码 | `Encoder::encode(&self, &SyscallEvent) -> Result<Array1<f64>, DaotiError>` | 由 `Vec<f64>` 改为 `Array1<f64>` |
| 解码 | `Decoder::decode(&self, &Array1<f64>) -> Result<DecodeOutcome, DaotiError>` | 返回 event + confidence |
| 权重加载 | `WeightsLoader::load(&Path) -> Result<BilateralWeights, DaotiError>` | 缺失 → `ModelMissing` |
| 上线裁决 | `B2Gate::is_ready() -> bool` + `unmet_reasons() -> Vec<String>` | 四条件 |
| 配置 | `Config.model: ModelConfig`（平铺键 `model_*`） | 兼容极简解析器 |

---

## 5. 判词体系（创始者）

**用户可见（道体对外）**：

| 判词 | 语义 | 触发 |
|---|---|---|
| 道体·达 | 规则直通 | B1 映射表命中 |
| 道体·化 | 网络推导 | B2 gate 通过且推导成功注入 |
| 道体·疑 | 网络存疑 | 置信度不足 / 解码非法，转降级 |
| 道体·退 | WSL2 兜底 | 网络失败或未就绪，降级 WSL2 |
| 道体·养 | 反馈采集 | 记录成功/失败/用户反馈供离线训练 |

**内部过程（道体内部，不直接外显）**：

| 判词 | 语义 |
|---|---|
| 道体·识 | 识别 syscall 未命中映射表 |
| 道体·寻 | 编码：SyscallEvent → Array1<f64> |
| 道体·译 | 解码：Array1<f64> → SyscallEvent |
| 道体·断 | 置信度判断 + 降级决策 |

---

## 6. 验收口径（创始者）：能化 / 能疑 / 能退 / 能养 / 能解释

| 口径 | 场景 | 预期 |
|---|---|---|
| **能化** | gate 通过 + 权重就绪，未命中 syscall | 网络推导出合法操作并注入，判词「道体·化」 |
| **能疑** | 置信度 < 阈值 或 解码非法 | 不注入，判词「道体·疑」，转降级 |
| **能退** | 网络未就绪 / 推理失败 / gate 未通过 | 降级 WSL2 跑通，判词「道体·退」，绝无死路 |
| **能养** | 每次推导/降级 | 成功/失败/用户反馈四分类落盘，供离线训练 |
| **能解释** | 任意路径 | 判词可解释「为何走网络 / 为何降级」 |

---

## 7. 风险与护栏

| # | 风险 | 缓解 |
|---|---|---|
| R1 | 网络输出 NaN/Inf 或维度错乱 | `forward` 内检测并返回 `InferenceFailed`；道体旁路降级 |
| R2 | 推导操作误注入危险 Win32 | `validate_derived` 黑名单校验（不复用白名单） |
| R3 | B2 引入后 B1 回归 | 默认 `network=None`，B1 全量测试不回归（回归红线） |
| R4 | 权重文件缺失/损坏 | 加载器结构化报错 + 道体旁路，不 panic |
| R5 | 重依赖拖累编译 | ndarray 不启用 blas（默认即不含 OpenBLAS/LAPACK）；不引入 ONNX/重型 ML |
| R6 | 配置解析器不兼容嵌套表 | 用平铺键 `model_*`，不动极简解析器 |

---

## 8. 文档同步与验收证据

1. 本文件与 `docs/开发计划-TechnicalPlan.md` §9.2 / §9.3 同步（B2 由「待推进/废弃」更正为「必交付」）。
2. `docs/模式B-跨平台二进制重映射开发计划.md` §4 删除「B2 不在当前交付范围」。
3. `驭灵模式B：跨平台二进制信号重映射 — 开发计划（重写版）.md` §5 删除「远期核心」与「B2 不启用，系统停留在 B1 状态」。
4. 每步交付同步 LRC 记忆 + 更新 §3 状态 + `cargo test --workspace` 全量回归。

> **道体玄盾 · 守护每一次生成** —— B2 是「化形」之力，网络是捷径，WSL2 是兜底，绝无死路。
