# 模式B-B2 离线训练契约（道体·养）

> 对应《模式B-B2双梯形网络增强开发计划.md》§3 B2-7。
> 本文件为**契约定义**（非开发项）：约定离线训练闭环的输入 / 输出 / 职责 / 版本管理。
> 不引入 ONNX 或任何重型 ML 依赖；训练本身由独立后置工具链实现（P2）。

---

## 1. 闭环总览

```
在线采集（已实现）                    离线训练（独立后置，契约约束）
┌──────────────────────┐            ┌────────────────────────────────────┐
│ TelemetryCollector    │  JSON 落盘  │ ① 读 telemetry JSON                │
│ 四分类样本 + 覆盖率    │ ──────────► │ ② 配对样本（linux syscall → win 操作）│
│ (~/.daoti/telemetry/) │            │ ③ 训练双梯形网络（ascent/descent/bias）│
└──────────────────────┘            │ ④ 产出权重文件 + 写版本号            │
                                    └──────────────────┬─────────────────┘
                                                       │ 权重文件
                                                       ▼
                                    ┌────────────────────────────────────┐
                                    │ WeightsLoader::load()               │
                                    │ 校验 magic/version/dim 后供在线推理 │
                                    └────────────────────────────────────┘
```

**职责边界**：在线侧只负责「采集」与「加载校验」；离线侧负责「训练」与「产出」。
两侧以**权重文件格式**与**训练数据格式**两个契约为界面解耦。

---

## 2. 契约 A：训练数据格式（离线脚本的输入）

来源：`TelemetryCollector::to_json()`（`daoti-core/src/interceptor/telemetry.rs`）。
落盘目录：`~/.daoti/telemetry/`。

### 2.1 顶层结构

```json
{
  "records": [ /* MissRecord 数组，见 2.2 */ ],
  "next_seq": 1
}
```

- `next_seq`：单调递增序号游标（恢复落盘时续写，保证样本顺序稳定）。

### 2.2 MissRecord 结构

```json
{
  "seq": 1,
  "event": { "nr": 300, "name": "unknown", "args": [], "tid": 1 },
  "fallback": "wsl2",
  "outcome": "failure"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `seq` | u64 | 样本全局序号（单调递增） |
| `event.nr` | i32 | Linux syscall 编号（x86_64 ABI） |
| `event.name` | String | syscall 名称 |
| `event.args` | String[] | 参数（字符串描述，codec 转向量） |
| `event.tid` | u64 | 发起线程 id |
| `fallback` | String | 降级去向（`"wsl2"` / `"error"`；成功/反馈样本为空串 `""`） |
| `outcome` | enum | 四分类标签，见 2.3 |

### 2.3 outcome 四分类（snake_case 序列化）

| 枚举值 | JSON 值 | 语义 | 是否计入覆盖率分母 |
|---|---|---|---|
| `Success` | `"success"` | 命中映射 / 推导成功（道体·达 / 道体·化） | 是（分子） |
| `Failure` | `"failure"` | 未命中降级（道体·退） | 是（分母） |
| `UserPositive` | `"user_positive"` | 用户反馈：结果正确（道体·养） | 否 |
| `UserNegative` | `"user_negative"` | 用户反馈：结果错误（道体·养） | 否 |

> **覆盖率定义**：`coverage = Success 数 / (Success 数 + Failure 数)`。
> 用户反馈（`UserPositive` / `UserNegative`）**不计入**自动化覆盖率，仅作训练标签。

---

## 3. 契约 B：权重文件二进制格式（离线脚本的输出）

来源：`BilateralWeights::to_bytes()`（`daoti-core/src/bilateral/weights.rs`）。
所有整数与浮点均为**小端（little-endian）**。

### 3.1 布局（顺序固定）

| 偏移段 | 类型 | 内容 |
|---|---|---|
| 0 | u8×8 | 魔数 `"DAOTIBLT"`（ASCII，与字节序无关） |
| 8 | u32 LE | 版本号 `WEIGHTS_VERSION = 1` |
| 12 | u64 LE | 向量维度 `dim`（默认 2048） |
| 20 | u64 LE | 递归迭代次数 `t_iter`（默认 5） |
| 28 | u64 LE | 操作字典条目数 `op_dict_len` |
| 36 | — | 操作字典（见 3.2），重复 `op_dict_len` 次 |
| — | u64 LE + f64×len | 上梯形矩阵 `ascent`（行优先，长度 = `dim*dim`） |
| — | u64 LE + f64×len | 下梯形矩阵 `descent`（行优先，长度 = `dim*dim`） |
| — | u64 LE + f64×len | 偏置向量 `bias`（长度 = `dim`） |

### 3.2 操作字典条目（OpEntry）

| 字段 | 类型 | 内容 |
|---|---|---|
| `nr` | i32 LE | Linux syscall 编号 |
| `name` | u32 LE 长度 + UTF-8 字节 | syscall 名称 |
| `windows_op` | u32 LE 长度 + UTF-8 字节 | 映射后的 Windows 操作名 |

### 3.3 字符串编码

统一 `u32 LE（字节长度） + UTF-8 字节序列`，无空终止符。

### 3.4 加载校验（WeightsLoader::load）

| 校验项 | 失败行为 |
|---|---|
| 文件不存在 | `DaotiError::ModelMissing`（道体旁路，B1 不回归） |
| 魔数 ≠ `"DAOTIBLT"` | `DaotiError::ModelCorrupt` |
| 版本 ≠ `WEIGHTS_VERSION` | `DaotiError::ModelCorrupt` |
| `dim == 0` | `DaotiError::ModelCorrupt` |
| `ascent`/`descent` 长度 ≠ `dim*dim` | `DaotiError::ModelCorrupt` |
| `bias` 长度 ≠ `dim` | `DaotiError::ModelCorrupt` |
| 其它 I/O 错误 | `DaotiError::Io` |

---

## 4. 契约 C：离线脚本职责

离线脚本（独立工具链，非本期开发）须遵循以下职责序列：

1. **读**：加载 `~/.daoti/telemetry/` 下全部 JSON，按 `seq` 全局排序合并。
2. **配对**：以 `event.nr` + `event.name` + `event.args` 为键，将「linux syscall」与「windows 操作」配对；
   仅使用 `outcome ∈ {success, user_positive}` 的样本作正例，`failure / user_negative` 作负例/纠偏。
3. **训练**：产出 `ascent` / `descent` / `bias` 三个张量（维度 = `dim`，`t_iter` 为递归迭代次数）。
4. **产出**：调用与 `BilateralWeights::to_bytes()` **完全一致**的序列化，写入权重文件；
   必须写入 `op_dict`（nr + name + windows_op），供 codec 编解码复用。
5. **写版本号**：权重文件内嵌 `WEIGHTS_VERSION`；升版时同步更新 `weights.rs` 的 `WEIGHTS_VERSION` 常量。

**硬约束**：离线脚本不得绕过 `to_bytes()` 自造格式，否则加载端校验会拒绝。

---

## 5. 契约 D：权重版本管理

| 规则 | 说明 |
|---|---|
| 版本号持久化 | `WEIGHTS_VERSION` 随权重文件二进制持久化（第 8~11 字节） |
| 加载校验 | 加载时校验版本号与代码编译期常量一致，不一致 → `ModelCorrupt` |
| 维度校验 | 加载时校验 `ascent`/`descent` 长度 = `dim*dim`、`bias` 长度 = `dim` |
| 与配置一致 | `dim` 须与 `ModelConfig.model_dim`（平铺键 `model_dim`）一致，由道体接入层校验 |
| 升版流程 | 训练格式变更时：升 `WEIGHTS_VERSION` → 更新序列化/反序列化 → 全量回归 |

---

## 6. 文档-代码一致性对照

| 契约项 | 代码位置 | 状态 |
|---|---|---|
| 训练数据 JSON（四分类） | `crates/daoti-core/src/interceptor/telemetry.rs` | ✅ 已实现（B2-6 验收） |
| 权重二进制格式 | `crates/daoti-core/src/bilateral/weights.rs` | ✅ 已实现（B2-1 验收） |
| 魔数 / 版本常量 | `weights.rs` `MAGIC` / `WEIGHTS_VERSION` | ✅ 已实现 |
| 加载校验 | `weights.rs` `WeightsLoader::load` | ✅ 已实现 |
| 覆盖率统计 | `telemetry.rs` `coverage()` | ✅ 已实现（B2-6 验收） |
| 离线训练脚本 | 独立后置工具链（P2） | ⏳ 未开发（本契约为其约束） |

---

## 7. 验收口径

- [x] 契约 A（训练数据格式）与 `TelemetryCollector::to_json` 实际序列化一致
- [x] 契约 B（权重格式）与 `BilateralWeights::to_bytes` 实际序列化一致
- [x] 契约 D（版本管理）与 `WeightsLoader::load` 校验逻辑一致
- [ ] 契约 C（离线脚本）由 P2 独立工具链实现时，须以本文为验收基准
