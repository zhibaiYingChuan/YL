# 驭灵·道体 Unix/glibc 动态执行知识学习框架

> 文档版本：v1.0  
> 编制日期：2026-08-25  
> 目标：让道体从 glibc/Unix 的规则与运行态样本中学习动态 ELF 初始化状态，并以可验证状态应用到解释器。

## 1. 边界

本框架是知识获取、样本编码、状态生成与验证框架，不替代 ELF 解释器，也不调用 WSL、Wine、QEMU、Docker 或其他外部执行器。

任何学习结果必须经过解释器真实执行验证。网络输出只能作为候选状态，不能直接证明 glibc 初始化正确。

## 2. 学习目标

1. 提取 `_rtld_global`、`link_map`、`_r_debug`、namespace 等结构的字段语义与偏移。
2. 提取 `dl_main`、对象创建、重定位和 syscall 对运行时状态的影响规则。
3. 将源码规则、调试现场和真实 Linux 快照编码为统一知识样本。
4. 生成候选初始化状态，并由状态应用器以边界校验后写入 `MemoryModel`。
5. 以 `hello_dynamic` 的真实解释执行作为最终验收。

## 3. 阶段计划

### 阶段 1：离线知识提取

输入来源：glibc 源码、System V ABI、x86-64 ABI、现有运行日志、Linux GDB 快照。

输出：JSONL 知识样本。当前 Windows 环境先支持源码规则和调试日志；没有 Linux 快照时不得宣称快照对齐完成。

### 阶段 2：候选状态生成

知识样本通过双梯形网络得到候选向量。向量只表达候选状态，不直接决定内存写入；必须经过字段映射和地址边界检查。

### 阶段 3：状态应用与差异反馈

状态应用器只允许写入声明过的字段地址。每次写入记录字段名、地址、旧值、新值和来源。执行失败现场转化为新的调试样本。

### 阶段 4：端到端验收

```text
daoti run ./fixtures/runtime/hello_dynamic
```

必须真实输出 `Hello from libc!` 并返回退出码 0。未达到该条件时，动态 ELF 仍标记为未闭环。

## 4. 知识表示

核心类型为 `GlibcKnowledgeSample`：

- `context`：状态上下文，如 `rtld_global_init`；
- `input_vector`：固定维度状态输入；
- `output_vector`：固定维度候选输出；
- `source`：`glibc_source`、`gdb_snapshot` 或 `debug_log`。

当前实现使用 JSON 兼容的向量表示，维度由加载器校验。生产知识库建议使用 JSONL，每行一个样本。

## 5. 安全与真实性约束

- 样本向量必须有限且维度一致；
- 来源必须属于允许枚举；
- 状态应用不得写入 ELF 映射范围之外；
- 不得因为网络输出而跳过重定位、TLS、auxv 或 link_map 的结构验证；
- Linux 快照缺失时，验收报告必须明确标注“未完成真实态对齐”。

## 6. 当前项目落点

- 双梯形网络：`crates/daoti-core/src/bilateral/network.rs`；
- glibc 知识模块：`crates/daoti-core/src/glibc_knowledge.rs`；
- 动态 ELF 装载器：`crates/daoti-core/src/elf/dynamic_loader.rs`；
- 真实执行验收：`fixtures/runtime/hello_dynamic`。

## 7. 当前状态

已具备：动态 ELF 映射、依赖加载、TLS、auxv、重定位和解释器执行链路；已定位 `_rtld_global._dl_ns[0]._ns_loaded` 候选字段并补充最小 `link_map` 头部。

未完成：glibc 源码结构提取器、知识样本持久化、候选状态应用器、Linux 真实快照对齐，以及 `hello_dynamic` 退出码 0 的端到端验收。
