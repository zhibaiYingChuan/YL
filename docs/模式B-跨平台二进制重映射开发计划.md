# 驭灵模式B：跨平台二进制信号重映射 — 开发计划

> 文档版本：v2.0 · 编制日期：2026-08-11
> 编制角色：创始者（产品决策）× 定义者（工程规范）联席定稿
> 依据：`驭灵模式B：跨平台二进制信号重映射 — 开发计划（重写版）.md`
> ONNX 状态：**完全移除，整个模式B不引入 ONNX 依赖**

## 0. 核心架构澄清：道体与双梯形网络的关系

| 角色 | 实体 | 职责 |
|------|------|------|
| **帅（大脑）** | 道体（agent.rs + decision/）| 决策、编排、降级、解释 |
| **将（工具）** | 双梯形网络（bilateral.rs）| `Array1<f64> → Array1<f64>` 纯数学变换 |
| **士兵** | Interceptor/Injector（interceptor/）| 拦截/注入系统调用 |
| **翻译官** | Encoder/Decoder（codec/）| SyscallEvent ↔ Array1<f64> 互转 |

**核心原则**：双梯形网络不做决策、不安排降级、不管理状态。所有"什么时候用、怎么用、失败了怎么办"都由道体决定。

## 1. 三阶段路线

| 阶段 | 名称 | 产品命名 | 策略 | 目标 |
|------|------|----------|------|------|
| B0 | 无感代理 | **道体·通** | 格式识别 + WSL2 隐形化 | `daoti run ./xxx` 语法成立 |
| B1 | 规则映射 | **道体·达** | 确定性 syscall 映射表（20个）| 常用调用直通，无需 WSL2 |
| B2 | 网络增强 | **道体·化** | 道体调度双梯形网络 | 复杂调用由网络推导转换 |

## 2. B0 道体·通（无感代理）

### 2.1 B0 已完成项
- ✅ `DaotiError` 新增 6 个模式B变体
- ✅ `EventKind` 新增 `CrossPlatformRun`/`RunFallback`
- ✅ CLI Run 命令 target 改为 `Option<String>`（`-t` 指定）
- ✅ `detect_binary_format()` 魔数检测 ELF/PE（当前在 commands.rs）

### 2.2 B0 待完成项

| 步骤 | 内容 | 文件 |
|------|------|------|
| B0-4 | BinaryFormat + detect_binary_format 提升至 daoti-common | `daoti-common/src/format.rs` |
| B0-5 | RunResult 结构体 + agent.run_cross_platform() | `daoti-core/src/agent.rs` |
| B0-6 | CLI run() 重构：调用 agent.run_cross_platform() + 判词风格输出 | `daoti-cli/src/commands.rs` |
| B0-7 | daemon Actor RunCrossPlatform 指令 | `daoti-daemon/src/actor.rs` |
| B0-8 | daemon HTTP POST /api/run 端点 | `daoti-daemon/src/http.rs` |
| B0-9 | 玄镜前端跨平台运行输入框 | `daoti-ui-web/src/App.jsx` + `daemon.js` |

### 2.3 B0 验收标准

| 编号 | 场景 | 预期 |
|------|------|------|
| B0-T1 | `daoti run ./nonexistent` | 判词"道体寻灵：……不在此间"→ 退出码 1 |
| B0-T2 | `daoti run ./hello.elf` | 判词"道体识灵：此乃 Linux 之躯 → 遣 WSL2 行之"→ 输出结果 |
| B0-T3 | `daoti run -t wsl2 ./hello.elf` | 向后兼容，跳过检测 |
| B0-T4 | 模式A `daoti heal` | 回归通过 |
| B0-T5 | `cargo build --workspace` | 零警告 |
| B0-T6 | `cargo test --workspace` | 全通过 |

## 3. B1 道体·达（规则映射）

### 3.1 模块清单

| 模块 | 路径 | 内容 |
|------|------|------|
| interceptor | `daoti-core/src/interceptor/` | Interceptor/Injector trait + SyscallEvent + SyscallMapper + 20映射表 |
| codec | `daoti-core/src/codec/` | Encoder/Decoder trait（B2预留，B1仅定义接口） |
| state | `daoti-core/src/interceptor/state.rs` | ProcessState（FD表/内存表/cwd/env） |
| telemetry | `daoti-core/src/interceptor/telemetry.rs` | TelemetryCollector（收集未命中syscall，B2训练数据基础） |
| agent | `daoti-core/src/agent.rs` | agent.run_b1() + DecisionPipeline |
| executor | `daoti-core/src/executor/safe.rs` | validate_inject() 注入安全校验 |

### 3.2 20个 syscall 确定性映射表

| nr | Linux | Windows 操作 |
|----|-------|-------------|
| 0 | read | ReadFile |
| 1 | write | WriteFile |
| 2 | open | CreateFileW |
| 3 | close | CloseHandle |
| 4 | stat | GetFileAttributesExW |
| 5 | fstat | GetFileInformationByHandle |
| 8 | lseek | SetFilePointerEx |
| 9 | mmap | VirtualAlloc |
| 11 | munmap | VirtualFree |
| 12 | brk | HeapAlloc/HeapFree |
| 13 | rt_sigaction | SetConsoleCtrlHandler |
| 16 | ioctl | DeviceIoControl |
| 19 | readv | 循环 ReadFile |
| 20 | writev | 循环 WriteFile |
| 21 | access | GetFileAttributesW |
| 22 | pipe | CreatePipe |
| 32 | dup | DuplicateHandle |
| 39 | getpid | GetCurrentProcessId |
| 79 | getcwd | GetCurrentDirectoryW |
| 186 | gettid | GetCurrentThreadId |

### 3.3 B1 降级链路

```
对每个 SyscallEvent：
  道体查映射表 → 命中 → inject → 更新 ProcessState
                 → 未命中 → 道体判断降级
                             → WSL2可用 → 切换到WSL2（批量降级阈值=5条）
                             → WSL2不可用 → 返回错误
```

### 3.4 B1 验收标准（10项，见开发计划重写版 §4.7）

## 4. B2 道体·化（网络增强）—— 必交付

**定位（更正）**：B2 双梯形网络是本期必交付的增强能力，非远期搁置项（旧版「远期核心」表述已纠正）。
网络是「加速路径」，WSL2 是「最终兜底」；网络任何环节失败都必须降级 WSL2 跑通，绝无死路。

**上线开关（非开发任务）**——以下条件全部满足才「上线」网络推理：
1. B1 映射覆盖率在真实场景中 > 80%
2. TelemetryCollector 积累 ≥ 10 万组配对 syscall 日志
3. 双梯形网络离线训练验证成功率 > 90%

上线开关与开发解耦：**开发照常进行（B2-0～B2-6），上线由 `B2Gate` 动态裁决**。详见《模式B-B2双梯形网络增强开发计划.md》。

## 5. 创始者产品建议（已采纳）

| 建议 | 采纳状态 | 落地 |
|------|----------|------|
| CLI 输出统一判词风格 | ✅ 采纳 | B0 实施中落地 |
| TelemetryCollector 前置 | ✅ 采纳 | B1 实施中落地 |
| 道体·通/达/化 命名 | ✅ 采纳 | 本文档使用 |
| 玄镜决策路径可视化 | B1 阶段实施 | UI 展示道体决策链 |
| DecisionPipeline 子模块 | B2 阶段预留 | 解耦道体职责 |
| WSL2 修复指引 | ✅ 采纳 | B0 错误信息含指引 |

---

> 本文档替换旧版 `模式B-跨平台二进制重映射开发计划.md`。每阶段完成后同步更新。
