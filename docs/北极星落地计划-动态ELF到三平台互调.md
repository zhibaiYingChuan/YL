# 北极星落地计划：三平台任意软件互调

> 版本：v1.0  
> 状态：执行中  
> 适用范围：`daoti` workspace

## 1. 目标与真实性边界

北极星目标是：在 Windows、Linux、macOS 之间，根据二进制格式和可用执行资源，透明选择本地解释、平台桥接或远程节点执行，并统一返回 stdout、stderr、退出码和诊断信息。

当前交付证据限于 Windows 宿主上的受控 x86_64 ELF/ET_DYN 入口 fixture、解析和契约路径。`hello_libc.elf` 的真实 libc stdout 仍未验收；现有 `_IO_cleanup` 前的解释器级兼容捕获旁路不能宣称完成真实 guest `write` syscall 闭环，也不能代表任意 Linux 程序已支持。

硬约束：

- 不以固定地址、宿主输出注入或放宽断言伪造成功。
- 本地解释、宿主桥接、远程执行必须在执行报告中明确标识。
- 每个阶段先建立可验证的最小竖切，再扩展覆盖面。
- 动态 ELF、PE、Mach-O 失败时必须返回可诊断错误，不得静默回退为错误平台执行。

## 2. 分阶段路线

### 阶段 1：静态 ELF（已完成）

范围：Windows 宿主、x86_64、ET_EXEC、静态 Linux ELF。

验收：`hello_libc.elf` 输出 `Hello from libc!`，退出码 0；核心和 workspace 测试全绿。

### 阶段 2：动态 ELF（当前主线）

目标：分两条竖切交付动态 x86_64 ELF：先完成不依赖 glibc 的极简动态程序，再扩展到真实 glibc 依赖树。

#### 第一竖切：极简动态程序（当前目标）

范围：仓库固定的 `hello_minimal_dynamic.elf`，x86_64、ET_DYN、无 `PT_INTERP`、不链接 glibc，仅依赖自身 PT_LOAD 和动态重定位。执行必须走 `X86_64Interpreter` 与 `LinuxEmulationInjector`，输出写入审计缓冲区，不触碰宿主控制台或真实 OS 内存 API。

验收：段映射、load bias、`R_X86_64_RELATIVE` 重定位和入口执行均有证据；捕获固定文本 `Hello from minimal dynamic!`，退出码 0。fixture 缺失时测试必须明确 `ignored` 或报告环境缺失，不能假绿。极简竖切失败时不得静默切换桥接；若临时使用宿主桥接，执行报告必须标记 `bridge` 模式及回退原因。

#### 第二竖切：glibc 动态程序（后续目标）

范围：`hello_dynamic`、`ld-linux-x86-64.so.2`、`libc.so.6` 及其真实初始化 syscall、TLS、link_map 和依赖图。当前 glibc `rtld.c:1720` 的 `main_map` 断言尚未通过，因此不计入第一竖切验收，也不得宣称 libc 支持完成。

顺序：

1. 扩展 ELF 模型：保留 ELF 类型、`PT_INTERP`、动态段和基础动态标签；拒绝越界表项。
2. 建立 ET_DYN 装载模型：计算 load bias，映射 PT_LOAD，并以 `entry + load_bias` 启动。
3. 解析 `DT_NEEDED`、字符串表、符号表和 RELA 表；建立依赖图和循环检测。
4. 加载受控依赖根目录中的 `ld-linux-x86-64.so.2` 与 `libc.so.6`；搜索路径必须显式配置，禁止扫描宿主任意目录。
5. 实现 `R_X86_64_RELATIVE`、`R_X86_64_GLOB_DAT`、`R_X86_64_JUMP_SLOT`；第一版默认立即绑定。
6. 初始化动态 ELF 的 auxv、TLS 和入口调用约定。
7. 增加 Linux fixture 和 Windows CI 可复现测试；没有 fixture 时测试必须明确跳过或失败为环境缺失，不能假绿。

第一竖切验收：`hello_minimal_dynamic.elf` 的段映射、RELATIVE 重定位和本地解释执行，输出固定文本并返回 0。第二竖切是 glibc 动态程序（当前 `hello_dynamic`），因为它需要真实动态链接器、TLS、link_map、依赖树和更多 Linux syscall。

### 阶段 3：PE 解释器

先覆盖 Windows x86_64 控制台程序，不承诺 GUI。复用 runtime、MemoryModel、OutputSink 和 syscall bridge 抽象；新增 PE loader、导入表、基址重定位、Windows API shim。Notepad GUI 不是第一验收项，必须后置到窗口/消息循环能力具备后。

### 阶段 4：Mach-O 执行节点

第一版采用明确协议的远程 macOS executor：通过 `daoti-macos-node` 的 `POST /execute` 接收 base64 Mach-O、参数和超时，写入 macOS 临时目录后执行，返回 stdout/stderr/exit code。节点默认仅监听回环地址并要求 `X-Daoti-Token`；客户端 `MacOsHttpClient` 负责 HTTPS（本地回环测试允许 HTTP）、大小限制、超时和响应 request_id 校验。CI 在 macOS runner 上执行真实 Mach-O 节点测试；Windows/Linux 只验证协议与非 macOS 拒绝路径。Mach-O 本地解释器列为后续路线，不伪装成远程能力。

### 阶段 5：统一调度层（已恢复推进）

当前先实施自动能力探测：RemoteMacOs 在配置裁决后执行带超时的 `/health` 探测，成功才标记可用，失败记录结构化 fallback 事件；glibc 动态仿真作为阶段 2.5 长期研究主线并行推进，不阻塞本阶段。

#### 阶段 5 后续增强

引入：

```rust
pub enum ExecutionTarget {
    Native,
    StaticElfInterpreter,
    DynamicElfInterpreter,
    PeInterpreter,
    RemoteMacOs,
    RemoteLinux,
    RemoteWindows,
}
```

调度输入为路径、格式探测结果、宿主平台和能力注册表；调度输出必须包含目标、模式、版本、降级原因和可观测事件。调度层不直接解析格式，不绕过 executor 契约。

## 3. 当前实现任务清单

- [x] 固化静态 ELF MVP 真实性边界。
- [x] 为动态 ELF 增加结构化 program header / dynamic metadata 模型（仅解析/规划证据）。
- [x] 为 ET_DYN 增加 load bias 规划和测试。
- [x] 为 DT_NEEDED / RELA 增加纯解析测试（10 个场景，含边界与异常路径）。
- [x] 建立受控动态 ELF fixture 与 CLI metadata 验收；真实 PT_INTERP/libc 仍未验证。
- [x] 建立 PE、Mach-O、远程 executor 的契约测试骨架（仅 mock/契约路径，不代表真实 PE 或 macOS 节点可用）。
- [x] 完成 Mach-O LC_MAIN 入口换算与 fat 切片边界测试（仅本地解析，不代表远程 macOS 执行可用）。
- [x] 建立统一 `ExecutionTarget` 和 dispatch 诊断（已接入 Agent、CLI、daemon；真实可执行能力仍按目标标记）。

## 4. 动态 ELF 第一阶段契约

输入必须满足：ELF64、小端、x86_64、ET_DYN、存在 PT_LOAD、入口非零；PT_INTERP、动态表和所有表项必须在文件边界内。第一阶段只解析和规划，不在未完成重定位前执行。

输出必须提供：load bias、映射段列表、解释器路径（如存在）、DT_NEEDED 名称、动态标签、REL/RELA 数量和明确的 unsupported 原因。

## 5. 验证与发布门禁

每次动态 ELF变更必须运行：

```powershell
cargo fmt --all -- --check
cargo test -p daoti-core elf
cargo test --workspace
cargo run -p daoti-cli -- run .\hello_libc.elf
```

阶段性新增测试必须覆盖：正常路径、表项越界、缺少动态依赖、load bias 溢出、重定位类型不支持、超时/取消/错误恢复。任何失败都必须保留真实错误，不得修改现有严格 stdout 断言。

## 6. 统一 dispatch / CLI / daemon 验收测试

以下是当前仓库可重复执行的契约验收，不把 mock 或解析能力写成真实三平台执行能力：

```powershell
cargo test -p daoti-core dispatch
cargo test -p daoti-cli --test cli_smoke
cargo test -p daoti-daemon --test integration_test
```

验收覆盖：

- `daoti-core`：统一 `ExecutionTarget`、静态/动态 ELF、PE、Mach-O 诊断，以及 mock 节点契约。
- `daoti-cli`：`--help` 暴露 `dispatch` / `daemon`，缺失文件返回结构化错误；Windows 上另验静态/受控 ET_DYN fixture。
- `daoti-daemon`：`POST /api/dispatch` 未带 token 返回 401，带 token 后缺失目标返回 JSON 错误；健康、事件历史和快照回归继续执行。
- [x] 能力探测统一由 `CapabilityRegistry::probe_results()` 输出，CLI `daoti capabilities` 与 daemon dispatch 报告携带 `capability_evidence`；不可用目标必须保留失败原因。
- [x] CI 三平台（Ubuntu/Windows/macOS）执行 workspace check、能力探测命令与 CLI 入口门禁；通过结果只证明当前 runner 的真实探测，不勾选远程/mock 能力。
- [ ] 三平台真实二进制互调：当前仍未交付，不因 CI 编译/探测通过而勾选。
- 真实能力边界：当前仅有受控 ET_DYN 入口 fixture 及受控 Mach-O/PE fixture 的解析/契约证据；真实 libc、通用 PE native、WSL2/Docker 实际执行、远程 macOS/Linux/Windows 节点仍未验收，不能勾选通用能力。

## 7. 工程文化监督清单

- 契约优先：先测解析和布局，再接执行。
- TDD：每种动态标签先有纯函数测试，再进入 loader。
- 动态差异：每次变更审查代码、配置、fixture 和 CI 环境差异。
- 文档即代码：实现边界改变时同步架构总览和快速上手。
- 无责复盘：失败记录输入、运行模式、根因、检测盲区和新增检查项。
