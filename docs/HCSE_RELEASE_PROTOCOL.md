# HCSE 发布规范 — 驭灵（道体）

> 文档版本：v1.0 · 编制日期：2026-08-11 · 依据：推进计划-AdvancePlan.md P3-1
>
> 本文档定义驭灵项目从代码到发布的全链路可信交付检查项，与 HCSE 框架对齐。
> 发布前必须逐项通过，未通过项须在发布公告中明确标注。

---

## 1. 发布检查项

### 1.1 构建正确性

| 检查项 | 验证命令 | 通过标准 |
|--------|---------|----------|
| Rust workspace 编译 | `cargo build --workspace` | 零错误、零警告（允许预留 API 警告） |
| Clippy lint | `cargo clippy --workspace -- -D warnings` | 零告警 |
| 全量测试 | `cargo test --workspace` | 全部通过 |
| 前端构建 | `cd daoti-ui-web && bun run build` | vite build 成功 |
| UI feature 编译 | `cargo check -p daoti-ui --features ui` | 零错误 |

### 1.2 韧性覆盖（HCSE 五层交互）

依据 [HCSE_RESILIENCE_AUDIT.md](./HCSE_RESILIENCE_AUDIT.md)，发布前必须确认：

| 层级 | 场景 | 覆盖状态 |
|------|------|----------|
| L1 CLI/Daemon 主链路 | 加载失败/数据为空/超时 | ✅ RES-004 超时测试 + RES-005 配置损坏 + RES-006 端口被占 |
| L2 UI 模态框 | 打开失败/操作超时/取消 | ✅ P0-4 CSP + P0-7 修复面板 |
| L3 UI 卡片 | 加载失败/无响应 | ✅ P1-1 Lagged 补拉 + 指数退避 |
| L4 UI 按钮/表单 | 超时/状态不恢复 | ✅ P0-7 恢复路径 + P0-5 历史补拉 |
| L5 跨层级 | 网络断开/崩溃/资源耗尽 | ✅ RES-003 广播满 + RES-004 超时 + RES-007 快照损坏 |

### 1.3 安全红线

| 检查项 | 状态 | 实现位置 |
|--------|------|----------|
| 命令白名单校验 | ✅ | `SafeCommandExecutor` |
| 禁止模式黑名单 | ✅ | 拦截 `rm -rf /`, `format` 等 |
| `shell=false` 全量 | ✅ | 所有子进程经 `Command::args()` 传参 |
| Bun 红线（禁止 exec/spawn） | ✅ | `daoti-ui-web` 仅 HTTP/SSE 只读 |
| 日志脱敏（Webhook URL/输出截断） | ✅ | `sanitize_url` + `truncate_output_with_hint` |
| 单实例锁 + PID 文件 | ✅ | `daemon_pid_file()` + 存活检测 |

### 1.4 质量指标

| 指标 | 当前值 | 通过标准 |
|------|--------|----------|
| Rust 测试数 | 91 | ≥ 80 |
| 编译警告数（workspace） | 1（预留 API） | ≤ 1 |
| Clippy 警告数 | 0 | 0 |
| vcrc/lint 通过 | ✅ | 必须通过 |
| 阶段 7 preflight 证据 | ⚠️ 部分 | `daoti stage7-preflight --version vX.Y.Z --output <report.json>`；报告必须逐项记录状态，任一检查失败即阻断发布 |

### 1.5 依赖与环境差异检查

| 检查项 | 验证方式 |
|--------|----------|
| 本地与 CI 的 Rust 工具链版本一致 | `.github/workflows/ci.yml` 指定 `stable` |
| Windows + Ubuntu 双平台 CI | CI workflow 含双平台矩阵 |
| Tauri 构建需 WebView2 Runtime | `downloadBootstrapper` 自动下载 |
| 前端构建需 Bun | 发布包内嵌前端产物，用户无需安装 Bun |

---

## 2. 发布流程

### 2.1 发布前 checklist

- [ ] `cargo build --workspace` 零错误零警告
- [ ] `cargo test --workspace` 全量通过
- [ ] `cargo clippy --workspace -- -D warnings` 零告警
- [ ] `cd daoti-ui-web && bun run build` 成功
- [ ] `cargo check -p daoti-ui --features ui` 零错误
- [ ] 运行 `scripts/build-release.ps1` 产物完整
- [ ] Windows 全新机器安装测试（双击安装 → `daoti status` 三系统在线）
- [ ] 五种 HealOutcome 场景均验证通过
- [ ] SSE 断线重连 + 历史补拉验证通过
- [ ] 快照创建/列表/详情/diff UI 全链路通

### 2.2 版本标签规范

```
v{major}.{minor}.{patch}

- major: 不向后兼容的架构变更
- minor: 新增里程碑（如 P1→P2）
- patch: bug 修复、文档更新
```

### 2.3 发布公告模板

```markdown
# 驭灵（道体）v{x}.{y}.{z}

## 本版本里程碑
- [P0-P2 交付闭环完成] ...

## 已知限制
- ONNX 推理已移除，RuleEngine 为唯一推演引擎
- Webhook 通知仅支持企业微信/钉钉格式
- 前端需 Bun 构建，用户仅消费静态产物

## 安装方式
- 下载 `daoti-installer.exe`，双击安装
- 或解压 sidecar 二进制，执行 `daoti init`
```

---

## 3. 风险登记与缓解

| 风险 | 影响 | 缓解措施 | 当前状态 |
|------|------|----------|----------|
| 推演规则覆盖不足 | 未识别故障无法自动修复 | RuleEngine 持续扩充五行映射表；`daoti explain` 给白话路径 | 监控中 |
| Windows Defender 误杀二进制 | 安装后无法启动 | 代码签名（TRACK-02）；添加 Windows Defender 排除目录文档 | 待办 |
| WSL 发行版名不确定 | `daoti init` 探测失败 | 默认 `Ubuntu` 降级；配置可手动编辑 | ✅ 已缓解 |
| macOS/Linux 无传感器实现 | 仅 Windows 可用 | P3-3 跨平台扩展 | 待办 |

---
> 本协议随迭代持续更新。每次发布后回写 §3 风险登记与 §1 检查项的变更。
