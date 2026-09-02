#!/usr/bin/env bash
# 驭灵·道体 统一构建脚本（Linux / macOS，对应 scripts/build-release.ps1）
# 构建顺序：daemon → CLI → 前端 → sidecar 复制 → UI 宿主（含 Tauri 打包）。
# 产物：target/release/ 下二进制 + daoti-ui/bundles/ 下安装包。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"

echo "══════ 驭灵·道体 统一构建 ══════"
echo "目标平台：${TRIPLE}"
echo ""

# ── 1. Rust 后端 ──
echo "[1/4] 构建 daemon 内核..."
(cd "$ROOT" && cargo build -p daoti-daemon --release)

echo "[2/4] 构建 CLI 令牌..."
(cd "$ROOT" && cargo build -p daoti-cli --release)

# ── 2. 前端（玄镜） ──
echo "[3/4] 构建玄镜前端..."
if command -v bun >/dev/null 2>&1; then
  (cd "$ROOT/daoti-ui-web" && bun run build)
else
  (cd "$ROOT/daoti-ui-web" && npm run build)
fi

# ── 3. 复制 sidecar 二进制 ──
echo "[4/4] 复制 sidecar 二进制到 daoti-ui..."
SIDECAR_DIR="$ROOT/crates/daoti-ui/binaries"
DAEMON_SRC="$ROOT/target/release/daoti-daemon"
CLI_SRC="$ROOT/target/release/daoti"

if [ ! -f "$DAEMON_SRC" ]; then echo "daemon 二进制缺失：$DAEMON_SRC" >&2; exit 1; fi
if [ ! -f "$CLI_SRC" ]; then echo "CLI 二进制缺失：$CLI_SRC" >&2; exit 1; fi

cp "$DAEMON_SRC" "$SIDECAR_DIR/daoti-daemon-${TRIPLE}"
cp "$CLI_SRC" "$SIDECAR_DIR/daoti-${TRIPLE}"

echo ""
echo "✅ 构建完成！"
echo "  daemon: $SIDECAR_DIR/daoti-daemon-${TRIPLE}"
echo "  CLI   : $SIDECAR_DIR/daoti-${TRIPLE}"
echo "  前端   : $ROOT/daoti-ui-web/dist"
echo ""
echo "下一步：cargo build -p daoti-ui --features ui --release 生成 Tauri 安装包"
