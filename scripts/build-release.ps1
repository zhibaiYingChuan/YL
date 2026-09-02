<#
.SYNOPSIS
    驭灵·道体 统一构建脚本（P0-2 打包安装链路）
.DESCRIPTION
    构建顺序：daemon → CLI → 前端 → sidecar 复制 → UI 宿主（含 Tauri 打包）。
    产物：target/release/ 下二进制 + daoti-ui/bundle/ 下安装包。
    注意：sidecar 二进制必须随后端重新编译，否则 Tauri 打包会带入过期二进制（缺新端点）。
#>

# 本脚本必须以 UTF-8 with BOM 保存，否则 PS5.1 下中文注释会乱码
# 编码一致性保护 (适用于 PS5.1 和 PS7)
if ($PSVersionTable.PSVersion.Major -lt 6) {
    chcp 65001 > $null
}
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$Triple = "x86_64-pc-windows-msvc"

Write-Host "══════ 驭灵·道体 统一构建 ══════" -ForegroundColor Cyan
Write-Host "目标平台：$Triple`n"

# ── 1. Rust 后端 ──
Write-Host "[1/5] 构建 daemon 内核..." -ForegroundColor Yellow
Push-Location $Root
cargo build -p daoti-daemon --release
if ($LASTEXITCODE -ne 0) { throw "daemon 构建失败（退出码 $LASTEXITCODE）" }

Write-Host "[2/5] 构建 CLI 令牌..." -ForegroundColor Yellow
cargo build -p daoti-cli --release
if ($LASTEXITCODE -ne 0) { throw "CLI 构建失败（退出码 $LASTEXITCODE）" }

# ── 2. 前端（玄镜） ──
Write-Host "[3/5] 构建玄镜前端..." -ForegroundColor Yellow
Push-Location "$Root\daoti-ui-web"
$bun = if (Test-Path "$Root\daoti-ui-web\node_modules\.bin\bun.cmd") {
    "$Root\daoti-ui-web\node_modules\.bin\bun.cmd"
} else {
    "bun"
}
& $bun run build
if ($LASTEXITCODE -ne 0) { throw "前端构建失败（退出码 $LASTEXITCODE）" }
Pop-Location

# ── 3. 复制 sidecar 二进制 ──
Write-Host "[4/5] 复制 sidecar 二进制到 daoti-ui..." -ForegroundColor Yellow
$SidecarDir = "$Root\crates\daoti-ui\binaries"
$DaemonSrc = "$Root\target\release\daoti-daemon.exe"
$CliSrc = "$Root\target\release\daoti.exe"

if (-not (Test-Path -LiteralPath $DaemonSrc)) { throw "daemon 二进制缺失：$DaemonSrc" }
if (-not (Test-Path -LiteralPath $CliSrc)) { throw "CLI 二进制缺失：$CliSrc" }

Copy-Item -LiteralPath $DaemonSrc -Destination "$SidecarDir\daoti-daemon-$Triple.exe" -Force
Copy-Item -LiteralPath $CliSrc -Destination "$SidecarDir\daoti-$Triple.exe" -Force

# ── 4. Tauri 打包（含 sidecar） ──
Write-Host "[5/5] 打包 Tauri 安装包（含最新 sidecar）..." -ForegroundColor Yellow
Push-Location "$Root\crates\daoti-ui"
cargo tauri build --features ui
if ($LASTEXITCODE -ne 0) { throw "Tauri 打包失败（退出码 $LASTEXITCODE）" }
Pop-Location

Write-Host "`n✅ 构建完成！" -ForegroundColor Green
Write-Host "  daemon : $SidecarDir\daoti-daemon-$Triple.exe"
Write-Host "  CLI    : $SidecarDir\daoti-$Triple.exe"
Write-Host "  前端    : $Root\daoti-ui-web\dist"
Write-Host "  安装包  : $Root\target\release\bundle\"
