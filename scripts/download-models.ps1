<# .SYNOPSIS
    下载驭灵道体 ONNX 权重到 models/ 目录。

.DESCRIPTION
    将 daoti.onnx 权重下载到 models/ 目录。权重体积较大（数 MB 至数百 MB），
    故不随仓库入库；本脚本支持从 URL 或环境变量 DAOTI_MODEL_URL 获取下载地址。
    默认启用"已有文件则跳过"，可用 -Force 强制覆盖；下载采用临时文件 + 原子
    重命名，避免半截文件被推理层当作有效模型加载。

.PARAMETER Url
    权重下载地址。若省略，则读取环境变量 $env:DAOTI_MODEL_URL；两者皆无则报错。

.PARAMETER OutDir
    输出目录，默认项目根下的 models/。

.PARAMETER Force
    若目标文件已存在，是否强制重新下载覆盖。默认跳过已有文件。

.EXAMPLE
    # 从环境变量地址下载
    $env:DAOTI_MODEL_URL = "https://example.com/daoti.onnx"
    ./scripts/download-models.ps1

.EXAMPLE
    # 显式指定地址并强制覆盖
    ./scripts/download-models.ps1 -Url "https://example.com/daoti.onnx" -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Url,

    [Parameter(Mandatory = $false)]
    [string]$OutDir = "g:\Yl\models",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# 解析权重地址：优先参数，其次环境变量（不硬编码臆造地址）
if ([string]::IsNullOrWhiteSpace($Url)) {
    $Url = $env:DAOTI_MODEL_URL
}
if ([string]::IsNullOrWhiteSpace($Url)) {
    Write-Error "未提供权重地址。请用 -Url 参数或设置环境变量 DAOTI_MODEL_URL。"
    exit 1
}

# 目标文件名固定为 daoti.onnx（推理层按此约定探测）
$TargetName = "daoti.onnx"
$TargetPath = Join-Path -Path $OutDir -ChildPath $TargetName

# 已存在且未强制覆盖 → 跳过（幂等，避免重复下载大文件）
if ((Test-Path -LiteralPath $TargetPath) -and (-not $Force)) {
    Write-Host "模型已存在: $TargetPath （用 -Force 强制重新下载）"
    exit 0
}

# 确保输出目录存在（New-Item 幂等）
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 下载到同目录临时文件，下载完成后原子重命名，避免半截文件
$TempPath = Join-Path -Path $OutDir -ChildPath "$TargetName.partial"
Write-Host "下载中: $Url"

try {
    Invoke-WebRequest -Uri $Url -OutFile $TempPath -ErrorAction Stop
} catch {
    # 清理半截临时文件，避免残留
    if (Test-Path -LiteralPath $TempPath) {
        Remove-Item -LiteralPath $TempPath -Force
    }
    Write-Error "下载失败: $($_.Exception.Message)"
    exit 1
}

# 完整性校验：下载文件不得为空
$file = Get-Item -LiteralPath $TempPath -ErrorAction Stop
if ($file.Length -le 0) {
    Remove-Item -LiteralPath $TempPath -Force
    Write-Error "下载文件为空，已中止。"
    exit 1
}

# 原子重命名：覆盖已存在的目标（先删旧后改名，保证最终一致）
if (Test-Path -LiteralPath $TargetPath) {
    Remove-Item -LiteralPath $TargetPath -Force
}
Move-Item -LiteralPath $TempPath -Destination $TargetPath -Force

Write-Host "完成: $TargetPath （$([math]::Round($file.Length / 1MB, 2)) MB）"