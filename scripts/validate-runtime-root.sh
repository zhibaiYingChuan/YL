#!/usr/bin/env bash
set -euo pipefail

# 校验受控 runtime root 中真实动态链接器、libc 与 hello_dynamic 资产。
root="${1:-}"
if [[ -z "$root" ]]; then
    printf '用法：%s <runtime-root> [sha256-manifest]\n' "$0" >&2
    exit 2
fi
if [[ ! -d "$root" ]]; then
    printf 'runtime root 不存在：%s\n' "$root" >&2
    exit 1
fi

manifest="${2:-${root}/SHA256SUMS}"
command -v sha256sum >/dev/null 2>&1 || { printf '缺少 sha256sum\n' >&2; exit 2; }
command -v readelf >/dev/null 2>&1 || { printf '缺少 readelf\n' >&2; exit 2; }
[[ -f "$manifest" ]] || { printf '缺少 SHA256 manifest：%s\n' "$manifest" >&2; exit 1; }

lookup_asset() {
    local name="$1"
    local path
    path="$(find "$root" -type f \( -name "$name" -o -name "${name}.*" \) -print -quit)"
    [[ -n "$path" ]] || { printf '缺失 runtime 资产：%s\n' "$name" >&2; exit 1; }
    printf '%s\n' "$path"
}

verify_hash() {
    local path="$1"
    local rel expected actual
    rel="${path#"$root"/}"
    expected="$(awk -v p="$rel" '$2 == p || $2 == "*" p { print tolower($1); exit }' "$manifest")"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { printf 'manifest 缺少或非法 SHA256：%s\n' "$rel" >&2; exit 1; }
    actual="$(sha256sum "$path" | awk '{print tolower($1)}')"
    [[ "$actual" == "$expected" ]] || { printf 'SHA256 不匹配：%s\n期望：%s\n实际：%s\n' "$rel" "$expected" "$actual" >&2; exit 1; }
}

verify_elf() {
    local path="$1" require_interp="$2"
    local header interp needed
    header="$(readelf -h "$path")"
    grep -Eq 'Class:[[:space:]]+ELF64' <<<"$header" || { printf 'ELF 架构类别错误：%s\n' "$path" >&2; exit 1; }
    grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' <<<"$header" || { printf 'ELF machine 错误：%s\n' "$path" >&2; exit 1; }
    grep -Eq 'Type:[[:space:]]+DYN' <<<"$header" || { printf 'ELF 不是 ET_DYN：%s\n' "$path" >&2; exit 1; }
    interp="$(readelf -l "$path" | awk '/Requesting program interpreter:/ {gsub(/[\[\]]/, "", $NF); print $NF}')"
    if [[ "$require_interp" == 1 && -z "$interp" ]]; then
        printf '缺少 PT_INTERP：%s\n' "$path" >&2; exit 1
    fi
    needed="$(readelf -d "$path" 2>/dev/null | awk -F'[][]' '/NEEDED/ {print $2}')"
    if [[ "$require_interp" == 1 && -z "$needed" ]]; then
        printf '缺少 DT_NEEDED：%s\n' "$path" >&2; exit 1
    fi
    printf '通过：%s (PT_INTERP=%s)\n' "$path" "${interp:-none}"
}

loader="$(lookup_asset ld-linux-x86-64.so.2)"
libc="$(lookup_asset libc.so.6)"
hello="$(lookup_asset hello_dynamic)"
for asset in "$loader" "$libc" "$hello"; do verify_hash "$asset"; done
verify_elf "$loader" 0
verify_elf "$libc" 0
verify_elf "$hello" 1
printf 'runtime root 校验通过：%s\n' "$root"
