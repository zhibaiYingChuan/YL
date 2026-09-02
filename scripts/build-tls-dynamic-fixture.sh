#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-${root}/target/tls_dynamic}"
provider_dir="$(dirname "$out")"
provider="${provider_dir}/libtls_provider.so"
provider_b="${provider_dir}/libtls_provider_b.so"
mkdir -p "$provider_dir"

cc="${CC:-cc}"
libc="$(ldconfig -p 2>/dev/null | awk '/libc\.so\.6 \(.*x86-64/ {print $NF; exit}')"
if [[ -z "$libc" || ! -f "$libc" ]]; then
    libc="/lib/x86_64-linux-gnu/libc.so.6"
fi
loader="/lib64/ld-linux-x86-64.so.2"
if [[ ! -f "$loader" ]]; then
    loader="/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
fi
if ! command -v "$cc" >/dev/null 2>&1 || [[ ! -f "$libc" || ! -f "$loader" ]]; then
    printf 'TLS fixture requires a C compiler/linker (CC=%s)\n' "$cc" >&2
    exit 2
fi

"$cc" -O0 -fPIC -shared -ftls-model=global-dynamic \
    -Wl,--build-id=none -Wl,-soname,libtls_provider.so -o "$provider" \
    "${root}/tests/fixtures/tls_provider.c"
"$cc" -O0 -fPIC -shared -ftls-model=global-dynamic \
    -Wl,--build-id=none -Wl,-soname,libtls_provider_b.so -o "$provider_b" \
    "${root}/tests/fixtures/tls_provider_b.c"
# 主程序通过汇编明确生成 GD TLS 序列，避免不同 linker 对 C TLS 模型
# 做不同 relaxation；该序列直接携带 DTPMOD64/DTPOFF64 与 __tls_get_addr@PLT。
# 根对象使用 ET_DYN 共享链接：它保留 GD TLS 重定位和 PLT 调用，
# 同时由自有 _start 通过 exit syscall 结束，不引入 libc 启动代码。
"$cc" -nostdlib -shared -fPIC -Wl,-e,_start \
    -Wl,--build-id=none -Wl,-z,now -Wl,-rpath,'$ORIGIN' \
    -L"$provider_dir" -Wl,-rpath,'$ORIGIN' \
    -o "$out" "${root}/tests/fixtures/tls_dynamic.S" \
    -ltls_provider -ltls_provider_b -Wl,--no-as-needed "$libc" -Wl,--as-needed

if command -v readelf >/dev/null 2>&1; then
    for tls_provider in "$provider" "$provider_b"; do
        readelf -lW "$tls_provider" | grep -Eq '[[:space:]]TLS[[:space:]]' || {
            printf 'TLS provider has no PT_TLS: %s\n' "$tls_provider" >&2
            exit 1
        }
    done
    readelf -rW "$out" | grep -Eq 'DTPMOD|DTPOFF|TLS' || {
        printf 'TLS fixture has no dynamic TLS relocation: %s\n' "$out" >&2
        exit 1
    }
    readelf -Ws "$provider" | grep -q 'daoti_tls_value' || {
        printf 'TLS provider has no daoti_tls_value symbol: %s\n' "$provider" >&2
        exit 1
    }
    readelf -Ws "$provider_b" | grep -q 'daoti_tls_value_b' || {
        printf 'TLS provider has no daoti_tls_value_b symbol: %s\n' "$provider_b" >&2
        exit 1
    }
fi
# DT_NEEDED 使用稳定名称；把实际链接的 libc 复制到受控 fixture 根目录，
# 使 DynamicElfLoader 不依赖宿主机绝对路径即可完成真实依赖解析。
cp "$libc" "${provider_dir}/libc.so.6"
cp "$loader" "${provider_dir}/ld-linux-x86-64.so.2"
printf 'built real TLS ET_DYN fixture: %s\n' "$out"
