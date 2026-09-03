#!/usr/bin/env bash
# 生成真实 glibc 动态 ELF hello fixture（任务 1 契约：Hello from libc! / 退出码 0）。
# 仅在 Linux runner 上执行；Windows/macOS 不提供真实 glibc 依赖树。
# 失败语义：环境缺少 C 编译器或 glibc 时显式退出 2（视为环境缺失），不生成半成品。
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-${root}/target/hello_glibc}"
provider_dir="$(dirname "$out")"
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
    printf 'glibc hello fixture requires a C compiler/linker (CC=%s) and glibc\n' "$cc" >&2
    exit 2
fi

# 最小化真实 libc 程序：write(1, "Hello from libc!\n") 后正常退出 0，
# 由 libc 启动例程（crt1.o + libc.so）完成 _start → __libc_start_main 初始化。
src="${provider_dir}/hello_glibc.c"
printf '%s\n' \
    '#include <unistd.h>' \
    'int main(void) {' \
    '  static const char message[] = "Hello from libc!\n";' \
    '  if (write(1, message, sizeof(message) - 1) != (ssize_t)(sizeof(message) - 1)) return 1;' \
    '  return 0;' \
    '}' > "$src"

# 使用默认 PIE 链接：现代发行版 gcc 默认产出 ET_DYN 位置无关可执行，
# 携带 PT_INTERP（/lib64/ld-linux-x86-64.so.2）与 DT_NEEDED=libc.so.6。
"$cc" -O0 -Wl,--build-id=none -Wl,-rpath,'$ORIGIN' -o "$out" "$src"
rm -f "$src"

# 受控依赖树：把真实 loader 与 libc 复制到 fixture 目录，
# 使 DynamicElfLoader 不依赖宿主机绝对路径即可完成真实解析。
cp "$loader" "${provider_dir}/ld-linux-x86-64.so.2"
cp "$libc" "${provider_dir}/libc.so.6"

if command -v readelf >/dev/null 2>&1; then
    type=$(readelf -h "$out" | awk -F: '/Type:/ {gsub(/^[ \t]+/, "", $2); print $2}')
    printf 'fixture ELF type: %s\n' "$type"
    # 契约：必须为 ET_DYN（Position-Independent Executable）
    [[ "$type" == *"DYN"* ]] || {
        printf 'fixture 不是 ET_DYN（Type=%s）\n' "$type" >&2
        exit 1
    }
    readelf -lW "$out" | grep -Eq 'INTERP' || {
        printf 'fixture 缺少 PT_INTERP（动态 ELF 契约）\n' >&2
        exit 1
    }
    readelf -dW "$out" | grep -q 'NEEDED.*libc.so.6' || {
        printf 'fixture 未声明 DT_NEEDED=libc.so.6\n' >&2
        exit 1
    }
fi
# 真实执行冒烟：确认 fixture 本身在宿主上可运行（作为基线，不等价于 daoti 解释器闭环）。
out_basename="$(basename "$out")"
(cd "$provider_dir" && "./$out_basename")

# 契约清单：记录 ET_DYN/PT_INTERP/DT_NEEDED/宿主冒烟结果，供 CI artifact 取证，
# 并在 daoti 解释器闭环完成前保留真实失败信号（不假绿）。
manifest="${provider_dir}/hello_glibc_manifest.txt"
{
    printf 'fixture=%s\n' "$out"
    printf 'loader=%s\n' "$loader"
    printf 'libc=%s\n' "$libc"
    if command -v readelf >/dev/null 2>&1; then
        readelf -h "$out" | awk -F: '/Type:/ {gsub(/^[ \t]+/, "", $2); printf "elf_type=%s\n", $2}'
        readelf -lW "$out" | awk '/INTERP/ {print "has_pt_interp=yes; interp=" $2; exit}'
        readelf -dW "$out" | grep 'NEEDED' | awk '{print "dt_needed=" $5}'
    fi
} > "$manifest"

printf 'built real glibc hello fixture: %s\n' "$out"
printf 'manifest: %s\n' "$manifest"
cat "$manifest"