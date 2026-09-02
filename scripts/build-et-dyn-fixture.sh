#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-${root}/target/et_dyn_console_fixture}"
mkdir -p "$(dirname "$out")"
trap 'rm -f "${out}.o"' EXIT

cc="${CC:-cc}"
if ! command -v "$cc" >/dev/null 2>&1; then
  printf 'ET_DYN fixture requires a C compiler/linker (CC=%s)\n' "$cc" >&2
  exit 2
fi
"$cc" -c -fPIC -nostdlib -o "${out}.o" "${root}/tests/fixtures/et_dyn_console.S"
"$cc" -nostdlib -pie -Wl,--build-id=none -Wl,-e,_start -o "$out" "${out}.o"
rm -f "${out}.o"

if command -v readelf >/dev/null 2>&1; then
  type=$(readelf -h "$out" | awk -F: '/Type:/ {gsub(/^[ \t]+/, "", $2); print $2}')
  [ "$type" = "DYN (Position-Independent Executable file)" ] || {
    printf 'fixture is not ET_DYN (Type=%s)\n' "$type" >&2
    exit 1
  }
fi
printf 'built real ET_DYN fixture: %s\n' "$out"
