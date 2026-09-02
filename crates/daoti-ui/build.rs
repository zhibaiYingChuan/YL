//! 玄镜 Tauri 宿主构建脚本
//!
//! 仅当启用 `ui` feature 时才调用 `tauri_build::build()`（生成 Windows 资源/图标嵌入等）。
//! 未启用时为空操作，保证 `cargo build --workspace`（默认 feature）不引入 Tauri 重量依赖。

fn main() {
    #[cfg(feature = "ui")]
    {
        tauri_build::build();
    }
}
