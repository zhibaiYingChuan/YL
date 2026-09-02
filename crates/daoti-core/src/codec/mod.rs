//! 编解码层 (daoti-core::codec)
//!
//! 模式B 的"翻译官"：`SyscallEvent` ↔ 数值向量 互转。对应《模式B-B2双梯形网络增强开发计划.md》
//! §3 B2-3：trait 契约由 `Vec<f64>` 升级为 `Array1<f64>`，落地 `SyscallCodec`
//! （nr + name hash + args hash 打包），解码返回 `DecodeOutcome { event, confidence }` 供道体置信度校验。

use daoti_common::DaotiError;
use ndarray::Array1;

use crate::bilateral::weights::OpEntry;
use crate::interceptor::SyscallEvent;

/// 编码契约：SyscallEvent → 数值向量（双梯形网络的输入）
pub trait Encoder: Send + Sync {
    /// 将 syscall 事件编码为数值向量
    fn encode(&self, event: &SyscallEvent) -> Result<Array1<f64>, DaotiError>;
}

/// 解码契约：数值向量 → 带置信度的 syscall 事件（双梯形网络输出还原）
pub trait Decoder: Send + Sync {
    /// 将数值向量解码为 syscall 事件 + 置信度
    fn decode(&self, vector: &Array1<f64>) -> Result<DecodeOutcome, DaotiError>;
}

/// 解码结果：事件 + Win32 操作名 + 置信度（供道体 gate 校验，低于阈值则降级）
#[derive(Debug, Clone, PartialEq)]
pub struct DecodeOutcome {
    /// 还原出的 syscall 事件（`name` 为 Linux 名称）
    pub event: SyscallEvent,
    /// 推导出的 Win32 操作名（来自操作字典 `windows_op`，供 `B1Step::Derived.operation` 使用）
    pub windows_op: String,
    /// 置信度（0.0~1.0），由 nr 槽位整数接近度决定
    pub confidence: f64,
}

/// 真实编解码器：nr + name hash + args hash 打包成 `dim` 维向量；
/// 逆向经操作字典（B2-1 的 `op_dict`）还原 `SyscallEvent`。
#[derive(Debug, Clone)]
pub struct SyscallCodec {
    dim: usize,
    op_dict: Vec<OpEntry>,
}

impl SyscallCodec {
    /// Linux x86_64 syscall 硬编码表（常用动态 ELF/glibc 基础调用）。
    pub fn linux_x86_64_table() -> Vec<OpEntry> {
        [
            (0, "read", "ReadFile"),
            (1, "write", "WriteFile"),
            (2, "open", "CreateFileW"),
            (3, "close", "CloseHandle"),
            (4, "stat", "GetFileAttributesExW"),
            (5, "fstat", "GetFileInformationByHandle"),
            (8, "lseek", "SetFilePointerEx"),
            (9, "mmap", "VirtualAlloc"),
            (11, "munmap", "VirtualFree"),
            (12, "brk", "VirtualAlloc"),
            (39, "getpid", "GetCurrentProcessId"),
            (60, "exit", "ExitProcess"),
            (89, "readlink", "GetFinalPathNameByHandleW"),
            (158, "arch_prctl", "SetThreadContext"),
            (202, "futex", "WaitOnAddress"),
            (218, "set_tid_address", "SetThreadId"),
            (231, "exit_group", "ExitProcess"),
            (257, "openat", "CreateFileW"),
            (262, "newfstatat", "GetFileAttributesExW"),
            (273, "set_robust_list", "SetThreadContext"),
            (302, "prlimit64", "GetProcessInformation"),
            (318, "getrandom", "BCryptGenRandom"),
        ]
        .into_iter()
        .map(|(nr, name, windows_op)| OpEntry {
            nr,
            name: name.into(),
            windows_op: windows_op.into(),
        })
        .collect()
    }

    /// 按 Linux x86_64 编号查找硬编码 syscall。
    pub fn linux_x86_64_syscall(nr: i32) -> Option<OpEntry> {
        Self::linux_x86_64_table()
            .into_iter()
            .find(|entry| entry.nr == nr)
    }

    /// 构造编解码器，`dim` 至少为 3（nr / tid / name hash 三个固定槽位）。
    pub fn new(dim: usize, op_dict: Vec<OpEntry>) -> Result<Self, DaotiError> {
        if dim < 3 {
            return Err(DaotiError::DecodeError("编解码维度至少为 3".into()));
        }
        Ok(Self { dim, op_dict })
    }

    /// 编码维度
    pub fn dim(&self) -> usize {
        self.dim
    }
}

impl Encoder for SyscallCodec {
    fn encode(&self, event: &SyscallEvent) -> Result<Array1<f64>, DaotiError> {
        let mut v = Array1::zeros(self.dim);
        v[0] = event.nr as f64;
        v[1] = event.tid as f64;
        v[2] = hash_to_unit(&event.name);
        for (i, arg) in event.args.iter().enumerate() {
            let idx = 3 + i;
            if idx >= self.dim {
                break;
            }
            v[idx] = hash_to_unit(arg);
        }
        Ok(v)
    }
}

impl Decoder for SyscallCodec {
    fn decode(&self, vector: &Array1<f64>) -> Result<DecodeOutcome, DaotiError> {
        if vector.len() != self.dim {
            return Err(DaotiError::DecodeError(format!(
                "向量维度 {} 与编解码维度 {} 不符",
                vector.len(),
                self.dim
            )));
        }
        let nr_f = vector[0];
        if !nr_f.is_finite() {
            return Err(DaotiError::DecodeError("nr 槽位非有限值".into()));
        }
        let nr = nr_f.round() as i32;
        // 置信度：nr 槽位越接近整数，还原越确信
        let confidence = (1.0 - (nr_f - nr as f64).abs()).clamp(0.0, 1.0);
        // 经操作字典还原名称（未知编号 → DecodeError）
        let entry = self
            .op_dict
            .iter()
            .find(|e| e.nr == nr)
            .ok_or_else(|| DaotiError::DecodeError(format!("未知 syscall 编号 {nr}")))?;
        // args 与 tid 由 hash 编码不可逆，还原时置空/零（B2 聚焦操作推导，参数还原非本步职责）
        let event = SyscallEvent::new(nr, entry.name.clone(), vec![], 0);
        Ok(DecodeOutcome {
            event,
            windows_op: entry.windows_op.clone(),
            confidence,
        })
    }
}

/// FNV-1a 64 位哈希（确定性，无第三方依赖）
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// 字符串哈希归一化到 [0, 1)
fn hash_to_unit(s: &str) -> f64 {
    (fnv1a(s.as_bytes()) as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_op_dict() -> Vec<OpEntry> {
        vec![
            OpEntry {
                nr: 0,
                name: "read".into(),
                windows_op: "ReadFile".into(),
            },
            OpEntry {
                nr: 1,
                name: "write".into(),
                windows_op: "WriteFile".into(),
            },
        ]
    }

    fn codec() -> SyscallCodec {
        SyscallCodec::new(16, sample_op_dict()).expect("构造编解码器失败")
    }

    #[test]
    fn linux_x86_64_table_contains_write() {
        let write = SyscallCodec::linux_x86_64_table()
            .into_iter()
            .find(|entry| entry.nr == 1)
            .expect("Linux x86_64 表必须包含 write");
        assert_eq!(write.name, "write");
        assert_eq!(write.windows_op, "WriteFile");
    }

    /// encode → decode roundtrip：已知字典内 nr 与 name 一致，且还原 Win32 操作名。
    #[test]
    fn roundtrip_preserves_nr_and_name() {
        let c = codec();
        let ev = SyscallEvent::new(0, "read", vec!["3".into(), "buf".into()], 42);
        let v = c.encode(&ev).expect("编码失败");
        let outcome = c.decode(&v).expect("解码失败");
        assert_eq!(outcome.event.nr, 0);
        assert_eq!(outcome.event.name, "read");
        assert_eq!(outcome.windows_op, "ReadFile");
    }

    /// 编码向量长度等于 dim。
    #[test]
    fn encode_produces_dim_vector() {
        let c = codec();
        let ev = SyscallEvent::new(1, "write", vec![], 1);
        let v = c.encode(&ev).expect("编码失败");
        assert_eq!(v.len(), 16);
    }

    /// 未知操作（字典外编号）→ DecodeError。
    #[test]
    fn unknown_nr_is_decode_error() {
        let c = codec();
        let mut v = Array1::zeros(16);
        v[0] = 9999.0;
        let err = c.decode(&v).expect_err("未知编号应报错");
        assert!(matches!(err, DaotiError::DecodeError(_)));
    }

    /// 置信度：nr 槽位接近整数时高，偏离时低。
    #[test]
    fn confidence_reflects_nr_integerness() {
        let c = codec();
        let mut v = Array1::zeros(16);
        v[0] = 0.0; // 精确整数
        let high = c.decode(&v).expect("解码失败").confidence;
        v[0] = 0.4; // 偏离 0.4
        let low = c.decode(&v).expect("解码失败").confidence;
        assert!(high > low);
    }

    /// 向量维度不符 → DecodeError。
    #[test]
    fn mismatched_vector_dim_is_rejected() {
        let c = codec();
        let v = Array1::from_vec(vec![0.0, 1.0]);
        let err = c.decode(&v).expect_err("维度不符应报错");
        assert!(matches!(err, DaotiError::DecodeError(_)));
    }

    /// 构造时 dim < 3 被拒绝。
    #[test]
    fn too_small_dim_is_rejected() {
        let err = SyscallCodec::new(2, sample_op_dict()).expect_err("维度过小应报错");
        assert!(matches!(err, DaotiError::DecodeError(_)));
    }
}
