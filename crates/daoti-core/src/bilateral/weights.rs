//! 双梯形网络权重加载器 (daoti-core::bilateral::weights)
//!
//! 模式B B2 的自定义二进制权重格式，对应《模式B-B2双梯形网络增强开发计划.md》§3 B2-1：
//! `magic + version + dim + t_iter + 层参数 + 操作字典`。
//!
//! 职责边界：本模块只做「读/写字节 + 结构校验」，不决策、不降级、不读配置。
//! 缺失返回 `DaotiError::ModelMissing`，损坏返回 `DaotiError::ModelCorrupt`，均不 panic。

use daoti_common::DaotiError;
use std::io::{Cursor, Read};
use std::path::Path;

/// 权重文件魔数（8 字节 ASCII，与字节序无关）
pub const MAGIC: &[u8; 8] = b"DAOTIBLT";

/// 当前二进制格式版本（加载时校验，不支持则报错）
pub const WEIGHTS_VERSION: u32 = 1;

/// 操作字典条目：syscall 语义与 Windows 操作的对应（供 codec 编解码）
#[derive(Debug, Clone, PartialEq)]
pub struct OpEntry {
    /// Linux syscall 编号（x86_64 ABI）
    pub nr: i32,
    /// Linux syscall 名称（如 "read"）
    pub name: String,
    /// 映射后的 Windows 操作（如 "ReadFile"）
    pub windows_op: String,
}

/// 双梯形网络权重（纯数据，由网络与编解码器消费）
///
/// 矩阵以行优先扁平化存储：`ascent` / `descent` 长度 = `dim*dim`，`bias` 长度 = `dim`。
#[derive(Debug, Clone, PartialEq)]
pub struct BilateralWeights {
    /// 格式版本（当前 1）
    pub version: u32,
    /// 向量维度（默认 2048）
    pub dim: usize,
    /// 递归迭代次数（默认 5，信号共振）
    pub t_iter: usize,
    /// 上梯形（正向，底层→顶层抽象意图）变换矩阵，行优先
    pub ascent: Vec<f64>,
    /// 下梯形（逆向，顶层→底层具象信号）变换矩阵，行优先
    pub descent: Vec<f64>,
    /// 偏置向量
    pub bias: Vec<f64>,
    /// 操作字典
    pub op_dict: Vec<OpEntry>,
}

impl BilateralWeights {
    /// 序列化为二进制（小端），供离线训练工具链产出权重文件时复用。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(MAGIC);
        write_u32(self.version, &mut out);
        write_u64(self.dim as u64, &mut out);
        write_u64(self.t_iter as u64, &mut out);
        write_u64(self.op_dict.len() as u64, &mut out);
        for entry in &self.op_dict {
            write_i32(entry.nr, &mut out);
            write_str(&entry.name, &mut out);
            write_str(&entry.windows_op, &mut out);
        }
        write_f64_slice(&self.ascent, &mut out);
        write_f64_slice(&self.descent, &mut out);
        write_f64_slice(&self.bias, &mut out);
        out
    }

    /// 从二进制反序列化；格式非法返回 `DaotiError::ModelCorrupt`（结构化报错，不 panic）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DaotiError> {
        let mut c = Cursor::new(bytes);

        // 1. 魔数
        let magic = read_exact(&mut c, MAGIC.len())?;
        if magic.as_slice() != MAGIC {
            return Err(corrupt("魔数不匹配，非双梯形权重文件"));
        }

        // 2. 版本
        let version = read_u32(&mut c)?;
        if version != WEIGHTS_VERSION {
            return Err(corrupt(&format!(
                "不支持的权重版本 {version}（期望 {WEIGHTS_VERSION}）"
            )));
        }

        // 3. 维度与迭代次数
        let dim = read_usize(&mut c)?;
        if dim == 0 {
            return Err(corrupt("维度为零，非法权重"));
        }
        let t_iter = read_usize(&mut c)?;

        // 4. 操作字典
        let op_dict_len = read_usize(&mut c)?;
        let mut op_dict = Vec::with_capacity(op_dict_len.min(1024));
        for _ in 0..op_dict_len {
            let nr = read_i32(&mut c)?;
            let name = read_str(&mut c)?;
            let windows_op = read_str(&mut c)?;
            op_dict.push(OpEntry {
                nr,
                name,
                windows_op,
            });
        }

        // 5. 层参数（上梯形 / 下梯形 / 偏置）
        let ascent = read_f64_vec(&mut c)?;
        let descent = read_f64_vec(&mut c)?;
        let bias = read_f64_vec(&mut c)?;

        // 长度校验：ascent / descent = dim*dim，bias = dim
        let mat_len = dim
            .checked_mul(dim)
            .ok_or_else(|| corrupt("维度平方溢出"))?;
        if ascent.len() != mat_len {
            return Err(corrupt(&format!(
                "上梯形矩阵长度 {} 与维度 {dim} 不符（期望 {mat_len}）",
                ascent.len()
            )));
        }
        if descent.len() != mat_len {
            return Err(corrupt(&format!(
                "下梯形矩阵长度 {} 与维度 {dim} 不符（期望 {mat_len}）",
                descent.len()
            )));
        }
        if bias.len() != dim {
            return Err(corrupt(&format!(
                "偏置向量长度 {} 与维度 {dim} 不符",
                bias.len()
            )));
        }

        Ok(BilateralWeights {
            version,
            dim,
            t_iter,
            ascent,
            descent,
            bias,
            op_dict,
        })
    }
}

/// 权重加载器：从磁盘读取权重文件。
pub struct WeightsLoader;

impl WeightsLoader {
    /// 加载权重文件。
    ///
    /// - 文件不存在 → `DaotiError::ModelMissing`（道体旁路，不影响 B1）
    /// - 文件损坏 / 格式非法 → `DaotiError::ModelCorrupt`
    /// - 其它 I/O 错误 → `DaotiError::Io`
    pub fn load(path: &Path) -> Result<BilateralWeights, DaotiError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DaotiError::ModelMissing)
            }
            Err(e) => return Err(DaotiError::Io(e)),
        };
        BilateralWeights::from_bytes(&bytes)
    }
}

// ─── 二进制读写辅助（小端，无第三方依赖）────────────────────────

fn corrupt(msg: &str) -> DaotiError {
    DaotiError::ModelCorrupt(msg.to_string())
}

fn read_exact(c: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, DaotiError> {
    let mut buf = vec![0u8; len];
    c.read_exact(&mut buf)
        .map_err(|e| corrupt(&format!("字节流读取不足 {len} 字节：{e}")))?;
    Ok(buf)
}

fn read_u32(c: &mut Cursor<&[u8]>) -> Result<u32, DaotiError> {
    let b = read_exact(c, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(c: &mut Cursor<&[u8]>) -> Result<u64, DaotiError> {
    let b = read_exact(c, 8)?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_i32(c: &mut Cursor<&[u8]>) -> Result<i32, DaotiError> {
    let b = read_exact(c, 4)?;
    Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_f64(c: &mut Cursor<&[u8]>) -> Result<f64, DaotiError> {
    let b = read_exact(c, 8)?;
    Ok(f64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

fn read_usize(c: &mut Cursor<&[u8]>) -> Result<usize, DaotiError> {
    let v = read_u64(c)?;
    usize::try_from(v).map_err(|_| corrupt(&format!("长度 {v} 超出本平台 usize 范围")))
}

fn read_str(c: &mut Cursor<&[u8]>) -> Result<String, DaotiError> {
    let len = read_u32(c)? as usize;
    let b = read_exact(c, len)?;
    String::from_utf8(b).map_err(|e| corrupt(&format!("操作字典含非法 UTF-8：{e}")))
}

/// 读取「长度前缀 + f64 数组」
fn read_f64_vec(c: &mut Cursor<&[u8]>) -> Result<Vec<f64>, DaotiError> {
    let len = read_usize(c)?;
    let mut v = Vec::with_capacity(len.min(1 << 24));
    for _ in 0..len {
        v.push(read_f64(c)?);
    }
    Ok(v)
}

fn write_u32(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn write_u64(v: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn write_i32(v: i32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn write_str(s: &str, out: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    write_u32(bytes.len() as u32, out);
    out.extend_from_slice(bytes);
}

fn write_f64_slice(v: &[f64], out: &mut Vec<u8>) {
    write_u64(v.len() as u64, out);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个小维度合法权重（dim=2, t_iter=3），供 roundtrip / 损坏测试复用。
    fn sample_weights() -> BilateralWeights {
        BilateralWeights {
            version: WEIGHTS_VERSION,
            dim: 2,
            t_iter: 3,
            ascent: vec![1.0, 0.0, 0.5, 1.0],
            descent: vec![1.0, 0.5, 0.0, 1.0],
            bias: vec![0.0, 0.0],
            op_dict: vec![
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
            ],
        }
    }

    /// 序列化 → 反序列化 roundtrip：所有字段无损一致。
    #[test]
    fn roundtrip_is_lossless() {
        let w = sample_weights();
        let bytes = w.to_bytes();
        let loaded = BilateralWeights::from_bytes(&bytes).expect("合法字节应可解析");
        assert_eq!(loaded, w);
    }

    /// 魔数不符被拒绝。
    #[test]
    fn wrong_magic_is_rejected() {
        let mut bytes = sample_weights().to_bytes();
        bytes[0] = b'X';
        let err = BilateralWeights::from_bytes(&bytes).expect_err("错误魔数应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
        assert!(err.to_string().contains("魔数"));
    }

    /// 版本不符被拒绝。
    #[test]
    fn wrong_version_is_rejected() {
        let mut w = sample_weights();
        w.version = 99;
        let err = BilateralWeights::from_bytes(&w.to_bytes()).expect_err("版本不符应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
        assert!(err.to_string().contains("版本"));
    }

    /// 上梯形矩阵长度与 dim 不符被拒绝（截断尾部字节）。
    #[test]
    fn mismatched_matrix_length_is_rejected() {
        let bytes = sample_weights().to_bytes();
        // 截断 8 字节（破坏 bias 的最后一个 f64），触发偏置长度不足
        let truncated = &bytes[..bytes.len() - 8];
        let err = BilateralWeights::from_bytes(truncated).expect_err("截断应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
    }

    /// 维度为零被拒绝。
    #[test]
    fn zero_dim_is_rejected() {
        let mut w = sample_weights();
        w.dim = 0;
        w.ascent = vec![];
        w.descent = vec![];
        w.bias = vec![];
        let err = BilateralWeights::from_bytes(&w.to_bytes()).expect_err("零维应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
    }

    /// 文件不存在返回 ModelMissing。
    #[test]
    fn load_missing_file_returns_model_missing() {
        let path = Path::new("__definitely_missing_weights__.bin");
        let err = WeightsLoader::load(path).expect_err("缺失应报错");
        assert!(matches!(err, DaotiError::ModelMissing));
    }

    /// 文件损坏返回 ModelCorrupt（写垃圾字节后加载）。
    #[test]
    fn load_corrupt_file_returns_model_corrupt() {
        let path = std::env::temp_dir().join("daoti_test_corrupt_weights.bin");
        std::fs::write(&path, b"this is not a valid weight file").expect("写测试文件失败");
        let err = WeightsLoader::load(&path).expect_err("损坏应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
        let _ = std::fs::remove_file(&path);
    }

    /// 合法文件可被磁盘加载（写入临时文件后读回）。
    #[test]
    fn load_valid_file_roundtrips() {
        let path = std::env::temp_dir().join("daoti_test_valid_weights.bin");
        std::fs::write(&path, sample_weights().to_bytes()).expect("写测试文件失败");
        let loaded = WeightsLoader::load(&path).expect("合法文件应加载成功");
        assert_eq!(loaded, sample_weights());
        let _ = std::fs::remove_file(&path);
    }
}
