//! 双梯形网络纯数学变换 (daoti-core::bilateral::network)
//!
//! 对应《模式B-B2双梯形网络增强开发计划.md》§3 B2-2：
//! `BilateralLadderNetwork::forward(Array1<f64>) -> Result<Array1<f64>, DaotiError>`。
//!
//! 职责边界：本模块 = 「将」，唯一职责是 `Array1<f64> → Array1<f64>` 纯数学变换；
//! 不决策、不降级、不读配置、不管理状态。维度 / `t_iter` 由构造参数传入。

use daoti_common::DaotiError;
use ndarray::{Array1, Array2};

/// 双梯形网络：正向（底层→顶层抽象意图）与逆向（顶层→底层具象信号）交替传播，
/// 递归迭代 `t_iter` 次实现信号共振。
#[derive(Debug)]
pub struct BilateralLadderNetwork {
    dim: usize,
    t_iter: usize,
    ascent: Array2<f64>,
    descent: Array2<f64>,
    bias: Array1<f64>,
}

impl BilateralLadderNetwork {
    /// 构造网络，校验维度一致性；权重含 NaN/Inf 或维度错乱时返回结构化错误。
    pub fn new(
        ascent: Array2<f64>,
        descent: Array2<f64>,
        bias: Array1<f64>,
        t_iter: usize,
    ) -> Result<Self, DaotiError> {
        let dim = ascent.nrows();
        if dim == 0 {
            return Err(DaotiError::ModelCorrupt("维度为零".into()));
        }
        if ascent.ncols() != dim {
            return Err(DaotiError::ModelCorrupt("上梯形矩阵非方阵".into()));
        }
        if descent.nrows() != dim || descent.ncols() != dim {
            return Err(DaotiError::ModelCorrupt("下梯形矩阵维度不符".into()));
        }
        if bias.len() != dim {
            return Err(DaotiError::ModelCorrupt("偏置向量维度不符".into()));
        }
        // 权重 NaN/Inf 防御（R1 护栏前置，避免污染传播）
        if ascent
            .iter()
            .chain(descent.iter())
            .chain(bias.iter())
            .any(|x| !x.is_finite())
        {
            return Err(DaotiError::ModelCorrupt("权重含 NaN/Inf".into()));
        }
        Ok(Self {
            dim,
            t_iter,
            ascent,
            descent,
            bias,
        })
    }

    /// 网络维度（输入/输出维度一致）。
    pub fn dim(&self) -> usize {
        self.dim
    }

    /// 前向传播：正向 + 逆向交替迭代 `t_iter` 次（信号共振），输出维度保持 `dim`。
    ///
    /// - 输入维度不符 → `DaotiError::InferenceFailed`
    /// - 输入 / 输出含 NaN/Inf → `DaotiError::InferenceFailed`
    /// - 零向量安全：全零输入不 panic，返回由偏置与非线性决定的确定性输出。
    pub fn forward(&self, input: Array1<f64>) -> Result<Array1<f64>, DaotiError> {
        if input.len() != self.dim {
            return Err(DaotiError::InferenceFailed(format!(
                "输入维度 {} 与网络维度 {} 不符",
                input.len(),
                self.dim
            )));
        }
        if input.iter().any(|x| !x.is_finite()) {
            return Err(DaotiError::InferenceFailed("输入含 NaN/Inf".into()));
        }

        let mut h = input;
        for _ in 0..self.t_iter {
            // 正向传播：底层 → 顶层抽象意图
            h = self.ascent.dot(&h);
            h = &h + &self.bias;
            h.mapv_inplace(f64::tanh);
            // 逆向传播：顶层 → 底层具象信号
            h = self.descent.dot(&h);
            h = &h + &self.bias;
            h.mapv_inplace(f64::tanh);
        }

        // 输出 NaN/Inf 检测（R1 护栏）
        if h.iter().any(|x| !x.is_finite()) {
            return Err(DaotiError::InferenceFailed("输出含 NaN/Inf".into()));
        }
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个 2 维、恒等权重、零偏置、3 次迭代的小网络供测试。
    fn net_2d() -> BilateralLadderNetwork {
        let ascent =
            Array2::from_shape_vec((2, 2), vec![1.0, 0.0, 0.0, 1.0]).expect("构造上梯形矩阵失败");
        let descent =
            Array2::from_shape_vec((2, 2), vec![1.0, 0.0, 0.0, 1.0]).expect("构造下梯形矩阵失败");
        let bias = Array1::from_vec(vec![0.0, 0.0]);
        BilateralLadderNetwork::new(ascent, descent, bias, 3).expect("构造网络失败")
    }

    /// 维度保持：2 维输入 → 2 维输出。
    #[test]
    fn output_dimension_is_preserved() {
        let net = net_2d();
        let out = net
            .forward(Array1::from_vec(vec![0.5, -0.3]))
            .expect("前向失败");
        assert_eq!(out.len(), 2);
    }

    /// 确定性：同输入同输出。
    #[test]
    fn same_input_yields_same_output() {
        let net = net_2d();
        let input = Array1::from_vec(vec![0.7, 0.2]);
        let a = net.forward(input.clone()).expect("前向失败");
        let b = net.forward(input).expect("前向失败");
        assert_eq!(a, b);
    }

    /// 零向量安全：全零输入不 panic，返回有限输出。
    #[test]
    fn zero_vector_is_safe() {
        let net = net_2d();
        let out = net
            .forward(Array1::from_vec(vec![0.0, 0.0]))
            .expect("零向量应安全");
        assert!(out.iter().all(|x| x.is_finite()));
    }

    /// 输入 NaN 被拦截。
    #[test]
    fn nan_input_is_rejected() {
        let net = net_2d();
        let err = net
            .forward(Array1::from_vec(vec![f64::NAN, 0.0]))
            .expect_err("NaN 输入应报错");
        assert!(matches!(err, DaotiError::InferenceFailed(_)));
    }

    /// 输入 Inf 被拦截。
    #[test]
    fn inf_input_is_rejected() {
        let net = net_2d();
        let err = net
            .forward(Array1::from_vec(vec![f64::INFINITY, 0.0]))
            .expect_err("Inf 输入应报错");
        assert!(matches!(err, DaotiError::InferenceFailed(_)));
    }

    /// 维度不符被拦截。
    #[test]
    fn mismatched_input_dim_is_rejected() {
        let net = net_2d();
        let err = net
            .forward(Array1::from_vec(vec![1.0, 2.0, 3.0]))
            .expect_err("维度不符应报错");
        assert!(matches!(err, DaotiError::InferenceFailed(_)));
    }

    /// 维度错乱权重被拒绝构造（非方阵）。
    #[test]
    fn non_square_ascent_is_rejected() {
        let ascent = Array2::from_shape_vec((2, 3), vec![1.0; 6]).expect("构造失败");
        let descent = Array2::from_shape_vec((2, 2), vec![1.0; 4]).expect("构造失败");
        let bias = Array1::from_vec(vec![0.0, 0.0]);
        let err =
            BilateralLadderNetwork::new(ascent, descent, bias, 3).expect_err("非方阵上梯形应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
    }

    /// 含 NaN 权重被拒绝构造。
    #[test]
    fn nan_weight_is_rejected() {
        let ascent =
            Array2::from_shape_vec((2, 2), vec![f64::NAN, 0.0, 0.0, 1.0]).expect("构造失败");
        let descent = Array2::from_shape_vec((2, 2), vec![1.0; 4]).expect("构造失败");
        let bias = Array1::from_vec(vec![0.0, 0.0]);
        let err =
            BilateralLadderNetwork::new(ascent, descent, bias, 3).expect_err("NaN 权重应报错");
        assert!(matches!(err, DaotiError::ModelCorrupt(_)));
    }
}
