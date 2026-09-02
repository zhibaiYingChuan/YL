"""
daoti_scheduler.py - 道体五行气场调度器
================================================================================
核心思想: 道体主卦五行通过相生相克关系决定各模块激活权重 (零 nn.Parameter)
  - 相生增强 (+0.3): 我生者=输出通道, 生我者=输入通道
  - 相克抑制 (-0.5): 克我者=受克
  - 我克轻抑 (-0.2): 我克者=耗散
  - 同行正常 (1.0)

状态信号调制:
  - coherence 高 + deviation 低 → 自洽 → 减少探索 (木/火降权)
  - coherence 低 + curiosity 高 → 不自洽 → 增强探索 (木/火升权)
  - deviation 高 + coherence 高 → 偏离但自洽 → 增强稳定 (土/金升权)

退化保证: enable_scheduler=False 或所有 weight=0 时, 行为与 v20 完全一致
================================================================================
"""

import torch
import torch.nn as nn

# 八卦顺序 (与 trigram_space_v16.py 的 BAGUA_NAMES 一致)
BAGUA_NAMES_V16 = ["乾", "坤", "震", "巽", "坎", "离", "艮", "兑"]

# 八卦→五行映射
GUA_WUXING_V16 = {
    "乾": "金", "兑": "金", "坤": "土", "艮": "土",
    "震": "木", "巽": "木", "坎": "水", "离": "火",
}

# 五行索引 (与 trigram_space_v16.py 的 WUXING_IDX 一致)
WUXING_IDX_V16 = {"金": 0, "木": 1, "水": 2, "火": 3, "土": 4}

# 五行相生 (与 daoti_modules_part2.py 一致)
WUXING_SHENG_V16 = {0: 2, 1: 3, 2: 0, 3: 4, 4: 1}

# 五行相克 (与 daoti_modules_part2.py 一致)
WUXING_KE_V16 = {0: 1, 1: 4, 2: 3, 3: 0, 4: 2}


class WuxingQiScheduler:
    """道体五行气场调度器 — 零训练参数, 由道体状态驱动模块激活。"""

    # 模块五行属性 (固定常量, 非 nn.Parameter)
    # 0金(决断) 1木(生发) 2水(流动) 3火(明察) 4土(承载)
    MODULE_WUXING = {
        # 层1 state预处理
        "SpectralGate": 0,           # 金: 频域收敛
        "SubspaceGate": 1,           # 木: 结构生长
        "StyleBalancer": 4,          # 土: 风格平衡
        "NayinModulation": 2,        # 水: 纳音流动
        "ShishuPerturbation": 1,     # 木: 时枢穿透
        "GanzhiEncoder": 2,          # 水: 干支流动
        "FlyingStarLayer": 2,        # 水: 星宫流转
        "QimenZhifuController": 2,   # 水: 值符运化
        # 层2 信号收集
        "ResonanceModulator": 3,     # 火: 共振明察
        "CuriosityScorer": 3,        # 火: 好奇觉知
        "AdaptiveDepthController": 0,# 金: 深度决断
        "WuyunLiuqiScheduler": 2,    # 水: 运气调度
        "PinealRhythmRegulator": 4,  # 土: 节律承载
        # 层3 后处理
        "DomainProjectionLayer": 1,  # 木: 域投影生长
        "MirrorRecursiveCell": 1,    # 木: 镜像递归
        "ArcuateFasciculusBypass": 0,# 金: 快慢通路决断
        "ArcuateConsistency": 0,     # 金: 一致性校验
        "HeluoMemoryBinder": 4,      # 土: 记忆绑定
        "HeluoMemoryIndex": 4,       # 土: 记忆索引
        "HeluoConsolidator": 4,      # 土: 记忆整合
        "ResonanceJudge": 3,         # 火: 共振评判
        # 表达层
        "HippocampusExpression": 3,  # 火: 表达明察
        "HippocampusAuditory": 2,    # 水: 听觉流动
    }

    # 生克权重常量
    ALPHA_SHENG = 0.3    # 相生增强
    ALPHA_KE = 0.5       # 被克抑制
    ALPHA_DRAIN = 0.2    # 我克耗散
    W_MAX = 1.5          # 权重上限

    def __init__(self):
        self.WUXING_SHENG = WUXING_SHENG_V16
        self.WUXING_KE = WUXING_KE_V16

    def compute_dominant_wuxing(self, combined_sim):
        """从八卦分布计算道体主导五行。
        
        Args:
            combined_sim: [B, 8] 八卦相似度 (顺序与 BAGUA_NAMES_V16 一致)
        Returns:
            dominant_wuxing_idx: int (0金 1木 2水 3火 4土)
            wuxing_dist: [5] 五行分布
        """
        if combined_sim.dim() == 1:
            combined_sim = combined_sim.unsqueeze(0)
        # BAGUA_NAMES_V16 = ["乾", "坤", "震", "巽", "坎", "离", "艮", "兑"]
        # 金: 乾(0)+兑(7), 木: 震(2)+巽(3), 水: 坎(4), 火: 离(5), 土: 坤(1)+艮(6)
        wuxing_dist = torch.zeros(combined_sim.shape[0], 5, device=combined_sim.device)
        wuxing_dist[:, 0] = combined_sim[:, 0] + combined_sim[:, 7]  # 金
        wuxing_dist[:, 1] = combined_sim[:, 2] + combined_sim[:, 3]  # 木
        wuxing_dist[:, 2] = combined_sim[:, 4]                        # 水
        wuxing_dist[:, 3] = combined_sim[:, 5]                        # 火
        wuxing_dist[:, 4] = combined_sim[:, 1] + combined_sim[:, 6]  # 土
        dominant_idx = wuxing_dist[0].argmax().item()
        return dominant_idx, wuxing_dist[0]

    def compute_base_weights(self, dominant_wuxing_idx):
        """根据道体主导五行, 用相生相克计算各模块基础权重。"""
        weights = {}
        dom = dominant_wuxing_idx
        for module_name, wx in self.MODULE_WUXING.items():
            w = 1.0
            # 相生: 我生者(输出) 或 生我者(输入)
            if self.WUXING_SHENG[dom] == wx or self.WUXING_SHENG[wx] == dom:
                w += self.ALPHA_SHENG
            # 被克: 克我者
            if self.WUXING_KE[wx] == dom:
                w -= self.ALPHA_KE
            # 我克者: 耗散
            if self.WUXING_KE[dom] == wx:
                w -= self.ALPHA_DRAIN
            weights[module_name] = max(0.0, w)
        return weights

    def compute_weights(self, trigram_result, state_signals):
        """计算所有模块的最终激活权重。
        
        Args:
            trigram_result: trigram(state) 的输出 dict (含 combined_sim, cavity_coherence 等)
            state_signals: dict (含 deviation, curiosity, change_ratio)
        Returns:
            weights: {模块名: float} 激活权重
        """
        # 1. 道体主导五行
        combined_sim = trigram_result.get("combined_sim")
        if combined_sim is None:
            return {name: 0.0 for name in self.MODULE_WUXING}
        dominant_idx, _ = self.compute_dominant_wuxing(combined_sim)

        # 2. 基础权重 (五行生克)
        weights = self.compute_base_weights(dominant_idx)

        # 3. 状态信号调制
        coherence = state_signals.get("coherence", 0.5)
        deviation = state_signals.get("deviation", 0.5)
        curiosity = state_signals.get("curiosity", 0.5)

        explore_drive = curiosity * (1.0 - coherence)   # 好奇且不自洽→探索
        stabilize_drive = deviation * coherence          # 偏离但自洽→稳定

        for module_name, wx in self.MODULE_WUXING.items():
            if wx in (1, 3):  # 木/火: 探索型
                modulation = 0.5 + 0.5 * explore_drive
            elif wx in (0, 4):  # 金/土: 稳定型
                modulation = 0.5 + 0.5 * stabilize_drive
            else:  # 水: 居中调度
                modulation = 0.5 + 0.5 * (explore_drive + stabilize_drive) * 0.5
            weights[module_name] = min(self.W_MAX, weights[module_name] * modulation)

        return weights

    def compute_scheduler_decision(self, trigram_result, state_signals):
        """道体自主推演超参数决策 — 调度器从"权重控制器"升级为"自主大脑"

        基于道体当前状态（五行分布、coherence、deviation、curiosity、alpha）
        动态生成所有推演超参数, 替换 inference_engine_v23.py 中所有硬编码常量。

        哲学原则:
          - coherence低→大步长+低收敛计数+低阻尼+低过盛阈值（探索突破假主导）
          - coherence高→小步长+高收敛计数+高阻尼+高过盛阈值（精细确认真方向）
          - deviation高→高 retrieval_blend（偏离需更多外部参考）
          - curiosity高→低 max_steps（好奇时快速切换, 不拘泥于单一目标）
          - 五行极端分布(单一五行>0.4)→低阈值易触发相克/受克(破局)
          - 五行均衡分布(无>0.25)→高阈值走相生/守中(保守演化)

        Args:
            trigram_result: trigram(state) 的输出 dict (含 combined_sim, cavity_coherence, 五行分布等)
            state_signals: dict (含 coherence, deviation, curiosity, alpha, change_ratio)

        Returns:
            decision: dict {
                "step_size": float,                    # 推演步长
                "max_steps": int,                      # 最大推演步数
                "convergence_stable": int,             # 连续多少步目标卦不变算收敛
                "uncertainty_entropy_thresh": float,   # 信息熵阈值 (归一化)
                "uncertainty_margin_thresh": float,    # top1/top2 margin 阈值
                "retrieval_blend": float,              # 检索修正 gua_sims 的权重
                "damping": float,                      # 阻尼插值系数
                "over_strong_base_thresh": float,      # 过盛基准阈值 (替换 0.55 硬编码)
                "alpha_thresh_yang": float,            # 阳盛阈值 (替换 0.55 硬编码)
                "alpha_thresh_yin": float,             # 阴盛阈值 (替换 0.45 硬编码)
                "pathway": str,                        # "explore" / "stabilize" / "retrieve"
                "module_weights": dict,                # 各模块激活权重 (来自 compute_weights)
            }
        """
        # === 提取当前状态信号 ===
        combined_sim = trigram_result.get("combined_sim")
        if combined_sim is None:
            coherence = state_signals.get("coherence", 0.5)
            deviation = state_signals.get("deviation", 0.5)
            curiosity = state_signals.get("curiosity", 0.5)
            alpha = state_signals.get("alpha", 0.5)
        else:
            dominant_idx, wuxing_dist = self.compute_dominant_wuxing(combined_sim)
            coherence = state_signals.get("coherence", 0.5)
            deviation = state_signals.get("deviation", 0.5)
            curiosity = state_signals.get("curiosity", 0.5)
            alpha = state_signals.get("alpha", 0.5)

            # === 计算模块权重 (复用 compute_weights) ===
            module_weights = self.compute_weights(trigram_result, state_signals)

            # === 五行极端度 ===
            wuxing_max = wuxing_dist.max().item() if hasattr(wuxing_dist, 'max') else max(wuxing_dist.values()) if isinstance(wuxing_dist, dict) else 0.5
            wuxing_balanced = wuxing_max < 0.25

        # === 1. step_size 调度 ===
        # coherence低→大步长 (突破惯性), coherence高→小步长 (精细调整)
        base_step = 0.30
        if coherence < 0.3:
            step_size = base_step * 1.5  # 0.45: 强突破
        elif coherence < 0.5:
            step_size = base_step * 1.0  # 0.30: 标准突破
        elif coherence < 0.7:
            step_size = base_step * 0.7  # 0.21: 适度精细
        else:
            step_size = base_step * 0.5  # 0.15: 精细调整
        # curiosity 调制: 好奇→稍大步
        step_size *= (1.0 + 0.2 * curiosity)
        step_size = max(0.05, min(0.60, step_size))

        # === 2. max_steps 调度 ===
        # coherence低→更多步 (需要更多探索), curiosity高→更少步 (快速切换)
        if coherence < 0.3:
            max_steps = 25
        elif coherence < 0.5:
            max_steps = 20
        elif coherence < 0.7:
            max_steps = 15
        else:
            max_steps = 10
        # curiosity 调制: 好奇→快速切换
        max_steps = int(max_steps * (1.0 - 0.3 * curiosity))
        max_steps = max(5, min(30, max_steps))

        # === 3. convergence_stable 调度 ===
        # coherence高→需要更多步确认 (严谨), coherence低→快速收敛 (不固执)
        if coherence < 0.3:
            convergence_stable = 2
        elif coherence < 0.5:
            convergence_stable = 3
        elif coherence < 0.7:
            convergence_stable = 4
        else:
            convergence_stable = 5

        # === 4. uncertainty_entropy_thresh 调度 ===
        # coherence高→高熵阈值 (易触发检索, 严谨核实)
        # coherence低→低熵阈值 (不易触发检索, 敢于自主判断)
        entropy_base = 0.7
        if coherence < 0.3:
            uncertainty_entropy_thresh = entropy_base - 0.15  # 0.55
        elif coherence < 0.5:
            uncertainty_entropy_thresh = entropy_base  # 0.70
        elif coherence < 0.7:
            uncertainty_entropy_thresh = entropy_base + 0.10  # 0.80
        else:
            uncertainty_entropy_thresh = entropy_base + 0.15  # 0.85

        # === 5. uncertainty_margin_thresh 调度 ===
        # deviation高→大margin阈值 (偏离需要更多外部参考)
        margin_base = 0.05
        uncertainty_margin_thresh = margin_base * (1.0 + deviation)
        uncertainty_margin_thresh = min(0.15, uncertainty_margin_thresh)

        # === 6. retrieval_blend 调度 ===
        # deviation高→高 blend (需要外部参考矫正方向)
        blend_base = 0.30
        retrieval_blend = blend_base * (1.0 + deviation)
        # curiosity高→更高 blend (好奇时吸收更多外部信息)
        retrieval_blend *= (1.0 + 0.3 * curiosity)
        retrieval_blend = min(0.80, retrieval_blend)

        # === 7. damping 调度 ===
        # coherence高→高阻尼 (保守, 保留更多已有结构)
        # coherence低→低阻尼 (大胆, 接受更多 trigram 新输出)
        damping = 0.15 + 0.20 * coherence  # 范围 [0.15, 0.35], 默认 d=0.25
        damping = max(0.10, min(0.50, damping))

        # === 8. over_strong_base_thresh 调度 ===
        # base=0.55 (v24适配), coherence调制
        # coherence低→阈值低 (易相克破局), coherence高→阈值高 (保守相生)
        over_strong_base_thresh = 0.55 + (coherence - 0.5) * 0.16
        # 五行极端度高→阈值降低 (易触发相克破局)
        if not wuxing_balanced and wuxing_max > 0.4:
            over_strong_base_thresh *= 0.9
        # 天时同我/生我: 由 _causal_derive 内部处理天时调制, 这里不重复

        # === 9. alpha 阴阳阈值 ===
        # alpha_thresh_yang: 默认 0.55, 低coherence→降低 (易判断为阳盛激进步)
        # alpha_thresh_yin: 默认 0.45, 低coherence→升高 (易判断为阴盛激进步)
        alpha_thresh_yang = 0.55 - 0.10 * (1.0 - coherence)  # 范围 [0.45, 0.55]
        alpha_thresh_yin = 0.45 + 0.10 * (1.0 - coherence)   # 范围 [0.45, 0.55]

        # === 10. 路径决策 ===
        # 综合判断当前道体应该走什么路径
        if coherence < 0.35 and curiosity > 0.6:
            pathway = "explore"
        elif deviation > 0.6 and coherence > 0.5:
            pathway = "retrieve"
        else:
            pathway = "stabilize"

        # === 组装决策字典 ===
        decision = {
            "step_size": round(step_size, 3),
            "max_steps": max_steps,
            "convergence_stable": convergence_stable,
            "uncertainty_entropy_thresh": round(uncertainty_entropy_thresh, 3),
            "uncertainty_margin_thresh": round(uncertainty_margin_thresh, 4),
            "retrieval_blend": round(retrieval_blend, 3),
            "damping": round(damping, 3),
            "over_strong_base_thresh": round(over_strong_base_thresh, 3),
            "alpha_thresh_yang": round(alpha_thresh_yang, 3),
            "alpha_thresh_yin": round(alpha_thresh_yin, 3),
            "pathway": pathway,
            "module_weights": module_weights,
        }
        return decision


class DaotiModulePool(nn.Module):
    """道体全模块池 — 集中实例化, 统一 eval/requires_grad=False。"""

    def __init__(self, state_dim=2048):
        super().__init__()
        self.state_dim = state_dim

        # 从各 part 文件导入模块
        from light_daoti.daoti_modules_part1 import (
            SpectralGate, SubspaceGate, ResonanceModulator, CuriosityScorer,
            ArcuateConsistency, ArcuateFasciculusBypass, PinealRhythmRegulator,
            AdaptiveDepthController, StyleBalancer,
        )
        from light_daoti.daoti_modules_part2 import (
            NayinModulation, ShishuPerturbation, WuyunLiuqiScheduler,
            GanzhiEncoder, FlyingStarLayer, QimenZhifuController,
        )
        from light_daoti.daoti_modules_part3 import (
            DomainProjectionLayer, HeluoMemoryBinder, HeluoMemoryIndex,
            HeluoConsolidator, MirrorRecursiveCell, ResonanceJudge,
        )
        from light_daoti.daoti_modules_part4 import (
            HippocampusExpression, HippocampusAuditory,
        )

        # 层1 state预处理模块
        self.spectral_gate = SpectralGate(state_dim)
        self.subspace_gate = SubspaceGate(state_dim)
        self.style_balancer = StyleBalancer(state_dim)
        self.nayin_modulation = NayinModulation(state_dim)
        self.shishu_perturbation = ShishuPerturbation(state_dim)
        self.ganzhi_encoder = GanzhiEncoder(state_dim)
        self.flying_star = FlyingStarLayer(state_dim)
        self.qimen_zhifu = QimenZhifuController(state_dim)

        # 层2 信号收集模块
        self.resonance_modulator = ResonanceModulator(state_dim)
        self.curiosity_scorer = CuriosityScorer(state_dim)
        self.adaptive_depth = AdaptiveDepthController(state_dim)
        self.wuyun_liuqi = WuyunLiuqiScheduler(state_dim)
        self.pineal_rhythm = PinealRhythmRegulator(state_dim)

        # 层3 后处理模块
        self.domain_proj = DomainProjectionLayer(state_dim)
        self.mirror_recursive = MirrorRecursiveCell(state_dim)
        self.arcuate_bypass = ArcuateFasciculusBypass(state_dim)
        self.arcuate_consistency = ArcuateConsistency(state_dim)
        self.memory_binder = HeluoMemoryBinder(state_dim)
        self.memory_index = HeluoMemoryIndex(state_dim)
        self.memory_consolidator = HeluoConsolidator(state_dim)
        self.resonance_judge = ResonanceJudge(state_dim)

        # 表达层模块
        self.hippocampus_expression = HippocampusExpression(state_dim)
        self.hippocampus_auditory = HippocampusAuditory(state_dim)

        # 统一设置为 eval 模式 + 不参与训练
        self.eval()
        for p in self.parameters():
            p.requires_grad = False

    def get_module(self, name):
        """按名称获取模块实例。"""
        return getattr(self, name, None)
