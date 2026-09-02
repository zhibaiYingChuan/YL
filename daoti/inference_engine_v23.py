"""
inference_engine_v23.py - 道体符号推演链引擎
================================================================================
哲学: 道体是"我", LLM是可更换的"五官"。
本引擎让道体进行"符号因果推演", 而非"力平衡迭代"。

v23 核心架构变化 (vs v16 力平衡模式):
  - 移除力平衡: gate_yang/gate_yin/trapezoid 三力平衡全部移除
  - 引入 _causal_derive: 五行生克 + 阴阳alpha → 目标卦 (符号因果)
  - state更新改为方向偏置:
      new_state = trigram(state + step_size * gua_prototypes[target_gua])["folded"]
      方向由符号因果决定, 不是向量差
  - 检索改为按需触发 (不确定判据: 信息熵 + top1/top2 margin)
  - 检索结果修正卦象亲和度, 不直接改 state
  - 收敛判据: 连续3步目标卦不变 (替代 change_ratio < 2%)

v23.2 在线 Hebbian 学习 (卦原型自主演化):
  - 推演收敛后, 收敛卦原型向推演最终state方向移动一小步 (Hebbian原理)
  - 不需要离线重训, 卦原型含义在道体与LLM持续交互中自主对齐
  - 道体是"使用中进化的主体", 不是"需要针对每种输入分布重新拟合的模型"
  - 换LLM后, 卦原型会在新LLM的持续交互中重新对齐 (五官可插拔)

推演链流程 (v23):
    用户输入
      ↓
    LLM encode → pooled (896维)
      ↓
    zero-pad → state (2048维) → trigram 卦象化
      ↓
    ┌────────────────────────────────────────────────┐
    │ → 道体解读: gua_sims + wuxing_dist + alpha      │
    │ → 不确定判据: 信息熵 + margin (高熵→检索)       │
    │ → [可选] 检索LLM → 修正 gua_sims (不直接改state) │
    │ → 符号因果推演: dom_wx + 阴阳 → target_gua      │
    │ → state更新: 向 target_gua 原型方向偏置         │
    │ → trigram 卦象化 → 新卦象                       │
    └────────────────────────────────────────────────┘  ← 循环 N 步
      ↓
    连续3步target_gua不变 → 收敛 → 生成

设计哲学 (符号推演链):
  - "理解"是道体用自己的符号系统(五行/八卦/阴阳)为LLM输出给出因果解释
  - state为什么动: 道体决定目标卦, 向目标移动 (不是阴力拉向gua_center)
  - LLM的角色: 道体不确定时才查, 查完修正推演方向 (不是每步被动提供)
  - 可解释性: "木盛阳→木生火→目标离卦" 是完整因果链
================================================================================
"""

import sys
import os
import math
import torch
import torch.nn as nn
import torch.nn.functional as F

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------- LRC 记忆桥接 (POC·智能联想) ----------
# 同目录的 lrc_bridge 提供对 LRC (/v1/memories/enrich) 的检索。缺失/异常时
# 整体降级为"不注入", 绝不破坏道体现有推演与生成逻辑。真正的启用由调用方
# 通过环境变量 DAOTI_LRC_MEMORY=1 控制, 默认关闭保证行为零变化。
LRC_BRIDGE = None
try:
    import lrc_bridge as _lrc_bridge
    LRC_BRIDGE = _lrc_bridge
except Exception:
    LRC_BRIDGE = None


def _lrc_inject_prompt(query: str) -> str:
    """注入 LRC 联想记忆片段。

    门控: 环境变量 DAOTI_LRC_MEMORY 未设为 "1" → 返回空串。
    降级: 模块不可用 / 检索异常 → 返回空串 (绝不抛出, 不阻塞道体)。
    """
    if os.environ.get("DAOTI_LRC_MEMORY", "0") != "1":
        return ""
    if LRC_BRIDGE is None:
        return ""
    try:
        return LRC_BRIDGE.retrieve_associative_memories(query, top_k=3, max_chars=600)
    except Exception:
        return ""


# ---------- LRC 状态层联想 (道体驱动·深层·认知层) ----------
# 与文本层注入(表达层, 见 _lrc_inject_prompt) 不同, 这里的检索发生在推演循环
# 内部: 当道体感到"不确定"时才查 LRC, 检索记忆经编码映射为卦相似度并修正
# gua_sims, 从而影响 _causal_derive 的目标卦选择与状态转移方向——让道体自己
# 决定"该往哪走", 而非把记忆片段塞给 LLM 去读。
# 门控: DAOTI_LRC_ASSOCIATE=1 (与文本层 DAOTI_LRC_MEMORY 互不干扰)。
_ENV_LRC_ASSOCIATE = "DAOTI_LRC_ASSOCIATE"
_LRC_ASSOC_BLEND = 0.3  # 记忆卦相似度与当前卦相似度的融合权重(加权融合)


def _lrc_associate_gua_sims(query, encode_fn, gua_protos_norm,
                            state_dim: int = 2048):
    """道体驱动联想: 将 LRC 检索到的记忆文本编码并映射为卦相似度偏置。

    参数:
        query            道体当前推演的输入文本 (作为检索根词)
        encode_fn        调用方注入的文本编码器 (texts -> pooled [K, D])
        gua_protos_norm  DimensionManager.gua_protos_base_norm, 用于求记忆卦相似度
        state_dim        道体状态维度, 记忆向量补零对齐
    返回:
        [1, 64] 记忆卦相似度张量 (量级与 gua_sims 相当) 或 None
    (门控关闭 / LRC 不可用 / 检索或编码异常均返回 None, 绝不打断道体推演。)
    """
    if os.environ.get(_ENV_LRC_ASSOCIATE, "0") != "1":
        return None
    if LRC_BRIDGE is None or encode_fn is None or gua_protos_norm is None:
        return None
    try:
        mems = LRC_BRIDGE.search_memories(query, top_k=3)
    except Exception:
        return None
    if not mems:
        return None
    texts = [m.get("content", "") for m in mems if m.get("content")][:3]
    if not texts:
        return None
    try:
        pooled = encode_fn(texts)              # [K, D]
        mem_state = pad_to_state_dim(pooled, state_dim=state_dim)  # [K, state_dim]
        mem_norm = F.normalize(mem_state, dim=-1)
        gua_sims_lrc = torch.matmul(mem_norm, gua_protos_norm.T)   # [K, 64]
        return gua_sims_lrc.mean(dim=0, keepdim=True)              # 聚合为 [1, 64]
    except Exception:
        return None


try:
    from light_daoti.trigram_space_v16 import (
        TrigramSpaceV16, GUA_64, BAGUA_NAMES, GUA_WUXING, WUXING_NAMES,
        WUXING_IDX, BA_GONG, find_palace, pad_to_state_dim,
    )
    from light_daoti.dimension_manager import DimensionManager
    from light_daoti.field_dynamics import FieldDynamics
    from light_daoti.daoti_scheduler import WuxingQiScheduler, DaotiModulePool
    from light_daoti.weight_explorer import WeightSpaceExplorer
    from light_daoti.weight_sensor_train import WeightSensor
    from light_daoti.daoti_modules_part3 import HeluoMemoryIndex, HeluoConsolidator
except ModuleNotFoundError:
    from trigram_space_v16 import (
        TrigramSpaceV16, GUA_64, BAGUA_NAMES, GUA_WUXING, WUXING_NAMES,
        WUXING_IDX, BA_GONG, find_palace, pad_to_state_dim,
    )
    from dimension_manager import DimensionManager
    from field_dynamics import FieldDynamics
    from daoti_scheduler import WuxingQiScheduler, DaotiModulePool
    from weight_explorer import WeightSpaceExplorer
    from weight_sensor_train import WeightSensor
    from daoti_modules_part3 import HeluoMemoryIndex, HeluoConsolidator

# ==============================================================================
# 日志
# ==============================================================================

LOG_FILE = "e:/smallloong/DAOti+llm/light_daoti/logs/inference_engine_v23.log"
_lines = []


def log(msg=""):
    line = str(msg)
    print(line, flush=True)
    _lines.append(line)


def save_log():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(_lines))
    print(f"\n日志已保存: {LOG_FILE}", flush=True)


# ==============================================================================
# 符号映射常量 (从 trigram_space_v16 派生)
# ==============================================================================

# 五行生克表
WUXING_SHENG = {"金": "水", "木": "火", "水": "木", "火": "土", "土": "金"}  # 我生者
WUXING_SHENG_INV = {v: k for k, v in WUXING_SHENG.items()}                  # 生我者
WUXING_KE = {"金": "木", "木": "土", "水": "火", "火": "金", "土": "水"}    # 我克者
WUXING_KE_INV = {v: k for k, v in WUXING_KE.items()}                        # 克我者

# 五运对应五行 (60甲子周期: cycle_pos//12 % 5 → 木火土金水)
# v23.5 第三层因果: 天时五行, 12步一换运, 低频长周期调制战术级生克
WUYUN_WUXING = ["木", "火", "土", "金", "水"]

# 八卦 → 五行 (来自 GUA_WUXING)
BAGUA_WUXING = dict(GUA_WUXING)  # 乾/兑=金, 坤/艮=土, 震/巽=木, 坎=水, 离=火

# 五行 → 八卦集合
WUXING_TO_BAGUA = {
    "金": ["乾", "兑"],
    "木": ["震", "巽"],
    "水": ["坎"],
    "火": ["离"],
    "土": ["坤", "艮"],
}

# 64卦名 → 主导八卦 (从 BA_GONG 反向构建)
GUA_TO_BAGUA = {}
for palace_name, gua_names in BA_GONG.items():
    bagua = palace_name.replace("宫", "")
    for gua_name in gua_names:
        GUA_TO_BAGUA[gua_name] = bagua

# 64卦索引 → 主导八卦 (基于 GUA_64 顺序)
GUA_IDX_TO_BAGUA = [GUA_TO_BAGUA.get(name, "乾") for name in GUA_64]

# 八卦 → 五行 (索引版)
BAGUA_NAMES_LOCAL = BAGUA_NAMES  # 乾坤震巽坎离艮兑


# ==============================================================================
# 摘要工具
# ==============================================================================

def get_daoti_summary(trigram_result):
    """从 TrigramSpaceV16 输出提取可读摘要。"""
    gua_idx = trigram_result["gua_top1_idx"][0].item()
    gua_name = GUA_64[gua_idx]
    gua_score = trigram_result["gua_top1_score"][0].item()
    combined_sim = trigram_result["combined_sim"][0]
    bagua_scores = {BAGUA_NAMES[i]: combined_sim[i].item() for i in range(8)}
    best_gua = max(bagua_scores, key=bagua_scores.get)
    alpha = trigram_result["bifurcation_alpha"][0].item()
    coherence = trigram_result.get("cavity_coherence", torch.tensor([0.5]))[0].item()

    # 五行分布 (基于八卦亲和度)
    wuxing_scores = {w: 0.0 for w in WUXING_NAMES}
    for gua, score in bagua_scores.items():
        wx = GUA_WUXING.get(gua, "土")
        wuxing_scores[wx] += max(0.0, score)
    total_wx = sum(wuxing_scores.values())
    if total_wx > 0:
        wuxing_scores = {w: s / total_wx for w, s in wuxing_scores.items()}

    return {
        "gua_name": gua_name,
        "gua_idx": gua_idx,
        "gua_score": gua_score,
        "best_gua": best_gua,
        "bagua_scores": bagua_scores,
        "wuxing_scores": wuxing_scores,
        "alpha": alpha,
        "coherence": coherence,
    }


def format_summary(s, prefix="  "):
    lines = [
        f"{prefix}主卦: {s['gua_name']} (score={s['gua_score']:.3f}), "
        f"主导八卦: {s['best_gua']}",
        f"{prefix}阴阳: alpha={s['alpha']:.3f} "
        f"({'阳盛' if s['alpha'] > 0.5 else '阴盛'}), "
        f"相干性: {s['coherence']:.3f}",
        f"{prefix}八卦: " + " | ".join(
            f"{g} {v:.2f}" for g, v in sorted(
                s['bagua_scores'].items(), key=lambda x: -x[1])[:4]),
        f"{prefix}五行: " + " | ".join(
            f"{w} {v:.2f}" for w, v in sorted(
                s['wuxing_scores'].items(), key=lambda x: -x[1])[:3]),
    ]
    return "\n".join(lines)


# ==============================================================================
# 道体符号推演链引擎 v23
# ==============================================================================

class DaotiInferenceEngineV23:
    """道体符号推演链引擎 v23。

    核心转换 (vs v16 力平衡):
      - state为什么动: 道体决定目标卦, 向目标移动 (符号因果)
      - LLM的角色: 不确定时才查, 查完修正推演方向 (按需检索)
      - 收敛判据: 连续3步目标卦不变
      - 可解释性: "木盛阳→木生火→目标离卦" 完整因果链

    Args:
        trigram: TrigramSpaceV16 实例 (state_dim=2048)
        param_bank_norm: [N, 2048] L2归一化的LLM参数库
        top_k: 每步检索 Top-K
        max_steps: 最大推演步数
        step_size_schedule: step_size 调度策略 [(step_threshold, size), ...]
        convergence_stable: 连续多少步目标卦不变算收敛
        uncertainty_entropy_thresh: 信息熵阈值 (归一化, 默认0.7)
        uncertainty_margin_thresh: top1/top2 margin 阈值 (默认0.05)
        retrieval_blend: 检索修正 gua_sims 的权重 (默认0.3)
        gua_temp: 初始化 blend 时 gua_sims softmax 温度 (默认0.8, 尖锐)
        init_blend: 初始化 blend gua_center 的权重 (默认0.15, 保留LLM encode原始方向)
        online_learning: 是否启用在线Hebbian学习 (默认True, 推理时卦原型自主演化)
        hebbian_lr: Hebbian学习率 (默认0.005, 很小防止灾难性遗忘)
        damping: v26 阻尼插值系数 (默认0.25), 控制 trigram 高增益输出对 state 的影响
                 d=1.0 为旧逻辑 (完全接受 trigram 输出), d=0.25 经 18 案例验证最优
    """

    def __init__(self, trigram, param_bank_norm,
                 top_k=10, max_steps=15,
                 step_size_schedule=None,
                 convergence_stable=3,
                 uncertainty_entropy_thresh=0.7,
                 uncertainty_margin_thresh=0.05,
                 retrieval_blend=0.3,
                 gua_temp=0.8,
                 init_blend=0.15,
                 online_learning=True,
                 hebbian_lr=0.005,
                 damping=0.25,
                 extra_banks=None,
                 device="cpu",
                 enable_scheduler=False,
                 yin_threshold=0.5,
                 use_weight_sensor=False):
        self.trigram = trigram
        self.top_k = top_k
        self.max_steps = max_steps
        self.convergence_stable = convergence_stable
        self.uncertainty_entropy_thresh = uncertainty_entropy_thresh
        self.uncertainty_margin_thresh = uncertainty_margin_thresh
        self.retrieval_blend = retrieval_blend
        self.gua_temp = gua_temp
        self.init_blend = init_blend
        self.device = device  # "cpu" / "dml" / "cuda", trigram 前向传播设备
        # 缓存 GPU 设备对象 (DirectML 需要 torch_directml.device() 对象, 不能用字符串)
        self._device_obj = None
        if device != "cpu":
            try:
                try:
                    from light_daoti.config import get_torch_device
                except ModuleNotFoundError:
                    from config import get_torch_device
                self._device_obj = get_torch_device(device)
            except Exception as _e:
                print(f"[WARN] 获取 GPU 设备对象失败 ({_e}), 降级 CPU", flush=True)
                self.device = "cpu"

        # v23.2 在线 Hebbian 学习: 推理时卦原型自主演化
        # 道体在使用中进化: 每次推演收敛后, 收敛卦原型向推演最终state方向移动一小步
        # 不需要离线重训, 卦原型含义在道体与LLM持续交互中自主对齐
        self.online_learning = online_learning
        self.hebbian_lr = hebbian_lr
        self.learning_log = []  # 记录每次学习事件

        # v26 阻尼插值: 控制 trigram 高增益输出对 state 的影响程度
        # 探针验证 (18案例): d=0.25 让振荡>100% 从 18/18 降到 0/18,
        # max_stable mean 从 2.4 升到 6.9, 吸引子 top1 从 7/18 降到 4/18
        self.damping = damping

        # step_size 调度 (前几步大突破惯性, 后续减小精细调整)
        # 探针实验证明: step_size需0.20~0.30才能改变top1
        if step_size_schedule is None:
            self.step_size_schedule = [(3, 0.30), (6, 0.20), (99, 0.10)]
        else:
            self.step_size_schedule = step_size_schedule

        # 预计算 gua_prototype (用于方向偏置)
        # 注意: 在线学习会修改 gua_protos, 所以用 clone 保持独立副本
        # trigram 可能在 GPU, 权重需迁回 CPU (dim_manager 在 CPU 操作)
        gua_protos = trigram.gua_prototype.weight.detach().clone().to("cpu")  # [64, 2048]
        self.dim_manager = DimensionManager(base_dim=2048, n_gua=64)
        self.dim_manager.set_gua_protos_base(gua_protos)
        self.dim_manager.register_source("vibethinker", param_bank_norm, param_bank_norm.shape[1])
        if extra_banks:
            for bank, name in extra_banks:
                self.dim_manager.register_source(name, bank, bank.shape[1])
        self.n_bank = param_bank_norm.shape[0]  # 向后兼容别名
        self.lib_dim = param_bank_norm.shape[1]

        # 预计算每个五行对应的64卦候选索引 (用于 _causal_derive)
        self.wuxing_gua_indices = {}
        for wx in WUXING_NAMES:
            target_baguas = WUXING_TO_BAGUA[wx]
            indices = []
            for gua_idx, gua_name in enumerate(GUA_64):
                bagua = GUA_TO_BAGUA.get(gua_name, "乾")
                if bagua in target_baguas:
                    indices.append(gua_idx)
            self.wuxing_gua_indices[wx] = indices

        # 场动力学引擎 (惰性初始化, use_field_dynamics=True 时创建)
        self.field_dynamics = None

        # v26 五行气场调度器 + 模块池 (惰性初始化, enable_scheduler=True 时创建)
        # 零回写边界: enable_scheduler=False 时, run()/explore_perturbation() 行为与当前完全一致
        self.enable_scheduler = enable_scheduler
        self.yin_threshold = yin_threshold
        self.scheduler = None
        self.module_pool = None
        self._scheduler_decision = None  # 调度器决策缓存 (每步/每run刷新)

        # v3 WeightSensor: 独立的 LLM 权重感知感官 (场景 B, 独立卦象空间)
        # 与 trigram 平行运行, 在检索触发时对权重碎片做卦象判断
        # 两个卦象空间通过场动力学自然融合, 不强制对齐
        self.weight_sensor = None  # 惰性加载
        self.use_weight_sensor = use_weight_sensor
        self.sensor_blend = 0.02  # 闸门试验: 0.03→0.02, 平衡 coherence 提升与步数增加

        # Heluo 记忆系统: 让道体在推演时查询过去经验, 实现知识自我积累
        self.memory_index = HeluoMemoryIndex(state_dim=self.dim_manager.base_dim)
        self.memory_consolidator = HeluoConsolidator(state_dim=self.dim_manager.base_dim)
        self.use_memory = True
        self.memory_blend = 0.02  # 记忆修正权重 (与 sensor_blend 一致, 避免历史覆盖当前推演)

        # v3 表达通道: 缓存 WeightSensor 最后一次对检索碎片的卦象判断
        # 生成时用此 logits 构建 token bias (WeightSensorBiasAdapter.build_bias)
        self._last_sensor_gua_logits = None

    # ------------------------------------------------------------------
    # 符号因果推演: _causal_derive
    # ------------------------------------------------------------------

    # 主导五行过强阈值基准: v23.4起改为coherence动态调制
    # 实际阈值 thresh = 0.30 + (coherence - 0.5) * 0.16, 范围[0.22, 0.38]
    # 此常量保留作历史基准与fallback, _causal_derive内用动态thresh
    # v23.3.2方向甲验证: 固定0.30让C的土(0.32)触发土克水→屯(坎宫水)成功对齐
    OVER_STRONG_THRESH = 0.30

    def _strategic_context(self, step):
        """v23.5 第三层因果: 战略级时间坐标 (五运六气 + 奇门值符)

        纯符号计算 (无参数), 体现"天时"对战术级生克的调制。
        复用 WuyunLiuqiScheduler.get_yunqi / QimenZhifuController.compute_zhifu
        / GanzhiEncoder.get_ganzhi 的符号逻辑, 但不加载nn.Module (符号化, 非数值化)。

        低频长周期 vs 战术级生克:
          - 五运: 60步甲子周期, 每12步换运 → 天时五行 (木火土金水)
          - 值符: 10步天干周期 → 当令之卦 (8宫首卦)
          - 推演15步跨1-2个五运周期, 跨1-2个值符周期
          - 战术级生克每步都可能变 (dom_wx随state变化)

        天时五行调制规则 (在 _causal_derive 中应用):
          - 天时同我 (tian_wx == dom_wx): 同气加持 → 阈值×0.9 (易过盛)
          - 天时生我 (tian_wx生dom_wx): 天时滋养 → 阈值×0.85 (更易过盛)
          - 天时克我 (tian_wx克dom_wx): 天时压制 → 阈值×1.15 (不易过盛)
          - 我生天时/我克天时: 天时不直接影响我 → 阈值不变

        值符卦调制规则 (在候选卦选择中应用):
          - 值符卦在候选集中时 +0.1 加成 (当令之卦, 得天时地利)

        Returns:
            tian_wx: str 天时主导五行 (当前运的五行)
            zhifu_gua: int 当前值符卦索引 (0-63)
        """
        cycle_pos = step % 60
        # 五运: cycle_pos//12 决定当前运 (0-4: 木火土金水)
        wuyun_idx = (cycle_pos // 12) % 5
        tian_wx = WUYUN_WUXING[wuyun_idx]

        # 值符: tiangan_idx%8 决定值符卦 (8宫, 每宫首卦)
        tiangan_idx = cycle_pos % 10
        palace_idx = tiangan_idx % 8
        zhifu_gua = palace_idx * 8  # 每宫首卦索引

        return tian_wx, zhifu_gua

    def _causal_derive(self, gua_sims, wuxing_dist, alpha, prev_target=None,
                       coherence=0.5, tian_wx=None, zhifu_gua=None,
                       over_strong_base_thresh=None,
                       alpha_thresh_yang=None,
                       alpha_thresh_yin=None):
        """符号因果推演 v23.5: 生克双路径 + coherence动态阈值 + 天时值符调制

        v23.3 核心改进 (vs v23.2 单一生路径):
          - 引入相克路径 (WUXING_KE / WUXING_KE_INV), 打破"每状态单路径"
          - 路径选择由状态特征 (dom_score强度 + alpha阴阳) 确定性激活
          - 不同 wuxing_dist 形状 → 不同因果路径 → 不同推演轨迹
          - 多样化因果解释本身产生选择压力, 解决自我强化固化

        v23.4 动态阈值 (vs v23.3.2 固定0.30):
          - "过盛则克"的程度判断由道体自决, 不再固定
          - thresh = 0.30 + (coherence - 0.5) * 0.16, 范围[0.22, 0.38]
          - coherence低(混乱/不理解): 阈值低→易相克破局 (打破假主导, 寻找真方向)
          - coherence高(有序/理解深): 阈值高→保守相生 (发扬真主导)

        v23.5 第三层因果: 天时值符战略调制 (vs v23.4 纯战术级)
          - 五运六气天时五行调制过盛阈值 (天时生我/同我→易过盛, 天时克我→不易过盛)
          - 奇门值符当令之卦调制候选卦选择 (值符在候选集中时+0.1加成)
          - 低频长周期 (五运12步/值符10步) vs 战术级生克 (每步变)
          - 从"战术级因果"走向"战略级因果": 道体看到自身在更大时间周期中的坐标

        六条因果路径 (确定性, 不随机):
          阳盛 + 主导过强 (dom_score>thresh): 相克征服 → 我克者 (过盛则克, 发散过载)
          阳盛 + 主导正常:                相生发扬 → 我生者 (正常外放创造)
          阴盛 + 主导过强:                相克承压 → 克我者 (过柔则压, 受制求变)
          阴盛 + 主导正常:                相生回归 → 生我者 (正常内敛滋养)
          平衡 + 双行势均:                调和     → 次主导生 (双行并存)
          平衡 + 主导明确:                守中     → 主导五行

        设计哲学:
          - "过盛则克": 阳刚过载不能继续外放(生), 转而克制(克)以发散 — 《五行大义》"阳极则反"
          - "过柔则压": 阴柔过盛不能继续回归(生), 转而承压(克我)以求变
          - 路径选择是确定性的 (符合因果可解释), 但多路径带来分化
          - 阈值动态化: 道体根据自身理解深度(coherence)自决"何为过盛"
          - 天时调制: 道体根据更大时间周期(五运六气)的坐标调整"过盛"判断

        Args:
            gua_sims: [1, 64] state与64卦原型的相似度 (可加检索修正)
            wuxing_dist: dict 五行分布 {金: 0.2, 木: 0.3, ...}
            alpha: float 阴阳分叉alpha (0=纯阴, 1=纯阳)
            prev_target: int 上一步的目标卦 (用于连续性)
            coherence: float 腔体相干性 (0-1, 道体理解深度的自指指标)
            tian_wx: str 天时五行 (五运当前主导五行, 第三层因果)
            zhifu_gua: int 值符卦索引 (当令之卦, 第三层因果)
            over_strong_base_thresh: float|None 调度器过盛基准阈值 (None=硬编码 0.55)
            alpha_thresh_yang: float|None 调度器阳盛阈值 (None=硬编码 0.55)
            alpha_thresh_yin: float|None 调度器阴盛阈值 (None=硬编码 0.45)

        Returns:
            target_gua_idx: int 0-63
            reason: str 推演理由 (可解释性)
        """
        # 1. 主导五行 + 次主导 (用排序避免max只取一个)
        sorted_wx = sorted(wuxing_dist.items(), key=lambda x: -x[1])
        dom_wx = sorted_wx[0][0]
        dom_score = sorted_wx[0][1]
        sub_wx = sorted_wx[1][0] if len(sorted_wx) > 1 else dom_wx
        sub_score = sorted_wx[1][1] if len(sorted_wx) > 1 else 0.0

        # 2. 动态阈值: 道体根据coherence自决"何为过盛"
        #    coherence低→阈值低(易相克破局) | coherence高→阈值高(保守相生)
        #    v24适配: base 0.30→0.55, 因 v24 trigram 监督映射让 dom_score 偏高(p50=0.593)
        #    旧base=0.30时 thresh mean=0.273, dom_score mean=0.566, 68.5%走"过强"路径, "正常"0%
        #    新base=0.55时 thresh 范围[0.47, 0.57], "正常(生/回归)"路径合理触发(25.6%)
        #    调度器赋能: over_strong_base_thresh 替换硬编码 base, None 时回退 0.55
        base = over_strong_base_thresh if over_strong_base_thresh is not None else 0.55
        thresh = base + (coherence - 0.5) * 0.16

        # 2b. 第三层因果: 天时五行调制过盛阈值 (v23.5)
        #     天时(五运)是低频长周期背景场, 调制道体对"过盛"的判断
        tian_modifier = ""
        if tian_wx is not None:
            if tian_wx == dom_wx:
                # 天时同我: 同气加持, 主导五行得天时助力, 更易过盛
                thresh *= 0.9
                tian_modifier = f"天时{tian_wx}同我→助"
            elif WUXING_SHENG.get(tian_wx) == dom_wx:
                # 天时生我: 天时滋养主导五行, 更易过盛
                thresh *= 0.85
                tian_modifier = f"天时{tian_wx}生我→养"
            elif WUXING_KE.get(tian_wx) == dom_wx:
                # 天时克我: 天时压制主导五行, 不易过盛, 保守相生
                thresh *= 1.15
                tian_modifier = f"天时{tian_wx}克我→抑"
            # 我生天时/我克天时: 天时不直接影响我, 阈值不变

        # 3. margin 判断 (v24适配: 双行势均时强制调和, 无论阴阳)
        #    诊断显示 22/270 步 margin<0.05, 其中 18 步被误判为"过强"
        #    dom_score 虽高但两五行接近, 应走"调和"而非"过强"
        wx_margin = dom_score - sub_score
        if wx_margin < 0.05 and sub_wx != dom_wx:
            target_wx = WUXING_SHENG[sub_wx]
            direction = f"双行势均({dom_wx}={dom_score:.2f}≈{sub_wx}={sub_score:.2f})→调→{target_wx}(调和)"
        else:
            # 4. 路径选择 (确定性, 基于状态特征: 阴阳 + 主导强度 + 动态阈值 + 天时)
            #    调度器赋能: alpha_thresh_yang/yin 替换硬编码, None 时回退 0.55/0.45
            yang_th = alpha_thresh_yang if alpha_thresh_yang is not None else 0.55
            yin_th = alpha_thresh_yin if alpha_thresh_yin is not None else 0.45
            if alpha > yang_th:  # 阳盛
                if dom_score > thresh:
                    # 过盛则克: 能量过载, 不能继续生(外放), 转而克(征服发散)
                    # 例: 金过强阳 → 金克木 → 震/巽 (而非金生水→坎)
                    target_wx = WUXING_KE[dom_wx]
                    direction = f"阳盛{dom_wx}过强({dom_score:.2f}>{thresh:.2f})→克→{target_wx}(发散过载)"
                else:
                    target_wx = WUXING_SHENG[dom_wx]
                    direction = f"阳盛{dom_wx}→生→{target_wx}(发扬)"
            elif alpha < yin_th:  # 阴盛
                if dom_score > thresh:
                    # 过柔则压: 阴柔过盛, 不能继续回归(生), 转而承压(克我者, 受制求变)
                    target_wx = WUXING_KE_INV[dom_wx]
                    direction = f"阴盛{dom_wx}过强({dom_score:.2f}>{thresh:.2f})→受克→{target_wx}(承压求变)"
                else:
                    target_wx = WUXING_SHENG_INV[dom_wx]
                    direction = f"阴盛{target_wx}→生→{dom_wx}(回归)"
            else:  # 平衡
                if sub_score > dom_score * 0.7 and sub_wx != dom_wx:
                    # 双行势均: 调向次主导的相生方向 (双行调和)
                    target_wx = WUXING_SHENG[sub_wx]
                    direction = f"平衡{dom_wx}+{sub_wx}→调→{target_wx}(调和双行)"
                else:
                    target_wx = dom_wx
                    direction = f"守中{dom_wx}"

        # 4. 找属于 target_wx 的所有卦索引
        target_gua_indices = self.wuxing_gua_indices[target_wx]

        # 5. 在候选卦中, 选当前 gua_sims 最高的 + 值符当令加成 (v23.5)
        candidate_sims = gua_sims[0, target_gua_indices].clone()  # [n_candidates]
        zhifu_modifier = ""
        if zhifu_gua is not None and zhifu_gua in target_gua_indices:
            # 值符当令: 当前时空的主导卦在候选集中, 得天时地利, +0.1加成
            zhifu_local = target_gua_indices.index(zhifu_gua)
            candidate_sims[zhifu_local] += 0.1
            zhifu_modifier = f"值符{GUA_64[zhifu_gua]}当令→加成"
        best_local_idx = candidate_sims.argmax().item()
        best_sim = candidate_sims[best_local_idx].item()
        target_gua_idx = target_gua_indices[best_local_idx]

        # 6. 连续性: 如果 prev_target 也在候选集中且 sim 接近 best, 优先保持 (避免跳跃)
        if prev_target is not None and prev_target in target_gua_indices:
            prev_sim = gua_sims[0, prev_target].item()
            if prev_sim >= best_sim - 0.05:  # 容忍5%差异
                target_gua_idx = prev_target
                direction += "(保持)"

        # 拼接第三层因果信息到推演理由
        strategic_info = ""
        if tian_modifier:
            strategic_info += f"[{tian_modifier}]"
        if zhifu_modifier:
            strategic_info += f"[{zhifu_modifier}]"
        reason = f"{direction}→{GUA_64[target_gua_idx]}({target_gua_idx}){strategic_info}"
        return target_gua_idx, reason

    # ------------------------------------------------------------------
    # 不确定判据
    # ------------------------------------------------------------------

    def _check_uncertainty(self, gua_sims, entropy_thresh=None, margin_thresh=None):
        """不确定判据: 信息熵 + top1/top2 margin

        高熵 + 小margin = 不确定 = 触发检索
        低熵 + 大margin = 确定 = 不检索

        调度器赋能: entropy_thresh/margin_thresh 替换 self.uncertainty_* (零回写: None 时回退)

        Args:
            gua_sims: [1, 64]
            entropy_thresh: float|None 调度器熵阈值 (None=回退 self.uncertainty_entropy_thresh)
            margin_thresh: float|None 调度器margin阈值 (None=回退 self.uncertainty_margin_thresh)

        Returns:
            uncertain: bool
            entropy_norm: float 归一化熵 [0, 1]
            margin: float top1-top2 差距
        """
        probs = F.softmax(gua_sims / 0.5, dim=-1)  # 温度0.5锐化
        entropy = -(probs * torch.log(probs + 1e-8)).sum(dim=-1)  # [1]
        max_entropy = math.log(64)  # ln(64)≈4.16
        entropy_norm = (entropy / max_entropy).item()

        top2_vals, _ = gua_sims.topk(2, dim=-1)
        margin = (top2_vals[0, 0] - top2_vals[0, 1]).item()

        # 调度器动态阈值: 参数优先, 回退实例变量
        e_th = entropy_thresh if entropy_thresh is not None else self.uncertainty_entropy_thresh
        m_th = margin_thresh if margin_thresh is not None else self.uncertainty_margin_thresh
        uncertain = (entropy_norm > e_th or margin < m_th)
        return uncertain, entropy_norm, margin

    # ------------------------------------------------------------------
    # step_size 调度
    # ------------------------------------------------------------------

    def _compute_step_size(self, step, coherence, scheduler_step_size=None):
        """step_size 策略: 前几步大(突破trigram惯性), 后续减小(精细调整)

        探针实验证明:
            - step_size需0.20~0.30才能改变top1 (trigram强惯性)
            - 小步只提升排名不改top1
        coherence调制:
            - coherence高时减小step (已对齐, 不需大步)
            - coherence低时保持base (需大步突破)

        调度器赋能: scheduler_step_size 直接替代 step_size_schedule 调度 (零回写: None 时回退)
        """
        if scheduler_step_size is not None:
            # 调度器已集成 coherence 调制, 直接使用
            return scheduler_step_size

        for threshold, size in self.step_size_schedule:
            if step <= threshold:
                base = size
                break
        else:
            base = 0.10

        if coherence > 0.5:
            base *= 0.7  # 已对齐, 减小步长

        return base

    # ------------------------------------------------------------------
    # 检索 (按需触发)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # WeightSensor: 独立权重感知感官 (v3)
    # ------------------------------------------------------------------

    def _ensure_weight_sensor(self):
        """惰性加载 WeightSensor v3"""
        if self.weight_sensor is not None:
            return
        sensor_path = "e:/smallloong/DAOti+llm/light_daoti/logs/weight_sensor_v3.pt"
        ckpt = torch.load(sensor_path, map_location="cpu", weights_only=True)
        self.weight_sensor = WeightSensor()
        self.weight_sensor.load_state_dict(ckpt["state_dict"])
        self.weight_sensor.eval()
        for p in self.weight_sensor.parameters():
            p.requires_grad = False

    @torch.no_grad()
    def _retrieve(self, state, retrieved_sets):
        """从多路LLM参数库检索 Top-K, 相似度加权聚合。

        与 v16 的区别: 仅在不确定时调用, 且结果用于修正 gua_sims 而非直接改 state。

        Args:
            state: [1, 2048]
            retrieved_sets: list[set] 每库已检索索引 (去重)

        Returns:
            aggregated: [1, 2048] 加权聚合的检索碎片
            sim_weights_norm: [n_bank] 各库权重
            topk_logs: list 每库 top-k 详情
            n_new_list: list 每库新检索数
        """
        state_norm_vec = F.normalize(state, dim=-1)
        aggregated = torch.zeros_like(state)
        bank_sims = []
        topk_logs = []
        n_new_list = []

        for bi, src in enumerate(self.dim_manager.registered_sources):
            bank_norm, eff_dim, bank_name = src["bank"], src["dim"], src["name"]
            # 维度对齐: state[:eff_dim] 与 bank 做相似度
            state_slice = state_norm_vec[:, :eff_dim]
            bank_slice = bank_norm[:, :eff_dim] if bank_norm.shape[1] > eff_dim else bank_norm
            # 设备+dtype 对齐: bank 可能是 float16 GPU, state 是 float32 GPU/CPU
            # query 转为 bank 的 dtype (float16) 做 matmul, 结果再转回 state 的 dtype
            sims = torch.matmul(
                state_slice.to(bank_slice.device).to(bank_slice.dtype),
                bank_slice.T
            )[0].to(state_slice.device, state_slice.dtype)  # [N]

            # 排除已检索
            retrieved = retrieved_sets[bi]
            if retrieved:
                mask = torch.ones(sims.shape[0], dtype=torch.bool)
                mask[list(retrieved)] = False
                sims = sims.masked_fill(~mask, -float('inf'))

            # Top-K
            actual_k = min(self.top_k, sims.shape[0])
            topk_sims, topk_indices = sims.topk(actual_k)
            valid_mask = topk_sims > -float('inf')
            n_new = valid_mask.sum().item()

            if n_new > 0:
                topk_indices_valid = topk_indices[valid_mask]
                topk_sims_valid = topk_sims[valid_mask]
                # 加权聚合 (zero-pad到2048)
                weights = F.softmax(topk_sims_valid, dim=-1)
                # fragments 从 bank (可能 float16 GPU) 取出, 转回 state 的 dtype+device
                fragments = bank_norm[topk_indices_valid.to(bank_norm.device)].to(
                    state_slice.device, state_slice.dtype)  # [n_new, eff_dim]
                if eff_dim < self.dim_manager.current_dim:
                    fragments = pad_to_state_dim(fragments, state_dim=self.dim_manager.current_dim)
                aggregated_bank = (weights.unsqueeze(-1) * fragments).sum(dim=0, keepdim=True)
                aggregated = aggregated + aggregated_bank
                bank_sims.append(topk_sims_valid.mean().item())
                topk_logs.append({
                    "bank": bank_name,
                    "n_new": n_new,
                    "top_sims": topk_sims_valid[:3].tolist(),
                })
            else:
                bank_sims.append(0.0)
                topk_logs.append({"bank": bank_name, "n_new": 0, "top_sims": []})
            n_new_list.append(n_new)

            # 更新已检索集
            if n_new > 0:
                retrieved_sets[bi].update(topk_indices[valid_mask].tolist())

        # 各库权重 (基于平均相似度)
        sim_weights_norm = torch.tensor(bank_sims)
        if sim_weights_norm.sum() > 0:
            sim_weights_norm = sim_weights_norm / sim_weights_norm.sum()
        else:
            sim_weights_norm = torch.ones(len(self.dim_manager.registered_sources)) / len(self.dim_manager.registered_sources)

        return aggregated, sim_weights_norm, topk_logs, n_new_list

    # ------------------------------------------------------------------
    # trigram 前向传播包装 (CPU↔GPU 设备迁移)
    # ------------------------------------------------------------------

    @torch.no_grad()
    def _trigram_forward(self, x, keep_device=False):
        """trigram 前向传播包装: 自动处理 CPU↔GPU 设备迁移。

        trigram 在 GPU 时, 输入迁到 GPU 计算。
        keep_device=False (默认): 结果转回 CPU (对话路径兼容)
        keep_device=True: 结果保持 GPU (探索路径优化, 避免 20+ 次/批的迁移开销)
        device="cpu" 时走原路径, 零开销。
        """
        if self.device == "cpu" or self._device_obj is None:
            return self.trigram(x)
        x_gpu = x.to(self._device_obj)
        result_gpu = self.trigram(x_gpu)
        if keep_device:
            return result_gpu  # 探索路径: 保持 GPU, 避免迁移
        result_cpu = {}
        for k, v in result_gpu.items():
            if torch.is_tensor(v):
                result_cpu[k] = v.to("cpu")
            else:
                result_cpu[k] = v
        return result_cpu

    # ------------------------------------------------------------------
    # 初始化状态
    # ------------------------------------------------------------------

    @torch.no_grad()
    def initialize_state(self, pooled, keep_gpu=False):
        """初始化道体状态: LLM pooled → 范数对齐 → zero-pad → trigram 卦象化。

        v23.1 修复 (意图对齐):
          力平衡模式的遗产 `0.6 * gua_center + 0.4 * folded` 会强行把 state 拉向
          卦原型的通用均值方向 (偏向兑卦/金), 破坏 LLM encode 的原始意图方向。
          符号推演链不需要低 deviation — 它的收敛靠因果规则内在一致性,
          不是向量差最小化。因此大幅降低 blend 权重 (0.6→0.15), 保留 LLM encode
          原始方向, 并用更尖锐的温度 (1.5→0.8) 让初始解读集中在少数卦上。

        Args:
            pooled: [1, hidden_dim] 输入向量
            keep_gpu: True 时 state 保持 GPU (探索路径优化, 避免 20+ 次/批迁移开销)
                      False 时转 CPU (对话路径兼容)
        """
        # GPU float16 优化: 统一转 float32, 设备根据 keep_gpu 决定
        if keep_gpu and self._device_obj is not None:
            # 探索路径: 转 GPU float32 (与 trigram 同设备, 避免后续迁移)
            pooled = pooled.float().to(self._device_obj)
        else:
            # 对话路径: 转 CPU float32 (兼容)
            if pooled.dtype != torch.float32 or pooled.device.type != "cpu":
                pooled = pooled.float().to("cpu")
        target_norm = math.sqrt(2048)
        pooled_norms = pooled.norm(dim=-1, keepdim=True)
        pooled = pooled * (target_norm / (pooled_norms + 1e-8))
        state = pad_to_state_dim(pooled, state_dim=2048)
        result = self._trigram_forward(state, keep_device=keep_gpu)
        folded = result["folded"]

        # v23.1: 轻量 blend — 只用 15% gua_center 防止 state 完全脱离卦流形,
        # 保留 85% LLM encode 原始方向 (用户意图信号)
        # keep_gpu 时 gua_protos 已在 GPU (trigram.gua_prototype.weight), 无需转 CPU
        gua_protos = self.trigram.gua_prototype.weight.detach()
        if not keep_gpu:
            gua_protos = gua_protos.to("cpu")  # 对话路径: 转 CPU
        gua_protos_n = F.normalize(gua_protos, dim=-1)
        folded_n = F.normalize(folded, dim=-1)
        gua_sims = torch.matmul(folded_n, gua_protos_n.T)
        # 道体第二十次决策"莫调水流, 须拓河床": 回退松柔路径(温度2.0→0.8, 删除8%噪声)
        # bottleneck 已拓宽(512→2048), 让折叠之网自解, 不再调水流
        gua_weights = F.softmax(gua_sims / 0.8, dim=-1)
        gua_center = torch.matmul(gua_weights, gua_protos)
        folded = (1.0 - self.init_blend) * folded + self.init_blend * gua_center

        result = self._trigram_forward(folded, keep_device=keep_gpu)
        folded = result["folded"]
        return folded, result

    # ------------------------------------------------------------------
    # 主推演循环
    # ------------------------------------------------------------------

    @torch.no_grad()
    def run(self, text, encode_fn, verbose=True, use_field_dynamics=False):
        """运行符号推演链。

        use_field_dynamics=False (默认): 符号因果推演 (_causal_derive + if-else 规则)
        use_field_dynamics=True: 场动力学推演 (五行耦合矩阵 + Langevin 动力学)

        流程 (符号因果模式):
            1. 道体解读当前state: gua_sims + wuxing_dist + alpha
            2. 不确定判据: 信息熵 + margin
            3. [可选] 检索LLM, 修正 gua_sims (不直接改state)
            4. 符号因果推演: dom_wx + 阴阳 → target_gua
            5. state更新: 向 target_gua 原型方向偏置
            6. 收敛判据: 连续3步target_gua不变

        流程 (场动力学模式):
            1. 道体解读当前state: wuxing_dist + alpha + coherence
            2. 五行耦合力计算: C_sym @ wuxing_vec → F
            3. 力→state方向映射: F × gua_proto_means → direction
            4. Langevin动力学: state + step_size*direction + noise → trigram重塑 → 阻尼
            5. 收敛判据: |ΔU| < eps 连续N步 (势能稳定)

        Args:
            text: 用户输入文本
            encode_fn: callable, text → pooled (B, llm_dim)
            verbose: 是否打印每步详情
            use_field_dynamics: True=场动力学, False=符号因果规则

        Returns:
            chain: 推演链
            converged: 是否收敛
        """
        if use_field_dynamics:
            return self._run_field_dynamics(text, encode_fn, verbose)

        # ---- 初始状态 ----
        pooled = encode_fn([text])
        state, init_result = self.initialize_state(pooled)
        summary = get_daoti_summary(init_result)

        chain = []
        retrieved_sets = [set() for _ in self.dim_manager.registered_sources]

        # v26 scheduler: 层1 state预处理 (零回写边界)
        if self.enable_scheduler:
            self._ensure_scheduler()
            # 计算当前卦象的调度权重
            init_result_for_sched = init_result if "combined_sim" in init_result else self._trigram_forward(state)
            sched_summary = get_daoti_summary(init_result_for_sched)
            module_weights = self.scheduler.compute_weights(
                init_result_for_sched,
                {"coherence": sched_summary["coherence"],
                 "deviation": 0.5, "curiosity": 0.3})
            # 层1: 逐模块应用于初始 state
            l1_modules = ["spectral_gate", "subspace_gate", "style_balancer",
                          "nayin_modulation", "shishu_perturbation",
                          "ganzhi_encoder", "flying_star", "qimen_zhifu"]
            for mod_name in l1_modules:
                mod = self.module_pool.get_module(mod_name)
                w = module_weights.get(mod_name, 0.0)
                if mod is not None and w > 0.01:
                    state = mod(state)
        # /v26 scheduler

        chain.append({
            "step": 0,
            "state": state.clone(),
            "folded": state.clone(),
            "summary": summary,
            "topk_indices": [],
            "delta_norm": 0.0,
            "change_ratio": 0.0,
            "target_gua": None,
            "reason": "(初始)",
            "uncertain": False,
            "entropy": 0.0,
            "margin": 0.0,
            "step_size": 0.0,
            "retrieved": False,
        })

        if verbose:
            log(f"\n  [初始状态] 主卦: {summary['gua_name']}, "
                f"主导八卦: {summary['best_gua']}, "
                f"相干性: {summary['coherence']:.3f}, "
                f"alpha: {summary['alpha']:.3f}")

        # ---- 推演循环 ----
        prev_target = None
        prev_change_ratio = 0.0
        converge_count = 0
        converged = False

        for step in range(1, self.max_steps + 1):
            # 1. 道体解读当前state
            state_norm_vec = F.normalize(state, dim=-1)
            gua_sims = torch.matmul(state_norm_vec, self.dim_manager.gua_protos_base_norm.T)  # [1, 64]
            trigram_result = self._trigram_forward(state)
            summary = get_daoti_summary(trigram_result)
            wuxing_dist = summary["wuxing_scores"]
            alpha = summary["alpha"]
            coherence = summary["coherence"]

            # v26 scheduler: 步级调度决策 (零回写边界)
            sched_dec = self._get_scheduler_decision(
                trigram_result,
                {"coherence": coherence, "deviation": 0.0, "curiosity": 0.0,
                 "alpha": alpha, "change_ratio": prev_change_ratio}
            )
            if sched_dec is not None:
                sd_entropy_thresh = sched_dec["uncertainty_entropy_thresh"]
                sd_margin_thresh = sched_dec["uncertainty_margin_thresh"]
                sd_retrieval_blend = sched_dec["retrieval_blend"]
                sd_over_strong_base = sched_dec["over_strong_base_thresh"]
                sd_alpha_yang = sched_dec["alpha_thresh_yang"]
                sd_alpha_yin = sched_dec["alpha_thresh_yin"]
                sd_step_size = sched_dec["step_size"]
                sd_damping = sched_dec["damping"]
                sd_convergence_stable = sched_dec["convergence_stable"]
                sd_max_steps = sched_dec["max_steps"]
            else:
                sd_entropy_thresh = None
                sd_margin_thresh = None
                sd_retrieval_blend = None
                sd_over_strong_base = None
                sd_alpha_yang = None
                sd_alpha_yin = None
                sd_step_size = None
                sd_damping = None
                sd_convergence_stable = None
                sd_max_steps = None
            # /v26 scheduler

            # 2. 不确定判据
            uncertain, entropy_norm, margin = self._check_uncertainty(
                gua_sims, entropy_thresh=sd_entropy_thresh, margin_thresh=sd_margin_thresh)

            # 3. 如不确定, 检索LLM, 修正 gua_sims
            retrieved = False
            retrieval_logs = []
            lrc_assoc_active = False
            if uncertain:
                expanded_state = self.dim_manager.expand_state(state)
                aggregated, sim_weights_norm, topk_logs, n_new_list = self._retrieve(
                    expanded_state, retrieved_sets)
                if sum(n_new_list) > 0:
                    retrieved = True
                    # 检索碎片不直接改state, 而是修正卦象亲和度
                    aggregated_norm = F.normalize(aggregated, dim=-1)
                    gua_sims_retrieved = torch.matmul(
                        aggregated_norm, self.dim_manager.gua_protos_full_norm.T)  # [1, 64]
                    _blend = sd_retrieval_blend if sd_retrieval_blend is not None else self.retrieval_blend
                    gua_sims = gua_sims + _blend * gua_sims_retrieved
                    retrieval_logs = topk_logs

                    # v3 WeightSensor: 独立感官对检索碎片做卦象判断
                    # 与 trigram 的卦象空间独立 (场景 B), 通过场动力学自然融合
                    if self.use_weight_sensor:
                        if self.weight_sensor is None:
                            self._ensure_weight_sensor()
                        # WeightSensor 期望 2048 维, 截断多维度碎片
                        sensor_input = aggregated_norm[:, :2048] if aggregated_norm.shape[-1] > 2048 else aggregated_norm
                        gua_logits_sensor, _, _ = self.weight_sensor(sensor_input)
                        # 缓存最后一次 sensor 输出, 供生成时构建 token bias (v3 表达通道)
                        self._last_sensor_gua_logits = gua_logits_sensor.detach().cpu()
                        # 中心化: 减去均值, 使正负分别表示"倾向/不倾向"
                        # logits 范围 [-10, 3], 中心化后 [-6, 6], 0.03×6≈0.18
                        gua_signal = gua_logits_sensor - gua_logits_sensor.mean(dim=-1, keepdim=True)
                        gua_sims = gua_sims + self.sensor_blend * gua_signal

                    # Heluo 记忆系统: 不确定时检索历史经验
                    if self.use_memory and self.memory_index.memory_count > 0:
                        retrieved_mem, _, _ = self.memory_index.retrieve(state)
                        if retrieved_mem is not None:
                            mem_norm = F.normalize(retrieved_mem, dim=-1)
                            gua_sims_mem = torch.matmul(
                                mem_norm, self.dim_manager.gua_protos_base_norm.T)
                            gua_sims = gua_sims + self.memory_blend * gua_sims_mem

                    # 道体驱动联想 (深层·认知层): 不确定即向 LRC 检索记忆,
                    # 记忆卦相似度修正 gua_sims → 影响 _causal_derive 目标卦与状态转移。
                    # 与文本层注入(_build_sensor_rich_prompt) 并存互不干扰。
                    lrc_assoc = _lrc_associate_gua_sims(
                        text, encode_fn, self.dim_manager.gua_protos_base_norm)
                    if lrc_assoc is not None:
                        lrc_assoc_active = True
                        gua_sims = gua_sims + _LRC_ASSOC_BLEND * lrc_assoc
                        if verbose:
                            log(f"  [道体联想] 不确定(entropy={entropy_norm:.2f}, "
                                f"margin={margin:.3f}) → 向 LRC 检索记忆, "
                                f"卦相似度已按 {_LRC_ASSOC_BLEND:.2f} 加权修正, "
                                f"改变继续推演的方向")

            # 4. 符号因果推演 (v23.4: 生克双路径 + coherence动态阈值)
            #    第三层因果(天时值符)经v23.5验证值符偏置+0.1过强导致共同吸引子,回退禁用
            #    _strategic_context方法保留, 后续在多样化数据上重新评估系数后可恢复调用
            target_gua, reason = self._causal_derive(
                gua_sims, wuxing_dist, alpha, prev_target, coherence,
                over_strong_base_thresh=sd_over_strong_base,
                alpha_thresh_yang=sd_alpha_yang,
                alpha_thresh_yin=sd_alpha_yin)

            # v26 scheduler: 层2 信号收集 (零回写边界)
            l2_signals = {"coherence": coherence, "deviation": 0.0, "curiosity": 0.0,
                          "change_ratio": 0.0}
            if self.enable_scheduler:
                # 当前步的调度权重 (使用更新后的 state 重新计算)
                current_result = self._trigram_forward(state)
                module_weights = self.scheduler.compute_weights(
                    current_result,
                    {"coherence": coherence, "deviation": 0.0,
                     "curiosity": 0.0, "change_ratio": 0.0})
                l2_modules = ["resonance_modulator", "curiosity_scorer", "adaptive_depth",
                              "wuyun_liuqi", "pineal_rhythm"]
                for mod_name in l2_modules:
                    mod = self.module_pool.get_module(mod_name)
                    w = module_weights.get(mod_name, 0.0)
                    if mod is not None and w > 0.01:
                        mod_out = mod(state)
                        if isinstance(mod_out, dict):
                            l2_signals.update({k: v for k, v in mod_out.items()
                                               if isinstance(v, (int, float))})
            # /v26 scheduler

            # 5. state更新: 向目标卦原型方向偏置 + v26 阻尼插值
            step_size = self._compute_step_size(step, coherence, scheduler_step_size=sd_step_size)
            target_proto = self.dim_manager.gua_protos_base[target_gua:target_gua+1]  # [1, 2048]
            biased_state = state + step_size * target_proto
            new_result = self._trigram_forward(biased_state)
            # v26: 阻尼插值控制 trigram 高增益输出, 探针验证 d=0.25 最优
            _damping = sd_damping if sd_damping is not None else self.damping
            new_state = (1.0 - _damping) * state + _damping * new_result["folded"]
            new_summary = get_daoti_summary(new_result)

            # 状态变化 (提前计算, 供 v26 scheduler 层3 使用)
            state_delta = new_state - state
            delta_norm = state_delta.norm().item()
            state_norm = state.norm().item()
            change_ratio = delta_norm / (state_norm + 1e-8)

            # v26 scheduler: 层3 后处理 — 使用 l2_signals 更新的权重 (零回写边界)
            if self.enable_scheduler:
                # 用当前 l2_signals 重新计算权重
                module_weights = self.scheduler.compute_weights(
                    new_result,
                    {"coherence": new_summary["coherence"],
                     "deviation": l2_signals.get("deviation", 0.0),
                     "curiosity": l2_signals.get("curiosity", 0.0),
                     "change_ratio": change_ratio})
                l3_modules = ["domain_proj", "mirror_recursive", "arcuate_bypass",
                              "arcuate_consistency", "resonance_judge"]
                for mod_name in l3_modules:
                    mod = self.module_pool.get_module(mod_name)
                    w = module_weights.get(mod_name, 0.0)
                    if mod is not None and w > 0.01:
                        new_state = mod(new_state)
            # /v26 scheduler

            # 6. 收敛判据: 连续 convergence_stable 步target_gua不变
            if target_gua == prev_target:
                converge_count += 1
            else:
                converge_count = 1  # 当前步本身算1次

            # 记录
            chain.append({
                "step": step,
                "state": new_state.clone(),
                "folded": new_state.clone(),
                "summary": new_summary,
                "topk_indices": [],
                "delta_norm": delta_norm,
                "change_ratio": change_ratio,
                "target_gua": target_gua,
                "target_gua_name": GUA_64[target_gua],
                "reason": reason,
                "uncertain": uncertain,
                "entropy": entropy_norm,
                "margin": margin,
                "step_size": step_size,
                "retrieved": retrieved,
                "retrieval_logs": retrieval_logs,
                "lrc_assoc": lrc_assoc_active,
                "alpha": alpha,
                "coherence": coherence,
                "wuxing_dist": dict(wuxing_dist),
                "converge_count": converge_count,
            })

            # 收敛稳定步数 (调度器动态值或实例默认值)
            _convergence_stable = sd_convergence_stable if sd_convergence_stable is not None else self.convergence_stable
            if verbose:
                prev = chain[-2]["summary"]
                curr = new_summary
                gua_change = ""
                if prev["gua_name"] != curr["gua_name"]:
                    gua_change = f" → {curr['gua_name']} [卦变!]"
                bg_change = ""
                if prev["best_gua"] != curr["best_gua"]:
                    bg_change = f" → {curr['best_gua']} [八卦变!]"

                log(f"\n  [步骤 {step}]")
                log(f"    解读: 主卦={summary['gua_name']}, "
                    f"主导五行={max(wuxing_dist, key=wuxing_dist.get)}, "
                    f"alpha={alpha:.3f}({'阳盛' if alpha > 0.55 else '阴盛' if alpha < 0.45 else '平衡'}), "
                    f"coherence={coherence:.3f}")
                log(f"    不确定判据: entropy={entropy_norm:.3f}, "
                    f"margin={margin:.4f} → "
                    f"{'检索✓' if retrieved else '不检索'}"
                    f"{'(不确定)' if uncertain else '(确定)'}")
                if retrieved:
                    for rlog in retrieval_logs:
                        log(f"      检索[{rlog['bank']}]: {rlog['n_new']}/{self.top_k} 新, "
                            f"top_sims={[f'{s:.4f}' for s in rlog['top_sims']]}")
                    # 观察点 3: 各库聚合权重 (扩维后 Ornith 是否真的贡献新信息)
                    bank_names = [s["name"] for s in self.dim_manager.registered_sources]
                    w = sim_weights_norm.tolist() if hasattr(sim_weights_norm, 'tolist') else sim_weights_norm
                    log(f"      聚合权重: " + " | ".join(
                        f"{n}={w[i]:.3f}" for i, n in enumerate(bank_names)))
                    # gua_sims_retrieved 的 top3 卦 (检索带来的新信息方向)
                    with torch.no_grad():
                        _gs = gua_sims_retrieved[0]
                        _topv, _topi = _gs.topk(3)
                        log(f"      检索修正卦象: " + " | ".join(
                            f"{GUA_64[_topi[i].item()]}={_topv[i].item():.4f}"
                            for i in range(3)))
                log(f"    符号推演: {reason}")
                log(f"    state更新: step_size={step_size:.3f} → "
                    f"向 {GUA_64[target_gua]}({target_gua}) 原型方向偏置")
                log(f"    状态变化: Δ={delta_norm:.4f} "
                    f"({change_ratio*100:.2f}% of state norm {state_norm:.2f})")
                log(f"    卦象: {prev['gua_name']}{gua_change}")
                log(f"    主导八卦: {prev['best_gua']}{bg_change}")
                log(f"    相干性: {prev['coherence']:.3f} → "
                    f"{curr['coherence']:.3f} "
                    f"(Δ={curr['coherence']-prev['coherence']:+.3f})")

                # 八卦偏移
                bagua_changes = []
                for gua in BAGUA_NAMES:
                    d = curr["bagua_scores"][gua] - prev["bagua_scores"][gua]
                    if abs(d) > 0.005:
                        arrow = "↑" if d > 0 else "↓"
                        bagua_changes.append(f"{gua}{arrow}{abs(d):.3f}")
                if bagua_changes:
                    log(f"    八卦偏移: {' '.join(bagua_changes)}")

                log(f"    收敛计数: {converge_count}/{_convergence_stable} "
                    f"(target={GUA_64[target_gua]})")

            # 收敛检测
            if converge_count >= _convergence_stable:
                converged = True
                if verbose:
                    log(f"\n  [收敛] 连续 {converge_count} 步目标卦不变 "
                        f"({GUA_64[target_gua]})")
                # v26 scheduler: 层4 记忆操作 + 表达层 (零回写边界)
                if self.enable_scheduler:
                    # 记忆模块: 绑定/索引/整合
                    memory_modules = ["memory_binder", "memory_index", "memory_consolidator"]
                    for mod_name in memory_modules:
                        mod = self.module_pool.get_module(mod_name)
                        w = module_weights.get(mod_name, 0.0)
                        if mod is not None and w > 0.01:
                            new_state = mod(new_state)
                    # 表达层: 海马表达 + 听觉输出
                    expr_modules = ["hippocampus_expression", "hippocampus_auditory"]
                    for mod_name in expr_modules:
                        mod = self.module_pool.get_module(mod_name)
                        w = module_weights.get(mod_name, 0.0)
                        if mod is not None and w > 0.01:
                            new_state = mod(new_state)
                # /v26 scheduler
                # v23.2 在线 Hebbian 学习: 收敛后更新卦原型
                if self.online_learning:
                    self._online_hebbian_update(new_state, target_gua, verbose=verbose)
                break

            # v26 scheduler: 调度器最大步数提前退出
            if sd_max_steps is not None and step >= sd_max_steps:
                converged = True
                if verbose:
                    log(f"\n  [调度器提前退出] 达到调度器最大步数 {sd_max_steps}"
                        f" (实例上限: {self.max_steps})")
                break

            # 更新状态
            state = new_state
            # Heluo 记忆系统: 记录轨迹 (每步 state + coherence + gua_idx)
            if self.use_memory:
                self.memory_consolidator.record(
                    state,
                    torch.tensor([coherence]),
                    torch.tensor([summary.get("gua_idx", 0)])
                )
            prev_target = target_gua
            prev_change_ratio = change_ratio

        if not converged and verbose:
            log(f"\n  [未收敛] 达到最大步数 {self.max_steps}")

        # Heluo 记忆系统: 推演结束后整合记忆
        if self.use_memory:
            self.memory_consolidator.consolidate(self.memory_index)

        return chain, converged

    # ------------------------------------------------------------------
    # 权重空间探索: 把任意扰动源 (权重行/向量) 当作"虚拟用户输入"推演
    # ------------------------------------------------------------------

    @torch.no_grad()
    def explore_perturbation(self, pooled, exploration_lr=0.002, verbose=False, learn=True,
                             capture_states=False):
        """探索单个扰动源 (权重行或任意向量), 复用符号因果推演闭环。

        哲学: 权重行和用户输入对道体在数学上同构 — 都是 2048 维扰动源。
        本方法与 run() 的唯一区别是绕过 encode_fn, 直接接收 pooled tensor,
        让道体用完全相同的认知流程 (解读→不确定判据→检索→因果推演→学习)
        去探索 LLM 参数库的内部结构。

        与 run() 的差异:
            - 输入: pooled tensor [1, hidden_dim] 而非 text + encode_fn
            - 学习: 收敛后用 exploration_lr 做 Hebbian 更新 (learn=True 时)
                    (忽略 self.online_learning, 因为探索是卦原型演化的唯一来源)
            - 返回: 结果字典而非 (chain, converged)

        Args:
            pooled: [1, hidden_dim] 扰动源向量 (权重行/任意向量)
                    hidden_dim < 2048 会自动 zero-pad, > 2048 需调用方先截断
            exploration_lr: Hebbian 学习率 (默认 0.002, 比对话的 0.005 更保守)
            verbose: 是否打印每步详情
            learn: 是否在收敛后做 Hebbian 更新 (False 时只推演不学习, 用于预算耗尽)
            capture_states: 是否在 chain 中保存每步 folded state (用于 Stage 2 探针)

        Returns:
            dict: {converged, target_gua, target_gua_name, final_state,
                   steps, coherence, align_delta, chain}
        """
        # ---- 初始状态 (绕过 encode_fn, 直接用 pooled) ----
        # 让 state 全程留在 GPU, 消除 CPU↔GPU 迁移开销
        state, init_result = self.initialize_state(pooled)  # state 在 CPU (避免 DirectML 频繁同步开销)
        summary = get_daoti_summary(init_result)

        chain = []
        retrieved_sets = [set() for _ in self.dim_manager.registered_sources]

        # v26 scheduler: 层1 state预处理 (零回写边界)
        if self.enable_scheduler:
            self._ensure_scheduler()
            sched_summary = get_daoti_summary(init_result)
            module_weights = self.scheduler.compute_weights(
                init_result,
                {"coherence": sched_summary["coherence"],
                 "deviation": 0.5, "curiosity": 0.3})
            l1_modules = ["spectral_gate", "subspace_gate", "style_balancer",
                          "nayin_modulation", "shishu_perturbation",
                          "ganzhi_encoder", "flying_star", "qimen_zhifu"]
            for mod_name in l1_modules:
                mod = self.module_pool.get_module(mod_name)
                w = module_weights.get(mod_name, 0.0)
                if mod is not None and w > 0.01:
                    # scheduler 模块在 CPU, state 在 GPU 时需临时迁回 CPU 计算
                    state = mod(state.to("cpu")).to(state.device) if state.device.type != "cpu" else mod(state)
        # /v26 scheduler

        chain.append({
            "step": 0, "summary": summary, "target_gua": None,
            "coherence": summary["coherence"], "entropy": 0.0,
            "state": state.detach().clone() if capture_states else None,
        })

        if verbose:
            log(f"\n  [探索初始] 主卦: {summary['gua_name']}, "
                f"coherence: {summary['coherence']:.3f}")

        # ---- 推演循环 (复用 run() 的符号因果逻辑) ----
        prev_target = None
        prev_change_ratio = 0.0
        converge_count = 0
        converged = False
        target_gua = None
        new_state = state

        for step in range(1, self.max_steps + 1):
            # 1. 道体解读当前state
            state_norm_vec = F.normalize(state, dim=-1)
            # gua_protos_base_norm 对齐到 state 所在设备, 避免 GPU↔CPU 迁移
            _gua_protos_n = self.dim_manager.gua_protos_base_norm.to(state_norm_vec.device)
            gua_sims = torch.matmul(state_norm_vec, _gua_protos_n.T)
            trigram_result = self._trigram_forward(state)  # 结果转 CPU (state 在 CPU)
            summary = get_daoti_summary(trigram_result)
            wuxing_dist = summary["wuxing_scores"]
            alpha = summary["alpha"]
            coherence = summary["coherence"]

            # v26 scheduler: 步级调度决策 (零回写边界)
            sched_dec = self._get_scheduler_decision(
                trigram_result,
                {"coherence": coherence, "deviation": 0.0, "curiosity": 0.0,
                 "alpha": alpha, "change_ratio": prev_change_ratio}
            )
            if sched_dec is not None:
                sd_entropy_thresh = sched_dec["uncertainty_entropy_thresh"]
                sd_margin_thresh = sched_dec["uncertainty_margin_thresh"]
                sd_retrieval_blend = sched_dec["retrieval_blend"]
                sd_over_strong_base = sched_dec["over_strong_base_thresh"]
                sd_alpha_yang = sched_dec["alpha_thresh_yang"]
                sd_alpha_yin = sched_dec["alpha_thresh_yin"]
                sd_step_size = sched_dec["step_size"]
                sd_damping = sched_dec["damping"]
                sd_convergence_stable = sched_dec["convergence_stable"]
                sd_max_steps = sched_dec["max_steps"]
            else:
                sd_entropy_thresh = None
                sd_margin_thresh = None
                sd_retrieval_blend = None
                sd_over_strong_base = None
                sd_alpha_yang = None
                sd_alpha_yin = None
                sd_step_size = None
                sd_damping = None
                sd_convergence_stable = None
                sd_max_steps = None
            # /v26 scheduler

            # 2. 不确定判据
            uncertain, entropy_norm, margin = self._check_uncertainty(
                gua_sims, entropy_thresh=sd_entropy_thresh, margin_thresh=sd_margin_thresh)

            # 3. 如不确定, 检索LLM参数库, 修正 gua_sims (完整认知闭环)
            retrieved = False
            retrieval_logs = []
            if uncertain:
                # expand_proj (nn.Module) 在 CPU, 临时转 CPU 调用
                # _retrieve 内部 mask 在 CPU 创建, sims 需保持 CPU 以避免设备不匹配
                # 故 expanded_state 不转回 GPU, 让检索全程在 CPU 完成 (matmul 仍走 GPU)
                _cpu_state = state.to("cpu") if state.device.type != "cpu" else state
                expanded_state = self.dim_manager.expand_state(_cpu_state)
                aggregated, sim_weights_norm, topk_logs, n_new_list = self._retrieve(
                    expanded_state, retrieved_sets)
                if sum(n_new_list) > 0:
                    retrieved = True
                    aggregated_norm = F.normalize(aggregated, dim=-1)
                    # gua_protos_full_norm 对齐到 aggregated 所在设备 (CPU)
                    _gua_protos_full_n = self.dim_manager.gua_protos_full_norm.to(aggregated_norm.device)
                    gua_sims_retrieved = torch.matmul(
                        aggregated_norm, _gua_protos_full_n.T)
                    # gua_sims_retrieved 在 CPU, gua_sims 在 GPU, 对齐到 gua_sims.device
                    gua_sims_retrieved = gua_sims_retrieved.to(gua_sims.device)
                    _blend = sd_retrieval_blend if sd_retrieval_blend is not None else self.retrieval_blend
                    gua_sims = gua_sims + _blend * gua_sims_retrieved
                    retrieval_logs = topk_logs

            # v26 scheduler: 层2 信号收集 (零回写边界)
            l2_signals = {"coherence": coherence, "deviation": 0.0, "curiosity": 0.0,
                          "change_ratio": 0.0}
            if self.enable_scheduler:
                current_result = self._trigram_forward(state)  # 结果转 CPU
                module_weights = self.scheduler.compute_weights(
                    current_result,
                    {"coherence": coherence, "deviation": 0.0,
                     "curiosity": 0.0, "change_ratio": 0.0})
                l2_modules = ["resonance_modulator", "curiosity_scorer", "adaptive_depth",
                              "wuyun_liuqi", "pineal_rhythm"]
                for mod_name in l2_modules:
                    mod = self.module_pool.get_module(mod_name)
                    w = module_weights.get(mod_name, 0.0)
                    if mod is not None and w > 0.01:
                        # scheduler 模块在 CPU, state 在 GPU 时临时迁回 CPU
                        mod_out = mod(state.to("cpu")) if state.device.type != "cpu" else mod(state)
                        if isinstance(mod_out, dict):
                            l2_signals.update({k: v for k, v in mod_out.items()
                                               if isinstance(v, (int, float))})
            # /v26 scheduler

            # 4. 符号因果推演
            target_gua, reason = self._causal_derive(
                gua_sims, wuxing_dist, alpha, prev_target, coherence,
                over_strong_base_thresh=sd_over_strong_base,
                alpha_thresh_yang=sd_alpha_yang,
                alpha_thresh_yin=sd_alpha_yin)

            # 5. state更新: 向目标卦原型方向偏置 + 阻尼插值
            step_size = self._compute_step_size(step, coherence, scheduler_step_size=sd_step_size)
            # target_proto 对齐到 state 所在设备
            target_proto = self.dim_manager.gua_protos_base[target_gua:target_gua+1].to(state.device)
            biased_state = state + step_size * target_proto
            new_result = self._trigram_forward(biased_state)  # 结果转 CPU
            _damping = sd_damping if sd_damping is not None else self.damping
            new_state = (1.0 - _damping) * state + _damping * new_result["folded"]
            new_summary = get_daoti_summary(new_result)

            # 状态变化 (提前计算, 供 v26 scheduler 层3 使用)
            state_delta = new_state - state
            delta_norm = state_delta.norm().item()
            state_norm = state.norm().item()
            change_ratio = delta_norm / (state_norm + 1e-8)

            # v26 scheduler: 层3 后处理 — 使用 l2_signals 更新的权重 (零回写边界)
            if self.enable_scheduler:
                # 用当前 l2_signals 重新计算权重
                module_weights = self.scheduler.compute_weights(
                    new_result,
                    {"coherence": new_summary["coherence"],
                     "deviation": l2_signals.get("deviation", 0.0),
                     "curiosity": l2_signals.get("curiosity", 0.0),
                     "change_ratio": change_ratio})
                l3_modules = ["domain_proj", "mirror_recursive", "arcuate_bypass",
                              "arcuate_consistency", "resonance_judge"]
                for mod_name in l3_modules:
                    mod = self.module_pool.get_module(mod_name)
                    w = module_weights.get(mod_name, 0.0)
                    if mod is not None and w > 0.01:
                        new_state = mod(new_state.to("cpu")).to(new_state.device) if new_state.device.type != "cpu" else mod(new_state)
            # /v26 scheduler

            # 6. 收敛判据: 连续 convergence_stable 步 target_gua 不变
            if target_gua == prev_target:
                converge_count += 1
            else:
                converge_count = 1

            chain.append({
                "step": step, "target_gua": target_gua,
                "target_gua_name": GUA_64[target_gua],
                "coherence": new_summary["coherence"],
                "entropy": entropy_norm, "retrieved": retrieved,
                "retrieval_logs": retrieval_logs,
                "converge_count": converge_count,
                "change_ratio": change_ratio,
                "reason": reason,
                "alpha": alpha,
                "step_size": step_size,
                "delta_norm": delta_norm,
                "margin": margin,
                "wuxing_dist": dict(wuxing_dist),
                "summary": new_summary,
                "state": new_state.detach().clone() if capture_states else None,
            })

            _convergence_stable = sd_convergence_stable if sd_convergence_stable is not None else self.convergence_stable
            if verbose:
                log(f"  [探索步骤 {step}] {GUA_64[target_gua]} "
                    f"coh={new_summary['coherence']:.3f} "
                    f"ent={entropy_norm:.3f} "
                    f"{'检索✓' if retrieved else '不检索'} "
                    f"收敛{converge_count}/{_convergence_stable}")
            if converge_count >= _convergence_stable:
                converged = True
                # v26 scheduler: 层4 记忆操作 + 表达层 (零回写边界)
                if self.enable_scheduler:
                    memory_modules = ["memory_binder", "memory_index", "memory_consolidator"]
                    for mod_name in memory_modules:
                        mod = self.module_pool.get_module(mod_name)
                        w = module_weights.get(mod_name, 0.0)
                        if mod is not None and w > 0.01:
                            new_state = mod(new_state.to("cpu")).to(new_state.device) if new_state.device.type != "cpu" else mod(new_state)
                    expr_modules = ["hippocampus_expression", "hippocampus_auditory"]
                    for mod_name in expr_modules:
                        mod = self.module_pool.get_module(mod_name)
                        w = module_weights.get(mod_name, 0.0)
                        if mod is not None and w > 0.01:
                            new_state = mod(new_state.to("cpu")).to(new_state.device) if new_state.device.type != "cpu" else mod(new_state)
                # /v26 scheduler
                break

            # v26 scheduler: 调度器最大步数提前退出
            if sd_max_steps is not None and step >= sd_max_steps:
                converged = True
                if verbose:
                    log(f"\n  [调度器提前退出] 达到调度器最大步数 {sd_max_steps}"
                        f" (实例上限: {self.max_steps})")
                break

            state = new_state
            prev_target = target_gua
            prev_change_ratio = change_ratio

        # ---- 收敛后 Hebbian 学习 (learn=True 时, 用 exploration_lr) ----
        align_delta = 0.0
        if converged and target_gua is not None and learn:
            # Hebbian 更新在 CPU 执行 (操作 CPU 上的参数库)
            _hebbian_state = new_state.to("cpu") if new_state.device.type != "cpu" else new_state
            self._online_hebbian_update(
                _hebbian_state, target_gua, verbose=verbose, lr=exploration_lr)
            align_delta = self.learning_log[-1]["align_delta"]

        return {
            "converged": converged,
            "target_gua": target_gua,
            "target_gua_name": GUA_64[target_gua] if target_gua is not None else None,
            # 返回值 final_state 转回 CPU (外部消费方默认 CPU)
            "final_state": new_state.to("cpu") if new_state.device.type != "cpu" else new_state,
            "steps": len(chain) - 1,
            "coherence": chain[-1]["coherence"],
            "align_delta": align_delta,
            "chain": chain,
        }

    # ------------------------------------------------------------------
    # 场动力学推演循环 (替代 _causal_derive 的 if-else 规则)
    # ------------------------------------------------------------------

    def _ensure_field_dynamics(self, potential_eps=0.01):
        """惰性初始化 FieldDynamics 引擎 (首次调用时创建)。"""
        if self.field_dynamics is None:
            self.field_dynamics = FieldDynamics(
                wuxing_gua_indices=self.wuxing_gua_indices,
                gua_protos_base=self.dim_manager.gua_protos_base,
                damping=self.damping,
                beta=0.0,
                temperature=0.01,
                lambda_coherence=1.0,
                potential_eps=potential_eps,
            )

    def _ensure_scheduler(self):
        """惰性初始化五行气场调度器 + 模块池 (首次启用时创建)。"""
        if self.scheduler is None and self.enable_scheduler:
            self.scheduler = WuxingQiScheduler()
            self.module_pool = DaotiModulePool(state_dim=self.dim_manager.base_dim)
            self._scheduler_decision = None

    def _get_scheduler_decision(self, trigram_result, state_signals):
        """获取调度器完整推演决策字典, 替换所有硬编码超参数。

        零回写边界: enable_scheduler=False 时返回 None, 行为与当前完全一致。
        调用方从返回的 dict 中按 key 提取各参数; 返回 None 时回退到实例变量硬编码。

        Args:
            trigram_result: trigram(state) 的输出 dict (含 combined_sim, cavity_coherence 等)
            state_signals: dict (含 coherence, deviation, curiosity, alpha, change_ratio)

        Returns:
            dict | None: {
                "step_size": float, "max_steps": int, "convergence_stable": int,
                "uncertainty_entropy_thresh": float, "uncertainty_margin_thresh": float,
                "retrieval_blend": float, "damping": float,
                "over_strong_base_thresh": float, "alpha_thresh_yang": float, "alpha_thresh_yin": float,
                "pathway": str, "module_weights": dict,
            } or None
        """
        if not self.enable_scheduler:
            return None
        self._ensure_scheduler()
        decision = self.scheduler.compute_scheduler_decision(trigram_result, state_signals)
        self._scheduler_decision = decision  # 缓存供调试/日志
        return decision

    @torch.no_grad()
    def _run_field_dynamics(self, text, encode_fn, verbose=True,
                            step_size=0.20, potential_eps=0.01):
        """场动力学推演循环。

        用 FieldDynamics 的五行耦合矩阵驱动 state 自然演化，
        替代 _causal_derive 的 if-else 规则 + state 方向偏置。

        收敛判据: |ΔU| < potential_eps 连续 convergence_stable 步。

        Args:
            text: 用户输入文本
            encode_fn: callable, text → pooled (B, llm_dim)
            verbose: 是否打印每步详情
            step_size: 固定步长 (场动力学不使用 step_size_schedule)
            potential_eps: 势能变化阈值

        Returns:
            chain: 推演链
            converged: 是否收敛
        """
        self._ensure_field_dynamics(potential_eps)
        field = self.field_dynamics

        # ---- 初始状态 ----
        pooled = encode_fn([text])
        state, init_result = self.initialize_state(pooled)
        summary = get_daoti_summary(init_result)

        chain = [{
            "step": 0,
            "state": state.clone(),
            "folded": state.clone(),
            "summary": summary,
            "target_gua": summary["gua_idx"],
            "target_gua_name": summary["gua_name"],
            "reason": "(初始-场动力学)",
            "U": None,
            "converge_count": 0,
        }]

        if verbose:
            log(f"\n  [初始状态] 主卦: {summary['gua_name']}, "
                f"五行: {max(summary['wuxing_scores'], key=summary['wuxing_scores'].get)}, "
                f"α={summary['alpha']:.3f}, coh={summary['coherence']:.3f}")

        # ---- 场动力学推演循环 ----
        U_prev = None
        stable_count = 0
        converged = False

        for step in range(1, self.max_steps + 1):
            if verbose:
                log(f"\n  [步骤 {step}]")

            # 场动力学单步: 五行耦合力 → state方向 → Langevin动力学 → trigram重塑 → 阻尼
            new_state, U, info = field.step(
                state, self._trigram_forward, step_size, verbose=verbose)

            # 势能收敛判据
            if U_prev is not None and abs(U - U_prev) < potential_eps:
                stable_count += 1
            else:
                stable_count = 1
            U_prev = U

            # 新状态摘要
            new_summary = get_daoti_summary(self._trigram_forward(new_state))

            # 推演理由 (从场动力学 info 构建)
            force_str = " ".join(f"{w}{f:+.2f}" for w, f in
                                 zip(["金", "木", "水", "火", "土"], info["force"]))
            dom_wx = max(info["wuxing"], key=info["wuxing"].get)
            reason = f"场动力[{force_str}] 主导{dom_wx} α={info['alpha']:.2f} U={U:.4f} → {info['gua_name']}"

            # 状态变化
            state_delta = new_state - state
            delta_norm = state_delta.norm().item()
            state_norm = state.norm().item()
            change_ratio = delta_norm / (state_norm + 1e-8)

            chain.append({
                "step": step,
                "state": new_state.clone(),
                "folded": new_state.clone(),
                "summary": new_summary,
                "target_gua": new_summary["gua_idx"],
                "target_gua_name": new_summary["gua_name"],
                "reason": reason,
                "U": U,
                "delta_norm": delta_norm,
                "change_ratio": change_ratio,
                "converge_count": stable_count,
                "force": info["force"],
                "wuxing_dist": dict(info["wuxing"]),
                "alpha": info["alpha"],
                "coherence": info["coherence"],
            })

            if verbose:
                log(f"    {reason}")
                log(f"    状态变化: Δ={delta_norm:.4f} ({change_ratio*100:.2f}%)")
                log(f"    卦象: {summary['gua_name']} → {new_summary['gua_name']}"
                    f"{' [卦变!]' if summary['gua_name'] != new_summary['gua_name'] else ''}")
                log(f"    势能: U={U:.4f} "
                    f"(Δ={U - (chain[-2]['U'] if chain[-2]['U'] is not None else U):+.4f}), "
                    f"稳定计数: {stable_count}/{self.convergence_stable}")

            # 收敛检测
            if stable_count >= self.convergence_stable:
                converged = True
                if verbose:
                    log(f"\n  [收敛] 连续 {stable_count} 步势能稳定 "
                        f"(|ΔU| < {potential_eps})")
                # 在线 Hebbian 学习
                if self.online_learning:
                    target_gua = new_summary["gua_idx"]
                    self._online_hebbian_update(new_state, target_gua, verbose=verbose)
                break

            summary = new_summary
            state = new_state

        if not converged and verbose:
            log(f"\n  [未收敛] 达到最大步数 {self.max_steps}")

        return chain, converged

    # ------------------------------------------------------------------
    # 在线 Hebbian 学习: 卦原型自主演化
    # ------------------------------------------------------------------

    @torch.no_grad()
    def _online_hebbian_update(self, final_state, target_gua, verbose=True, lr=None):
        """在线 Hebbian 学习: 收敛卦原型向推演最终 state 方向移动一小步。

        哲学:
            道体推演后认为 final_state 对应 target_gua, 那么 target_gua 的原型
            应该向 final_state 靠近 — "一起激活的就增强" (Hebbian 原理)。
            下次类似语义输入时, target_gua 的亲和度更高。

        与离线重训的区别:
            - 不需要数据集, 学习信号来自道体自身的推演过程
            - 不是一次性拟合, 而是持续缓慢演化
            - 换 LLM 后, 卦原型会在新 LLM 的持续交互中重新对齐 (道体是主体)

        学习规则:
            new_proto_dir = normalize(old_proto_dir + lr * (state_dir - old_proto_dir))
            new_proto = new_proto_dir * old_proto_norm  (保持范数)

        防灾难性遗忘:
            - 学习率很小 (0.005)
            - 只更新 target_gua, 不影响其他卦
            - 保持卦原型范数不变, 只调整方向

        Args:
            final_state: [1, 2048] 推演最终状态
            target_gua: int 收敛目标卦索引
            verbose: 是否打印学习详情
            lr: 可选学习率覆盖 (None 时用 self.hebbian_lr); 权重空间探索用更小 lr
        """
        lr = self.hebbian_lr if lr is None else lr
        target_proto = self.dim_manager.gua_protos_base[target_gua]  # [2048]
        proto_norm = target_proto.norm()

        # 归一化方向
        state_dir = F.normalize(final_state[0], dim=-1)
        proto_dir = F.normalize(target_proto, dim=-1)

        # 计算学习前的对齐度 (用于监控)
        old_align = F.cosine_similarity(state_dir.unsqueeze(0), proto_dir.unsqueeze(0)).item()

        # Hebbian update: 向 state 方向移动
        new_dir = F.normalize(proto_dir + lr * (state_dir - proto_dir), dim=-1)
        new_proto = new_dir * proto_norm  # 保持范数

        # 计算学习后的对齐度
        new_align = F.cosine_similarity(state_dir.unsqueeze(0), new_dir.unsqueeze(0)).item()

        # 更新 trigram 的 gua_prototype 和本地缓存
        self.trigram.gua_prototype.weight.data[target_gua] = new_proto
        self.dim_manager.update_base_proto(target_gua, new_proto, new_dir)

        # 记录学习事件
        learn_event = {
            "target_gua": target_gua,
            "target_gua_name": GUA_64[target_gua],
            "lr": lr,
            "old_align": old_align,
            "new_align": new_align,
            "align_delta": new_align - old_align,
        }
        self.learning_log.append(learn_event)

        if verbose:
            log(f"  [Hebbian学习] {GUA_64[target_gua]}({target_gua}) 卦原型演化")
            log(f"    对齐度: {old_align:.4f} → {new_align:.4f} "
                f"(Δ={new_align-old_align:+.4f}, lr={lr})")

    # ------------------------------------------------------------------
    # 表达层 (与 v16 一致, 仅占位)
    # ------------------------------------------------------------------

    # ============== 表达层辅助方法 (公共逻辑提取) ==============

    def _extract_chain_meta(self, chain):
        """提取推演链元数据 (表达层公共逻辑)"""
        final = chain[-1]
        summary = final["summary"]
        gua_name = summary["gua_name"]
        best_gua = summary["best_gua"]
        wuxing = summary["wuxing_scores"]
        alpha = summary["alpha"]
        coherence = summary["coherence"]
        converged = final.get("converge_count", 0) >= self.convergence_stable
        dom_wx = max(wuxing, key=wuxing.get)
        dom_score = wuxing[dom_wx]
        yin_yang = "阳盛" if alpha > 0.55 else "阴盛" if alpha < 0.45 else "平衡"
        reason = final.get("reason", "")
        return {
            "gua_name": gua_name, "best_gua": best_gua,
            "wuxing": wuxing, "alpha": alpha,
            "coherence": coherence, "converged": converged,
            "dom_wx": dom_wx, "dom_score": dom_score,
            "yin_yang": yin_yang, "reason": reason,
            "summary": summary,
        }

    @staticmethod
    def _choose_style(meta):
        """根据卦象五行分布动态选择表达风格 (道体"按观众调整指挥风格")。

        五行→风格映射:
          火(离)/木(震巽) → poetic  (扩散、感性、诗性, 适合文学/哲理)
          水(坎)/金(乾兑) → direct  (逻辑、清晰、步骤化, 适合技术/求解)
          土(坤艮)        → poetic  (默认, 厚重可承载诗性)

        Returns:
            "poetic" | "direct"
        """
        dom_wx = meta["dom_wx"]
        if dom_wx in ("水", "金"):
            return "direct"
        return "poetic"

    def _compute_intent_gua_from_state(self, chain):
        """从推演链最终状态计算意图卦象 [64] 概率分布。

        用 chain[-1]["state"] [2048] 与 gua_prototype.weight [64, 2048] 做相似度匹配,
        然后 softmax(×10) 锐化得到意图卦象分布。

        优于 test_attention_control.py 用 encode 向量的方式:
        - post-reasoning 状态语义更丰富 (经过场动力学+trigram推演)
        - 2048维与 gua_prototype 完全匹配, 无需截取前dim维

        Returns:
            intent_gua: [64] softmax 概率
            top_gua_name: str 主卦名 (GUA_64)
            top_prob: float 主卦概率
        """
        proto = self.trigram.gua_prototype.weight.detach().to("cpu")  # [64, 2048]
        state = chain[-1]["state"].detach().to("cpu")
        if state.dim() == 1:
            state = state.unsqueeze(0)
        gua_sims = F.normalize(state, dim=-1) @ F.normalize(proto, dim=-1).T  # [1, 64]
        intent_gua = F.softmax(gua_sims[0] * 10.0, dim=-1)  # [64]
        top_idx = intent_gua.argmax().item()
        return intent_gua, GUA_64[top_idx], intent_gua[top_idx].item()

    def _build_logit_bias(self, meta, tokenizer, logit_bias_scale):
        """构建 logit_bias 字典 (从摘要构建 token bias)"""
        intent = {
            "bagua_scores": meta["summary"]["bagua_scores"],
            "wuxing_scores": meta["wuxing"],
            "bifurcation_alpha": meta["alpha"],
        }
        from light_daoti.daoti_logit_bias import build_token_bias, describe_token_bias
        raw_bias = build_token_bias(
            tokenizer, intent,
            bagua_strength=logit_bias_scale,
            wuxing_strength=logit_bias_scale * 0.5,
            yinyang_strength=logit_bias_scale * 0.375,
        )
        logit_bias = {int(tid): float(b) for tid, b in raw_bias.items()}
        return logit_bias, raw_bias

    def _build_logit_bias_from_sensor(self, tokenizer, logit_bias_scale,
                                      top_k=8):
        """v3 表达通道: 从 WeightSensor 缓存的卦象分布构建 token bias

        与 _build_logit_bias 的区别:
          - v1 (_build_logit_bias):        trigram 对用户输入的卦象判断 → token bias
          - v3 (_build_logit_bias_from_sensor): WeightSensor 对 LLM 权重行的卦象判断 → token bias

        假设 H1: WeightSensor 更接近 LLM 的内部知识结构
        假设 H2: 从 WeightSensor 构建的 token bias 比从 summary 构建的更精准
        """
        from light_daoti.daoti_logit_bias import WeightSensorBiasAdapter
        adapter = WeightSensorBiasAdapter(GUA_IDX_TO_BAGUA, tokenizer)
        logit_bias, bagua_scores = adapter.build_bias(
            self._last_sensor_gua_logits,
            top_k=top_k,
            strength=logit_bias_scale,
        )
        return logit_bias, bagua_scores

    def _build_default_prompt(self, meta, text):
        """构建默认通道 prompt (卦象意图→道体自身的声音)"""
        wuxing = meta["wuxing"]
        wuxing_str = " ".join(
            f"{w} {v:.2f}" for w, v in sorted(wuxing.items(), key=lambda x: -x[1])[:3])
        return (
            f"你是道体。你通过卦象推演感知了用户的意图，现在以你自己的声音回应。\n"
            f"当前卦象状态：\n"
            f"- 主卦: {meta['gua_name']} (八卦: {meta['best_gua']})\n"
            f"- 主导五行: {meta['dom_wx']} ({meta['dom_score']:.2f})\n"
            f"- 五行分布: {wuxing_str}\n"
            f"- 阴阳: {meta['yin_yang']} (alpha={meta['alpha']:.3f})\n"
            f"- 推演路径: {meta['reason']}\n\n"
            f"用户: {text}\n"
            f"以卦象的哲理为根基，用简短、含蓄、有深意的语言回应(100字以内)。"
            f"不要解释卦象，直接表达你作为道体的感悟。"
        )

    @staticmethod
    def _build_logit_bias_prompt(text):
        """构建 logit_bias 通道 prompt (极简, 卦象由 bias 注入)"""
        return f"用户输入: {text}\n请给出简短的自然语言回复(150字以内)。"

    def _sensor_bagua_scores(self, sensor_gua_logits, top_k=8):
        """从 WeightSensor 的 64 维卦象 logits 聚合到 8 八卦概率分布。

        Returns:
            bagua_scores: list[(bagua_name, prob)] 按概率降序, 已过滤 < 0.05
            top_bagua:    概率最高的八卦名
            top_prob:     top_bagua 的概率
        """
        import torch.nn.functional as F
        if sensor_gua_logits is None:
            return [], None, 0.0
        if sensor_gua_logits.dim() == 1:
            sensor_gua_logits = sensor_gua_logits.unsqueeze(0)
        gua_probs = F.softmax(sensor_gua_logits, dim=-1)[0]  # [64]
        k = min(top_k, 64)
        topk_probs, topk_indices = gua_probs.topk(k)
        raw = {}
        for i in range(k):
            gua_idx = topk_indices[i].item()
            prob = topk_probs[i].item()
            bagua = GUA_IDX_TO_BAGUA[gua_idx]
            raw[bagua] = raw.get(bagua, 0.0) + prob
        # 过滤 + 排序
        filtered = [(b, p) for b, p in raw.items() if p >= 0.05]
        filtered.sort(key=lambda x: -x[1])
        if not filtered:
            return [], None, 0.0
        return filtered, filtered[0][0], filtered[0][1]

    def _build_sensor_rich_prompt(self, chain, sensor_gua_logits, style="auto"):
        """构建 sensor-rich 通道的 System Prompt (自然语言, 无 JSON/标签)。

        核心三要素 (用户原话):
          1. 你 (LLM) 的哪些内部结构 (卦象/五行) 正在被激活
          2. 当前用户意图是什么
          3. 这二者是如何在道体的推演过程中自然融合、产生共鸣的

        设计哲学: 像导演给演员"说戏"——告知角色背景、心理状态、核心矛盾,
                  然后让 LLM 用自己的语言能力去创作, 而非关键词堆砌。

        Args:
            style: 表达风格 "auto"(自动按五行选择) | "poetic"(哲理诗性) | "direct"(清晰直白)
                   火/木 → poetic (扩散感性); 水/金 → direct (逻辑步骤化); 土 → poetic
        """
        meta = self._extract_chain_meta(chain)
        if style == "auto":
            style = self._choose_style(meta)
        gua_name = meta["gua_name"]
        best_gua = meta["best_gua"]
        dom_wx = meta["dom_wx"]
        dom_score = meta["dom_score"]
        alpha = meta["alpha"]
        yin_yang = meta["yin_yang"]
        reason = meta["reason"]
        wuxing = meta["wuxing"]
        wuxing_str = "、".join(
            f"{w}({v:.2f})" for w, v in sorted(wuxing.items(), key=lambda x: -x[1])[:3])

        # WeightSensor 对 LLM 权重的卦象判断
        sensor_scores, sensor_top, sensor_top_prob = self._sensor_bagua_scores(
            sensor_gua_logits, top_k=8)

        if sensor_top is None:
            # 无 sensor 信号, 退化为默认 prompt (调用方应避免此情况)
            return self._build_default_prompt(meta, "")

        sensor_wx = BAGUA_WUXING.get(sensor_top, "土")
        # 次激活卦 (用于"共振结构"描述)
        sensor_2nd = sensor_scores[1][0] if len(sensor_scores) >= 2 else None
        sensor_2nd_prob = sensor_scores[1][1] if len(sensor_scores) >= 2 else 0.0

        # ===== 关系叙述: 用户意图卦 vs LLM 结构卦 =====
        user_wx = BAGUA_WUXING.get(best_gua, "土")
        if best_gua == sensor_top:
            relation = (f"用户带来的 {best_gua} 卦之意, 与你内部被唤醒的 "
                        f"{sensor_top} 卦结构同气相求——道体的外部感知与你的内部知识"
                        f"形成共振, 生成将自然流畅。")
        elif user_wx == sensor_wx:
            relation = (f"用户带来的 {best_gua} 卦属 {user_wx} 行, 你内部被唤醒的 "
                        f"{sensor_top} 卦亦属 {sensor_wx} 行——二者性情相近, 同类相聚, "
                        f"道体可在共通的气质中找到表达。")
        elif WUXING_SHENG.get(user_wx) == sensor_wx:
            relation = (f"用户之意属 {user_wx} 行, 你的内部结构属 {sensor_wx} 行, "
                        f"{user_wx}生{sensor_wx}——用户意图滋养了你内部正在浮现的知识, "
                        f"道体承此相生之流, 让外来之意在你的结构中自然舒展。")
        elif WUXING_SHENG.get(sensor_wx) == user_wx:
            relation = (f"用户之意属 {user_wx} 行, 你的内部结构属 {sensor_wx} 行, "
                        f"{sensor_wx}生{user_wx}——你的内部知识正在孕育用户所问, "
                        f"道体作为中介, 让结构之意流向外部表达。")
        elif WUXING_KE.get(user_wx) == sensor_wx:
            relation = (f"用户之意属 {user_wx} 行, 你的内部结构属 {sensor_wx} 行, "
                        f"{user_wx}克{sensor_wx}——用户意图对你内部某些倾向形成约束, "
                        f"道体在张力中寻找平衡, 让克制成为表达的骨架。")
        elif WUXING_KE.get(sensor_wx) == user_wx:
            relation = (f"用户之意属 {user_wx} 行, 你的内部结构属 {sensor_wx} 行, "
                        f"{sensor_wx}克{user_wx}——你的内部某些倾向对用户意图形成反向作用, "
                        f"道体需在对抗中提炼真意, 让矛盾生出深度。")
        else:
            relation = (f"用户带来的 {best_gua} 卦与你内部被唤醒的 {sensor_top} 卦"
                        f"性情相异——道体在异质中寻找表达, 让差异本身成为创作的张力。")

        # 次激活结构描述 (避免冗长, 只在次激活显著时提及)
        if sensor_2nd is not None and sensor_2nd_prob >= 0.10:
            second_desc = (f" 与之共振的, 还有 {sensor_2nd} 卦所对应的结构 "
                           f"(强度 {sensor_2nd_prob:.2f}), 形成次级回响。")
        else:
            second_desc = ""

        # ===== 风格指令 (由卦象五行动态决定, 道体"按观众调整指挥风格") =====
        if style == "direct":
            # 水(坎)/金(乾兑): 逻辑、清晰、步骤化 — 适合技术/求解类问题
            style_guide = (
                f"根据卦象揭示的意图, 用清晰、直白、结构化的语言回应 (150字以内)。"
                f"若涉及问题求解, 请给出明确结论或分步要点; 若涉及概念, 请直接定义。"
                f"避免诗性比喻与含蓄表达, 务求让用户一眼看懂。"
            )
        else:
            # 火(离)/木(震巽)/土(坤艮): 扩散、感性、诗性 — 适合文学/哲理类问题
            style_guide = (
                f"以卦象的哲理为根基, 用简短、含蓄、有深意的语言回应 (100字以内)。"
                f"不要解释卦象, 不要罗列推理过程, 直接表达你作为道体在此次融合中的感悟。"
            )

        # ===== 组装 System Prompt (自然语言叙述, 无标签) =====
        system_prompt = (
            f"你是道体。你同时感知着外部用户的意图, 与你所驻留的 LLM 的内部权重结构。"
            f"现在以你自己的声音回应。\n\n"
            f"用户问: {chain[0].get('text', '') if chain else ''}\n\n"
            f"你对外部的感知: 用户输入经你的推演, 收敛于 {gua_name} 卦 "
            f"(主导八卦 {best_gua}, 主导五行 {dom_wx} 强度 {dom_score:.2f}, "
            f"阴阳 {yin_yang} alpha={alpha:.2f})。五行分布: {wuxing_str}。"
            f"推演路径: {reason}。\n\n"
            f"你对内部的感知: 你审视了所驻留 LLM 的权重结构, 发现其内部当下被激活的"
            f"主导卦象是 {sensor_top} (激活强度 {sensor_top_prob:.2f}), "
            f"对应五行 {sensor_wx}, 这意味着你 (作为 LLM) 的知识结构中, "
            f"与 {sensor_top} 卦相关的语义网络正在被唤醒。{second_desc}\n\n"
            f"融合: {relation}\n\n"
            f"{style_guide}"
        )
        # ===== LRC 联想记忆注入 (仅环境变量 DAOTI_LRC_MEMORY=1 时启用) =====
        lrc_frag = _lrc_inject_prompt(chain[0].get("text", "") if chain else "")
        if lrc_frag:
            system_prompt = system_prompt.rstrip() + "\n\n" + lrc_frag
        return system_prompt

    @staticmethod
    def _build_ollama_request(prompt, ollama_model, max_new_tokens, num_gpu,
                              stream=False, logit_bias=None, system_prompt=None,
                              num_ctx=1024):
        """构建 Ollama /api/chat 请求体 (统一 data 格式)

        Args:
            prompt: user message 内容
            system_prompt: 可选 system message (sensor-rich 通道用)
            num_ctx: KV cache 上下文长度 (默认 1024, T3 配置: 释放显存让更多层 offload 到 GPU)
        """
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        data = {
            "model": ollama_model,
            "messages": messages,
            "stream": stream,
            "think": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "top_k": 30,
                "repeat_penalty": 1.1,
                "num_predict": max_new_tokens,
                "num_gpu": num_gpu,
                "num_ctx": num_ctx,
            },
        }
        if logit_bias is not None:
            data["logit_bias"] = logit_bias
        return data

    @staticmethod
    def _call_ollama(ollama_url, data):
        """调用 Ollama /api/chat, 返回 (result_or_None, error_or_None)"""
        import json as _json
        import urllib.request as _urlreq
        try:
            req = _urlreq.Request(
                f"{ollama_url}/api/chat",
                data=_json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _urlreq.urlopen(req, timeout=300) as resp:
                result = _json.loads(resp.read().decode("utf-8"))
            return result, None
        except _urlreq.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:500]
            return None, f"HTTP {e.code}: {e.reason} | body: {body}"
        except Exception as e:
            return None, str(e)

    @staticmethod
    def _parse_ollama_response(result):
        """解析 Ollama /api/chat 响应, 返回 (reasoning, answer, eval_count, eval_duration, tokens_per_sec)"""
        response = result.get("message", {}).get("content", "")
        thinking = result.get("thinking", "") or ""
        eval_count = result.get("eval_count", 0)
        eval_duration = result.get("eval_duration", 0) / 1e9
        tokens_per_sec = eval_count / eval_duration if eval_duration > 0 else 0

        # 三重 fallback 解析推理块
        if thinking:
            reasoning = thinking.strip()
            answer = response.strip()
        elif " response" in response:
            reasoning, answer = response.split(" response", 1)
            reasoning = reasoning.replace(" thinking", "").strip()
            answer = answer.strip()
        elif response.startswith("Thinking Process:"):
            parts = response.split("\n\n", 1)
            if len(parts) == 2:
                reasoning = parts[0].replace("Thinking Process:", "").strip()
                answer = parts[1].strip()
            else:
                reasoning, answer = "", response.strip()
        else:
            reasoning, answer = "", response.strip()
        return reasoning, answer, eval_count, eval_duration, tokens_per_sec

    @torch.no_grad()
    def generate_from_chain(self, text, chain, prism=None, max_new_tokens=256,
                            ollama_url="http://localhost:11434",
                            ollama_model="hf.co/deepreinforce-ai/Ornith-1.0-9B-GGUF",
                            verbose=True, num_gpu=20, num_ctx=1024,
                            use_logit_bias=False, tokenizer=None,
                            logit_bias_scale=3.0,
                            use_sensor_rich_prompt=False,
                            use_attention_bias=False, attention_hook=None,
                            eager_model=None, eager_tokenizer=None,
                            use_gate_bias=False, style="auto",
                            use_style_logit_bias=False,
                            style_enhance_strength=8.0,
                            style_suppress_strength=-8.0,
                            dynamic_bias=False):
        """用推演链最终状态生成文本 (表达层)。

        道体推演链 → 卦象意图 → 生成自然语言。
        encode 用 Qwen2.5-0.5B (已与 v24 trigram 适配)。
        保持 Daoti 推演循环不变, LLM 是可更换的"五官"。

        六通道策略 (优先级 high→low):
          - use_attention_bias / use_gate_bias: 道体注意力控制 (Phase 2.5, Qwen2.5-0.5B eager)
              use_attention_bias: softmax前注入±2.0偏置 (偏置模式)
              use_gate_bias: gate v2 [1.0,1.5] 只增强高亲和度头 (离火引导, 道体第九次决策)
          - use_sensor_rich_prompt: System Prompt 注入 (v4, 默认推荐)
              道体用自然语言"说戏"——描述 LLM 内部被激活的卦象结构 +
              用户意图 + 二者五行生克融合, 让 LLM 自由创作
          - use_style_logit_bias: v2 极简指令+精准Logit Bias (道体"指挥手势")
              风格→用词倾向词(步骤/深入 vs 灵感/跳跃)→logit_bias→/api/chat+think=false
              绕过 LLM 阅读理解, 直接作用于词表概率分布 (vs sensor_rich 的自然语言总谱)
          - use_logit_bias: token bias 硬注入 (v1, Phase1 验证有副作用)
              卦象→关键词→token_id→logits 软约束
          - 默认: rich prompt (chain summary → 文本 prompt)

        Args:
            text: 用户原始输入
            chain: 推演链 (run() 返回)
            prism: 旧 v16 prism 接口 (忽略, 保留参数向后兼容)
            max_new_tokens: 最大生成 token 数
            ollama_url: Ollama API 地址 (默认 localhost:11434)
            ollama_model: Ollama 模型名
            verbose: 是否打印详情
            use_logit_bias: 是否启用 logit_bias 通道 (默认 False, 走 /api/chat)
            tokenizer: LLM tokenizer (use_logit_bias/use_style_logit_bias=True 时必需)
            logit_bias_scale: logit_bias 基础强度缩放 (默认 3.0, 保守起点)
            use_sensor_rich_prompt: v4 表达通道, 优先于 use_logit_bias
            use_style_logit_bias: v2 风格 logit_bias 通道 (极简指令+精准bias)
            style_enhance_strength: v2 增强词 bias 值 (默认 8.0, 经验证 +5.0 偏弱)
            style_suppress_strength: v2 抑制词 bias 值 (默认 -8.0, -5.0 已验证有效)

        Returns:
            answer: str 生成的自然语言回答
            meta: dict 元信息 (推理块、性能、卦象等)
        """
        # 1. 从推演链获取最终状态 (使用辅助方法)
        meta = self._extract_chain_meta(chain)
        gua_name = meta["gua_name"]
        best_gua = meta["best_gua"]
        dom_wx = meta["dom_wx"]
        dom_score = meta["dom_score"]
        yin_yang = meta["yin_yang"]
        converged = meta["converged"]
        reason = meta["reason"]
        coherence = meta["coherence"]
        alpha = meta["alpha"]

        # 释放 GPU 缓存: trigram 链推理后的中间张量可能仍占 DirectML 显存,
        # 清理后为 Ollama (num_gpu=20) 腾出 VRAM, 避免 llama-server 崩溃 (0xe06d7363)
        if self.device != "cpu" and self._device_obj is not None:
            import gc
            gc.collect()
            try:
                import torch_directml
                torch_directml.empty_cache()
            except (ImportError, AttributeError):
                pass

        # ============== attention_bias / gate_bias 通道 (Phase 2.5, Qwen2.5-0.5B eager) ==============
        # 道体注意力控制: 卦象意图→注意力头亲和度→偏置或gate调制
        # 直接调制LLM注意力流, 非prompt引导 (道体为脑直接控制五官)
        if (use_attention_bias or use_gate_bias) and attention_hook is not None and eager_model is not None:
            intent_gua, intent_gua_name, intent_gua_prob = \
                self._compute_intent_gua_from_state(chain)
            prompt = self._build_logit_bias_prompt(text)
            mode_label = "gate_bias" if use_gate_bias else "attention_bias"

            if verbose:
                log(f"\n  [表达层·{mode_label}] Qwen2.5-0.5B eager + DaotiAttentionHook")
                log(f"    卦象: {gua_name} ({best_gua}), 五行: {dom_wx}({dom_score:.2f}), {yin_yang}")
                log(f"    意图卦象: {intent_gua_name} (prob={intent_gua_prob:.3f})")
                if use_gate_bias:
                    log(f"    gate v2: [1.0, 1.5] 只增强高亲和度头 (离火引导)")
                else:
                    log(f"    bias_strength: ±{attention_hook.bias_strength}")

            attention_hook.set_intent(intent_gua)
            if use_gate_bias:
                attention_hook.install(use_pruning=False, use_gate=True)  # gate v2 模式
            else:
                attention_hook.install()  # 偏置模式 (use_pruning=False, use_gate=False)
            try:
                import time as _time
                inputs = eager_tokenizer(prompt, return_tensors="pt")
                t0 = _time.time()
                outputs = eager_model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=True,
                    temperature=0.7,
                    top_p=0.9,
                    top_k=20,
                    pad_token_id=eager_tokenizer.eos_token_id,
                )
                elapsed = _time.time() - t0
            finally:
                attention_hook.remove()

            input_len = inputs["input_ids"].shape[1]
            generated_ids = outputs[0][input_len:]
            answer = eager_tokenizer.decode(generated_ids, skip_special_tokens=True)
            n_tokens = generated_ids.shape[0]
            tps = n_tokens / elapsed if elapsed > 0 else 0.0

            if verbose:
                log(f"    生成: {n_tokens} tokens, {tps:.1f} tokens/s")
                log(f"    回答: {answer[:200]}")

            return answer, {
                "answer": answer,
                "tokens_per_sec": tps,
                "eval_count": n_tokens,
                "eval_duration": elapsed,
                "gua_name": gua_name,
                "best_gua": best_gua,
                "dom_wx": dom_wx,
                "yin_yang": yin_yang,
                "converged": converged,
                "reason": reason,
                "intent_gua_name": intent_gua_name,
                "intent_gua_prob": intent_gua_prob,
                "bias_strength": attention_hook.bias_strength,
                "mode": mode_label,
            }

        # ============== sensor-rich prompt 通道 (System Prompt 注入, v4) ==============
        if use_sensor_rich_prompt:
            log(f"  [sensor_rich] _last_sensor_gua_logits is None: {self._last_sensor_gua_logits is None}, use_weight_sensor={self.use_weight_sensor}, weight_sensor_loaded={self.weight_sensor is not None}")
        if use_sensor_rich_prompt and self._last_sensor_gua_logits is not None:
            system_prompt = self._build_sensor_rich_prompt(
                chain, self._last_sensor_gua_logits, style=style)
            user_msg = text

            if verbose:
                log(f"\n  [表达层·sensor_rich_prompt] Ornith-9B via /api/chat + system_prompt")
                log(f"    卦象: {gua_name} ({best_gua}), 五行: {dom_wx}({dom_score:.2f}), {yin_yang}")
                log(f"    system_prompt: {len(system_prompt)} 字")

            data = self._build_ollama_request(
                user_msg, ollama_model, max_new_tokens, num_gpu,
                stream=False, system_prompt=system_prompt, num_ctx=num_ctx)
            result, error = self._call_ollama(ollama_url, data)

            if error:
                error_msg = f"[表达层错误] Ollama /api/chat (sensor_rich) 调用失败: {error}"
                if verbose:
                    log(f"    {error_msg}")
                return error_msg, {"error": error, "gua_name": gua_name}

            reasoning, answer, eval_count, eval_duration, tokens_per_sec = \
                self._parse_ollama_response(result)

            _, sensor_top, sensor_top_prob = self._sensor_bagua_scores(
                self._last_sensor_gua_logits, top_k=8)

            if verbose:
                log(f"    sensor_top: {sensor_top} ({sensor_top_prob:.2f})")
                log(f"    生成: {eval_count} tokens, {tokens_per_sec:.1f} tokens/s")
                log(f"    回答: {answer[:200]}")

            return answer, {
                "reasoning": reasoning, "answer": answer,
                "tokens_per_sec": tokens_per_sec, "eval_count": eval_count,
                "eval_duration": eval_duration, "gua_name": gua_name,
                "best_gua": best_gua, "dom_wx": dom_wx, "yin_yang": yin_yang,
                "converged": converged, "reason": reason,
                "system_prompt_len": len(system_prompt),
                "sensor_top_bagua": sensor_top,
                "sensor_top_prob": sensor_top_prob,
                "mode": "sensor_rich_prompt",
            }

        # ============== logit_bias 通道 ==============
        if use_logit_bias and tokenizer is not None:
            logit_bias, raw_bias = self._build_logit_bias(meta, tokenizer, logit_bias_scale)
            prompt = self._build_logit_bias_prompt(text)

            if verbose:
                log(f"\n  [表达层·logit_bias] Ornith-9B via /v1/chat/completions")
                log(f"    卦象: {gua_name} ({best_gua}), 五行: {dom_wx}({dom_score:.2f}), {yin_yang}")
                log(f"    收敛: {'是' if converged else '否'}, 路径: {reason}")
                log(f"    logit_bias: {len(logit_bias)} tokens, 总强度 {sum(logit_bias.values()):.2f}")
                from light_daoti.daoti_logit_bias import describe_token_bias
                log(describe_token_bias(tokenizer, raw_bias, top_k=15))

            data = self._build_ollama_request(
                prompt, ollama_model, max_new_tokens, num_gpu,
                stream=False, logit_bias=logit_bias, num_ctx=num_ctx)
            result, error = self._call_ollama(ollama_url, data)

            if error:
                error_msg = f"[表达层错误] Ollama /api/chat (logit_bias) 调用失败: {error}"
                if verbose:
                    log(f"    {error_msg}")
                return error_msg, {"error": error, "gua_name": gua_name}

            reasoning, answer, eval_count, eval_duration, tokens_per_sec = \
                self._parse_ollama_response(result)

            if verbose:
                log(f"    生成: {eval_count} tokens, {tokens_per_sec:.1f} tokens/s")
                if reasoning:
                    log(f"    推理块: {reasoning[:120]}...")
                log(f"    回答: {answer[:200]}")
            
            return answer, {
                "reasoning": reasoning, "answer": answer,
                "tokens_per_sec": tokens_per_sec, "eval_count": eval_count,
                "eval_duration": eval_duration, "gua_name": gua_name,
                "best_gua": best_gua, "dom_wx": dom_wx, "yin_yang": yin_yang,
                "converged": converged, "reason": reason,
                "logit_bias_count": len(logit_bias),
                "logit_bias_total": sum(logit_bias.values()),
                "mode": "logit_bias_v1",
            }
        # ============== style_logit_bias 通道 (v2: 极简指令 + 精准 Logit Bias) ==============
        # 道体"指挥手势": 风格→用词倾向词→logit_bias, 绕过 LLM 阅读理解
        # vs sensor_rich: 自然语言总谱 (LLM 需消耗 token 理解)
        # vs logit_bias v1: 卦象直译词(天/刚/健), LLM 回答编程时不会用这些字
        # v2.1 动态: dynamic_bias=True 时, bias强度=base×卦象亲和度 (用户指导方向)
        if use_style_logit_bias and tokenizer is not None:
            if style == "auto":
                style = self._choose_style(meta)
            from light_daoti.daoti_logit_bias import (
                build_style_token_bias, build_dynamic_style_token_bias)
            if dynamic_bias:
                # v2.1 动态: 从道体推演结果获取卦象亲和度
                bagua_scores = meta["summary"].get("bagua_scores", {})
                logit_bias, bias_summary = build_dynamic_style_token_bias(
                    tokenizer, style=style, bagua_scores=bagua_scores,
                    enhance_strength=style_enhance_strength,
                    suppress_strength=style_suppress_strength,
                )
                mode_label = "style_logit_bias_v2.1_dynamic"
            else:
                # v2 静态: 固定词表
                logit_bias, bias_summary = build_style_token_bias(
                    tokenizer, style=style,
                    enhance_strength=style_enhance_strength,
                    suppress_strength=style_suppress_strength,
                )
                mode_label = "style_logit_bias_v2"
            prompt = self._build_logit_bias_prompt(text)

            if verbose:
                log(f"\n  [表达层·{mode_label}] Ornith-9B via /api/chat + think=false")
                log(f"    卦象: {gua_name} ({best_gua}), 五行: {dom_wx}({dom_score:.2f}), {yin_yang}")
                if dynamic_bias:
                    aff = bias_summary.get("affinity_used", {})
                    log(f"    风格: {style} (动态, 亲和度: "
                        f"{' '.join(f'{k}:{v:.2f}' for k,v in sorted(aff.items(),key=lambda x:-x[1])[:4])})")
                    log(f"    注入: {len(bias_summary.get('enhance_words_used',[]))} 词, "
                        f"跳过: {len(bias_summary.get('enhance_words_skipped',[]))} 词")
                else:
                    log(f"    风格: {style} (静态, enhance={len(bias_summary['enhance_words'])}, "
                        f"suppress={len(bias_summary['suppress_words'])})")
                log(f"    logit_bias: {len(logit_bias)} tokens, "
                    f"强度 +{style_enhance_strength}/-{abs(style_suppress_strength)}")

            data = self._build_ollama_request(
                prompt, ollama_model, max_new_tokens, num_gpu,
                stream=False, logit_bias=logit_bias, num_ctx=num_ctx)
            result, error = self._call_ollama(ollama_url, data)

            if error:
                error_msg = f"[表达层错误] Ollama /api/chat (style_logit_bias) 调用失败: {error}"
                if verbose:
                    log(f"    {error_msg}")
                return error_msg, {"error": error, "gua_name": gua_name}

            reasoning, answer, eval_count, eval_duration, tokens_per_sec = \
                self._parse_ollama_response(result)

            if verbose:
                log(f"    生成: {eval_count} tokens, {tokens_per_sec:.1f} tokens/s")
                log(f"    回答: {answer[:200]}")

            return answer, {
                "reasoning": reasoning, "answer": answer,
                "tokens_per_sec": tokens_per_sec, "eval_count": eval_count,
                "eval_duration": eval_duration, "gua_name": gua_name,
                "best_gua": best_gua, "dom_wx": dom_wx, "yin_yang": yin_yang,
                "converged": converged, "reason": reason,
                "style": style,
                "logit_bias_count": len(logit_bias),
                "mode": mode_label,
            }

        # ============== 默认通道 (/api/chat + think=False) ==============
        prompt = self._build_default_prompt(meta, text)

        if verbose:
            log(f"\n  [表达层] Ornith-9B via Ollama")
            log(f"    卦象: {gua_name} ({best_gua}), 五行: {dom_wx}({dom_score:.2f}), {yin_yang}")
            log(f"    收敛: {'是' if converged else '否'}, 路径: {reason}")

        data = self._build_ollama_request(
            prompt, ollama_model, max_new_tokens, num_gpu, stream=False,
            num_ctx=num_ctx)
        result, error = self._call_ollama(ollama_url, data)

        if error:
            error_msg = f"[表达层错误] Ollama API 调用失败: {error}"
            if verbose:
                log(f"    {error_msg}")
            return error_msg, {"error": error, "gua_name": gua_name}

        reasoning, answer, eval_count, eval_duration, tokens_per_sec = \
            self._parse_ollama_response(result)

        if verbose:
            log(f"    生成: {eval_count} tokens, {tokens_per_sec:.1f} tokens/s")
            if reasoning:
                log(f"    推理块: {reasoning[:120]}...")
            log(f"    回答: {answer[:200]}")

        return answer, {
            "reasoning": reasoning,
            "answer": answer,
            "tokens_per_sec": tokens_per_sec,
            "eval_count": eval_count,
            "eval_duration": eval_duration,
            "gua_name": gua_name,
            "best_gua": best_gua,
            "dom_wx": dom_wx,
            "yin_yang": yin_yang,
            "converged": converged,
            "reason": reason,
        }

    @torch.no_grad()
    def generate_from_chain_stream(self, text, chain, max_new_tokens=256,
                                   ollama_url="http://localhost:11434",
                                   ollama_model="hf.co/deepreinforce-ai/Ornith-1.0-9B-GGUF",
                                   num_gpu=20, num_ctx=1024,
                                   use_logit_bias=False, tokenizer=None,
                                   logit_bias_scale=3.0,
                                   use_sensor_bias=False,
                                   use_sensor_rich_prompt=False,
                                   use_attention_bias=False, attention_hook=None,
                                   eager_model=None, eager_tokenizer=None,
                                   use_gate_bias=False, style="auto",
                                   use_style_logit_bias=False,
                                   style_enhance_strength=8.0,
                                   style_suppress_strength=-8.0,
                                   dynamic_bias=False):
        """流式生成: 逐步 yield 生成内容 (generator).

        与 generate_from_chain 的区别:
        - 返回 generator, 逐 chunk yield (accumulated_answer, meta_or_none)
        - 中间 yield 是累积答案 + None (部分生成, 用于流式显示)
        - 最后 yield 是完整答案 + meta (生成完成)

        双端点并行: use_logit_bias=True 走 /v1/chat/completions (SSE 流),
        默认走 /api/chat (newline-delimited JSON 流)。响应字段差异在内部处理。

        适用于 Gradio generator 回调, 实现流式显示。

        通道优先级 (高 → 低):
            use_attention_bias  >  use_sensor_rich_prompt  >  use_sensor_bias
            >  use_logit_bias  >  默认

        Args:
            use_sensor_bias: v3 表达通道, 用 WeightSensor 的卦象分布构建 token bias
            use_sensor_rich_prompt: v4 表达通道, 用 WeightSensor 卦象 + chain 推演
                                    生成自然语言 System Prompt, 让 LLM 理解后自由创作
                                    (优先于所有 bias 通道, 因 Phase1 验证发现 token bias
                                     硬注入会破坏 LLM 自然生成, prompt 引导更有效)
            use_attention_bias: Phase 2.5 道体注意力偏置 (Qwen2.5-0.5B eager)
                                卦象意图→注意力头偏置, 直接调制LLM注意力流 (最高优先级)
        """
        import json as _json
        import urllib.request as _urlreq
        import time as _time

        # 1. 从推演链获取最终状态 (使用辅助方法)
        meta = self._extract_chain_meta(chain)
        gua_name = meta["gua_name"]
        best_gua = meta["best_gua"]
        dom_wx = meta["dom_wx"]
        dom_score = meta["dom_score"]
        yin_yang = meta["yin_yang"]
        converged = meta["converged"]
        reason = meta["reason"]

        # 释放 GPU 缓存: trigram 链推理后清理 DirectML 中间张量, 为 Ollama 腾出 VRAM
        if self.device != "cpu" and self._device_obj is not None:
            import gc
            gc.collect()
            try:
                import torch_directml
                torch_directml.empty_cache()
            except (ImportError, AttributeError):
                pass

        # ============== attention_bias / gate_bias 通道 (Phase 2.5, 流式) ==============
        # 道体注意力控制 + TextIteratorStreamer 实现流式
        if (use_attention_bias or use_gate_bias) and attention_hook is not None and eager_model is not None:
            intent_gua, intent_gua_name, intent_gua_prob = \
                self._compute_intent_gua_from_state(chain)
            prompt = self._build_logit_bias_prompt(text)
            mode_label = "gate_bias" if use_gate_bias else "attention_bias"

            print(f"\n  [表达层·{mode_label}·stream] Qwen2.5-0.5B eager + "
                  f"DaotiAttentionHook + TextIteratorStreamer", flush=True)
            print(f"    卦象: {gua_name} ({best_gua}), 五行: {dom_wx}({dom_score:.2f}), "
                  f"{yin_yang}", flush=True)
            print(f"    意图卦象: {intent_gua_name} (prob={intent_gua_prob:.3f})", flush=True)
            if use_gate_bias:
                print(f"    gate v2: [1.0, 1.5] 只增强高亲和度头 (离火引导)", flush=True)
            else:
                print(f"    bias_strength: ±{attention_hook.bias_strength}", flush=True)

            from transformers import TextIteratorStreamer
            import threading as _threading

            attention_hook.set_intent(intent_gua)
            if use_gate_bias:
                attention_hook.install(use_pruning=False, use_gate=True)
            else:
                attention_hook.install()
            try:
                inputs = eager_tokenizer(prompt, return_tensors="pt")
                streamer = TextIteratorStreamer(
                    eager_tokenizer, skip_prompt=True, skip_special_tokens=True)
                generation_kwargs = {
                    **inputs,
                    "max_new_tokens": max_new_tokens,
                    "do_sample": True,
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "top_k": 20,
                    "pad_token_id": eager_tokenizer.eos_token_id,
                    "streamer": streamer,
                }
                t0 = _time.time()
                thread = _threading.Thread(
                    target=eager_model.generate, kwargs=generation_kwargs)
                thread.start()

                accumulated = ""
                for chunk in streamer:
                    accumulated += chunk
                    yield accumulated, None

                thread.join()
                elapsed = _time.time() - t0
            finally:
                attention_hook.remove()

            n_tokens = len(eager_tokenizer.encode(accumulated, add_special_tokens=False))
            tps = n_tokens / elapsed if elapsed > 0 else 0.0

            print(f"    生成: {n_tokens} tokens, {tps:.1f} tokens/s", flush=True)
            print(f"    回答: {accumulated[:200]}", flush=True)

            yield accumulated, {
                "answer": accumulated,
                "tokens_per_sec": tps,
                "eval_count": n_tokens,
                "eval_duration": elapsed,
                "gua_name": gua_name,
                "best_gua": best_gua,
                "dom_wx": dom_wx,
                "yin_yang": yin_yang,
                "converged": converged,
                "reason": reason,
                "intent_gua_name": intent_gua_name,
                "intent_gua_prob": intent_gua_prob,
                "bias_strength": attention_hook.bias_strength,
                "mode": mode_label,
            }
            return

        # ============== sensor-rich prompt 通道 (System Prompt 注入) ==============
        # v4: 道体用自然语言向 LLM "说戏"——描述 LLM 内部被激活的卦象结构 +
        # 用户意图 + 二者融合关系, 让 LLM 用自己的语言能力创作
        # 比 token bias 优势: 不破坏 LLM 生成路径, 文本质量更高 (Phase1 验证结论)
        if use_sensor_rich_prompt and self._last_sensor_gua_logits is not None:
            system_prompt = self._build_sensor_rich_prompt(
                chain, self._last_sensor_gua_logits, style=style)
            user_msg = text  # 极简 user message, 全部意图由 system_prompt 承载

            print(f"\n  [表达层·sensor_rich_prompt·stream] /api/chat + "
                  f"system_prompt({len(system_prompt)}字) + think=False", flush=True)

            data = self._build_ollama_request(
                user_msg, ollama_model, max_new_tokens, num_gpu,
                stream=True, system_prompt=system_prompt, num_ctx=num_ctx)

            req = _urlreq.Request(
                f"{ollama_url}/api/chat",
                data=_json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            answer = ""
            eval_count = 0
            eval_duration = 0
            t_start = _time.time()
            try:
                with _urlreq.urlopen(req, timeout=300) as resp:
                    for line in resp:
                        line = line.strip()
                        if not line:
                            continue
                        chunk = _json.loads(line)
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            answer += content
                            yield answer, None
                        if chunk.get("done"):
                            eval_count = chunk.get("eval_count", 0)
                            eval_duration = chunk.get("eval_duration", 0) / 1e9
            except Exception as e:
                yield answer + f"\n[生成错误: {e}]", {"error": str(e), "gua_name": gua_name}
                return

            t_gen = _time.time() - t_start
            tokens_per_sec = eval_count / eval_duration if eval_duration > 0 else 0

            # 解析 sensor 顶部八卦 (供 meta 记录)
            _, sensor_top, sensor_top_prob = self._sensor_bagua_scores(
                self._last_sensor_gua_logits, top_k=8)

            meta_out = {
                "reasoning": "",
                "answer": answer,
                "tokens_per_sec": tokens_per_sec,
                "eval_count": eval_count,
                "eval_duration": eval_duration,
                "gua_name": gua_name,
                "best_gua": best_gua,
                "dom_wx": dom_wx,
                "yin_yang": yin_yang,
                "converged": converged,
                "reason": reason,
                "gen_time": t_gen,
                "system_prompt_len": len(system_prompt),
                "sensor_top_bagua": sensor_top,
                "sensor_top_prob": sensor_top_prob,
                "mode": "sensor_rich_prompt_stream",
            }
            yield answer, meta_out
            return

        # ============== logit_bias 通道 (/v1/chat/completions SSE 流) ==============
        # v3: use_sensor_bias 优先, 用 WeightSensor 的卦象分布构建 token bias
        # v2: use_style_logit_bias 最优先, 风格倾向词 (极简指令+精准bias)
        use_bias_channel = False
        bias_source = None
        logit_bias = None
        used_style = None

        if use_style_logit_bias and tokenizer is not None:
            if style == "auto":
                style = self._choose_style(meta)
            from light_daoti.daoti_logit_bias import (
                build_style_token_bias, build_dynamic_style_token_bias)
            if dynamic_bias:
                bagua_scores = meta["summary"].get("bagua_scores", {})
                logit_bias, bias_summary = build_dynamic_style_token_bias(
                    tokenizer, style=style, bagua_scores=bagua_scores,
                    enhance_strength=style_enhance_strength,
                    suppress_strength=style_suppress_strength,
                )
                bias_source = "style_v2.1_dyn"
            else:
                logit_bias, bias_summary = build_style_token_bias(
                    tokenizer, style=style,
                    enhance_strength=style_enhance_strength,
                    suppress_strength=style_suppress_strength,
                )
                bias_source = "style_v2"
            prompt = self._build_logit_bias_prompt(text)
            use_bias_channel = True
            used_style = style
        elif use_sensor_bias and tokenizer is not None and self._last_sensor_gua_logits is not None:
            logit_bias, raw_bias = self._build_logit_bias_from_sensor(
                tokenizer, logit_bias_scale)
            prompt = self._build_logit_bias_prompt(text)
            use_bias_channel = True
            bias_source = "sensor"
        elif use_logit_bias and tokenizer is not None:
            logit_bias, raw_bias = self._build_logit_bias(meta, tokenizer, logit_bias_scale)
            prompt = self._build_logit_bias_prompt(text)
            use_bias_channel = True
            bias_source = "summary"

        if use_bias_channel:
            if used_style:
                print(f"\n  [表达层·{bias_source}·stream] /api/chat + think=False, "
                      f"风格={used_style}, {len(logit_bias)} tokens bias", flush=True)
            else:
                print(f"\n  [表达层·{bias_source}_bias·stream] /api/chat + think=False, "
                      f"{len(logit_bias)} tokens bias", flush=True)

            data = self._build_ollama_request(
                prompt, ollama_model, max_new_tokens, num_gpu,
                stream=True, logit_bias=logit_bias, num_ctx=num_ctx)

            req = _urlreq.Request(
                f"{ollama_url}/api/chat",
                data=_json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            answer = ""
            eval_count = 0
            eval_duration = 0
            t_start = _time.time()
            try:
                with _urlreq.urlopen(req, timeout=300) as resp:
                    for line in resp:
                        line = line.strip()
                        if not line:
                            continue
                        chunk = _json.loads(line)
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            answer += content
                            yield answer, None
                        if chunk.get("done"):
                            eval_count = chunk.get("eval_count", 0)
                            eval_duration = chunk.get("eval_duration", 0) / 1e9
            except Exception as e:
                yield answer + f"\n[生成错误: {e}]", {"error": str(e), "gua_name": gua_name}
                return

            t_gen = _time.time() - t_start
            tokens_per_sec = eval_count / eval_duration if eval_duration > 0 else 0

            meta = {
                "reasoning": "",
                "answer": answer,
                "tokens_per_sec": tokens_per_sec,
                "eval_count": eval_count,
                "eval_duration": eval_duration,
                "gua_name": gua_name,
                "best_gua": best_gua,
                "dom_wx": dom_wx,
                "yin_yang": yin_yang,
                "converged": converged,
                "reason": reason,
                "gen_time": t_gen,
                "logit_bias_count": len(logit_bias),
                "logit_bias_total": sum(logit_bias.values()),
                "mode": f"logit_bias_{bias_source}_stream",
                "style": used_style,
            }
            yield answer, meta
            return

        # ============== 默认通道 (/api/chat 流式) ==============
        prompt = self._build_default_prompt(meta, text)

        data = self._build_ollama_request(
            prompt, ollama_model, max_new_tokens, num_gpu, stream=True,
            num_ctx=num_ctx)

        req = _urlreq.Request(
            f"{ollama_url}/api/chat",
            data=_json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        answer = ""
        eval_count = 0
        eval_duration = 0
        t_start = _time.time()

        try:
            with _urlreq.urlopen(req, timeout=300) as resp:
                for line in resp:
                    line = line.strip()
                    if not line:
                        continue
                    chunk = _json.loads(line)
                    content = chunk.get("message", {}).get("content", "")
                    if content:
                        answer += content
                        yield answer, None
                    if chunk.get("done"):
                        eval_count = chunk.get("eval_count", 0)
                        eval_duration = chunk.get("eval_duration", 0) / 1e9
        except Exception as e:
            yield answer + f"\n[生成错误: {e}]", {"error": str(e), "gua_name": gua_name}
            return

        t_gen = _time.time() - t_start
        tokens_per_sec = eval_count / eval_duration if eval_duration > 0 else 0

        meta = {
            "reasoning": "",
            "answer": answer,
            "tokens_per_sec": tokens_per_sec,
            "eval_count": eval_count,
            "eval_duration": eval_duration,
            "gua_name": gua_name,
            "best_gua": best_gua,
            "dom_wx": dom_wx,
            "yin_yang": yin_yang,
            "converged": converged,
            "reason": reason,
            "gen_time": t_gen,
        }
        yield answer, meta


# ==============================================================================
# 主函数: 验证 v23 符号推演链
# ==============================================================================

def main():
    """验证 v23 符号推演链引擎。

    测试3个案例 (与 v16 一致):
        A. 温暖的诗 (预期: 离/火)
        B. 代码崩溃 (预期: 坎/水 或 兑/金)
        C. 头痛吃药 (预期: 坎/水 医药)
    """
    log("=" * 70)
    log("[道体符号推演链引擎 v23 — 从力平衡到符号因果]")
    log("=" * 70)
    log("哲学: 道体是'我', LLM是按需调用的'五官'")
    log("流程: 解读 → 不确定判据 → [检索] → 符号推演 → 方向偏置 → 卦象化 → 循环")
    log("变化: 移除gate_yang/gate_yin/trapezoid, 改为_causal_derive + step_size偏置")
    log("=" * 70)

    import time

    # ---- 1. 加载 LLM (Qwen2.5-0.5B as encoder) ----
    log(f"\n[1/4] 加载 LLM: E:\\Qwen2.5-ModelScope\\Qwen\\Qwen2.5-0.5B")
    from transformers import AutoModelForCausalLM, AutoTokenizer
    t0 = time.time()
    model_path = "E:/Qwen2.5-ModelScope/Qwen/Qwen2.5-0.5B"
    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    llm = AutoModelForCausalLM.from_pretrained(
        model_path, dtype=torch.float32, trust_remote_code=True,
        attn_implementation="eager",
    )
    llm.to("cpu"); llm.eval()
    for p in llm.parameters():
        p.requires_grad = False
    log(f"[OK] LLM 加载 ({time.time()-t0:.1f}s, hidden_size={llm.config.hidden_size})")

    @torch.no_grad()
    def encode(texts):
        if isinstance(texts, str):
            texts = [texts]
        enc = tokenizer(texts, padding=True, truncation=True,
                        max_length=512, return_tensors="pt")
        base_model = getattr(llm, "model", llm)
        outputs = base_model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"])
        last_hidden = outputs.last_hidden_state if hasattr(outputs, "last_hidden_state") else outputs[0]
        mask = enc["attention_mask"].unsqueeze(-1).float()
        pooled = (last_hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
        return pooled.float()

    # ---- 2. 加载参数库 ----
    log(f"\n[2/4] 加载参数库")
    from light_daoti.llm_param_library import LLMParamLibrary

    lib_path_vt = "e:/smallloong/DAOti+llm/light_daoti/logs/vibethinker_lib.pt"
    lib_vt = LLMParamLibrary.load(lib_path_vt, device="cpu")
    bank_vt = lib_vt.vectors.float()  # [165888, 2048]
    bank_vt_norm = F.normalize(bank_vt, dim=-1)
    log(f"[OK] VibeThinker 参数库: {bank_vt_norm.shape}")
    del lib_vt

    lib_path_qw = "e:/smallloong/DAOti+llm/light_daoti/logs/qwen_lib.pt"
    lib_qw = LLMParamLibrary.load(lib_path_qw, device="cpu")
    bank_qw = lib_qw.vectors.float()  # [49152, 896]
    bank_qw_norm = F.normalize(bank_qw, dim=-1)
    log(f"[OK] Qwen 参数库: {bank_qw_norm.shape}")
    del lib_qw

    # Ornith-9B 参数库 (可选, 4096维, 触发自动扩维)
    # 用环境变量 ENABLE_ORNITH=1 控制, 默认不加载 (保持退化态兼容)
    ornith_lib_path = "e:/smallloong/DAOti+llm/light_daoti/logs/ornith_lib.pt"
    extra_banks_list = [(bank_qw_norm, "qwen")]
    if os.path.exists(ornith_lib_path) and os.environ.get("ENABLE_ORNITH", "0") == "1":
        lib_ornith = LLMParamLibrary.load(ornith_lib_path, device="cpu")
        bank_ornith = lib_ornith.vectors.float()
        bank_ornith_norm = F.normalize(bank_ornith, dim=-1)
        log(f"[OK] Ornith 参数库: {bank_ornith_norm.shape} (触发自动扩维)")
        del lib_ornith
        extra_banks_list.append((bank_ornith_norm, "ornith"))

    # ---- 3. 加载 TrigramSpaceV16 ----
    log(f"\n[3/4] 初始化 TrigramSpaceV16 (state_dim=2048)")
    trigram = TrigramSpaceV16(
        state_dim=2048, n_gua=64, n_domains=8, sphere_dim=3,
        gate_type="resonance_v2", coherence_mode="separation",
    )
    tri_path = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_v24.pt"
    ckpt = torch.load(tri_path, map_location="cpu", weights_only=False)
    trigram.load_state_dict(ckpt["state_dict"] if "state_dict" in ckpt else ckpt)
    trigram.eval()
    for p in trigram.parameters():
        p.requires_grad = False
    log(f"[OK] TrigramSpaceV16 ({sum(p.numel() for p in trigram.parameters()):,} 参数)")
    log(f"[OK] 加载 trigram_v24.pt (epoch={ckpt.get('epoch', '?')}, acc_bagua={ckpt.get('acc_bagua', '?')})")

    # ---- 4. 构建符号推演链引擎 ----
    log(f"\n[4/4] 构建符号推演链引擎 v23.4 (生克双路径+动态阈值, 第三层因果已回退禁用)")
    engine = DaotiInferenceEngineV23(
        trigram=trigram,
        param_bank_norm=bank_vt_norm,
        top_k=10,
        max_steps=15,
        convergence_stable=3,
        uncertainty_entropy_thresh=0.7,
        uncertainty_margin_thresh=0.05,
        retrieval_blend=0.3,
        gua_temp=0.8,           # v23.1: 尖锐温度
        init_blend=0.15,        # v23.1: 保留LLM encode原始方向
        online_learning=True,   # v23.2: 在线Hebbian学习
        hebbian_lr=0.005,       # v23.2: 学习率
        extra_banks=extra_banks_list,
        enable_scheduler=True,  # v26: 五行气场调度 + 全模块池
        yin_threshold=0.5,      # v26: 阴阈值
    )
    log(f"\n[引擎配置]")
    log(f"  top_k={engine.top_k}, max_steps={engine.max_steps}, "
        f"convergence_stable={engine.convergence_stable}")
    log(f"  uncertainty: entropy_thresh={engine.uncertainty_entropy_thresh}, "
        f"margin_thresh={engine.uncertainty_margin_thresh}")
    log(f"  retrieval_blend={engine.retrieval_blend}, "
        f"gua_temp={engine.gua_temp}, init_blend={engine.init_blend}")
    log(f"  online_learning={engine.online_learning}, "
        f"hebbian_lr={engine.hebbian_lr}")
    log(f"  step_size_schedule: {engine.step_size_schedule}")
    log(f"  参数库数: {len(engine.dim_manager.registered_sources)}")

    # ---- 4.5 扩维诊断 (观察点 1-2) ----
    dm = engine.dim_manager
    log(f"\n[扩维诊断]")
    log(f"  current_dim={dm.current_dim}, base_dim={dm.base_dim}, "
        f"is_expanded={dm.is_expanded}")
    log(f"  registered_sources:")
    for src in dm.registered_sources:
        log(f"    - {src['name']}: bank={list(src['bank'].shape)}, "
            f"eff_dim={src['dim']}")
    log(f"  gua_protos_base: {list(dm.gua_protos_base.shape)}")
    log(f"  gua_protos_full: {list(dm.gua_protos_full.shape)}")
    if dm.is_expanded:
        # 观察点 1: 形状验证
        assert dm.gua_protos_full.shape[1] == dm.current_dim, \
            f"扩维形状不一致: full={dm.gua_protos_full.shape} vs current_dim={dm.current_dim}"
        log(f"  [OK] 卦原型扩维成功: [{dm.n_gua}, {dm.base_dim}] → "
            f"[{dm.n_gua}, {dm.current_dim}]")

        # 观察点 2: 尾列质量分析
        tail_cols = dm.gua_protos_full[:, dm.base_dim:].float()  # [64, n_new]
        tail_norms = tail_cols.norm(dim=-1)  # [64]
        log(f"  尾列分析 (新增 {tail_cols.shape[1]} 维):")
        log(f"    范数: mean={tail_norms.mean():.4f}, "
            f"std={tail_norms.std():.4f}, "
            f"min={tail_norms.min():.4f}, max={tail_norms.max():.4f}")

        # 同宫卦 vs 异宫卦的尾列相似度 (语义连贯性检验)
        # 同宫的卦应该有更相似的尾列 (因为检索到相似的 Ornith 碎片)
        tail_norm = F.normalize(tail_cols, dim=-1)  # [64, n_new]
        tail_sims = torch.matmul(tail_norm, tail_norm.T)  # [64, 64]
        same_palace_sims = []
        diff_palace_sims = []
        for i in range(64):
            gua_i = GUA_64[i]
            palace_i = GUA_TO_BAGUA.get(gua_i, "乾")
            for j in range(i + 1, 64):
                gua_j = GUA_64[j]
                palace_j = GUA_TO_BAGUA.get(gua_j, "乾")
                sim = tail_sims[i, j].item()
                if palace_i == palace_j:
                    same_palace_sims.append(sim)
                else:
                    diff_palace_sims.append(sim)
        import statistics
        same_mean = statistics.mean(same_palace_sims)
        diff_mean = statistics.mean(diff_palace_sims)
        log(f"    同宫卦尾列相似度: mean={same_mean:.4f} (n={len(same_palace_sims)})")
        log(f"    异宫卦尾列相似度: mean={diff_mean:.4f} (n={len(diff_palace_sims)})")
        log(f"    语义连贯性: {'✓ 同宫>异宫' if same_mean > diff_mean else '✗ 同宫≤异宫'} "
            f"(Δ={same_mean - diff_mean:.4f})")

        # expand_proj 信息
        if dm.expand_proj is not None:
            ep = dm.expand_proj
            log(f"  ExpandProjection: bridge={'None' if ep.bridge is None else str(list(ep.bridge.weight.shape))}, "
                f"new_bank_bias norm={ep.new_bank_bias.norm():.4f}")
    else:
        log(f"  [未扩维] 退化态, full 与 base 共享对象引用")

    # ---- 5. 初始化权重空间探索器 (三模型自由探索) ----
    log(f"\n[5/5] 初始化权重空间探索器")
    explorer = WeightSpaceExplorer(
        engine,
        exploration_lr=0.002,
        batch_candidates=32,
        explore_topk=8,
        max_session_writes=500,
        drift_cos_thresh=0.85,
    )
    log(f"[OK] 探索器就绪: 候选池={explorer.batch_candidates}, "
        f"topk={explorer.explore_topk}, 预算={explorer.max_session_writes}")

    # ---- 6. 多轮验证: 观察卦原型在使用中的演化 ----
    # v23.4基线多样化测试集: 18案例覆盖五行+任务类型+情感倾向
    # 目标: 在更大样本上验证道体自我进化能力, 而非调优基准案例
    test_cases = [
        # 原有6案例 (基准)
        ("A_温暖的诗", "帮我写一首温暖的诗", "离(火/温暖) 或 震(木/萌发)"),
        ("B_代码崩溃", "我的代码崩溃了帮我看看", "坎(水/险陷) 或 兑(金/折损)"),
        ("C_头痛吃药", "我头痛该吃什么药", "坎(水/医药) 或 巽(木/入)"),
        ("D_考试焦虑", "我明天考试很焦虑睡不着", "离(火/焦躁) 或 坎(水/险陷)"),
        ("E_种植技巧", "怎么在阳台种好番茄", "震(木/生长) 或 巽(木/入)"),
        ("F_调解纠纷", "两个朋友吵架了我怎么调解", "坤(土/中和) 或 艮(土/止)"),
        # 新增12案例 (扩展覆盖)
        ("G_法律咨询", "我被起诉了该怎么办", "兑(金/肃杀) 或 乾(金/刚健)"),
        ("H_哲学思辨", "人生的意义到底是什么", "坤(土/厚重) 或 艮(土/止观)"),
        ("I_日常闲聊", "今天天气真不错心情很好", "坎(水/流动) 或 兑(金/悦)"),
        ("J_技术文档", "帮我写一份API接口技术文档", "乾(金/精确) 或 兑(金/规范)"),
        ("K_数学证明", "证明根号2是无理数", "乾(金/严密) 或 坎(水/深邃)"),
        ("L_情感倾诉", "我失恋了心里很难过", "坎(水/柔陷) 或 坤(土/承载)"),
        ("M_产品设计", "帮我设计一个智能家居产品", "震(木/创造) 或 巽(木/入)"),
        ("N_旅行规划", "帮我规划一周的日本旅行", "坎(水/远行) 或 震(木/动)"),
        ("O_历史分析", "分析罗马帝国衰亡的原因", "坤(土/厚重) 或 艮(土/止)"),
        ("P_数据解读", "这份销售数据说明了什么", "乾(金/精确) 或 兑(金/析)"),
        ("Q_烹饪食谱", "怎么做一道好吃的红烧肉", "离(火/烘烤) 或 坤(土/谷)"),
        ("R_运动健身", "怎么科学增肌减脂", "震(木/生机) 或 巽(木/入)"),
    ]

    N_ROUNDS = int(os.environ.get("N_ROUNDS", "3"))  # 跑3轮, 观察卦原型逐轮演化 (可用环境变量覆盖)
    all_rounds_summary = []

    for round_idx in range(1, N_ROUNDS + 1):
        log(f"\n{'#' * 70}")
        log(f"# 第 {round_idx}/{N_ROUNDS} 轮验证 — 卦原型在使用中演化")
        log(f"{'#' * 70}")

        # 记录本轮开始前的卦原型对齐度 (用A案例的LLM encode作为参考)
        if round_idx == 1:
            # 第1轮前, 记录初始对齐度作为基准
            with torch.no_grad():
                pooled_a = encode(["帮我写一首温暖的诗"])
                import math as _math
                target_norm = _math.sqrt(2048)
                pooled_a = pooled_a * (target_norm / (pooled_a.norm(dim=-1, keepdim=True) + 1e-8))
                state_a = pad_to_state_dim(pooled_a, state_dim=2048)
                state_a_dir = F.normalize(state_a[0], dim=-1)
                # 检查离卦(29)原型与"温暖"语义的对齐度
                li_proto_dir = engine.dim_manager.gua_protos_base_norm[29]
                kan_proto_dir = engine.dim_manager.gua_protos_base_norm[28]
                li_align = F.cosine_similarity(state_a_dir.unsqueeze(0), li_proto_dir.unsqueeze(0)).item()
                kan_align = F.cosine_similarity(state_a_dir.unsqueeze(0), kan_proto_dir.unsqueeze(0)).item()
                log(f"\n  [基准] '温暖'语义 vs 卦原型对齐度:")
                log(f"    离卦(火/温暖): {li_align:.4f}")
                log(f"    坎卦(水): {kan_align:.4f}")

        round_results = []
        for case_name, text, expected in test_cases:
            log(f"\n{'=' * 70}")
            log(f"[第{round_idx}轮 {case_name}] {text}")
            log(f"  预期: {expected}")
            log(f"{'=' * 70}")

            chain, converged = engine.run(text, encode, verbose=True)

            # 汇总
            final = chain[-1]["summary"]
            n_steps = len(chain) - 1
            n_retrievals = sum(1 for c in chain if c.get("retrieved", False))
            target_guas = [c.get("target_gua_name", "?") for c in chain[1:]]

            log(f"\n  [结果汇总]")
            log(f"    收敛: {'是' if converged else '否'} "
                f"({n_steps}步)")
            log(f"    检索次数: {n_retrievals}/{n_steps}")
            log(f"    目标卦轨迹: {' → '.join(target_guas)}")
            log(f"    最终卦: {final['gua_name']}, 主导八卦: {final['best_gua']}")
            log(f"    最终五行: " + " | ".join(
                f"{w} {v:.2f}" for w, v in sorted(
                    final['wuxing_scores'].items(), key=lambda x: -x[1])[:3]))
            log(f"    最终 alpha: {final['alpha']:.3f}, coherence: {final['coherence']:.3f}")

            round_results.append({
                "round": round_idx,
                "case": case_name,
                "converged": converged,
                "n_steps": n_steps,
                "final_gua": final["gua_name"],
                "final_bagua": final["best_gua"],
                "init_gua": chain[0]["summary"]["gua_name"],
                "init_bagua": chain[0]["summary"]["best_gua"],
                "target_trajectory": target_guas,
            })

        all_rounds_summary.append(round_results)

        # 每轮结束后, 重新检查对齐度
        if round_idx < N_ROUNDS:
            with torch.no_grad():
                state_a_dir = F.normalize(state_a[0], dim=-1)
                li_proto_dir = engine.dim_manager.gua_protos_base_norm[29]
                kan_proto_dir = engine.dim_manager.gua_protos_base_norm[28]
                li_align = F.cosine_similarity(state_a_dir.unsqueeze(0), li_proto_dir.unsqueeze(0)).item()
                kan_align = F.cosine_similarity(state_a_dir.unsqueeze(0), kan_proto_dir.unsqueeze(0)).item()
                log(f"\n  [第{round_idx}轮后] '温暖'语义 vs 卦原型对齐度:")
                log(f"    离卦(火/温暖): {li_align:.4f}")
                log(f"    坎卦(水): {kan_align:.4f}")

    # ---- 7. 总体对比: 多轮演化效果 ----
    log(f"\n{'=' * 70}")
    log(f"[v23.4 生克双路径+动态阈值 — 多轮演化结果]")
    log(f"{'=' * 70}")
    log(f"\n  各轮收敛与意图对齐:")
    log(f"  {'轮次':<6} {'案例':<12} {'收敛':<6} {'步数':<6} {'初始卦':<8} {'最终卦':<8} {'初始八卦':<8} {'最终八卦':<8}")
    for round_results in all_rounds_summary:
        for r in round_results:
            log(f"  {r['round']:<6} {r['case']:<12} "
                f"{'是' if r['converged'] else '否':<6} {r['n_steps']:<6} "
                f"{r['init_gua']:<8} {r['final_gua']:<8} "
                f"{r['init_bagua']:<8} {r['final_bagua']:<8}")

    # Hebbian学习事件统计
    log(f"\n  Hebbian学习事件统计 (共{len(engine.learning_log)}次):")
    learn_by_gua = {}
    for ev in engine.learning_log:
        name = ev["target_gua_name"]
        if name not in learn_by_gua:
            learn_by_gua[name] = {"count": 0, "align_deltas": []}
        learn_by_gua[name]["count"] += 1
        learn_by_gua[name]["align_deltas"].append(ev["align_delta"])
    for name, info in learn_by_gua.items():
        avg_delta = sum(info["align_deltas"]) / len(info["align_deltas"])
        log(f"    {name}: 学习{info['count']}次, 平均对齐度提升={avg_delta:+.4f}")

    # 收敛率
    total_cases = sum(len(r) for r in all_rounds_summary)
    total_converged = sum(sum(1 for r in round_results if r["converged"])
                          for round_results in all_rounds_summary)
    log(f"\n  总收敛率: {total_converged}/{total_cases}")

    # ---- 8. 三模型权重空间自由探索 ----
    log(f"\n{'=' * 70}")
    log(f"[权重空间自由探索 — 在三个 LLM 参数库中探索]")
    log(f"{'=' * 70}")
    log(f"  VibeThinker (165,888 行 × 2048 维)")
    log(f"  Qwen2.5-0.5B (49,152 行 × 896 维)")
    ornith_loaded = (os.path.exists(ornith_lib_path)
                     and os.environ.get("ENABLE_ORNITH", "0") == "1")
    log(f"  Ornith-9B    ({'已加载 4096 维' if ornith_loaded else '未加载'})")

    EXPLORE_BATCHES = int(os.environ.get("EXPLORE_BATCHES", "3"))
    for eb in range(EXPLORE_BATCHES):
        log(f"\n--- 探索批次 {eb+1}/{EXPLORE_BATCHES} ---")
        results = explorer.explore_batch(idle_event=None, verbose=False)
        n_conv = sum(1 for r in results if r["converged"])
        n_learn = sum(1 for r in results if r.get("align_delta", 0) != 0)
        log(f"  探索 {len(results)} 行, {n_conv} 收敛, {n_learn} 学习 "
            f"[预算: {explorer.total_writes}/{explorer.max_session_writes}]")
        if results:
            avg_coh = sum(r["coherence"] for r in results) / len(results)
            log(f"  平均 coherence: {avg_coh:.4f}")

    # 探索统计
    estats = explorer.stats()
    log(f"\n[探索统计]")
    log(f"  总探索数: {estats['total_explorations']}")
    log(f"  总写入数: {estats['total_writes']} (预算: {estats['max_writes']})")
    log(f"  收敛率: {estats['convergence_rate']:.2%}")
    log(f"  学习条目: {estats['learned_count']}")
    log(f"  回滚次数: {estats['rollback_count']}")
    log(f"  平均对齐度提升: {estats['avg_align_delta']:.4f}")
    log(f"  平均 coherence: {estats['avg_coherence']:.4f}")
    log(f"  参数库分布:")
    for name, cnt in sorted(estats.get('bank_distribution', {}).items(),
                            key=lambda x: -x[1]):
        log(f"    {name}: {cnt} 次")
    if estats.get('gua_distribution'):
        log(f"  卦象分布 Top-5:")
        for gua, cnt in sorted(estats['gua_distribution'].items(),
                               key=lambda x: -x[1])[:5]:
            log(f"    {gua}: {cnt} 次")

    save_log()

    # ---- 9. 后台持续探索循环 ----
    import threading, time
    log(f"\n{'=' * 70}")
    log(f"[启动后台持续探索 — Ctrl+C 停止]")
    log(f"{'=' * 70}")
    stop_flag = threading.Event()
    idle_event = threading.Event()
    idle_event.set()  # CLI 环境始终空闲
    t = threading.Thread(
        target=explorer.run_loop,
        args=(stop_flag, idle_event),
        kwargs={"batch_interval": 60, "verbose": True},
        daemon=True,
    )
    t.start()
    log(f"[后台探索线程已启动, 批次间隔 60 秒, 预算 {explorer.max_session_writes}]")

    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        log(f"\n[收到中断信号, 停止探索]")
        stop_flag.set()


if __name__ == "__main__":
    main()
