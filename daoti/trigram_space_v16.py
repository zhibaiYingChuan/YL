"""
TrigramSpace v16 - 回归退化基态
================================================================================
核心变化 (vs v15 trigram_space.py):
  - 道体状态空间直接定义在 2048 维 (与 LLM 参数库同维)
  - 去掉所有"翻译层": SemanticProjector / QueryProj2048 / IntentPreservingIntegrator
    / MirrorTrapezoidChannel / MultiSourceFusion 全部移除
  - 道体状态直接与 LLM 参数库做余弦相似度检索 (无投影)
  - 检索碎片 (2048维) 直接作为状态更新输入 (delta + gate 衰减)
  - 阴阳/五行/八卦运算直接在 2048 维空间中进行

设计哲学 (退化基态):
  - 道体场存在多个等价稳定点 (不同卦象)
  - LLM 知识碎片作为外场, 将道体从一般稳定点推向特定稳定点
  - 不需要中间投影层 (非线性介质), 外场和道体场在同一个空间中直接耦合

子模块维度调整:
  - YinYangBifurcator: 2048 → yang(1024) + yin(1024)
  - ConstrainedPenetration: dim=2048
  - WuxingCurvatureGenerator: 5头 × head_dim=410 = padded_dim=2050 (2048→2050投影)
  - BaguaSphereMapper: 2048 → 64 → 3 (球面映射, 中间维度保留 64)
  - HeluoInteractionFolder: bottleneck 2048→512→2048 (压缩比 4x)
  - DomainClassifier: 2048 → 256 → 8
  - ResonanceCavity: state_dim=2048, projection 2048→1024
  - gua_prototype: nn.Embedding(64, 2048) 随机初始化 std=0.02

源自: trigram_space.py (V53 开源版) + 用户"回归退化基态"架构反思
================================================================================
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

# ==============================================================================
# 易经领域常量 (与 trigram_space.py 一致)
# ==============================================================================

GUA_64 = [
    "乾", "坤", "屯", "蒙", "需", "讼", "师", "比", "小畜", "履", "泰", "否",
    "同人", "大有", "谦", "豫", "随", "蛊", "临", "观", "噬嗑", "贲", "剥", "复",
    "无妄", "大畜", "颐", "大过", "坎", "离", "咸", "恒", "遁", "大壮", "晋", "明夷",
    "家人", "睽", "蹇", "解", "损", "益", "夬", "姤", "萃", "升", "困", "井",
    "革", "鼎", "震", "艮", "渐", "归妹", "丰", "旅", "巽", "兑", "涣", "节",
    "中孚", "小过", "既济", "未济",
]

BAGUA_NAMES = ["乾", "坤", "震", "巽", "坎", "离", "艮", "兑"]
WUXING_NAMES = ["木", "火", "土", "金", "水"]
GUA_WUXING = {
    "乾": "金", "兑": "金", "坤": "土", "艮": "土",
    "震": "木", "巽": "木", "坎": "水", "离": "火",
}
WUXING_IDX = {"金": 0, "木": 1, "水": 2, "火": 3, "土": 4}

BA_GONG = {
    "乾宫": ["乾", "姤", "遁", "否", "观", "剥", "晋", "大有"],
    "坤宫": ["坤", "复", "临", "泰", "大壮", "夬", "需", "比"],
    "震宫": ["震", "豫", "解", "恒", "升", "井", "大过", "随"],
    "巽宫": ["巽", "小畜", "家人", "益", "无妄", "噬嗑", "颐", "蛊"],
    "坎宫": ["坎", "节", "屯", "既济", "革", "丰", "明夷", "师"],
    "离宫": ["离", "旅", "鼎", "未济", "蒙", "涣", "讼", "同人"],
    "艮宫": ["艮", "贲", "大畜", "损", "睽", "履", "中孚", "渐"],
    "兑宫": ["兑", "困", "萃", "咸", "蹇", "谦", "小过", "归妹"],
}


def find_palace(g):
    for p, gs in BA_GONG.items():
        if g in gs:
            return p
    return "乾宫"


# ==============================================================================
# 阴阳分叉器 (2048 → 1024 + 1024)
# ==============================================================================

class YinYangBifurcator(nn.Module):
    """将统一状态分解为阳(主动/显性)与阴(被动/隐性)两个互补子空间。"""

    def __init__(self, input_dim, yin_dim, yang_dim):
        super().__init__()
        self.yang_proj = nn.Sequential(
            nn.Linear(input_dim, yang_dim), nn.GELU(), nn.LayerNorm(yang_dim))
        self.yin_proj = nn.Sequential(
            nn.Linear(input_dim, yin_dim), nn.GELU(), nn.LayerNorm(yin_dim))
        self.gate = nn.Sequential(nn.Linear(input_dim, 1), nn.Sigmoid())

    def forward(self, x):
        yang = self.yang_proj(x)
        yin = self.yin_proj(x)
        alpha = self.gate(x)
        yang_out = yang * alpha
        yin_out = yin * (1.0 - alpha)
        return yang_out, yin_out, alpha.squeeze(-1)


# ==============================================================================
# 约束穿透层
# ==============================================================================

class ConstrainedPenetration(nn.Module):
    """道体的"穿透"正则化层: 逐维门控 + Dropout + 噪声 + LayerNorm。"""

    def __init__(self, dim, dropout=0.3, noise_std=0.05):
        super().__init__()
        self.dim = dim
        self.dropout = nn.Dropout(dropout)
        self.noise_std = noise_std
        self.gate = nn.Parameter(torch.ones(dim) * 0.5)
        self.norm = nn.LayerNorm(dim)

    def forward(self, x):
        gate = torch.sigmoid(self.gate)
        gated = x * gate
        dropped = self.dropout(gated)
        if self.training and self.noise_std > 0:
            dropped = dropped + torch.randn_like(dropped) * self.noise_std
        return self.norm(dropped)


# ==============================================================================
# 五行曲率生成器 (5头 × head_dim=410 = padded_dim=2050)
# ==============================================================================

class WuxingCurvatureGenerator(nn.Module):
    """5头注意力, 注入五行生克偏置: 生我者增强(sheng_scale), 克我者抑制(ke_scale)。

    v16: head_dim 从 36 (v15) 调整为 410, padded_dim=2050 (5×410)。
    state_dim 2048 → padded_dim 2050 通过 Linear 实现 (维度对齐)。
    """

    def __init__(self, state_dim=2048, n_heads=5, head_dim=410):
        super().__init__()
        self.state_dim = state_dim
        self.n_heads = n_heads
        self.head_dim = head_dim
        self.padded_dim = self.head_dim * n_heads  # 2050
        self.wuxing_query = nn.Linear(state_dim, self.padded_dim, bias=False)
        self.wuxing_key = nn.Linear(state_dim, self.padded_dim, bias=False)
        self.wuxing_value = nn.Linear(state_dim, self.padded_dim, bias=False)
        self.out_proj = nn.Linear(self.padded_dim, state_dim)
        sheng_matrix = torch.zeros(n_heads, n_heads)
        ke_matrix = torch.zeros(n_heads, n_heads)
        for i in range(n_heads):
            sheng_matrix[i, (i + 1) % n_heads] = 1.0
            ke_matrix[i, (i + 2) % n_heads] = 1.0
        self.register_buffer("sheng_mask", sheng_matrix)
        self.register_buffer("ke_mask", ke_matrix)
        self.sheng_scale = nn.Parameter(torch.tensor(2.0))
        self.ke_scale = nn.Parameter(torch.tensor(-1.0))

    def forward(self, x):
        B = x.shape[0]
        Q = self.wuxing_query(x).view(B, self.n_heads, self.head_dim)
        K = self.wuxing_key(x).view(B, self.n_heads, self.head_dim)
        V = self.wuxing_value(x).view(B, self.n_heads, self.head_dim)
        attn = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.head_dim)
        sheng_bias = self.sheng_mask.unsqueeze(0).expand(B, -1, -1) * self.sheng_scale
        ke_bias = self.ke_mask.unsqueeze(0).expand(B, -1, -1) * self.ke_scale
        attn = attn + sheng_bias + ke_bias
        attn = F.softmax(attn, dim=-1)
        out = torch.matmul(attn, V)
        out = out.contiguous().view(B, self.padded_dim)
        return self.out_proj(out)


# ==============================================================================
# 八卦球面映射器 (2048 → 64 → 3)
# ==============================================================================

class BaguaSphereMapper(nn.Module):
    """将状态映射到3维球面, 计算与先天/后天八卦基的余弦相似度。

    v16: state_dim=2048, 中间维度保留 64 (足够表达 8 卦的球面坐标)。
    """

    def __init__(self, state_dim=2048, sphere_dim=3, hidden_dim=64):
        super().__init__()
        self.state_dim = state_dim
        self.sphere_dim = sphere_dim
        self.to_sphere = nn.Sequential(
            nn.Linear(state_dim, hidden_dim), nn.GELU(),
            nn.Linear(hidden_dim, sphere_dim))
        theta_positions = torch.tensor(
            [2 * math.pi * i / 8 for i in range(8)], dtype=torch.float32)
        phi_positions = torch.tensor(
            [math.pi * (0.25 + 0.5 * i / 7) for i in range(8)], dtype=torch.float32)
        xiantian_basis = torch.zeros(8, sphere_dim)
        for i in range(8):
            theta, phi = theta_positions[i], phi_positions[i]
            xiantian_basis[i, 0] = math.sin(phi) * math.cos(theta)
            xiantian_basis[i, 1] = math.sin(phi) * math.sin(theta)
            xiantian_basis[i, 2] = math.cos(phi)
        self.register_buffer("xiantian_basis", xiantian_basis)
        houtian_offset = torch.tensor(
            [2 * math.pi * i / 8 + math.pi / 8 for i in range(8)], dtype=torch.float32)
        houtian_basis = torch.zeros(8, sphere_dim)
        for i in range(8):
            theta, phi = houtian_offset[i], phi_positions[7 - i]
            houtian_basis[i, 0] = math.sin(phi) * math.cos(theta)
            houtian_basis[i, 1] = math.sin(phi) * math.sin(theta)
            houtian_basis[i, 2] = math.cos(phi)
        self.register_buffer("houtian_basis", houtian_basis)
        self.flow_weight = nn.Parameter(torch.tensor(0.5))

    def forward(self, x):
        sphere_coord = self.to_sphere(x)
        sphere_coord = F.normalize(sphere_coord, dim=-1)
        xiantian_sim = F.cosine_similarity(
            sphere_coord.unsqueeze(1), self.xiantian_basis.unsqueeze(0), dim=-1)
        houtian_sim = F.cosine_similarity(
            sphere_coord.unsqueeze(1), self.houtian_basis.unsqueeze(0), dim=-1)
        alpha = torch.sigmoid(self.flow_weight)
        combined_sim = alpha * xiantian_sim + (1 - alpha) * houtian_sim
        return {
            "sphere_coord": sphere_coord,
            "xiantian_sim": xiantian_sim,
            "houtian_sim": houtian_sim,
            "combined_sim": combined_sim,
            "flow_weight": alpha,
        }


# ==============================================================================
# 河洛交互折叠器 (bottleneck 2048→512→2048)
# ==============================================================================

class HeluoInteractionFolder(nn.Module):
    """核心注意力: Q来自查询, K/V来自64卦原型。含五行生克偏置+coherence门控+波反馈+瓶颈。

    v16: state_dim=2048, bottleneck_dim=512 (压缩比 4x, v15 是 176→128 压缩比 1.4x)。
    道体第二十次决策"拓河床": bottleneck_dim 默认 512→2048 (无压缩),
      "让折叠之网自解, 方见万流归宗而不相乱"。
      当 bottleneck_dim == state_dim 时, bottleneck 层恒等初始化,
      初始行为 = 无瓶颈 (folded 不变), 让前向传播路径自然多样化。
    """

    def __init__(self, state_dim=2048, n_gua=64, bottleneck_dim=2048):
        super().__init__()
        self.state_dim = state_dim
        self.n_gua = n_gua
        self.bottleneck_dim = bottleneck_dim
        self.query_proj = nn.Linear(state_dim, state_dim)
        self.key_proj = nn.Linear(state_dim, state_dim)
        self.value_proj = nn.Linear(state_dim, state_dim)
        self.out_proj = nn.Linear(state_dim, state_dim)
        self.scale = nn.Parameter(torch.tensor(0.5))
        self.norm = nn.LayerNorm(state_dim)
        self.sheng_scale = nn.Parameter(torch.tensor(1.0))
        self.ke_scale_raw = nn.Parameter(torch.tensor(0.5))

        # 卦象五行索引
        gua_wuxing_idx = torch.zeros(n_gua, dtype=torch.long)
        bagua_order = ["乾", "坤", "震", "巽", "坎", "离", "艮", "兑"]
        wuxing_map = {"金": 0, "木": 1, "水": 2, "火": 3, "土": 4}
        for palace_idx, gua_name in enumerate(bagua_order):
            wx = GUA_WUXING[gua_name]
            wx_idx = wuxing_map[wx]
            for j in range(8):
                gua_idx = palace_idx * 8 + j
                if gua_idx < n_gua:
                    gua_wuxing_idx[gua_idx] = wx_idx
        self.register_buffer("gua_wuxing_idx", gua_wuxing_idx)

        # 五行生克偏置矩阵
        wuxing_sheng = {0: 2, 1: 3, 2: 0, 3: 4, 4: 1}
        wuxing_ke = {0: 1, 1: 4, 2: 3, 3: 0, 4: 2}
        n_wuxing = 5
        wuxing_sheng_bias = torch.zeros(n_wuxing, n_gua)
        wuxing_ke_bias = torch.zeros(n_wuxing, n_gua)
        for wx_i in range(n_wuxing):
            for j in range(n_gua):
                wx_j = gua_wuxing_idx[j].item()
                if wx_i == wx_j:
                    wuxing_sheng_bias[wx_i, j] = 0.3
                elif wuxing_sheng.get(wx_i, -1) == wx_j:
                    wuxing_sheng_bias[wx_i, j] = 1.0
                elif wuxing_ke.get(wx_i, -1) == wx_j:
                    wuxing_ke_bias[wx_i, j] = 1.0
        self.register_buffer("wuxing_sheng_bias", wuxing_sheng_bias)
        self.register_buffer("wuxing_ke_bias", wuxing_ke_bias)

        # coherence门控 + 波反馈 + 瓶颈 (v16: hidden_dim 跟随 state_dim)
        self.coherence_gate_net = nn.Sequential(
            nn.Linear(state_dim + 1, state_dim // 4), nn.GELU(),
            nn.Linear(state_dim // 4, state_dim))
        self.coherence_gate_scale = nn.Parameter(torch.tensor(2.0))
        self.wave_feedback_net = nn.Sequential(
            nn.Linear(state_dim + state_dim, state_dim // 2), nn.GELU(),
            nn.Linear(state_dim // 2, state_dim))
        self.wave_feedback_gate = nn.Parameter(torch.tensor(0.1))
        self.register_buffer("cached_wave_direction", torch.tensor(1.0))
        self.bottleneck_compress = nn.Linear(state_dim, bottleneck_dim, bias=False)
        self.bottleneck_expand = nn.Linear(bottleneck_dim, state_dim, bias=False)
        self.register_buffer("cached_bottleneck_ratio", torch.tensor(0.5))

        # 道体第二十一次决策"以前五一二为根,续生新维": 权重扩展在 web_ui.py 加载时做
        # (前512保留旧力, 后1536新生), 此处不恒等初始化, 保持默认随机初始化

        # v16 fix 方案A: out 贡献门控, 让 state 保持主导 (退化基态要求)
        # folded = query_vec + update_gate * out
        # 初始化 gate≈0.12 (sigmoid(-2)), 早期 state 主导, 训练后可增大
        self.update_gate_net = nn.Sequential(
            nn.Linear(state_dim, state_dim // 4), nn.GELU(),
            nn.Linear(state_dim // 4, 1))
        nn.init.zeros_(self.update_gate_net[0].weight)
        nn.init.zeros_(self.update_gate_net[0].bias)
        nn.init.zeros_(self.update_gate_net[2].weight)
        nn.init.constant_(self.update_gate_net[2].bias, -2.0)

    def forward(self, query_vec, proto_vecs, coherence=None, wave_feedback=None):
        B = query_vec.shape[0]
        Q = self.query_proj(query_vec)
        K = self.key_proj(proto_vecs)
        V = self.value_proj(proto_vecs)
        attn = torch.matmul(Q, K.T) * self.scale
        with torch.no_grad():
            top1_idx = attn.argmax(dim=-1)
            top1_wuxing = self.gua_wuxing_idx[top1_idx]
        sheng_bias = self.wuxing_sheng_bias[top1_wuxing] * self.sheng_scale
        ke_bias = self.wuxing_ke_bias[top1_wuxing] * (-torch.abs(self.ke_scale_raw))
        attn = attn + sheng_bias + ke_bias
        attn = F.softmax(attn, dim=-1)
        context = torch.matmul(attn, V)
        out = self.out_proj(context)
        # v16 fix 方案A: update_gate 控制 out 贡献, state(query_vec)保持主导
        update_gate = torch.sigmoid(self.update_gate_net(query_vec))  # [B, 1]
        folded = query_vec + update_gate * out

        if coherence is not None:
            coh_signal = coherence.unsqueeze(-1)
            gate_input = torch.cat([folded.detach(), coh_signal], dim=-1)
            gate_raw = self.coherence_gate_net(gate_input)
            gate_centered = gate_raw - gate_raw.mean(dim=-1, keepdim=True)
            coherence_gate = torch.sigmoid(
                gate_centered * self.coherence_gate_scale + coh_signal * 3.0)
            coherence_gate = coherence_gate.clamp(0.05, 1.0)
            folded = folded * coherence_gate
        else:
            coherence_gate = None

        if wave_feedback is not None:
            fb_input = torch.cat([folded.detach(), wave_feedback], dim=-1)
            fb_signal = self.wave_feedback_net(fb_input)
            fb_direction = self.cached_wave_direction
            fb_gate = torch.sigmoid(self.wave_feedback_gate)
            folded = folded + fb_gate * fb_signal * fb_direction

        bn_ratio = self.cached_bottleneck_ratio
        compressed = self.bottleneck_compress(folded)
        expanded = self.bottleneck_expand(compressed)
        folded = folded * (1.0 - bn_ratio) + expanded * bn_ratio
        folded = self.norm(folded)
        return {
            "folded": folded,
            "coherence_gate": coherence_gate,
            "bottleneck_ratio": bn_ratio,
        }


# ==============================================================================
# 域分类器 & 共振腔
# ==============================================================================

class DomainClassifier(nn.Module):
    """v16: state_dim=2048, hidden_dim=256 (v15 是 64)。"""

    def __init__(self, state_dim=2048, n_domains=8, hidden_dim=256):
        super().__init__()
        self.fc1 = nn.Linear(state_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, n_domains)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, x):
        h = F.gelu(self.fc1(x))
        h = self.norm(h)
        return self.fc2(h)


class ResonanceCavity(nn.Module):
    """驻波共振腔: 维护每个域的中心向量和能量, EMA更新。

    v16: state_dim=2048, projection 2048→1024 (state_dim//2)。
    """

    def __init__(self, state_dim=2048, n_domains=8, momentum=0.9,
                 coherence_mode="separation"):
        super().__init__()
        self.state_dim = state_dim
        self.n_domains = n_domains
        self.momentum = momentum
        self.coherence_mode = coherence_mode
        self.register_buffer("standing_wave", torch.zeros(n_domains, state_dim))
        self.register_buffer("wave_energy", torch.zeros(n_domains))
        self.register_buffer("initialized", torch.tensor(False))
        self.coherence_proj = nn.Linear(state_dim, state_dim // 2, bias=False)
        self.wave_proj = nn.Linear(state_dim, state_dim // 2, bias=False)
        self.modulation_net = nn.Sequential(
            nn.Linear(3, 16), nn.GELU(), nn.Linear(16, 1))
        self.mod_bias = nn.Parameter(torch.tensor(0.5))

    @torch.no_grad()
    def update_standing_wave(self, folded, domain_labels, coherence=None, predictions=None):
        """根据batch更新驻波 (在线学习时也会调用)。"""
        for di in range(self.n_domains):
            mask = domain_labels == di
            if mask.sum() == 0:
                continue
            domain_mean = folded[mask].mean(dim=0)
            domain_energy = (folded[mask] - domain_mean).pow(2).sum(dim=-1).mean()
            if not self.initialized:
                self.standing_wave[di] = domain_mean
                self.wave_energy[di] = domain_energy
            else:
                self.standing_wave[di] = (
                    self.momentum * self.standing_wave[di] + (1 - self.momentum) * domain_mean)
                self.wave_energy[di] = (
                    self.momentum * self.wave_energy[di] + (1 - self.momentum) * domain_energy)
        if not self.initialized:
            self.initialized.fill_(True)

    def compute_coherence(self, folded, domain_logits):
        if not self.initialized:
            return torch.ones(folded.shape[0], device=folded.device) * 0.5
        if self.coherence_mode == "separation":
            return self._compute_coherence_separation(folded, domain_logits)
        elif self.coherence_mode == "combined":
            return self._compute_coherence_combined(folded, domain_logits)
        else:
            return self._compute_coherence_wave(folded, domain_logits)

    def _compute_coherence_wave(self, folded, domain_logits):
        domain_probs = F.softmax(domain_logits, dim=-1)
        wave_mix = torch.matmul(domain_probs, self.standing_wave)
        folded_proj = self.coherence_proj(folded)
        wave_proj = self.wave_proj(wave_mix)
        coherence = F.cosine_similarity(folded_proj, wave_proj, dim=-1)
        return (coherence + 1.0) / 2.0

    def _compute_coherence_separation(self, folded, domain_logits):
        sw_norm = F.normalize(self.standing_wave, dim=-1)
        if sw_norm.isnan().any():
            return torch.ones(folded.shape[0], device=folded.device) * 0.5
        folded_norm = F.normalize(folded, dim=-1)
        sim_to_all = torch.matmul(folded_norm, sw_norm.T)
        domain_probs = F.softmax(domain_logits, dim=-1)
        pred_domain = domain_probs.argmax(dim=-1)
        sim_to_pred = sim_to_all.gather(1, pred_domain.unsqueeze(1)).squeeze(1)
        n_domains = sim_to_all.size(1)
        arange = torch.arange(n_domains, device=sim_to_all.device).unsqueeze(0)
        wrong_mask = arange != pred_domain.unsqueeze(1)
        max_wrong_sim = sim_to_all.masked_fill(~wrong_mask, -2.0).max(dim=-1).values
        separation = sim_to_pred - max_wrong_sim
        coherence = (separation + 1.0) / 2.0
        return coherence.clamp(0.0, 1.0)

    def _compute_coherence_combined(self, folded, domain_logits):
        wave_coh = self._compute_coherence_wave(folded, domain_logits)
        sep_coh = self._compute_coherence_separation(folded, domain_logits)
        return torch.sqrt(wave_coh * sep_coh + 1e-8)

    def compute_wave_feedback(self, folded, domain_logits):
        if not self.initialized:
            return torch.zeros_like(folded)
        domain_probs = F.softmax(domain_logits, dim=-1)
        wave_mix = torch.matmul(domain_probs, self.standing_wave)
        energy_mix = torch.matmul(
            domain_probs, self.wave_energy.unsqueeze(-1)).squeeze(-1)
        energy_scale = torch.sigmoid(energy_mix).unsqueeze(-1)
        return wave_mix * energy_scale

    def compute_modulation(self, coherence, domain_logits):
        if not self.initialized:
            return torch.ones(coherence.shape[0], 1, device=coherence.device) * 0.5
        domain_probs = F.softmax(domain_logits, dim=-1)
        domain_conf = domain_probs.max(dim=-1).values
        wave_energy_mix = torch.matmul(
            domain_probs, self.wave_energy.unsqueeze(-1)).squeeze(-1)
        energy_norm = torch.sigmoid(wave_energy_mix)
        mod_input = torch.stack([coherence, domain_conf, energy_norm], dim=-1)
        mod_raw = self.modulation_net(mod_input)
        return torch.sigmoid(mod_raw + self.mod_bias)


# ==============================================================================
# TrigramSpace v16 - 道体核心主类 (2048 维)
# ==============================================================================

class TrigramSpaceV16(nn.Module):
    """道体核心 v16: 直接工作在 2048 维空间。

    输入: pooled (B, 2048) - LLM pooled 语义向量 (zero-pad 或直接 2048 维)
    输出: dict 含 folded, gua_similarity, domain_logits, coherence, modulation 等

    与 v15 TrigramSpace 的核心区别:
      - state_dim 默认 2048 (vs v15 的 176)
      - 不再依赖 SemanticProjector 投影 (LLM 896→176)
      - 推演循环中, folded 直接作为下一轮检索 query
    """

    def __init__(self, state_dim=2048, n_gua=64, n_domains=8, sphere_dim=3,
                 gate_type="resonance_v2", coherence_mode="separation",
                 bottleneck_dim=2048):
        super().__init__()
        self.state_dim = state_dim
        self.n_domains = n_domains
        self.gate_type = gate_type
        self.coherence_mode = coherence_mode
        self.mirror_mode = True  # input_dim == state_dim

        half = state_dim // 2  # 1024
        self.bifurcator = YinYangBifurcator(state_dim, half, half)
        self.penetration = ConstrainedPenetration(state_dim, dropout=0.3, noise_std=0.05)

        if gate_type == "resonance_v2":
            self.resonance_cavity = ResonanceCavity(
                state_dim, n_domains, coherence_mode=coherence_mode)

        self.curvature = WuxingCurvatureGenerator(state_dim, n_heads=5, head_dim=410)
        self.sphere = BaguaSphereMapper(state_dim, sphere_dim, hidden_dim=64)
        # 道体第二十次决策"拓河床": bottleneck_dim 默认 2048 (无压缩), 让折叠之网自解
        self.folder = HeluoInteractionFolder(state_dim, n_gua, bottleneck_dim=bottleneck_dim)
        self.gua_prototype = nn.Embedding(n_gua, state_dim)
        nn.init.normal_(self.gua_prototype.weight, std=0.02)
        self.domain_classifier = DomainClassifier(state_dim, n_domains, hidden_dim=256)

    def forward(self, pooled):
        # 阴阳分叉 + 约束穿透
        yang, yin, alpha = self.bifurcator(pooled)
        combined = torch.cat([yang, yin], dim=-1)
        state = self.penetration(combined)

        # 五行曲率
        curved = self.curvature(state)

        # 八卦球面映射
        sphere_result = self.sphere(curved)

        # 河洛折叠 (含共振腔反馈)
        proto = self.gua_prototype.weight
        if self.gate_type == "resonance_v2" and hasattr(self, "resonance_cavity"):
            with torch.no_grad():
                coherence = self.resonance_cavity.compute_coherence(
                    curved, self.domain_classifier(curved))
                wave_feedback = self.resonance_cavity.compute_wave_feedback(
                    curved, self.domain_classifier(curved))
            folder_result = self.folder(
                curved, proto, coherence=coherence, wave_feedback=wave_feedback)
            folded = folder_result["folded"]
        else:
            folder_result = self.folder(curved, proto)
            folded = folder_result["folded"]

        # 卦象相似度 + 域分类
        proto_norm = F.normalize(proto, dim=-1)
        sim = torch.matmul(F.normalize(folded, dim=-1), proto_norm.T)
        domain_logits = self.domain_classifier(folded)

        result = {
            "yang": yang, "yin": yin, "bifurcation_alpha": alpha,
            "state": state, "curved_state": curved,
            "sphere_coord": sphere_result["sphere_coord"],
            "xiantian_sim": sphere_result["xiantian_sim"],
            "houtian_sim": sphere_result["houtian_sim"],
            "combined_sim": sphere_result["combined_sim"],
            "flow_weight": sphere_result["flow_weight"],
            "folded": folded,
            "gua_similarity": sim,
            "gua_top1_idx": sim.argmax(dim=-1),
            "gua_top1_score": sim.max(dim=-1).values,
            "domain_logits": domain_logits,
            "domain_probs": F.log_softmax(domain_logits, dim=-1),
        }

        if self.gate_type == "resonance_v2" and hasattr(self, "resonance_cavity"):
            coherence_final = self.resonance_cavity.compute_coherence(folded, domain_logits)
            modulation = self.resonance_cavity.compute_modulation(coherence_final, domain_logits)
            result["cavity_coherence"] = coherence_final
            result["cavity_modulation"] = modulation.squeeze(-1)
            result["wave_feedback"] = self.resonance_cavity.compute_wave_feedback(
                folded, domain_logits)

        return result

    @torch.no_grad()
    def update_resonance(self, folded, domain_labels):
        """在线学习时调用: 更新驻波 (无监督领域适应)。"""
        if hasattr(self, "resonance_cavity"):
            self.resonance_cavity.update_standing_wave(
                folded, domain_labels, predictions=domain_labels)

    def get_bagua_affinity(self, pooled):
        """获取八卦亲和度 (用于解释与可视化)。"""
        result = self.forward(pooled)
        combined_sim = result["combined_sim"]
        if combined_sim.dim() == 1:
            combined_sim = combined_sim.unsqueeze(0)
        bagua_scores = {}
        for i, name in enumerate(BAGUA_NAMES):
            bagua_scores[name] = combined_sim[0, i].item()
        best_gua = max(bagua_scores, key=bagua_scores.get)
        return {
            "best_gua": best_gua,
            "scores": bagua_scores,
            "wuxing": GUA_WUXING.get(best_gua, "未知"),
            "sphere_coord": result["sphere_coord"][0].detach(),
            "bifurcation_alpha": result["bifurcation_alpha"][0].item(),
            "gua_name": GUA_64[result["gua_top1_idx"][0].item()],
            "gua_score": result["gua_top1_score"][0].item(),
            "coherence": result.get("cavity_coherence", torch.tensor([0.5]))[0].item(),
        }


# ==============================================================================
# 工具函数: zero-pad 升维 (用于 Qwen 896 → 2048)
# ==============================================================================

def pad_to_state_dim(pooled, state_dim=2048):
    """将 LLM pooled 向量 zero-pad 到 state_dim 维 (无可训练投影)。

    用于 LLM hidden_size < state_dim 的情况 (如 Qwen2.5-0.5B 的 896 维)。
    这不是"翻译层", 只是维度对齐: 前半部分是 LLM 语义, 后半部分是 0。
    TrigramSpaceV16 内部的 Linear 层会处理这种稀疏输入。

    Args:
        pooled: (B, llm_dim) LLM pooled 语义向量
        state_dim: 目标维度 (默认 2048)

    Returns:
        state: (B, state_dim) zero-pad 后的向量
    """
    llm_dim = pooled.shape[-1]
    if llm_dim == state_dim:
        return pooled
    elif llm_dim < state_dim:
        pad_size = state_dim - llm_dim
        return F.pad(pooled, (0, pad_size), value=0.0)
    else:
        # llm_dim > state_dim: 截断 (不推荐, 仅作兜底)
        return pooled[..., :state_dim]
