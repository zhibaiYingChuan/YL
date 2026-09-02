"""
train_perception_v2.py - 实验1 v2: 修正对比损失施加位置
================================================================================
v1 诊断: SupCon 施加在 projection head 输出 z(512) 上, projection head 成为
        "逃生通道", trigram 无需改变高增益行为, folded similarity 反而更差(0.016).

v2 修正:
  1. 移除 projection head — SupCon 直接施加在 folded(2048) 上
  2. 新增 L_intent 意图保持损失 — 强制 folded 保留输入信息 (folded sim ≥ 0.5)
  3. L_topo 也施加在 folded 上
  4. 评估在 folded 空间进行 (不再依赖 projection head)

损失 = L_contrast (SupCon on folded) + λ_intent * L_intent
     + λ_topo * L_topo + λ_anchor * L_anchor

  - L_contrast: 同类拉近, 异类推远 (直接在 folded 空间)
  - L_intent:   folded 与输入的余弦相似度 hinge (≥0.5), 防止高增益坍缩
  - L_topo:     球面均匀性 + alpha 连续性 (在 folded 空间)
  - L_anchor:   弱监督锚定 (类别→期望八卦)

成功标准:
  - folded similarity ∈ [0.5, 0.8] (解决 v24 的 0.17 和 v1 的 0.016)
  - 同类聚簇纯度 > 0.7 (在 folded 空间, 非 projection 空间)
  - 下游 18 案例收敛率不劣于 v26 基线
================================================================================
"""

import sys
import os
import time
import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from light_daoti.trigram_space_v16 import TrigramSpaceV16, GUA_64, BAGUA_NAMES, pad_to_state_dim
from light_daoti.config import detect_device, get_torch_device
from emergence.train.contrastive_dataset import generate_dataset, get_category_bagua_mapping

# ==============================================================================
# 配置
# ==============================================================================

LOG_FILE = "e:/smallloong/DAOti+llm/emergence/logs/train_perception_v2.log"
ENCODE_CACHE = "e:/smallloong/DAOti+llm/emergence/logs/qwen_encodes.pt"
MODEL_SAVE = "e:/smallloong/DAOti+llm/emergence/logs/trigram_emergence_v2.pt"

HP = {
    "epochs": 50,
    "batch_cats": 8,        # 每批采样类别数
    "batch_per_cat": 4,     # 每类采样条数 → batch_size = 32
    "lr_trigram": 1e-4,     # trigram 主体学习率 (迁移学习)
    "lr_proto": 5e-4,       # gua_prototype 学习率 (稍大, 允许快速自组织)
    "temperature": 0.1,     # SupCon 温度
    "lambda_topo": 0.1,     # 拓扑一致性权重
    "lambda_anchor": 0.01,  # 弱监督锚定权重
    "lambda_intent": 1.0,   # 意图保持权重 (v2 新增, 核心)
    "intent_threshold": 0.5, # folded sim 下界 (hinge)
}

_lines = []


def log(msg=""):
    line = str(msg)
    print(line, flush=True)
    _lines.append(line)


def save_log():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(_lines))


# ==============================================================================
# SupCon 损失 (直接在 folded 空间计算)
# ==============================================================================

def supcon_loss(folded, labels, temperature=0.1):
    """SupCon 损失: 同类为正样本, 异类为负样本. 直接在 folded(2048) 空间计算.

    Args:
        folded: [B, 2048] trigram 输出 (会先 L2 归一化)
        labels: [B] 类别标签
        temperature: 温度参数
    Returns:
        loss: scalar
    """
    z = F.normalize(folded, dim=-1)  # L2 归一化
    B = z.size(0)
    sim = torch.matmul(z, z.T) / temperature  # [B, B]

    # 对角线置 -inf (排除自身) — torch.eye 在 DirectML 回退 CPU, 先 CPU 创建再迁移
    mask_self = torch.eye(B, dtype=torch.bool).to(z.device)
    sim.masked_fill_(mask_self, -1e9)

    # 正样本掩码: 同类且非自身
    labels = labels.view(-1, 1)
    mask_pos = (labels == labels.T) & ~mask_self  # [B, B]

    n_pos = mask_pos.sum(dim=1)  # [B]
    valid = n_pos > 0
    if not valid.any():
        return torch.tensor(0.0, device=z.device, requires_grad=True)

    log_prob = sim - torch.logsumexp(sim, dim=1, keepdim=True)  # [B, B]
    pos_log_prob = (mask_pos.float() * log_prob).sum(dim=1) / n_pos.clamp(min=1).float()  # [B]

    loss = -pos_log_prob[valid].mean()
    return loss


# ==============================================================================
# 意图保持损失 (v2 新增 — 核心)
# ==============================================================================

def intent_loss(folded, pooled):
    """意图保持损失: 强制 folded 保留输入信息.

    folded 的前 896 维应与 pooled (LLM encode) 保持一定相似度,
    防止 trigram 高增益放大器完全重塑输入 (v24/v1 的根本问题).

    使用 hinge loss: 只在 sim < threshold 时惩罚, 不限制上界
    (让 SupCon 自然平衡, 目标落点 [0.5, 0.8]).

    Args:
        folded: [B, 2048] trigram 输出
        pooled: [B, 896] LLM encode (输入)
    Returns:
        loss: scalar
    """
    dim = pooled.size(1)
    folded_sub = F.normalize(folded[:, :dim], dim=-1)  # [B, 896]
    pooled_norm = F.normalize(pooled, dim=-1)  # [B, 896]
    sim = F.cosine_similarity(folded_sub, pooled_norm, dim=-1)  # [B]
    # hinge: 只惩罚 sim < threshold
    return F.relu(HP["intent_threshold"] - sim).mean()


# ==============================================================================
# 拓扑一致性损失 (在 folded 空间计算)
# ==============================================================================

def topo_loss(folded, alpha):
    """拓扑一致性: 球面均匀性 (防坍缩) + alpha 连续性. 在 folded 空间计算.

    Args:
        folded: [B, 2048] trigram 输出 (会先 L2 归一化)
        alpha: [B] 阴阳分叉值
    Returns:
        L_topo = L_uniform + 0.5 * L_alpha
    """
    z = F.normalize(folded, dim=-1)
    B = z.size(0)
    sim_mat = torch.matmul(z, z.T)  # [B, B]
    mask_self = torch.eye(B, dtype=torch.bool).to(z.device)
    sim_mat = sim_mat.masked_fill(mask_self, 0.0)
    L_uniform = (sim_mat ** 2).sum() / (B * (B - 1))

    L_alpha = alpha.var()
    return L_uniform + 0.5 * L_alpha


# ==============================================================================
# 弱监督锚定损失
# ==============================================================================

def anchor_loss(combined_sim, labels, cat_bagua_map):
    """弱监督锚定: 类别→期望八卦的软约束.

    Args:
        combined_sim: [B, 8] 八卦亲和度
        labels: [B] 类别标签
        cat_bagua_map: dict {cat_id: bagua_idx}
    Returns:
        L_anchor: scalar (交叉熵, 非常小权重)
    """
    target = torch.tensor([cat_bagua_map[l.item()] for l in labels],
                          device=labels.device, dtype=torch.long)
    return F.cross_entropy(combined_sim, target)


# ==============================================================================
# 预计算 Qwen encodes (缓存)
# ==============================================================================

def precompute_encodes(texts, encode_fn, cache_path):
    """预计算所有文本的 Qwen encode, 缓存到磁盘."""
    if os.path.exists(cache_path):
        log(f"[缓存] 加载预计算 encodes: {cache_path}")
        data = torch.load(cache_path, map_location="cpu", weights_only=False)
        if data["texts"] == texts:
            log(f"  [OK] 缓存命中 ({data['pooled'].shape})")
            return data["pooled"]
        log(f"  [WARN] 缓存文本不匹配, 重新计算")

    log(f"[预计算] 编码 {len(texts)} 条文本...")
    t0 = time.time()
    pooled_list = []
    batch_size = 32
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        pooled = encode_fn(batch)  # [B, 896]
        pooled_list.append(pooled.detach().cpu())
        if (i // batch_size) % 5 == 0:
            log(f"  进度: {min(i + batch_size, len(texts))}/{len(texts)} ({time.time()-t0:.1f}s)")
    pooled_all = torch.cat(pooled_list, dim=0)  # [N, 896]
    log(f"  [OK] 完成 ({time.time()-t0:.1f}s), shape={pooled_all.shape}")

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    torch.save({"texts": texts, "pooled": pooled_all}, cache_path)
    log(f"  [缓存] 已保存: {cache_path}")
    return pooled_all


# ==============================================================================
# 批次采样器 (类别均衡)
# ==============================================================================

class CategoryBalancedSampler:
    """每批采样 batch_cats 个类别, 每类 batch_per_cat 条."""

    def __init__(self, labels, batch_cats, batch_per_cat, seed=42):
        self.labels = torch.tensor(labels)
        self.batch_cats = batch_cats
        self.batch_per_cat = batch_per_cat
        self.rng = torch.Generator().manual_seed(seed)
        self.cat_indices = {}
        for c in range(12):
            idx = (self.labels == c).nonzero(as_tuple=True)[0].tolist()
            self.cat_indices[c] = idx

    def epoch_batches(self):
        """生成一个 epoch 的批次索引列表."""
        all_cats = list(range(12))
        batches = []
        n_per_cat = len(self.cat_indices[0]) // self.batch_per_cat
        total_batches = (n_per_cat * 12) // self.batch_cats

        shuffled = {}
        for c in range(12):
            perm = torch.randperm(len(self.cat_indices[c]), generator=self.rng).tolist()
            shuffled[c] = [self.cat_indices[c][i] for i in perm]

        cat_ptr = {c: 0 for c in range(12)}
        for _ in range(total_batches):
            avail_cats = [c for c in all_cats
                          if cat_ptr[c] + self.batch_per_cat <= len(shuffled[c])]
            if len(avail_cats) < self.batch_cats:
                break
            sel_cats = torch.randperm(len(avail_cats), generator=self.rng)[:self.batch_cats].tolist()
            sel_cats = [avail_cats[i] for i in sel_cats]

            batch_idx = []
            batch_labels = []
            for c in sel_cats:
                start = cat_ptr[c]
                batch_idx.extend(shuffled[c][start:start + self.batch_per_cat])
                batch_labels.extend([c] * self.batch_per_cat)
                cat_ptr[c] += self.batch_per_cat

            batches.append((batch_idx, batch_labels))
        return batches


# ==============================================================================
# 训练 (无 projection head, 损失直接在 folded 上)
# ==============================================================================

def train(trigram, pooled_all, labels, cat_bagua_map, device_obj):
    """对比学习训练主循环 (v2: 无 projection head)."""
    log(f"\n{'='*70}")
    log(f"[训练 v2] 感知层对比学习 (无 projection head, 损失在 folded 上)")
    log(f"  epochs={HP['epochs']}, batch_size={HP['batch_cats']*HP['batch_per_cat']}")
    log(f"  lr_trigram={HP['lr_trigram']}, lr_proto={HP['lr_proto']}")
    log(f"  τ={HP['temperature']}, λ_topo={HP['lambda_topo']}, "
        f"λ_anchor={HP['lambda_anchor']}, λ_intent={HP['lambda_intent']}")
    log(f"  intent_threshold={HP['intent_threshold']} (folded sim 下界)")
    log(f"{'='*70}")

    # 参数组 (无 projection head)
    proto_params = list(trigram.gua_prototype.parameters())
    trigram_params = [p for n, p in trigram.named_parameters()
                      if "gua_prototype" not in n]

    optimizer = torch.optim.Adam([
        {"params": trigram_params, "lr": HP["lr_trigram"]},
        {"params": proto_params, "lr": HP["lr_proto"]},
    ])

    sampler = CategoryBalancedSampler(labels, HP["batch_cats"], HP["batch_per_cat"])

    best_loss = float("inf")
    history = []

    for epoch in range(1, HP["epochs"] + 1):
        trigram.train()
        epoch_loss = 0.0
        epoch_l_contrast = 0.0
        epoch_l_intent = 0.0
        epoch_l_topo = 0.0
        epoch_l_anchor = 0.0
        epoch_folded_sim = 0.0  # 监控 folded similarity
        n_batches = 0

        batches = sampler.epoch_batches()
        for batch_idx, batch_labels in batches:
            idx_tensor = torch.tensor(batch_idx)
            pooled_batch = pooled_all[idx_tensor].to(device_obj)  # [B, 896]
            label_batch = torch.tensor(batch_labels, device=device_obj)

            # zero-pad 896 → 2048
            state_batch = pad_to_state_dim(pooled_batch)  # [B, 2048]

            # trigram 前向
            result = trigram(state_batch)
            folded = result["folded"]  # [B, 2048]
            alpha = result["bifurcation_alpha"]  # [B]
            combined_sim = result["combined_sim"]  # [B, 8]

            # 损失 (全部在 folded 空间, 无 projection head)
            l_contrast = supcon_loss(folded, label_batch, HP["temperature"])
            l_intent = intent_loss(folded, pooled_batch)
            l_topo = topo_loss(folded, alpha)
            l_anchor = anchor_loss(combined_sim, label_batch, cat_bagua_map)

            loss = (l_contrast
                    + HP["lambda_intent"] * l_intent
                    + HP["lambda_topo"] * l_topo
                    + HP["lambda_anchor"] * l_anchor)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(trigram.parameters(), 1.0)
            optimizer.step()

            # 更新共振腔驻波 (修复 coherence 恒 0.5 问题)
            with torch.no_grad():
                domain_preds = result["domain_logits"].argmax(dim=-1)
                trigram.update_resonance(folded, domain_preds)

            # 监控 folded similarity
            with torch.no_grad():
                dim = pooled_batch.size(1)
                f_norm = F.normalize(folded[:, :dim], dim=-1)
                p_norm = F.normalize(pooled_batch, dim=-1)
                batch_sim = F.cosine_similarity(f_norm, p_norm, dim=-1).mean().item()

            epoch_loss += loss.item()
            epoch_l_contrast += l_contrast.item()
            epoch_l_intent += l_intent.item()
            epoch_l_topo += l_topo.item()
            epoch_l_anchor += l_anchor.item()
            epoch_folded_sim += batch_sim
            n_batches += 1

        avg_loss = epoch_loss / n_batches
        avg_lc = epoch_l_contrast / n_batches
        avg_li = epoch_l_intent / n_batches
        avg_lt = epoch_l_topo / n_batches
        avg_la = epoch_l_anchor / n_batches
        avg_sim = epoch_folded_sim / n_batches

        history.append({
            "epoch": epoch, "loss": avg_loss, "l_contrast": avg_lc,
            "l_intent": avg_li, "l_topo": avg_lt, "l_anchor": avg_la,
            "folded_sim": avg_sim,
        })

        if avg_loss < best_loss:
            best_loss = avg_loss

        if epoch % 5 == 0 or epoch == 1:
            log(f"  [epoch {epoch:3d}] loss={avg_loss:.4f} "
                f"(contrast={avg_lc:.4f}, intent={avg_li:.4f}, "
                f"topo={avg_lt:.4f}, anchor={avg_la:.4f}) "
                f"folded_sim={avg_sim:.4f} best={best_loss:.4f}")

        # 每 10 epoch 保存 checkpoint
        if epoch % 10 == 0:
            ckpt = {
                "epoch": epoch,
                "trigram_state": trigram.state_dict(),
                "hp": HP,
            }
            torch.save(ckpt, MODEL_SAVE.replace(".pt", f"_ep{epoch}.pt"))

    # 保存最终模型
    final_ckpt = {
        "epoch": HP["epochs"],
        "trigram_state": trigram.state_dict(),
        "hp": HP,
        "history": history,
    }
    torch.save(final_ckpt, MODEL_SAVE)
    log(f"\n[保存] 最终模型: {MODEL_SAVE}")
    return history


# ==============================================================================
# 评估 (在 folded 空间, 无 projection head)
# ==============================================================================

@torch.no_grad()
def evaluate(trigram, pooled_all, labels, device_obj):
    """训练后评估: folded similarity, 聚簇纯度, 类间/类内相似度. 全部在 folded 空间."""
    log(f"\n{'='*70}")
    log(f"[评估 v2] 感知层表示质量 (folded 空间, 无 projection head)")
    log(f"{'='*70}")

    trigram.eval()

    # 全量前向
    folded_list = []
    alpha_list = []
    batch_size = 64
    for i in range(0, len(labels), batch_size):
        pooled_batch = pooled_all[i:i + batch_size].to(device_obj)
        state_batch = pad_to_state_dim(pooled_batch)
        result = trigram(state_batch)
        folded_list.append(result["folded"].cpu())
        alpha_list.append(result["bifurcation_alpha"].cpu())

    folded_all = torch.cat(folded_list, dim=0)  # [N, 2048]
    alpha_all = torch.cat(alpha_list, dim=0)  # [N]
    labels_t = torch.tensor(labels)

    # 1. folded similarity: 输入 pooled 与 folded 前 896 维的余弦相似度
    pooled_norm = F.normalize(pooled_all, dim=-1)
    folded_norm = F.normalize(folded_all[:, :pooled_all.size(1)], dim=-1)
    sim_folded = F.cosine_similarity(pooled_norm, folded_norm, dim=-1)
    mean_sim = sim_folded.mean().item()
    std_sim = sim_folded.std().item()

    log(f"\n1. folded similarity (输入 vs 输出余弦相似度):")
    log(f"   均值={mean_sim:.4f}, 标准差={std_sim:.4f}")
    log(f"   目标: [0.5, 0.8] (v24 基线 ≈ 0.17, v1 结果 ≈ 0.016)")
    log(f"   判定: {'✓ 通过' if 0.5 <= mean_sim <= 0.8 else '✗ 未通过 (需调整)'}")

    # 2. 聚簇纯度: K-means 在 folded 空间 (2048维), 比较与类别标签的一致性
    from sklearn.cluster import KMeans
    folded_np = F.normalize(folded_all, dim=-1).numpy()
    km = KMeans(n_clusters=12, random_state=42, n_init=10)
    cluster_labels = km.fit_predict(folded_np)

    purity = 0.0
    for c in range(12):
        mask = cluster_labels == c
        if mask.sum() == 0:
            continue
        true_labels = labels_t[mask].numpy()
        most_common = Counter(true_labels).most_common(1)[0][1]
        purity += most_common / len(labels)
    log(f"\n2. 聚簇纯度 (K-means on folded, 12簇): {purity:.4f}")
    log(f"   目标: > 0.7")
    log(f"   判定: {'✓ 通过' if purity > 0.7 else '✗ 未通过'}")

    # 3. 类内/类间相似度 (在 folded 空间)
    folded_norm_full = F.normalize(folded_all, dim=-1)
    sim_mat = torch.matmul(folded_norm_full, folded_norm_full.T)
    labels_2d = labels_t.view(-1, 1)
    same_class = (labels_2d == labels_2d.T)
    mask_self = torch.eye(len(labels), dtype=torch.bool)

    intra_sim = sim_mat[same_class & ~mask_self].mean().item()
    inter_sim = sim_mat[~same_class & ~mask_self].mean().item()
    log(f"\n3. 类内/类间相似度 (folded 空间):")
    log(f"   类内相似度: {intra_sim:.4f}")
    log(f"   类间相似度: {inter_sim:.4f}")
    log(f"   差值: {intra_sim - inter_sim:.4f} (越大越好)")

    # 4. 八卦分布: 每类的期望八卦命中率
    cat_bagua = get_category_bagua_mapping()
    bagua_correct = 0
    total = 0
    for i in range(len(labels)):
        result_i = trigram(pad_to_state_dim(pooled_all[i:i+1].to(device_obj)))
        combined = result_i["combined_sim"][0]
        pred_bagua = combined.argmax().item()
        expected_bagua = cat_bagua[labels[i]]
        if pred_bagua == expected_bagua:
            bagua_correct += 1
        total += 1
    bagua_acc = bagua_correct / total
    log(f"\n4. 八卦命中率 (类别期望八卦): {bagua_correct}/{total} = {bagua_acc:.4f}")
    log(f"   (注意: 对比学习允许拓扑旋转, 此指标仅参考)")

    return {
        "folded_sim_mean": mean_sim,
        "folded_sim_std": std_sim,
        "cluster_purity": purity,
        "intra_sim": intra_sim,
        "inter_sim": inter_sim,
        "bagua_acc": bagua_acc,
    }


# ==============================================================================
# 主函数
# ==============================================================================

def main():
    t_start = time.time()
    log("=" * 70)
    log("[实验1 v2] 感知层对比学习 (修正版)")
    log("  修正: SupCon 直接在 folded 上 + L_intent 意图保持损失")
    log("  目标: folded sim ∈ [0.5,0.8], 聚簇纯度 > 0.7")
    log("  (v1 诊断: projection head 逃生通道导致 folded sim=0.016)")
    log("=" * 70)

    # 1. 加载 Qwen encode
    log(f"\n[1/5] 加载 Qwen2.5-0.5B (encode 用)...")
    from transformers import AutoTokenizer, AutoModelForCausalLM
    model_path = "E:/Qwen2.5-ModelScope/Qwen/Qwen2.5-0.5B"
    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    llm = AutoModelForCausalLM.from_pretrained(
        model_path, dtype=torch.float32, trust_remote_code=True)
    llm.eval()
    for p in llm.parameters():
        p.requires_grad = False
    log(f"  [OK] Qwen2.5-0.5B ({time.time()-t_start:.1f}s)")

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

    # 2. 生成数据集 + 预计算 encodes
    log(f"\n[2/5] 生成数据集 + 预计算 encodes...")
    texts, labels, cat_names = generate_dataset()
    log(f"  数据集: {len(texts)} 条, {len(set(labels))} 类")
    pooled_all = precompute_encodes(texts, encode, ENCODE_CACHE)

    # 释放 LLM (预计算完成后不再需要)
    del llm, tokenizer
    import gc; gc.collect()

    cat_bagua_map = get_category_bagua_mapping()
    log(f"  类别→八卦映射: {cat_bagua_map}")

    # 3. 加载 trigram v24 (迁移学习起点)
    log(f"\n[3/5] 加载 trigram v24...")
    trigram = TrigramSpaceV16(
        state_dim=2048, n_gua=64, n_domains=8, sphere_dim=3,
        gate_type="resonance_v2", coherence_mode="separation",
    )
    ckpt = torch.load("e:/smallloong/DAOti+llm/light_daoti/logs/trigram_v24.pt",
                      map_location="cpu", weights_only=False)
    trigram.load_state_dict(ckpt["state_dict"] if "state_dict" in ckpt else ckpt)
    log(f"  [OK] trigram_v24.pt (epoch={ckpt.get('epoch', '?')})")

    # 4. 硬件分摊 (无 projection head, 只需 trigram 上 GPU)
    device_str = detect_device("auto")
    if device_str != "cpu":
        device_obj = get_torch_device(device_str)
        trigram.to(device_obj)
        log(f"  [OK] trigram → {device_str} (GPU 分摊)")
    else:
        device_obj = torch.device("cpu")

    # 5. 训练 (无 projection head)
    log(f"\n[4/5] 开始对比学习训练 (v2: 无 projection head)...")
    t_train = time.time()
    history = train(trigram, pooled_all, labels, cat_bagua_map, device_obj)
    log(f"\n  训练完成 ({time.time()-t_train:.1f}s)")

    # 6. 评估 (在 folded 空间)
    log(f"\n[5/5] 评估表示质量 (folded 空间)...")
    metrics = evaluate(trigram, pooled_all, labels, device_obj)

    # 总结
    log(f"\n{'='*70}")
    log(f"[实验1 v2 总结]")
    log(f"  folded similarity: {metrics['folded_sim_mean']:.4f} (目标 [0.5, 0.8])")
    log(f"  聚簇纯度: {metrics['cluster_purity']:.4f} (目标 > 0.7, folded 空间)")
    log(f"  类内相似度: {metrics['intra_sim']:.4f}")
    log(f"  类间相似度: {metrics['inter_sim']:.4f}")
    log(f"  八卦命中率: {metrics['bagua_acc']:.4f}")
    log(f"  总耗时: {time.time()-t_start:.1f}s")
    log(f"{'='*70}")

    save_log()
    log(f"\n日志已保存: {LOG_FILE}")
    log(f"模型已保存: {MODEL_SAVE}")


if __name__ == "__main__":
    main()
