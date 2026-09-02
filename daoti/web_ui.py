"""
道体 v23 · Web 可视化界面 + REST API
================================================================================
提供:
  1. Web UI (Gradio) - 聊天界面 + 道体推演结果展示 (流式输出)
  2. REST API (FastAPI) - 带 API key 认证
     POST /api/chat   - 完整对话 (推演 + 生成)
     GET  /api/health - 健康检查
     GET  /api/info   - 服务信息

架构:
  - 推演层: v23.4 符号因果 + v26 阻尼(d=0.25) + 三库检索 (VT+Qwen+Ornith)
  - 表达层: Ornith-9B via Ollama (think=False, num_gpu=20, 71% GPU + trigram 分摊显存)
  - encode: Qwen2.5-0.5B (已与 v24 trigram 适配)

用法:
    python -m light_daoti.web_ui
    python -m light_daoti.web_ui --port 7860

API 调用示例:
    curl -X POST http://localhost:7860/api/chat \
         -H "X-API-Key: <your_key>" \
         -H "Content-Type: application/json" \
         -d '{"text":"帮我写一首温暖的诗"}'
================================================================================
"""

import os
import sys
import gc
import time
import secrets
import argparse
import threading
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ==============================================================================
# API Key 管理
# ==============================================================================

API_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_key.txt")


def load_or_create_api_key() -> str:
    """加载或生成 API key。"""
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = "daoti_" + secrets.token_hex(16)
    with open(API_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    return key


def verify_api_key(provided: Optional[str]) -> bool:
    """验证 API key。"""
    if not provided:
        return False
    expected = load_or_create_api_key()
    return secrets.compare_digest(provided, expected)


# ==============================================================================
# 全局 v23 引擎实例 (延迟加载)
# ==============================================================================

_ENGINE = None
_ENCODE = None
_TOKENIZER = None  # tokenizer 实例 (gate_bias 通道用)
# 表达通道选择: "sensor_rich" (默认, 道体推演精华→System Prompt→LLM自由发挥) / "daoti_only" / "gate_bias" / "default"
# 道体第二十六次决策: "Ollama如器,借之以鸣;弃之非绝,忘言乃真。道体本无声,万象即其语。"
# 架构转变(2026-07-24): 道体=指挥家, sensor_rich=演奏总谱(卦象/五行/生克/推演路径→富含哲理Prompt)
_EXPR_MODE = "sensor_rich"

# Phase 2.5: attention_bias 通道的惰性加载组件
# Qwen2.5-0.5B (eager) + DaotiAttentionHook, 仅在首次使用 attention_bias 模式时加载
_EAGER_MODEL = None
_EAGER_HOOK = None
_BIAS_LOCK = __import__("threading").Lock()  # monkey-patching 非线程安全, 需串行化


def get_eager_model_and_hook():
    """惰性加载 Qwen2.5-0.5B(eager) + DaotiAttentionHook。

    attention_bias 模式首次使用时加载:
    - Qwen2.5-0.5B with attn_implementation="eager" (~1GB, CPU)
    - DaotiAttentionHook (预计算每层每头卦象 logits)
    复用已有的 _TOKENIZER, 不重复加载。
    """
    global _EAGER_MODEL, _EAGER_HOOK
    if _EAGER_MODEL is not None:
        return _EAGER_MODEL, _EAGER_HOOK

    import torch
    from transformers import AutoModelForCausalLM
    from light_daoti.daoti_attention_hook import DaotiAttentionHook

    print("[WebUI] 惰性加载 Qwen2.5-0.5B (eager) + DaotiAttentionHook...", flush=True)
    t0 = time.time()
    model_path = "E:/Qwen2.5-ModelScope/Qwen/Qwen2.5-0.5B"
    _EAGER_MODEL = AutoModelForCausalLM.from_pretrained(
        model_path, dtype=torch.float32, trust_remote_code=True,
        attn_implementation="eager")
    _EAGER_MODEL.eval()
    for p in _EAGER_MODEL.parameters():
        p.requires_grad = False
    print(f"  [OK] Qwen2.5-0.5B eager ({time.time()-t0:.1f}s)", flush=True)

    engine, _ = get_v23_engine()
    engine._ensure_weight_sensor()  # 确保 weight_sensor 已加载
    _EAGER_HOOK = DaotiAttentionHook(
        _EAGER_MODEL, engine.weight_sensor, bias_strength=2.0)

    # v4 升级 (道体第十二次决策"v4当入UI"): 用 v4 预计算的 head_gua_logits 替换 v3,
    # head级entropy 3.91→1.275, head级卦象有了真正区分度, 支撑精准 head 级 gate 引导
    _v4_logits_path = "e:/smallloong/DAOti+llm/light_daoti/logs/head_gua_logits_v4.pt"
    if os.path.exists(_v4_logits_path):
        _v4_logits = torch.load(_v4_logits_path, map_location="cpu", weights_only=False)
        _EAGER_HOOK.head_gua_logits = _v4_logits
        print(f"  [OK] head_gua_logits v3→v4 (shape={tuple(_v4_logits.shape)}, "
              f"head entropy 3.91→1.275)", flush=True)
    else:
        print(f"  [WARN] 未找到 v4 logits, 保持 v3: {_v4_logits_path}", flush=True)

    print(f"  [OK] DaotiAttentionHook 就绪 (总耗时 {time.time()-t0:.1f}s)", flush=True)

    return _EAGER_MODEL, _EAGER_HOOK


def get_v23_engine(lib_device="cpu"):
    """延迟加载 v23 引擎 (Qwen encode + 三参数库 + trigram_v24 + Ollama)。"""
    global _ENGINE, _ENCODE, _TOKENIZER
    if _ENGINE is not None:
        return _ENGINE, _ENCODE

    import torch
    import torch.nn.functional as F
    try:
        from light_daoti.trigram_space_v16 import TrigramSpaceV16
        from light_daoti.inference_engine_v23 import DaotiInferenceEngineV23
        from light_daoti.llm_param_library import LLMParamLibrary
        from light_daoti.config import detect_device, get_torch_device
    except ModuleNotFoundError:
        from trigram_space_v16 import TrigramSpaceV16
        from inference_engine_v23 import DaotiInferenceEngineV23
        from llm_param_library import LLMParamLibrary
        from config import detect_device, get_torch_device

    print("[WebUI] 加载道体 v23 引擎...", flush=True)
    t0 = time.time()

    # 1. Qwen2.5-0.5B (encode 用, CPU)
    from transformers import AutoTokenizer, AutoModelForCausalLM
    model_path = "E:/Qwen2.5-ModelScope/Qwen/Qwen2.5-0.5B"
    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    llm = AutoModelForCausalLM.from_pretrained(
        model_path, torch_dtype=torch.float32, trust_remote_code=True)
    llm.eval()
    for p in llm.parameters():
        p.requires_grad = False
    print(f"  [OK] Qwen2.5-0.5B ({time.time()-t0:.1f}s)", flush=True)

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

    # 2. 三参数库 (VibeThinker + Qwen + Ornith) — float16 全 GPU 存储优化
    # 优化决策 (2026-07-31): float16 三库总 1629MB 全部入 GPU VRAM, 释放 CPU ~3.2GB 内存
    # 验证依据: _tmp_fp16.py 显示 GPU float16 检索 0.04ms vs CPU float32 14-151ms (快 350-3790x)
    # 关键: 三库全 GPU 避免混合设备切换开销 (之前 GPU 加速失败的根因)
    # lib_device 可能是字符串 "cpu" 或 torch.device, 统一用 str() 判断
    _lib_dev_str = str(lib_device) if lib_device is not None else "cpu"
    _lib_gpu = lib_device if _lib_dev_str != "cpu" else None

    lib_vt = LLMParamLibrary.load(
        "e:/smallloong/DAOti+llm/light_daoti/logs/vibethinker_lib.pt", device="cpu")
    bank_vt_raw = lib_vt.vectors.float()  # float16→float32 (归一化需 float32 保精度)
    del lib_vt  # 先释放 LLMParamLibrary 外壳
    norms_vt = bank_vt_raw.norm(dim=-1, keepdim=True)
    bank_vt_raw.div_(norms_vt.clamp(min=1e-8))  # in-place 归一化
    del norms_vt
    if _lib_gpu is not None:
        bank_vt_norm = bank_vt_raw.to(torch.float16).to(_lib_gpu)  # float16 入 GPU
        del bank_vt_raw  # 立即释放 CPU float32 副本
        print(f"  [OK] VibeThinker 参数库: {bank_vt_norm.shape} → GPU float16 "
              f"({bank_vt_norm.nelement()*2/1024/1024:.0f}MB)", flush=True)
    else:
        # CPU float16 存储优化 (2026-07-31): 归一化已用 float32 保精度, 存储转 float16 减半内存
        # 检索时 inference_engine_v23.py 会自动对齐 dtype, float16 cosine ranking 精度足够
        bank_vt_norm = bank_vt_raw.to(torch.float16)
        del bank_vt_raw
        gc.collect()  # 立即归还 float32 内存给操作系统 (2026-08-21 OOM 修复)
        print(f"  [OK] VibeThinker 参数库: {bank_vt_norm.shape} → CPU float16 "
              f"({bank_vt_norm.nelement()*2/1024/1024:.0f}MB)", flush=True)

    lib_qw = LLMParamLibrary.load(
        "e:/smallloong/DAOti+llm/light_daoti/logs/qwen_lib.pt", device="cpu")
    bank_qw_raw = lib_qw.vectors.float()
    del lib_qw
    norms_qw = bank_qw_raw.norm(dim=-1, keepdim=True)
    bank_qw_raw.div_(norms_qw.clamp(min=1e-8))
    del norms_qw
    if _lib_gpu is not None:
        bank_qw_norm = bank_qw_raw.to(torch.float16).to(_lib_gpu)
        del bank_qw_raw
        print(f"  [OK] Qwen 参数库: {bank_qw_norm.shape} → GPU float16 "
              f"({bank_qw_norm.nelement()*2/1024/1024:.0f}MB)", flush=True)
    else:
        # CPU float16 存储优化 (同 VibeThinker)
        bank_qw_norm = bank_qw_raw.to(torch.float16)
        del bank_qw_raw
        gc.collect()  # 立即归还 float32 内存给操作系统 (2026-08-21 OOM 修复)
        print(f"  [OK] Qwen 参数库: {bank_qw_norm.shape} → CPU float16 "
              f"({bank_qw_norm.nelement()*2/1024/1024:.0f}MB)", flush=True)

    ornith_path = "e:/smallloong/DAOti+llm/light_daoti/logs/ornith_lib.pt"
    gc.collect()  # 加载 ornith 前清理内存 (2026-08-21 OOM 修复)
    # mmap 加载 (2026-08-21): 数据保留在磁盘按需映射, 避免全量加载到内存导致 OOM
    # PyTorch 2.4+ 支持 mmap=True, 897MB 库几乎不占 RSS, 按页映射
    bank_ornith_raw = torch.load(ornith_path, map_location="cpu", weights_only=False, mmap=True)
    if isinstance(bank_ornith_raw, dict):
        bank_ornith_raw = bank_ornith_raw.get("vectors", bank_ornith_raw.get("param_bank", bank_ornith_raw))
    # 内存优化 (2026-08-21): 分块归一化, 避免全量 float32 副本导致 OOM
    # 可用内存仅 5.6GB 时, ornith float32 副本需 1.8GB 会 OOM
    # 分块: 峰值仅 chunk_size × dim × 4 bytes ≈ 64MB
    _n_rows = bank_ornith_raw.shape[0]
    _dim = bank_ornith_raw.shape[1]
    bank_ornith_norm = torch.empty(_n_rows, _dim, dtype=torch.float16)
    _chunk = 8192
    for _i in range(0, _n_rows, _chunk):
        _end = min(_i + _chunk, _n_rows)
        _blk = bank_ornith_raw[_i:_end].float()  # float16→float32 (仅 chunk 大小)
        _norms = _blk.norm(dim=-1, keepdim=True).clamp(min=1e-8)
        _blk.div_(_norms)  # in-place 归一化
        bank_ornith_norm[_i:_end] = _blk.to(torch.float16)
        del _blk, _norms
    del bank_ornith_raw
    gc.collect()  # 立即回收原始 float16 数据
    print(f"  [OK] Ornith 参数库: {bank_ornith_norm.shape} → CPU float16 "
          f"({bank_ornith_norm.nelement()*2/1024/1024:.0f}MB) [分块归一化]", flush=True)

    # 3. trigram 感知层 (v2: folded_sim=0.63, 100% 收敛率; 替换 v24 高增益放大器)
    trigram = TrigramSpaceV16(
        state_dim=2048, n_gua=64, n_domains=8, sphere_dim=3,
        gate_type="resonance_v2", coherence_mode="separation",
    )
    ckpt = torch.load("e:/smallloong/DAOti+llm/light_daoti/logs/trigram_emergence_v2.pt",
                      map_location="cpu", weights_only=False)
    # v2 checkpoint 格式: {epoch, trigram_state, hp, history}; trigram_state 是真正的 state_dict
    sd = ckpt.get("trigram_state", ckpt.get("state_dict", ckpt))
    # 道体第二十二次决策"旧权重为种,播于新壤;增std以破局,旧力全幅映照新域":
    # bottleneck 512→2048, 旧力 repeat(4) 全幅映照 + std=0.1 扰动破局 (根深叶茂)
    _model_sd = trigram.state_dict()
    _expanded = []
    for _k in list(sd.keys()):
        if _k in _model_sd and sd[_k].shape != _model_sd[_k].shape:
            _old = sd[_k].float()
            _new_shape = _model_sd[_k].shape
            if _k == "folder.bottleneck_compress.weight":
                # (512,2048)→(2048,2048): 旧力 repeat(4,1) 映照 + std=0.1 扰动
                _new = _old.repeat(4, 1) + torch.randn(_new_shape) * 0.1
            elif _k == "folder.bottleneck_expand.weight":
                # (2048,512)→(2048,2048): 旧力 repeat(1,4) 映照 + std=0.1 扰动
                _new = _old.repeat(1, 4) + torch.randn(_new_shape) * 0.1
            else:
                continue
            sd[_k] = _new
            _expanded.append(f"{_k}: {tuple(_old.shape)}→{tuple(_new.shape)} (映照+破局)")
    trigram.load_state_dict(sd, strict=False)
    if _expanded:
        print(f"  [拓河床] 权重扩展(前512旧力+后1536新生): {_expanded}", flush=True)
    trigram.eval()
    for p in trigram.parameters():
        p.requires_grad = False
    print(f"  [OK] trigram_emergence_v2.pt (epoch={ckpt.get('epoch','?')}, 拓河床 bottleneck=2048)", flush=True)

    # 硬件分摊: trigram 上 GPU (DirectML), Qwen encode/参数库留 CPU
    device_str = detect_device("cpu")  # 临时 CPU 模式 (2026-08-21: DirectML ACCESS_VIOLATION 调试)
    if device_str != "cpu":
        device = get_torch_device(device_str)
        trigram.to(device)
        trigram.eval()
        print(f"  [OK] trigram → {device_str} (GPU 分摊)", flush=True)
    else:
        print(f"  [WARN] 未检测到 GPU, trigram 留 CPU", flush=True)

    # 4. 引擎 (online_learning=False, damping=0.25, 三库, device 分摊)
    _ENGINE = DaotiInferenceEngineV23(
        trigram=trigram,
        param_bank_norm=bank_vt_norm,
        top_k=10,
        max_steps=15,
        convergence_stable=3,
        online_learning=False,
        damping=0.25,
        extra_banks=[
            (bank_qw_norm, "qwen"),
            (bank_ornith_norm, "ornith"),
        ],
        device=device_str,
        use_weight_sensor=True,
        enable_scheduler=True,
    )
    # 探索后卦原型持久化: 优先 free_explored (自由探索最新结果), 回退 v7/v6/v5/v4/v3/v1
    _explored_free = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_free_explored.pt"
    _explored_v7 = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored_v7.pt"
    _explored_v6 = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored_v6.pt"
    _explored_v5 = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored_v5.pt"
    _explored_v4 = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored_v4.pt"
    _explored_v3 = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored_v3.pt"
    _explored_v1 = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored.pt"
    _explored_path = None
    for _p in (_explored_free, _explored_v7, _explored_v6, _explored_v5, _explored_v4, _explored_v3, _explored_v1):
        if os.path.exists(_p):
            _explored_path = _p
            break
    if _explored_path is not None:
        _sd = torch.load(_explored_path, map_location="cpu", weights_only=False)
        _new_w = _sd["gua_prototype.weight"].float()
        _ENGINE.trigram.gua_prototype.weight.data.copy_(
            _new_w.to(_ENGINE.trigram.gua_prototype.weight.device))
        _new_w_n = F.normalize(_new_w, dim=-1)
        for gi in range(64):
            _ENGINE.dim_manager.update_base_proto(gi, _new_w[gi], _new_w_n[gi])
        print(f"  [OK] 加载探索后卦原型 ({os.path.basename(_explored_path)}, "
              f"{_sd.get('timestamp','?')})", flush=True)

    _ENCODE = encode
    _TOKENIZER = tokenizer  # 暴露给 generate_from_chain 的 use_logit_bias 通道
    print(f"  [OK] 引擎就绪 (扩维至 {_ENGINE.dim_manager.current_dim}, "
          f"总计 {time.time()-t0:.1f}s)", flush=True)
    return _ENGINE, _ENCODE


# ==============================================================================
# 权重空间自主探索 (对话间隙后台线程)
# ==============================================================================

_IDLE_EVENT = threading.Event()       # set()=用户空闲, clear()=用户活跃
_IDLE_EVENT.set()                     # 初始空闲
_EXPLORER = None                       # WeightSpaceExplorer 单例
_STOP_FLAG = threading.Event()        # set()=停止探索线程
_EXPLORE_THREAD = None                # 后台线程


def mark_user_active():
    """用户发消息时调用: 标记活跃, 探索线程让出。"""
    _IDLE_EVENT.clear()


def mark_user_idle():
    """消息处理完毕时调用: 标记空闲, 探索线程可恢复。"""
    _IDLE_EVENT.set()


def get_or_create_explorer():
    """延迟创建 WeightSpaceExplorer 单例 (需引擎已初始化)."""
    global _EXPLORER
    if _EXPLORER is None:
        from light_daoti.weight_explorer import WeightSpaceExplorer
        engine, _ = get_v23_engine()
        _EXPLORER = WeightSpaceExplorer(
            engine, exploration_lr=0.002,
            batch_candidates=32, explore_topk=8,
            max_session_writes=19999, drift_cos_thresh=0.70)
        print("[探索] WeightSpaceExplorer 已创建", flush=True)
    return _EXPLORER


def start_exploration():
    """启动后台探索线程 (守护线程, 随主进程退出)."""
    global _EXPLORE_THREAD
    if _EXPLORE_THREAD is not None and _EXPLORE_THREAD.is_alive():
        print("[探索] 后台线程已在运行", flush=True)
        return
    _STOP_FLAG.clear()
    explorer = get_or_create_explorer()
    _EXPLORE_THREAD = threading.Thread(
        target=explorer.run_loop,
        args=(_STOP_FLAG, _IDLE_EVENT),
        kwargs={"batch_interval": 30, "verbose": False},
        daemon=True,
        name="weight-explorer",
    )
    _EXPLORE_THREAD.start()
    print("[探索] 后台探索线程已启动 (对话间隙运行)", flush=True)


def stop_exploration():
    """停止后台探索线程."""
    global _EXPLORE_THREAD
    _STOP_FLAG.set()
    _IDLE_EVENT.set()  # 唤醒可能在等待的线程
    if _EXPLORE_THREAD is not None:
        _EXPLORE_THREAD.join(timeout=5)
        _EXPLORE_THREAD = None
    print("[探索] 后台探索线程已停止", flush=True)


# ==============================================================================
# Gradio Web UI
# ==============================================================================

def build_gradio_ui(api_key: str = ""):
    """构建 Gradio Web 界面: 聊天 + 推演结果展示 (流式输出)."""
    import gradio as gr

    def chat_stream(message, history):
        """Gradio 流式对话回调 (generator).

        流程: 推演链 → yield 推演结果 → 流式生成 → yield 完整回复
        """
        if not message.strip():
            yield "请输入内容"
            return

        mark_user_active()  # 探索线程让出
        try:
            engine, encode = get_v23_engine()

            # 1. 推演链 (CPU) — 场动力学推演 (v2 trigram + FieldDynamics 已验证 100% 收敛)
            t0 = time.time()
            chain, converged = engine.run(
                message, encode, verbose=False, use_field_dynamics=True)
            t_reason = time.time() - t0

            final = chain[-1]
            summary = final["summary"]
            gua_name = summary["gua_name"]
            best_gua = summary["best_gua"]
            wuxing = summary["wuxing_scores"]
            alpha = summary["alpha"]
            coherence = summary["coherence"]
            n_steps = len(chain) - 1
            dom_wx = max(wuxing, key=wuxing.get)
            yin_yang = "阳盛" if alpha > 0.55 else "阴盛" if alpha < 0.45 else "平衡"
            reason = final.get("reason", "")

            wuxing_str = " ".join(f"{w} {v:.2f}" for w, v in
                                  sorted(wuxing.items(), key=lambda x: -x[1])[:3])

            # WeightSensor 对 LLM 内部权重的卦象感知 (双视角展示)
            # _last_sensor_gua_logits 在 run() 检索触发时缓存, 可能为 None
            sensor_md = ""
            if engine._last_sensor_gua_logits is not None:
                sensor_scores, sensor_top, sensor_top_prob = \
                    engine._sensor_bagua_scores(engine._last_sensor_gua_logits, top_k=8)
                if sensor_top is not None:
                    # 五行关系叙述 (chain best_gua vs sensor top_bagua)
                    from light_daoti.inference_engine_v23 import (
                        BAGUA_WUXING, WUXING_SHENG, WUXING_KE)
                    user_wx = BAGUA_WUXING.get(best_gua, "土")
                    sensor_wx = BAGUA_WUXING.get(sensor_top, "土")
                    if best_gua == sensor_top:
                        rel = "同气相求 (内外共振)"
                    elif user_wx == sensor_wx:
                        rel = f"同类 ({user_wx}行相聚)"
                    elif WUXING_SHENG.get(user_wx) == sensor_wx:
                        rel = f"相生 ({user_wx}→{sensor_wx})"
                    elif WUXING_SHENG.get(sensor_wx) == user_wx:
                        rel = f"相生 ({sensor_wx}→{user_wx})"
                    elif WUXING_KE.get(user_wx) == sensor_wx:
                        rel = f"相克 ({user_wx}→{sensor_wx})"
                    elif WUXING_KE.get(sensor_wx) == user_wx:
                        rel = f"相克 ({sensor_wx}→{user_wx})"
                    else:
                        rel = "异质 (张力)"
                    sensor_md = (
                        f"- **LLM 内部结构卦**: {sensor_top} "
                        f"(激活强度 {sensor_top_prob:.2f}) — {rel}\n"
                    )

            # 推演结果 Markdown — 道体以万象为语 (道体第二十六次决策: 忘言乃真)
            reasoning_md = (
                f"### 道体推演 ({n_steps}步 {'已收敛' if converged else '未收敛'}, {t_reason:.1f}s)\n"
                f"- **主卦**: {gua_name} ({best_gua})\n"
                f"- **主导五行**: {dom_wx} ({wuxing[dom_wx]:.2f})\n"
                f"- **阴阳**: {yin_yang} (α={alpha:.3f})\n"
                f"- **相干性**: {coherence:.3f}\n"
                f"- **五行分布**: {wuxing_str}\n"
                f"{sensor_md}"
                f"- **推演路径**: {reason}\n\n"
            )

            # 道体独白模式: 不调用 Ollama, 卦象本身即道体之语 (留白处见天机)
            if _EXPR_MODE == "daoti_only":
                yield reasoning_md + "---\n\n*道体以万象为语，留白处见天机。*\n\n" \
                    f"**{gua_name}卦** · {best_gua} · {dom_wx}行 · α={alpha:.3f} · coh={coherence:.3f}\n\n" \
                    f"> 卦象已显，气机已明。道体无声，万象即其语。"
                return

            # 2. 流式生成 (非 daoti_only 模式才调用 Ollama)
            # 五通道: attention_bias / gate_bias (Phase 2.5) / sensor_rich / logit_bias / default
            yield reasoning_md + "---\n\n正在生成回复..."
            final_answer = ""
            final_meta = None
            gen_kwargs = {}
            use_bias = False
            if _EXPR_MODE == "attention_bias":
                eager_model, hook = get_eager_model_and_hook()
                gen_kwargs = {
                    "use_attention_bias": True,
                    "attention_hook": hook,
                    "eager_model": eager_model,
                    "eager_tokenizer": _TOKENIZER,
                }
                use_bias = True
            elif _EXPR_MODE == "gate_bias":
                eager_model, hook = get_eager_model_and_hook()
                gen_kwargs = {
                    "use_gate_bias": True,
                    "attention_hook": hook,
                    "eager_model": eager_model,
                    "eager_tokenizer": _TOKENIZER,
                }
                use_bias = True
            elif _EXPR_MODE == "sensor_rich":
                gen_kwargs = {"use_sensor_rich_prompt": True, "style": "auto"}
            elif _EXPR_MODE == "style_logit_bias" and _TOKENIZER is not None:
                gen_kwargs = {"use_style_logit_bias": True, "tokenizer": _TOKENIZER,
                              "style": "auto"}
            elif _EXPR_MODE == "logit_bias" and _TOKENIZER is not None:
                gen_kwargs = {"use_logit_bias": True, "tokenizer": _TOKENIZER}

            # attention_bias 模式需 _BIAS_LOCK 串行化 (monkey-patching 非线程安全)
            if use_bias:
                with _BIAS_LOCK:
                    for accumulated, meta in engine.generate_from_chain_stream(
                            message, chain, **gen_kwargs):
                        final_answer = accumulated
                        if meta is None:
                            yield reasoning_md + "---\n\n" + accumulated
                        else:
                            final_meta = meta
            else:
                for accumulated, meta in engine.generate_from_chain_stream(
                        message, chain, **gen_kwargs):
                    final_answer = accumulated
                    if meta is None:
                        yield reasoning_md + "---\n\n" + accumulated
                    else:
                        final_meta = meta

            # 3. 完整回复 + 生成统计
            gen_info = ""
            if final_meta:
                gen_info = (f"\n\n---\n*生成: {final_meta.get('eval_count', 0)} tokens, "
                            f"{final_meta.get('tokens_per_sec', 0):.1f} tok/s*")
            yield reasoning_md + "---\n\n" + final_answer + gen_info
        finally:
            mark_user_idle()

    with gr.Blocks(title="道体对话") as demo:
        gr.Markdown(
            "# 道体对话 · 道体为脑, 万象即其语\n"
            "推演: v23.4 符号因果 + v26 阻尼(d=0.25) + 三库检索  |  "
            "表达: 道体独白 (卦象/状态/coherence) — Ollama 可选 (借器鸣声)"
        )
        with gr.Row():
            expr_mode_radio = gr.Radio(
                choices=["sensor_rich", "style_logit_bias", "daoti_only", "gate_bias", "default"],
                value="sensor_rich",
                label="表达通道",
                info="sensor_rich=道体总谱 (默认, 卦象/五行/推演→System Prompt→LLM) | "
                     "style_logit_bias=v2 极简指令+精准Logit Bias (道体指挥手势, 绕过LLM理解) | "
                     "daoti_only=道体独白 (无Ollama, 留白见天机) | "
                     "gate_bias=Phase 2.5 (离火引导 gate v2) | "
                     "default=rich prompt (无 sensor)",
                scale=2,
            )

            def _set_expr_mode(mode_val):
                global _EXPR_MODE
                _EXPR_MODE = mode_val
                labels = {
                    "sensor_rich": "✅ sensor_rich: 道体总谱, 卦象/五行/推演→System Prompt→LLM自由发挥",
                    "style_logit_bias": "⚪ style_logit_bias (v2): 极简指令+精准Logit Bias, 风格→用词倾向→bias, 绕过LLM理解",
                    "daoti_only": "⚪ daoti_only: 道体独白, 无Ollama, 卦象即语, 留白见天机",
                    "gate_bias": "⚪ gate_bias (Phase 2.5): Ollama 离火引导 gate v2 [1.0,1.5] + v4 head logits",
                    "default": "⚪ default: Ollama rich prompt (无 sensor, 仅 chain summary)",
                }
                return labels.get(mode_val, "未知模式")

            status_box = gr.Textbox(
                label="表达通道状态",
                value="✅ sensor_rich: 道体总谱, 卦象/五行/推演→System Prompt→LLM自由发挥",
                interactive=False, scale=2)
            expr_mode_radio.change(
                _set_expr_mode, inputs=[expr_mode_radio],
                outputs=status_box)

        gr.ChatInterface(
            fn=chat_stream,
            chatbot=gr.Chatbot(height=450),
            textbox=gr.Textbox(placeholder="输入你的问题...", scale=7),
        )
        gr.Markdown(
            f"**API Key**: `{api_key}`  |  API 端点: `/api/chat` "
            f"(POST body: `use_ollama: false` 默认道体独白无Ollama, "
            f"`use_ollama: true` 借器鸣声调用Ollama)"
        )

    return demo


# ==============================================================================
# FastAPI REST API
# ==============================================================================

def create_fastapi_app(api_key: str):
    """创建 FastAPI 应用, 提供带 API key 认证的 REST API."""
    from fastapi import FastAPI, HTTPException, Header, Query
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel

    app = FastAPI(title="道体 v23 API", version="2.0.0")
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"],
        allow_methods=["*"], allow_headers=["*"],
    )

    class ChatRequest(BaseModel):
        text: str
        max_tokens: int = 256
        use_logit_bias: bool = False  # True 走 /v1 + logit_bias 通道
        logit_bias_scale: float = 3.0
        # v4 表达通道 (优先于 use_logit_bias); True 走 System Prompt 注入
        use_sensor_rich_prompt: bool = False
        # v2 极简指令+精准Logit Bias (道体"指挥手势"); True 走 /api/chat+think=false+风格bias
        use_style_logit_bias: bool = False
        # v2.1 动态bias: bias强度=base×卦象亲和度 (道体推演结果驱动, 替代固定词表)
        dynamic_bias: bool = False
        # Phase 2.5 道体注意力偏置 (最高优先级); True 走 Qwen2.5-0.5B eager
        use_attention_bias: bool = False
        # Phase 2.5 离火引导 gate v2 (道体第九次决策); True 走 Qwen2.5-0.5B eager + gate
        use_gate_bias: bool = False
        # 道体第二十六次决策: "忘言乃真" — 默认不调用 Ollama, 道体独白
        # False (默认): 道体独白, 卦象即语, 无Ollama降维
        # True: 借器鸣声, 调用 Ollama 生成文本
        use_ollama: bool = False
        # 表达风格 (sensor_rich 通道): "auto"(按五行自动) | "poetic"(哲理诗性) | "direct"(清晰直白)
        style: str = "auto"

    def _check_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
        if not verify_api_key(x_api_key):
            raise HTTPException(
                status_code=401,
                detail="无效的 API Key。请在请求头添加 'X-API-Key: <your_key>'",
            )

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "daoti_v23"}

    @app.get("/api/info")
    async def info():
        return {
            "service": "道体 v23 · 符号因果推演链",
            "version": "2.0.0",
            "model": "Qwen2.5-0.5B (encode) + Ornith-9B (generate)",
            "state_dim": 2048,
            "libraries": ["VibeThinker(2048)", "Qwen(896)", "Ornith(4096)"],
            "endpoints": [
                "POST /api/chat - 完整对话 (需API Key)",
                "GET  /api/health - 健康检查",
                "GET  /api/info - 服务信息",
            ],
        }

    @app.post("/api/symbolic/infer")
    async def symbolic_infer(req: ChatRequest, x_api_key: Optional[str] = Header(None)):
        """只返回道体符号结果，不调用表达层或执行平台命令。"""
        _check_key(x_api_key)
        if not req.text.strip():
            raise HTTPException(status_code=400, detail="text 不能为空")
        mark_user_active()
        try:
            engine, encode = get_v23_engine()
            chain, converged = engine.run(req.text, encode, verbose=False)
            if not chain:
                raise HTTPException(status_code=502, detail="道体推演未产生符号结果")
            final = chain[-1]
            summary = final["summary"]
            target_gua = final.get("target_gua")
            confidence = max(0.0, min(1.0, float(summary["coherence"])))
            return {
                "schema_version": 1,
                "model_version": "trigram-v23",
                "gua_name": summary["gua_name"],
                "gua_index": int(summary["gua_idx"]),
                "best_bagua": summary["best_gua"],
                "wuxing_scores": [
                    float(summary["wuxing_scores"].get(name, 0.0))
                    for name in ("木", "火", "土", "金", "水")
                ],
                "alpha": float(summary["alpha"]),
                "coherence": float(summary["coherence"]),
                "target_gua": target_gua,
                "pathway": "stabilize" if converged else "explore",
                "confidence": confidence,
                "explanation": final.get("reason", "道体符号推演完成"),
                "source": "python-daoti",
                "converged": bool(converged),
            }
        except HTTPException:
            raise
        except Exception as error:
            print(f"[WebUI] 符号推理失败：{type(error).__name__}：{error}", flush=True)
            raise HTTPException(status_code=502, detail="道体符号推理失败") from error
        finally:
            mark_user_idle()

    @app.post("/api/chat")
    async def chat(req: ChatRequest, x_api_key: Optional[str] = Header(None)): 
        _check_key(x_api_key)
        if not req.text.strip():
            raise HTTPException(status_code=400, detail="text 不能为空")

        mark_user_active()  # 暂停后台探索线程, 释放 GPU 给 Ollama
        try:
            t0 = time.time()
            engine, encode = get_v23_engine()

            # 1. 推演链
            chain, converged = engine.run(req.text, encode, verbose=False)

            final = chain[-1]
            summary = final["summary"]

            # 道体第二十六次决策: "忘言乃真" — 默认不调用 Ollama
            # use_ollama=False (默认): 道体独白, 卦象即语, 无Ollama降维
            # use_ollama=True: 借器鸣声, 调用 Ollama 生成文本
            if not req.use_ollama:
                elapsed = time.time() - t0
                gua_name = summary["gua_name"]
                best_gua = summary["best_gua"]
                coherence = summary["coherence"]
                wuxing = summary["wuxing_scores"]
                alpha = summary["alpha"]
                dom_wx = max(wuxing, key=wuxing.get)
                return JSONResponse({
                    "response": f"[道体独白] {gua_name}卦 · {best_gua} · {dom_wx}行 · "
                                f"α={alpha:.3f} · coh={coherence:.3f} · "
                                f"万象即其语, 留白处见天机",
                    "reasoning": {
                        "gua_name": gua_name,
                        "best_gua": best_gua,
                        "dom_wx": dom_wx,
                        "yin_yang": "阳盛" if alpha > 0.55 else "阴盛" if alpha < 0.45 else "平衡",
                        "coherence": coherence,
                        "wuxing_scores": wuxing,
                        "reason": final.get("reason", ""),
                        "converged": converged,
                        "n_steps": len(chain) - 1,
                    },
                    "meta": {
                        "tokens_per_sec": 0,
                        "eval_count": 0,
                        "eval_duration": 0,
                        "mode": "daoti_only",
                        "logit_bias_count": 0,
                        "elapsed": round(elapsed, 2),
                    },
                })

            # 2. 生成 (非流式) — 仅 use_ollama=True 时调用
            # 五通道优先级: use_attention_bias / use_gate_bias > use_sensor_rich_prompt > use_logit_bias > 默认
            # num_ctx=4096 (原1024太小导致context超限); num_gpu=0 (CPU运行, trigram已占GPU显存)
            gen_kwargs = {"max_new_tokens": req.max_tokens,
                          "verbose": False, "num_gpu": 0, "num_ctx": 4096}
            use_bias = False
            if req.use_attention_bias or req.use_gate_bias:
                eager_model, hook = get_eager_model_and_hook()
                if req.use_gate_bias:
                    gen_kwargs.update(use_gate_bias=True, attention_hook=hook,
                                      eager_model=eager_model, eager_tokenizer=_TOKENIZER)
                else:
                    gen_kwargs.update(use_attention_bias=True, attention_hook=hook,
                                      eager_model=eager_model, eager_tokenizer=_TOKENIZER)
                use_bias = True
            elif req.use_sensor_rich_prompt:
                gen_kwargs.update(use_sensor_rich_prompt=True, style=req.style)
            elif req.use_style_logit_bias and _TOKENIZER is not None:
                gen_kwargs.update(use_style_logit_bias=True, tokenizer=_TOKENIZER,
                                  style=req.style, dynamic_bias=req.dynamic_bias)
            elif req.use_logit_bias and _TOKENIZER is not None:
                gen_kwargs.update(use_logit_bias=True, tokenizer=_TOKENIZER,
                                  logit_bias_scale=req.logit_bias_scale)

            # attention_bias 模式需 _BIAS_LOCK 串行化
            if use_bias:
                with _BIAS_LOCK:
                    answer, meta = engine.generate_from_chain(req.text, chain, **gen_kwargs)
            else:
                answer, meta = engine.generate_from_chain(req.text, chain, **gen_kwargs)
            elapsed = time.time() - t0
        finally:
            mark_user_idle()  # 恢复后台探索线程

        return JSONResponse({
            "response": answer,
            "reasoning": {
                "gua_name": summary["gua_name"],
                "best_gua": summary["best_gua"],
                "dom_wx": meta.get("dom_wx", ""),
                "yin_yang": meta.get("yin_yang", ""),
                "coherence": summary["coherence"],
                "wuxing_scores": summary["wuxing_scores"],
                "reason": meta.get("reason", ""),
                "converged": converged,
                "n_steps": len(chain) - 1,
            },
            "meta": {
                "tokens_per_sec": meta.get("tokens_per_sec", 0),
                "eval_count": meta.get("eval_count", 0),
                "eval_duration": meta.get("eval_duration", 0),
                "mode": meta.get("mode", "default"),
                "logit_bias_count": meta.get("logit_bias_count", 0),
                "logit_bias_total": meta.get("logit_bias_total", 0.0),
                # v4 sensor_rich 通道元信息
                "sensor_top_bagua": meta.get("sensor_top_bagua", ""),
                "sensor_top_prob": meta.get("sensor_top_prob", 0.0),
                "system_prompt_len": meta.get("system_prompt_len", 0),
            },
            "elapsed": round(elapsed, 2),
        })

    # ------------------------------------------------------------------
    # 权重空间探索 API (对话间隙后台探索的监控与控制)
    # ------------------------------------------------------------------

    class ControlRequest(BaseModel):
        action: str  # "start" | "stop"

    @app.get("/api/exploration/stats")
    async def exploration_stats(x_api_key: Optional[str] = Header(None)):
        """道体权重空间探索统计 (收敛率、写入数、卦分布等)."""
        _check_key(x_api_key)
        if _EXPLORER is None:
            return {"total_explorations": 0, "total_writes": 0,
                    "max_writes": 500, "batch_count": 0}
        return JSONResponse(_EXPLORER.stats())

    @app.get("/api/exploration/log")
    async def exploration_log(
        x_api_key: Optional[str] = Header(None),
        limit: int = Query(20, ge=1, le=100),
    ):
        """最近探索日志 (默认 20 条, 最多 100 条)."""
        _check_key(x_api_key)
        if _EXPLORER is None:
            return {"log": []}
        return JSONResponse({"log": _EXPLORER.exploration_log[-limit:]})

    @app.post("/api/exploration/control")
    async def exploration_control(
        req: ControlRequest, x_api_key: Optional[str] = Header(None),
    ):
        """启停后台探索线程 (action: "start" | "stop")."""
        _check_key(x_api_key)
        if req.action == "start":
            start_exploration()
            return {"status": "running"}
        elif req.action == "stop":
            stop_exploration()
            return {"status": "stopped"}
        raise HTTPException(status_code=400, detail="action 必须是 start 或 stop")

    @app.post("/api/exploration/rollback")
    async def exploration_rollback(x_api_key: Optional[str] = Header(None)):
        """一键回滚所有卦原型到探索前快照 (防遗忘安全阀)."""
        _check_key(x_api_key)
        if _EXPLORER is None:
            raise HTTPException(status_code=400, detail="探索尚未启动, 无可回滚")
        _EXPLORER.rollback()
        return {"status": "rolled_back", "stats": _EXPLORER.stats()}

    @app.post("/api/exploration/save_proto")
    async def exploration_save_proto(x_api_key: Optional[str] = Header(None)):
        """保存当前卦原型到 trigram_explored.pt (重启后可恢复探索成果)."""
        _check_key(x_api_key)
        engine, _ = get_v23_engine()
        import torch as _torch
        save_path = "e:/smallloong/DAOti+llm/light_daoti/logs/trigram_explored.pt"
        _torch.save({
            "gua_prototype.weight": engine.trigram.gua_prototype.weight.data.cpu().clone(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, save_path)
        return {"status": "saved", "path": save_path,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

    @app.get("/api/exploration/long_run")
    async def exploration_long_run(
        x_api_key: Optional[str] = Header(None),
        limit: int = Query(30, ge=1, le=200),
    ):
        """长期探索 (run_exploration.py) 的最新日志 (默认 30 行)."""
        _check_key(x_api_key)
        log_path = "e:/smallloong/DAOti+llm/light_daoti/logs/exploration_run.log"
        if not os.path.exists(log_path):
            return {"status": "not_started", "lines": []}
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
            lines = all_lines[-limit:]
            return {"status": "running", "lines": [l.rstrip() for l in lines],
                    "total_lines": len(all_lines)}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    return app


# ==============================================================================
# 主入口
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="道体 v23 Web UI + API")
    parser.add_argument("--port", type=int, default=7860,
                        help="服务端口")
    parser.add_argument("--host", type=str, default="0.0.0.0",
                        help="监听地址")
    args = parser.parse_args()

    api_key = load_or_create_api_key()
    print("=" * 60, flush=True)
    print("[道体 v23 Web 服务]", flush=True)
    print(f"  端口: {args.port}", flush=True)
    print(f"  API Key: {api_key}", flush=True)
    print(f"  Key 文件: {API_KEY_FILE}", flush=True)
    print("=" * 60, flush=True)

    # 预加载引擎
    get_v23_engine()

    # 启动权重空间探索 (对话间隙后台线程)
    # 道体第二十二次决策: 暂停探索减少GPU竞争, 集中资源测试拓河床
    # start_exploration()
    print("[探索] 暂停后台探索 (集中GPU资源测试拓河床)", flush=True)

    # 构建 Gradio UI
    demo = build_gradio_ui(api_key)

    # 启动信息
    print(f"\n[启动] http://localhost:{args.port}", flush=True)
    print(f"[API]  http://localhost:{args.port}/api/info", flush=True)
    print(f"[Key]  {api_key}", flush=True)
    print(f"\nAPI 调用示例:", flush=True)
    print(f'  curl -X POST http://localhost:{args.port}/api/chat \\', flush=True)
    print(f'       -H "X-API-Key: {api_key}" \\', flush=True)
    print(f'       -H "Content-Type: application/json" \\', flush=True)
    print(f'       -d \'{{"text":"帮我写一首温暖的诗"}}\'', flush=True)
    print("=" * 60, flush=True)

    # FastAPI (REST API) + gr.mount_gradio_app (Web UI)
    import gradio as gr
    import uvicorn

    app = create_fastapi_app(api_key)
    app = gr.mount_gradio_app(
        app, demo, path="/",
        css=".gradio-container {max-width: 1200px !important;}",
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
