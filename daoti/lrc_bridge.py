"""
lrc_bridge.py - 道体 ↔ LRC 记忆桥接 (POC 第一阶段·概念验证)
================================================================================
目的: 让道体 (Python 推理引擎) 在表达层向 LRC (Rust MCP 服务) 发起记忆检索,
      把 LRC 返回的文本记忆"拼接到道体的 prompt", 实现"智能联想"。

工程约束 (来自 HCSE 韧性规范):
  - 纯 stdlib (urllib), 零第三方依赖 — 兼容道体部署环境
  - 全部方法失败降级: 任何异常都返回空结果, 绝不抛出 — LRC 挂了不影响道体
  - 超时保护: 默认 3s, 防止检索卡死阻塞道体对话
  - 环境变量门控: DAOTI_LRC_MEMORY=1 才注入 (默认关闭, 保证现有行为零变化)

协议 (对齐 LRC v1 REST API):
  - POST /v1/memories/enrich   双路检索增强 (fast TF-IDF + deep 语义, RRF 融合)
        req: {query, top_k, session_id?, user_id?}
        res: {memories: [{id, content, memory_type, score, bagua_category,
                          importance, topological_depth, version, created_at}],
              fast_path_hits, deep_path_hits, total}
  - POST /v1/memories/remember 写回记忆 (为后续"道体决策→写回 LRC"预留)
        req: {content, memory_type, importance?}
================================================================================
"""

import os
import json
import time
import urllib.request
import urllib.error

# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
DEFAULT_LRC_URL = os.environ.get("LRC_BASE_URL", "http://127.0.0.1:3099")
ENRICH_PATH = "/v1/memories/enrich"
REMEMBER_PATH = "/v1/memories/remember"

# 注入开关: 环境变量 DAOTI_LRC_MEMORY=1 时, 道体表达层注入 LRC 联想记忆
MEMORY_INJECT_ENV = "DAOTI_LRC_MEMORY"


def is_inject_enabled() -> bool:
    """是否启用 LRC 记忆注入 (默认关闭, 保证道体现有行为零变化)。"""
    return os.environ.get(MEMORY_INJECT_ENV, "0") == "1"


# --------------------------------------------------------------------------
# HTTP 客户端 (纯 stdlib, 失败降级)
# --------------------------------------------------------------------------
class LrcClient:
    """道体侧 LRC 记忆检索客户端。所有方法失败均降级返回, 不向上抛异常。"""

    def __init__(self, base_url: str = DEFAULT_LRC_URL, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _post_json(self, path: str, payload: dict):
        """POST JSON, 返回解析后的 dict / None。超时与网络错误均返回 None。"""
        url = self.base_url + path
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return None

    def health(self) -> bool:
        """探测 LRC 是否可连 (用于降级判断, 不抛异常)。"""
        url = self.base_url + "/health"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def search_memories(self, query: str, top_k: int = 5,
                        session_id: str = None, user_id: str = None):
        """检索 LRC 记忆 (双路+RRF)。失败返回空 list。"""
        payload = {"query": query, "top_k": max(1, min(100, top_k))}
        if session_id:
            payload["session_id"] = session_id
        if user_id:
            payload["user_id"] = user_id
        result = self._post_json(ENRICH_PATH, payload)
        if not result or not isinstance(result.get("memories"), list):
            return []
        # 按分数降序, 过滤空内容, 保证返回结构稳定
        mems = [m for m in result["memories"] if m.get("content")]
        mems.sort(key=lambda m: float(m.get("score", 0.0)), reverse=True)
        return mems

    def remember(self, content: str, memory_type: str = "fact",
                 importance: int = 5) -> str | None:
        """写回一条记忆到 LRC (为"道体决策→写回记忆"预留)。失败返回 None。"""
        if not content:
            return None
        payload = {"content": content, "memory_type": memory_type,
                   "importance": max(1, min(10, importance))}
        result = self._post_json(REMEMBER_PATH, payload)
        if not result:
            return None
        return (result.get("memory_id") or result.get("id")
                or result.get("status") or "ok")


# --------------------------------------------------------------------------
# 记忆 → prompt 文本格式化 ("智能联想"的可读片段)
# --------------------------------------------------------------------------
def format_memories_for_prompt(memories, max_items: int = 3,
                               max_chars: int = 600) -> str:
    """把 LRC 检索到的记忆格式化为注入 prompt 的中文片段。

    只保留高相关的 top-max_items, 截断过长内容, 避免污染道体 prompt。
    """
    if not memories:
        return ""
    lines = []
    budget = max_chars
    for m in memories[:max_items]:
        content = (m.get("content") or "").strip()
        if not content:
            continue
        _score = float(m.get("score", 0.0))
        if len(content) > 120:
            content = content[:120] + "…"
        line = f"- [关联度{_score:.2f}] {content}"
        if budget - len(line) < 0:
            break
        lines.append(line)
        budget -= len(line)
    if not lines:
        return ""
    return ("你记忆中与此相关的片段浮现出来 :\n" + "\n".join(lines)
            + "\n借这些记忆的余韵, 让联想自然生发。")


def _builtin_client():
    """模块级共享客户端 (惰性)。"""
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = LrcClient()
    return _CLIENT


_CLIENT = None


def retrieve_associative_memories(query: str, top_k: int = 3,
                                  max_chars: int = 600) -> str:
    """对外便捷入口: 检索 + 格式化, 返回可直接拼进 prompt 的片段。

    任一步失败都返回空串 (降级), 绝不会打断调用方。
    """
    if not query or not query.strip():
        return ""
    mems = _builtin_client().search_memories(query, top_k=top_k)
    if not mems:
        return ""
    return format_memories_for_prompt(mems, max_items=top_k, max_chars=max_chars)


# --------------------------------------------------------------------------
# 自测 (python lrc_bridge.py)
# --------------------------------------------------------------------------
def _self_test():
    print("=" * 60)
    print("[lrc_bridge] 自测 · 道体 ↔ LRC 桥接 (POC)")
    print(f"  LRC: {DEFAULT_LRC_URL}")
    print(f"  注入开关 DAOTI_LRC_MEMORY: {os.environ.get(MEMORY_INJECT_ENV, '0')}")
    print("=" * 60)

    client = _builtin_client()
    t0 = time.time()
    ok = client.health()
    print(f"\n[1] LRC 健康检查: {'OK' if ok else 'FAIL'} ({time.time()-t0:.2f}s)")

    test_queries = ["道体 智能联想 记忆注入 跨语言架构",
                    "如何处理 推理引擎 命中率 不确定"]
    for qi, q in enumerate(test_queries, 1):
        print(f"\n[检索 {qi}] query={q!r}")
        t0 = time.time()
        mems = client.search_memories(q, top_k=3)
        dt = time.time() - t0
        print(f"  返回 {len(mems)} 条 (用时 {dt:.2f}s)")
        frag = format_memories_for_prompt(mems)
        if frag:
            print("  ---- 注入片段 ----")
            print(frag)
        else:
            print("  (无返回, 降级为空)")

    print("\n" + "=" * 60)
    print("[完成] 若上面能检索出记忆, 桥接即可用 (health FAIL 且无返回=LRC未启动)。")
    print(f"启用注入: 运行道体前设置环境变量 {MEMORY_INJECT_ENV}=1")


if __name__ == "__main__":
    _self_test()