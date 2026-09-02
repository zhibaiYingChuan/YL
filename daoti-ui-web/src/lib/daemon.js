// 玄镜 · daemon 客户端（R8 单一数据源）
// 玄镜不采集三系统状态、不执行任何系统命令（Bun 红线），仅经 HTTP/SSE 消费 daemon。
// 读端点（GET）只读无需鉴权；写端点（POST /api/heal、/api/run、/api/b1/run）需
// 携带 X-Daoti-Token（S2：防本地任意进程 / 跨站副作用触发执行）。
// daemon 默认回环地址与端口见 daoti-daemon::DaemonArgs（默认 17890）。

const DAEMON_ORIGIN = 'http://127.0.0.1:17890';

// 写端点鉴权 token 缓存（S2）：仅在 Tauri 宿主可读（经 get_daemon_token 命令读取本地
// ~/.daoti/daemon.token，与 daemon 共用同一文件）。浏览器 dev server 无本地文件访问
// 能力，写操作将因缺失 token 返回 401（仅读端点可用）。
let writeTokenCache = null;

/**
 * 解析写端点鉴权 token：
 * - Tauri 环境：经 IPC 调用 get_daemon_token 读取本地 token（与 daemon 共用同一文件）。
 * - 浏览器 dev server：无本地文件访问能力，返回 null（写端点会 401，仅读端点可用）。
 * @returns {Promise<string|null>}
 */
async function resolveWriteToken() {
  if (writeTokenCache) return writeTokenCache;
  const isTauri = typeof window !== 'undefined' && window.__TAURI_INTERNALS__;
  if (!isTauri) return null;
  try {
    const { invoke } = window.__TAURI_INTERNALS__;
    writeTokenCache = await invoke('get_daemon_token');
    return writeTokenCache;
  } catch {
    return null;
  }
}

/** 构造写端点请求头：Content-Type + 可选的 X-Daoti-Token。 */
async function writeHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  const token = await resolveWriteToken();
  if (token) headers['X-Daoti-Token'] = token;
  return headers;
}

/** 健康检查：GET /api/health（P2-2 返回 JSON 结构化指标）
 * @returns {Promise<object>} { status, event_bus_sent, event_bus_dropped, mpsc_dropped }
 */
export async function fetchHealth() {
  const res = await fetch(`${DAEMON_ORIGIN}/api/health`);
  if (!res.ok) throw new Error(`health status ${res.status}`);
  return res.json();
}

/**
 * 快照回魂列表：GET /api/snapshots
 * 返回轻量元数据数组 [{ ts, metal, wood, water, verdict }]，按时间倒序。
 */
export async function fetchSnapshots() {
  const res = await fetch(`${DAEMON_ORIGIN}/api/snapshots`);
  if (!res.ok) throw new Error(`snapshots status ${res.status}`);
  return res.json();
}

/**
 * 单条快照详情：GET /api/snapshots/{ts}
 * 返回完整 FusionState JSON；快照不存在/损坏时抛错。
 * @param {number} ts 快照时间戳
 */
export async function fetchSnapshot(ts) {
  const res = await fetch(`${DAEMON_ORIGIN}/api/snapshots/${ts}`);
  if (!res.ok) throw new Error(`snapshot ${ts} status ${res.status}`);
  return res.json();
}

/**
 * 历史事件拉取：GET /api/events/history?before_seq=&limit=（P0-5 断线重连补回放）
 *
 * @param {object} params - { beforeSeq: number|undefined, limit: number|undefined }
 * @returns {Promise<Array>} 历史事件数组（倒序，最新在前）
 */
export async function fetchHistory({ beforeSeq, limit } = {}) {
  const params = new URLSearchParams();
  if (beforeSeq != null) params.set('before_seq', beforeSeq);
  if (limit != null) params.set('limit', limit);
  const qs = params.toString();
  const url = `${DAEMON_ORIGIN}/api/events/history${qs ? `?${qs}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`history status ${res.status}`);
  return res.json();
}

/**
 * P1-6 快照对比：GET /api/snapshots/diff?ts1=&ts2=
 *
 * @param {number} ts1 第一个快照时间戳
 * @param {number} ts2 第二个快照时间戳
 * @returns {Promise<object>} { ts1, ts2, health_before, health_after, field_changes }
 */
export async function fetchSnapshotDiff(ts1, ts2) {
  const res = await fetch(
    `${DAEMON_ORIGIN}/api/snapshots/diff?ts1=${ts1}&ts2=${ts2}`,
  );
  if (!res.ok) throw new Error(`diff status ${res.status}`);
  return res.json();
}

/**
 * P0-7 一键修复：POST /api/heal
 *
 * 触发一次完整诊断-修复闭环，返回四类结局。
 * @returns {Promise<object>} { outcome, icon, decision, results, health, verdict, recovery }
 */
export async function fetchHeal() {
  const res = await fetch(`${DAEMON_ORIGIN}/api/heal`, {
    method: 'POST',
    headers: await writeHeaders(),
  });
  if (!res.ok) throw new Error(`heal status ${res.status}`);
  return res.json();
}

/**
 * B0 跨平台运行：POST /api/run
 *
 * 提交二进制文件路径和参数到 daemon 执行。
 * @param {string} path 二进制文件路径
 * @param {string[]} [args] 命令行参数
 * @returns {Promise<object>} { status, format, mode, exit_code, stdout, stderr }
 */
export async function submitCrossRun(path, args = []) {
  const res = await fetch(`${DAEMON_ORIGIN}/api/run`, {
    method: 'POST',
    headers: await writeHeaders(),
    body: JSON.stringify({ path, args }),
  });
  if (!res.ok) {
    // 透传 daemon 返回的结构化错误（如「文件不存在」），而非仅笼统的 HTTP 状态码。
    let detail = '';
    try {
      const body = await res.json();
      if (body && body.error) detail = `：${body.error}`;
    } catch {
      // body 非 JSON 时忽略，保留纯状态码
    }
    throw new Error(`run status ${res.status}${detail}`);
  }
  return res.json();
}

/**
 * 订阅 daemon 事件流（SSE）。
 *
 * 连接策略（解决 daemon 离线时控制台高频刷 `ERR_CONNECTION_REFUSED` 的问题）：
 * - 连接前先轻量探测 `/api/health`，离线则直接进入**指数退避**等待，不盲目发起 SSE
 *   fetch（避免每次失败都在控制台刷一条连接错误）。
 * - 重连使用指数退避 `2s → 4s → … → 60s` 封顶，连接成功后重置为初始间隔；
 *   这样 daemon 短时重启/离线时，控制台不再高频堆叠错误日志。
 * - 页面不可见（后台标签页）时暂停探测，避免在用户不关注时持续刷网络错误；
 *   重新可见时立即恢复感知。
 * @param {(evt:object)=>void} onEvent 收到事件回调（DaotiEvent）
 * @param {(err:Error)=>void} onError 连接错误回调
 * @param {()=>void} [onConnected] 可选的首次/重连成功回调（用于设置初始健康态，
 *   替代 App.jsx 中脆弱的独立 fetchHealth，避免页面加载时 daemon 未就绪就报
 *   ERR_CONNECTION_REFUSED 且永不重试）
 * @param {(skipped:number)=>void} [onLagged] P1-1 慢消费者丢事件回调，
 *   参数 n 为丢失条数，前端可据此调用 fetchHistory 补拉
 * @returns {()=>void} 取消订阅函数
 */
export function subscribeEvents(onEvent, onError, onConnected, onLagged) {
  const controller = new AbortController();
  let active = true;
  let delayMs = 2000; // 初始退避间隔
  const MAX_DELAY = 60000; // 退避上限（60s，进一步压低离线时的错误频率）

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  // 页面可见时立即恢复，隐藏时暂停（后台标签页不探测，避免刷新连贯性错误）
  const waitVisible = async () => {
    while (active && document.hidden) {
      await sleep(1000);
    }
  };

  (async () => {
    while (active) {
      await waitVisible(); // 页面隐藏时原地等待，不发起任何请求
      // 连接前健康探测：离线时走退避，避免直接发起 SSE 触发高频连接错误
      let healthy = false;
      try {
        const r = await fetch(`${DAEMON_ORIGIN}/api/health`, { signal: controller.signal });
        healthy = r.ok;
      } catch {
        healthy = false;
      }
      if (!healthy) {
        if (active) onError(new Error('daemon 离线'));
        await sleep(delayMs);
        delayMs = Math.min(delayMs * 2, MAX_DELAY);
        continue;
      }

      try {
        const res = await fetch(`${DAEMON_ORIGIN}/api/events`, {
          signal: controller.signal,
          headers: { Accept: 'text/event-stream' },
        });
        if (!res.ok || !res.body) throw new Error(`events status ${res.status}`);
        delayMs = 2000; // 连接成功，重置退避
        onConnected?.(); // 通知 App 健康态已建立

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (active) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          // SSE 数据按空行分隔
          const blocks = buffer.split('\n\n');
          buffer = blocks.pop() ?? '';
          for (const block of blocks) {
            const dataLine = block
              .split('\n')
              .find((l) => l.startsWith('data:'));
            if (!dataLine) continue;
            try {
              const evt = JSON.parse(dataLine.slice(5).trim());
              // P1-1：慢消费者丢事件 → 通知前端补拉历史
              if (evt.type === 'lagged') {
                onLagged?.(evt.skipped);
              } else {
                onEvent(evt);
              }
            } catch {
              /* 忽略无法解析的帧 */
            }
          }
        }
      } catch (err) {
        if (active) onError(err);
        // 断线后指数退避重连
        await sleep(delayMs);
        delayMs = Math.min(delayMs * 2, MAX_DELAY);
      }
    }
  })();

  return () => {
    active = false;
    controller.abort();
  };
}