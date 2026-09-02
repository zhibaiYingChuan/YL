import React from 'react';
import { fetchSnapshots, fetchSnapshot, fetchSnapshotDiff, fetchHistory, fetchHeal, submitCrossRun, subscribeEvents } from './lib/daemon.js';

// 三气归属：金属 Windows，木属 WSL，水属 Docker
const SYS = {
  windows: { ring: 'win', badge: 'gold', label: 'Windows', xing: '金' },
  wsl2: { ring: 'wsl', badge: 'wood', label: 'WSL2', xing: '木' },
  docker: { ring: 'docker', badge: 'water', label: 'Docker', xing: '水' },
};

const KIND_LABEL = { Sense: '感知', Infer: '推演', Decide: '调度', Execute: '执行', Result: '结果', Learn: '学习' };
const KIND_ICON = { Sense: '☰', Infer: '☷', Decide: '☵', Execute: '☲', Result: '☯', Learn: '♻' };

function fmtTime(ts) {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
}

function RingCircle({ sys, state }) {
  const conf = SYS[sys];
  const dot = state == null ? 'muted' : state === 'ok' ? 'ok' : state === 'warn' ? 'warn' : 'err';
  return (
    <div className="yl-ring">
      <div className={`yl-ring-circle ${conf.ring}`}>
        <span className={`yl-dot ${dot}`} />
      </div>
      <div className="yl-ring-name">{conf.label}</div>
      <span className={`yl-badge ${conf.badge}`}>{conf.xing}</span>
    </div>
  );
}

function Dashboard({ events, health }) {
  const records = events.slice(-3).reverse();
  return (
    <div className="yl-grid yl-grid-col2">
      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />三气归元图</div>
        <div className="yl-rings">
          <RingCircle sys="windows" state={health ? 'ok' : null} />
          <RingCircle sys="wsl2" state={health ? 'ok' : null} />
          <RingCircle sys="docker" state={health ? 'ok' : null} />
        </div>
      </div>
      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />近期推演轨迹</div>
        <div className="yl-records">
          {records.length === 0 && <div className="yl-tl-body">暂无推演记录，等待道体感应……</div>}
          {records.map((e) => (
            <div className="yl-record" key={e.seq}>
              <span className="yl-tl-time">{fmtTime(e.ts_ms)}</span>
              <span className="yl-badge wood">{KIND_ICON[e.kind] || '☰'}</span>
              <span className="yl-tl-body">{e.title}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/** P0-2 首次运行设置横幅：daemon 不可达时显示引导 */
function SetupBanner({ doSetup, loading }) {
  return (
    <div className="yl-card yl-setup-banner">
      <div className="yl-card-title"><span className="yl-dot warn" />首次运行 · 环境探测</div>
      <p className="yl-tl-body">
        尚未检测到道体守护进程。点击下方按钮自动探测三系统（Windows/WSL2/Docker）
        并生成配置文件，完成后即可感应三气。
      </p>
      <button
        type="button"
        className="yl-heal-btn"
        onClick={doSetup}
        disabled={loading}
      >
        {loading ? '探测中…' : '☯ 开始探测'}
      </button>
    </div>
  );
}

function Timeline({ events }) {
  return (
    <div className="yl-card">
      <div className="yl-card-title"><span className="yl-dot ok" />推演时间轴</div>
      <div className="yl-timeline">
        {events.length === 0 && <div className="yl-tl-body">尚未收到事件流……</div>}
        {events.map((e) => (
          <div className="yl-tl-item" key={e.seq}>
            <span className="yl-tl-time">{fmtTime(e.ts_ms)}</span>
            <span>{KIND_ICON[e.kind] || '☯'}</span>
            <div className="yl-tl-body">
              <strong>[{KIND_LABEL[e.kind] || e.kind}]</strong> {e.title}
              {e.detail && <div className="yl-tl-body">{e.detail}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Settings({ events }) {
  const last = events[events.length - 1];
  const verdict = last ? `${KIND_ICON[last.kind] || '☯'} ${last.title}` : '道体潜龙勿用，静待感应';
  return (
    <div className="yl-grid">
      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />道体判词</div>
        <div className="yl-verdict">{verdict}</div>
        <p className="yl-tl-body">此处为归元配置占位：三库镇物将在后续迭代接入。</p>
      </div>
    </div>
  );
}

/** P0-7 一键修复面板：调用 daemon /api/heal，展示四类结局 */
function HealPanel() {
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState(null);
  const [err, setErr] = React.useState(null);

  const doHeal = async () => {
    setLoading(true);
    setErr(null);
    setResult(null);
    try {
      const r = await fetchHeal();
      setResult(r);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  // 结局样式映射
  const tone = result
    ? result.outcome === '已修复' || result.outcome === '无需干预'
      ? 'ok'
      : result.outcome === '部分成功'
        ? 'warn'
        : 'err'
    : 'muted';

  return (
    <div className="yl-grid">
      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />一键归元 · 修复闭环</div>
        <p className="yl-tl-body">
          推演三气，疏通滞涩。点击下方按钮触发完整诊断-修复闭环（感知→推演→执行→二次感知）。
        </p>

        <button
          type="button"
          className="yl-heal-btn"
          onClick={doHeal}
          disabled={loading}
        >
          {loading ? '推演中…' : '☯ 开始修复'}
        </button>

        {err && (
          <div className="yl-heal-result yl-heal-err">
            <span className="yl-heal-icon">❌</span>
            <span>守护未响应：{err}</span>
          </div>
        )}
        {result && (
          <div className={`yl-heal-result yl-heal-${tone}`}>
            <div className="yl-heal-head">
              <span className="yl-heal-icon">{result.icon}</span>
              <span className="yl-heal-outcome">{result.outcome}</span>
            </div>

            <div className="yl-heal-bars">
              <HealthBar label="windows" xing="金" value={result.health.metal} />
              <HealthBar label="wsl2" xing="木" value={result.health.wood} />
              <HealthBar label="docker" xing="水" value={result.health.water} />
            </div>

            <div className="yl-heal-verdict">{result.verdict}</div>

            {result.results && result.results.length > 0 && (
              <div className="yl-heal-details">
                {result.results.map((r, i) => (
                  <div key={i} className={`yl-heal-detail ${r.success ? 'yl-heal-ok' : 'yl-heal-err'}`}>
                    <span>{r.success ? '✅' : '❌'}</span>
                    <span className="yl-heal-detail-target">[{r.target}]</span>
                    <span>{r.command}</span>
                    {!r.success && r.stderr && (
                      <div className="yl-heal-detail-msg">{r.stderr}</div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {result.recovery && (
              <div className="yl-heal-recovery">
                <div className="yl-heal-recovery-title">── 恢复路径 ──</div>
                {result.recovery.split('\n').map((line, i) => (
                  <div key={i} className="yl-heal-recovery-line">{line}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/** B0 道体·通：跨平台运行面板
 *  提交二进制路径到 daemon，由道体自动识别格式并择路执行。 */
function CrossRunPanel() {
  const [path, setPath] = React.useState('');
  const [args, setArgs] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState(null);
  const [err, setErr] = React.useState(null);

  const doRun = async () => {
    if (!path.trim()) return;
    setLoading(true); setErr(null); setResult(null);
    try {
      const argList = args.trim() ? args.trim().split(/\s+/) : [];
      const r = await submitCrossRun(path.trim(), argList);
      setResult(r);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  // 打开系统文件选择对话框，取选中文件的绝对路径填入输入框。
  // 仅在 Tauri 宿主内可用（浏览器 dev server 无本地文件访问能力）。
  const pickFile = async () => {
    const tauri = typeof window !== 'undefined' && window.__TAURI_INTERNALS__;
    if (!tauri) return;
    try {
      const p = await tauri.invoke('pick_binary');
      if (p) setPath(p);
    } catch {
      /* 取消选择或宿主不支持时忽略 */
    }
  };

  return (
    <div className="yl-grid">
      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />道体·通 · 跨平台运行</div>
        <p className="yl-tl-body">
          输入二进制文件的绝对路径（或用右侧「选择文件」定位），道体自动识灵并择路执行。支持 ELF/PE 格式。
        </p>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginTop: '16px' }}>
          <input
            type="text"
            placeholder="二进制文件的绝对路径，如 C:\Users\you\hello.elf"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && doRun()}
            disabled={loading}
            style={{ flex: 1, padding: '8px 12px', background: 'var(--yl-bg-primary)', border: '1px solid var(--yl-border-subtle)', borderRadius: 'var(--yl-radius-sm)', color: 'var(--yl-text)' }}
          />
          <button
            type="button"
            className="yl-heal-btn"
            onClick={pickFile}
            disabled={loading}
          >
            选择文件
          </button>
          <input
            type="text"
            placeholder="参数（可选，空格分隔）"
            value={args}
            onChange={(e) => setArgs(e.target.value)}
            disabled={loading}
            style={{ flex: 1, padding: '8px 12px', background: 'var(--yl-bg-primary)', border: '1px solid var(--yl-border-subtle)', borderRadius: 'var(--yl-radius-sm)', color: 'var(--yl-text)' }}
          />
          <button
            type="button"
            className="yl-heal-btn"
            onClick={doRun}
            disabled={loading || !path.trim()}
          >
            {loading ? '运行中…' : '☯ 道体·通'}
          </button>
        </div>

        {err && (
          <div className="yl-heal-result yl-heal-err" style={{ marginTop: '16px' }}>
            <span className="yl-heal-icon">❌</span>
            <span>道体难行：{err}</span>
          </div>
        )}

        {result && (
          <div className="yl-heal-result yl-heal-ok" style={{ marginTop: '16px' }}>
            <div className="yl-heal-head">
              <span className="yl-heal-icon">☯</span>
              <span className="yl-heal-outcome">
                已归元 · {result.format} · {result.mode}
              </span>
              <span style={{ marginLeft: 'auto', color: 'var(--yl-muted)', fontSize: '12px' }}>
                退出码 {result.exit_code}
              </span>
            </div>
            {result.stdout && (
              <div style={{ marginTop: '12px' }}>
                <div style={{ color: 'var(--yl-gold)', fontSize: '12px', marginBottom: '4px' }}>── 灵归 ──</div>
                <pre style={{
                  background: 'var(--yl-bg-primary)',
                  padding: '12px',
                  borderRadius: 'var(--yl-radius-sm)',
                  fontSize: '12px',
                  fontFamily: 'var(--yl-font-mono)',
                  color: 'var(--yl-text)',
                  overflowX: 'auto',
                  maxHeight: '300px',
                  overflowY: 'auto',
                }}>
                  {result.stdout}
                </pre>
              </div>
            )}
            {result.stderr && (
              <div style={{ marginTop: '8px' }}>
                <span style={{ color: 'var(--yl-crimson)', fontSize: '12px' }}>stderr:</span>
                <pre style={{
                  background: 'var(--yl-bg-primary)',
                  padding: '8px',
                  borderRadius: 'var(--yl-radius-sm)',
                  fontSize: '12px',
                  color: 'var(--yl-crimson)',
                  overflowX: 'auto',
                  maxHeight: '150px',
                  overflowY: 'auto',
                }}>
                  {result.stderr}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// 三系统五行色（复用 SYS 徽章）
const SYS_XING = { windows: '金', wsl2: '木', docker: '水' };
const SYS_BADGE = { windows: 'gold', wsl2: 'wood', docker: 'water' };

function fmtTsFull(ts) {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
}

function HealthBar({ label, xing, value }) {
  const pct = Math.round((value ?? 0) * 100);
  const tone = value >= 0.9 ? 'ok' : value < 0.5 ? 'err' : 'warn';
  return (
    <div className="yl-snap-bar">
      <span className={`yl-badge ${SYS_BADGE[label]}`}>{xing}</span>
      <span className="yl-snap-bar-label">{label}</span>
      <div className="yl-snap-bar-track"><div className={`yl-snap-bar-fill ${tone}`} style={{ width: `${pct}%` }} /></div>
      <span className="yl-snap-bar-num">{pct}%</span>
    </div>
  );
}

/** 快照回魂面板：快照列表 + 回放详情 + P1-6 对比（仅只读消费 daemon） */
function Snapshot({ health }) {
  const [metas, setMetas] = React.useState(null);
  const [err, setErr] = React.useState(null);
  const [selectedTs, setSelectedTs] = React.useState(null);
  const [detail, setDetail] = React.useState(null);
  const [detailErr, setDetailErr] = React.useState(null);
  // P1-6 对比
  const [diffTs, setDiffTs] = React.useState(null);
  const [diffResult, setDiffResult] = React.useState(null);
  const [diffErr, setDiffErr] = React.useState(null);

  // 加载快照列表
  React.useEffect(() => {
    let active = true;
    fetchSnapshots()
      .then((list) => { if (active) { setMetas(list); setErr(null); } })
      .catch((e) => { if (active) { setMetas([]); setErr(e.message); } });
    return () => { active = false; };
  }, []);

  // 选中某条快照时加载详情
  React.useEffect(() => {
    if (selectedTs == null) { setDetail(null); setDetailErr(null); return; }
    let active = true;
    setDetail(null); setDetailErr(null);
    fetchSnapshot(selectedTs)
      .then((d) => { if (active) setDetail(d); })
      .catch((e) => { if (active) setDetailErr(e.message); });
    return () => { active = false; };
  }, [selectedTs]);

  return (
    <div className="yl-grid yl-grid-col2">
      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />快照回魂 · 列表</div>
        {err && <div className="yl-tl-body" style={{ color: 'var(--yl-crimson)' }}>快照读取失败：{err}</div>}
        {!err && metas == null && <div className="yl-tl-body">正在感应快照……</div>}
        {!err && metas != null && metas.length === 0 && (
          <div className="yl-tl-body">暂无快照。请先运行 `daoti snapshot` 留存三气之相。</div>
        )}
        {!err && metas != null && metas.length > 0 && (
          <div className="yl-snap-list">
            {metas.map((m) => (
              <button
                type="button"
                key={m.ts}
                className={`yl-snap-item ${selectedTs === m.ts ? 'active' : ''}`}
                onClick={() => setSelectedTs(m.ts)}
              >
                <div className="yl-snap-item-head">
                  <span className="yl-tl-time">{fmtTsFull(m.ts)}</span>
                  <span className="yl-verdict-sm">{m.verdict}</span>
                </div>
                <div className="yl-snap-item-bars">
                  <HealthBar label="windows" xing="金" value={m.metal} />
                  <HealthBar label="wsl2" xing="木" value={m.wood} />
                  <HealthBar label="docker" xing="水" value={m.water} />
                </div>
                {selectedTs != null && selectedTs !== m.ts && (
                  <div className="yl-snap-item-diff" onClick={(e) => {
                    e.stopPropagation();
                    setDiffResult(null); setDiffErr(null);
                    fetchSnapshotDiff(selectedTs, m.ts)
                      .then((r) => setDiffResult(r))
                      .catch((e2) => setDiffErr(e2.message));
                  }}>
                    📊 对比
                  </div>
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="yl-card">
        <div className="yl-card-title"><span className="yl-dot ok" />回放 · 快照详情</div>
        {selectedTs == null && <div className="yl-tl-body">点击左侧快照，回放当场三气之相。</div>}
        {detailErr && <div className="yl-tl-body" style={{ color: 'var(--yl-crimson)' }}>详情读取失败：{detailErr}</div>}
        {detail == null && !detailErr && selectedTs != null && <div className="yl-tl-body">正在回放……</div>}
        {detail && (
          <div className="yl-snap-detail">
            {['windows', 'wsl2', 'docker'].map((sys) => {
              const snap = detail[sys];
              return (
                <div className="yl-snap-detail-sys" key={sys}>
                  <div className="yl-snap-detail-title">
                    <span className={`yl-badge ${SYS_BADGE[sys]}`}>{SYS_XING[sys]}</span>
                    <span>{SYS[sys].label}</span>
                    {snap == null && <span className="yl-tl-body">（不可达）</span>}
                  </div>
                  {snap && (
                    <div className="yl-snap-detail-body">
                      {Object.entries(snap.metrics || {}).map(([k, v]) => (
                        <div key={k} className="yl-snap-detail-row"><span>{k}</span><span>{v}</span></div>
                      ))}
                      {Object.entries(snap.fields || {}).map(([k, v]) => (
                        <div key={k} className="yl-snap-detail-row"><span>{k}</span><span>{v}</span></div>
                      ))}
                      {(!snap.metrics || Object.keys(snap.metrics).length === 0) &&
                       (!snap.fields || Object.keys(snap.fields).length === 0) && (
                        <div className="yl-tl-body">无指标</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* P1-6 快照对比结果 */}
      {diffResult && (
        <div className="yl-card" style={{ marginTop: '24px' }}>
          <div className="yl-card-title"><span className="yl-dot ok" />对比 · 快照差异</div>
          <div className="yl-snap-diff">
            <div style={{ marginBottom: '12px' }}>
              <span className="yl-tl-time">{fmtTsFull(diffResult.ts1)}</span>
              <span style={{ margin: '0 8px', color: 'var(--yl-muted)' }}>→</span>
              <span className="yl-tl-time">{fmtTsFull(diffResult.ts2)}</span>
            </div>
            <div className="yl-heal-bars">
              {[
                { xing: '金', sys: 'windows', before: diffResult.health_before.metal, after: diffResult.health_after.metal },
                { xing: '木', sys: 'wsl2', before: diffResult.health_before.wood, after: diffResult.health_after.wood },
                { xing: '水', sys: 'docker', before: diffResult.health_before.water, after: diffResult.health_after.water },
              ].map((h) => {
                const arrow = h.after > h.before ? '↑' : h.after < h.before ? '↓' : '━';
                const tone = h.after > h.before ? 'ok' : h.after < h.before ? 'err' : 'warn';
                return (
                  <div className="yl-snap-bar" key={h.xing}>
                    <span className={`yl-badge ${SYS_BADGE[h.sys]}`}>{h.xing}</span>
                    <span className="yl-snap-bar-label">{SYS[h.sys].label}</span>
                    <span className={`yl-dot ${tone}`} style={{ margin: '0 8px' }}>{arrow}</span>
                    <span className="yl-snap-bar-num">{Math.round(h.before * 100)}% → {Math.round(h.after * 100)}%</span>
                  </div>
                );
              })}
            </div>
            {diffResult.field_changes.length > 0 && (
              <div style={{ marginTop: '12px' }}>
                <div className="yl-tl-body" style={{ fontWeight: 600, marginBottom: '8px' }}>字段级变化：</div>
                {diffResult.field_changes.map((fc, i) => (
                  <div key={i} className="yl-snap-detail-row">
                    <span className={`yl-badge ${SYS_BADGE[fc.system]}`}>{SYS_XING[fc.system]}</span>
                    <span>{fc.key}</span>
                    <span className="yl-heal-detail">{fc.before} → {fc.after}</span>
                  </div>
                ))}
              </div>
            )}
            {diffResult.field_changes.length === 0 && (
              <div className="yl-tl-body" style={{ marginTop: '12px' }}>两次快照无字段级变化。</div>
            )}
          </div>
        </div>
      )}
      {diffErr && (
        <div className="yl-card" style={{ marginTop: '24px' }}>
          <div className="yl-tl-body" style={{ color: 'var(--yl-crimson)' }}>对比失败：{diffErr}</div>
        </div>
      )}

    </div>
  );
}

const VIEWS = {
  dashboard: { label: '命轮 · 仪表盘', Comp: Dashboard },
  timeline: { label: '推演 · 时间轴', Comp: Timeline },
  snapshot: { label: '回魂 · 快照', Comp: Snapshot },
  crossrun: { label: '道体·通 · 跨平台', Comp: CrossRunPanel },
  heal: { label: '归元 · 修复', Comp: HealPanel },
  settings: { label: '归元 · 配置', Comp: Settings },
};

export default function App() {
  const [view, setView] = React.useState('dashboard');
  const [events, setEvents] = React.useState([]);
  const [health, setHealth] = React.useState(null);
  const [conn, setConn] = React.useState('感应中…');

  // P0-2 首次运行检测：daemon 不可达时显示设置引导
  const [setupNeeded, setSetupNeeded] = React.useState(false);
  const [setupLoading, setSetupLoading] = React.useState(false);
  const [setupDone, setSetupDone] = React.useState(false);

  React.useEffect(() => {
    // 仅在 daemon 持续离线时（非首次加载的短暂探测期）显示设置引导
    const timer = setTimeout(() => {
      if (!health) setSetupNeeded(true);
    }, 8000); // 8 秒后仍无健康信号，提示首次运行
    return () => clearTimeout(timer);
  }, [health]);

  // daemon 上线后隐藏设置引导
  React.useEffect(() => {
    if (health === 'ok') {
      setSetupNeeded(false);
      setSetupDone(false);
    }
  }, [health]);

  const doFirstSetup = async () => {
    setSetupLoading(true);
    // 检测是否在 Tauri 环境（有 __TAURI_INTERNALS__）
    const isTauri = typeof window !== 'undefined' && window.__TAURI_INTERNALS__;
    if (isTauri) {
      try {
        const { invoke } = window.__TAURI_INTERNALS__;
        const result = await invoke('run_setup');
        if (result.success) {
          setSetupDone(true);
          setSetupNeeded(false);
        }
      } catch (e) {
        // Tauri 命令失败时静默降级
      }
    } else {
      // 浏览器 dev 模式：提示手动运行 daoti init
      setSetupDone(true);
    }
    setSetupLoading(false);
  };

  // 订阅 daemon 事件（R8 唯——只读）
  // 健康态由 subscribeEvents 的 onConnected 回调驱动，避免独立
  // fetchHealth 在 daemon 未就绪时报 ERR_CONNECTION_REFUSED 且永不重试。
  // P0-5：连接成功后先拉历史事件再续实时流。
  // P1-1：慢消费者丢事件时自动补拉历史，不再静默丢失。
  React.useEffect(() => {
    const cancel = subscribeEvents(
      (evt) => setEvents((prev) => [...prev, evt].slice(-200)),
      () => setConn('道体离线，重连中…'),
      () => {
        setHealth('ok');
        // 拉取历史事件（最新 100 条），倒序后合并到事件列表前端
        fetchHistory({ limit: 100 })
          .then((history) => {
            if (history && history.length > 0) {
              const chrono = history.slice().reverse();
              setEvents((prev) => {
                const existing = new Set(prev.map((e) => e.seq));
                const merged = prev.slice();
                for (const ev of chrono) {
                  if (!existing.has(ev.seq)) {
                    merged.push(ev);
                    existing.add(ev.seq);
                  }
                }
                return merged.slice(-200);
              });
            }
          })
          .catch(() => {});
      },
      // P1-1 onLagged：慢消费者丢 N 条，自动补拉历史
      (skipped) => {
        setConn((prev) => prev + ` · 已漏 ${skipped} 条，补拉中…`);
        // 以当前最后一条事件的 seq 为锚点拉取历史
        setEvents((prev) => {
          const lastSeq = prev.length > 0 ? prev[prev.length - 1].seq : null;
          if (lastSeq != null) {
            fetchHistory({ beforeSeq: lastSeq, limit: skipped + 10 })
              .then((history) => {
                if (history && history.length > 0) {
                  const chrono = history.slice().reverse();
                  setEvents((prev2) => {
                    const existing = new Set(prev2.map((e) => e.seq));
                    const merged = prev2.slice();
                    for (const ev of chrono) {
                      if (!existing.has(ev.seq)) {
                        merged.push(ev);
                        existing.add(ev.seq);
                      }
                    }
                    return merged.slice(-200);
                  });
                }
                setConn((prevC) => prevC.replace(/ · 已漏.*$/, ''));
              })
              .catch(() => {
                setConn((prevC) => prevC.replace(/ · 已漏.*$/, ''));
              });
          }
          return prev;
        });
      },
    );
    return cancel;
  }, []);

  React.useEffect(() => {
    if (events.length) setConn(`道体在线 · 已收 ${events.length} 条事件 · 最新 ${fmtTime(events[events.length - 1].ts_ms)}`);
  }, [events]);

  const { label, Comp } = VIEWS[view];

  return (
    <div className="yl-layout">
      <nav className="yl-nav">
        <div className="yl-brand">☯ 驭灵 · 玄镜</div>
        {Object.entries(VIEWS).map(([key, v]) => (
          <button
            type="button"
            key={key}
            className={`yl-nav-item ${key === view ? 'active' : ''}`}
            onClick={() => setView(key)}
          >
            {v.label}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <span className="yl-tl-body">玄镜只读 daemon · 零系统命令</span>
      </nav>
      <main className="yl-main">
        {setupNeeded && !setupDone && (
          <SetupBanner doSetup={doFirstSetup} loading={setupLoading} />
        )}
        {setupDone && !health && (
          <div className="yl-card yl-setup-banner" style={{ borderColor: 'var(--yl-cyan)' }}>
            <div className="yl-card-title"><span className="yl-dot ok" />环境已探测</div>
            <p className="yl-tl-body">
              配置已生成至 ~/.daoti.toml。请在终端运行 <code>daoti daemon start</code> 启动守护进程，
              或等待守护进程自动启动后刷新页面。
            </p>
          </div>
        )}
        <h2 style={{ marginBottom: 20, letterSpacing: '0.05em' }}>{label}</h2>
        <Comp events={events} health={health} />
      </main>
      <footer className="yl-status">
        <span className={`yl-dot ${health ? 'ok' : conn.startsWith('道体离线') ? 'err' : 'warn'}`} />
        <span>{health ? '道体已感应' : '道体离线'}</span>
        <span>{conn}</span>
      </footer>
    </div>
  );
}