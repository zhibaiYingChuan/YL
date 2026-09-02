//! 事件历史落盘 (eventlog)
//!
//! P0-5 历史时间轴 HTTP 拉取接口：将事件总线的每一条 `DaotiEvent` 以 JSONL
//! （每行一条 JSON）追加写入 `~/.daoti/events/daoti_events.jsonl`，供历史
//! 接口分页回读。daemon 重启后历史仍可读取（持久化）。

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use daoti_common::DaotiEvent;

/// 事件落盘器：线程安全（内部 Mutex），追加写入 JSONL，支持倒序分页读取。
pub struct EventLog {
    /// JSONL 文件路径（如 `~/.daoti/events/daoti_events.jsonl`）
    path: PathBuf,
    /// 最大保留条数（超过则日志 warning，暂不自动截断）
    _max_events: u64,
    /// 文件句柄互斥（只写不读，读历史时用独立临时句柄）
    writer: Mutex<File>,
}

impl EventLog {
    /// 创建事件日志。目录不存在时自动创建；文件不存在时自动新建。
    pub fn open(dir: &Path, max_events: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("daoti_events.jsonl");
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(EventLog {
            path,
            _max_events: max_events,
            writer: Mutex::new(file),
        })
    }

    /// 追加一条事件到 JSONL 文件。非阻塞；IO 失败时返回错误。
    pub fn append(&self, ev: &DaotiEvent) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(ev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let mut w = self.writer.lock().unwrap();
        w.write_all(&line)?;
        w.flush()?;
        Ok(())
    }

    /// 分页读取历史事件（倒序：最新的在前）。
    ///
    /// - `before_seq`: 可选锚点序号，只返回序号 < before_seq 的事件。
    /// - `limit`: 最多返回条数（上限）。
    ///
    /// 实现：从文件末尾逐行反向读取，直到收集够 limit 条或到达 before_seq 边界。
    /// 日志文件异常（不存在/不可读）返回空列表，不 panic。
    pub fn history(&self, before_seq: Option<u64>, limit: u64) -> Vec<DaotiEvent> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        let file_len = meta.len();
        if file_len == 0 {
            return Vec::new();
        }

        let mut reader = BufReader::new(file);
        // 从文件末尾开始逐行反向读取
        // 策略：用固定缓冲区从尾部逐块前移，解析行
        let mut results: Vec<DaotiEvent> = Vec::new();
        let mut pos = file_len;

        // 每次回退读取 8KB 的块
        let mut buf = Vec::new();
        while pos > 0 && (results.len() as u64) < limit {
            let chunk_size = std::cmp::min(pos, 8192);
            pos -= chunk_size;
            reader.seek(SeekFrom::Start(pos)).ok();
            buf.resize(chunk_size as usize, 0);
            if reader.read_exact(&mut buf).is_err() {
                break;
            }
            // 解析块中的行（从后往前）
            let text = String::from_utf8_lossy(&buf);
            let lines: Vec<&str> = text.lines().collect();
            for line in lines.into_iter().rev() {
                if (results.len() as u64) >= limit {
                    break;
                }
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(ev) = serde_json::from_str::<DaotiEvent>(line) {
                    // 如果指定了 before_seq，过滤
                    if let Some(bs) = before_seq {
                        if ev.seq >= bs {
                            continue;
                        }
                    }
                    results.push(ev);
                }
            }
        }

        // 结果已按倒序（最新在前），但块级读取可能打乱顺序，需要排序
        results.sort_by_key(|e| std::cmp::Reverse(e.seq));
        results.truncate(limit as usize);
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daoti_common::EventKind;

    fn temp_eventlog() -> (tempfile::TempDir, EventLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::open(dir.path(), 100).unwrap();
        (dir, log)
    }

    #[test]
    fn append_and_read_back() {
        let (_dir, log) = temp_eventlog();

        let e1 = DaotiEvent::new(0, EventKind::Sense, "感 · 金");
        let e2 = DaotiEvent::new(0, EventKind::Infer, "推演").with_detail("艮上坎下");
        let e3 = DaotiEvent::new(0, EventKind::Execute, "执行");

        // 写入时 seq 由 EventBus 分配，这里手动设置用于测试
        for (i, e) in [&e1, &e2, &e3].iter().enumerate() {
            let mut ev = (*e).clone();
            ev.seq = i as u64;
            log.append(&ev).unwrap();
        }

        let history = log.history(None, 10);
        assert_eq!(history.len(), 3);
        // 最新在前
        assert_eq!(history[0].seq, 2);
        assert_eq!(history[1].seq, 1);
        assert_eq!(history[2].seq, 0);
    }

    #[test]
    fn history_respects_before_seq() {
        let (_dir, log) = temp_eventlog();
        for i in 0..5u64 {
            let mut ev = DaotiEvent::new(0, EventKind::Sense, "x");
            ev.seq = i;
            log.append(&ev).unwrap();
        }

        // before_seq = 3 → 只返回 seq < 3 的事件（0,1,2）
        let history = log.history(Some(3), 10);
        assert_eq!(history.len(), 3);
        let seqs: Vec<u64> = history.iter().map(|e| e.seq).collect();
        assert!(seqs.contains(&0));
        assert!(seqs.contains(&1));
        assert!(seqs.contains(&2));
        assert!(!seqs.contains(&3));
    }

    #[test]
    fn history_respects_limit() {
        let (_dir, log) = temp_eventlog();
        for i in 0..10u64 {
            let mut ev = DaotiEvent::new(0, EventKind::Sense, "x");
            ev.seq = i;
            log.append(&ev).unwrap();
        }

        let history = log.history(None, 3);
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn empty_log_returns_empty() {
        let (_dir, log) = temp_eventlog();
        assert!(log.history(None, 10).is_empty());
    }
}
