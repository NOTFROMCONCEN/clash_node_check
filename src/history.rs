use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistorySnapshot {
    pub unix_ts: u64,
    pub total: usize,
    pub tcp_alive: usize,
    pub strict_pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub tls_pass: usize,
    pub udp_pass: usize,
    pub ttfb_pass: usize,
    pub avg_security_score: u8,
}

impl HistorySnapshot {
    pub fn timestamp_label(&self) -> String {
        format!("Unix {}", self.unix_ts)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SnapshotStore {
    snapshots: Vec<HistorySnapshot>,
}

pub fn load_snapshots() -> Vec<HistorySnapshot> {
    let Some(path) = snapshots_file_path() else {
        return Vec::new();
    };
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str::<SnapshotStore>(&content)
        .map(|store| store.snapshots)
        .unwrap_or_default()
}

pub fn append_snapshot(snapshot: HistorySnapshot, keep_limit: usize) -> Result<usize, String> {
    let path = snapshots_file_path().ok_or_else(|| "无法定位历史目录".to_owned())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("创建历史目录失败 {}: {error}", parent.display()))?;
    }

    let mut snapshots = load_snapshots();
    snapshots.push(snapshot);
    if keep_limit > 0 && snapshots.len() > keep_limit {
        let drain_count = snapshots.len().saturating_sub(keep_limit);
        snapshots.drain(0..drain_count);
    }

    let store = SnapshotStore { snapshots };
    let payload =
        serde_json::to_string_pretty(&store).map_err(|error| format!("序列化历史失败: {error}"))?;
    fs::write(&path, payload)
        .map_err(|error| format!("写入历史文件失败 {}: {error}", path.display()))?;
    Ok(store.snapshots.len())
}

pub fn build_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn snapshots_file_path() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join("dist").join("history").join("snapshots.json"))
}
