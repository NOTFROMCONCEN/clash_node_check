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
        format_unix_timestamp(self.unix_ts)
    }

    pub fn strict_pass_rate(&self) -> f32 {
        percent(self.strict_pass, self.total)
    }

    pub fn fail_rate(&self) -> f32 {
        percent(self.fail, self.total)
    }

    pub fn tcp_alive_rate(&self) -> f32 {
        percent(self.tcp_alive, self.total)
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

fn percent(value: usize, total: usize) -> f32 {
    if total == 0 {
        0.0
    } else {
        value as f32 * 100.0 / total as f32
    }
}

fn format_unix_timestamp(unix_ts: u64) -> String {
    const SECONDS_PER_DAY: i64 = 86_400;
    let seconds = unix_ts as i64;
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let seconds_of_day = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_unix_timestamp_as_readable_utc_time() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_unix_timestamp(1_717_200_000), "2024-06-01 00:00 UTC");
    }

    #[test]
    fn computes_snapshot_rates() {
        let snapshot = HistorySnapshot {
            unix_ts: 0,
            total: 20,
            tcp_alive: 18,
            strict_pass: 10,
            warn: 8,
            fail: 2,
            tls_pass: 9,
            udp_pass: 6,
            ttfb_pass: 12,
            avg_security_score: 81,
        };

        assert_eq!(snapshot.strict_pass_rate(), 50.0);
        assert_eq!(snapshot.fail_rate(), 10.0);
        assert_eq!(snapshot.tcp_alive_rate(), 90.0);
    }
}
