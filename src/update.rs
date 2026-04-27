use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use serde::{Deserialize, Serialize};

pub const GITHUB_OWNER: &str = "NOTFROMCONCEN";
pub const GITHUB_REPO: &str = "clash_node_check";

const UPDATE_CACHE_TTL_SECS: u64 = 6 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub current_version: String,
    pub latest_version: String,
    pub release_page: String,
    pub download_url: Option<String>,
    pub asset_name: Option<String>,
    pub notes: Option<String>,
    pub published_at: Option<String>,
    pub update_available: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedReleaseInfo {
    checked_at_secs: u64,
    latest_version: String,
    release_page: String,
    download_url: Option<String>,
    asset_name: Option<String>,
    notes: Option<String>,
    published_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedAtomRelease {
    tag: String,
    release_page: String,
    published_at: Option<String>,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn release_repository_slug() -> &'static str {
    "NOTFROMCONCEN/clash_node_check"
}

pub fn release_repository_url() -> String {
    format!("https://github.com/{}/{}", GITHUB_OWNER, GITHUB_REPO)
}

pub fn check_latest_release() -> Result<ReleaseInfo, String> {
    if let Some(cached) = load_cached_release() {
        return Ok(cached);
    }

    let user_agent = format!("clash-node-checker/{}", current_version());
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("创建更新检查客户端失败：{error}"))?;

    let release = match fetch_release_via_latest_redirect(&client, &user_agent) {
        Ok(release) => release,
        Err(primary_error) => {
            let fallback =
                fetch_release_via_atom(&client, &user_agent).map_err(|fallback_error| {
                    format!(
                        "更新检查失败：latest 重定向失败（{}）；atom 兜底失败（{}）",
                        primary_error, fallback_error
                    )
                })?;
            fallback
        }
    };

    save_cached_release(&release);
    Ok(release)
}

fn fetch_release_via_latest_redirect(
    client: &Client,
    user_agent: &str,
) -> Result<ReleaseInfo, String> {
    let latest_url = format!(
        "https://github.com/{}/{}/releases/latest",
        GITHUB_OWNER, GITHUB_REPO
    );

    let response = client
        .get(latest_url)
        .header(USER_AGENT, user_agent)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("请求 GitHub Release latest 页面失败：{error}"))?;

    let release_page = response.url().to_string();
    let latest_tag = extract_tag_from_release_path(response.url().path())
        .ok_or_else(|| format!("无法从 latest 跳转地址解析版本标签：{}", response.url()))?;
    build_release_info(&latest_tag, release_page, None, None, None, None)
}

fn fetch_release_via_atom(client: &Client, user_agent: &str) -> Result<ReleaseInfo, String> {
    let atom_url = format!(
        "https://github.com/{}/{}/releases.atom",
        GITHUB_OWNER, GITHUB_REPO
    );

    let atom = client
        .get(atom_url)
        .header(USER_AGENT, user_agent)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("请求 releases.atom 失败：{error}"))?
        .text()
        .map_err(|error| format!("读取 releases.atom 响应失败：{error}"))?;

    let parsed = parse_latest_release_from_atom(&atom)
        .ok_or_else(|| "无法从 releases.atom 解析最新版本".to_owned())?;

    build_release_info(
        &parsed.tag,
        parsed.release_page,
        None,
        None,
        None,
        parsed.published_at,
    )
}

fn build_release_info(
    latest_tag: &str,
    release_page: String,
    download_url: Option<String>,
    asset_name: Option<String>,
    notes: Option<String>,
    published_at: Option<String>,
) -> Result<ReleaseInfo, String> {
    let latest_version = normalize_version_tag(latest_tag);
    if latest_version.is_empty() {
        return Err(format!("解析到的版本标签无效：{latest_tag}"));
    }

    let current_version = current_version().to_owned();
    let update_available = compare_versions(&current_version, &latest_version) == Ordering::Less;

    Ok(ReleaseInfo {
        current_version,
        latest_version,
        release_page,
        download_url,
        asset_name,
        notes,
        published_at,
        update_available,
    })
}

fn load_cached_release() -> Option<ReleaseInfo> {
    let cache_path = cache_file_path()?;
    let content = fs::read_to_string(cache_path).ok()?;
    let cache: CachedReleaseInfo = serde_json::from_str(&content).ok()?;

    let now_secs = now_unix_secs().ok()?;
    if now_secs.saturating_sub(cache.checked_at_secs) > UPDATE_CACHE_TTL_SECS {
        return None;
    }
    if cache.latest_version.trim().is_empty() || cache.release_page.trim().is_empty() {
        return None;
    }

    let current_version = current_version().to_owned();
    let update_available =
        compare_versions(&current_version, &cache.latest_version) == Ordering::Less;

    Some(ReleaseInfo {
        current_version,
        latest_version: cache.latest_version,
        release_page: cache.release_page,
        download_url: cache.download_url,
        asset_name: cache.asset_name,
        notes: cache.notes,
        published_at: cache.published_at,
        update_available,
    })
}

fn save_cached_release(release: &ReleaseInfo) {
    let Ok(now_secs) = now_unix_secs() else {
        return;
    };
    let Some(cache_path) = cache_file_path() else {
        return;
    };
    let Some(parent) = cache_path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }

    let cache = CachedReleaseInfo {
        checked_at_secs: now_secs,
        latest_version: release.latest_version.clone(),
        release_page: release.release_page.clone(),
        download_url: release.download_url.clone(),
        asset_name: release.asset_name.clone(),
        notes: release.notes.clone(),
        published_at: release.published_at.clone(),
    };

    if let Ok(json) = serde_json::to_string(&cache) {
        let _ = fs::write(cache_path, json);
    }
}

fn cache_file_path() -> Option<PathBuf> {
    if let Ok(cwd) = std::env::current_dir() {
        return Some(
            cwd.join("dist")
                .join("cache")
                .join("release-check-cache.json"),
        );
    }
    Some(
        std::env::temp_dir()
            .join("clash-node-checker")
            .join("release-check-cache.json"),
    )
}

fn now_unix_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("系统时间错误：{error}"))
}

fn parse_latest_release_from_atom(atom: &str) -> Option<ParsedAtomRelease> {
    let entry = extract_between(atom, "<entry>", "</entry>").unwrap_or(atom);
    let release_page = extract_release_page_from_text(entry)?;
    let tag = extract_tag_from_release_url(&release_page)?;
    let published_at = extract_between(entry, "<updated>", "</updated>")
        .map(str::trim)
        .map(str::to_owned)
        .filter(|value| !value.is_empty());

    Some(ParsedAtomRelease {
        tag,
        release_page,
        published_at,
    })
}

fn extract_release_page_from_text(text: &str) -> Option<String> {
    let prefix = format!(
        "https://github.com/{}/{}/releases/tag/",
        GITHUB_OWNER, GITHUB_REPO
    );
    let index = text.find(&prefix)?;
    let remainder = &text[index..];
    let mut end = remainder.len();
    for (idx, ch) in remainder.char_indices() {
        if ch == '"' || ch == '\'' || ch == '<' || ch.is_whitespace() {
            end = idx;
            break;
        }
    }
    let value = remainder[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn extract_tag_from_release_url(url: &str) -> Option<String> {
    let marker = "/releases/tag/";
    let index = url.find(marker)?;
    let tail = &url[index + marker.len()..];
    let value = tail
        .split(['?', '#', '/'])
        .next()
        .unwrap_or_default()
        .trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn extract_tag_from_release_path(path: &str) -> Option<String> {
    let mut segments = path.trim_matches('/').split('/');
    let _ = segments.next()?;
    let _ = segments.next()?;
    let releases = segments.next()?;
    let tag = segments.next()?;
    let value = segments.next()?;
    if releases != "releases" || tag != "tag" {
        return None;
    }
    if value.trim().is_empty() {
        None
    } else {
        Some(value.trim().to_owned())
    }
}

fn extract_between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let start_index = text.find(start)?;
    let after_start = &text[start_index + start.len()..];
    let end_index = after_start.find(end)?;
    Some(&after_start[..end_index])
}

fn normalize_version_tag(tag: &str) -> String {
    tag.trim()
        .trim_start_matches(['v', 'V'])
        .split(['-', '+'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned()
}

pub fn compare_versions(current: &str, latest: &str) -> Ordering {
    match (parse_version_parts(current), parse_version_parts(latest)) {
        (Some(current_parts), Some(latest_parts)) => {
            compare_version_parts(&current_parts, &latest_parts)
        }
        _ => normalize_version_tag(current).cmp(&normalize_version_tag(latest)),
    }
}

fn compare_version_parts(current: &[u64], latest: &[u64]) -> Ordering {
    let max_len = current.len().max(latest.len());
    for index in 0..max_len {
        let current_value = current.get(index).copied().unwrap_or(0);
        let latest_value = latest.get(index).copied().unwrap_or(0);
        match current_value.cmp(&latest_value) {
            Ordering::Equal => continue,
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

fn parse_version_parts(version: &str) -> Option<Vec<u64>> {
    let normalized = normalize_version_tag(version);
    if normalized.is_empty() {
        return None;
    }

    normalized
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::{
        compare_versions, extract_tag_from_release_path, normalize_version_tag,
        parse_latest_release_from_atom,
    };

    #[test]
    fn trims_release_tag_prefix() {
        assert_eq!(normalize_version_tag("v1.0.3"), "1.0.3");
        assert_eq!(normalize_version_tag("V2.1.0-beta.1"), "2.1.0");
    }

    #[test]
    fn compares_semantic_versions() {
        assert_eq!(compare_versions("1.0.3", "1.0.3"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.2", "1.0.3"), Ordering::Less);
        assert_eq!(compare_versions("1.2.0", "1.1.9"), Ordering::Greater);
        assert_eq!(compare_versions("v1.0.3", "1.0.10"), Ordering::Less);
    }

    #[test]
    fn parses_tag_from_release_path() {
        assert_eq!(
            extract_tag_from_release_path("/NOTFROMCONCEN/clash_node_check/releases/tag/v1.5.9"),
            Some("v1.5.9".to_owned())
        );
        assert_eq!(
            extract_tag_from_release_path("/NOTFROMCONCEN/clash_node_check/releases/latest"),
            None
        );
    }

    #[test]
    fn parses_latest_entry_from_atom() {
        let atom = r#"
<?xml version="1.0" encoding="UTF-8"?>
<feed>
  <entry>
    <id>tag:github.com,2008:Repository/123456/v1.6.0</id>
    <updated>2026-04-27T01:23:45Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/NOTFROMCONCEN/clash_node_check/releases/tag/v1.6.0"/>
    <title>v1.6.0</title>
  </entry>
</feed>
"#;
        let parsed = parse_latest_release_from_atom(atom).expect("failed to parse atom");
        assert_eq!(parsed.tag, "v1.6.0");
        assert_eq!(
            parsed.release_page,
            "https://github.com/NOTFROMCONCEN/clash_node_check/releases/tag/v1.6.0"
        );
        assert_eq!(parsed.published_at.as_deref(), Some("2026-04-27T01:23:45Z"));
    }
}
