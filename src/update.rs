use std::cmp::Ordering;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderValue, USER_AGENT};
use serde::Deserialize;

pub const GITHUB_OWNER: &str = "NOTFROMCONCEN";
pub const GITHUB_REPO: &str = "clash_node_check";

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

#[derive(Debug, Deserialize)]
struct GitHubReleaseResponse {
    tag_name: String,
    html_url: String,
    body: Option<String>,
    published_at: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubReleaseAsset {
    name: String,
    browser_download_url: String,
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
    let api_url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        GITHUB_OWNER, GITHUB_REPO
    );
    let user_agent = format!("clash-node-checker/{}", current_version());
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("创建更新检查客户端失败：{error}"))?;

    let release = client
        .get(api_url)
        .header(ACCEPT, HeaderValue::from_static("application/vnd.github+json"))
        .header(USER_AGENT, user_agent)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("请求 GitHub Release 失败：{error}"))?
        .text()
        .map_err(|error| format!("读取 GitHub Release 响应失败：{error}"))?;
    let release = serde_json::from_str::<GitHubReleaseResponse>(&release)
        .map_err(|error| format!("解析 GitHub Release 响应失败：{error}"))?;

    let latest_version = normalize_version_tag(&release.tag_name);
    let current_version = current_version().to_owned();
    let update_available = compare_versions(&current_version, &latest_version) == Ordering::Less;
    let asset = preferred_asset(&release.assets).or_else(|| release.assets.first());

    Ok(ReleaseInfo {
        current_version,
        latest_version,
        release_page: release.html_url,
        download_url: asset.map(|item| item.browser_download_url.clone()),
        asset_name: asset.map(|item| item.name.clone()),
        notes: release
            .body
            .map(|body| body.trim().to_owned())
            .filter(|body| !body.is_empty()),
        published_at: release
            .published_at
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        update_available,
    })
}

fn preferred_asset(assets: &[GitHubReleaseAsset]) -> Option<&GitHubReleaseAsset> {
    assets.iter().find(|asset| {
        let name = asset.name.to_ascii_lowercase();
        (name.contains("windows") || name.ends_with(".exe"))
            && (name.ends_with(".zip") || name.ends_with(".exe"))
    })
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
        (Some(current_parts), Some(latest_parts)) => compare_version_parts(&current_parts, &latest_parts),
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

    use super::{compare_versions, normalize_version_tag};

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
}